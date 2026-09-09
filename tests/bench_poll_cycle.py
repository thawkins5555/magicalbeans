"""How late a fleet actually gets polled, per device count and pool size.

Deliberately not a test_*.py: the answer depends on how many cores are under
it, so this prints numbers rather than asserting them (run_all.py only picks
up test_*.py).

    python3 tests/bench_poll_cycle.py [devices ...] [--workers 8,16,32]
                                      [--interval 15] [--seconds 20]
                                      [--down-fraction 0.05] [--seed 7]
                                      [--auto]
    python3 tests/bench_poll_cycle.py --stub [--interfaces 8,48,240]

Each `devices` figure is one fleet, run once against each pool size.

The headline column is LATENESS: actual_poll_ts - due_ts, per poll. It is the
honest measure of "an outage would be seen this late", and it is the number
the poll-pool autoscaler has to be tuned against. polls/min says how much
work got done; lateness says whether any of it was done on time. A pool that
is one worker short does not drop polls, it defers them, and every deferral
lands on the next cycle too — which is why p95 and max matter more than the
mean, and why overruns alone (the only signal the product ships today) reads
as "fine" long after the fleet has stopped being watched in real time.

`--synthetic` (the default) drives the REAL _loop/_schedule_pass against a
REAL ThreadPoolExecutor over a REAL NodesDatabase. Only NodePoller._poll_device
is monkeypatched, to a sleep drawn from a fixed distribution:

    70% at 0.3 s, 20% at 0.8 s, 5% at 3 s, 5% "down" at 10 s

Each device is assigned its class once, from a seeded RNG, so two runs of the
same arguments schedule the same fleet. No SNMP and no sockets: what is being
measured is the scheduler and the pool, not the network. `--down-fraction`
raises the 10 s share at the expense of the 0.3 s one, which is what a site
outage does to a poll cycle — a handful of devices each holding a worker for
a full timeout budget.

`--stub` is the calibration pass, run once rather than on every tuning
iteration: a handful of real tests/stubs SNMP agents, polled through the real
_poll_device, so the synthetic costs above can be checked against the real
parse-and-write path at several interface counts. It prints what it measured
beside the distribution this bench assumes.

nodepoll.py is not modified by any of this; everything here is a monkeypatch
applied for the length of one run and put back afterwards.
"""
import os
import random
import statistics
import sys
import threading
import time

import _paths
from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

# (share, seconds). The last bucket is the "down" one --down-fraction moves.
DISTRIBUTION = ((0.70, 0.3), (0.20, 0.8), (0.05, 3.0), (0.05, 10.0))
SAMPLE_INTERVAL_S = 0.2


def pct(values, fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * fraction))
    return ordered[max(0, min(len(ordered) - 1, index))]


def cost_classes(devices: int, down_fraction: float, seed: int) -> list[float]:
    """One cost per device, drawn once so a rerun schedules the same fleet."""
    shares = list(DISTRIBUTION)
    if down_fraction is not None:
        spare = shares[3][0] - down_fraction
        shares[3] = (down_fraction, shares[3][1])
        shares[0] = (max(0.0, shares[0][0] + spare), shares[0][1])
    rng = random.Random(seed)
    weights = [share for share, _cost in shares]
    costs = [cost for _share, cost in shares]
    return rng.choices(costs, weights=weights, k=devices)


# ------------------------------------------------------------------ fleet

def build_fleet(folder: str, devices: int, interval: int) -> NodesDatabase:
    db = NodesDatabase(os.path.join(folder, f"nodes-{devices}.db"))
    group_id = db.ensure_default_group()
    rows = [{"ip": f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}",
             "name": f"sw-{i}", "group_id": group_id,
             "overrides": {"poll_interval_s": interval, "ping_enabled": 0,
                           "snmp_version": 2, "community": "public"}}
            for i in range(1, devices + 1)]
    db.add_devices_bulk(rows)
    return db


def device_ids(db) -> list[int]:
    with db._lock:
        return [row[0] for row in
                db._conn.execute("SELECT id FROM devices ORDER BY id").fetchall()]


def stagger(db, ids: list[int], interval: int) -> None:
    """Give every device a last_poll_ts spread across one interval, so the
    fleet starts the run in steady state.

    Left NULL — which is what a freshly seeded devices table has —
    _schedule_pass finds every device due on its very first pass and submits
    the whole fleet at once. That is real (it is what a restart does), but it
    measures a restart, and the burst dominates any run short enough to be
    worth waiting for. Re-applied before each pool size so combo three starts
    where combo one did.
    """
    now = time.time()
    step = interval / max(1, len(ids))
    with db._lock:
        db._conn.executemany(
            "UPDATE devices SET last_poll_ts = ? WHERE id = ?",
            [(now - interval + index * step, device_id)
             for index, device_id in enumerate(ids)])
        db._conn.commit()


class Sampler(threading.Thread):
    """pool_state() on a fixed cadence — the same three numbers the status
    strip and the autoscaler would read."""

    def __init__(self, poller):
        super().__init__(daemon=True)
        self.poller = poller
        self.busy: list[int] = []
        self.queued: list[int] = []
        self.saturated = 0
        self._done = threading.Event()

    def run(self) -> None:
        while not self._done.is_set():
            state = self.poller.pool_state()
            self.busy.append(state["busy"])
            self.queued.append(state["queued"])
            self.saturated += 1 if state["saturated"] else 0
            self._done.wait(SAMPLE_INTERVAL_S)

    def stop(self) -> None:
        self._done.set()
        self.join(timeout=5)


def run_combo(db, devices: int, workers: int, interval: int, seconds: float,
              costs: list[float], auto: bool = False) -> dict:
    """One (device count x pool size) run of the real scheduler.

    _submit is wrapped rather than _schedule_pass: the scheduler sets
    _next_run[device_id] = now + interval immediately before submitting, so
    the due time that just fired is that value less the device's interval —
    exact, given every device here is on the same interval and focus polling
    is off. The patched _poll_device pops it when the poll actually STARTS,
    which is what makes the recorded lateness include queue wait rather than
    only scheduler drift.
    """
    ids = device_ids(db)
    by_id = {device_id: costs[index] for index, device_id in enumerate(ids)}
    stagger(db, ids, interval)

    due: dict[int, float] = {}
    lateness: list[float] = []
    lock = threading.Lock()

    real_submit = NodePoller._submit
    real_poll = NodePoller._poll_device

    def submit(self, device_id):
        with lock:
            due[device_id] = self._next_run.get(device_id, time.time()) - interval
        return real_submit(self, device_id)

    def poll_device(self, device, config):
        device_id = device["id"]
        with lock:
            expected = due.pop(device_id, None)
        if expected is not None:
            lateness.append(time.time() - expected)
        time.sleep(by_id.get(device_id, 0.3))

    # poll_workers_auto is set EXPLICITLY, never left to DEFAULTS. With it
    # on, `workers` is only where the pool starts and the number that matters
    # is where it ends up, so the two cases have to be told apart or the
    # workers column silently stops meaning what the header says.
    db.save_settings({"enabled": True, "poll_workers": workers,
                      "poll_workers_auto": auto,
                      "poll_workers_min": 1 if auto else workers,
                      "poll_workers_max": 512 if auto else workers,
                      "default_interval_s": interval,
                      "focus_poll_interval_s": 0})
    NodePoller._submit = submit
    NodePoller._poll_device = poll_device
    poller = NodePoller(db)
    sampler = Sampler(poller)
    try:
        started = time.perf_counter()
        poller.start(db.settings())
        sampler.start()
        time.sleep(seconds)
        elapsed = time.perf_counter() - started
        sampler.stop()
        polls = poller.counters.get("polls", 0)
        overruns = poller.counters.get("overruns", 0)
        ended = getattr(poller._executor, "_max_workers", workers)
    finally:
        poller.stop()
        NodePoller._submit = real_submit
        NodePoller._poll_device = real_poll

    samples = max(1, len(sampler.busy))
    return {"devices": devices, "interval": interval, "workers": workers,
            "ended": ended,
            "polls_min": polls * 60.0 / max(elapsed, 1e-9),
            "p50": pct(lateness, 0.50), "p95": pct(lateness, 0.95),
            "max": max(lateness) if lateness else 0.0,
            "overruns": overruns,
            "busy_mean": statistics.fmean(sampler.busy) if sampler.busy else 0.0,
            "busy_p95": pct(sampler.busy, 0.95),
            "queue_p95": pct(sampler.queued, 0.95),
            "saturated_pct": 100.0 * sampler.saturated / samples}


HEADER = (f"  {'devices':>7} {'interval':>8} {'workers':>7} {'ended':>6} "
          f"{'polls/min':>9} "
          f"{'late p50':>9} {'late p95':>9} {'late max':>9} {'overruns':>8} "
          f"{'busy mean':>9} {'busy p95':>8} {'queue p95':>9} {'sat %':>6}")


def row(result: dict) -> str:
    return (f"  {result['devices']:>7} {result['interval']:>8} "
            f"{result['workers']:>7} {result['ended']:>6} "
            f"{result['polls_min']:>9.0f} "
            f"{result['p50']:>9.2f} {result['p95']:>9.2f} "
            f"{result['max']:>9.2f} {result['overruns']:>8} "
            f"{result['busy_mean']:>9.1f} {result['busy_p95']:>8} "
            f"{result['queue_p95']:>9} {result['saturated_pct']:>5.0f}%")


def synthetic(argv_sizes, workers, interval, seconds, down_fraction, seed,
              auto=False) -> int:
    folder = tmpdir("bench_poll_cycle_")
    print(f"scratch: {folder}")
    shares = list(DISTRIBUTION)
    if down_fraction is not None:
        spare = shares[3][0] - down_fraction
        shares[3] = (down_fraction, shares[3][1])
        shares[0] = (max(0.0, shares[0][0] + spare), shares[0][1])
    mean_cost = sum(share * cost for share, cost in shares)
    print("cost distribution: " +
          ", ".join(f"{share * 100:.0f}% at {cost} s" for share, cost in shares) +
          f"  (mean {mean_cost:.2f} s per poll, seed {seed})")

    for devices in argv_sizes:
        started = time.perf_counter()
        db = build_fleet(folder, devices, interval)
        costs = cost_classes(devices, down_fraction, seed)
        need = devices * mean_cost / interval
        print(f"\n{devices:,} devices on a {interval} s interval "
              f"(seeded in {time.perf_counter() - started:.1f} s; "
              f"{need:.1f} workers' worth of work per cycle), "
              f"{seconds:.0f} s per pool size"
              + ("  [auto-sizing ON: workers is the START size, ended is where "
                 "it got to]" if auto else ""))
        print(HEADER)
        try:
            for count in workers:
                print(row(run_combo(db, devices, count, interval, seconds,
                                    costs, auto)))
        finally:
            db.close()
    return 0


# ------------------------------------------------------------------- stubs

def stub(interface_counts, polls: int) -> int:
    """Calibration: the real _poll_device against real stub agents, so the
    synthetic costs above can be checked against the real parse-and-write
    path rather than against a guess. Sequential on purpose — nodepoll reads
    one module-level DEFAULT_SNMP_PORT, so one stub is addressable at a time,
    and this pass is about per-poll cost, not concurrency.

    One device row, recreated per stub, and always on 127.0.0.1: Windows only
    assigns the one loopback address, so 127.0.0.2 is not a second stub host
    here the way it would be on Linux, and `devices.ip` is UNIQUE.
    """
    folder = tmpdir("bench_poll_stub_")
    print(f"scratch: {folder}")
    db = NodesDatabase(os.path.join(folder, "nodes.db"))
    group_id = db.ensure_default_group()
    poller = NodePoller(db)
    real_port = nodepoll.DEFAULT_SNMP_PORT

    print(f"\nreal _poll_device against tests/stubs/stub_agent_iftable.py, "
          f"{polls} polls each")
    print(f"  {'stub':<28} {'interfaces':>10} {'polls':>6} {'mean s':>8} "
          f"{'p95 s':>8} {'max s':>8}")
    try:
        for interfaces in interface_counts:
            proc, port = spawn_stub("stub_agent_iftable.py", "ok",
                                    "--interfaces", str(interfaces))
            try:
                nodepoll.DEFAULT_SNMP_PORT = port
                # snmp_version=1 is v2c here (0=v1, 1=v2c, 3=v3 — nodesdb's
                # own column comment), which is what this stub speaks.
                # ping_enabled=0: 127.0.0.1 answers ICMP on any machine with
                # a ping binary, and this pass is about the SNMP parse-and-
                # write cost, not about how fast loopback replies.
                device_id = db.add_device("127.0.0.1", f"stub-{interfaces}",
                                          group_id=group_id, snmp_version=1,
                                          community="public", ping_enabled=0,
                                          poll_interval_s=999, snmp_timeout_s=2.0,
                                          snmp_retries=1)
                costs = []
                for _ in range(polls):
                    device = db.device(device_id)
                    config = db.effective_config(device)
                    started = time.perf_counter()
                    poller._poll_device(device, config)
                    costs.append(time.perf_counter() - started)
                status = db.device(device_id)["status"]
                print(f"  {'iftable ok (' + status + ')':<28} {interfaces:>10} "
                      f"{polls:>6} {statistics.fmean(costs):>8.3f} "
                      f"{pct(costs, 0.95):>8.3f} {max(costs):>8.3f}")
                db.remove_device(device_id)
            finally:
                proc.kill()
    finally:
        nodepoll.DEFAULT_SNMP_PORT = real_port
        db.close()

    print("\nthe synthetic distribution this bench assumes, for comparison:")
    for share, cost in DISTRIBUTION:
        print(f"  {share * 100:>4.0f}% at {cost:>5.1f} s")
    print("  A stub on loopback is the floor, not the fleet: it answers every\n"
          "  request first time, so what it measures is decode + database\n"
          "  write. The 3 s and 10 s buckets above are timeout budgets, which\n"
          "  no stub can produce and no calibration should replace.")
    return 0


def main(argv) -> int:
    sizes = []
    workers = [8, 16, 32]
    interval = 15
    seconds = 20.0
    down_fraction = None
    seed = 7
    mode = "synthetic"
    auto = False
    interface_counts = [8, 48, 240]
    polls = 10
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--stub":
            mode = "stub"
        elif item == "--auto":
            auto = True
        elif item == "--synthetic":
            mode = "synthetic"
        elif item in ("--workers", "--interval", "--seconds", "--down-fraction",
                      "--seed", "--interfaces", "--polls"):
            index += 1
            value = argv[index]
            if item == "--workers":
                workers = [int(part) for part in value.split(",") if part]
            elif item == "--interval":
                interval = int(value)
            elif item == "--seconds":
                seconds = float(value)
            elif item == "--down-fraction":
                down_fraction = float(value)
            elif item == "--seed":
                seed = int(value)
            elif item == "--interfaces":
                interface_counts = [int(part) for part in value.split(",") if part]
            else:
                polls = int(value)
        else:
            sizes.append(int(item.replace("_", "")))
        index += 1
    if mode == "stub":
        return stub(interface_counts, polls)
    return synthetic(sizes or [300], workers, interval, seconds,
                     down_fraction, seed, auto)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

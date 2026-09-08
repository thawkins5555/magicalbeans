"""The discovery thread pool: that it actually overlaps addresses, that one
worker still means one at a time, that the fold rule survives two addresses
of the same device landing together, and that the worker count reaches a job
from settings and from the per-scan override.

Hermetic: the ping sweep is patched all-alive and _snmp_identify is replaced
with a stand-in that counts how many probes are in flight and sleeps instead
of touching a socket, so the timings measure the pool and nothing else.
"""
import json
import os
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

import netpath.nodediscover as nodediscover
from netpath.nodediscover import (DEFAULT_DISCOVERY_WORKERS,
                                  MAX_DISCOVERY_WORKERS, DiscoveryJob)
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase
from netpath.snmppoll import SnmpError
from netpath.web import api as web_api

TMPDIR = _paths.tmpdir("disc_workers_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class Probes:
    """Stands in for _snmp_identify: records the high-water mark of probes
    running at the same moment, then fails the way an unanswered address
    does, so _try_snmp exhausts its version/community list."""

    def __init__(self, delay_s):
        self.delay_s = delay_s
        self._lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0
        self.calls = 0

    def __call__(self, ip, version, community, timeout_s, oids, pdu=None):
        with self._lock:
            self.in_flight += 1
            self.calls += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            time.sleep(self.delay_s)
            raise SnmpError(f"no reply from {ip}")
        finally:
            with self._lock:
                self.in_flight -= 1


def run_sweep(db, poller, target, overrides, wait_s=60.0):
    """One subnet job, run to completion; returns (elapsed, job row)."""
    started = time.monotonic()
    job_id = poller.start_discovery("subnet", target, overrides=overrides)
    deadline = started + wait_s
    while time.monotonic() < deadline:
        job = db.discovery_job(job_id)
        if job["state"] != "running":
            return time.monotonic() - started, job_id, job
        time.sleep(0.02)
    raise AssertionError(f"discovery job {job_id} never finished")


BASE = {"discovery_communities": "public", "default_snmp_timeout_s": 1.0,
        "max_scan_addresses": 1024, "discovery_arc_hop": False,
        # Pacing is not what these cases measure; keep it out of the timings.
        "discovery_probes_per_second": 2000}

db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
poller = NodePoller(db)
real_try_snmp = DiscoveryJob._try_snmp
nodediscover.sweep = lambda addresses, **kw: {ip: True for ip in addresses}

try:
    # ------------------------------------------------ 1. addresses overlap
    print("1. a pool of workers probes addresses at the same time")
    probes = Probes(0.2)
    nodediscover._snmp_identify = probes
    elapsed, _job_id, job = run_sweep(
        db, poller, "127.0.0.0/28", dict(BASE, discovery_workers=16))
    check("every address in the /28 was probed",
          job["state"] == "done" and job["probed"] == 14 == job["total"],
          (job["state"], job["probed"], job["total"]))
    check("16 workers put at least 8 probes in flight at once",
          probes.peak >= 8, probes.peak)
    check("...and the whole sweep took far less than the serial time",
          elapsed < 6.0, elapsed)
    print(f"   peak in flight {probes.peak}, {probes.calls} probes, "
          f"{elapsed:.2f}s (serial would be about "
          f"{probes.calls * probes.delay_s:.1f}s)")

    # ------------------------------------------------- 2. one worker is one
    print("2. one worker is still strictly one address at a time")
    probes = Probes(0.1)
    nodediscover._snmp_identify = probes
    elapsed, _job_id, job = run_sweep(
        db, poller, "127.0.0.8/29", dict(BASE, discovery_workers=1))
    check("every address in the /29 was probed",
          job["state"] == "done" and job["probed"] == 6 == job["total"],
          (job["state"], job["probed"], job["total"]))
    check("a single worker never has two probes in flight",
          probes.peak == 1, probes.peak)
    print(f"   peak in flight {probes.peak}, {probes.calls} probes, {elapsed:.2f}s")

    # --------------------------------- 3. the fold rule under a real race
    print("3. two addresses of one device, answering at the same instant, "
          "fold into one offer")
    shared = ["10.55.0.1", "10.55.0.2"]
    barrier = threading.Barrier(2, timeout=30)

    def racing_try_snmp(self, ip, communities, timeout_s, retries=0):
        """Both workers reach _record together, which is the ordering the
        serial loop could never produce and the job lock has to survive."""
        barrier.wait()
        return {"community_or_user": "public", "snmp_version": 1,
                "sys_descr": "shared router", "sys_name": "r1",
                "sys_object_id": "1.3.6.1.4.1.9.1.1",
                "ip_addresses": json.dumps(shared)}

    DiscoveryJob._try_snmp = racing_try_snmp
    _elapsed, job_id, job = run_sweep(
        db, poller, "127.0.0.16/30", dict(BASE, discovery_workers=2))
    DiscoveryJob._try_snmp = real_try_snmp
    rows = db.discovery_results(job_id)
    folded = [r for r in rows if r["folded_into_result_id"]]
    primary = [r for r in rows if not r["folded_into_result_id"]]
    check("both addresses were recorded", len(rows) == 2, len(rows))
    check("exactly one of them folded into the other",
          len(folded) == 1 and len(primary) == 1, (len(folded), len(primary)))
    check("...into a row of this same job",
          bool(folded) and folded[0]["folded_into_result_id"] == primary[0]["id"],
          [dict(r) for r in rows])
    check("the job counts one device found, not two",
          job["identified"] == 1, job["identified"])

    # ------------------------------------------- 4. the setting and override
    print("4. the worker count reaches a job from settings and per scan")
    check("the shipped default is 32", db.settings()["discovery_workers"] == 32,
          db.settings().get("discovery_workers"))
    check("...which is what nodediscover uses when nothing is set",
          DEFAULT_DISCOVERY_WORKERS == 32, DEFAULT_DISCOVERY_WORKERS)
    check("the ceiling is 256", MAX_DISCOVERY_WORKERS == 256,
          MAX_DISCOVERY_WORKERS)

    captured = {}

    class FakeNodesDb:
        def group(self, group_id):
            return {"id": group_id} if group_id == 1 else None

    class FakePoller:
        def start_discovery(self, kind, target, overrides=None,
                            allow_ping_only=False, group_id=None,
                            scan_overrides=None):
            captured["overrides"] = overrides
            captured["scan_overrides"] = scan_overrides
            return 7

    class FakeLog:
        def add(self, *args, **kwargs):
            pass

    class FakeService:
        def __init__(self):
            self.nodes_db = FakeNodesDb()
            self.node_poller = FakePoller()
            self.settings = {"never_scan_cidrs": ""}
            self.log = FakeLog()

    web_api._discovery_communities_for_group = lambda service, group_id: "public"

    def post(**extra):
        captured.clear()
        body = {"target": "10.0.0.0/30", "group_id": 1}
        body.update(extra)
        return web_api.post_nodes_discovery(FakeService(), {}, body)

    post(workers=4)
    check("a per-scan worker count arrives as a job override",
          captured["overrides"].get("discovery_workers") == 4,
          captured["overrides"])
    check("...and is also kept on the row, keyed as the dialog sent it, so "
          "Re-discover can replay it",
          captured["scan_overrides"] == {"workers": 4},
          captured["scan_overrides"])
    post()
    check("...and a scan that does not ask for one sets no override",
          "discovery_workers" not in captured["overrides"], captured["overrides"])

    def refused(**extra):
        try:
            post(**extra)
        except ValueError:
            return True
        return False

    check("zero workers is refused", refused(workers=0))
    check("more than 256 workers is refused", refused(workers=300))
    check("256 workers is accepted", not refused(workers=256))

finally:
    DiscoveryJob._try_snmp = real_try_snmp
    poller.shutdown()
    db.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")

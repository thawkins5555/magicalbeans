"""Background scheduling of traces."""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .db import Database
from .eventlog import DNS, ERROR, NullLog, SYSTEM, TRACE
from .namelookup import asn_lookup, reverse
from .tracer import TraceResult, expected_budget, ping, run_trace


def classify(result: TraceResult, warn_rtt_ms: float, warn_loss: float) -> str:
    """Map a trace onto ok / warn / fail / error.

    Only the destination hop decides the verdict. Intermediate routers often
    rate-limit or ignore ICMP, so their loss is not a fault signal.
    """
    if result.error and not result.hops:
        return "error"
    if not result.reached:
        # A router that answered with an ICMP unreachable told us why. That is
        # a different fault from silence, and worth keeping apart: the path
        # works up to that router, and something beyond it refused.
        return "blocked" if result.unreachable_code else "fail"
    loss = result.dest_loss()
    if loss >= 100:
        return "blocked" if result.unreachable_code else "fail"
    rtt = result.dest_rtt()
    if loss > warn_loss:
        return "warn"
    if rtt is not None and rtt > warn_rtt_ms:
        return "warn"
    return "ok"


class Monitor:
    """Runs traces on a schedule and writes them to the database.

    `on_complete(target_id)` is called from a worker thread, so a Qt UI should
    only use it to set a flag and refresh from its own timer.
    """

    def __init__(self, db: Database, workers: int = 4, on_complete=None, log=None):
        self.db = db
        self.on_complete = on_complete
        self.log = log or NullLog()
        self.workers = workers
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._inflight: set[int] = set()
        # Queued and started are tracked separately: with more destinations
        # than workers a trace can sit in the pool queue, and "waiting for a
        # worker" is a different problem from "the trace is slow".
        self._queued: dict[int, float] = {}
        self._started: dict[int, float] = {}
        self._lock = threading.Lock()
        self._next_run: dict[int, float] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_workers(self, count: int) -> None:
        """Resize the pool. Traces already running finish on the old pool."""
        count = max(1, int(count))
        if count == self.workers:
            return
        previous = self._executor
        self._executor = ThreadPoolExecutor(max_workers=count)
        self.workers = count
        previous.shutdown(wait=False)
        self.log.add(SYSTEM, f"Trace worker pool resized to {count}")

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netpath-scheduler", daemon=True)
        self._thread.start()
        self.log.add(SYSTEM, f"Scheduler started with {self.workers} worker threads")

    def stop(self, wait: bool = False) -> None:
        if self.running:
            self.log.add(SYSTEM, "Scheduler stopped")
        self._stop.set()
        if wait and self._thread:
            self._thread.join(timeout=5)

    def drain(self, timeout_s: float = 3.0) -> bool:
        """Wait for in-flight traces to finish. True if they all did."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self.inflight():
                return True
            time.sleep(0.05)
        return not self.inflight()

    def shutdown(self, drain_s: float = 3.0) -> None:
        self.stop()
        # Queued work is dropped, but a trace already running still wants to
        # write its result; closing the database under it raises inside the
        # worker and loses the measurement.
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.drain(drain_s)

    def inflight(self) -> set[int]:
        with self._lock:
            return set(self._inflight)

    def worker_state(self) -> dict[int, dict[str, float]]:
        """Per in-flight target: when it was queued and when it started."""
        with self._lock:
            return {
                target_id: {"queued": self._queued.get(target_id),
                            "started": self._started.get(target_id)}
                for target_id in self._inflight
            }

    def next_runs(self) -> dict[int, float]:
        return dict(self._next_run)

    def trace_now(self, target_id: int) -> None:
        """Queue an immediate trace, ignoring the schedule."""
        self._submit(target_id)

    # ------------------------------------------------------------- internals

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            for target in self.db.targets():
                if not target["enabled"]:
                    continue
                due = self._next_run.get(target["id"])
                if due is None:
                    last = self.db.last_trace(target["id"])
                    due = (last["started_ts"] + target["interval_s"]) if last else now
                    self._next_run[target["id"]] = due
                if now >= due:
                    self._next_run[target["id"]] = now + target["interval_s"]
                    if target["id"] in self.inflight():
                        self._record_overrun(target, now)
                    else:
                        self._submit(target["id"])
            self._stop.wait(1.0)

    def _record_overrun(self, target, now: float) -> None:
        """The previous run is still going, so this slot is lost."""
        with self._lock:
            started = self._started.get(target["id"])
        running_for = (now - started) if started else None
        label = target["label"] or target["host"]
        interval = target["interval_s"]

        note = (f"Previous trace still running after "
                f"{running_for:.0f}s" if running_for else
                "Previous trace still running")
        note += f"; interval is {interval}s"

        keys = target.keys()
        timeout_s = float(target["timeout_s"]) if "timeout_s" in keys else 2.0
        budget = expected_budget(target["max_hops"], target["probes"], timeout_s)
        note += (f". A trace to this destination can take up to {budget:.0f}s, "
                 f"so the interval needs to be longer than that or the hop "
                 f"count reduced.")

        try:
            self.db.record_overrun(target["id"], now, started, note)
        except Exception:
            pass
        self.log.add(ERROR, f"Scheduled trace skipped: {note}", target=label)

    def _submit(self, target_id: int) -> None:
        if self._stop.is_set():
            return
        with self._lock:
            if target_id in self._inflight:
                return
            self._inflight.add(target_id)
            self._queued[target_id] = time.time()
        try:
            self._executor.submit(self._run_one, target_id)
        except RuntimeError:
            # The pool was shut down between the check above and here. Undo the
            # bookkeeping rather than letting the exception kill the scheduler
            # thread and stop every future trace.
            with self._lock:
                self._inflight.discard(target_id)
                self._queued.pop(target_id, None)

    def _run_one(self, target_id: int) -> None:
        label = str(target_id)
        try:
            target = self.db.target(target_id)
            if target is None:
                return
            label = target["label"] or target["host"]
            with self._lock:
                self._started[target_id] = time.time()
            keys = target.keys()
            timeout_s = float(target["timeout_s"]) if "timeout_s" in keys else 2.0
            self.log.add(TRACE, f"Trace started on {threading.current_thread().name}",
                         target=label,
                         detail=f"host      {target['host']}\n"
                                f"max hops  {target['max_hops']}\n"
                                f"probes    {target['probes']}\n"
                                f"timeout   {timeout_s}s per probe\n"
                                f"interval  {target['interval_s']}s")

            result = run_trace(
                target["host"],
                max_hops=target["max_hops"],
                probes=target["probes"],
                timeout_s=timeout_s,
            )
            status = classify(result, target["warn_rtt_ms"], target["warn_loss"])
            trace_id = self.db.record_trace(target_id, result, status)

            rtt = result.dest_rtt()
            summary = (f"{status} \u00b7 {len(result.hops)} hops \u00b7 "
                       f"{result.duration_s:.1f}s")
            if rtt is not None:
                summary += f" \u00b7 {rtt:.1f} ms"
            if result.error:
                summary += f" \u00b7 {result.error}"

            detail = []
            if result.command:
                detail.append("$ " + " ".join(result.command))
            detail.append(f"resolved  {result.dest_ip or 'unresolved'}")
            detail.append(f"reached   {bool(result.reached)}")
            if result.unreachable_code:
                from .tracer import unreachable_text
                detail.append(f"refused   {result.unreachable_code} "
                              f"({unreachable_text(result.unreachable_code)}) "
                              f"from {result.unreachable_from}")
                if result.rtt_is_to_refuser and rtt is not None:
                    detail.append(f"rtt       {rtt:.1f} ms measured to "
                                  f"{result.unreachable_from}, not the target")
            detail.append(f"path      {result.path_text()}")
            detail.append(f"stored as trace id {trace_id}")
            if result.raw_output:
                detail.append("")
                detail.append(result.raw_output)

            self.log.add(ERROR if status in ("fail", "blocked", "error") else TRACE,
                         f"Trace finished: {summary}", target=label,
                         detail="\n".join(detail))

            if self.on_complete:
                self.on_complete(target_id)
        except Exception as exc:  # a scheduler thread must never die quietly
            import traceback
            self.log.add(ERROR, f"Worker raised {type(exc).__name__}: {exc}",
                         target=label, detail=traceback.format_exc())
            traceback.print_exc()
        finally:
            with self._lock:
                self._inflight.discard(target_id)
                self._queued.pop(target_id, None)
                self._started.pop(target_id, None)


class Resolver:
    """Fills in reverse-DNS names for hop addresses, out of band.

    Traces themselves run numerically (-n / -d). Asking traceroute to resolve
    inline would add a lookup to every hop of every run, for routers whose
    names almost never change. Instead each address is looked up once here and
    cached in app.db for a week, where every module can read it.

    An address with no PTR record falls back to IPAM's own idea of its name —
    what a DHCP lease says the client called itself — before giving up.
    Plenty of devices never get a DNS entry at all but still asked a DHCP
    server for an address, and that's the only name anything here will ever
    have for them.
    """

    def __init__(self, db: Database, app_db, workers: int = 8,
                 poll_s: float = 15.0,
                 timeout_s: float = 3.0, on_resolved=None, log=None,
                 cache_ttl_s: float = 7 * 86400, extra_ips=None,
                 server: str = "", use_nslookup: bool = True, ipam_db=None):
        self.db = db
        self.ipam_db = ipam_db
        # Candidates come from the trace database; the cache they are checked
        # against and written to is the application's, because NetFlow and
        # Syslog read the same names.
        self.app_db = app_db
        # A callable returning more addresses to name — the flow collector's
        # endpoints. Results go in the same cache, since the setting is global.
        self.extra_ips = extra_ips
        self.log = log or NullLog()
        self.cache_ttl_s = cache_ttl_s
        self.server = server or ""
        self.use_nslookup = use_nslookup
        self.poll_s = poll_s
        self.timeout_s = timeout_s
        self.on_resolved = on_resolved
        self.workers = workers
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pending: set[str] = set()
        # When each pending lookup was submitted, for the Debug page — a
        # reverse lookup has no separate queued/running distinction worth
        # tracking (unlike a trace, gethostbyaddr either starts immediately
        # on a free thread or waits briefly for one; both look the same from
        # here), so this is simpler than Monitor's queued/started pair.
        self._started: dict[str, float] = {}
        self._lock = threading.Lock()

    def configure(self, workers: int, timeout_s: float,
                  cache_ttl_s: float | None = None,
                  server: str | None = None,
                  use_nslookup: bool | None = None) -> None:
        self.timeout_s = float(timeout_s)
        if cache_ttl_s:
            self.cache_ttl_s = float(cache_ttl_s)
        if server is not None:
            self.server = server or ""
        if use_nslookup is not None:
            self.use_nslookup = bool(use_nslookup)
        workers = max(1, int(workers))
        if workers != self.workers:
            previous = self._executor
            self._executor = ThreadPoolExecutor(max_workers=workers)
            self.workers = workers
            previous.shutdown(wait=False)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netpath-resolver", daemon=True)
        self._thread.start()
        self.log.add(SYSTEM, f"Reverse DNS resolver started "
                             f"({self.workers} threads, {self.timeout_s:.0f}s timeout)")

    def stop(self) -> None:
        self._stop.set()

    def inflight(self) -> set[str]:
        with self._lock:
            return set(self._pending)

    def worker_state(self) -> dict[str, dict[str, float]]:
        """Per pending address: when the lookup was submitted, for the Debug
        page. Reverse lookups have no separate queued/running distinction
        worth tracking — unlike a trace, a lookup either starts on a free
        thread immediately or waits briefly for one, and both look the same
        from here — so this is simpler than Monitor's queued/started pair."""
        with self._lock:
            return {ip: {"started": self._started.get(ip)} for ip in self._pending}

    def drain(self, timeout_s: float = 3.0) -> bool:
        """Wait for in-flight lookups to finish. True if they all did."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self.inflight():
                return True
            time.sleep(0.05)
        return not self.inflight()

    def shutdown(self) -> None:
        self.stop()
        # No drain: a name lookup in flight has nothing to write that
        # matters, and gethostbyaddr can block past any timeout we set.
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                batch = self.app_db.unknown_ips(
                    self.db.distinct_hop_ips(), self.cache_ttl_s)[:40]
                if self.extra_ips and len(batch) < 40:
                    try:
                        extra = self.app_db.unknown_ips(self.extra_ips(),
                                                        self.cache_ttl_s)
                    except Exception:
                        extra = []
                    batch = batch + extra[:40 - len(batch)]
                if batch:
                    # Results are cached for a week, so a quiet log here means
                    # every address is already known, not that nothing is running.
                    self.log.add(DNS, f"Looking up {len(batch)} new address(es)")
                for ip in batch:
                    with self._lock:
                        if ip in self._pending:
                            continue
                        self._pending.add(ip)
                        self._started[ip] = time.time()
                    self._executor.submit(self._resolve, ip)
            except Exception:
                import traceback
                traceback.print_exc()
            self._stop.wait(self.poll_s)

    def _resolve(self, ip: str) -> None:
        name, how = None, "none"
        started = time.time()
        try:
            name, how = reverse(ip, timeout_s=self.timeout_s,
                                server=self.server or None,
                                use_nslookup=self.use_nslookup)
        except Exception:
            name, how = None, "error"

        if not name and self.ipam_db is not None:
            try:
                lease = self.ipam_db.dhcp_lease_for_ip(ip)
                if lease and lease["hostname"]:
                    name, how = lease["hostname"], "dhcp"
            except Exception:
                pass

        elapsed = time.time() - started
        # The method is logged because it is the useful diagnostic: a name
        # that only nslookup or DHCP finds says DNS itself has nothing for
        # this address, not that the lookup failed outright.
        self.log.add(DNS, f"PTR {ip} \u2192 {name or 'no record'} "
                          f"[{how}] ({elapsed:.2f}s)")
        try:
            self.app_db.set_hostname(ip, name)
            if self.on_resolved:
                self.on_resolved(ip, name)
        except Exception:
            pass
        with self._lock:
            self._pending.discard(ip)
            self._started.pop(ip, None)


class AsnResolver:
    """Fills in ASN/organization for hop addresses, out of band — the same
    pattern as Resolver, against the longer-lived asn_cache table instead of
    the hostnames cache, since ASN assignment changes far less often than a
    PTR record. Targets exactly the addresses Resolver already names
    (db.distinct_hop_ips()), so there is no separate IP-discovery mechanism:
    every hop that gets a reverse-DNS name is a candidate for an ASN too.
    """

    def __init__(self, db: Database, app_db, workers: int = 4,
                 poll_s: float = 30.0, timeout_s: float = 3.0,
                 cache_ttl_s: float = 30 * 86400, server: str = "",
                 on_resolved=None, log=None):
        self.db = db
        self.app_db = app_db
        self.workers = workers
        self.poll_s = poll_s
        self.timeout_s = timeout_s
        self.cache_ttl_s = cache_ttl_s
        self.server = server or ""
        self.on_resolved = on_resolved
        self.log = log or NullLog()
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def configure(self, workers: int, timeout_s: float,
                  cache_ttl_s: float | None = None,
                  server: str | None = None) -> None:
        self.timeout_s = float(timeout_s)
        if cache_ttl_s:
            self.cache_ttl_s = float(cache_ttl_s)
        if server is not None:
            self.server = server or ""
        workers = max(1, int(workers))
        if workers != self.workers:
            previous = self._executor
            self._executor = ThreadPoolExecutor(max_workers=workers)
            self.workers = workers
            previous.shutdown(wait=False)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netpath-asn", daemon=True)
        self._thread.start()
        self.log.add(SYSTEM, f"ASN/owner resolver started "
                             f"({self.workers} threads, {self.timeout_s:.0f}s timeout)")

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        self.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def inflight(self) -> set[str]:
        with self._lock:
            return set(self._pending)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                batch = self.app_db.unknown_asn_ips(
                    self.db.distinct_hop_ips(), self.cache_ttl_s)[:40]
                for ip in batch:
                    with self._lock:
                        if ip in self._pending:
                            continue
                        self._pending.add(ip)
                    self._executor.submit(self._resolve, ip)
            except Exception:
                import traceback
                traceback.print_exc()
            self._stop.wait(self.poll_s)

    def _resolve(self, ip: str) -> None:
        try:
            asn, org = asn_lookup(ip, server=self.server, timeout_s=self.timeout_s)
        except Exception:
            asn, org = None, None
        self.log.add(DNS, f"ASN {ip} → "
                          f"{f'AS{asn} ({org})' if asn else 'none/private'}")
        try:
            self.app_db.set_asn(ip, asn, org)
            if self.on_resolved:
                self.on_resolved(ip, asn, org)
        except Exception:
            pass
        with self._lock:
            self._pending.discard(ip)


class HopProber:
    """Continuous, MTR-style per-hop probing for targets that opt in.

    A scheduled traceroute (Monitor) says what the path looked like at one
    moment; this fills the gaps between those moments with a steady stream of
    single pings to every hop already seen on a target's most recent trace,
    so loss/RTT stats accumulate continuously instead of only refreshing at
    the traceroute's own interval. It learns which addresses to probe from
    Monitor's completed traces rather than discovering hops on its own — no
    separate topology logic to keep in sync.

    Off by default, opt-in per target: this adds a sustained stream of ICMP
    traffic to every hop of every enabled target's path, which is a real cost
    on a production network, not just background CPU.
    """

    def __init__(self, db: Database, workers: int = 8, interval_s: float = 4.0,
                 timeout_s: float = 1.5, log=None):
        self.db = db
        self.workers = workers
        self.interval_s = interval_s
        self.timeout_s = timeout_s
        self.log = log or NullLog()
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._enabled: set[int] = set()
        self._hops: dict[int, set[str]] = {}
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_enabled(self, target_id: int, enabled: bool) -> None:
        with self._lock:
            if enabled:
                self._enabled.add(target_id)
            else:
                self._enabled.discard(target_id)
                self._hops.pop(target_id, None)
        if enabled:
            self.refresh_hops(target_id)

    def sync_enabled(self, targets) -> None:
        """Reconcile the enabled set with each target row's own flag, e.g. on
        startup or after targets are reloaded from the database."""
        with self._lock:
            self._enabled = {t["id"] for t in targets
                             if "hop_probe_enabled" in t.keys() and t["hop_probe_enabled"]}

    def refresh_hops(self, target_id: int) -> None:
        """Learn which hop IPs to probe from the target's latest completed
        trace. Meant to be called from Monitor's on_complete callback, so
        continuous probing always tracks the current path. Clears
        accumulated stats for any hop that has dropped off the path, so a
        route change never blends old-path and new-path numbers together."""
        with self._lock:
            if target_id not in self._enabled:
                return
        try:
            last = self.db.last_trace(target_id)
            if last is None:
                return
            rows = self.db.hop_rows_for_trace(last["id"])
        except Exception:
            return
        current = {row["ip"] for row in rows if row["ip"]}
        with self._lock:
            previous = self._hops.get(target_id, set())
            self._hops[target_id] = current
        if previous and previous != current:
            try:
                self.db.reset_hop_stats(target_id, current)
            except Exception:
                pass

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        try:
            self.sync_enabled(self.db.targets())
            for target_id in list(self._enabled):
                self.refresh_hops(target_id)
        except Exception:
            pass
        self._thread = threading.Thread(target=self._loop, name="netpath-hopprobe", daemon=True)
        self._thread.start()
        self.log.add(SYSTEM, f"Continuous hop probing started "
                             f"({self.workers} threads, every {self.interval_s:.0f}s)")

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        self.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                jobs = [(target_id, ip) for target_id, ips in self._hops.items()
                        if target_id in self._enabled for ip in ips]
            for target_id, ip in jobs:
                if self._stop.is_set():
                    break
                try:
                    self._executor.submit(self._probe_one, target_id, ip)
                except RuntimeError:
                    break
            self._stop.wait(self.interval_s)

    def _probe_one(self, target_id: int, ip: str) -> None:
        try:
            result = ping(ip, timeout_s=self.timeout_s)
            self.db.record_hop_probe(target_id, ip, result)
        except Exception:
            pass

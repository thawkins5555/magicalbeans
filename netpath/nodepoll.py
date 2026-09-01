"""NodePoller: the per-device SNMP/ping scheduler.

Monitor-shaped, not IpamWorker-shaped — a hot-resizable ThreadPoolExecutor,
restart-safe per-device due-time seeding (from the device's own
last_poll_ts, so a service restart does not fire every device at once),
reschedule-before-run, overrun logging, and a wrap-everything/finally
worker discipline, all copied from netpath/monitor.py's Monitor class.
Nodes will typically manage far more devices than IPAM manages subnets, so
the finer-grained, restart-safe scheduling Monitor already has is the
right shape, not IpamWorker's coarser "unseen = immediately due" one.
"""

from __future__ import annotations

import random
import socket
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import nodeoids
from .eventlog import ERROR, NODES, NullLog
from .ipam_scan import ping_many
from .nodediscover import DiscoveryJob
from .nodeoids import DEFAULT_SNMP_PORT
from .nodesdb import NodesDatabase
from .snmppoll import (
    ERROR_STATUS, PDU_GET, PDU_GETNEXT, PDU_REPORT, Response, SnmpError,
    SnmpTimeout, SnmpUnsupported, build_request, build_v3_request,
    decode_response, discovery_probe,
)
from .trapdecode import localized_key

MAX_UDP = 65535


class EngineCache:
    """One entry per device needing v3: device_id -> (engine_id, boots,
    time, learned_at). A v3 device's first poll after startup (or after
    this entry expires) sends discovery_probe() first, learns engine
    parameters from the Report-PDU, then proceeds with the real signed
    request. Entries are kept for the process lifetime — engine boots/time
    only need refreshing if the target actually reboots or its clock skews
    enough to be rejected, which shows up as an auth failure and triggers
    a fresh discovery on the next poll, not a background expiry timer."""

    def __init__(self):
        self._entries: dict[int, tuple[bytes, int, int, float]] = {}
        self._lock = threading.Lock()

    def get(self, device_id: int):
        with self._lock:
            return self._entries.get(device_id)

    def set(self, device_id: int, engine_id: bytes, boots: int, engine_time: int) -> None:
        with self._lock:
            self._entries[device_id] = (engine_id, boots, engine_time, time.time())

    def invalidate(self, device_id: int) -> None:
        with self._lock:
            self._entries.pop(device_id, None)


class _Session:
    """One UDP socket for one poll: send/recv with retry, closed after."""

    def __init__(self, ip: str, port: int, timeout_s: float, retries: int):
        self.ip = ip
        self.port = port
        self.timeout_s = max(0.2, float(timeout_s))
        self.retries = max(0, int(retries))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout_s)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, packet: bytes) -> Response:
        """Send, wait for a reply, decode it. Retries on timeout up to
        self.retries times; raises SnmpTimeout if every attempt times out."""
        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            try:
                self.sock.sendto(packet, (self.ip, self.port))
                data, _addr = self.sock.recvfrom(MAX_UDP)
                return decode_response(data)
            except socket.timeout:
                last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                continue
            except OSError as exc:
                last_error = SnmpError(str(exc))
                continue
        raise last_error or SnmpTimeout(f"no reply from {self.ip}:{self.port}")


def credential_for(config: dict) -> tuple[str | None, str | None, str | None]:
    """Decrypt-just-in-time, the same shape as ipam_worker.credential_for_server:
    returns (community_or_user, auth_proto, auth_password) with the DPAPI
    blob decrypted immediately before use and never cached. `config` is
    already the effective_config() merge of a device's own overrides over
    its group's defaults."""
    if int(config.get("snmp_version") or 1) == 3:
        identity = config.get("v3_user")
    else:
        identity = config.get("community")
    auth_proto = config.get("v3_auth_proto")
    blob = config.get("v3_auth_pass_enc")
    password = None
    if blob:
        try:
            from . import dpapi
            password = dpapi.unprotect(bytes(blob)).decode("utf-8")
        except Exception:
            password = None
    return identity, auth_proto, password


def counter_rate(previous: int | None, previous_ts: float, current: int | None,
                 current_ts: float, bit_width: int, *,
                 speed_bps: float | None = None) -> float | None:
    """Per-second rate (units of the counter, e.g. bytes/sec for an octet
    counter) from two counter samples, handling wraparound and rejecting
    nonsense. A 32-bit counter that decreased is assumed to have wrapped
    once; a 64-bit counter that decreased is assumed to have been reset
    (rebooted/reinitialized) since a real wrap would take centuries at any
    realistic speed. If speed_bps is given (bits/sec) and the implied rate
    would exceed ~1.3x it, the sample is treated as a reset rather than a
    multi-wrap and None is returned — this is why ifXTable's 64-bit
    counters (nodeoids.IFX_TABLE) are preferred whenever present."""
    if previous is None or current is None:
        return None
    dt = current_ts - previous_ts
    if dt <= 0:
        return None
    if current >= previous:
        rate = (current - previous) / dt
    elif bit_width >= 64:
        return None
    else:
        modulus = 2 ** bit_width
        rate = (modulus - previous + current) / dt
    if speed_bps and rate * 8 > speed_bps * 1.3:
        return None
    return rate


def detect_reboot(uptime_ticks: int, uptime_ts: float, previous_ticks: int | None,
                  previous_ts: float) -> tuple[bool, str]:
    """sysUpTime is a TimeTicks (hundredths of a second) since the agent's
    own last (re)initialization, wrapping at ~497 days (2**32 hundredths).
    A reboot is detected when the current uptime is significantly smaller
    than the previous reading, ruling out two false-positive cases: a
    497-day wrap (only plausible when the previous reading was already
    enormous) and ordinary jitter (a 30-second grace band)."""
    if previous_ticks is None:
        return False, ""
    elapsed_s = uptime_ts - previous_ts
    if elapsed_s <= 0:
        return False, ""
    grace_ticks = 30 * 100
    if uptime_ticks + grace_ticks >= previous_ticks:
        return False, ""   # uptime kept increasing (or barely dipped): normal
    wrap_modulus = 2 ** 32
    near_wrap = previous_ticks > wrap_modulus - (elapsed_s * 100 + grace_ticks) * 2
    if near_wrap:
        return False, ""
    return True, (f"uptime dropped from {previous_ticks} to {uptime_ticks} "
                  f"hundredths of a second after {elapsed_s:.0f}s")


def _credential_label(config: dict) -> str:
    """How to name the credential in an operator-facing message, without
    ever printing the credential itself: a community string is a secret."""
    version = int(config.get("snmp_version") or 1)
    if version == 3:
        user = config.get("v3_user")
        return f"SNMPv3 user {user!r}" if user else "SNMPv3 (no user set)"
    name = {0: "v1", 1: "v2c"}.get(version, f"v{version}")
    return (f"the SNMP{name} community" if config.get("community")
            else f"SNMP{name} with no community set")


def _oid_key(oid: str) -> tuple:
    """An OID as a tuple of ints, so "…1.10" orders after "…1.9" rather than
    between "…1.1" and "…1.2" the way string comparison would put it. A
    malformed arc sorts as a string after every numeric one — the caller only
    ever asks "did the walk advance?", and a garbled answer did not."""
    return tuple((0, int(arc)) if arc.isdigit() else (1, arc)
                 for arc in str(oid).split("."))


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return f"{age / 3600:.1f}h ago"


class NodePoller:
    def __init__(self, db: NodesDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._queued: dict[int, float] = {}
        self._started: dict[int, float] = {}
        self._next_run: dict[int, float] = {}
        # device_id -> when it was last pinged, so ping_interval_s can
        # decouple ICMP probing from the SNMP poll cadence.
        self._last_ping: dict[int, float] = {}
        self._engines = EngineCache()
        self._discovery_jobs: dict[int, DiscoveryJob] = {}
        self._last_completed: float = 0.0
        # device_id -> index into db.credential_candidates(device) that last
        # worked, so a profile with several alternate credentials (a
        # mixed-vendor subnet, say) costs one extra request only on a
        # device's first poll or after its cached credential stops working,
        # not on every poll thereafter. In-memory and process-lifetime only,
        # the same tradeoff EngineCache above already makes.
        self._credentials: dict[int, int] = {}
        # (device_id, expires_ts, interval_s): the device currently selected
        # in a browser polls at interval_s until expires_ts. Renewed by the
        # frontend every refresh tick while selected, so it self-expires
        # when the tab is left or the browser closes — no cleanup path.
        self._focus: tuple[int, float, float] | None = None
        self.counters = {"polls": 0, "ok": 0, "timeout": 0, "auth_fail": 0,
                         "unsupported": 0, "errors": 0, "overruns": 0}
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        workers = max(1, int((settings or self.db.settings()).get("poll_workers", 16)))
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._thread = threading.Thread(target=self._loop, name="node-poller", daemon=True)
        self._thread.start()

    def reconfigure(self, settings: dict) -> None:
        """Hot pool resize, matching Monitor.set_workers: build a new
        executor, swap it in, let the old one drain in-flight work rather
        than cancelling it. Starts/stops the loop only if `enabled`
        actually changed."""
        if settings.get("enabled", True):
            if not self.running:
                self.start(settings)
                return
            workers = max(1, int(settings.get("poll_workers", 16)))
            if self._executor is not None and self._executor._max_workers == workers:
                return
            previous, self._executor = self._executor, ThreadPoolExecutor(max_workers=workers)
            if previous:
                previous.shutdown(wait=False)
        elif self.running:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        for job in list(self._discovery_jobs.values()):
            job.cancel()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def shutdown(self) -> None:
        self.stop()

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return "Poller stopped"
        n = self.db.device_count()
        return f"Polling {n} device(s) · last poll {_ago(self._last_completed)}"

    def worker_state(self) -> dict:
        with self._lock:
            return {device_id: {"queued": self._queued.get(device_id),
                                "started": self._started.get(device_id)}
                    for device_id in set(self._queued) | set(self._started)}

    def next_runs(self) -> dict[int, float]:
        return dict(self._next_run)

    def poll_now(self, device_id: int) -> None:
        self._submit(device_id)

    def set_focus(self, device_id: int, ttl_s: float, interval_s: float) -> None:
        """The device a browser has selected polls at interval_s until the
        TTL lapses. interval_s <= 0 (the setting's off switch) clears any
        focus instead. Pulls the device's next run forward so the first
        fast poll lands promptly rather than after the profile interval."""
        if interval_s <= 0:
            self._focus = None
            return
        now = time.time()
        self._focus = (device_id, now + ttl_s, interval_s)
        due = self._next_run.get(device_id)
        if due is not None and due > now + interval_s:
            self._next_run[device_id] = now + interval_s

    # ------------------------------------------------------------ discovery

    def start_discovery(self, kind: str, target: str,
                        overrides: dict | None = None,
                        allow_ping_only: bool = False) -> int:
        settings = dict(self.db.settings())
        if overrides:
            settings.update(overrides)
        job_id = self.db.add_discovery_job(kind, target,
                                           allow_ping_only=allow_ping_only)
        job = DiscoveryJob(self.db, job_id, kind, target, settings, log=self.log)
        self._discovery_jobs[job_id] = job
        job.start()
        return job_id

    def cancel_discovery(self, job_id: int) -> None:
        job = self._discovery_jobs.get(job_id)
        if job is not None:
            job.cancel()

    def discovery_running(self, job_id: int) -> bool:
        job = self._discovery_jobs.get(job_id)
        return job is not None and job.running

    def promote(self, job_id: int, result_ids: list[int]) -> list[int]:
        """Creates a devices row per discovery result, carrying the
        discovered community/version as a per-device override only when it
        matches none of the target group's own credentials — its primary
        credential or any additional one — so a device that a profile's
        existing credential list already covers keeps trying that shared
        list (and benefits from any future credential added to the
        profile) instead of being pinned to one override. Already-promoted
        result ids are a no-op rather than a duplicate-IP error, so a
        second promote call with an overlapping selection is always safe
        to retry. A ping-only result (no SNMP answer) is skipped outright
        unless its job was started with the allow-ping-only option — the
        checkbox state in the browser is a convenience, this is the rule."""
        job = self.db.discovery_job(job_id)
        allow_ping_only = bool(job and job["allow_ping_only"])
        device_ids = []
        for result_id in result_ids:
            result = self.db.discovery_result(result_id)
            if result is None or result["job_id"] != job_id:
                continue
            if not result["snmp_ok"] and not allow_ping_only:
                continue
            if result["promoted_device_id"]:
                device_ids.append(result["promoted_device_id"])
                continue
            existing = self.db.device_by_ip(result["ip"])
            if existing is not None:
                self.db.mark_promoted(result_id, existing["id"])
                device_ids.append(existing["id"])
                continue
            group_id = result["suggested_group_id"]
            group_row = self.db.group(group_id) if group_id else None
            overrides = {}
            if result["snmp_ok"] and result["community_or_user"]:
                known = [group_row] + list(self.db.group_credentials(group_id)) \
                       if group_row is not None else []
                matches_known = any(
                    g["community"] == result["community_or_user"]
                    and g["snmp_version"] == result["snmp_version"] for g in known)
                if not matches_known:
                    overrides["community"] = result["community_or_user"]
                    overrides["snmp_version"] = result["snmp_version"]
            elif not result["snmp_ok"]:
                # A ping-only device would otherwise sit failing SNMP on
                # every poll; it can be switched back on in its Edit form
                # once real credentials are known.
                overrides["snmp_enabled"] = 0
                overrides["ping_enabled"] = 1
            # The manual name is left as the IP (add_device's default):
            # the displayed name prefers sys_name on its own, so copying
            # sysName into the manual field would only shadow later
            # renames on the device.
            device_id = self.db.add_device(
                result["ip"], group_id=group_id, **overrides)
            if result["snmp_ok"]:
                self.db.seed_identity(
                    device_id, sys_descr=result["sys_descr"] or "",
                    sys_name=result["sys_name"] or "",
                    sys_object_id=result["sys_object_id"] or "",
                    vendor=result["vendor"] or "")
            self.db.mark_promoted(result_id, device_id)
            device_ids.append(device_id)
        return device_ids

    # ------------------------------------------------------------------ loop

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            focus = self._focus
            for device in self.db.devices():
                if not device["enabled"]:
                    continue
                config = self.db.effective_config(device)
                interval = config["poll_interval_s"]
                # The device selected in a browser polls faster (SNMP
                # devices only — a fast ping-only cadence shows nothing
                # new) until its focus TTL lapses.
                focused = (focus is not None and device["id"] == focus[0]
                           and now < focus[1] and config.get("snmp_enabled", True))
                if focused:
                    interval = min(interval, focus[2])
                due = self._next_run.get(device["id"])
                if due is None:
                    due = (device["last_poll_ts"] + interval) if device["last_poll_ts"] else now
                    self._next_run[device["id"]] = due
                if now >= due:
                    self._next_run[device["id"]] = now + interval
                    if device["id"] in self._started or device["id"] in self._queued:
                        # A poll slower than the fast focus cadence is
                        # expected, not an overrun worth logging — only
                        # blowing the device's own profile interval is.
                        if not (focused and interval < config["poll_interval_s"]):
                            self._record_overrun(device, now)
                    else:
                        self._submit(device["id"])
            self._stop.wait(1.0)

    def _submit(self, device_id: int) -> None:
        with self._lock:
            if device_id in self._queued or device_id in self._started:
                return
            self._queued[device_id] = time.time()
        try:
            self._executor.submit(self._run_one, device_id)
        except RuntimeError:
            with self._lock:
                self._queued.pop(device_id, None)

    def _record_overrun(self, device, now) -> None:
        self.counters["overruns"] += 1
        running_for = now - self._started.get(device["id"], now)
        interval = self.db.effective_config(device)["poll_interval_s"]
        self.log.add(ERROR, f"Poll overrun for {device['name'] or device['ip']}: "
                            f"still running after {running_for:.0f}s, interval is "
                            f"{interval}s — lengthen the interval or shorten the "
                            f"timeout.", target=device["ip"])
        self.db.record_device_event(device["id"], "poll_overrun",
                                    f"running {running_for:.0f}s")

    def _run_one(self, device_id: int) -> None:
        """Wrapped entirely in except Exception (a scheduler thread must
        never die quietly); finally always clears _queued/_started for
        this id regardless of outcome."""
        with self._lock:
            self._queued.pop(device_id, None)
            self._started[device_id] = time.time()
        try:
            device = self.db.device(device_id)
            if device is None or not device["enabled"]:
                return
            config = self.db.effective_config(device)
            self.counters["polls"] += 1
            self._poll_device(device, config)
        except Exception:
            self.counters["errors"] += 1
            self.log.add(ERROR, f"Node poll worker error for device #{device_id}",
                         detail=traceback.format_exc())
            traceback.print_exc()
        finally:
            with self._lock:
                self._started.pop(device_id, None)
                self._last_completed = time.time()

    # ---------------------------------------------------------------- poll

    def _poll_device(self, device, config: dict) -> None:
        device_id = device["id"]
        ip = device["ip"]
        now = time.time()

        settings = self.db.settings()
        ping_ok = None
        ping_rtt_ms = None
        ping_loss_pct = None
        if config.get("ping_enabled"):
            # Several probes, not one: a single probe can only ever report
            # 0% or 100% loss, which is no use for spotting a link that is
            # up but dropping a fifth of its traffic. The timeout is its own
            # setting rather than snmp_timeout_s borrowed — ICMP round trips
            # and SNMP round trips have nothing to do with each other, and
            # tying them meant raising an SNMP timeout silently slowed every
            # ping.
            interval = float(settings.get("ping_interval_s", 0) or 0)
            due = (interval <= 0
                   or (now - self._last_ping.get(device_id, 0.0)) >= interval)
            if due:
                self._last_ping[device_id] = now
                sent, received, rtt = ping_many(
                    ip, count=int(config.get("ping_count", 3) or 1),
                    timeout_ms=int(config.get("ping_timeout_ms", 1000) or 1000))
                ping_ok = received > 0
                ping_rtt_ms = rtt
                ping_loss_pct = 100.0 * (sent - received) / sent if sent else None
            else:
                # Not this device's turn to be pinged. The last known result
                # still stands: skipping a probe must not read as a failed
                # one, and record_poll overwrites both columns every time, so
                # the previous RTT has to be carried forward too or the device
                # row would blank it on every poll between pings.
                previous_ok = device["ping_ok"]
                ping_ok = None if previous_ok is None else bool(previous_ok)
                ping_rtt_ms = device["ping_rtt_ms"]

        snmp_ok = None
        snmp_error = ""
        identity = None
        uptime_ticks = None
        interfaces: list[dict] = []
        metrics: list[tuple] = []   # (key, label, unit, kind, value)

        if config.get("snmp_enabled"):
            try:
                cred_config, identity, uptime_ticks, metrics = \
                    self._poll_snmp_scalars_with_credential(device, config)
                interfaces = self._poll_interfaces(device, cred_config)
                if config.get("mib_file_id"):
                    metrics = metrics + self._poll_custom_mib(
                        device, cred_config, config["mib_file_id"])
                snmp_ok = True
            except SnmpUnsupported as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self.counters["unsupported"] += 1
            except SnmpTimeout as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self.counters["timeout"] += 1
            except _AuthFailure as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self.counters["auth_fail"] += 1
            except SnmpError as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self.counters["errors"] += 1

        # -------------------------------------------------------- status

        down_after = int(settings.get("down_after_failures", 3))
        if not config.get("snmp_enabled"):
            # A ping-only device by design (SNMP off entirely) is reachable
            # by ping alone, regardless of the "degrade gracefully when
            # SNMP is failing" setting below — that setting is about a
            # device that normally has SNMP on, not one configured without
            # it. Ping-only is documented as a first-class configuration.
            reachable = bool(ping_ok)
        elif not config.get("ping_enabled"):
            # Nothing is pinging it, so SNMP is the only evidence there is.
            reachable = bool(snmp_ok)
        else:
            # Both probes run, so DOWN means both failed. A device answering
            # ICMP with a broken community string is reachable and
            # misconfigured; reporting it down hides the SNMP error behind
            # an outage that isn't happening. Per device and per profile,
            # because occasionally SNMP failing really is the outage.
            ping_only_ok = bool(config.get("unreachable_ping_only", True))
            reachable = bool(snmp_ok) or (ping_only_ok and bool(ping_ok))

        if snmp_ok is False and snmp_error and "unsupported" in snmp_error.lower():
            status = "unsupported"
        elif reachable:
            status = "up"
        elif device["consecutive_fail"] + 1 >= down_after:
            status = "down"
        else:
            status = device["status"] if device["status"] in ("up", "down") else "unknown"

        # Recorded before record_poll so a device that goes on to be marked
        # down still leaves the loss sample that explains why.
        if ping_loss_pct is not None:
            self.db.record_metric_sample(
                device_id, "ping_loss_pct", "Packet loss", "%", "gauge",
                now, ping_loss_pct)
        if ping_rtt_ms is not None:
            self.db.record_metric_sample(
                device_id, "ping_rtt_ms", "Ping response time", "ms", "gauge",
                now, ping_rtt_ms)

        previous = self.db.record_poll(
            device_id, ping_ok=ping_ok, ping_rtt_ms=ping_rtt_ms, snmp_ok=snmp_ok,
            snmp_error=snmp_error, identity=identity, uptime_ticks=uptime_ticks,
            status=status, reachable=reachable)
        if previous is None:
            return

        if self.counters is not None and snmp_ok:
            self.counters["ok"] += 1

        # ---------------------------------------------------------- debug
        # A per-poll trace, the same idea as monitor.py's own trace-logging
        # convention (command + raw output in `detail`) — this is the
        # concrete answer to "there should be a way to debug this": before
        # this, `eventlog.NODES` was imported and never once used, so a
        # device silently failing to poll left no record anywhere beyond
        # its own current status/error fields.
        detail_lines = [
            f"ping       {'n/a' if ping_ok is None else ('ok' if ping_ok else 'no reply')}"
            + (f" ({ping_rtt_ms:.0f} ms)" if ping_rtt_ms is not None else ""),
            f"snmp       {'n/a' if snmp_ok is None else ('ok' if snmp_ok else 'failed')}",
        ]
        if snmp_ok:
            detail_lines.append(f"interfaces {len(interfaces)}")
            detail_lines.append(f"metrics    {len(metrics)}")
        elif snmp_error:
            detail_lines.append(f"error      {snmp_error}")
        detail_lines.append(f"elapsed    {time.time() - now:.2f}s")
        self.log.add(NODES, f"Polled {device['ip']}: {status}", target=device["ip"],
                    detail="\n".join(detail_lines))

        # -------------------------------------------------------- events

        was_status = previous["status"]
        first_poll = previous["last_poll_ts"] is None
        if status == "up" and was_status not in ("up",) and not first_poll:
            self.db.record_device_event(device_id, "up", "responding again")
        elif status == "down" and was_status != "down":
            self.db.record_device_event(device_id, "down", snmp_error or "not responding")
        elif status == "unsupported" and was_status != "unsupported":
            self.db.record_device_event(device_id, "unsupported", snmp_error)

        if snmp_ok is False and snmp_error and isinstance(snmp_error, str) and \
           "auth" in snmp_error.lower():
            self.db.record_device_event(device_id, "auth_fail", snmp_error)
        elif snmp_ok:
            if previous["snmp_ok"] is False if "snmp_ok" in previous.keys() else False:
                self.db.record_device_event(device_id, "auth_ok", "")

        if uptime_ticks is not None:
            rebooted, note = detect_reboot(
                uptime_ticks, now, previous["last_uptime_ticks"],
                previous["last_uptime_ts"] or now)
            if rebooted:
                self.db.record_device_event(device_id, "rebooted", note)

        self._check_vendor_mib(device_id, previous, identity)

        # ----------------------------------------------------- interfaces

        if interfaces:
            # Captured before replace_interfaces() overwrites descr/alias/
            # admin_status/oper_status — comparing against a post-replace
            # read would always compare the new value to itself and never
            # detect a link_up/link_down transition.
            existing = {row["if_index"]: row for row in self.db.interfaces(device_id)}
            result = self.db.replace_interfaces(device_id, interfaces)
            for row in interfaces:
                if_index = row["if_index"]
                prior = existing.get(if_index)
                in_bps = out_bps = in_err_rate = out_err_rate = None
                if prior is not None:
                    in_bps = counter_rate(
                        prior["last_in_octets"], prior["last_sample_ts"] or 0,
                        row.get("in_octets"), now, row.get("_octet_bits", 32),
                        speed_bps=row.get("speed_bps"))
                    out_bps = counter_rate(
                        prior["last_out_octets"], prior["last_sample_ts"] or 0,
                        row.get("out_octets"), now, row.get("_octet_bits", 32),
                        speed_bps=row.get("speed_bps"))
                    # ifInErrors/ifOutErrors are 32-bit counters; the rate
                    # is errors per second between polls.
                    in_err_rate = counter_rate(
                        prior["last_in_errors"], prior["last_sample_ts"] or 0,
                        row.get("in_errors"), now, 32)
                    out_err_rate = counter_rate(
                        prior["last_out_errors"], prior["last_sample_ts"] or 0,
                        row.get("out_errors"), now, 32)
                self.db.update_interface_rate(
                    device_id, if_index, in_octets=row.get("in_octets"),
                    out_octets=row.get("out_octets"),
                    in_errors=row.get("in_errors"), out_errors=row.get("out_errors"),
                    in_bps=in_bps, out_bps=out_bps,
                    in_error_rate=in_err_rate, out_error_rate=out_err_rate, ts=now)
                interface_id = self.db.interface_id_for(device_id, if_index)
                if interface_id is not None and prior is not None:
                    if prior["oper_status"] and prior["oper_status"] != row.get("oper_status"):
                        kind = "link_up" if row.get("oper_status") == "up" else "link_down"
                        if row.get("oper_status") in ("up", "down"):
                            self.db.record_interface_event(
                                interface_id, kind,
                                f"{row.get('descr') or if_index}: {prior['oper_status']} -> {row.get('oper_status')}")
                if interface_id is not None:
                    label = row.get("descr") or f"if{if_index}"
                    for suffix, unit, value in (
                        ("in_bps", "bps", in_bps), ("out_bps", "bps", out_bps),
                        ("in_err", "err/s", in_err_rate),
                        ("out_err", "err/s", out_err_rate),
                    ):
                        if value is not None:
                            self.db.record_metric_sample(
                                device_id, f"if_{suffix}.{if_index}",
                                f"{label} {suffix}", unit, "gauge", now, value)

        for key, label, unit, kind, value in metrics:
            self.db.record_metric_sample(device_id, key, label, unit, kind, now, value)

    def working_config(self, device) -> dict:
        """The config an *on-demand* read should use — effective_config()
        merged with the credential this device actually answers on.

        effective_config() resolves a device's overrides over its profile's
        own columns, which is the profile's PRIMARY credential and nothing
        else. But a profile can carry alternates (group_credentials, for a
        mixed-vendor subnet), and the scheduled poller finds whichever one
        works and caches it in self._credentials. Any on-demand read that
        built its own config straight from effective_config() therefore
        queried a device that answers on an alternate with the wrong
        community — every request ignored, every read a timeout, on a device
        the poller shows as up. That is what made the OID browser report
        "the device stopped answering" for every device, and what left the
        MAC-address and DOM reads quietly empty on the same devices.

        One candidate (the overwhelmingly common case, and any device with
        its own credential override) costs nothing extra: it *is*
        effective_config. With alternates, the poller's cached winner is
        trusted; only a device the poller has not resolved yet is probed
        here, one cheap GET per candidate, and the winner is cached the same
        way the poll path caches it.
        """
        config = self.db.effective_config(device)
        candidates = self.db.credential_candidates(device)
        if len(candidates) <= 1:
            return config
        cached = self._credentials.get(device["id"])
        if cached is not None and cached < len(candidates):
            return {**config, **candidates[cached]}
        for index, candidate in enumerate(candidates):
            trial = {**config, **candidate}
            try:
                self._snmp_get(device, trial,
                               [nodeoids.SYSTEM_SCALARS["sys_object_id"]])
            except SnmpError:
                continue
            self._credentials[device["id"]] = index
            return trial
        return config

    def _snmp_get(self, device, config: dict, oids: list[str]) -> Response:
        """One GET round trip against a device, handling v1/v2c/v3
        (noAuthNoPriv/authNoPriv only) transparently."""
        version = int(config.get("snmp_version") or 1)
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity, _proto, _pw = credential_for(config)
                packet = build_request(version, identity or "public", PDU_GET,
                                       random.randint(1, 2**16), oids)
                response = session.request(packet)
                self._check_error_status(response)
                return response

            identity, auth_proto, password = credential_for(config)
            engine = self._engines.get(device["id"])
            if engine is None:
                engine = self._discover_engine(session, device)
            engine_id, boots, engine_time, _learned_at = engine
            auth_key = localized_key(auth_proto, password, engine_id) \
                if auth_proto and password else None
            packet = build_v3_request(
                random.randint(1, 2**16), random.randint(1, 2**16), PDU_GET, oids,
                engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
                user=identity or "", auth_proto=auth_proto, auth_key=auth_key)
            response = session.request(packet)
            if response.pdu_tag == PDU_REPORT:
                # Out of time window, or unknown engine: refresh and fail
                # this attempt cleanly; the next poll re-discovers.
                self._engines.invalidate(device["id"])
                raise _AuthFailure(f"{device['ip']}: engine resync required "
                                   f"(received a Report-PDU)")
            self._check_error_status(response)
            return response
        finally:
            session.close()

    def _discover_engine(self, session: _Session, device) -> tuple:
        probe = discovery_probe()
        response = session.request(probe)
        if not response.engine_id:
            raise SnmpError(f"{device['ip']}: no engine id in discovery reply")
        self._engines.set(device["id"], response.engine_id, response.engine_boots,
                          response.engine_time)
        return self._engines.get(device["id"])

    @staticmethod
    def _check_error_status(response: Response) -> None:
        if response.error_status == 16:   # authorizationError
            raise _AuthFailure("authorization error")

    def _poll_snmp_scalars_with_credential(self, device, config: dict):
        """Resolves which SNMP credential actually works for this device
        this poll, then fetches the system scalars with it — one function,
        so a working credential is never fetched twice. Tries the cached
        last-known-good candidate (from self._credentials) first; on a
        cache miss, or if that candidate no longer works, walks the full
        candidate list from db.credential_candidates() in order. Every
        failure mode a single-credential poll could hit (SnmpTimeout,
        SnmpUnsupported, _AuthFailure, or any other SnmpError) is credential
        -specific in a mixed profile — a v3 authPriv alternate is
        SnmpUnsupported while a v2c alternate right after it might work
        fine — so all of SnmpError's subclasses are caught uniformly here
        and only re-raised, as the last one seen, once every candidate has
        failed. Returns (winning_config, identity, uptime_ticks, metrics);
        raises the same exception _poll_snmp_scalars alone would if no
        candidate works, so the caller's existing except chain still
        classifies the failure exactly as before this feature existed."""
        candidates = self.db.credential_candidates(device)
        cached_index = self._credentials.get(device["id"])
        order = [cached_index] if cached_index is not None and cached_index < len(candidates) else []
        order += [i for i in range(len(candidates)) if i not in order]
        last_error: Exception | None = None
        for index in order:
            trial_config = {**config, **candidates[index]}
            try:
                identity, uptime_ticks, metrics = self._poll_snmp_scalars(device, trial_config)
            except SnmpError as exc:
                last_error = exc
                continue
            self._credentials[device["id"]] = index
            return trial_config, identity, uptime_ticks, metrics
        raise last_error or SnmpTimeout(f"no reply from {device['ip']}")

    def _poll_snmp_scalars(self, device, config: dict):
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        response = self._snmp_get(device, config, oids)
        values = {vb["oid"]: vb["value"] for vb in response.varbinds}
        identity = {
            "sys_descr": values.get(nodeoids.SYSTEM_SCALARS["sys_descr"]) or "",
            "sys_object_id": values.get(nodeoids.SYSTEM_SCALARS["sys_object_id"]) or "",
            "sys_name": values.get(nodeoids.SYSTEM_SCALARS["sys_name"]) or "",
            "sys_contact": values.get(nodeoids.SYSTEM_SCALARS["sys_contact"]) or "",
            "sys_location": values.get(nodeoids.SYSTEM_SCALARS["sys_location"]) or "",
        }
        # sysObjectID first, sysDescr only where that named nothing — a
        # device this app cannot name gets neither a profile suggestion nor a
        # vendor MIB, and plenty of gear answers a generic sysObjectID while
        # describing itself perfectly well in text.
        identity["vendor"], identity["vendor_source"] = nodeoids.identify_vendor(
            identity["sys_object_id"], identity["sys_descr"])
        uptime = values.get(nodeoids.SYSTEM_SCALARS["sys_uptime"])
        uptime_ticks = int(uptime) if isinstance(uptime, (int, float)) else None

        metrics = []
        try:
            extra_response = self._snmp_get(device, config, list(nodeoids.UCD_SNMP.values()))
            extra = {vb["oid"]: vb["value"] for vb in extra_response.varbinds
                     if vb["type"] not in ("noSuchObject", "noSuchInstance")}
            idle = extra.get(nodeoids.UCD_SNMP["cpu_raw_idle"])
            if isinstance(idle, (int, float)):
                metrics.append(("cpu_pct", "CPU", "%", "gauge", max(0.0, 100.0 - float(idle))))
            avail = extra.get(nodeoids.UCD_SNMP["mem_avail_kb"])
            total = extra.get(nodeoids.UCD_SNMP["mem_total_kb"])
            if isinstance(avail, (int, float)) and isinstance(total, (int, float)) and total:
                metrics.append(("mem_pct", "Memory", "%", "gauge",
                               max(0.0, 100.0 * (1 - float(avail) / float(total)))))
        except SnmpError:
            pass   # best-effort: UCD-SNMP-MIB not present on this device

        return identity, uptime_ticks, metrics

    def _check_vendor_mib(self, device_id: int, previous, identity: dict | None) -> None:
        """Vendor autodetection already happens on every poll
        (nodeoids.vendor_for on the device's sysObjectID). This is the
        other half the user asked for: if the vendor is identified but no
        uploaded MIB actually describes that vendor's objects, say so, so
        an admin knows there is a MIB to go and add rather than wondering
        why a device's own metrics never appear.

        Coverage is re-evaluated on every poll and compared against the
        persisted per-device verdict (devices.mib_covered), with events
        recorded only on transitions — the same stored-previous-state
        shape every status transition above uses. Keying off sysObjectID
        changes instead (as the first cut did) made the whole feature
        inert for any device whose identity was already stored — every
        pre-existing device on an upgrade, and every device promoted from
        Discovery (seed_identity pre-fills sysObjectID) — and could
        neither clear when the MIB was later uploaded nor re-fire when a
        covering MIB was deleted. mib_present pairs with mib_missing in
        alertrules.CLEARS, so the upload auto-resolves the alert."""
        if not identity:
            return
        sys_object_id = identity.get("sys_object_id") or ""
        # Only devices whose sysObjectID sits under enterprises have a
        # vendor MIB at all. This is checked before consulting vendor_for:
        # that function longest-prefix-matches trapoids.WELL_KNOWN, which
        # also names standard-tree nodes ("system" for 1.3.6.1.2.1.1), so a
        # device reporting a standard-tree sysObjectID would otherwise be
        # reported as missing a "system MIB" that does not exist.
        vendor = identity.get("vendor") or nodeoids.identify_vendor(
            sys_object_id, identity.get("sys_descr") or "")[0]
        applicable = bool(sys_object_id) and \
            bool(nodeoids.enterprise_root(sys_object_id)) and bool(vendor)
        was_covered = previous["mib_covered"]      # None / 0 / 1
        if not applicable:
            # The coverage question doesn't apply (no identity yet, a
            # standard-tree sysObjectID, or no recognizable vendor); make
            # sure no stale verdict lingers from a previous identity.
            if was_covered is not None:
                self.db.set_mib_covered(device_id, None)
            return
        covered = self.db.has_mib_covering(sys_object_id)
        if covered:
            self._auto_assign_mib(device_id, sys_object_id, vendor)
        if covered and not (was_covered is None or was_covered):
            # uncovered -> covered: the MIB arrived. CLEARS resolves the
            # standing mib_missing alert off this event.
            self.db.record_device_event(
                device_id, "mib_present",
                f"An uploaded MIB now describes {vendor} objects "
                f"({sys_object_id}); vendor-specific data can be decoded.")
        elif not covered and (was_covered is None or was_covered):
            # first verdict, or covered -> uncovered (a MIB was deleted).
            self.db.record_device_event(
                device_id, "mib_missing",
                f"No uploaded MIB describes {vendor} objects ({sys_object_id}). "
                f"Upload the {vendor} MIB under Nodes → Profiles & MIBs to decode "
                f"this device's vendor-specific data.")
        if was_covered is None or bool(was_covered) != covered:
            self.db.set_mib_covered(device_id, covered)

    def _auto_assign_mib(self, device_id: int, sys_object_id: str,
                         vendor: str) -> None:
        """Point a device at its own vendor's MIB once one is present.

        Uploading a MIB used to do nothing for polling until somebody went
        to each device and set the Custom MIB override by hand, so the
        common case — install the bundle for the vendor you actually run —
        left every device still undecoded. Assignment happens only where the
        operator has expressed no preference — and a preference can live on
        the polling profile as well as the device: mib_file_id is an
        _OVERRIDE_COLUMNS entry, so a device-level auto-assignment layered
        over a group whose MIB was chosen by hand would *beat* that choice,
        the opposite of standing aside. Hence the effective (device-or-group)
        value is what is checked, not the device column alone. It is an
        ordinary override afterwards and can be cleared or changed from the
        device like any other.
        """
        device = self.db.device(device_id)
        if device is None:
            return
        if self.db.effective_config(device).get("mib_file_id") is not None:
            return
        mib_file_id = self.db.mib_file_covering(sys_object_id)
        if mib_file_id is None:
            return
        self.db.update_device(device_id, mib_file_id=mib_file_id)
        mib = self.db.mib_file(mib_file_id)
        name = (mib["module"] if mib and mib["module"] else
                (mib["filename"] if mib else str(mib_file_id)))
        # Recorded, not silent: this changes what gets polled every cycle, so
        # it belongs in the device's own event history where it can be seen
        # and undone rather than being discovered from new metric names.
        self.db.record_device_event(
            device_id, "mib_assigned",
            f"Assigned the {name} MIB to this device automatically: it "
            f"describes {vendor} objects ({sys_object_id}) and no MIB had "
            f"been chosen. Change or clear it under this device's Custom MIB "
            f"override.")

    def _poll_custom_mib(self, device, config: dict, mib_file_id: int) -> list[tuple]:
        """A device or its polling profile can be assigned one uploaded
        MIB (nodesdb's mib_file_id override); this polls that MIB's own
        resolved *scalar* objects and reports them under its own names —
        the same best-effort shape as the UCD-SNMP-MIB block above (one
        failed GET never fails the whole poll; a device that doesn't
        answer any of this MIB's objects just contributes nothing).

        mibparse.py stores an OBJECT-TYPE's own OID exactly as its MIB
        clause names it (its position in the tree) — for a genuine
        scalar, the actual instance to GET is that OID with the standard
        ".0" suffix appended, the same convention nodeoids.SYSTEM_SCALARS'
        own hand-written OIDs already bake in. Table objects are out of
        scope here, same as HOST-RESOURCES-MIB never being walked above —
        appending ".0" to a table column's OID (rather than a real row
        index) always misses, so it just silently contributes nothing
        rather than a per-row index-walk this pass doesn't attempt."""
        objects = [o for o in self.db.mib_objects(mib_file_id, resolved_only=True)
                  if not o["is_notification"]]
        if not objects:
            return []
        instance_oids = [f"{o['oid']}.0" for o in objects]
        metrics = []
        try:
            response = self._snmp_get(device, config, instance_oids)
            values = {vb["oid"]: vb for vb in response.varbinds}
            for obj, instance_oid in zip(objects, instance_oids):
                vb = values.get(instance_oid)
                if not vb or vb["type"] in ("noSuchObject", "noSuchInstance"):
                    continue
                if not isinstance(vb["value"], (int, float)):
                    continue   # a string/OID-valued object isn't a chartable metric
                # Always stored as "gauge": a Counter-typed object is
                # charted at its raw, ever-increasing value rather than a
                # computed per-second rate — the same deliberate scope
                # limit as no table-walk support. Rate computation needs a
                # previous-value/previous-ts baseline per metric (see
                # counter_rate() above, used for interface octet/error
                # counters), which isn't worth building for an arbitrary,
                # admin-picked MIB object in this pass.
                metrics.append((f"mib_{obj['name']}", obj["name"], "", "gauge", vb["value"]))
        except SnmpError:
            pass   # best-effort: this MIB's objects aren't answered by this device
        return metrics

    def _poll_interfaces(self, device, config: dict) -> list[dict]:
        """Walks the ifIndex column to discover interfaces, then GETs the
        needed columns for each index in one round trip per interface.
        The ifIndex walk itself opts into raise_on_timeout: this result
        feeds directly into the device's own up/down status, so a genuine
        mid-walk timeout must be reported as the failure it is rather
        than silently returning however many interfaces were found before
        the device stopped answering."""
        indexes = self._walk_indexes(device, config, nodeoids.IF_TABLE["if_index"],
                                     raise_on_timeout=True)
        if not indexes:
            return []
        rows = []
        skipped_timeouts = 0
        for if_index in indexes[:512]:   # a sane ceiling; real devices rarely exceed this
            oids = [f"{oid}.{if_index}" for oid in nodeoids.IF_TABLE.values()]
            ifx_oids = [f"{oid}.{if_index}" for oid in nodeoids.IFX_TABLE.values()]
            try:
                response = self._snmp_get(device, config, oids + ifx_oids)
            except SnmpTimeout:
                # Unlike the ifIndex walk above, one interface's own GET
                # timing out doesn't invalidate the whole poll — the
                # device answered enough to enumerate its interfaces, so
                # the rest are still worth collecting. It's tracked and
                # folded into snmp_error below, though, rather than
                # disappearing the way it silently used to.
                skipped_timeouts += 1
                continue
            except SnmpError:
                continue
            values = {vb["oid"]: vb for vb in response.varbinds}

            def _val(table, key):
                vb = values.get(f"{table[key]}.{if_index}")
                return vb["value"] if vb and vb["type"] not in ("noSuchObject", "noSuchInstance") else None

            speed = _val(nodeoids.IF_TABLE, "if_speed")
            high_speed = _val(nodeoids.IFX_TABLE, "if_high_speed")
            speed_bps = (float(high_speed) * 1_000_000 if isinstance(high_speed, (int, float)) and high_speed
                        else (float(speed) if isinstance(speed, (int, float)) else None))
            hc_in = _val(nodeoids.IFX_TABLE, "if_hc_in_octets")
            hc_out = _val(nodeoids.IFX_TABLE, "if_hc_out_octets")
            in_octets = hc_in if isinstance(hc_in, (int, float)) else _val(nodeoids.IF_TABLE, "if_in_octets")
            out_octets = hc_out if isinstance(hc_out, (int, float)) else _val(nodeoids.IF_TABLE, "if_out_octets")
            octet_bits = 64 if isinstance(hc_in, (int, float)) or isinstance(hc_out, (int, float)) else 32

            admin_raw = _val(nodeoids.IF_TABLE, "if_admin_status")
            oper_raw = _val(nodeoids.IF_TABLE, "if_oper_status")
            in_errors = _val(nodeoids.IF_TABLE, "if_in_errors")
            out_errors = _val(nodeoids.IF_TABLE, "if_out_errors")
            rows.append({
                "if_index": if_index,
                "descr": _val(nodeoids.IF_TABLE, "if_descr") or "",
                "alias": _val(nodeoids.IFX_TABLE, "if_alias") or "",
                "phys_addr": (_val(nodeoids.IF_TABLE, "if_phys_addr") or ""),
                "speed_bps": speed_bps,
                "admin_status": {1: "up", 2: "down", 3: "testing"}.get(
                    int(admin_raw), "") if admin_raw is not None else "",
                "oper_status": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                               5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(
                    int(oper_raw), "") if oper_raw is not None else "",
                "in_octets": int(in_octets) if isinstance(in_octets, (int, float)) else None,
                "out_octets": int(out_octets) if isinstance(out_octets, (int, float)) else None,
                "in_errors": int(in_errors) if isinstance(in_errors, (int, float)) else None,
                "out_errors": int(out_errors) if isinstance(out_errors, (int, float)) else None,
                "_octet_bits": octet_bits,
            })
        if skipped_timeouts:
            self.log.add(NODES, f"{skipped_timeouts} of {len(indexes)} interface(s) on "
                                f"{device['ip']} timed out this poll and were skipped",
                        target=device["ip"])
        return rows

    def _walk_column(self, device, config: dict, base_oid: str,
                     raise_on_timeout: bool = False) -> dict[str, object]:
        """Repeated GETNEXT (works for v1/v2c/v3 alike, avoiding a separate
        GETBULK code path) over one table column: index suffix -> value.
        Stops when the walk leaves base_oid's subtree or hits a safety
        cap.

        `noSuchObject`/`noSuchInstance`/`endOfMibView` and "left the
        subtree" are all genuine, substantive "that's the end of the
        table" signals — handled the same way regardless of
        `raise_on_timeout`. A `SnmpTimeout` mid-walk is different: it
        means the device stopped answering, not that the table ended, so
        by default (every on-demand/best-effort caller — DOM/sensor
        reads, a custom MIB poll) it's still swallowed the same way any
        other `SnmpError` here always has been, but a caller whose result
        actually drives the device's own up/down status
        (`_poll_interfaces`, via `_walk_indexes`) opts in to
        `raise_on_timeout=True` so a genuine mid-poll timeout is reported
        as the real failure it is instead of masquerading as "this
        device just doesn't have any more rows."""
        values: dict[str, object] = {}
        current = base_oid
        for _ in range(512):
            try:
                response = self._snmp_get_next(device, config, current)
            except SnmpTimeout as exc:
                if raise_on_timeout:
                    raise SnmpTimeout(
                        f"{exc} (table walk cut short after {len(values)} row(s))") from exc
                break
            except SnmpError:
                break
            if not response.varbinds:
                break
            vb = response.varbinds[0]
            oid = vb["oid"]
            if not oid or not (oid == base_oid or oid.startswith(base_oid + ".")):
                break
            if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                break
            values[oid[len(base_oid) + 1:]] = vb["value"]
            current = oid
        return values

    def _walk_indexes(self, device, config: dict, base_oid: str,
                      raise_on_timeout: bool = False) -> list[int]:
        indexes: list[int] = []
        for suffix in self._walk_column(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout):
            try:
                indexes.append(int(suffix))
            except ValueError:
                break
        return indexes

    # ENTITY-MIB (RFC 6933) and ENTITY-SENSOR-MIB (RFC 3433) columns used
    # by read_dom() to find a port's transceiver sensors.
    _ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
    _ENT_PHYSICAL_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
    _ENT_ALIAS_MAPPING = "1.3.6.1.2.1.47.1.3.2.1.2"
    _ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
    _ENT_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
    _ENT_SENSOR_PRECISION = "1.3.6.1.2.1.99.1.1.1.3"
    _ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
    _ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
    _ENT_SENSOR_UNITS = "1.3.6.1.2.1.99.1.1.1.6"
    _IF_INDEX_COLUMN = "1.3.6.1.2.1.2.2.1.1"

    _SENSOR_TYPE_UNITS = {3: "V AC", 4: "V DC", 5: "A", 6: "W", 7: "Hz",
                          8: "°C", 9: "%RH", 10: "RPM", 11: "m³/min",
                          12: ""}
    _SENSOR_STATUS = {1: "ok", 2: "unavailable", 3: "nonoperational"}

    def read_dom(self, device_id: int, if_index: int) -> list[dict]:
        """Live on-demand read of ENTITY-SENSOR-MIB sensors belonging to one
        interface — DOM/DDM data on an SFP port (light levels, bias
        current, supply voltage, temperature) on devices that expose it
        the standard way. Walked only while a human has the interface
        dialog open, never on the poll cycle: several table walks per
        call is fine once in a while and wasteful every interval.

        Returns [] when the device lacks ENTITY-MIB/sensor support or maps
        no physical entity to this ifIndex — the dialog says so."""
        device = self.db.device(device_id)
        if device is None:
            return []
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return []

        # entAliasMappingIdentifier maps entPhysicalIndex -> the ifIndex
        # arc it corresponds to; keep the entities mapped to this port.
        alias = self._walk_column(device, config, self._ENT_ALIAS_MAPPING)
        port_entities = set()
        for suffix, value in alias.items():
            target = str(value)
            if target.startswith(self._IF_INDEX_COLUMN + ".") and \
               target.rsplit(".", 1)[-1] == str(if_index):
                try:
                    port_entities.add(int(suffix.split(".")[0]))
                except ValueError:
                    continue
        if not port_entities:
            return []

        contained_in = {}
        for suffix, value in self._walk_column(
                device, config, self._ENT_PHYSICAL_CONTAINED_IN).items():
            try:
                contained_in[int(suffix)] = int(value)
            except (TypeError, ValueError):
                continue

        def belongs_to_port(entity: int) -> bool:
            seen = 0
            while entity and seen < 16:   # a real containment tree is shallow
                if entity in port_entities:
                    return True
                entity = contained_in.get(entity, 0)
                seen += 1
            return False

        sensor_values = self._walk_column(device, config, self._ENT_SENSOR_VALUE)
        if not sensor_values:
            return []
        types = self._walk_column(device, config, self._ENT_SENSOR_TYPE)
        scales = self._walk_column(device, config, self._ENT_SENSOR_SCALE)
        precisions = self._walk_column(device, config, self._ENT_SENSOR_PRECISION)
        statuses = self._walk_column(device, config, self._ENT_SENSOR_STATUS)
        units = self._walk_column(device, config, self._ENT_SENSOR_UNITS)
        descrs = self._walk_column(device, config, self._ENT_PHYSICAL_DESCR)

        sensors = []
        for suffix, raw in sensor_values.items():
            try:
                entity = int(suffix)
            except ValueError:
                continue
            if not belongs_to_port(entity) or not isinstance(raw, (int, float)):
                continue
            sensor_type = int(types.get(suffix) or 0)
            scale = int(scales.get(suffix) or 9)       # 9 = units (10^0)
            precision = int(precisions.get(suffix) or 0)
            # RFC 3433: the reading is value x 10^(3*(scale-9)) with
            # `precision` decimal places already folded into the integer.
            value = raw * (10 ** (3 * (scale - 9))) / (10 ** precision)
            unit = str(units.get(suffix) or "").strip() or \
                self._SENSOR_TYPE_UNITS.get(sensor_type, "")
            sensors.append({
                "entity": entity,
                "label": str(descrs.get(suffix) or f"sensor {entity}"),
                "value": round(value, max(precision, 4)),
                "unit": unit,
                "status": self._SENSOR_STATUS.get(
                    int(statuses.get(suffix) or 0), "unknown"),
            })
        sensors.sort(key=lambda s: s["entity"])
        return sensors

    # BRIDGE-MIB (RFC 4188) columns used by read_mac_table() to map the
    # forwarding-database entries learned on a switch port back to the
    # ifIndex the rest of the app already keys interfaces by.
    _DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
    _DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
    # Q-BRIDGE-MIB (RFC 4363) dot1qTpFdbPort. The table a VLAN-aware switch
    # actually populates, and the one most modern gear answers instead of
    # dot1dTpFdbTable. Its index is <dot1qFdbId>.<6 MAC bytes> rather than
    # the MAC alone, which is why a six-arc-only parser sees nothing here.
    _DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    # CISCO-VTP-MIB vtpVlanState: the VLAN list for the per-VLAN community
    # trick below. 1 == operational.
    _VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
    # Bounds on the Cisco per-VLAN path: a trunk-heavy switch can carry
    # hundreds of VLANs and this runs while a human waits on a dialog.
    _MAX_VLAN_CONTEXTS = 48
    _VLAN_WALK_BUDGET_S = 15.0

    @staticmethod
    def _fdb_entries(fdb_port: dict, target_ports: set, vlan: str | None,
                     vlan_indexed: bool) -> list[dict]:
        """Rows of a forwarding-database column, filtered to one port.

        Both FDB tables carry the learned MAC in the row's own OID suffix,
        so no second GET is needed for the address column. dot1dTpFdbTable
        is indexed by the MAC alone (six arcs); dot1qTpFdbTable prefixes it
        with the filtering-database id, so the MAC is always the **last
        six** arcs and anything before it is the VLAN.
        """
        entries = []
        for suffix, port in fdb_port.items():
            try:
                if int(port) not in target_ports:
                    continue
            except (TypeError, ValueError):
                continue
            parts = suffix.split(".")
            if len(parts) < 6:
                continue
            if vlan_indexed and len(parts) < 7:
                continue
            try:
                mac = ":".join(f"{int(p):02x}" for p in parts[-6:])
            except ValueError:
                continue
            entries.append({
                "mac": mac,
                "vlan": (parts[0] if vlan_indexed else vlan) or "",
            })
        return entries

    def _bridge_ports_for(self, device, config: dict, if_index: int):
        """(bridge ports mapping to this ifIndex, whether the device answered).

        A switch that does not answer dot1dBasePortIfIndex at all is a
        different fact from one that answers and simply has no bridge port
        for this interface, and the caller reports them differently.
        """
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX)
        if not base_port_if_index:
            return set(), False
        ports = set()
        for suffix, value in base_port_if_index.items():
            try:
                if int(value) == if_index:
                    ports.add(int(suffix))
            except (TypeError, ValueError):
                continue
        return ports, True

    def _cisco_vlan_fdb(self, device, config: dict, if_index: int,
                        target_ports: set):
        """Classic Cisco IOS exposes its forwarding database only inside
        per-VLAN SNMP contexts, reached by suffixing the community with
        `@<vlan>`. There is no community to suffix under v3, so that is
        skipped rather than pretended at; and the walk is bounded in both
        VLAN count and wall-clock, because this runs while a human waits on
        an interface dialog and a trunk switch can carry hundreds of VLANs.

        Returns (entries, answered). `answered` reports whether any VLAN
        context produced a bridge-port table, which is how the caller tells
        "this switch cannot tell us" from "it can, and this port has learned
        nothing" on a device whose global context answers neither.
        """
        if int(config.get("snmp_version") or 1) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:          # operational only
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            # VLAN 1002-1005 are the legacy FDDI/token-ring defaults every
            # IOS switch reports and none of them ever learn anything.
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        deadline = time.time() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.time() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            ports = target_ports
            if not ports:
                # On these switches dot1dBasePortIfIndex lives in the same
                # per-VLAN context as the forwarding table, so the global
                # read the caller tried first comes back empty on exactly
                # the devices this path exists for.
                ports, port_answered = self._bridge_ports_for(
                    device, scoped, if_index)
                answered = answered or port_answered
                if not ports:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT)
            entries.extend(self._fdb_entries(fdb_port, ports, vlan, False))
        return entries, answered

    def read_mac_table(self, device_id: int, if_index: int) -> list[dict] | None:
        """Live on-demand read of the MAC addresses learned on one switch
        port — same on-demand-while-the-dialog-is-open shape as read_dom()
        above: walked only when a human asks, never on the poll cycle.

        Three sources, because no single one covers the field. Q-BRIDGE's
        dot1qTpFdbTable is what a VLAN-aware switch actually populates and
        is tried first; the original BRIDGE-MIB dot1dTpFdbTable is the
        fallback; and classic Cisco IOS, which populates neither globally,
        is read per VLAN through the community@vlan convention. The first
        source that yields anything wins — they describe the same port, so
        merging them would double-count.

        Note the MIB catalog has nothing to do with this: polling uses these
        numeric OIDs directly, and an uploaded MIB only ever supplies display
        names. Reading more tables is the only thing that widens coverage.

        Returns None (not []) when the device answers none of them, so the
        dialog can say "no data" instead of "zero MACs learned on this
        port" — those are different facts."""
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        target_ports, answered = self._bridge_ports_for(device, config, if_index)
        is_cisco = (device["vendor"] or "").lower() == "cisco"

        entries = []
        if target_ports:
            entries = self._fdb_entries(
                self._walk_column(device, config, self._DOT1Q_FDB_PORT),
                target_ports, None, True)
            if not entries:
                entries = self._fdb_entries(
                    self._walk_column(device, config, self._DOT1D_FDB_PORT),
                    target_ports, None, False)
        # Deliberately also reached when the global context answered nothing
        # at all: a classic IOS switch hides dot1dBasePortIfIndex in the same
        # per-VLAN contexts as the forwarding table, so bailing out on an
        # empty global read would skip this path on the very devices it is
        # here for.
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_fdb(
                device, config, if_index, target_ports)
            answered = answered or cisco_answered
        if not answered:
            return None

        # One MAC can legitimately appear in several VLANs; dedupe on the
        # pair rather than the address so that stays visible.
        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["mac"], e["vlan"])):
            key = (entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    # Bounds for the OID browser. Generous enough to be useful on a switch,
    # small enough that a dialog someone is sitting in front of cannot hang:
    # a full walk of a large device is tens of thousands of objects and
    # minutes of GETNEXTs, which is why this browses subtrees rather than
    # offering "walk everything".
    _BROWSE_MAX_ROWS = 600
    _BROWSE_BUDGET_S = 20.0

    def walk_subtree(self, device_id: int, base_oid: str,
                     max_rows: int | None = None,
                     budget_s: float | None = None) -> dict | None:
        """Live on-demand GETNEXT walk of one subtree, for the OID browser.

        Same on-demand shape as read_dom()/read_mac_table(): run only while a
        human is looking at the dialog, never on the poll cycle.

        Deliberately not _walk_column(): that returns index-suffix -> value
        for one table column and caps at 512 rows, which is right for its
        callers and wrong here. A browser needs the whole OID, the SNMP type
        and the raw value of every object it passed, and it needs to say why
        it stopped — silently truncating at a cap would make a partial walk
        look like the device's complete answer.

        Returns None when the device is unknown or has SNMP disabled.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None
        base = (base_oid or "").strip().strip(".")
        if not base or not all(part.isdigit() for part in base.split(".")):
            raise ValueError("An OID must be numeric, like 1.3.6.1.2.1.1")

        max_rows = int(max_rows or self._BROWSE_MAX_ROWS)
        deadline = time.time() + float(budget_s or self._BROWSE_BUDGET_S)
        rows: list[dict] = []
        stopped = "end of subtree"
        current = base
        while True:
            if len(rows) >= max_rows:
                stopped = f"stopped at the {max_rows}-row limit"
                break
            if time.time() > deadline:
                stopped = f"stopped after {self._BROWSE_BUDGET_S:.0f}s"
                break
            try:
                response = self._snmp_get_next(device, config, current)
            except SnmpTimeout:
                # Name what was actually tried. "The device stopped
                # answering" alone sent an operator hunting the device when
                # the answer was on this end — which credential we used, and
                # against which address and port.
                stopped = (
                    f"no reply from {device['ip']}:{DEFAULT_SNMP_PORT} "
                    f"using {_credential_label(config)}"
                    + (f" — stopped after {len(rows)} row(s)" if rows else ""))
                break
            except SnmpError as exc:
                stopped = f"SNMP error: {exc}"
                break
            if not response.varbinds:
                stopped = "the device returned nothing"
                break
            vb = response.varbinds[0]
            oid = vb["oid"]
            if not oid or not (oid == base or oid.startswith(base + ".")):
                break                      # walked out of the subtree: done
            if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                break
            # A GETNEXT answer must lexicographically follow the request; a
            # broken agent that echoes the request OID (or goes backwards)
            # would otherwise fill the dialog with the same row until the cap
            # or the clock stopped it, presented as the device's answer.
            if _oid_key(oid) <= _oid_key(current):
                stopped = ("the device answered with a non-increasing OID "
                           f"({oid}) — its SNMP agent is misbehaving")
                break
            rows.append({"oid": oid, "type": vb["type"],
                         "value": vb["value"], "text": vb.get("text")})
            current = oid
        return {"base": base, "rows": rows, "stopped": stopped,
                "complete": stopped == "end of subtree"}

    def browse_bases(self, device_id: int) -> list[dict]:
        """The subtrees the browser opens on: the two every SNMP agent
        answers, plus this device's own vendor arc where its sysObjectID
        names one. Enough to be immediately useful without walking a whole
        switch."""
        bases = [
            {"oid": nodeoids.SYSTEM_BASE, "label": "system"},
            {"oid": nodeoids.INTERFACES_BASE, "label": "interfaces"},
        ]
        device = self.db.device(device_id)
        if device is not None:
            root = nodeoids.enterprise_root(device["sys_object_id"] or "")
            if root:
                vendor = device["vendor"] or "vendor"
                bases.append({"oid": root, "label": f"{vendor} ({root})"})
        return bases

    def _snmp_get_next(self, device, config: dict, oid: str) -> Response:
        version = int(config.get("snmp_version") or 1)
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity, _proto, _pw = credential_for(config)
                packet = build_request(version, identity or "public", PDU_GETNEXT,
                                       random.randint(1, 2**16), [oid])
                return session.request(packet)
            identity, auth_proto, password = credential_for(config)
            engine = self._engines.get(device["id"])
            if engine is None:
                engine = self._discover_engine(session, device)
            engine_id, boots, engine_time, _learned_at = engine
            auth_key = localized_key(auth_proto, password, engine_id) \
                if auth_proto and password else None
            packet = build_v3_request(
                random.randint(1, 2**16), random.randint(1, 2**16), PDU_GETNEXT, [oid],
                engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
                user=identity or "", auth_proto=auth_proto, auth_key=auth_key)
            return session.request(packet)
        finally:
            session.close()


class _AuthFailure(SnmpError):
    """Internal: an authorization/engine-sync failure, reported to the
    device as status 'auth' rather than a generic error or a timeout."""


if __name__ == "__main__":
    # counter_rate / detect_reboot are pure functions and provable without
    # any network at all.
    assert counter_rate(100, 0.0, 200, 10.0, 32) == 10.0
    assert counter_rate(2**32 - 50, 0.0, 50, 10.0, 32) == 10.0        # one 32-bit wrap
    assert counter_rate(2**63, 0.0, 5, 10.0, 64) is None              # 64-bit: reset, not a wrap
    assert counter_rate(0, 0.0, 10**12, 1.0, 32, speed_bps=1e9) is None  # implausible vs. link speed
    assert counter_rate(100, 5.0, 200, 5.0, 32) is None               # dt == 0
    assert counter_rate(None, 0.0, 200, 10.0, 32) is None             # first poll
    print("counter_rate OK")

    ok, note = detect_reboot(100, 1010.0, 500_000, 1000.0)
    assert ok, "a real restart must be detected"
    ok, _ = detect_reboot(29_000, 300.0, 2**32 - 1000, 0.0)
    assert not ok, "a 497-day TimeTicks wrap is not a reboot"
    ok, _ = detect_reboot(130_000, 300.0, 100_000, 0.0)
    assert not ok, "uptime going forwards is not a reboot"
    print("detect_reboot OK")

    print("all self-tests passed")

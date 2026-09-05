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
import sqlite3
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import mibcatalog, nodeoids, vendorid
from .eventlog import ERROR, NODES, NullLog
from .ipam_scan import ping_many
from .nodediscover import DiscoveryJob
from .nodeoids import DEFAULT_SNMP_PORT
from .nodesdb import NodesDatabase, detected_vendor
from .snmppoll import (
    ERROR_STATUS, PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT, Response,
    SnmpError, SnmpTimeout, SnmpUnsupported, build_request, build_v3_request,
    decode_response, discovery_probe,
)
from .trapdecode import localized_key

MAX_UDP = 65535

# RFC 3414 §5's usmStats counters, the objects an agent names in the
# Report-PDU it answers a v3 request it would not process with. Reported by
# name, because "engine resync required" told an operator nothing about
# whether the password was wrong, the clock was out, or the security level
# was refused — three different problems with three different fixes.
USM_STATS = {
    "1.3.6.1.6.3.15.1.1.1": ("unsupportedSecLevels",
                             "the device refused this security level "
                             "(authPriv is not supported by this poller)"),
    "1.3.6.1.6.3.15.1.1.2": ("notInTimeWindows",
                             "the device rejected the message's engine time"),
    "1.3.6.1.6.3.15.1.1.3": ("unknownUserNames",
                             "the device does not know this SNMPv3 user"),
    "1.3.6.1.6.3.15.1.1.4": ("unknownEngineIDs",
                             "the device did not recognise the engine id"),
    "1.3.6.1.6.3.15.1.1.5": ("wrongDigests",
                             "the authentication password or protocol is wrong"),
    "1.3.6.1.6.3.15.1.1.6": ("decryptionErrors",
                             "the device could not decrypt the message"),
}


# The per-interface metric keys one poll emits, in the order they are
# recorded. `in_bps`/`out_bps` and the two `*_err` keys keep the names the
# charts and any stored history already use; the rest are new in 4.39.0.
def _INTERFACE_METRICS(in_bps, out_bps, in_err_rate, out_err_rate,
                       in_disc_rate, out_disc_rate, in_util, out_util):
    return (
        ("in_bps", "bps", in_bps),
        ("out_bps", "bps", out_bps),
        ("in_err", "err/s", in_err_rate),
        ("out_err", "err/s", out_err_rate),
        ("in_error_rate", "err/s", in_err_rate),
        ("out_error_rate", "err/s", out_err_rate),
        ("in_discard_rate", "disc/s", in_disc_rate),
        ("out_discard_rate", "disc/s", out_disc_rate),
        ("in_util_pct", "%", in_util),
        ("out_util_pct", "%", out_util),
    )


# suffix -> (unit, device-level label). A device-level key is the worst
# value across the device's interfaces this poll, which is what a rule
# written against a device rather than a port can usefully mean.
_DEVICE_MAX_KEYS = {
    "in_util_pct": ("%", "Interface inbound utilization (busiest port)"),
    "out_util_pct": ("%", "Interface outbound utilization (busiest port)"),
    "in_error_rate": ("err/s", "Interface inbound errors (worst port)"),
    "out_error_rate": ("err/s", "Interface outbound errors (worst port)"),
    "in_discard_rate": ("disc/s", "Interface inbound discards (worst port)"),
    "out_discard_rate": ("disc/s", "Interface outbound discards (worst port)"),
}


def report_reason(response) -> tuple[str, str]:
    """(usmStats name, plain explanation) for a Report-PDU, or ("", "")
    when it names nothing this table knows."""
    for vb in getattr(response, "varbinds", None) or ():
        oid = str(vb.get("oid") or "")
        # The instance is the counter's OID with .0 appended.
        known = USM_STATS.get(oid) or USM_STATS.get(oid.rsplit(".", 1)[0])
        if known:
            return known
    return "", ""


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

    def current(self, device_id: int):
        """(engine_id, boots, engine_time) with engineTime advanced to now.

        engineTime is the agent's own clock in seconds, and RFC 3414 §3.2
        rejects an authenticated message whose engineTime is more than 150
        seconds from the agent's. Sending back the value learned at
        discovery — as this did — means every v3 device starts failing 150
        seconds after its first poll and keeps failing until something
        invalidates the entry, which the review saw as a spurious
        auth_fail roughly every third poll. The elapsed wall time since
        the value was learned is added instead.
        """
        with self._lock:
            entry = self._entries.get(device_id)
        if entry is None:
            return None
        engine_id, boots, engine_time, learned_at = entry
        elapsed = max(0.0, time.time() - learned_at)
        return engine_id, boots, engine_time + int(elapsed)

    def set(self, device_id: int, engine_id: bytes, boots: int, engine_time: int) -> None:
        with self._lock:
            self._entries[device_id] = (engine_id, boots, engine_time, time.time())

    def invalidate(self, device_id: int) -> None:
        with self._lock:
            self._entries.pop(device_id, None)

    def forget(self, device_ids) -> None:
        """Drop entries for devices that no longer exist. The cache is
        keyed by device id and kept for the process lifetime, so without
        this a long-running install accumulates one entry per device ever
        deleted."""
        keep = set(device_ids)
        with self._lock:
            for device_id in [k for k in self._entries if k not in keep]:
                self._entries.pop(device_id, None)


class _Session:
    """One UDP socket for one poll: send/recv with retry, closed after."""

    def __init__(self, ip: str, port: int, timeout_s: float, retries: int):
        self.ip = ip
        self.port = port
        self.timeout_s = max(0.2, float(timeout_s))
        self.retries = max(0, int(retries))
        # A device on an IPv6 management plane needs an AF_INET6 socket;
        # AF_INET was hardcoded, so every such device timed out on every
        # poll. A literal address is unambiguous — a colon cannot appear in
        # a dotted-quad — and the port is separate, so there is nothing to
        # parse.
        self.family = socket.AF_INET6 if ":" in str(ip) else socket.AF_INET
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout_s)
        # Request ids for this session's own exchanges. A counter from a
        # random start rather than random.randint per request: two requests
        # in one walk drawing the same id by chance is exactly the
        # confusion the id exists to prevent.
        self._request_id = random.randint(1, 2 ** 24)
        self.dropped = 0        # datagrams discarded as not ours

    def next_request_id(self) -> int:
        self._request_id = (self._request_id + 1) % (2 ** 31 - 1) or 1
        return self._request_id

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _is_peer(self, addr) -> bool:
        """Whether a datagram came from the device we asked. `addr` is
        (host, port[, flow, scope]) — only the host is compared, because a
        few agents answer from an ephemeral port rather than 161, which is
        odd but not forgery. IPv6 literals are compared after normalising
        both sides, since 'fe80::1' and 'fe80:0:0:0:0:0:0:1' are the same
        address written two ways."""
        try:
            source = addr[0]
        except (TypeError, IndexError):
            return False
        if source == self.ip:
            return True
        if self.family != socket.AF_INET6:
            return False
        try:
            packed = socket.inet_pton(socket.AF_INET6, source.split("%")[0])
            mine = socket.inet_pton(socket.AF_INET6, self.ip.split("%")[0])
        except (OSError, AttributeError):
            return False
        return packed == mine

    def request(self, packet: bytes, expect_request_id: int | None = None) -> Response:
        """Send, wait for OUR reply, decode it.

        A UDP socket accepts whatever arrives. The first reading of this
        took the first datagram it got — so a late answer to attempt 1 was
        consumed as the answer to attempt 2 (the review reproduced it on a
        device that answers in 2.6 s with a 2 s timeout), and anything
        sent from any other address could be answered with. Now a datagram
        is dropped and the wait continues when it did not come from the
        device, or when it carries a different request id than the one
        sent. A Report-PDU is exempt from the id test: an agent reports an
        engine mismatch against its own msgID, and dropping it would turn
        one v3 resync into a timeout.

        Retries on timeout up to self.retries times; raises SnmpTimeout if
        every attempt times out.
        """
        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            try:
                self.sock.sendto(packet, (self.ip, self.port))
            except OSError as exc:
                last_error = SnmpError(str(exc))
                continue
            deadline = time.monotonic() + self.timeout_s
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                    break
                try:
                    self.sock.settimeout(remaining)
                    data, addr = self.sock.recvfrom(MAX_UDP)
                except socket.timeout:
                    last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                    break
                except OSError as exc:
                    last_error = SnmpError(str(exc))
                    break
                if not self._is_peer(addr):
                    self.dropped += 1
                    continue
                try:
                    response = decode_response(data)
                except SnmpUnsupported:
                    raise
                except SnmpError as exc:
                    # Garbage from the right address is not an answer: keep
                    # waiting for one within this attempt's budget rather
                    # than failing the whole request on it.
                    self.dropped += 1
                    last_error = exc
                    continue
                if (expect_request_id is not None
                        and response.pdu_tag != PDU_REPORT
                        and response.request_id != expect_request_id):
                    self.dropped += 1
                    continue
                return response
        raise last_error or SnmpTimeout(f"no reply from {self.ip}:{self.port}")


def credential_for(config: dict) -> tuple[str | None, str | None, str | None]:
    """Decrypt-just-in-time, the same shape as ipam_worker.credential_for_server:
    returns (community_or_user, auth_proto, auth_password) with the DPAPI
    blob decrypted immediately before use and never cached. `config` is
    already the effective_config() merge of a device's own overrides over
    its group's defaults."""
    if int(config.get("snmp_version", 1)) == 3:
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


def _interface_reassigned(prior: "sqlite3.Row | dict", row: dict) -> bool:
    """True only when there is affirmative evidence that the physical port
    answering at this ifIndex changed between `prior` (last poll's stored
    row) and `row` (this poll's fresh read) -- used to decide, on the poll
    a reboot is first observed, whether an oper_status transition at this
    ifIndex is real or an artifact of the agent renumbering ifIndex across
    the reload (a stack member reboot can move port 5 from ifIndex 10 to
    14).

    ifPhysAddress (the port's burned-in MAC) is checked first: it is tied
    to the hardware itself, not to how the agent currently names or
    numbers the port, so it survives a stack member being renumbered
    without the physical port changing (descr encodes the member number
    and would differ across such a renumbering even though the port is
    the same). ifDescr is the fallback for rows/platforms that leave
    phys_addr blank (common for logical or aggregate interfaces).

    A field that is empty/None on either side is never treated as
    evidence of a change -- only a genuine disagreement between two
    non-empty values counts. Otherwise a platform that simply doesn't
    populate one of these columns would have every reboot treated as an
    ifIndex reassignment, silently reintroducing the bug this function
    exists to fix (every post-reboot oper_status comparison suppressed,
    forever)."""
    for field in ("phys_addr", "descr"):
        old = prior[field] if field in prior.keys() else None
        new = row.get(field)
        if old and new:
            return old != new
    return False


def _credential_label(config: dict) -> str:
    """How to name the credential in an operator-facing message, without
    ever printing the credential itself: a community string is a secret."""
    version = int(config.get("snmp_version", 1))
    if version == 3:
        user = config.get("v3_user")
        return f"SNMPv3 user {user!r}" if user else "SNMPv3 (no user set)"
    name = {0: "v1", 1: "v2c"}.get(version, f"v{version}")
    return (f"the SNMP{name} community" if config.get("community")
            else f"SNMP{name} with no community set")


# Moved to nodeoids in 4.32 so vendorid can share it; kept under its old
# name here so the walk code and its tests read unchanged.
_oid_key = nodeoids.oid_key


def _format_cdp_address(raw) -> str:
    """cdpCacheAddress, as this app's OCTET_STRING decoder hands it back,
    is a space-separated run of hex bytes for anything non-printable (see
    trapdecode._octets_text) — a raw IPv4 address decodes as e.g.
    "0A 00 00 09". Reformatted to dotted-decimal when it is exactly four
    bytes; left as-is (and still informative) for anything else, since a
    real cdpCacheAddress can carry a different protocol's address entirely
    and this app does not attempt every one CISCO-CDP-MIB allows."""
    text = str(raw or "").strip()
    if not text:
        return ""
    parts = text.split()
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return text
    if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
        return ".".join(str(o) for o in octets)
    return text


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


class _OidWalkJob:
    """A whole-device SNMP walk, run on its own thread.

    Its own thread rather than the poll pool: a full walk of a core switch
    is tens of thousands of GETNEXTs and minutes of wall time, and parking
    one of four poll workers on it for that long would stall the devices
    behind it. Exactly one runs per device at a time — a second request
    while one is running is refused politely, the way backup_now does.
    """

    def __init__(self, poller, device_id: int, base: str, max_rows: int,
                 budget_s: float):
        self.poller = poller
        self.device_id = device_id
        self.base = base
        self.max_rows = max_rows
        self.budget_s = budget_s
        self.rows: list[dict] = []
        self.state = "starting"      # starting|running|done|failed
        self.stopped = ""
        self.error = ""
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.device_label = ""
        self._count = 0              # read without the lock by status()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "running")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"oid-walk-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self, with_rows: bool = False) -> dict:
        elapsed = (self.finished_ts or time.time()) - self.started_ts
        result = {"device_id": self.device_id, "state": self.state,
                  "rows": self._count, "elapsed": elapsed,
                  "stopped": self.stopped, "error": self.error,
                  "base": self.base, "started_ts": self.started_ts,
                  "complete": self.stopped == "end of subtree",
                  "device_label": self.device_label}
        if with_rows:
            result["walk"] = list(self.rows)
        return result

    def _run(self) -> None:
        try:
            device = self.poller.db.device(self.device_id)
            if device is None:
                raise ValueError("No such device")
            self.device_label = device["sys_name"] or device["name"] or device["ip"]
            config = self.poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")
            self.state = "running"

            # Progress only: _walk_from owns the list and hands it back
            # whole below, so a status() mid-walk reports a count without
            # racing a list another thread is appending to.
            def note(_row):
                self._count += 1

            rows, stopped = self.poller._walk_from(
                device, config, self.base, self.max_rows, self.budget_s,
                cancelled=self._cancel.is_set, on_row=note)
            self.rows = rows
            self._count = len(rows)
            self.stopped = stopped
            self.state = "done"
        except Exception as exc:                      # a job thread must not die quietly
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            self.poller.log.add(
                ERROR, f"OID walk failed for device #{self.device_id}: {self.error}",
                detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()


class _VendorIdJob:
    """One device's vendor identification, on its own thread.

    Off the poll pool for the same reason _OidWalkJob is: the bounded walk
    is up to a few hundred requests and ~20 s by budget, but a device that
    stops answering half way through pays its timeout per request on top,
    and on a 60 s profile that is an overrun parked on one of the pool's
    workers. Concurrency is capped by NodePoller._maybe_identify instead.
    """

    def __init__(self, poller, device_id: int, trigger: str):
        self.poller = poller
        self.device_id = device_id
        self.trigger = trigger
        self.state = "starting"          # starting|hopping|walking|done|failed
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.requests = 0
        self.objects = 0
        self.arcs: list[int] = []
        self.error = ""
        self.decision = None
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "hopping", "walking")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"vendor-id-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self) -> dict:
        return {"device_id": self.device_id, "state": self.state, "trigger": self.trigger,
                "elapsed": (self.finished_ts or time.time()) - self.started_ts,
                "requests": self.requests, "objects": self.objects,
                "arcs_found": list(self.arcs), "error": self.error,
                "decision": self.decision.json() if self.decision else None}

    def _run(self) -> None:
        poller = self.poller
        db = poller.db
        settings = db.settings()
        hop = None
        rows_by_arc: dict[int, list[str]] = {}
        capped: dict[int, bool] = {}
        candidates: list = []
        walk_info: dict = {}
        error = ""
        device = db.device(self.device_id)
        sys_object_id = (device["sys_object_id"] if device else "") or ""
        previous_attempts = 0
        try:
            if device is None:
                raise ValueError("No such device")
            evidence_before = vendorid._evidence_dict(device)
            if evidence_before.get("error"):
                previous_attempts = int(evidence_before.get("attempts") or 0)
            config = poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")

            # The hop keeps the device's own retries: a missed hop loses an
            # arc. The walk below goes without them.
            self.state = "hopping"

            def getnext(oid):
                if self._cancel.is_set():
                    raise SnmpError("cancelled")
                self.requests += 1
                return poller._getnext_one(device, config, oid)

            hop = vendorid.hop_enterprise_arcs(getnext)
            self.arcs = list(hop.arcs)
            if hop.stopped == "timeout" and not hop.arcs:
                # The hop swallows a timeout on purpose so a partial answer
                # survives — but no answer at all is not an identification,
                # it is a device that did not reply. Recorded as an error so
                # the bounded retries apply instead of this counting as done.
                raise SnmpTimeout(f"no reply from {device['ip']} during the "
                                  f"identification walk")

            self.state = "walking"
            max_objects = int(settings.get("vendor_walk_max_objects", 500) or 500)
            budget_s = float(settings.get("vendor_walk_budget_s", 20.0) or 20.0)
            walk_config = {**config, "snmp_retries": 0}
            deadline = time.time() + budget_s
            walk_started = time.time()
            walk_requests = 0
            stopped = "complete"
            for arc in hop.arcs:
                remaining = max_objects - self.objects
                remaining_s = deadline - time.time()
                if remaining <= 0 or remaining_s <= 0:
                    stopped = ("stopped at the %d-object limit" % max_objects
                               if remaining <= 0 else "stopped after %.0fs" % budget_s)
                    break
                if self._cancel.is_set():
                    stopped = "cancelled"
                    break
                generic = arc in vendorid.GENERIC_ARCS
                per_arc = 20 if generic else min(vendorid.PER_ARC_OBJECTS, remaining)
                per_arc_s = min(vendorid.PER_ARC_BUDGET_S, remaining_s)

                def note(_row):
                    self.objects += 1

                rows, why = poller._walk_from(
                    device, walk_config, f"{nodeoids.ENTERPRISES}.{arc}",
                    max_rows=per_arc, budget_s=per_arc_s,
                    cancelled=self._cancel.is_set, on_row=note)
                walk_requests += len(rows) + 1
                rows_by_arc[arc] = [row["oid"] for row in rows]
                capped[arc] = len(rows) >= per_arc or why.startswith("stopped")
            self.requests += walk_requests
            if self._cancel.is_set():
                # What was gathered is kept and shown, but a cancelled walk
                # is not a verdict: it is recorded as incomplete, so the
                # dialog says so and the bounded retries still apply.
                error = "cancelled"
            walk_info = {"objects": sum(len(v) for v in rows_by_arc.values()),
                         "requests": walk_requests,
                         "elapsed_s": round(time.time() - walk_started, 2),
                         "stopped": stopped}
            candidates = vendorid.fingerprint(rows_by_arc, poller._mib_index_cached())
        except Exception as exc:              # a job thread must not die quietly
            error = ("cancelled" if self._cancel.is_set()
                     else (str(exc) or exc.__class__.__name__))
            if not isinstance(exc, (SnmpError, ValueError)):
                poller.log.add(ERROR, f"Vendor identification failed for device "
                                      f"#{self.device_id}: {error}",
                               detail=traceback.format_exc())
        try:
            device = db.device(self.device_id)
            if device is None:
                self.state = "failed"
                return
            decision = vendorid.decide(
                sys_object_id, device["sys_descr"] or "", hop.arcs if hop else [],
                candidates, manual=device["vendor_override"] or "",
                learned=db.learned_vendor(sys_object_id),
                catalog_arcs=mibcatalog.ARC_KEYS)
            self.decision = decision
            evidence = vendorid.evidence(
                sys_object_id, self.trigger, hop, rows_by_arc, capped, candidates,
                decision, walk_info, catalog_arcs=mibcatalog.ARC_KEYS, error=error,
                attempts=previous_attempts + 1)
            db.record_identification(self.device_id, decision, evidence, sys_object_id)
            poller._apply_identification(self.device_id, decision, error)
            self.error = error
            self.state = "failed" if error else "done"
        except Exception as exc:
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            poller.log.add(ERROR, f"Vendor identification could not be recorded for "
                                  f"device #{self.device_id}: {self.error}",
                           detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()
            poller._bump("identifications")


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
        # device_id -> when its forwarding table was last walked, and which
        # walks are in flight. Its own cadence, well away from the poll
        # cycle: a switch's FDB is hundreds to thousands of rows and is
        # walked at most once per mac_table_interval_s, opt-in per profile.
        self._next_mac_walk: dict[int, float] = {}
        self._mac_running: set[int] = set()
        # device_id -> when its LLDP/CDP neighbour table was last walked, and
        # which walks are in flight. The topology walk's own cadence
        # (lldp_interval_s), mirroring _next_mac_walk/_mac_running exactly —
        # see _maybe_walk_lldp.
        self._next_lldp_walk: dict[int, float] = {}
        self._lldp_running: set[int] = set()
        self._engines = EngineCache()
        self._discovery_jobs: dict[int, DiscoveryJob] = {}
        # device_id -> the whole-device OID walk running or last finished for
        # it. In memory and one-at-a-time per device, the same shape as
        # _discovery_jobs above: a walk result is transient, downloaded once
        # and then dropped.
        self._oid_walks: dict[int, "_OidWalkJob"] = {}
        # device_id -> its running or last vendor identification job, and
        # the MIB corpus index the fingerprint scores against, rebuilt only
        # when nodesdb.mib_generation() says the corpus changed.
        self._vendor_ids: dict[int, "_VendorIdJob"] = {}
        self._mib_index: tuple | None = None       # (generation, MibIndex)
        self._last_completed: float = 0.0
        # The merged per-device configs the scheduling pass reads, and the
        # nodesdb config generation and wall time they were built at.
        self._configs: dict | None = None
        self._configs_generation: int = -1
        self._configs_loaded: float = 0.0
        # device_id -> when its ipAddrTable was last read. See
        # _refresh_addresses: once an hour, not once a poll.
        self._addresses_read: dict[int, float] = {}
        # device_id -> when its ENTITY-SENSOR-MIB table was last walked.
        # See _poll_environment/_SENSOR_REFRESH_S: a fixed cadence, in
        # memory only, the same shape _addresses_read already uses for a
        # walk that answers something that does not change between one
        # poll and the next.
        self._sensor_read: dict[int, float] = {}
        # device_id -> the GETBULK repetition count that last worked for it.
        # A device that answers "tooBig" is retried at half as many rows, and
        # remembering that means the next walk starts where the last one
        # ended up rather than re-learning the same limit every time.
        self._bulk_repetitions: dict[int, int] = {}
        # Forwarding-table walks run here, not on the poll pool: one walk is
        # hundreds to thousands of rows, and parking poll workers on them is
        # what made the pool saturate.
        self._mac_executor: ThreadPoolExecutor | None = None
        # When the pool first looked saturated, and whether that has been
        # reported. See _note_saturation.
        self._saturated_since: float | None = None
        self._saturation_reported = False
        # Set by the application once the alert engine exists, so the poller
        # can raise a system alert about itself. Left None (and every use
        # guarded) so the poller runs standalone in tests and scripts.
        self.alert_engine = None
        # device_id -> index into db.credential_candidates(device) that last
        # worked, so a profile with several alternate credentials (a
        # mixed-vendor subnet, say) costs one extra request only on a
        # device's first poll or after its cached credential stops working,
        # not on every poll thereafter. In-memory and process-lifetime only,
        # the same tradeoff EngineCache above already makes.
        self._credentials: dict[int, int] = {}
        # device_id -> when an on-demand credential probe last failed for it,
        # so a device that is simply down does not re-sweep its profile's
        # candidates on every dialog a human opens. See working_config().
        self._credential_probe_failed: dict[int, float] = {}
        # device_id set: the devices whose SNMP is currently failing on
        # AUTHENTICATION, as this process has observed it. auth_fail is
        # recorded on entering the set and auth_ok only on leaving it, which
        # is what makes both of them transitions. Reading the previous poll's
        # snmp_ok/snmp_error off the device row could not do that: any failure
        # recovering looked like an auth recovery (a WAN device that times out
        # one poll in ten wrote an auth_ok on every recovery), and a
        # multi-credential profile whose recorded error alternates between an
        # auth string and a timeout re-recorded auth_fail every other poll.
        # In memory and process-lifetime only, like _credentials above: a
        # restart re-records one auth_fail per still-failing device, which is
        # one event, not one per poll.
        self._auth_failing: set[int] = set()
        # (device_id, expires_ts, interval_s): the device currently selected
        # in a browser polls at interval_s until expires_ts. Renewed by the
        # frontend every refresh tick while selected, so it self-expires
        # when the tab is left or the browser closes — no cleanup path.
        self._focus: tuple[int, float, float] | None = None
        self.counters = {"polls": 0, "ok": 0, "timeout": 0, "auth_fail": 0,
                         "unsupported": 0, "errors": 0, "overruns": 0,
                         "mac_walks": 0, "identifications": 0,
                         # Tier 1 #5/#7/#8: one counter per new walk, the
                         # same shape mac_walks already has — lldp_walks
                         # counts completed LLDP/CDP walks, poe_polls/
                         # stp_polls/rf_polls count poll-cycle reads that
                         # actually produced data (a device whose capability
                         # probe came back negative never bumps them again).
                         "lldp_walks": 0, "poe_polls": 0, "stp_polls": 0,
                         "rf_polls": 0}
        self.error: str | None = None

    def _bump(self, key: str, by: int = 1) -> None:
        """counters[...] += 1 from a pool worker is a read-modify-write on a
        shared dict; under the lock the totals stay exact."""
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + by

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        workers = max(1, int((settings or self.db.settings()).get("poll_workers", 16)))
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._mac_executor = ThreadPoolExecutor(
            max_workers=self._MAC_WALK_WORKERS, thread_name_prefix="mac-walk")
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

    _MAC_WALK_WORKERS = 4

    def stop(self) -> None:
        """Fast: cancels queued work and returns without waiting for a poll
        already running to finish. Used for a hot restart (start() calls
        this first) and for an operator disabling Nodes polling from
        Settings on an HTTP thread, neither of which should block on the
        network — shutdown() below is the version that waits."""
        self._stop.set()
        for job in list(self._discovery_jobs.values()):
            job.cancel()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._mac_executor:
            self._mac_executor.shutdown(wait=False, cancel_futures=True)
            self._mac_executor = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def _inflight_ids(self) -> set[int]:
        with self._lock:
            return set(self._queued) | set(self._started)

    def _running_discovery_jobs(self) -> list:
        """stop() already calls job.cancel() on each of these; a running
        job's own per-address loop notices _stop and lands within about
        one address's worth of work (see _discovery_budget_s) rather than
        finishing its whole sweep, which can be a subnet's worth of
        addresses and far too long to wait out here."""
        return [job for job in list(self._discovery_jobs.values()) if job.running]

    def drain(self, timeout_s: float) -> bool:
        """Wait for in-flight polls and discovery jobs to finish. True if
        they all did. The same shape as Monitor.drain (netpath/monitor.py)
        for the trace scheduler this class was copied from."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self._inflight_ids() and not self._running_discovery_jobs():
                return True
            time.sleep(0.05)
        return not self._inflight_ids() and not self._running_discovery_jobs()

    def _discovery_budget_s(self, job) -> float:
        """One address's worst case for a running discovery job, from its
        own settings dict -- not a model of the whole sweep (see
        _running_discovery_jobs). Two SNMP versions tried, a handful of
        community guesses each, plus the vendor arc hop
        (hop_enterprise_arcs: "typically three to eight" GETNEXTs, no
        retry of its own) are approximated as ten SNMP round trips rather
        than counted exactly -- a generous approximation, the same shape
        as a per-device poll's own budget below; DiscoveryJob._run_safe's
        guard (netpath/nodediscover.py) is the backstop for whatever this
        misses."""
        settings = job.settings
        default_timeout = float(settings.get("default_snmp_timeout_s", 3.0))
        snmp_timeout_s = float(settings.get("discovery_snmp_timeout_s") or default_timeout)
        ping_timeout_s = float(settings.get("discovery_ping_timeout_s") or default_timeout)
        snmp_retries = max(0, int(settings.get("discovery_snmp_retries") or 0))
        ping_retries = max(0, int(settings.get("discovery_ping_retries") or 0))
        return (ping_timeout_s * (1 + ping_retries)
               + snmp_timeout_s * (1 + snmp_retries) * 10)

    # A full poll's fixed part: the ping sweep (if enabled) plus a handful
    # of SNMP round trips that always happen (scalars, ifTable, ifXTable) —
    # not a page-by-page model of a GETBULK walk against a very-high-port-
    # count chassis, which _inflight_budget_s cannot see coming. _run_one's
    # guard is the backstop for whatever this approximation misses, exactly
    # as expected_budget's own docstring in tracer.py says of a trace.
    _SNMP_ROUND_TRIPS = 4

    def _inflight_budget_s(self, ceiling_s: float = 30.0) -> float:
        """The longest a currently in-flight poll could still legitimately
        run, per its own device's configured ping/SNMP timeouts and
        retries — the drain window shutdown() should honour before giving
        up on it. Capped so one misconfigured device cannot hang shutdown
        indefinitely. Mirrors Monitor._inflight_budget_s for the trace
        scheduler this class was copied from."""
        worst = 0.0
        for device_id in self._inflight_ids():
            try:
                device = self.db.device(device_id)
                if device is None:
                    continue
                config = self.db.effective_config(device)
            except Exception:
                continue
            budget = 0.0
            if config.get("ping_enabled"):
                budget += (int(config.get("ping_count", 3) or 1)
                          * (int(config.get("ping_timeout_ms", 1000) or 1000) / 1000))
            timeout_s = float(config.get("snmp_timeout_s", 3.0))
            retries = int(config.get("snmp_retries", 2))
            budget += timeout_s * (retries + 1) * self._SNMP_ROUND_TRIPS
            try:
                if len(self.db.credential_candidates(device)) > 1:
                    budget += self._PROBE_BUDGET_S
            except Exception:
                pass
            worst = max(worst, budget)
        for job in self._running_discovery_jobs():
            try:
                worst = max(worst, self._discovery_budget_s(job))
            except Exception:
                continue
        return min(worst, ceiling_s)

    def shutdown(self, drain_s: float = 0.0) -> None:
        """Same as stop(), but waits for whatever was already running to
        finish (or to hit its own worst-case budget) before returning, so
        the databases Service.shutdown() closes right after this are not
        closed under a poll still writing its result. See _run_one's
        except clause for the backstop when a poll still overruns even
        this."""
        self.stop()
        self.drain(max(drain_s, self._inflight_budget_s()))

    def pool_state(self) -> dict:
        """How much of the poll pool is in use right now.

        The review found the gauge on this counted queued and running
        together against the pool size, so it read "48 of 32 busy" — which
        is not wrong so much as unsayable. The two are separate here.
        """
        with self._lock:
            busy = len(self._started)
            queued = len(self._queued)
        workers = getattr(self._executor, "_max_workers", 0) if self._executor else 0
        return {"busy": busy, "queued": queued, "workers": workers,
                "saturated": bool(workers and busy >= workers and queued)}

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return "Poller stopped"
        n = self.db.device_count()
        pool = self.pool_state()
        return (f"Polling {n} device(s) · {pool['busy']} busy and "
                f"{pool['queued']} queued of {pool['workers']} worker(s) · "
                f"last poll {_ago(self._last_completed)}")

    def worker_state(self) -> dict:
        with self._lock:
            return {device_id: {"queued": self._queued.get(device_id),
                                "started": self._started.get(device_id)}
                    for device_id in set(self._queued) | set(self._started)}

    def next_runs(self) -> dict[int, float]:
        return dict(self._next_run)

    def poll_now(self, device_id: int) -> bool:
        """Submits this device to the worker pool now, ahead of its interval.
        True when it was queued, False when a poll for it was already queued
        or running — a click during an in-flight poll cannot start a second
        one, and reporting "Polled" off the first one's completion claimed
        credit for work the click did not cause."""
        return self._submit(device_id)

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
                keys = result.keys()
                self.db.seed_identity(
                    device_id, sys_descr=result["sys_descr"] or "",
                    sys_name=result["sys_name"] or "",
                    sys_object_id=result["sys_object_id"] or "",
                    vendor=result["vendor"] or "",
                    vendor_source=(result["vendor_source"] if "vendor_source" in keys else "") or "",
                    vendor_confidence=(result["vendor_confidence"]
                                       if "vendor_confidence" in keys else "") or "",
                    vendor_evidence=(result["vendor_evidence"]
                                     if "vendor_evidence" in keys else None))
            self.db.mark_promoted(result_id, device_id)
            device_ids.append(device_id)
        return device_ids

    # ------------------------------------------------------------------ loop

    # A backstop behind the generation counter: a config change made
    # outside this process (a second copy of the app on the same file)
    # would not bump it, so the merged configs are rebuilt at least this
    # often regardless.
    _CONFIG_REFRESH_S = 60.0

    def _loop(self) -> None:
        """The scheduling thread. Every pass is guarded: this thread dying
        silently — which one transient database error was enough to do —
        stopped all polling with `poller.error` still None and the status
        strip still reading "Polling N devices". Now the failure is
        recorded, shown, and the thread keeps going."""
        while not self._stop.is_set():
            try:
                self._schedule_pass()
                if self.error:
                    self.log.add(NODES, "Polling scheduling recovered")
                    self.error = None
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                self.error = f"Poller scheduling failed: {message}"
                self._bump("errors")
                self.log.add(ERROR, self.error, detail=traceback.format_exc())
            self._stop.wait(1.0)

    def _schedule_pass(self) -> None:
        """One pass over the fleet: whose turn is it to be polled.

        Reads six columns per enabled device and nothing else. The merged
        per-device config — which used to be recomputed here once per
        device per second, four settings reads and a group read each — is
        held between passes and rebuilt only when nodesdb's config
        generation moves or the backstop expires.
        """
        now = time.time()
        generation = self.db.config_generation()
        if (self._configs is None or generation != self._configs_generation
                or now - self._configs_loaded > self._CONFIG_REFRESH_S):
            self._configs = self.db.effective_configs()
            self._configs_generation = generation
            self._configs_loaded = now
            self._forget_devices(set(self._configs))
        self._note_saturation(now)
        focus = self._focus
        for device in self.db.schedule_rows():
            device_id = device["id"]
            config = self._configs.get(device_id)
            if config is None:
                # Added since the last rebuild; it is picked up on the next
                # pass, because add_device bumped the generation.
                continue
            interval = config["poll_interval_s"]
            # The device selected in a browser polls faster (SNMP
            # devices only — a fast ping-only cadence shows nothing
            # new) until its focus TTL lapses.
            focused = (focus is not None and device_id == focus[0]
                       and now < focus[1] and config.get("snmp_enabled", True))
            if focused:
                interval = min(interval, focus[2])
            due = self._next_run.get(device_id)
            if due is None:
                due = (device["last_poll_ts"] + interval) if device["last_poll_ts"] else now
                self._next_run[device_id] = due
            if now >= due:
                self._next_run[device_id] = now + interval
                if device_id in self._started or device_id in self._queued:
                    # A poll slower than the fast focus cadence is
                    # expected, not an overrun worth logging — only
                    # blowing the device's own profile interval is.
                    if not (focused and interval < config["poll_interval_s"]):
                        self._record_overrun(device, now, config)
                else:
                    self._submit(device_id)
            self._maybe_walk_mac_table(device, config, now)
            self._maybe_walk_lldp(device, config, now)

    # How long the pool has to look saturated before it is worth telling
    # somebody. A burst at the top of a poll cycle is normal; five minutes
    # of it means the pool is genuinely too small for the fleet.
    _SATURATION_S = 300.0

    def _note_saturation(self, now: float) -> None:
        """Raise (and clear) a system alert when every poll worker is busy
        and devices are still waiting.

        §4.1 S5 and the review's Tier 2 list: nothing said the pool was the
        bottleneck, so a fleet that had outgrown poll_workers looked like a
        fleet of slow devices. The alert names the number to raise.
        """
        pool = self.pool_state()
        engine = self.alert_engine
        if not pool["saturated"]:
            if self._saturation_reported:
                clear = getattr(engine, "clear_system_occurrence", None)
                if clear is not None:
                    clear("poll_pool_saturated", "poller")
            self._saturated_since = None
            self._saturation_reported = False
            return
        if self._saturated_since is None:
            self._saturated_since = now
            return
        if self._saturation_reported or now - self._saturated_since < self._SATURATION_S:
            return
        self._saturation_reported = True
        raise_it = getattr(engine, "system_occurrence", None)
        if raise_it is None:
            return
        minutes = (now - self._saturated_since) / 60.0
        raise_it(
            "poll_pool_saturated", "poller", "Polling pool", severity=3,
            extra={"busy": pool["busy"], "queued": pool["queued"],
                   "workers": pool["workers"],
                   "saturated_minutes": round(minutes, 1)},
            message=(f"Every one of the {pool['workers']} poll workers has "
                     f"been busy with {pool['queued']} device(s) waiting for "
                     f"{minutes:.0f} minutes. Devices are being polled later "
                     f"than their interval. Raise Nodes → Settings → Poll "
                     f"workers, or lengthen the polling interval."))

    def _forget_devices(self, keep: set) -> None:
        """Drop the per-device state of devices that no longer exist.

        Every one of these is keyed by device id and kept for the process
        lifetime, so without this a long-running install accumulates an
        entry per device ever deleted — small individually, unbounded
        together, and the review asked for the cleanup by name.
        """
        for cache in (self._next_run, self._last_ping, self._next_mac_walk,
                      self._next_lldp_walk,
                      self._credentials, self._credential_probe_failed,
                      self._addresses_read, self._bulk_repetitions,
                      self._sensor_read):
            for device_id in [k for k in cache if k not in keep]:
                cache.pop(device_id, None)
        with self._lock:
            for jobs in (self._oid_walks, self._vendor_ids):
                for device_id in [k for k in jobs if k not in keep]:
                    if not jobs[device_id].running:
                        jobs.pop(device_id, None)
        self._engines.forget(keep)

    def _maybe_walk_mac_table(self, device, config: dict, now: float) -> None:
        """Queue a forwarding-table walk when this device's own interval has
        come round. Off (0) unless a profile or a device asks for it, so an
        upgrade adds no SNMP load anywhere until somebody opts in.

        Not started while the device is failing or SNMP-disabled: a walk of
        hundreds of OIDs against a box that is not answering is the poll
        overrun problem all over again, at ten times the size.
        """
        interval = float(config.get("mac_table_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_mac_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every opted-in switch at once.
            self._next_mac_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._mac_running:
                return
            self._mac_running.add(device_id)
        self._next_mac_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_mac_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._mac_running.discard(device_id)

    def _maybe_walk_lldp(self, device, config: dict, now: float) -> None:
        """Queue an LLDP/CDP neighbour walk when this device's own interval
        has come round — _maybe_walk_mac_table's own scheduling, applied to
        lldp_interval_s instead of mac_table_interval_s, and sharing its
        executor: both are the same shape of thing (a whole-device table
        walk of hundreds of rows, off the poll pool), so there is no reason
        for a second thread pool to size separately."""
        interval = float(config.get("lldp_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_lldp_walk.get(device_id)
        if due is None:
            self._next_lldp_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._lldp_running:
                return
            self._lldp_running.add(device_id)
        self._next_lldp_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_lldp_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._lldp_running.discard(device_id)

    def _submit(self, device_id: int) -> bool:
        """True when this call put the device on the pool; False when it was
        already queued or running, or the pool has shut down."""
        with self._lock:
            if device_id in self._queued or device_id in self._started:
                return False
            self._queued[device_id] = time.time()
        try:
            self._executor.submit(self._run_one, device_id)
        except (RuntimeError, AttributeError):
            # The pool has shut down, or there is none (the scheduler being
            # exercised without one). Either way the device is not queued.
            with self._lock:
                self._queued.pop(device_id, None)
            return False
        return True

    def _record_overrun(self, device, now, config: dict | None = None) -> None:
        """Record that a poll was still running as the next one fell due.

        Not recorded while the device is not answering: a poll that spends
        its whole budget in timeouts and retries is the configured timeout
        doing exactly what it was told to, and the outage itself is already
        reported by device_down. status == "down" catches a formally down
        device; consecutive_fail > 0 catches the two or three polls before
        that, which is when the first overrun would otherwise fire — an
        overrun leads the outage, it does not follow it. Suppressed at
        source rather than filtered later, so no event row and no Debug
        line are written either (wirelessdb.out_of_service is the same
        shape).
        """
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        self._bump("overruns")
        running_for = now - self._started.get(device["id"], now)
        if config is None:
            config = self.db.effective_config(device)
        interval = config["poll_interval_s"]
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
            self._bump("polls")
            self._poll_device(device, config)
        except Exception as exc:
            self._bump("errors")
            # Same two non-bug shapes as Monitor._run_one (netpath/
            # monitor.py), the poller's own worst case rather than a
            # trace's: "Cannot operate on a closed database" while _stop is
            # set means this poll ran past shutdown()'s drain window
            # (bounded by _inflight_budget_s, not unlimited) and the
            # database closed under it. A foreign key failure with the
            # device now gone means it was deleted mid-poll — an ordinary
            # operator action, not a bug. Neither gets the traceback below,
            # which would read exactly like a crash in a log an operator
            # checks right after a stop or a delete. The same exceptions
            # for any OTHER reason are still a real bug and still get the
            # full treatment.
            device_gone = False
            if isinstance(exc, sqlite3.IntegrityError):
                try:
                    device_gone = self.db.device(device_id) is None
                except Exception:
                    pass  # can't tell any more; falls through to the loud path
            if isinstance(exc, sqlite3.ProgrammingError) and self._stop.is_set():
                self.log.add(NODES, f"Poll of device #{device_id} finished after "
                                    f"the poller stopped; its result was not saved")
            elif device_gone:
                self.log.add(NODES, f"Device #{device_id} was deleted while its "
                                    f"poll was running; the result was not saved")
            else:
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
        # Whether SNMP failed because the device refuses something this
        # poller does not speak, rather than because it is unreachable.
        # Decided by exception type: the old test looked for the substring
        # "unsupported" in the message, and no message this raises has ever
        # contained it, so the whole `unsupported` status, its device event
        # and the rule that watches for it were unreachable code.
        snmp_unsupported = False
        identity = None
        uptime_ticks = None
        interfaces: list[dict] = []
        # Whether the interface read finished. A partial read must not
        # delete the interfaces it never reached (see replace_interfaces).
        interfaces_complete = True
        metrics: list[tuple] = []   # (key, label, unit, kind, value)

        if config.get("snmp_enabled"):
            try:
                cred_config, identity, uptime_ticks, metrics = \
                    self._poll_snmp_scalars_with_credential(device, config)
                interfaces, interfaces_complete = self._poll_interfaces(
                    device, cred_config)
                if config.get("mib_file_id"):
                    metrics = metrics + self._poll_custom_mib(
                        device, cred_config, config["mib_file_id"])
                snmp_ok = True
            except SnmpUnsupported as exc:
                snmp_ok = False
                snmp_error = str(exc)
                snmp_unsupported = True
                self._bump("unsupported")
            except SnmpTimeout as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("timeout")
            except _AuthFailure as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("auth_fail")
            except SnmpError as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("errors")

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

        if snmp_unsupported:
            status = "unsupported"
        elif reachable:
            status = "up"
        elif device["consecutive_fail"] + 1 >= down_after:
            status = "down"
        else:
            status = device["status"] if device["status"] in ("up", "down") else "unknown"

        # Every sample this poll produced, written in ONE transaction at the
        # end (see the T4 block below) rather than one commit each. A device
        # that goes on to be marked down still leaves the loss sample that
        # explains why: the flush is unconditional, not part of the success
        # path.
        samples: list[tuple] = []   # (key, label, unit, kind, ts, value)
        if ping_loss_pct is not None:
            samples.append(("ping_loss_pct", "Packet loss", "%", "gauge",
                            now, ping_loss_pct))
        if ping_rtt_ms is not None:
            samples.append(("ping_rtt_ms", "Ping response time", "ms", "gauge",
                            now, ping_rtt_ms))

        # T1 — the device row.
        previous = self.db.record_poll(
            device_id, ping_ok=ping_ok, ping_rtt_ms=ping_rtt_ms, snmp_ok=snmp_ok,
            snmp_error=snmp_error, identity=identity, uptime_ticks=uptime_ticks,
            status=status, reachable=reachable)
        if previous is None:
            return

        if self.counters is not None and snmp_ok:
            self._bump("ok")

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

        # Both of these are TRANSITIONS, the same discipline as the up/down
        # events above, and for the same reason: a device event is a fact
        # about a change, and an alert an operator resolved by hand must not
        # be re-opened by the next poll simply repeating what the last one
        # said. Recorded on every failing poll, "SNMP authentication failing"
        # came back within a poll interval however often it was resolved.
        #
        # The transition is held HERE, in _auth_failing, rather than derived
        # from the device row's previous snmp_ok/snmp_error. That row cannot
        # answer the question:
        #
        # - "SNMP failed last poll and works now" is not "the credentials
        #   were rejected and are now accepted". A device on a lossy WAN link
        #   that times out one poll in ten recovered into an auth_ok every
        #   time, and every one of those became an alert occurrence.
        # - A profile with several candidate credentials re-raises the LAST
        #   candidate's error, so the recorded error can alternate between an
        #   auth string and a timeout while nothing about the device changed.
        #   Comparing this poll's error text with the last one's then read as
        #   "a different auth error, a new fact" every other poll — exactly
        #   the repeat this is supposed to suppress.
        #
        # So: entering the set records auth_fail, leaving it (SNMP actually
        # working) records auth_ok, and everything else — a timeout while
        # already failing, a second identical auth failure, a different auth
        # error for the same broken profile — records nothing at all. A
        # timeout recovery for a device that was never failing on auth is not
        # an auth recovery and records nothing.
        auth_failing = bool(snmp_ok is False and isinstance(snmp_error, str)
                            and "auth" in snmp_error.lower())
        with self._lock:
            if auth_failing and device_id not in self._auth_failing:
                self._auth_failing.add(device_id)
                auth_event = ("auth_fail", snmp_error)
            elif snmp_ok and device_id in self._auth_failing:
                self._auth_failing.discard(device_id)
                auth_event = ("auth_ok", "")
            else:
                auth_event = None
        if auth_event is not None:
            self.db.record_device_event(device_id, auth_event[0], auth_event[1])

        # A switch whose SNMP agent has died but which still answers ICMP is
        # reachable and broken, so `unreachable_ping_only` rightly keeps it
        # out of device_down — and before this nothing else said anything at
        # all, so a dead agent on a live switch was invisible. This is the
        # event the `snmp_failing_ping_ok` rule watches.
        #
        # Unlike the auth events above this one is recorded on EVERY failing
        # poll, and deliberately: the rule carries `auto_resolve_after_s`,
        # which measures from the alert's last occurrence, so the repeats are
        # what keep it open while the agent is still dead and their stopping
        # is what closes it. Recording it as a transition instead would
        # freeze `last_ts` and the alert would announce an all-clear an hour
        # later with the agent still down — a false all-clear, which is worse
        # than the repeat this discipline otherwise avoids. An auth failure
        # has its own event above and is excluded here.
        if (not auth_failing and snmp_ok is False and ping_ok
                and not snmp_unsupported):
            self.db.record_device_event(
                device_id, "snmp_error",
                f"SNMP is not answering but the device replies to ping: "
                f"{snmp_error}")

        # Hoisted out of the branch below: the interface block needs it too.
        # A device that has just restarted has restarted its interface
        # counters with it, and counter_rate cannot tell a reset apart from
        # a 32-bit wrap — it computes (2**32 - previous + current) / dt and
        # reports a switch that has been up for eight seconds as carrying
        # 220 Mbps. One poll's rates are dropped instead; the counters
        # themselves are still stored, so the poll after this one measures
        # against the post-reboot baseline and is correct.
        rebooted = False
        if uptime_ticks is not None:
            rebooted, note = detect_reboot(
                uptime_ticks, now, previous["last_uptime_ticks"],
                previous["last_uptime_ts"] or now)
            if rebooted:
                self.db.record_device_event(device_id, "rebooted", note)

        walk_pending = bool(
            snmp_ok and identity and settings.get("vendor_walk_enabled", True)
            and config.get("snmp_enabled", True)
            and self._identification_due(previous, identity.get("sys_object_id") or "", now))
        self._check_vendor_mib(device_id, previous, identity, defer_assignment=walk_pending)
        if walk_pending:
            self._maybe_identify(device_id, identity, config, settings)

        # ----------------------------------------------------- interfaces

        if interfaces:
            # Captured before replace_interfaces() overwrites descr/alias/
            # admin_status/oper_status — comparing against a post-replace
            # read would always compare the new value to itself and never
            # detect a link_up/link_down transition.
            existing = {row["if_index"]: row for row in self.db.interfaces(device_id)}
            # T2 — the interface table. Its `ids` map replaces one
            # interface_id_for() SELECT per port below.
            result = self.db.replace_interfaces(
                device_id, interfaces, allow_delete=interfaces_complete)
            interface_ids = result["ids"]
            rate_rows: list[dict] = []
            # The device-level worst case of each per-interface rate. The
            # shipped threshold rules (if_in_util_high, if_out_util_high,
            # if_in_errors_high, if_out_errors_high, if_in_discards_high,
            # if_out_discards_high) all read a metric with no interface
            # suffix, and nothing has ever recorded one — six rules that
            # could not fire on any device. "The worst port on this box" is
            # what a device-level rule can usefully mean.
            worst: dict[str, float] = {}
            for row in interfaces:
                if_index = row["if_index"]
                prior = existing.get(if_index)
                # This row's own GET timestamp, not the poll-start `now`:
                # the rate's dt has to match when the counters were actually
                # read (see the comment in _poll_interfaces). Metric samples
                # recorded below still use `now`, aligned with the rest of
                # this poll.
                sample_ts = row.get("_sample_ts") or now
                in_bps = out_bps = in_err_rate = out_err_rate = None
                in_disc_rate = out_disc_rate = None
                # ifCounterDiscontinuityTime: the agent saying this port's
                # counters restarted. A rate across that is fiction for
                # exactly the same reason a rate across a reboot is.
                discontinuity = row.get("discontinuity_ts")
                broke = (discontinuity is not None and prior is not None
                         and prior["discontinuity_ts"] is not None
                         and discontinuity != prior["discontinuity_ts"])
                if prior is not None and not rebooted and not broke:
                    since = prior["last_sample_ts"] or 0
                    # in_bits/out_bits track ifHCIn/OutOctets independently
                    # (see _poll_interfaces) because a device can answer
                    # one 64-bit ifXTable counter for a row without
                    # answering the other: applying one combined width to
                    # both counters would treat a genuinely 32-bit
                    # fallback as 64-bit and drop its wrapped sample.
                    in_bits = row.get("_in_octet_bits", 32)
                    out_bits = row.get("_out_octet_bits", 32)
                    in_bps = counter_rate(
                        prior["last_in_octets"], since, row.get("in_octets"),
                        sample_ts, in_bits, speed_bps=row.get("speed_bps"))
                    out_bps = counter_rate(
                        prior["last_out_octets"], since, row.get("out_octets"),
                        sample_ts, out_bits, speed_bps=row.get("speed_bps"))
                    # ifInErrors/ifOutErrors and ifInDiscards/ifOutDiscards
                    # are 32-bit counters; the rate is events per second
                    # between polls.
                    in_err_rate = counter_rate(
                        prior["last_in_errors"], since, row.get("in_errors"),
                        sample_ts, 32)
                    out_err_rate = counter_rate(
                        prior["last_out_errors"], since, row.get("out_errors"),
                        sample_ts, 32)
                    in_disc_rate = counter_rate(
                        prior["last_in_discards"], since, row.get("in_discards"),
                        sample_ts, 32)
                    out_disc_rate = counter_rate(
                        prior["last_out_discards"], since, row.get("out_discards"),
                        sample_ts, 32)
                speed_bps = row.get("speed_bps")
                # counter_rate already refuses any rate implying more than
                # 1.3x speed_bps (treating that as a reset rather than a
                # real burst), so a raw util here tops out around 130%,
                # not unbounded -- still above 100%, which is not a real
                # utilization. Clamped into [0, 100] for the same reason
                # the rate itself is bounded: a number a dashboard or
                # alert rule can trust.
                in_util = (max(0.0, min(100.0, 100.0 * in_bps * 8 / speed_bps))
                           if in_bps is not None and speed_bps else None)
                out_util = (max(0.0, min(100.0, 100.0 * out_bps * 8 / speed_bps))
                            if out_bps is not None and speed_bps else None)
                rate_rows.append({
                    "if_index": if_index, "in_octets": row.get("in_octets"),
                    "out_octets": row.get("out_octets"),
                    "in_errors": row.get("in_errors"),
                    "out_errors": row.get("out_errors"),
                    "in_discards": row.get("in_discards"),
                    "out_discards": row.get("out_discards"),
                    "in_bps": in_bps, "out_bps": out_bps,
                    "in_error_rate": in_err_rate, "out_error_rate": out_err_rate,
                    "in_discard_rate": in_disc_rate,
                    "out_discard_rate": out_disc_rate,
                    "discontinuity_ts": discontinuity,
                    "ts": sample_ts})
                interface_id = interface_ids.get(if_index)
                # Suppressed only when `rebooted` AND _interface_reassigned
                # says the port at this ifIndex actually changed: some
                # platforms (stack members, some firmware upgrades)
                # renumber ifIndex across a reload, so on the poll that
                # first observes a reboot, `prior` at this if_index may
                # describe a physically different port than the new row --
                # comparing their oper_status would then fabricate a
                # link_up/link_down event on a port that never actually
                # changed. But a reboot alone is not evidence of a
                # renumbering: on the overwhelming majority of platforms
                # ifIndex is stable across a reload, and a reboot is
                # exactly when a port that was up and does not come back
                # is most likely to happen. Skipping the comparison for
                # every reboot regardless of identity meant that case could
                # never fire an interface_down alert on any platform, and a
                # missed link_down is far worse than an occasional
                # fabricated one -- so the comparison still runs whenever
                # the prior and current rows agree (or we simply can't
                # tell, e.g. phys_addr/descr blank on one side).
                if (interface_id is not None and prior is not None
                        and not (rebooted and _interface_reassigned(prior, row))):
                    if prior["oper_status"] and prior["oper_status"] != row.get("oper_status"):
                        kind = "link_up" if row.get("oper_status") == "up" else "link_down"
                        if row.get("oper_status") in ("up", "down"):
                            self.db.record_interface_event(
                                interface_id, kind,
                                f"{row.get('descr') or if_index}: {prior['oper_status']} -> {row.get('oper_status')}")
                if interface_id is not None:
                    label = row.get("descr") or f"if{if_index}"
                    for suffix, unit, value in _INTERFACE_METRICS(
                            in_bps, out_bps, in_err_rate, out_err_rate,
                            in_disc_rate, out_disc_rate, in_util, out_util):
                        if value is None:
                            continue
                        samples.append((f"if_{suffix}.{if_index}",
                                        f"{label} {suffix}", unit, "gauge",
                                        now, value))
                        if suffix in _DEVICE_MAX_KEYS:
                            worst[suffix] = max(worst.get(suffix, value), value)
            for suffix, value in worst.items():
                unit, label = _DEVICE_MAX_KEYS[suffix]
                samples.append((f"if_{suffix}", label, unit, "gauge", now, value))
            # T3 — every interface's counters and rates.
            self.db.update_interface_rates(device_id, rate_rows)

        samples.extend((key, label, unit, kind, now, value)
                       for key, label, unit, kind, value in metrics)
        # T4 — every sample this poll produced, in one transaction.
        self.db.record_metric_samples(device_id, samples)

        # ---------------------------------------- PoE / STP / environment
        #
        # After the interface rows above are written, not before: PoE and
        # STP write per-port columns onto `interfaces` keyed by
        # (device_id, if_index), and a row that does not exist yet updates
        # nothing. Each of the three is its own best-effort, independently
        # gated read (see their own docstrings) — a device that fails one
        # must not lose the others, so each gets its own try rather than
        # sharing the block above's exception handling with the fields the
        # device's up/down status actually depends on.
        if snmp_ok and config.get("snmp_enabled"):
            if config.get("poe_enabled", True):
                try:
                    self._poll_poe(device_id, device, cred_config)
                except SnmpError:
                    pass
                except Exception:
                    self._bump("errors")
                    self.log.add(ERROR, f"PoE read failed for device #{device_id}",
                                 detail=traceback.format_exc())
            if config.get("stp_enabled", True):
                try:
                    self._poll_stp(device_id, device, cred_config)
                except SnmpError:
                    pass
                except Exception:
                    self._bump("errors")
                    self.log.add(ERROR, f"STP read failed for device #{device_id}",
                                 detail=traceback.format_exc())
            try:
                self._poll_environment(device_id, device, cred_config,
                                       {m[0] for m in metrics}, now)
            except SnmpError:
                pass
            except Exception:
                self._bump("errors")
                self.log.add(ERROR, f"Environmental sensor read failed for "
                                    f"device #{device_id}",
                             detail=traceback.format_exc())

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
        # A probe that just failed is not worth repeating for every read: the
        # interface dialog alone fires two (MAC table and DOM sensors), and an
        # unreachable device would pay the whole candidate sweep for each.
        failed_at = self._credential_probe_failed.get(device["id"], 0.0)
        if time.time() - failed_at < self._PROBE_RETRY_S:
            return config
        # retries=0, and a budget across the whole sweep: the probe only asks
        # "does this credential answer at all", and the real read that follows
        # still gets the device's full configured timeout and retries. With
        # them, an unreachable device with a few alternates took
        # candidates x timeout x (retries+1) — half a minute of a request a
        # human is waiting on, for a device that is simply down.
        deadline = time.time() + self._PROBE_BUDGET_S
        for index, candidate in enumerate(candidates):
            if time.time() > deadline:
                break
            trial = {**config, **candidate, "snmp_retries": 0}
            try:
                self._snmp_get(device, trial,
                               [nodeoids.SYSTEM_SCALARS["sys_object_id"]])
            except SnmpError:
                continue
            self._credentials[device["id"]] = index
            # The winning credential is returned with the device's own retry
            # setting restored — only the probe went without them.
            return {**config, **candidate}
        self._credential_probe_failed[device["id"]] = time.time()
        return config

    def _snmp_get(self, device, config: dict, oids: list[str]) -> Response:
        """One GET round trip against a device, handling v1/v2c/v3
        (noAuthNoPriv/authNoPriv only) transparently."""
        version = int(config.get("snmp_version", 1))
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity, _proto, _pw = credential_for(config)
                request_id = session.next_request_id()
                packet = build_request(version, identity or "public", PDU_GET,
                                       request_id, oids)
                response = session.request(packet, request_id)
                self._check_error_status(response)
                return response

            response = self._v3_exchange(session, device, config, PDU_GET, oids)
            self._check_error_status(response)
            return response
        finally:
            session.close()

    def _v3_exchange(self, session: _Session, device, config: dict, pdu_tag: int,
                     oids: list[str], max_repetitions: int = 0) -> Response:
        """One authenticated v3 round trip, with the engine resync RFC 3414
        §3.2 actually prescribes.

        Every v3 caller went through its own copy of "build the message,
        send it, and if a Report comes back give up" — so a device whose
        engineBoots had incremented (a restart) failed every poll until
        something else invalidated the cache, and the operator was told
        only "engine resync required". Here a Report is what it is: the
        agent telling us its current boots/time. Those are learned, the
        request is retried once with them, and only a second Report is an
        error — named after the usmStats counter the agent pointed at, so
        a wrong password reads differently from a wrong clock. A refused
        security level is raised as SnmpUnsupported, which the poll path
        classifies as status 'unsupported' rather than as an auth failure.
        """
        identity, auth_proto, password = credential_for(config)
        last: Response | None = None
        for attempt in (0, 1):
            engine = self._engines.current(device["id"])
            if engine is None:
                engine = self._discover_engine(session, device)
            engine_id, boots, engine_time = engine
            auth_key = localized_key(auth_proto, password, engine_id) \
                if auth_proto and password else None
            request_id = session.next_request_id()
            packet = build_v3_request(
                session.next_request_id(), request_id, pdu_tag, oids,
                engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
                user=identity or "", auth_proto=auth_proto, auth_key=auth_key,
                max_repetitions=max_repetitions)
            response = session.request(packet, request_id)
            if response.pdu_tag != PDU_REPORT:
                return response
            last = response
            name, explanation = report_reason(response)
            if name == "unsupportedSecLevels":
                raise SnmpUnsupported(f"{device['ip']}: {explanation}")
            if attempt == 0:
                # The Report carries the agent's own authoritative engine
                # id, boots and time — which is exactly what the retry
                # needs. Learn them rather than throwing the answer away
                # and rediscovering on the next poll.
                self._engines.invalidate(device["id"])
                if response.engine_id:
                    self._engines.set(device["id"], response.engine_id,
                                      response.engine_boots, response.engine_time)
                continue
            self._engines.invalidate(device["id"])
            raise _AuthFailure(
                f"{device['ip']}: SNMPv3 request refused"
                + (f" ({explanation})" if explanation
                   else " (the device answered with a Report-PDU)")
                + (f" [usmStats{name[0].upper()}{name[1:]}]" if name else ""))
        raise _AuthFailure(f"{device['ip']}: SNMPv3 request refused"
                           + (" (a Report-PDU, twice)" if last else ""))

    def _discover_engine(self, session: _Session, device) -> tuple:
        probe = discovery_probe()
        response = session.request(probe)
        if not response.engine_id:
            raise SnmpError(f"{device['ip']}: no engine id in discovery reply")
        self._engines.set(device["id"], response.engine_id, response.engine_boots,
                          response.engine_time)
        return self._engines.current(device["id"])

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
        device_id = device["id"]
        candidates = self.db.credential_candidates(device)
        cached_index = self._credentials.get(device_id)
        order = [cached_index] if cached_index is not None and cached_index < len(candidates) else []
        order += [i for i in range(len(candidates)) if i not in order]
        # A device that is simply down does not need its whole credential
        # list re-tried on every poll: four candidates at 3 s and two
        # retries is 36 s of a worker per poll, per down device. After a
        # sweep has failed, only the last-known-good candidate (or the
        # first, if there is none) is tried until the retry window passes —
        # the same negative caching the on-demand path in working_config
        # has always had.
        failed_at = self._credential_probe_failed.get(device_id, 0.0)
        if len(order) > 1 and time.time() - failed_at < self._PROBE_RETRY_S:
            order = order[:1]
        last_error: Exception | None = None
        for index in order:
            trial_config = {**config, **candidates[index]}
            try:
                identity, uptime_ticks, metrics = self._poll_snmp_scalars(device, trial_config)
            except SnmpError as exc:
                last_error = exc
                continue
            self._credentials[device_id] = index
            self._credential_probe_failed.pop(device_id, None)
            return trial_config, identity, uptime_ticks, metrics
        if len(candidates) > 1:
            self._credential_probe_failed[device_id] = time.time()
        raise last_error or SnmpTimeout(f"no reply from {device['ip']}")

    def _identity_extras(self, device, config: dict, oids: list[str]) -> dict:
        """Answers to identity OIDs read in a GET of their own, best-effort.

        Separate from the scalar GET so that an object the device does not
        implement can cost nothing but this request — on SNMPv1 an
        unimplemented object in a request spoils every answer in it, and
        identity is the one thing that must not be lost that way. Failure is
        silent for the same reason the UCD-SNMP read below is: not answering
        is the normal case, not an error.
        """
        if not oids:
            return {}
        try:
            response = self._snmp_get(device, config, oids)
        except SnmpError:
            return {}
        return {vb["oid"]: vb["value"] for vb in response.varbinds
                if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                      "endOfMibView")}

    def _poll_snmp_scalars(self, device, config: dict):
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        # An operator-chosen OID for vendor and/or location. Both the bare and
        # the .0 instance form are asked for, because "1.3.6.1.4.1.x.y" and
        # "…y.0" are both reasonable things to type and only one of them
        # answers; whichever does is used. See nodeoids.identity_oid_variants.
        #
        # On v2c and v3 they ride in the SAME GET as the standard scalars, for
        # no extra round trip: an object the agent does not implement comes
        # back as a per-varbind noSuchObject and the rest of the response is
        # unharmed. SNMPv1 has no such thing — it answers a request containing
        # one unimplemented object with noSuchName and the whole varbind list
        # echoed back as nulls, and _check_error_status raises only on
        # authorizationError, so merging them there silently blanked sysDescr,
        # sysObjectID, sysName and sysLocation on every v1 device with a custom
        # identity OID set. By construction at least one of the two forms
        # cannot answer, so on v1 they are read separately and best-effort.
        # Read without the usual `or 1` fallback, which turns a configured 0
        # (v1) into 1 (v2c) and would make the branch below unreachable for
        # exactly the devices it protects.
        #
        # _snmp_get's own `int(config.get("snmp_version") or 1)` fallback used
        # to apply the identical coercion — a configured 0 (v1) collapsing to
        # 1 (v2c) — which meant a device configured for v1 was actually polled
        # as v2c and the noSuchName case above could never arise. That
        # coercion is now fixed (`config.get("snmp_version", 1)` only defaults
        # a missing key, never an explicit 0), so this split is what actually
        # protects a v1 device's identity fields, now that v1 devices are
        # really polled as v1.
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        custom = nodeoids.identity_oid_variants(config)
        if custom["all"] and not is_v1:
            oids += [oid for oid in custom["all"] if oid not in oids]
        response = self._snmp_get(device, config, oids)
        values = {vb["oid"]: vb["value"] for vb in response.varbinds
                  if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                        "endOfMibView")}
        if custom["all"] and is_v1:
            values.update(self._identity_extras(device, config, custom["all"]))
        identity = {
            "sys_descr": values.get(nodeoids.SYSTEM_SCALARS["sys_descr"]) or "",
            "sys_object_id": values.get(nodeoids.SYSTEM_SCALARS["sys_object_id"]) or "",
            "sys_name": values.get(nodeoids.SYSTEM_SCALARS["sys_name"]) or "",
            "sys_contact": values.get(nodeoids.SYSTEM_SCALARS["sys_contact"]) or "",
            "sys_location": values.get(nodeoids.SYSTEM_SCALARS["sys_location"]) or "",
        }
        # The zero-SNMP half of vendor identification, every poll: a manual
        # or learned vendor, a real vendor arc in sysObjectID, the walk this
        # device already had for this sysObjectID, then the sysDescr guess.
        # See vendorid.poll_decision for the order and why.
        detected, source, confidence, vendor_arc = vendorid.poll_decision(
            identity["sys_object_id"], identity["sys_descr"], device,
            self.db.learned_vendor(identity["sys_object_id"]))
        # Always stored, always what the behavioural readers use — a custom
        # vendor name replaces the display value only (see
        # nodesdb.detected_vendor).
        identity["vendor_detected"] = detected
        identity["vendor"], identity["vendor_source"] = detected, source
        identity["vendor_confidence"] = confidence
        identity["vendor_arc"] = vendor_arc

        custom_vendor = nodeoids.first_text(values, custom["vendor"])
        if custom_vendor:
            identity["vendor"] = custom_vendor
            identity["vendor_source"] = "oid"
        custom_location = nodeoids.first_text(values, custom["location"])
        if custom_location:
            identity["sys_location"] = custom_location

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

        metrics.extend(self._poll_vendor_health(device, config, identity,
                                                already={m[0] for m in metrics}))
        # UPS-MIB: battery/output health for anything wired to a UPS that
        # answers SNMP. Not arc-gated the way _poll_vendor_health is — see
        # nodeoids.UPS_HEALTH's module comment for why — so it is read here,
        # best-effort, on every device exactly like the UCD-SNMP block
        # above rather than folded into _poll_vendor_health's per-arc loop.
        metrics.extend(self._poll_ups_health(device, config, identity,
                                             already={m[0] for m in metrics}))
        # Tier 1 #8: RSSI/SNR/capacity for a PtP wireless bridge — the same
        # arc-gated, best-effort scalar shape _poll_vendor_health uses just
        # above, kept as its own method because RF is not "health" and has
        # its own OID table (nodeoids.RF_METRICS).
        metrics.extend(self._poll_rf_metrics(device, config, identity))
        return identity, uptime_ticks, metrics

    # How often a device's ipAddrTable is re-read. Its addresses change when
    # somebody reconfigures it, not between polls, and the walk exists to
    # correlate traps and syslog rather than to chart anything — so once an
    # hour, not on the poll cycle.
    _ADDRESS_REFRESH_S = 3600.0

    def _health_column(self, device, config: dict, oid: str, how: str):
        """One vendor table column, reduced to a single number.

        Best-effort throughout: a device that does not implement the column
        answers nothing and contributes nothing, exactly like the UCD-SNMP
        read above. Errors are swallowed for the same reason — not
        answering a vendor object is the normal case, not a poll failure.
        """
        try:
            values = self._walk_column(device, config, oid)
        except SnmpError:
            return None
        numbers = [float(value) for value in values.values()
                   if isinstance(value, (int, float))]
        if not numbers:
            return None
        if how == "column_max":
            return max(numbers)
        if how == "column_avg":
            return sum(numbers) / len(numbers)
        return numbers[0]

    def _cisco_memory_pct(self, device, config: dict):
        """Cisco reports memory as used and free bytes per pool rather than
        as a percentage. Pools are summed: a router with a processor pool
        and an I/O pool has one memory figure, not two."""
        try:
            used = self._walk_column(device, config, nodeoids.CISCO_MEMORY_USED)
            free = self._walk_column(device, config, nodeoids.CISCO_MEMORY_FREE)
        except SnmpError:
            return None
        used_total = sum(float(v) for v in used.values()
                         if isinstance(v, (int, float)))
        free_total = sum(float(v) for v in free.values()
                         if isinstance(v, (int, float)))
        total = used_total + free_total
        if total <= 0:
            return None
        return 100.0 * used_total / total

    def _host_resources_storage_rows(self, device, config: dict) -> tuple:
        """(types, sizes, used) — hrStorageType/Size/Used, walked ONCE and
        shared by every reader of hrStorageTable (today: disk_pct's worst
        fixed disk and mem_pct's HOST-RESOURCES fallback), so a device that
        needs both pays for this table exactly once per poll rather than
        once per kind of row somebody wants out of it. All three empty
        dicts on a device with no HOST-RESOURCES-MIB support at all, or on
        any SnmpError — best-effort, same as everything else this reads."""
        try:
            types = self._walk_column(device, config, nodeoids.HR_STORAGE_TYPE)
            if not types:
                return {}, {}, {}
            sizes = self._walk_column(device, config, nodeoids.HR_STORAGE_SIZE)
            used = self._walk_column(device, config, nodeoids.HR_STORAGE_USED)
        except SnmpError:
            return {}, {}, {}
        return types, sizes, used

    @staticmethod
    def _worst_storage_pct(types: dict, sizes: dict, used: dict,
                           wanted_type: str) -> float | None:
        """The fullest hrStorageTable row of one hrStorageType, as a
        percentage — the one computation disk_pct and mem_pct both are,
        filtered to a different type. See nodeoids.HR_STORAGE_TYPE's
        comment for why no allocation-unit scaling belongs here: a
        used/size ratio does not need it."""
        worst = None
        for index, kind in types.items():
            if str(kind).strip(".") != wanted_type:
                continue
            size = sizes.get(index)
            taken = used.get(index)
            if not isinstance(size, (int, float)) or not isinstance(taken, (int, float)):
                continue
            if size <= 0:
                continue
            pct = 100.0 * float(taken) / float(size)
            worst = pct if worst is None else max(worst, pct)
        return worst

    def _host_resources_disk_pct(self, types: dict, sizes: dict, used: dict):
        """The busiest fixed disk, as a percentage, from an already-walked
        hrStorageTable (see _host_resources_storage_rows).

        hrStorageTable also holds RAM and virtual memory rows; reporting
        those as disk would make a machine using its page cache look full.
        Only hrStorageFixedDisk rows count, and the fullest of them is what
        an operator means by "the disk is filling up"."""
        return self._worst_storage_pct(types, sizes, used,
                                       nodeoids.HR_STORAGE_FIXED_DISK)

    def _host_resources_mem_pct(self, types: dict, sizes: dict, used: dict):
        """Physical memory, as a percentage, from the SAME already-walked
        hrStorageTable _host_resources_disk_pct reads — the HOST-RESOURCES
        fallback for mem_pct, tried only when neither UCD-SNMP, a Fortinet
        scalar nor the Cisco memory pool answered (see _poll_vendor_health):
        a Windows server or endpoint, a printer, most appliances answer
        none of those three and so have never had a mem_pct at all, on a
        fleet where cpu_pct and disk_pct already worked for them through
        this exact table.

        hrStorageRam is the physical-memory row alone. hrStorageVirtualMemory
        (swap, or swap-plus-physical depending on the agent) is a different
        row under a different type and is never read here, for the same
        reason the disk reader above excludes it: counting swap as physical
        memory would make a machine with a perfectly ordinary swap file read
        as critically low on RAM, the mirror image of the page-cache mistake
        that filter was already written to prevent.
        """
        return self._worst_storage_pct(types, sizes, used, nodeoids.HR_STORAGE_RAM)

    def _refresh_addresses(self, device, config: dict) -> None:
        """Remember every address this device answers on.

        A switch sends its traps from a loopback and its syslog from a
        management VRF, and neither address is in the devices table, so the
        alert engine could not tell whose message it was. ipAddrTable says
        which addresses are the device's own. Walked at most once an hour
        per device — see _ADDRESS_REFRESH_S."""
        device_id = device["id"]
        now = time.time()
        if now - self._addresses_read.get(device_id, 0.0) < self._ADDRESS_REFRESH_S:
            return
        self._addresses_read[device_id] = now
        try:
            rows = self._walk_column(device, config, nodeoids.IP_ADDR_TABLE)
        except SnmpError:
            return
        addresses = [str(value) for value in rows.values() if value]
        if addresses:
            self.db.record_device_addresses(device_id, addresses, "ipAddrTable")

    def _poll_vendor_health(self, device, config: dict, identity: dict,
                            already=()) -> list[tuple]:
        """CPU, memory, disk, temperature and session count for real network
        gear, keyed on the vendor arc SNMP identification worked out.

        Everything here is best-effort and additive: the thresholds are
        unchanged, so a device that starts answering cpu_pct can now open
        `cpu_high` where it previously reported nothing at all. Only the
        objects the device's own maker defines are asked for; the
        HOST-RESOURCES fallback runs only when neither the vendor table nor
        UCD-SNMP produced a figure, so a net-snmp box costs nothing extra.
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc(
                (identity or {}).get("sys_object_id") or "")
        metrics: list[tuple] = []
        # `already` is what the UCD-SNMP read produced. A vendor's own
        # object beats it — a FortiGate that also answers UCD-SNMP is still
        # better described by fgSysCpuUsage — so the vendor probes below
        # ignore it and record_metric_samples keeps the last value per key.
        # Only the generic HOST-RESOURCES fallback respects it, so a
        # net-snmp box costs no extra requests at all.
        produced: set = set()

        def add(key, label, unit, value):
            if value is None or key in produced:
                return
            produced.add(key)
            metrics.append((key, label, unit, "gauge", float(value)))

        probes = nodeoids.VENDOR_HEALTH.get(arc, ())
        scalars = [probe for probe in probes if probe[4] == "scalar"]
        if scalars:
            try:
                response = self._snmp_get(device, config,
                                          [probe[3] for probe in scalars])
                values = {vb["oid"]: vb for vb in response.varbinds}
            except SnmpError:
                values = {}
            for key, label, unit, oid, _how in scalars:
                vb = values.get(oid)
                if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                             "endOfMibView", "null") \
                        and isinstance(vb["value"], (int, float)):
                    add(key, label, unit, vb["value"])
        for key, label, unit, oid, how in probes:
            if how == "scalar" or key in produced:
                continue
            add(key, label, unit, self._health_column(device, config, oid, how))
        if arc == 9:
            add("mem_pct", "Memory", "%",
                self._cisco_memory_pct(device, config))
        known = produced | set(already)
        if "cpu_pct" not in known:
            for key, label, unit, oid, how in nodeoids.GENERIC_HEALTH:
                add(key, label, unit,
                    self._health_column(device, config, oid, how))
        # hrStorageTable answers BOTH disk_pct's and mem_pct's HOST-
        # RESOURCES fallback, so it is walked once (see
        # _host_resources_storage_rows) and only when at least one of the
        # two is still missing — a Cisco box that already has mem_pct from
        # its own memory pool, or a net-snmp box that already has it from
        # UCD-SNMP, costs nothing extra here, and one that answers neither
        # (a Windows host, a printer, most appliances) now gets mem_pct for
        # the first time from a table this poll was already reading for
        # disk_pct alone.
        if "disk_pct" not in known or "mem_pct" not in known:
            types, sizes, used = self._host_resources_storage_rows(device, config)
            if types:
                if "disk_pct" not in known:
                    add("disk_pct", "Storage", "%",
                        self._host_resources_disk_pct(types, sizes, used))
                if "mem_pct" not in known:
                    add("mem_pct", "Memory", "%",
                        self._host_resources_mem_pct(types, sizes, used))
        self._refresh_addresses(device, config)
        return metrics

    def _poll_rf_metrics(self, device, config: dict, identity: dict) -> list[tuple]:
        """RSSI/SNR/link-capacity for a point-to-point wireless bridge
        (Tier 1 #8), gated on the vendor arc this same poll's identity
        already worked out — RF_METRICS has no entry for anything that
        isn't a radio, so the scalar GET below is never sent to (and never
        costs so much as one packet against) a device this doesn't apply
        to. Recorded through record_metric_samples like every other metric
        here, which is what gives the future UI wave a chart with history
        for free rather than "current value only".
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
        probes = nodeoids.RF_METRICS.get(arc, ())
        if not probes:
            return []
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in probes])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            return []
        metrics = []
        for key, label, unit, oid, _how in probes:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                metrics.append((key, label, unit, "gauge", float(vb["value"])))
        if metrics:
            self._bump("rf_polls")
        return metrics

    def _poll_ups_health(self, device, config: dict, identity: dict,
                         already=()) -> list[tuple]:
        """UPS-MIB (RFC 1628) battery/output health.

        Tried on EVERY device, not gated by enterprise arc the way
        VENDOR_HEALTH is — see nodeoids.UPS_HEALTH's module comment for
        why keying this to a vendor list would not work for a UPS the way
        it does for a switch or router.

        Cost is controlled two ways, one per poll and one forever. Within
        a single poll: the first read is one GET of every scalar in the
        table, no more expensive than the UCD-SNMP read every device
        already gets, and the two per-line TABLE reads (upsInputVoltage,
        upsOutputPercentLoad — each its own GETBULK walk) are only
        attempted once that GET shows at least one scalar answered.
        Across polls: devices.ups_capable is the same probe-once-remember
        memory _poll_poe/_poll_stp already use for their own tables — NULL
        until the first attempt, then True or False, persisted, so a
        confirmed-not-a-UPS device is skipped entirely (not even the one
        scalar GET) on every later poll rather than paying that GET
        forever. Without this a fleet of 2,000 devices with 100 real UPSs
        sent 1,900 pointless GETs every poll, indefinitely — one extra
        request on a device that cannot answer is fine; the same request
        forever is the regression this guards against. Recorded only on
        the FIRST probe (capable is None), the same "a miss on the first
        probe is a verdict, a miss later is just a miss" rule _poll_poe's
        own docstring states — a UPS that times out one poll must not be
        relabelled incapable off that alone.
        """
        metrics: list[tuple] = []
        capable = device["ups_capable"]
        if capable == 0:
            return metrics
        scalars = [probe for probe in nodeoids.UPS_HEALTH if probe[4] == "scalar"]
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in scalars])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            # No answer at all, same as every scalar coming back
            # noSuchObject — folded into the `answered = False` path below
            # (same as _poll_poe/_poll_stp do for their own tables) so an
            # outright timeout on the first-ever probe still gets recorded
            # rather than silently retried forever.
            values = {}
        answered = False
        for key, label, unit, oid, _how, scale in scalars:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                answered = True
                if key not in already:
                    metrics.append((key, label, unit, "gauge",
                                    float(vb["value"]) * scale))
        if not answered:
            # Nothing in the scalar batch answered: not a UPS (or a UPS
            # that does not implement UPS-MIB at all), so the two column
            # walks below are skipped rather than sent to every non-UPS
            # device in the fleet on every poll.
            if capable is None:
                self.db.set_ups_capable(device["id"], False)
            return metrics
        if capable is None:
            self.db.set_ups_capable(device["id"], True)
        for key, label, unit, oid, how, scale in nodeoids.UPS_HEALTH:
            if how == "scalar" or key in already:
                continue
            value = self._health_column(device, config, oid, how)
            if value is not None:
                metrics.append((key, label, unit, "gauge", value * scale))
        if "ups_runtime_min" not in already and \
                not any(m[0] == "ups_runtime_min" for m in metrics):
            arc = identity.get("vendor_arc") if identity else None
            if arc is None:
                arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
            if arc == 318:   # APC / Schneider
                runtime = self._apc_runtime_fallback(device, config)
                if runtime is not None:
                    metrics.append(("ups_runtime_min", "Estimated runtime remaining",
                                    "min", "gauge", runtime))
        return metrics

    def _apc_runtime_fallback(self, device, config: dict) -> float | None:
        """APC PowerNet-MIB's upsAdvBatteryRunTimeRemaining, in TimeTicks
        (hundredths of a second), converted to minutes — read only when
        the standard upsEstimatedMinutesRemaining scalar did not answer.
        See nodeoids.APC_BATTERY_RUNTIME_TIMETICKS for why this one
        fallback, alone among everything else this module reads, is not
        cross-checked against a live unit."""
        try:
            response = self._snmp_get(
                device, config, [nodeoids.APC_BATTERY_RUNTIME_TIMETICKS])
        except SnmpError:
            return None
        for vb in response.varbinds:
            if vb["oid"] == nodeoids.APC_BATTERY_RUNTIME_TIMETICKS \
                    and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                           "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                return float(vb["value"]) / 100.0 / 60.0
        return None

    def _check_vendor_mib(self, device_id: int, previous, identity: dict | None,
                          defer_assignment: bool = False) -> None:
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
        # The vendor that was *detected* (never the display value a custom
        # OID may have replaced), and the arc it was decided from: the
        # sysObjectID's own for a real vendor arc, the walk's for a
        # generic-agent device. Coverage is asked about THAT arc — a
        # net-snmp box identified as Phoenix Contact by the walk needs the
        # Phoenix MIB, and asking about arc 8072 would never say so.
        vendor = identity.get("vendor_detected") or identity.get("vendor") or ""
        vendor_arc = identity.get("vendor_arc")
        if vendor_arc is None and "vendor_arc" not in identity:
            # An older-shaped identity (tests, replays): fall back to the
            # 4.31 rule, sysObjectID's arc only.
            vendor = vendor or nodeoids.identify_vendor(
                sys_object_id, identity.get("sys_descr") or "")[0]
            vendor_arc = nodeoids.enterprise_arc(sys_object_id)
        applicable = bool(vendor) and vendor_arc is not None
        was_covered = previous["mib_covered"]      # None / 0 / 1
        if not applicable:
            # The coverage question doesn't apply (no identity yet, a
            # standard-tree sysObjectID, or no recognizable vendor); make
            # sure no stale verdict lingers from a previous identity.
            if was_covered is not None:
                self.db.set_mib_covered(device_id, None)
            return
        coverage_oid = f"{nodeoids.ENTERPRISES}.{vendor_arc}"
        covered = self.db.has_mib_covering(coverage_oid)
        # While an identification walk is still due for this device, the
        # poll path leaves assignment to it: the walk's pick is the file that
        # actually named this device's objects, and an assignment made here
        # first — by "the file with the most objects under the arc" — would
        # stand, because assignment never overrides an existing choice.
        if covered and not defer_assignment:
            self._auto_assign_mib(device_id, coverage_oid, vendor,
                                  preferred=identity.get("preferred_mib_file_id"))
        if covered and not (was_covered is None or was_covered):
            # uncovered -> covered: the MIB arrived. CLEARS resolves the
            # standing mib_missing alert off this event.
            self.db.record_device_event(
                device_id, "mib_present",
                f"An uploaded MIB now describes {vendor} objects "
                f"(enterprise arc {vendor_arc}); vendor-specific data can be decoded.")
        elif not covered and (was_covered is None or was_covered):
            # first verdict, or covered -> uncovered (a MIB was deleted).
            bundle = mibcatalog.bundle_for_arc(vendor_arc)
            hint = (f"Install the {bundle.name} bundle from the MIB catalog"
                    if bundle else f"Upload the {vendor} MIB under Nodes → Profiles & MIBs")
            self.db.record_device_event(
                device_id, "mib_missing",
                f"No uploaded MIB describes {vendor} objects (enterprise arc "
                f"{vendor_arc}). {hint} to decode this device's vendor-specific data.")
        if was_covered is None or bool(was_covered) != covered:
            self.db.set_mib_covered(device_id, covered)

    def _auto_assign_mib(self, device_id: int, sys_object_id: str,
                         vendor: str, preferred: int | None = None) -> None:
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
        # The fingerprint's pick — the file that actually named the most of
        # what this device answered — beats "the file with the most objects
        # under the arc", which is a guess about the device from the MIB
        # alone. Only when the preferred file still exists.
        mib_file_id = preferred if preferred and self.db.mib_file(preferred) else None
        by_evidence = mib_file_id is not None
        if mib_file_id is None:
            mib_file_id = self.db.mib_file_covering(sys_object_id)
        if mib_file_id is None:
            return
        self.db.update_device(device_id, mib_file_id=mib_file_id)
        mib = self.db.mib_file(mib_file_id)
        name = (mib["module"] if mib and mib["module"] else
                (mib["filename"] if mib else str(mib_file_id)))
        why = ("the identification walk matched its objects on this device"
               if by_evidence else
               f"it describes {vendor} objects (enterprise arc "
               f"{nodeoids.enterprise_arc(sys_object_id)})")
        # Recorded, not silent: this changes what gets polled every cycle, so
        # it belongs in the device's own event history where it can be seen
        # and undone rather than being discovered from new metric names.
        self.db.record_device_event(
            device_id, "mib_assigned",
            f"Assigned the {name} MIB to this device automatically: {why} "
            f"and no MIB had been chosen. Change or clear it under this "
            f"device's Custom MIB override.")

    # ------------------------------------------------ vendor identification

    _IDENTIFY_RETRY_S = 3600.0
    _IDENTIFY_MAX_ATTEMPTS = 3

    def _getnext_one(self, device, config: dict, oid: str):
        """One GETNEXT for the arc hop: (oid, type, value), or None when the
        agent signalled the end. _snmp_get_next does not check error_status
        — a v1 agent answers a probe past its last object with noSuchName
        and the request OID echoed back, which would read as a loop — so the
        end conditions live here, where vendorid.hop_enterprise_arcs expects
        them."""
        response = self._snmp_get_next(device, config, oid)
        if getattr(response, "error_status", 0):
            return None
        if not response.varbinds:
            return None
        vb = response.varbinds[0]
        if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
            return None
        return vb["oid"], vb["type"], vb["value"]

    def _mib_index_cached(self):
        """The MIB corpus as vendorid wants it, rebuilt only when the corpus
        changed. Identification is rare, so even a rebuild per run would do;
        the cache is for a bulk Re-identify of a few hundred devices."""
        generation = self.db.mib_generation()
        with self._lock:
            cached = self._mib_index
            if cached is not None and cached[0] == generation:
                return cached[1]
        index = vendorid.build_mib_index(self.db.enterprise_objects(), self.db.mib_files())
        with self._lock:
            self._mib_index = (generation, index)
        return index

    def _identification_due(self, device, sys_object_id: str, now: float) -> bool:
        """Whether this device needs (another) identification walk: never
        identified, identified for a different sysObjectID, or the last run
        failed and it is time for one of the bounded retries. A device
        identified for its current sysObjectID returns False before any I/O
        — that is the "zero steady-state traffic" rule."""
        if device["identified_ts"] is None:
            return True
        if (device["identified_sys_object_id"] or "") != (sys_object_id or ""):
            return True
        evidence = vendorid._evidence_dict(device)
        if evidence.get("error"):
            attempts = int(evidence.get("attempts") or 0)
            last = float(evidence.get("ts") or 0)
            return attempts < self._IDENTIFY_MAX_ATTEMPTS and \
                now - last >= self._IDENTIFY_RETRY_S
        return False

    def _maybe_identify(self, device_id: int, identity, config: dict, settings) -> None:
        """Start the bounded identification walk for a device whose poll just
        succeeded, when it is due and there is room. Called from the poll
        worker but starts a separate thread; see _VendorIdJob."""
        if not identity or not settings.get("vendor_walk_enabled", True):
            return
        if not config.get("snmp_enabled", True):
            return
        device = self.db.device(device_id)
        if device is None:
            return
        if not self._identification_due(device, identity.get("sys_object_id") or "",
                                        time.time()):
            return
        limit = int(settings.get("vendor_walk_parallel", 4) or 4)
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return
            running = sum(1 for j in self._vendor_ids.values() if j.running)
            if running >= limit:
                return           # the next poll tries again; identified_ts stays NULL
            trigger = ("sysobjectid_changed" if device["identified_ts"] is not None
                       and not vendorid._evidence_dict(device).get("error")
                       else "first_poll")
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        job.start()

    def start_identify(self, device_id: int, trigger: str = "manual") -> dict:
        """Re-identify on demand: forget the previous verdict so the next
        poll would walk anyway, and start the walk now. Refused politely
        while one is already running for this device."""
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        if not self.db.effective_config(device).get("snmp_enabled", True):
            raise ValueError("SNMP is disabled for this device")
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return job.status()
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        self.db.clear_identification(device_id)
        job.start()
        return job.status()

    def identify_status(self, device_id: int) -> dict | None:
        job = self._vendor_ids.get(device_id)
        return job.status() if job else None

    def identifying(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        return job is not None and job.running

    def cancel_identify(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def _apply_identification(self, device_id: int, decision, error: str = "") -> None:
        """After a walk: coverage and MIB assignment against the decided arc,
        and one event saying what was decided and why."""
        device = self.db.device(device_id)
        if device is None:
            return
        identity = {"sys_object_id": device["sys_object_id"] or "",
                    "sys_descr": device["sys_descr"] or "",
                    "vendor_detected": decision.vendor, "vendor": decision.vendor,
                    "vendor_arc": decision.vendor_arc,
                    "preferred_mib_file_id": decision.mib_file_id}
        self._check_vendor_mib(device_id, device, identity)
        label = decision.vendor or "unidentified"
        text = (f"{label} via {decision.source} ({decision.confidence}): {decision.reason}"
                if decision.source else f"unidentified: {decision.reason}")
        if error:
            text += f" — walk incomplete: {error}"
        self.db.record_device_event(device_id, "identified", text)

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

    # A device the walk enumerated but whose per-interface GETs stopped
    # answering used to be read at N x timeout x (retries + 1) — 77 minutes
    # for a 512-port chassis at the shipped defaults, all of it on one poll
    # worker. Half the device's own poll interval is the budget, with a
    # floor so a 3-second focus poll still reads something.
    _INTERFACE_BUDGET_FRACTION = 0.5
    _INTERFACE_BUDGET_FLOOR_S = 3.0
    _INTERFACE_GIVE_UP_TIMEOUTS = 3
    _MAX_INTERFACES = 512

    def _v1_get_dropping_unknown(self, device, config: dict, oids: list,
                                 max_drops: int = 3) -> dict:
        """A GET against an SNMPv1 agent, minus the objects it does not
        implement.

        v1 has no per-varbind noSuchObject: an agent asked for one object
        it does not have answers the WHOLE request with error-status 2
        (noSuchName), error-index naming the offender, and echoes every
        varbind back as a null. The offending varbind is dropped and the
        request re-sent, up to `max_drops` times — beyond that the device
        is answering nothing useful and the interface is skipped, rather
        than the poll spending one round trip per column.
        """
        remaining = list(oids)
        for _ in range(max_drops + 1):
            if not remaining:
                return {}
            response = self._snmp_get(device, config, remaining)
            if response.error_status != 2:            # noSuchName
                return {vb["oid"]: vb for vb in response.varbinds}
            index = response.error_index
            if not 1 <= index <= len(remaining):
                return {}      # the agent will not say which: nothing to drop
            remaining.pop(index - 1)
        return {}

    def _interface_varbinds(self, device, config: dict, if_index: int,
                            is_v1: bool, want_ifx: bool) -> tuple:
        """(oid -> varbind, whether ifXTable still answers) for one
        interface.

        On v2c and v3 the IF-MIB and ifXTable columns ride in one GET: an
        object the agent lacks comes back as a per-varbind noSuchObject and
        the rest of the reply is unharmed. On v1 they cannot — mixing one
        ifXTable OID into the request makes a v1 agent answer noSuchName
        for the whole PDU, and since only authorizationError was ever
        raised on, every interface on every v1 device came back blank: no
        counters, no speed, no link events. So on v1 the two tables are two
        requests, and an ifXTable that answers noSuchName is remembered as
        "this device has none" for the rest of the poll rather than
        re-asked once per port.
        """
        oids = [f"{oid}.{if_index}" for oid in nodeoids.IF_TABLE.values()]
        ifx_oids = [f"{oid}.{if_index}" for oid in nodeoids.IFX_TABLE.values()]
        if not is_v1:
            response = self._snmp_get(device, config, oids + ifx_oids)
            return {vb["oid"]: vb for vb in response.varbinds}, want_ifx
        values = self._v1_get_dropping_unknown(device, config, oids)
        if not want_ifx:
            return values, False
        try:
            response = self._snmp_get(device, config, ifx_oids)
        except SnmpTimeout:
            raise
        except SnmpError:
            return values, False
        if response.error_status == 2:                # no ifXTable at all
            return values, False
        values.update({vb["oid"]: vb for vb in response.varbinds})
        return values, True

    def _poll_interfaces(self, device, config: dict) -> tuple:
        """(rows, complete) for a device's interfaces.

        Walks the ifIndex column to discover interfaces, then reads the
        columns for each index. The ifIndex walk opts into
        raise_on_timeout: its result feeds the device's own up/down
        status, so a genuine mid-walk timeout must be reported as the
        failure it is rather than silently returning however many
        interfaces were found before the device stopped answering.

        `complete` is what lets the caller decide whether an interface the
        walk did not produce is really gone. A walk cut short by a
        timeout, the row cap, an agent answering out of order, or a
        per-interface read this poll abandoned is not evidence of absence,
        and deleting on it takes the interfaces' link-event history with
        them.
        """
        interval = float(config.get("poll_interval_s") or 120)
        deadline = time.time() + max(self._INTERFACE_BUDGET_FLOOR_S,
                                     self._INTERFACE_BUDGET_FRACTION * interval)
        indexes, complete = self._walk_indexes(
            device, config, nodeoids.IF_TABLE["if_index"], raise_on_timeout=True)
        if not indexes:
            return [], complete
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        want_ifx = True
        wanted = indexes[:self._MAX_INTERFACES]
        if len(indexes) > self._MAX_INTERFACES:
            complete = False
        rows = []
        skipped = 0
        consecutive_timeouts = 0
        abandoned = ""
        for if_index in wanted:
            if time.time() > deadline:
                abandoned = "the poll's interface budget ran out"
                break
            if consecutive_timeouts >= self._INTERFACE_GIVE_UP_TIMEOUTS:
                abandoned = (f"{consecutive_timeouts} interfaces in a row did "
                             f"not answer")
                break
            try:
                values, want_ifx = self._interface_varbinds(
                    device, config, if_index, is_v1, want_ifx)
            except SnmpTimeout:
                # One interface's own GET timing out doesn't invalidate the
                # whole poll — the device answered enough to enumerate its
                # interfaces, so the rest are still worth collecting. Three
                # in a row does mean the device has gone quiet.
                skipped += 1
                consecutive_timeouts += 1
                continue
            except SnmpError:
                skipped += 1
                consecutive_timeouts = 0
                continue
            consecutive_timeouts = 0
            # Stamped right after this interface's own GET returns, not at
            # poll start: at 3 s focus-poll cadence the gap between an
            # earlier poll-start timestamp and when the counter was actually
            # read was up to ±17% of dt. This is the timestamp counter_rate
            # and update_interface_rates use below for this row.
            sample_ts = time.time()

            def _val(table, key, _values=values, _index=if_index):
                vb = _values.get(f"{table[key]}.{_index}")
                if not vb or vb["type"] in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView", "null"):
                    return None
                return vb["value"]

            speed = _val(nodeoids.IF_TABLE, "if_speed")
            high_speed = _val(nodeoids.IFX_TABLE, "if_high_speed")
            # ifSpeed is a Gauge32 that RFC 2863 defines as saturating at
            # 4294967295 for any link it cannot express in 32 bits of
            # bits/sec -- a real 10G+ port reports exactly that sentinel
            # here, which is why ifHighSpeed (Mbit/s) exists. Tempting to
            # treat the sentinel as "speed unknown" (None) instead of a
            # literal ~4.295 Gbit/s denominator, but that would only trade
            # one wrong number for a missing one: in_util/out_util below
            # are clamped into [0, 100] precisely so a row stuck with the
            # sentinel (ifHighSpeed absent) still reports a bounded,
            # honest-enough utilization instead of losing the metric
            # outright.
            speed_bps = (float(high_speed) * 1_000_000 if isinstance(high_speed, (int, float)) and high_speed
                        else (float(speed) if isinstance(speed, (int, float)) else None))
            hc_in = _val(nodeoids.IFX_TABLE, "if_hc_in_octets")
            hc_out = _val(nodeoids.IFX_TABLE, "if_hc_out_octets")
            in_octets = hc_in if isinstance(hc_in, (int, float)) else _val(nodeoids.IF_TABLE, "if_in_octets")
            out_octets = hc_out if isinstance(hc_out, (int, float)) else _val(nodeoids.IF_TABLE, "if_out_octets")
            # in_octets/out_octets fall back from the ifXTable 64-bit
            # counters to the ifTable 32-bit ones independently of each
            # other above, so the bit width used for the wrap maths below
            # has to be tracked independently too. A flaky agent that
            # answers ifHCInOctets but not ifHCOutOctets for this row (a
            # partial per-varbind failure) would otherwise get a single
            # combined width of 64 applied to the genuinely 32-bit
            # ifOutOctets fallback: when that counter wraps, counter_rate's
            # `bit_width >= 64` branch returns None instead of computing
            # the wrap-adjusted rate, and the sample is silently dropped.
            in_octet_bits = 64 if isinstance(hc_in, (int, float)) else 32
            out_octet_bits = 64 if isinstance(hc_out, (int, float)) else 32

            admin_raw = _val(nodeoids.IF_TABLE, "if_admin_status")
            oper_raw = _val(nodeoids.IF_TABLE, "if_oper_status")
            in_errors = _val(nodeoids.IF_TABLE, "if_in_errors")
            out_errors = _val(nodeoids.IF_TABLE, "if_out_errors")
            in_discards = _val(nodeoids.IF_TABLE, "if_in_discards")
            out_discards = _val(nodeoids.IF_TABLE, "if_out_discards")
            discontinuity = _val(nodeoids.IFX_TABLE, "if_discontinuity")
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
                "in_discards": int(in_discards) if isinstance(in_discards, (int, float)) else None,
                "out_discards": int(out_discards) if isinstance(out_discards, (int, float)) else None,
                "discontinuity_ts": (float(discontinuity)
                                     if isinstance(discontinuity, (int, float)) else None),
                "_in_octet_bits": in_octet_bits,
                "_out_octet_bits": out_octet_bits,
                "_sample_ts": sample_ts,
            })
        if skipped or abandoned:
            complete = False
            reason = abandoned or f"{skipped} did not answer"
            self.log.add(NODES, f"Read {len(rows)} of {len(indexes)} interface(s) "
                                f"on {device['ip']}: {reason}. Interfaces that "
                                f"were not read keep their stored values.",
                        target=device["ip"])
        return rows, complete

    def _walk_column(self, device, config: dict, base_oid: str,
                     raise_on_timeout: bool = False,
                     deadline: float | None = None) -> dict[str, object]:
        """One table column's values. See _walk_column_status, which this
        wraps for the callers that do not need to know whether the walk
        finished."""
        return self._walk_column_status(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout,
                                        deadline=deadline)[0]

    def _walk_column_status(self, device, config: dict, base_oid: str,
                            raise_on_timeout: bool = False,
                            deadline: float | None = None) -> tuple:
        """(index suffix -> value, whether the walk reached the end).

        `complete` is False whenever the walk stopped for a reason that is
        not "the table ended": a timeout, an SNMP error, the row cap, an
        agent that answered nothing, one that answered out of order, or
        the caller's own deadline. Callers that go on to delete rows the
        walk did not produce need to know the difference — a walk cut
        short is not evidence that anything is gone.

        v2c and v3 walk with GETBULK — one request answers up to
        `settings["snmp_bulk_max_repetitions"]` rows instead of one GETNEXT
        per row, which is where the whole cost of a forwarding-table walk
        used to go. v1 has no GETBULK PDU and always uses GETNEXT. Either
        way the walk runs on one shared `_Session` (one UDP socket) rather
        than opening a fresh one per row. Per response, every varbind is
        taken in order until the first one that leaves `base_oid`'s
        subtree, answers `noSuchObject`/`noSuchInstance`/`endOfMibView`, or
        is not lexicographically after the request (a misbehaving agent
        echoing itself, or going backwards) — the next request resumes
        from the last accepted OID. A device that answers a GETBULK with
        `error_status == 1` (tooBig, its reply would not fit) is retried
        at half the repetitions; at one repetition it falls back to
        GETNEXT for the rest of this walk rather than looping on tooBig
        forever. Stops when the walk leaves the subtree or hits
        `settings["snmp_walk_max_rows"]` (logged once, not per row).

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
        settings = self.db.settings()
        max_rows = int(settings.get("snmp_walk_max_rows", 16384) or 16384)
        # GETBULK does not exist in v1, so whether to use it is decided on
        # the configured version with 0 (v1) the only value that says no —
        # an absent version means v2c, the same default `_walk_request`,
        # `_snmp_get` and `_snmp_get_next` apply for framing. Framing
        # (build_request vs build_v3_request) is unaffected either way: v1
        # and v2c share the same community-based wire format. The
        # repetition count is the one this device last coped with.
        use_bulk, max_repetitions = self._bulk_settings(device, config)

        values: dict[str, object] = {}
        current = base_oid
        hit_cap = False
        complete = True
        session = self._session_for(device, config)
        try:
            while True:
                if len(values) >= max_rows:
                    hit_cap = True
                    complete = False
                    break
                if deadline is not None and time.time() > deadline:
                    # The caller's own wall-clock budget. Checked inside
                    # the walk, not only between walks: a Cisco per-VLAN
                    # sweep that checked only between VLANs could run two
                    # unbounded walks past the budget it was given.
                    complete = False
                    break
                try:
                    pdu_tag = PDU_GETBULK if use_bulk else PDU_GETNEXT
                    response = self._walk_request(
                        session, device, config, current, pdu_tag, max_repetitions)
                except SnmpTimeout as exc:
                    if raise_on_timeout:
                        raise SnmpTimeout(
                            f"{exc} (table walk cut short after {len(values)} row(s))") from exc
                    complete = False
                    break
                except SnmpError:
                    complete = False
                    break
                if use_bulk and response.error_status == 1:   # tooBig
                    if max_repetitions <= 1:
                        use_bulk = False
                    else:
                        max_repetitions = max(1, max_repetitions // 2)
                    self._remember_repetitions(device, max_repetitions)
                    continue
                if not response.varbinds:
                    complete = False
                    break
                stop = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base_oid or oid.startswith(base_oid + ".")):
                        stop = True
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                        stop = True
                        break
                    if _oid_key(oid) <= _oid_key(current):
                        complete = False
                        stop = True
                        break
                    values[oid[len(base_oid) + 1:]] = vb["value"]
                    current = oid
                    if len(values) >= max_rows:
                        hit_cap = True
                        complete = False
                        stop = True
                        break
                if stop:
                    break
        finally:
            session.close()
        if hit_cap:
            self.log.add(NODES, f"Table walk of {base_oid} on {device['ip']} "
                                f"stopped at the {max_rows}-row cap",
                         target=device["ip"])
        return values, complete

    def _walk_indexes(self, device, config: dict, base_oid: str,
                      raise_on_timeout: bool = False) -> tuple:
        """(the integer indexes the column reported, whether the walk
        finished).

        A suffix that is not an integer is skipped, not treated as the end
        of the table: one malformed row used to truncate the list, and
        because the caller then deleted every interface it had not seen,
        one bad row took the rest of the device's ports and their link
        history with it.
        """
        indexes: list[int] = []
        values, complete = self._walk_column_status(
            device, config, base_oid, raise_on_timeout=raise_on_timeout)
        for suffix in values:
            try:
                indexes.append(int(suffix))
            except ValueError:
                continue
        return indexes, complete

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

    # entPhySensorType values this app turns into a device-level metric —
    # see _poll_environment. The rest of _SENSOR_TYPE_UNITS' arcs (voltage,
    # current, power, frequency, fan speed, airflow) are real DOM readings
    # on a transceiver, which read_dom already surfaces, but none of them
    # is something a *device* has one true value for the way temperature
    # and humidity are, so none of them is promoted to a metric here.
    _SENSOR_TYPE_TEMPERATURE = 8
    _SENSOR_TYPE_HUMIDITY = 9

    def _decode_entity_sensor(self, suffix: str, raw, types: dict, scales: dict,
                              precisions: dict, statuses: dict, units: dict,
                              descrs: dict) -> dict | None:
        """One ENTITY-SENSOR-MIB row (RFC 3433) -> {"entity", "label",
        "value", "unit", "status"}, or None when `raw` is not the number
        entPhySensorValue is supposed to be (an unpopulated row, or an
        agent answering the wrong ASN.1 type for this instance).

        Factored out of read_dom so it and _poll_environment do the exact
        same scaling arithmetic in exactly one place. Before this, only
        read_dom had it — reachable solely through entAliasMappingIdentifier,
        which maps a sensor to the PORT it rides on. An environmental
        monitor's temperature and humidity probes belong to the chassis,
        not to any port, map to nothing in that table, and so were
        invisible everywhere in this app: read_dom returned [] and the
        interface dialog said "no sensors" for a device that had plenty.
        """
        if not isinstance(raw, (int, float)):
            return None
        try:
            entity = int(suffix)
        except ValueError:
            return None
        sensor_type = int(types.get(suffix) or 0)
        scale = int(scales.get(suffix) or 9)       # 9 = units (10^0)
        precision = int(precisions.get(suffix) or 0)
        # RFC 3433: the reading is value x 10^(3*(scale-9)) with
        # `precision` decimal places already folded into the integer.
        value = raw * (10 ** (3 * (scale - 9))) / (10 ** precision)
        unit = str(units.get(suffix) or "").strip() or \
            self._SENSOR_TYPE_UNITS.get(sensor_type, "")
        return {
            "entity": entity,
            "label": str(descrs.get(suffix) or f"sensor {entity}"),
            "value": round(value, max(precision, 4)),
            "unit": unit,
            "status": self._SENSOR_STATUS.get(
                int(statuses.get(suffix) or 0), "unknown"),
        }

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
            if not belongs_to_port(entity):
                continue
            reading = self._decode_entity_sensor(
                suffix, raw, types, scales, precisions, statuses, units, descrs)
            if reading is not None:
                sensors.append(reading)
        sensors.sort(key=lambda s: s["entity"])
        return sensors

    # How often the whole-device ENTITY-SENSOR-MIB walk in _poll_environment
    # runs, per device. Six column walks (type, scale, precision, value,
    # status, units, plus physical descr for a label — the same set
    # read_dom already does, just for every entity rather than one port's)
    # is the same shape of cost the LLDP/MAC walks are, so it gets a
    # cadence rather than running on the poll cycle — but a temperature or
    # a humidity reading does not change between one poll and the next the
    # way an interface counter does, so there is nothing to buy by
    # re-walking it that often either.
    #
    # Fixed here rather than a per-device config column the way
    # lldp_interval_s/mac_table_interval_s are: adding one of those means a
    # schema migration, a group-inheritance column and a settings-page
    # control, none of which is this change's to make. A fixed cadence,
    # in-memory only (see _sensor_read, and _refresh_addresses just above
    # for the identical tradeoff already made for ipAddrTable), costs
    # nothing extra to add and re-walks once per process restart at worst.
    #
    # Kept safely under alertengine's threshold_stale_s (900s shipped
    # default): a metric older than that reads as "absent" to a threshold
    # rule (see alertengine._evaluate_thresholds), and a sensor cadence
    # equal to or slower than that would make the temperature/humidity rules
    # flicker in and out of "no data" between refreshes instead of holding
    # a value. Five minutes leaves three refreshes of margin inside that
    # 900-second window.
    _SENSOR_REFRESH_S = 300.0

    def _walk_port_mapped_entities(self, device, config: dict) -> tuple[set, dict]:
        """(port_entities, contained_in) — the same two ENTITY-MIB tables
        read_dom() walks to answer "does this entity belong to THIS
        ifIndex", generalised here to build the full set of entities that
        belong to ANY port at all, once per device rather than once per
        candidate sensor.

        port_entities is every entPhysicalIndex entAliasMappingIdentifier
        names as riding on some interface — unfiltered by which one,
        unlike read_dom()'s own port_entities, which keeps only the rows
        naming the one ifIndex a human opened a dialog for. contained_in
        is entPhysicalContainedIn verbatim, exactly as read_dom builds it.
        Kept as its own method, separate from read_dom's identical-shaped
        inline code, so read_dom's behaviour is not this method's to
        risk — see _decode_entity_sensor's docstring for why that
        matters."""
        alias = self._walk_column(device, config, self._ENT_ALIAS_MAPPING)
        prefix = self._IF_INDEX_COLUMN + "."
        port_entities = set()
        for suffix, value in alias.items():
            if not str(value).startswith(prefix):
                continue
            try:
                port_entities.add(int(suffix.split(".")[0]))
            except ValueError:
                continue
        contained_in = {}
        for suffix, value in self._walk_column(
                device, config, self._ENT_PHYSICAL_CONTAINED_IN).items():
            try:
                contained_in[int(suffix)] = int(value)
            except (TypeError, ValueError):
                continue
        return port_entities, contained_in

    def _poll_environment(self, device_id: int, device, config: dict,
                          already: set, now: float) -> None:
        """Device-level temperature/humidity from ENTITY-SENSOR-MIB (RFC
        3433) — a Room Alert-class environmental monitor, or any switch,
        router or PDU that exposes its own chassis sensors through the
        standard MIB rather than (or in addition to) a vendor-specific one.

        Deliberately does NOT require entAliasMappingIdentifier to decide
        whether a sensor is WORTH READING — see _decode_entity_sensor's
        docstring for why that gate on read_dom() made an environmental
        monitor's sensors unreachable everywhere in this app. It DOES use
        that same mapping to decide WHICH metric key a temperature reading
        becomes, which is the fix for a real incident this shipped with
        for about a day: 45 C is a perfectly healthy switch chassis and a
        perfectly ordinary SFP DOM reading runs 40-55 C, but is a warning
        sign in a comms closet — one "temp_c" key and one threshold rule
        covering all three read as ten false "Temperature high" alerts on
        a 25-device fleet with one Room Alert and some healthy switches in
        it, the exact mib_missing-email-storm shape the product's own
        prior review already burned an operator's trust on once. So a
        temperature reading is classified into one of three keys before it
        is ever stored, and the three get three separate rules with three
        separate defaults instead of fighting over one:

        - temp_optic_c: the sensor maps to a port (via the same containment
          walk read_dom uses, generalised to "any port" by
          _walk_port_mapped_entities) — an SFP/QSFP's own DOM temperature,
          normal well above ambient.
        - temp_ambient_c: the sensor maps to no port, AND this device also
          answers at least one humidity sensor. A chassis essentially never
          carries one; a dedicated room/rack environmental monitor (Room
          Alert and the like) always does, on any vendor's arc, which is
          why this is the humidity table itself rather than a vendor check
          — it generalises past AVTECH for free.
        - temp_chassis_c: everything else unmapped — the DEFAULT for "an
          ordinary switch or router's own internal board/PSU/fan sensor",
          chosen deliberately as the fallback rather than temp_ambient_c:
          a device this cannot positively identify as an environmental
          monitor must not have its plain chassis warmth silently read as
          a room getting hot, which is the mistake being fixed here.
          Lands in the SAME key jnxOperatingTable's reading uses (see
          VENDOR_HEALTH), so a device answering both never reports two
          disagreeing chassis temperatures.

        Best-effort and gated two ways. Within the cadence window
        (_SENSOR_REFRESH_S — see that constant's comment) nothing runs at
        all. Across polls, once the cadence lets a walk through:
        devices.sensor_capable is the same probe-once-remember memory
        _poll_poe/_poll_stp/_poll_ups_health use for their own tables —
        NULL until the first attempt, then True or False, persisted, so a
        device confirmed to have no ENTITY-SENSOR-MIB support is skipped
        entirely rather than retried every _SENSOR_REFRESH_S forever. That
        distinction is the whole difference between "one wasted walk on a
        switch that will never answer it" and "one wasted walk every five
        minutes, indefinitely, on every such switch in a 2,000-device
        fleet" — the second is a real, compounding cost the first is not.
        Recorded only on the FIRST probe (capable is None), the same rule
        every other capability memory in this file already follows: a
        device already confirmed capable that simply times out once must
        not be relabelled incapable off that alone.
        """
        capable = device["sensor_capable"]
        if capable == 0:
            return
        if now - self._sensor_read.get(device_id, 0.0) < self._SENSOR_REFRESH_S:
            return
        self._sensor_read[device_id] = now
        try:
            sensor_values = self._walk_column(device, config, self._ENT_SENSOR_VALUE)
        except SnmpError:
            sensor_values = {}
        if not sensor_values:
            # No answer at all and an outright SnmpError are folded
            # together on purpose here, same as _poll_poe/_poll_stp do for
            # their own tables: either way this poll learned nothing from
            # the device, and "empty" is the only verdict there is to
            # record.
            if capable is None:
                self.db.set_sensor_capable(device_id, False)
            return
        if capable is None:
            self.db.set_sensor_capable(device_id, True)
        types = self._walk_column(device, config, self._ENT_SENSOR_TYPE)
        scales = self._walk_column(device, config, self._ENT_SENSOR_SCALE)
        precisions = self._walk_column(device, config, self._ENT_SENSOR_PRECISION)
        statuses = self._walk_column(device, config, self._ENT_SENSOR_STATUS)
        units = self._walk_column(device, config, self._ENT_SENSOR_UNITS)
        descrs = self._walk_column(device, config, self._ENT_PHYSICAL_DESCR)
        port_entities, contained_in = self._walk_port_mapped_entities(device, config)

        def on_a_port(entity: int) -> bool:
            seen = 0
            while entity and seen < 16:   # a real containment tree is shallow
                if entity in port_entities:
                    return True
                entity = contained_in.get(entity, 0)
                seen += 1
            return False

        has_humidity = any(int(types.get(suffix) or 0) == self._SENSOR_TYPE_HUMIDITY
                           for suffix in sensor_values)

        optic_temps: list[float] = []
        ambient_temps: list[float] = []
        chassis_temps: list[float] = []
        humidities: list[float] = []
        for suffix, raw in sensor_values.items():
            sensor_type = int(types.get(suffix) or 0)
            if sensor_type not in (self._SENSOR_TYPE_TEMPERATURE,
                                   self._SENSOR_TYPE_HUMIDITY):
                continue
            reading = self._decode_entity_sensor(
                suffix, raw, types, scales, precisions, statuses, units, descrs)
            # A sensor reporting anything other than "ok" (unplugged,
            # failed, out of range) contributes nothing rather than a
            # bogus reading — an alert on a physical quantity is worth
            # nothing if it can silently be sourced from a dead probe.
            if reading is None or reading["status"] != "ok":
                continue
            if sensor_type == self._SENSOR_TYPE_HUMIDITY:
                humidities.append(reading["value"])
                continue
            try:
                entity = int(suffix)
            except ValueError:
                continue
            if on_a_port(entity):
                optic_temps.append(reading["value"])
            elif has_humidity:
                ambient_temps.append(reading["value"])
            else:
                chassis_temps.append(reading["value"])

        # Worst (hottest/most humid) sensor of each kind wins — "the hot
        # spot is what matters", the same reasoning VENDOR_HEALTH's
        # column_max probes already use, applied per kind so an SFP
        # running warm never masks a genuinely hot chassis sensor or vice
        # versa.
        samples = []
        if optic_temps:
            samples.append(("temp_optic_c", "Optic temperature", "°C",
                            "gauge", now, max(optic_temps)))
        if ambient_temps:
            samples.append(("temp_ambient_c", "Ambient temperature", "°C",
                            "gauge", now, max(ambient_temps)))
        if chassis_temps and "temp_chassis_c" not in already:
            # `already` is what this poll's vendor-health pass produced —
            # a device with a better vendor-specific chassis reading
            # (Juniper's jnxOperatingTable) keeps it, and this only fills
            # in for one that has none, same as the pre-split code did.
            samples.append(("temp_chassis_c", "Chassis temperature", "°C",
                            "gauge", now, max(chassis_temps)))
        if humidities:
            samples.append(("humidity_pct", "Humidity", "%RH", "gauge", now,
                            max(humidities)))
        if samples:
            self.db.record_metric_samples(device_id, samples)

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
                     vlan_indexed: bool, port_map: dict | None = None) -> list[dict]:
        """Rows of a forwarding-database column.

        Filtered to `target_ports` — one port for the interface dialog, or
        every bridge port for the whole-device walk, which also passes
        `port_map` (bridge port -> ifIndex) so each entry says which
        interface learned the address.

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
            entry = {
                "mac": mac,
                "vlan": (parts[0] if vlan_indexed else vlan) or "",
            }
            if port_map is not None:
                # Whole-device form: carry which interface learned it. A
                # bridge port with no ifIndex mapping is dropped rather than
                # stored against a guess.
                if_index = port_map.get(int(port))
                if if_index is None:
                    continue
                entry["if_index"] = if_index
            entries.append(entry)
        return entries

    def _bridge_ports_for(self, device, config: dict, if_index: int,
                          deadline: float | None = None):
        """(bridge ports mapping to this ifIndex, whether the device answered).

        A switch that does not answer dot1dBasePortIfIndex at all is a
        different fact from one that answers and simply has no bridge port
        for this interface, and the caller reports them differently.
        """
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
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
        if int(config.get("snmp_version", 1)) == 3:
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
        # The budget is passed INTO each walk, not only checked between
        # VLANs: checking between them let the last VLAN start two
        # unbounded walks (bridge ports, then the forwarding table) after
        # the budget was already spent, which is how a dialog a human is
        # waiting on ran for minutes.
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
                    device, scoped, if_index, deadline=deadline)
                answered = answered or port_answered
                if not ports:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
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
        # detected_vendor, not device["vendor"]: a custom vendor_oid may have
        # replaced the displayed name with whatever the device calls itself,
        # and this gate needs the identified vendor key.
        is_cisco = detected_vendor(device).lower() == "cisco"

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

    def read_device_mac_table(self, device_id: int) -> list[dict] | None:
        """Every MAC this switch has learned, and on which interface.

        The whole-device counterpart of read_mac_table above, and the same
        three sources in the same order — a forwarding table is a forwarding
        table whether you want one port of it or all of it. What differs is
        that this is not filtered to one port, so the bridge-port map is
        needed in full, and that this runs on the mac_table_interval_s
        schedule rather than while somebody watches a dialog.

        Returns None when the device answers no forwarding table at all,
        which the caller must not confuse with an empty one: "this switch
        cannot tell us" and "this switch has learned nothing" are different
        facts, and only the second should overwrite what we already stored.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        port_map = self._bridge_port_map(device, config)
        is_cisco = detected_vendor(device).lower() == "cisco"
        answered = bool(port_map)

        entries = []
        if port_map:
            ports = set(port_map)
            entries = self._fdb_entries(
                self._walk_column(device, config, self._DOT1Q_FDB_PORT),
                ports, None, True, port_map)
            if not entries:
                entries = self._fdb_entries(
                    self._walk_column(device, config, self._DOT1D_FDB_PORT),
                    ports, None, False, port_map)
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_device_fdb(
                device, config, port_map)
            answered = answered or cisco_answered
        if not answered:
            return None

        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["if_index"], e["mac"],
                                                    e["vlan"])):
            key = (entry["if_index"], entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def _bridge_port_map(self, device, config: dict,
                         deadline: float | None = None) -> dict:
        """bridge port -> ifIndex, for every port the device reports."""
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
        mapping = {}
        for suffix, value in base_port_if_index.items():
            try:
                mapping[int(suffix)] = int(value)
            except (TypeError, ValueError):
                continue
        return mapping

    def _cisco_vlan_device_fdb(self, device, config: dict, port_map: dict):
        """The whole device's forwarding table out of classic IOS per-VLAN
        contexts — the community@vlan path read_mac_table already needs,
        without the per-port filter. Bounded in VLAN count and wall clock
        for the same reason: a trunk switch can carry hundreds of VLANs."""
        if int(config.get("snmp_version", 1)) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        # See _cisco_vlan_fdb: the budget goes into the walks themselves.
        deadline = time.time() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.time() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            mapping = port_map
            if not mapping:
                mapping = self._bridge_port_map(device, scoped, deadline=deadline)
                answered = answered or bool(mapping)
                if not mapping:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
            entries.extend(self._fdb_entries(
                fdb_port, set(mapping), vlan, False, mapping))
        return entries, answered

    # ------------------------------------------------------------- PoE / STP

    @staticmethod
    def _last_index_component(suffix: str) -> int | None:
        """The trailing arc of a table-column suffix, as an int — PoE's
        pethPsePortIndex (see nodeoids' PoE block for why this is treated
        as an ifIndex directly)."""
        parts = suffix.split(".")
        if not parts:
            return None
        try:
            return int(parts[-1])
        except ValueError:
            return None

    def _poll_poe(self, device_id: int, device, config: dict) -> None:
        """POWER-ETHERNET-MIB (Tier 1 #7): PSE budget/consumption and
        per-port admin/detection state, read every poll once the device is
        known to answer it.

        Probed at most once per device: devices.poe_capable is None until
        the first attempt, then True or False, so a device that does not
        implement PoE (the overwhelming majority of a fleet) pays for this
        walk exactly once, ever — not once per poll, and not once per
        process restart either, since the verdict is persisted rather than
        held in memory the way _bulk_repetitions/_credentials are. A device
        already known capable=False is skipped before sending anything.
        """
        capable = device["poe_capable"]
        if capable == 0:
            return
        try:
            pse_power = self._walk_column(device, config, nodeoids.PETH_MAIN_PSE_POWER)
        except SnmpError:
            pse_power = {}
        if not pse_power:
            # Nothing answered even the budget scalar: not a PSE. Recorded
            # only on the FIRST probe (capable is None) — a device that has
            # already been confirmed capable and simply timed out this poll
            # must not be relabeled incapable off one missed walk, the same
            # "a miss is not a verdict" rule read_device_mac_table's None
            # return already follows.
            if capable is None:
                self.db.set_poe_capable(device_id, False)
            return
        if capable is None:
            self.db.set_poe_capable(device_id, True)

        try:
            pse_consumption = self._walk_column(
                device, config, nodeoids.PETH_MAIN_PSE_CONSUMPTION)
        except SnmpError:
            pse_consumption = {}
        budget_w = sum(float(v) for v in pse_power.values()
                       if isinstance(v, (int, float)))
        now = time.time()
        samples = [("poe_budget_w", "PoE power budget", "W", "gauge", now, budget_w)]
        if pse_consumption:
            consumption_w = sum(float(v) for v in pse_consumption.values()
                                if isinstance(v, (int, float)))
            samples.append(("poe_consumption_w", "PoE power in use", "W",
                            "gauge", now, consumption_w))
        self.db.record_metric_samples(device_id, samples)
        self._bump("poe_polls")

        try:
            port_admin = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_ADMIN)
        except SnmpError:
            port_admin = {}
        try:
            port_detect = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_DETECTION)
        except SnmpError:
            port_detect = {}
        try:
            port_power_mw = self._walk_column(device, config, nodeoids.CISCO_POE_PORT_POWER_MW)
        except SnmpError:
            port_power_mw = {}   # not a Cisco PSE, or the extension MIB isn't there

        rows: dict[int, dict] = {}
        for suffix, value in port_admin.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_admin"] = \
                nodeoids.PETH_PORT_ADMIN_ENUM.get(int(value))
        for suffix, value in port_detect.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_detect_status"] = \
                nodeoids.PETH_PORT_DETECTION_ENUM.get(int(value))
        for suffix, value in port_power_mw.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_power_mw"] = int(value)
        if rows:
            self.db.update_interface_poe(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

    def _poll_stp(self, device_id: int, device, config: dict) -> None:
        """BRIDGE-MIB dot1dStp (Tier 1 #7): bridge-wide spanning-tree state
        every poll once the device is known to be a bridge, plus per-port
        state joined onto the SAME bridge-port -> ifIndex map the MAC table
        walk already resolves (_bridge_port_map) — dot1dStpPort IS
        dot1dBasePort, so there is no separate index guess to make here the
        way PoE's port-index assumption is. Probed once, same capability
        memory as PoE — see devices.stp_capable and _poll_poe's docstring.
        """
        capable = device["stp_capable"]
        if capable == 0:
            return
        try:
            response = self._snmp_get(device, config, [
                nodeoids.DOT1D_STP_PROTOCOL_SPEC, nodeoids.DOT1D_STP_PRIORITY,
                nodeoids.DOT1D_STP_TIME_SINCE_CHANGE, nodeoids.DOT1D_STP_TOP_CHANGES,
                nodeoids.DOT1D_STP_DESIGNATED_ROOT, nodeoids.DOT1D_STP_ROOT_COST,
                nodeoids.DOT1D_STP_ROOT_PORT])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            values = {}

        def num(oid):
            vb = values.get(oid)
            if vb is None or vb["type"] in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView", "null"):
                return None
            return vb["value"] if isinstance(vb["value"], (int, float)) else None

        protocol_spec_n = num(nodeoids.DOT1D_STP_PROTOCOL_SPEC)
        if protocol_spec_n is None:
            # Same "a miss on the first probe is a verdict, a miss later is
            # just a miss" rule _poll_poe follows.
            if capable is None:
                self.db.set_stp_capable(device_id, False)
            return
        if capable is None:
            self.db.set_stp_capable(device_id, True)

        priority = num(nodeoids.DOT1D_STP_PRIORITY)
        time_since_change = num(nodeoids.DOT1D_STP_TIME_SINCE_CHANGE)
        top_changes = num(nodeoids.DOT1D_STP_TOP_CHANGES)
        root_cost = num(nodeoids.DOT1D_STP_ROOT_COST)
        root_port = num(nodeoids.DOT1D_STP_ROOT_PORT)
        root_vb = values.get(nodeoids.DOT1D_STP_DESIGNATED_ROOT)
        root_id = (str(root_vb["value"])
                  if root_vb and root_vb["type"] not in
                  ("noSuchObject", "noSuchInstance", "endOfMibView", "null")
                  else None)

        self.db.update_stp_bridge(
            device_id,
            protocol_spec=nodeoids.DOT1D_STP_PROTOCOL_SPEC_ENUM.get(
                int(protocol_spec_n), str(int(protocol_spec_n))),
            priority=int(priority) if priority is not None else None,
            root_id=root_id,
            root_cost=int(root_cost) if root_cost is not None else None,
            root_port=int(root_port) if root_port is not None else None,
            time_since_change_s=(time_since_change / 100.0
                                 if time_since_change is not None else None))
        self._bump("stp_polls")
        if top_changes is not None:
            # A cumulative counter, stored as a gauge sample the same way
            # dot1dStpTopChanges' RFC-defined semantics are — the future
            # alerting wave rules on it *increasing* between samples
            # (series()), not on any single reading, so no rate math
            # belongs here.
            self.db.record_metric_samples(device_id, [
                ("stp_topology_changes", "STP topology changes", "count",
                 "gauge", time.time(), float(top_changes))])

        try:
            port_state = self._walk_column(device, config, nodeoids.DOT1D_STP_PORT_STATE)
        except SnmpError:
            port_state = {}
        if not port_state:
            return
        port_map = self._bridge_port_map(device, config)
        rows: dict[int, dict] = {}
        for suffix, value in port_state.items():
            try:
                bridge_port = int(suffix)
            except ValueError:
                continue
            if_index = port_map.get(bridge_port)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            state = nodeoids.DOT1D_STP_PORT_STATE_ENUM.get(int(value))
            if state is not None:
                rows[if_index] = {"stp_state": state}
        if rows:
            self.db.update_interface_stp(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

    def _run_mac_table(self, device_id: int) -> None:
        """One scheduled forwarding-table walk, on the poll pool.

        Wrapped in except Exception for the same reason _run_one is: a
        worker thread must never die quietly. A device that answers no
        forwarding table leaves what is stored alone rather than deleting
        it — a switch that failed to answer once has not forgotten every
        MAC it knows.
        """
        try:
            entries = self.read_device_mac_table(device_id)
            if entries is None:
                return
            stored = self.db.replace_mac_entries(device_id, entries)
            self._bump("mac_walks")
            self.log.add(NODES, f"Learned {stored} MAC address(es) on device "
                                f"#{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"MAC table walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._mac_running.discard(device_id)

    # ------------------------------------------------- LLDP/CDP neighbours

    # LLDP-MIB columns walked for one device's remote-systems table. Each
    # entry is walked as its own column (the same one-GETBULK-walk-per-
    # column shape _fdb_entries' callers already use for the FDB), then
    # joined back together on the shared lldpRemTimeMark.lldpRemLocalPortNum.
    # lldpRemIndex suffix in _walk_lldp — a device answering some columns
    # and timing out on others still contributes a row with whatever did
    # answer, rather than the whole walk failing on the slowest column.
    _LLDP_COLUMNS = {
        "chassis_id_subtype": nodeoids.LLDP_REM_CHASSIS_ID_SUBTYPE,
        "chassis_id":         nodeoids.LLDP_REM_CHASSIS_ID,
        "port_id_subtype":    nodeoids.LLDP_REM_PORT_ID_SUBTYPE,
        "port_id":            nodeoids.LLDP_REM_PORT_ID,
        "port_descr":         nodeoids.LLDP_REM_PORT_DESC,
        "sys_name":           nodeoids.LLDP_REM_SYS_NAME,
        "sys_descr":          nodeoids.LLDP_REM_SYS_DESC,
    }
    _CDP_COLUMNS = {
        "device_id":   nodeoids.CDP_CACHE_DEVICE_ID,
        "device_port": nodeoids.CDP_CACHE_DEVICE_PORT,
        "platform":    nodeoids.CDP_CACHE_PLATFORM,
        "address":     nodeoids.CDP_CACHE_ADDRESS,
    }

    def read_device_neighbors(self, device_id: int) -> list[dict] | None:
        """Every LLDP neighbour this device reports, plus CDP as a
        fallback/supplement on Cisco gear (classic IOS in particular often
        speaks CDP only). The whole-device counterpart of
        read_device_mac_table, with the same None-vs-empty-list contract:
        None means neither protocol answered anything at all — storage
        must be left alone — while an empty list is a genuine "this device
        has no neighbours right now" and ages every stored row.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        entries, lldp_answered = self._walk_lldp(device, config)
        answered = lldp_answered
        if detected_vendor(device).lower() == "cisco":
            cdp_entries, cdp_answered = self._walk_cdp(device, config)
            entries.extend(cdp_entries)
            answered = answered or cdp_answered
        if not answered:
            return None
        return entries

    def _walk_lldp(self, device, config: dict) -> tuple[list[dict], bool]:
        """(neighbour rows, whether the device answered anything). See
        nodeoids' LLDP block for why lldpRemLocalPortNum is used directly
        as the local ifIndex rather than resolved through lldpLocPortTable.
        """
        values: dict[str, dict] = {}
        answered = False
        for key, oid in self._LLDP_COLUMNS.items():
            try:
                column = self._walk_column(device, config, oid)
            except SnmpError:
                column = {}
            if column:
                answered = True
            values[key] = column
        if not answered:
            return [], False
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 3:
                continue                          # not a real 3-arc index
            try:
                local_port = int(parts[-2])
            except ValueError:
                continue
            chassis_subtype = values["chassis_id_subtype"].get(suffix)
            entries.append({
                "if_index": local_port,
                "protocol": "lldp",
                "rem_index": suffix,
                "chassis_id": str(values["chassis_id"].get(suffix) or ""),
                "chassis_id_subtype": (int(chassis_subtype)
                                       if isinstance(chassis_subtype, (int, float))
                                       else None),
                "port_id": str(values["port_id"].get(suffix) or ""),
                "port_id_subtype": (int(values["port_id_subtype"].get(suffix))
                                    if isinstance(values["port_id_subtype"].get(suffix),
                                                 (int, float)) else None),
                "port_descr": str(values["port_descr"].get(suffix) or ""),
                "sys_name": str(values["sys_name"].get(suffix) or ""),
                "sys_descr": str(values["sys_descr"].get(suffix) or ""),
            })
        return entries, True

    def _walk_cdp(self, device, config: dict) -> tuple[list[dict], bool]:
        """(neighbour rows, whether the device answered anything) from
        CISCO-CDP-MIB's cdpCacheTable. Indexed by cdpCacheIfIndex directly,
        so — unlike LLDP above — no local-port assumption is needed."""
        values: dict[str, dict] = {}
        answered = False
        for key, oid in self._CDP_COLUMNS.items():
            try:
                column = self._walk_column(device, config, oid)
            except SnmpError:
                column = {}
            if column:
                answered = True
            values[key] = column
        if not answered:
            return [], False
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            try:
                if_index = int(parts[0])
            except ValueError:
                continue
            device_id_text = str(values["device_id"].get(suffix) or "")
            entries.append({
                "if_index": if_index,
                "protocol": "cdp",
                "rem_index": suffix,
                "chassis_id": device_id_text,
                "sys_name": device_id_text,
                "port_id": str(values["device_port"].get(suffix) or ""),
                "platform": str(values["platform"].get(suffix) or ""),
                "remote_address": _format_cdp_address(values["address"].get(suffix)),
            })
        return entries, True

    def _run_lldp_table(self, device_id: int) -> None:
        """One scheduled LLDP/CDP walk, mirroring _run_mac_table exactly:
        a worker thread must never die quietly, and a device that answers
        neither protocol leaves its stored neighbours alone rather than
        deleting them — see read_device_neighbors' None contract."""
        try:
            entries = self.read_device_neighbors(device_id)
            if entries is None:
                return
            stored = self.db.replace_neighbors(device_id, entries)
            self._bump("lldp_walks")
            self.log.add(NODES, f"Learned {stored} LLDP/CDP neighbour(s) on "
                                f"device #{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"LLDP/CDP walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._lldp_running.discard(device_id)

    # Bounds for the OID browser. Generous enough to be useful on a switch,
    # small enough that a dialog someone is sitting in front of cannot hang:
    # a full walk of a large device is tens of thousands of objects and
    # minutes of GETNEXTs, which is why this browses subtrees rather than
    # offering "walk everything".
    # Bounds on the on-demand credential probe in working_config().
    _PROBE_BUDGET_S = 8.0
    _PROBE_RETRY_S = 60.0

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
        budget = float(budget_s or self._BROWSE_BUDGET_S)
        rows, stopped = self._walk_from(device, config, base, max_rows, budget)
        return {"base": base, "rows": rows, "stopped": stopped,
                "complete": stopped == "end of subtree"}

    def _bulk_settings(self, device, config: dict) -> tuple:
        """(use GETBULK, repetitions) for a walk of this device.

        The repetition count is remembered per device: an agent that
        answered "tooBig" once will answer it again, and re-learning the
        same limit at the start of every walk costs a wasted round trip
        each time.
        """
        settings = self.db.settings()
        configured = int(settings.get("snmp_bulk_max_repetitions", 40) or 0)
        raw_version = config.get("snmp_version")
        is_v1 = raw_version is not None and int(raw_version) == 0
        if is_v1 or configured <= 0:
            return False, 0
        learned = self._bulk_repetitions.get(device["id"])
        return True, min(configured, learned) if learned else configured

    def _remember_repetitions(self, device, repetitions: int) -> None:
        self._bulk_repetitions[device["id"]] = max(1, int(repetitions))

    def _walk_from(self, device, config, base: str, max_rows: int,
                   budget_s: float, cancelled=None,
                   on_row=None) -> tuple[list[dict], str]:
        """The subtree walk itself: rows collected, and why it stopped.

        Shared by walk_subtree (one subtree, in front of a waiting human)
        and the background whole-device walk, which differ only in their
        bounds and in having a cancel — not in what a walk is. `cancelled`
        is polled between requests; `on_row` sees each row as it arrives so
        a job can report progress without exposing its list.

        GETBULK on v2c and v3, over one shared socket, the same way
        _walk_column already walks a table column. This was one GETNEXT and
        one fresh UDP socket per row: the review put a fleet-wide first
        identification at about 2.8 hours, almost all of it round trips
        that a single GETBULK could have answered forty at a time.
        """
        deadline = time.time() + budget_s
        rows: list[dict] = []
        stopped = "end of subtree"
        current = base
        use_bulk, repetitions = self._bulk_settings(device, config)
        session = self._session_for(device, config)
        try:
            while True:
                if cancelled is not None and cancelled():
                    stopped = f"cancelled after {len(rows)} row(s)"
                    break
                if len(rows) >= max_rows:
                    stopped = f"stopped at the {max_rows}-row limit"
                    break
                if time.time() > deadline:
                    stopped = f"stopped after {budget_s:.0f}s"
                    break
                try:
                    response = self._walk_request(
                        session, device, config, current,
                        PDU_GETBULK if use_bulk else PDU_GETNEXT, repetitions)
                except SnmpTimeout:
                    # Name what was actually tried. "The device stopped
                    # answering" alone sent an operator hunting the device
                    # when the answer was on this end — which credential we
                    # used, and against which address and port.
                    stopped = (
                        f"no reply from {device['ip']}:{DEFAULT_SNMP_PORT} "
                        f"using {_credential_label(config)}"
                        + (f" — stopped after {len(rows)} row(s)" if rows else ""))
                    break
                except SnmpError as exc:
                    stopped = f"SNMP error: {exc}"
                    break
                if use_bulk and response.error_status == 1:      # tooBig
                    if repetitions <= 1:
                        use_bulk = False
                    else:
                        repetitions = max(1, repetitions // 2)
                    self._remember_repetitions(device, repetitions)
                    continue
                if not response.varbinds:
                    stopped = "the device returned nothing"
                    break
                done = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base or oid.startswith(base + ".")):
                        done = True          # walked out of the subtree
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance",
                                      "endOfMibView"):
                        done = True
                        break
                    # An answer must lexicographically follow the request; a
                    # broken agent that echoes the request OID (or goes
                    # backwards) would otherwise fill the dialog with the
                    # same row until the cap or the clock stopped it,
                    # presented as the device's answer.
                    if _oid_key(oid) <= _oid_key(current):
                        stopped = ("the device answered with a non-increasing "
                                   f"OID ({oid}) — its SNMP agent is "
                                   f"misbehaving")
                        done = True
                        break
                    row = {"oid": oid, "type": vb["type"],
                           "value": vb["value"], "text": vb.get("text")}
                    rows.append(row)
                    if on_row is not None:
                        on_row(row)
                    current = oid
                    if len(rows) >= max_rows:
                        stopped = f"stopped at the {max_rows}-row limit"
                        done = True
                        break
                if done:
                    break
        finally:
            session.close()
        return rows, stopped

    # The whole-device walk starts here rather than at .1: 1.3.6.1 is
    # internet(1), which is every MIB an agent can sensibly hold. Starting
    # above it would miss nothing real and starting below it invites an
    # agent to walk its own private branches forever.
    _FULL_WALK_BASE = "1.3.6.1"

    def start_oid_walk(self, device_id: int) -> dict:
        """Begin a whole-device walk in the background, or report the one
        already running for this device.

        Held in memory rather than in a table: a walk result is transient —
        it exists to be downloaded once and then thrown away — and a row
        surviving a restart would describe a job whose thread is gone.
        """
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and job.running:
                return job.status()
            settings = self.db.settings()
            job = _OidWalkJob(
                self, device_id,
                base=self._FULL_WALK_BASE,
                max_rows=int(settings.get("oid_walk_max_rows", 100_000)),
                budget_s=float(settings.get("oid_walk_budget_s", 600.0)))
            self._oid_walks[device_id] = job
        job.start()
        return job.status()

    def oid_walk_status(self, device_id: int, with_rows: bool = False) -> dict | None:
        job = self._oid_walks.get(device_id)
        return None if job is None else job.status(with_rows=with_rows)

    def cancel_oid_walk(self, device_id: int) -> bool:
        job = self._oid_walks.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def forget_oid_walk(self, device_id: int) -> None:
        """Drop a finished walk's rows. Called once the file has been handed
        over, so a 100k-row walk does not sit in memory for the life of the
        process."""
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and not job.running:
                self._oid_walks.pop(device_id, None)

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
        version = int(config.get("snmp_version", 1))
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity, _proto, _pw = credential_for(config)
                request_id = session.next_request_id()
                packet = build_request(version, identity or "public", PDU_GETNEXT,
                                       request_id, [oid])
                return session.request(packet, request_id)
            return self._v3_exchange(session, device, config, PDU_GETNEXT, [oid])
        finally:
            session.close()

    def _session_for(self, device, config: dict) -> _Session:
        """One `_Session` (one UDP socket) for a caller that makes several
        round trips of its own — `_walk_column`'s whole walk, rather than a
        fresh socket per row the way `_snmp_get_next`/`_snmp_get` do for
        their single-request callers."""
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        return _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)

    def _walk_request(self, session: _Session, device, config: dict, oid: str,
                      pdu_tag: int, max_repetitions: int = 0) -> Response:
        """One GETNEXT/GETBULK round trip over an already-open session —
        the same v1/v2c/v3 request assembly `_snmp_get_next` uses, minus
        opening and closing a socket per call. `non_repeaters` is always 0:
        every walk here is over a single column, so there is nothing to
        exempt from repetition. Ignored by `build_request`/`build_v3_request`
        for a non-GETBULK `pdu_tag`, so a v1 caller can pass it unused."""
        version = int(config.get("snmp_version", 1))
        if version in (0, 1):
            identity, _proto, _pw = credential_for(config)
            request_id = session.next_request_id()
            packet = build_request(version, identity or "public", pdu_tag,
                                   request_id, [oid],
                                   max_repetitions=max_repetitions)
            return session.request(packet, request_id)
        return self._v3_exchange(session, device, config, pdu_tag, [oid],
                                 max_repetitions=max_repetitions)


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

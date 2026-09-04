"""WirelessPoller: polls each configured FortiGate Wireless Controller for
its managed APs over SNMP.

Reuses the Nodes poller's low-level SNMP plumbing wholesale rather than
reinventing it: `nodepoll._Session` (one UDP socket per poll, with
retry), `nodepoll.EngineCache` (v3 engine discovery caching, keyed here
by controller id instead of device id), `nodepoll.credential_for()`
(decrypt-just-before-use, discard after), and `snmppoll`'s wire-format
functions. Same v1/v2c/v3 noAuthNoPriv/authNoPriv-only limitation as
Nodes (snmppoll raises SnmpUnsupported for v3 authPriv).

Table walking here is repeated GETNEXT, not GETBULK: this poller manages a
handful of controllers, not an estate of switches with hundreds-of-rows
forwarding tables, so the request-count problem GETBULK solves for
nodepoll.py's own `_walk_column` (4.34) does not arise here, and it is not
worth introducing a second table-walking idiom for one small poller.
"""

from __future__ import annotations

import random
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import fortinetoids as oids
from .eventlog import ERROR, NullLog, WIRELESS
from .nodepoll import EngineCache, _Session, credential_for
from .snmppoll import (
    PDU_GET, PDU_GETNEXT, PDU_REPORT, SnmpError, SnmpTimeout,
    build_request, build_v3_request, discovery_probe,
)
from .trapdecode import localized_key
from .wirelessdb import WirelessDatabase

# Only decides whether a string is already in dotted form; it is not a
# validator for whether the address is routable.
_DOTTED_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Bounds on the per-AP ping sweep. The module's whole design is "talk to the
# controller, not to every AP", so measuring per-AP latency is the one place
# that reaches further — and it must not be able to stretch a poll cycle on a
# controller carrying a hundred radios.
PING_TIMEOUT_MS = 700
PING_BUDGET_S = 20.0

SNMP_PORT = 161


class _AuthFailure(SnmpError):
    pass


class WirelessPoller:
    def __init__(self, db: WirelessDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        self._engines = EngineCache()
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._queued: set[int] = set()
        self._lock = threading.Lock()
        # Reset per controller in _poll_controller; defined here so the
        # helper is safe to call before a poll has started.
        self._ping_deadline = 0.0
        self.counters = {"polls": 0, "ok": 0, "errors": 0}
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._thread = threading.Thread(target=self._loop, name="wireless-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return "Poller stopped"
        return "Running"

    def poll_now(self, controller_id: int) -> None:
        with self._lock:
            if controller_id in self._queued or not self._executor:
                return
            self._queued.add(controller_id)
        try:
            self._executor.submit(self._run_one, controller_id)
        except RuntimeError:
            with self._lock:
                self._queued.discard(controller_id)

    def _loop(self) -> None:
        next_run: dict[int, float] = {}
        while not self._stop.is_set():
            settings = self.db.settings()
            if settings.get("enabled", True):
                interval = max(10, int(settings.get("poll_interval_s", 60)))
                now = time.time()
                for controller in self.db.controllers():
                    if not controller["enabled"]:
                        continue
                    due = next_run.get(controller["id"], 0)
                    if now >= due:
                        next_run[controller["id"]] = now + interval
                        self.poll_now(controller["id"])
            self._stop.wait(1.0)

    def _bump(self, key: str, by: int = 1) -> None:
        """counters[...] += 1 from a pool worker is a read-modify-write on a
        shared dict; under the lock the totals stay exact."""
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + by

    def _run_one(self, controller_id: int) -> None:
        try:
            controller = self.db.controller(controller_id)
            if controller is None:
                return
            self._bump("polls")
            self._poll_controller(controller)
            self._bump("ok")
        except Exception:
            self._bump("errors")
            traceback.print_exc()
            self.log.add(ERROR, f"Wireless poll of controller {controller_id} failed",
                        detail=traceback.format_exc())
        finally:
            with self._lock:
                self._queued.discard(controller_id)

    # --------------------------------------------------------------- polling

    def _ping_ap(self, ip: str, status: str) -> float | None:
        """Round-trip to one AP, or None.

        None means "no reading", which the column shows as blank: an AP that
        does not answer ICMP is not an AP with a 0 ms response, and storing 0
        would sort it to the top of the fastest devices. An offline AP is not
        probed at all — the controller has already said it is gone, and
        waiting out a timeout per absent AP is what would make the sweep slow.
        """
        if not ip or status != "online":
            return None
        if time.time() > self._ping_deadline:
            return None
        started = time.time()
        try:
            from .ipam_scan import ping_once
            ok = ping_once(ip, timeout_ms=PING_TIMEOUT_MS)
        except Exception:
            return None
        return (time.time() - started) * 1000.0 if ok else None

    def _poll_controller(self, controller) -> None:
        config = dict(controller)
        # One budget for the whole controller's sweep, so a rack of
        # unreachable APs cannot add a timeout each to the cycle.
        self._ping_deadline = time.time() + PING_BUDGET_S
        try:
            names = self._walk_column(controller, config, oids.WTP_CONFIG_NAME)
            macs = self._walk_column(controller, config, oids.WTP_SESSION_MAC)
            ips = self._walk_column(controller, config, oids.WTP_SESSION_IP)
            states = self._walk_column(controller, config, oids.WTP_SESSION_CONNECTION_STATE)
            models = self._walk_column(controller, config, oids.WTP_SESSION_MODEL)
            stations = self._walk_column(controller, config, oids.WTP_SESSION_STATION_COUNT)
            modes = self._walk_column(controller, config, oids.WTP_RADIO_MODE)
            channels = self._walk_column(controller, config, oids.WTP_RADIO_CHANNEL)
            powers = self._walk_column(controller, config, oids.WTP_RADIO_OPERATING_POWER)
            radio_stations = self._walk_column(controller, config, oids.WTP_RADIO_STATION_COUNT)
        except SnmpError as exc:
            self.db.record_poll(controller["id"], ok=False, error=str(exc))
            self.log.add(ERROR, f"Wireless controller {controller['name']} unreachable",
                        detail=str(exc))
            return

        # WTP_SESSION_* suffixes are "<vdomIndex>.<wtpIdLength>.<wtpId chars...>"
        # (WtpId is a string-valued table index, encoded the same way any
        # DisplayString index is in SNMP's OID-suffix convention); WTP_CONFIG_NAME
        # shares that same (vdom, wtpId) key. WTP_RADIO_* adds one more
        # trailing arc for the radio id.
        seen: set[tuple[str, str]] = set()
        for suffix, mac in macs.items():
            vdom_wtp = _split_vdom_wtp(suffix)
            if vdom_wtp is None:
                continue
            vdom, wtp_id = vdom_wtp
            seen.add((vdom, wtp_id))
            state_num = states.get(suffix)
            status = oids.CONNECTION_STATE.get(
                int(state_num) if state_num is not None else -1, "other")
            ip = _format_ip(ips.get(suffix))
            ap_id = self.db.upsert_ap(
                controller["id"], wtp_id, vdom,
                name=names.get(suffix) or wtp_id,
                status=status,
                model=models.get(suffix) or "",
                mac_address=_format_mac(mac),
                ip=ip,
                response_ms=self._ping_ap(ip, status),
                station_count=_as_int(stations.get(suffix)))
            radios = []
            prefix = suffix + "."
            # Keyed off the mode column rather than the channel column: a
            # disabled or monitor-mode radio reports a mode but may report no
            # channel at all, and dropping it entirely is what made a
            # FAP-231F look like it had two radios when it has three.
            radio_suffixes = sorted(
                set(modes) | set(channels) | set(powers) | set(radio_stations))
            for radio_suffix in radio_suffixes:
                if not radio_suffix.startswith(prefix):
                    continue
                radio_id = radio_suffix[len(prefix):]
                channel = channels.get(radio_suffix)
                mode_num = modes.get(radio_suffix)
                radios.append({
                    "radio_id": radio_id,
                    "channel": str(channel) if channel is not None else None,
                    "mode": oids.RADIO_MODE.get(
                        int(mode_num) if mode_num is not None else -1, "other"),
                    "operating_power_dbm": _as_int(powers.get(radio_suffix)),
                    "station_count": _as_int(radio_stations.get(radio_suffix)),
                })
            self.db.replace_radios(ap_id, radios)

        self.db.record_poll(controller["id"], ok=True)
        stale_after_polls = int(self.db.settings().get("stale_after_polls", 5))
        removed = self.db.prune_stale(controller["id"], seen, stale_after_polls)
        for ap in removed:
            # prune_stale has already recorded the ap_removed row the
            # Alerts engine drains; this is the same fact in the event log,
            # where an operator watching the Debug feed will see it.
            self.log.add(WIRELESS,
                        f"AP {ap['name']} removed from {controller['name']}",
                        target=controller["ip"],
                        detail=f"wtp id   {ap['wtp_id']}\n"
                               f"vdom     {ap['vdom'] or '-'}\n"
                               f"missed   {ap['missed_polls']} consecutive poll(s)")

    # ------------------------------------------------------------ SNMP layer

    def _walk_column(self, controller, config: dict, base_oid: str) -> dict[str, object]:
        values: dict[str, object] = {}
        current = base_oid
        for _ in range(4096):
            response = self._snmp_get_next(controller, config, current)
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

    def _snmp_get_next(self, controller, config: dict, oid: str):
        version = int(config.get("snmp_version", 1))
        session = _Session(controller["ip"], SNMP_PORT, 3.0, 2)
        try:
            if version in (0, 1):
                identity, _proto, _pw = credential_for(config)
                request_id = random.randint(1, 2**16)
                packet = build_request(version, identity or "public", PDU_GETNEXT,
                                       request_id, [oid])
                # The id filter is what makes a late reply to the previous
                # GETNEXT a dropped datagram rather than this one's answer.
                return session.request(packet, expect_request_id=request_id)
            identity, auth_proto, password = credential_for(config)
            engine = self._engines.get(controller["id"])
            if engine is None:
                probe = discovery_probe()
                response = session.request(probe)
                if not response.engine_id:
                    raise SnmpError(f"{controller['ip']}: no engine id in discovery reply")
                self._engines.set(controller["id"], response.engine_id,
                                  response.engine_boots, response.engine_time)
                engine = self._engines.get(controller["id"])
            engine_id, boots, engine_time, _learned_at = engine
            auth_key = localized_key(auth_proto, password, engine_id) \
                if auth_proto and password else None
            request_id = random.randint(1, 2**16)
            packet = build_v3_request(
                random.randint(1, 2**16), request_id, PDU_GETNEXT, [oid],
                engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
                user=identity or "", auth_proto=auth_proto, auth_key=auth_key)
            response = session.request(packet, expect_request_id=request_id)
            if response.pdu_tag == PDU_REPORT:
                self._engines.invalidate(controller["id"])
                raise _AuthFailure(f"{controller['ip']}: engine resync required")
            return response
        finally:
            session.close()


def _split_vdom_wtp(suffix: str) -> tuple[str, str] | None:
    """'<vdomIndex>.<len>.<char> <len>.<char>...' -> (vdom, wtp_id). WtpId
    is an ASN.1 OCTET STRING/DisplayString table index, so its OID-suffix
    encoding is a length prefix followed by that many decimal char-code
    arcs -- the same convention any string-indexed SNMP table uses."""
    parts = suffix.split(".")
    if len(parts) < 2:
        return None
    vdom = parts[0]
    try:
        length = int(parts[1])
        chars = parts[2:2 + length]
        if len(chars) != length:
            return None
        wtp_id = "".join(chr(int(c)) for c in chars)
    except (ValueError, IndexError):
        return None
    return vdom, wtp_id


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_ip(value) -> str:
    """fgWcWtpSessionWtpIpAddress is an InetAddress — four raw bytes for IPv4,
    sixteen for IPv6 — but by the time it reaches here snmppoll has already
    turned the octets into text: a non-printable string comes back as
    space-separated hex ("7F 00 00 01"), not as bytes. So the hex form is the
    normal case, and the dotted form (which some FortiOS builds send, and
    which the IpAddress type decodes to directly) is accepted as well.

    Anything that is neither becomes blank rather than a mangled address — a
    six-byte MAC, for instance, must not be stored as an IP and pinged.
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value or "").strip()
        if not text:
            return ""
        if _DOTTED_RE.match(text):
            return text
        groups = text.replace(":", " ").split()
        try:
            raw = bytes(int(g, 16) for g in groups if len(g) <= 2)
        except ValueError:
            return ""
        if len(raw) != len(groups):
            return ""
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
    return ""


def _format_mac(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return ":".join(f"{b:02x}" for b in value)
    return str(value or "")

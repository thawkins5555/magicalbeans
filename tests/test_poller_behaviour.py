"""Poller behaviour, driven end to end against stub SNMP agents: in/out octet
counters track their 32/64-bit width independently (a mixed ifXTable/ifTable
row still rates correctly across a wrap); in_util/out_util are clamped to
[0, 100] even with ifSpeed's RFC 2863 sentinel as the denominator; fortipoll's
_walk_column stops once GETNEXT stops advancing; and a post-reboot link
transition is suppressed only when _interface_reassigned sees a real port swap."""
import os
import socket
import threading
import time
import types

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import tmpdir

from netpath import nodeoids
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller, counter_rate, detect_reboot
import netpath.nodepoll as nodepoll_mod
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    T_SEQUENCE, T_TIMETICKS, T_COUNTER32, T_COUNTER64, T_GAUGE32,
    T_NO_SUCH_OBJECT, T_NO_SUCH_INSTANCE, T_END_OF_MIB_VIEW,
    PDU_GET, PDU_GETNEXT, PDU_GETBULK, PDU_RESPONSE,
    enc_int, enc_octets, enc_unsigned, enc_varbind, format_ticks, _tlv,
)
from netpath.wirelessdb import WirelessDatabase
from netpath.fortipoll import WirelessPoller

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


# --------------------------------------------------------------- Fix 1 (pure)

def test_counter_rate_width_matters():
    """The exact scenario Fix 1 exists for: a 32-bit counter that wrapped
    between two samples must compute a real rate, while the same pair of
    samples fed through the 64-bit branch (what the pre-fix single
    `_octet_bits` flag would have done to a genuinely 32-bit ifOutOctets
    riding alongside an answered ifHCInOctets) must refuse instead of
    reporting a fabricated multi-terabyte rate -- counter_rate treats any
    decrease at bit_width >= 64 as a reset, never a wrap, per its own
    docstring."""
    previous = 4_294_967_290       # 6 short of 2**32
    current = 1_000                # wrapped past 2**32 and a bit further
    dt = 1.0
    rate_32 = counter_rate(previous, 0.0, current, dt, 32)
    expected = ((2 ** 32) - previous + current) / dt
    check(rate_32 == expected,
          f"32-bit width computes the wrap-adjusted rate ({rate_32} == {expected})")
    rate_64 = counter_rate(previous, 0.0, current, dt, 64)
    check(rate_64 is None,
          "64-bit width on the same decreasing pair returns None (a reset, not a wrap) "
          f"(got {rate_64})")


# ------------------------------------------------------- in-process stub agent

class _OneInterfaceAgent:
    """A minimal SNMPv2c agent serving sysDescr/sysName/sysUpTime and a
    single IF-MIB/ifXTable row, with just enough state exposed as mutable
    attributes for the two scenarios below: an independent per-counter
    64/32-bit width split (Fix 1), and a utilization clamp driven off the
    ifSpeed sentinel (Fix 3). Modeled on test_nodepoll_e2e.py's StubAgent,
    trimmed to one interface and parametrized rather than mode-switched
    since both scenarios here only ever need one row."""

    def __init__(self, *, if_speed: int, if_high_speed: int | None,
                hc_out_answers: bool):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.started_at = time.time()
        self.if_speed = if_speed
        self.if_high_speed = if_high_speed
        self.hc_out_answers = hc_out_answers
        self.hc_in = 10_000_000
        self.hc_out = 10_000_000
        self.out32 = 4_294_967_290     # 6 short of 2**32, for the wrap scenario

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def uptime_ticks(self) -> int:
        # Monotonically increasing across both polls in every scenario
        # here: detect_reboot must never fire, since a "reboot" this poll
        # is exactly the other gate (Fix 2) and would mask what these
        # tests are checking.
        return 12345 + int((time.time() - self.started_at) * 100)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                reply = self._handle(data)
            except Exception as exc:  # pragma: no cover - debug aid
                print("stub agent error:", exc, flush=True)
                continue
            if reply is not None:
                self.sock.sendto(reply, addr)

    def _response(self, version, request_id, varbinds_bytes: bytes) -> bytes:
        pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
                   _tlv(T_SEQUENCE, varbinds_bytes))
        return _tlv(T_SEQUENCE, enc_int(version) + enc_octets("public") + pdu)

    def _handle(self, data: bytes):
        req = decode_response(data)
        oids = [vb["oid"] for vb in req.varbinds]
        if req.pdu_tag == PDU_GET:
            parts = b"".join(enc_varbind(oid, self._value_for(oid)) for oid in oids)
            return self._response(req.version, req.request_id, parts)
        if req.pdu_tag == PDU_GETNEXT:
            next_oid, next_val = self._next_for(oids[0])
            return self._response(req.version, req.request_id,
                                  enc_varbind(next_oid, next_val))
        if req.pdu_tag == PDU_GETBULK:
            # error_index carries max_repetitions on the wire (see
            # snmppoll._pdu_bytes) -- chain the same GETNEXT successor
            # step once per repetition, exactly what a real GetBulk reply
            # is.
            cursor = oids[0]
            parts = b""
            for _ in range(max(1, req.error_index or 1)):
                cursor, value = self._next_for(cursor)
                parts += enc_varbind(cursor, value)
            return self._response(req.version, req.request_id, parts)
        return None

    # -- scalar / single-row table data -------------------------------------

    def _value_for(self, oid: str) -> bytes:
        S = nodeoids.SYSTEM_SCALARS
        if oid == S["sys_descr"]:
            return enc_octets("Stub Agent Test Device v1.0")
        if oid == S["sys_object_id"]:
            return enc_octets("dummy")
        if oid == S["sys_uptime"]:
            return enc_unsigned(T_TIMETICKS, self.uptime_ticks())
        if oid == S["sys_contact"]:
            return enc_octets("test@example.com")
        if oid == S["sys_name"]:
            return enc_octets("stub-agent")
        if oid == S["sys_location"]:
            return enc_octets("lab")

        IF = nodeoids.IF_TABLE
        IFX = nodeoids.IFX_TABLE
        if oid == f"{IF['if_index']}.1":
            return enc_int(1)
        if oid == f"{IF['if_descr']}.1":
            return enc_octets("Gi0/1")
        if oid == f"{IF['if_admin_status']}.1":
            return enc_int(1)
        if oid == f"{IF['if_oper_status']}.1":
            return enc_int(1)
        if oid == f"{IF['if_phys_addr']}.1":
            return enc_octets(bytes([2, 0, 0, 0, 0, 1]))
        if oid == f"{IF['if_speed']}.1":
            return enc_unsigned(T_GAUGE32, self.if_speed)
        if oid == f"{IF['if_in_octets']}.1":
            return enc_unsigned(T_COUNTER32, 12_345)     # unused: hc_in always answers
        if oid == f"{IF['if_out_octets']}.1":
            return enc_unsigned(T_COUNTER32, self.out32 % (2 ** 32))
        if oid in (f"{IF['if_in_errors']}.1", f"{IF['if_out_errors']}.1",
                  f"{IF['if_in_discards']}.1", f"{IF['if_out_discards']}.1"):
            return enc_unsigned(T_COUNTER32, 0)
        if oid == f"{IFX['if_alias']}.1":
            return enc_octets("link1")
        if oid == f"{IFX['if_high_speed']}.1":
            if self.if_high_speed is None:
                return _tlv(T_NO_SUCH_OBJECT, b"")
            return enc_unsigned(T_GAUGE32, self.if_high_speed)
        if oid == f"{IFX['if_hc_in_octets']}.1":
            return enc_unsigned(T_COUNTER64, self.hc_in)
        if oid == f"{IFX['if_hc_out_octets']}.1":
            if not self.hc_out_answers:
                return _tlv(T_NO_SUCH_INSTANCE, b"")
            return enc_unsigned(T_COUNTER64, self.hc_out)
        return _tlv(T_NO_SUCH_OBJECT, b"")     # if_discontinuity and anything else

    def _next_for(self, oid: str):
        """The ifIndex column's lexicographic successor chain: one real
        row, then out of the subtree. Same shape as
        test_nodepoll_e2e.py's StubAgent, with n=1."""
        base = nodeoids.IF_TABLE["if_index"]
        if oid == base:
            return f"{base}.1", enc_int(1)
        if oid == f"{base}.1":
            return "1.3.6.1.2.1.2.2.1.2.1", enc_octets("out-of-subtree")
        return "9.9.9", _tlv(T_END_OF_MIB_VIEW, b"")


def _poll_once(poller: NodePoller, db: NodesDatabase, device_id: int) -> None:
    device = db.device(device_id)
    config = db.effective_config(device)
    poller._poll_device(device, config)


def _force_dt(db: NodesDatabase, device_id: int, if_index: int, dt: float) -> None:
    """Backdates the stored last_sample_ts so the next poll's rate is
    computed across a known dt, without an actual sleep: the poll that
    follows stamps its own sample_ts from a fresh time.time() call a few
    milliseconds later, so the realized dt is `dt` plus that small,
    negligible overhead rather than whatever a real sleep would jitter
    by."""
    db._conn.execute(
        "UPDATE interfaces SET last_sample_ts=? WHERE device_id=? AND if_index=?",
        (time.time() - dt, device_id, if_index))
    db._conn.commit()


def test_independent_octet_widths():
    """A row that answers ifHCInOctets but not ifHCOutOctets (a partial
    per-varbind failure, common on flaky agents) must end up with
    in-width 64 and out-width 32 -- not one flag covering both. Proven
    behaviourally: the 32-bit ifOutOctets fallback is made to wrap
    between the two polls below, and pre-fix (one combined
    `_octet_bits` derived from hc_in OR hc_out) that wrap would hit
    counter_rate's bit_width>=64 branch and come back None, exactly as
    test_counter_rate_width_matters proves above."""
    agent = _OneInterfaceAgent(if_speed=1_000_000_000, if_high_speed=1000,
                               hc_out_answers=False)
    agent.start()
    tmp = tmpdir("poller_review_widths_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "widths-stub", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(1 in ifaces, "poll 1: interface 1 discovered")
        check(ifaces[1]["in_bps"] is None and ifaces[1]["out_bps"] is None,
              "poll 1: first poll has no prior sample, so no rate yet")

        _force_dt(db, device_id, 1, 1.0)
        agent.hc_in += 500_000                                # ordinary increase
        agent.out32 = (agent.out32 + 1_006) % (2 ** 32)        # wraps: -> 1000

        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        in_bps = ifaces[1]["in_bps"]
        out_bps = ifaces[1]["out_bps"]
        check(in_bps is not None and in_bps > 0,
              f"poll 2: in_bps computed off the 64-bit hc_in counter ({in_bps})")
        check(out_bps is not None and 0 < out_bps < 5_000,
              "poll 2: out_bps computed off the 32-bit ifOutOctets wrap, not "
              f"dropped as a bogus 64-bit reset (got {out_bps})")
    finally:
        agent.stop()
        db.close()


def test_utilization_clamped_at_sentinel():
    """ifHighSpeed absent for a row leaves ifSpeed's RFC 2863 sentinel
    (4294967295) as the only denominator. Driven fast enough that the
    raw (pre-clamp) utilization would land around 120% -- comfortably
    under counter_rate's own ~1.3x rate-vs-speed rejection ceiling, so
    the rate is computed rather than refused, and comfortably over 100%
    so the clamp is what is actually being tested. if_in_util_pct must
    read exactly 100.0, not the unclamped ~120."""
    SENTINEL = 4_294_967_295
    agent = _OneInterfaceAgent(if_speed=SENTINEL, if_high_speed=None,
                               hc_out_answers=True)
    agent.start()
    tmp = tmpdir("poller_review_util_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "sentinel-stub", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(ifaces[1]["speed_bps"] == float(SENTINEL),
              f"poll 1: speed_bps falls back to the raw ifSpeed sentinel "
              f"when ifHighSpeed is absent ({ifaces[1]['speed_bps']})")

        _force_dt(db, device_id, 1, 1.0)
        # rate*8 ~= 1.2 * speed_bps: over 100% utilization, but under
        # counter_rate's 1.3x-of-speed_bps rejection so the rate survives
        # to reach the util clamp instead of coming back None.
        bump = int(SENTINEL * 1.2 / 8)
        agent.hc_in += bump
        agent.hc_out += bump

        _poll_once(poller, db, device_id)
        metrics = {row["key"]: row for row in db.metrics(device_id)}
        check("if_in_util_pct.1" in metrics, "poll 2: in_util_pct metric recorded")
        if "if_in_util_pct.1" in metrics:
            value = metrics["if_in_util_pct.1"]["last_value"]
            check(value == 100.0,
                 f"poll 2: in_util_pct clamped to exactly 100.0 (got {value})")
        check("if_out_util_pct.1" in metrics, "poll 2: out_util_pct metric recorded")
        if "if_out_util_pct.1" in metrics:
            value = metrics["if_out_util_pct.1"]["last_value"]
            check(value == 100.0,
                 f"poll 2: out_util_pct clamped to exactly 100.0 (got {value})")
    finally:
        agent.stop()
        db.close()


# ---------------------------------------------------------- Fix 2, take 2

class _ReassignableInterfaceAgent:
    """A minimal SNMPv2c agent serving sysUpTime and a single IF-MIB row
    whose oper_status, descr, and phys_addr are all mutable, plus a
    rebootable uptime. Modeled on test_nodepoll_e2e.py's StubAgent (for
    the reboot simulation via uptime_ticks_base) and this file's own
    _OneInterfaceAgent (for the one-row IF-MIB shape). Exists to drive
    _interface_reassigned's two branches: an ifIndex whose identity
    (phys_addr/descr) did or did not survive a reboot."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.started_at = time.time()
        self.uptime_ticks_base = 12345  # hundredths of a second
        self.if_oper = "up"
        self.if_descr = "Gi1/0/5"
        self.if_phys_addr = bytes([2, 0, 0, 0, 0, 5])

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def reboot(self):
        """Simulates the agent restarting with a small, fresh uptime --
        the same trick test_nodepoll_e2e.py's poll 8 uses to make
        detect_reboot fire."""
        self.uptime_ticks_base = 500
        self.started_at = time.time()

    def uptime_ticks(self) -> int:
        return self.uptime_ticks_base + int((time.time() - self.started_at) * 100)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                reply = self._handle(data)
            except Exception as exc:  # pragma: no cover - debug aid
                print("stub agent error:", exc, flush=True)
                continue
            if reply is not None:
                self.sock.sendto(reply, addr)

    def _response(self, version, request_id, varbinds_bytes: bytes) -> bytes:
        pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
                   _tlv(T_SEQUENCE, varbinds_bytes))
        return _tlv(T_SEQUENCE, enc_int(version) + enc_octets("public") + pdu)

    def _handle(self, data: bytes):
        req = decode_response(data)
        oids = [vb["oid"] for vb in req.varbinds]
        if req.pdu_tag == PDU_GET:
            parts = b"".join(enc_varbind(oid, self._value_for(oid)) for oid in oids)
            return self._response(req.version, req.request_id, parts)
        if req.pdu_tag == PDU_GETNEXT:
            next_oid, next_val = self._next_for(oids[0])
            return self._response(req.version, req.request_id,
                                  enc_varbind(next_oid, next_val))
        if req.pdu_tag == PDU_GETBULK:
            cursor = oids[0]
            parts = b""
            for _ in range(max(1, req.error_index or 1)):
                cursor, value = self._next_for(cursor)
                parts += enc_varbind(cursor, value)
            return self._response(req.version, req.request_id, parts)
        return None

    def _value_for(self, oid: str) -> bytes:
        S = nodeoids.SYSTEM_SCALARS
        if oid == S["sys_descr"]:
            return enc_octets("Stub Agent Test Device v1.0")
        if oid == S["sys_object_id"]:
            return enc_octets("dummy")
        if oid == S["sys_uptime"]:
            return enc_unsigned(T_TIMETICKS, self.uptime_ticks())
        if oid == S["sys_contact"]:
            return enc_octets("test@example.com")
        if oid == S["sys_name"]:
            return enc_octets("stub-agent")
        if oid == S["sys_location"]:
            return enc_octets("lab")

        IF = nodeoids.IF_TABLE
        IFX = nodeoids.IFX_TABLE
        if oid == f"{IF['if_index']}.1":
            return enc_int(1)
        if oid == f"{IF['if_descr']}.1":
            return enc_octets(self.if_descr)
        if oid == f"{IF['if_admin_status']}.1":
            return enc_int(1)
        if oid == f"{IF['if_oper_status']}.1":
            return enc_int(1 if self.if_oper == "up" else 2)
        if oid == f"{IF['if_phys_addr']}.1":
            return enc_octets(self.if_phys_addr)
        if oid == f"{IF['if_speed']}.1":
            return enc_unsigned(T_GAUGE32, 1_000_000_000)
        if oid == f"{IF['if_in_octets']}.1":
            return enc_unsigned(T_COUNTER32, 12_345)
        if oid == f"{IF['if_out_octets']}.1":
            return enc_unsigned(T_COUNTER32, 100)
        if oid in (f"{IF['if_in_errors']}.1", f"{IF['if_out_errors']}.1",
                  f"{IF['if_in_discards']}.1", f"{IF['if_out_discards']}.1"):
            return enc_unsigned(T_COUNTER32, 0)
        if oid == f"{IFX['if_alias']}.1":
            return enc_octets("link1")
        if oid == f"{IFX['if_high_speed']}.1":
            return enc_unsigned(T_GAUGE32, 1000)
        if oid == f"{IFX['if_hc_in_octets']}.1":
            return enc_unsigned(T_COUNTER64, 10_000_000)
        if oid == f"{IFX['if_hc_out_octets']}.1":
            return enc_unsigned(T_COUNTER64, 10_000_000)
        return _tlv(T_NO_SUCH_OBJECT, b"")

    def _next_for(self, oid: str):
        """One real row, then out of the subtree -- same shape as
        test_nodepoll_e2e.py's StubAgent and this file's
        _OneInterfaceAgent, with n=1."""
        base = nodeoids.IF_TABLE["if_index"]
        if oid == base:
            return f"{base}.1", enc_int(1)
        if oid == f"{base}.1":
            return "1.3.6.1.2.1.2.2.1.2.1", enc_octets("out-of-subtree")
        return "9.9.9", _tlv(T_END_OF_MIB_VIEW, b"")


def _setup_reassignable_device(prefix: str, name: str):
    """Common setup shared by the three Fix 2 tests below: start the
    agent, point a fresh db/poller at it. Returns (agent, db, poller,
    device_id); caller is responsible for agent.stop()/db.close() in a
    finally block."""
    agent = _ReassignableInterfaceAgent()
    agent.start()
    tmp = tmpdir(prefix)
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port
    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", name, group_id=group_id,
                              snmp_version=1, community="public",
                              ping_enabled=0, poll_interval_s=999,
                              snmp_timeout_s=1.0, snmp_retries=1)
    poller = NodePoller(db)
    return agent, db, poller, device_id


def test_link_down_recorded_after_reboot_when_identity_unchanged():
    """The regression itself: a reboot alone must not blind
    interface_down. The port at ifIndex 1 is the very same physical port
    across the reboot (phys_addr and descr both agree between the two
    polls) and goes up -> down on the same poll the reboot is first
    observed -- a real link_down event must still be recorded, since
    ifIndex was never reassigned here."""
    agent, db, poller, device_id = _setup_reassignable_device(
        "poller_review_reboot_same_", "reboot-same-stub")
    try:
        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(ifaces[1]["oper_status"] == "up", "poll 1: interface baseline is up")

        agent.if_oper = "down"
        agent.reboot()
        _poll_once(poller, db, device_id)

        reboot_events = db.device_events(device_id, kinds=["rebooted"])
        check(bool(reboot_events), "poll 2: a reboot was actually detected")

        iface_id = db.interface_id_for(device_id, 1)
        kinds = [e["kind"] for e in db.interface_events(iface_id)]
        check("link_down" in kinds,
              f"poll 2: link_down recorded despite the reboot -- identity "
              f"unchanged, so the up -> down comparison is still valid (got {kinds})")
    finally:
        agent.stop()
        db.close()


def test_link_down_suppressed_after_reboot_when_identity_changed():
    """The case Fix 2 exists for: the port answering at ifIndex 1 is
    provably a different physical port after the reboot (phys_addr AND
    descr both changed, as a stack renumbering would produce). No
    link_down may be recorded -- comparing the old port's 'up' against
    the new port's 'down' would fabricate an event about a port that
    never actually went down."""
    agent, db, poller, device_id = _setup_reassignable_device(
        "poller_review_reboot_diff_", "reboot-diff-stub")
    try:
        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(ifaces[1]["oper_status"] == "up", "poll 1: interface baseline is up")

        agent.if_oper = "down"
        agent.if_descr = "Gi1/0/9"
        agent.if_phys_addr = bytes([2, 0, 0, 0, 0, 9])
        agent.reboot()
        _poll_once(poller, db, device_id)

        reboot_events = db.device_events(device_id, kinds=["rebooted"])
        check(bool(reboot_events), "poll 2: a reboot was actually detected")

        iface_id = db.interface_id_for(device_id, 1)
        kinds = [e["kind"] for e in db.interface_events(iface_id)]
        check("link_down" not in kinds,
              f"poll 2: no link_down recorded -- ifIndex 1 names a different "
              f"port after the reboot, so its 'up' and 'down' are not "
              f"comparable (got {kinds})")
    finally:
        agent.stop()
        db.close()


def test_link_down_recorded_without_reboot():
    """Sanity check that the identity gate only narrows the reboot case:
    an ordinary up -> down with no reboot involved at all must still
    record a link_down exactly as before. (test_nodepoll_e2e.py's poll 3
    already covers this end to end; kept here too, directly alongside the
    two reboot scenarios above, as the third leg of that coverage.)"""
    agent, db, poller, device_id = _setup_reassignable_device(
        "poller_review_no_reboot_", "no-reboot-stub")
    try:
        _poll_once(poller, db, device_id)
        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(ifaces[1]["oper_status"] == "up", "poll 1: interface baseline is up")

        agent.if_oper = "down"
        _poll_once(poller, db, device_id)

        reboot_events = db.device_events(device_id, kinds=["rebooted"])
        check(not reboot_events, "poll 2: no reboot was involved in this scenario")

        iface_id = db.interface_id_for(device_id, 1)
        kinds = [e["kind"] for e in db.interface_events(iface_id)]
        check("link_down" in kinds,
              f"poll 2: ordinary up -> down (no reboot) still records "
              f"link_down -- the identity gate hasn't broken the everyday "
              f"path (got {kinds})")
    finally:
        agent.stop()
        db.close()


# --------------------------------------------------------------- Fix 4 (pure)

def test_fortipoll_walk_terminates_on_stuck_oid():
    """A GETNEXT peer that advances once and then keeps re-answering the
    same OID forever must not be walked to fortipoll's 4096-iteration
    cap: _walk_column has to notice the OID stopped advancing and stop
    itself, the same guard nodepoll.py's own _walk_column_status already
    applies via _oid_key. Driven directly against _walk_column with
    _snmp_get_next monkeypatched -- no real socket needed, since the walk
    loop itself is what is under test, not the wire format."""
    db = WirelessDatabase(os.path.join(tmpdir("poller_review_fortiwalk_"), "wireless.db"))
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    calls = {"n": 0}

    def fake_get_next(controller, config, oid):
        calls["n"] += 1
        # First call advances into the table (one real row); every call
        # after that echoes the same row back, exactly the misbehaviour
        # that was left unguarded.
        row_oid = f"{base_oid}.1"
        return types.SimpleNamespace(varbinds=[
            {"oid": row_oid, "type": "OctetString", "value": "AP0001"}])

    poller._snmp_get_next = fake_get_next
    controller = {"ip": "127.0.0.1", "id": 1}
    config = {"snmp_version": 1, "community": "public"}

    values = poller._walk_column(controller, config, base_oid)

    check(calls["n"] < 4096,
          f"walk against a stuck-OID peer stopped promptly, not at the "
          f"4096-row cap ({calls['n']} GETNEXT call(s))")
    check(values == {"1": "AP0001"},
          f"the one real row before the agent got stuck is still kept ({values})")
    db.close()


def test_format_ticks_divides_by_a_hundred():
    """The sibling every other uptime consumer already goes through, and now
    the reboot note's too. Pinned directly because "hundredths of a second"
    is exactly the step this product got wrong once: 15000 TimeTicks is two
    and a half minutes, not four hours."""
    for ticks, expected in ((15_000, "00:02:30.00"), (100, "00:00:01.00"),
                            (8_640_000, "1d 00:00:00"), (0, "00:00:00.00")):
        check(format_ticks(ticks) == expected,
              f"format_ticks({ticks}) is {expected} (got {format_ticks(ticks)})")


def test_reboot_note_is_human_units():
    """detect_reboot's note becomes the alert's message verbatim
    (alertengine._drain_device_events), and it used to print sysUpTime raw:
    a device up two and a half minutes reads 15000, so the alert said
    "...to 15000 hundredths of a second after 300s". Every other uptime
    consumer in the product divides by 100 first; this one now does too,
    and reboot_uptimes reads the same two figures back out for the
    device_rebooted template."""
    previous_ticks, current_ticks = 1_036_800_000, 15_000    # 120 days, 2.5 min
    rebooted, note = detect_reboot(current_ticks, 1300.0, previous_ticks, 1000.0)
    check(rebooted, "the reset is still detected")
    check(str(current_ticks) not in note and str(previous_ticks) not in note,
          f"neither raw tick count is printed at a human ({note!r})")
    check("hundredths" not in note, f"the note no longer says 'hundredths' ({note!r})")
    check(format_ticks(previous_ticks) in note and format_ticks(current_ticks) in note,
          f"both uptimes render through trapdecode.format_ticks ({note!r})")
    check("5 m 00 s" in note,
          f"the gap between readings is a duration, not a bare '300s' ({note!r})")

    previous, current = nodepoll_mod.reboot_uptimes(note)
    check(previous == format_ticks(previous_ticks)
          and current == format_ticks(current_ticks),
          f"the note round-trips back to its two uptimes ({previous!r}, {current!r})")
    check(nodepoll_mod.reboot_uptimes("something else entirely") == ("", ""),
          "a detail this did not write yields nothing rather than a wrong claim")


def main():
    test_counter_rate_width_matters()
    test_format_ticks_divides_by_a_hundred()
    test_reboot_note_is_human_units()
    test_independent_octet_widths()
    test_utilization_clamped_at_sentinel()
    test_link_down_recorded_after_reboot_when_identity_unchanged()
    test_link_down_suppressed_after_reboot_when_identity_changed()
    test_link_down_recorded_without_reboot()
    test_fortipoll_walk_terminates_on_stuck_oid()

    if FAILURES:
        print(f"\n{len(FAILURES)} test(s) failed:")
        for failure in FAILURES:
            print(f"  - {failure}")
        raise SystemExit(1)
    print("\nAll tests passed!")


if __name__ == "__main__":
    main()

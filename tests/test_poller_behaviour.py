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
                hc_out_answers: bool, if_type: int = 6):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.started_at = time.time()
        self.if_speed = if_speed
        self.if_high_speed = if_high_speed
        self.if_type = if_type          # ethernetCsmacd unless a test says else
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
        if oid == f"{IF['if_type']}.1":
            return enc_int(self.if_type)
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
    # Under the store's own lock, because this reaches past the store into
    # its connection while a poller thread may be writing through it. Without
    # the lock the two interleave, the worker's commit lands between this
    # UPDATE and this commit, and sqlite raises "cannot commit - no
    # transaction is active" -- a failure with nothing to do with the speed
    # arithmetic under test, roughly one run in ten, in whichever suite
    # happened to call this.
    with db._lock:
        db._conn.execute(
            "UPDATE interfaces SET last_sample_ts=? WHERE device_id=? AND if_index=?",
            (time.time() - dt, device_id, if_index))
        if db._conn.in_transaction:
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


def test_reboot_uptimes_refuses_the_legacy_sentence():
    """The 5.2 poller wrote the raw-tick sentence, and its rows are still
    drained by the 5.3 engine after a restart (the source cursor survives one).
    A loose `(.+?)` matched that sentence too and put "1036800000" in the
    reboot email's "Previous reported uptime" line -- the raw tick count this
    release exists to stop printing. Only what format_ticks can emit parses."""
    legacy = ("uptime dropped from 1036800000 to 15000 hundredths of a second "
              "after 300s without a reading")
    check(nodepoll_mod.reboot_uptimes(legacy) == ("", ""),
          f"the pre-5.3 sentence yields nothing, not its raw tick counts "
          f"({nodepoll_mod.reboot_uptimes(legacy)})")

    # Every shape format_ticks can emit, both sides: the sub-day HH:MM:SS.cc
    # form and the day form, the latter with a day count past one digit.
    for previous_ticks, current_ticks in ((1_036_800_000, 15_000),
                                          (4_294_000_000, 8_640_000),
                                          (360_000, 100),
                                          (8_640_000, 359_999)):
        rebooted, note = detect_reboot(current_ticks, 1300.0,
                                       previous_ticks, 1000.0)
        check(rebooted, f"the reset from {previous_ticks} is detected")
        check(nodepoll_mod.reboot_uptimes(note)
              == (format_ticks(previous_ticks), format_ticks(current_ticks)),
              f"{note!r} round-trips to its two uptimes "
              f"(got {nodepoll_mod.reboot_uptimes(note)})")


def test_reboot_note_has_no_empty_duration():
    """duration_text renders a sub-second gap as "", which pasted into the
    sentence unguarded read "after  without a reading" -- a double space and
    a claim with nothing in it."""
    rebooted, note = detect_reboot(100, 1000.4, 1_036_800_000, 1000.0)
    check(rebooted, "a reset across a sub-second gap is still detected")
    check("  " not in note and "after  without" not in note,
          f"no empty duration is pasted into the note ({note!r})")
    check(nodepoll_mod.reboot_uptimes(note)
          == (format_ticks(1_036_800_000), format_ticks(100)),
          f"the shortened note still round-trips "
          f"({nodepoll_mod.reboot_uptimes(note)})")


def test_interface_cap_is_a_note_not_an_error():
    """A device over _MAX_INTERFACES is a known, designed limit, not a fault.

    Reported as one it wrote snmp_error on the device row -- a red line in
    the device pane beside "snmp ok" -- and a NODES log line every poll
    interval for as long as the device stayed over the cap, which is where a
    real error that arrives later goes unnoticed. The truncation still has to
    reach the operator, so it travels as its own note: stored on the device
    row, handed back with the interface list it explains, and logged once
    when it starts rather than on every poll.
    """
    from netpath.web import api

    reported = 900
    folder = tmpdir("iface_cap_")
    db = NodesDatabase(os.path.join(folder, "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("192.0.2.77", "core-chassis", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=1.0, snmp_retries=0)
        poller = NodePoller(db)
        lines = []
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": lines.append(message))
        # The two SNMP touchpoints inside _poll_interfaces, stubbed so the
        # real one runs: a device that enumerates `reported` interfaces and
        # answers every per-interface GET with nothing in particular.
        poller._walk_indexes = lambda device, config, oid, raise_on_timeout=False: (
            list(range(1, reported + 1)), True, "")
        poller._interface_varbinds = lambda device, config, if_index, is_v1, \
            want_ifx, session=None, credential=None: ({}, want_ifx)
        poller._poll_snmp_scalars_with_credential = lambda device, config: (
            config, {"sys_descr": "big chassis", "sys_name": "core-chassis"},
            100_000, [])
        for name in ("_poll_poe", "_poll_stp", "_poll_environment",
                     "_check_vendor_mib", "_maybe_identify"):
            setattr(poller, name, lambda *a, **k: None)

        device = db.device(device_id)
        # Unpacked by position so a build that has no note to give still
        # reaches the assertions below and fails on what it actually got
        # wrong, rather than on the arity.
        read = poller._poll_interfaces(device, db.effective_config(device))
        rows, complete, reason = read[0], read[1], read[2]
        note = read[3] if len(read) > 3 else ""
        check(len(rows) == 512,
              f"the truncation itself is untouched: 512 interfaces read ({len(rows)})")
        check(complete is False,
              "...and the read is still marked incomplete, so the rows it "
              "never reached are not deleted")
        check(reason == "",
              f"**the cap is NOT an SNMP error reason** (got {reason!r})")
        check("900" in note and "512" in note,
              f"...it is a note, naming both counts ({note!r})")

        def poll():
            row = db.device(device_id)
            poller._poll_device(row, db.effective_config(row))

        for _ in range(3):
            poll()
        row = db.device(device_id)
        check(not row["snmp_error"],
              f"**three polls leave snmp_error empty** ({row['snmp_error']!r})")
        check(row["snmp_ok"] == 1, "...with SNMP itself still reported ok")
        truncation_lines = [line for line in lines if "900" in line]
        check(len(truncation_lines) == 1,
              f"**the truncation is logged ONCE, not once per poll** "
              f"({len(truncation_lines)} line(s) over three polls)")

        payload = api.get_nodes_device_interfaces(
            types.SimpleNamespace(nodes_db=db), {}, {}, device_id)
        check("900" in (payload.get("note") or "") and "512" in payload["note"],
              f"**the operator is still told the list is cut short**, beside "
              f"the interface list itself ({payload.get('note')!r})")
        check(len(payload["interfaces"]) == 512,
              "...which is the table the note is about")

        reported = 40
        poll()
        stored = db.device(device_id)
        check(not ("interfaces_note" in stored.keys()
                   and (stored["interfaces_note"] or "")),
              "a device that drops back under the cap loses the note")
        check(sum("no longer truncated" in line for line in lines) == 1,
              "...and says so once")
    finally:
        db.close()


# ------------------------------------------------- the walk's own two caps

class _BigColumnAgent:
    """Answers any walk of one column with an endless supply of rows, each
    carrying `value_bytes` of non-printable octet string, optionally after
    `delay_s`. One varbind per reply whatever max-repetitions asks for,
    which is a legal GetBulk answer and the only one that fits in a
    datagram at this size."""

    BASE = "1.3.6.1.2.1.17.1.4.1.2"          # dot1dBasePortIfIndex

    def __init__(self, value_bytes: int = 60_000, delay_s: float = 0.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self.value = bytes((index % 256) or 0xFF for index in range(value_bytes))
        self.delay_s = delay_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                req = decode_response(data)
                oid = req.varbinds[0]["oid"]
                if oid == self.BASE:
                    index = 0
                elif oid.startswith(self.BASE + "."):
                    index = int(oid[len(self.BASE) + 1:])
                else:
                    continue
                body = enc_varbind(f"{self.BASE}.{index + 1}", enc_octets(self.value))
                pdu = _tlv(PDU_RESPONSE, enc_int(req.request_id) + enc_int(0) +
                           enc_int(0) + _tlv(T_SEQUENCE, body))
                reply = _tlv(T_SEQUENCE, enc_int(req.version) +
                             enc_octets("public") + pdu)
            except Exception as exc:  # pragma: no cover - debug aid
                print("big-column agent error:", exc, flush=True)
                continue
            if self.delay_s:
                time.sleep(self.delay_s)
            self.sock.sendto(reply, addr)


def _walk_device(prefix: str, port: int, **overrides):
    db = NodesDatabase(os.path.join(tmpdir(prefix), "nodes.db"))
    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", "walk-target", group_id=group_id,
                              snmp_version=1, community="public",
                              ping_enabled=0, poll_interval_s=999,
                              snmp_timeout_s=1.0, snmp_retries=0, **overrides)
    nodepoll_mod.DEFAULT_SNMP_PORT = port
    poller = NodePoller(db)
    return db, poller, db.device(device_id)


def test_a_column_walk_is_bounded_by_bytes_not_only_rows():
    """16,384 rows of 64 KB octet string is three gigabytes retained on one
    poll worker: the row cap alone does not bound memory, because
    _decode_value renders a non-printable string as three bytes of Python
    str per wire byte and truncates only `text`. The row cap here is set
    far below the default so the unfixed walk finishes at all."""
    agent = _BigColumnAgent(value_bytes=60_000)
    agent.start()
    db, poller, device = _walk_device("poller_review_bytecap_", agent.port)
    try:
        db.save_settings({**db.settings(), "snmp_walk_max_rows": 200})
        lines = []
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": lines.append(message))
        values, complete, reason = poller._walk_column_detail(
            device, db.effective_config(device), agent.BASE)
        retained = sum(len(str(value)) for value in values.values())
        check(complete is False and "byte" in reason,
              f"a walk of 60 KB rows stops at the byte cap and says so "
              f"({reason!r})")
        check(len(values) < 200,
              f"...well before the 200-row cap it was given ({len(values)} rows)")
        check(retained <= poller._WALK_MAX_BYTES + 200_000,
              f"...having retained about the cap, not the row count times the "
              f"row size ({retained} bytes)")
        check(poller._WALK_MAX_BYTES >= 1024 * 1024,
              f"the cap is a few MB, not a limit a real table could reach "
              f"({poller._WALK_MAX_BYTES})")
        check(sum("byte" in line for line in lines) == 1,
              f"...and it is logged once, the way the row cap is ({lines})")
    finally:
        db.close()
        agent.stop()


def test_a_column_walk_has_a_deadline_even_when_the_caller_gives_none():
    """Of the ~30 column walks a full poll makes, two passed a deadline. An
    agent that answers each request just inside its timeout could hold a
    poll worker for the whole walk with no wall-clock ceiling at all."""
    agent = _BigColumnAgent(value_bytes=8, delay_s=0.1)
    agent.start()
    db, poller, device = _walk_device("poller_review_walkclock_", agent.port)
    try:
        db.save_settings({**db.settings(), "snmp_walk_max_rows": 30})
        poller._WALK_BUDGET_FRACTION = 0.0
        poller._WALK_BUDGET_FLOOR_S = 0.5
        started = time.time()
        values, complete, reason = poller._walk_column_detail(
            device, db.effective_config(device), agent.BASE)
        elapsed = time.time() - started
        check(complete is False and "time budget" in reason,
              f"a walk given no deadline derives one from the poll interval "
              f"and stops on it ({reason!r})")
        check(elapsed < 2.0 and len(values) < 30,
              f"...rather than running to the row cap ({len(values)} rows in "
              f"{elapsed:.1f}s)")
    finally:
        db.close()
        agent.stop()


# ------------------------------------- one socket per interface read, not 512

def test_the_interface_read_opens_one_socket_and_decrypts_once():
    """_interface_varbinds went through _snmp_get, which builds its own
    _Session -- a fresh UDP socket, and on v3 a fresh credential decrypt --
    per interface. A 512-port chassis was 512 ephemeral ports and 512
    decrypts per device per poll."""
    agent = _OneInterfaceAgent(if_speed=1_000_000_000, if_high_speed=1000,
                               hc_out_answers=True)
    agent.start()
    db, poller, device = _walk_device("poller_review_ifsockets_", agent.port)
    sessions = {"n": 0}
    credentials = {"n": 0}
    real_session, real_credential = nodepoll_mod._Session, nodepoll_mod.credential_for

    class CountingSession(real_session):
        def __init__(self, *args, **kwargs):
            sessions["n"] += 1
            super().__init__(*args, **kwargs)

    def counting_credential(config):
        credentials["n"] += 1
        return real_credential(config)

    nodepoll_mod._Session = CountingSession
    nodepoll_mod.credential_for = counting_credential
    try:
        # The ifIndex walk has its own session either way; this is about the
        # per-interface reads that follow it.
        poller._walk_indexes = lambda device, config, oid, raise_on_timeout=False: (
            list(range(1, 33)), True, "")
        rows, complete, reason, note = poller._poll_interfaces(
            device, db.effective_config(device))
        check(len(rows) == 32,
              f"all 32 interfaces are still read ({len(rows)})")
        check(rows[0]["descr"] == "Gi0/1" and rows[0]["speed_bps"] == 1_000_000_000,
              f"...and the row the agent really answers is unchanged ({rows[0]})")
        check(sessions["n"] == 1,
              f"32 interfaces cost ONE UDP socket, not one each "
              f"({sessions['n']} opened)")
        check(credentials["n"] == 1,
              f"...and one credential decrypt, not one each "
              f"({credentials['n']} decrypts)")
    finally:
        nodepoll_mod._Session = real_session
        nodepoll_mod.credential_for = real_credential
        db.close()
        agent.stop()


# ------------------------------- an OID that cannot be encoded, mid-poll

def test_an_unencodable_oid_does_not_freeze_the_device():
    """A ValueError is not an SnmpError, so one raised while building a
    request escaped _poll_device's every except clause: record_poll never
    ran and the device's status, last_poll_ts and snmp_error froze at
    whatever they last were, for ever. The same shape as the 5.8.0
    int(None) regression, through a different door -- here a stored MIB
    object whose OID carries an arc int() will not take."""
    agent, db, poller, device_id = _setup_reassignable_device(
        "poller_review_badoid_", "bad-oid-stub")
    try:
        _poll_once(poller, db, device_id)
        mib_id = db.add_mib_file("bad.mib", "BAD-MIB", 1, [], "")
        db.replace_mib_objects(mib_id, [
            {"name": "badScalar", "oid": "1.3.6.1.4.1.99999.\u00b2",
             "description": "", "syntax": "INTEGER", "enums": None,
             "is_notification": False}])
        db.update_device(device_id, mib_file_id=mib_id)
        before = db.device(device_id)["last_poll_ts"]
        time.sleep(0.01)
        raised = ""
        try:
            _poll_once(poller, db, device_id)
        except Exception as exc:
            raised = f"{type(exc).__name__}: {exc}"
        row = db.device(device_id)
        check(not raised,
              f"a MIB object whose OID cannot be encoded does not take the "
              f"poll with it ({raised})")
        check(row["last_poll_ts"] and row["last_poll_ts"] != before,
              "...record_poll still ran, so the device's status is this "
              "poll's rather than frozen at the last good one")
        check("not a valid object identifier" in (row["snmp_error"] or ""),
              f"...and the device row says what was wrong "
              f"({row['snmp_error']!r})")

        raised = ""
        try:
            poller.walk_subtree(device_id, "1.3.\u00b2")
        except ValueError as exc:
            raised = str(exc)
        check("An OID must be numeric" in raised,
              f"the OID browser refuses a non-ASCII digit up front rather "
              f"than letting the encoder refuse it on the wire ({raised!r})")
    finally:
        agent.stop()
        db.close()


# --------------------------------------- per-device state of deleted devices

# ------------------------- a truncated forwarding table never reaches storage

def _stub_columns(poller, answers: dict, seen: list):
    """Drives every column walk from a table of base OID -> (values, complete); stubs _walk_column_detail, which both _walk_column and _walk_column_status funnel through."""
    def detail(device, config, base_oid, raise_on_timeout=False, deadline=None):
        seen.append((base_oid, deadline))
        values, complete = answers.get(base_oid, ({}, True))
        return dict(values), complete, "" if complete else "cut short"
    poller._walk_column_detail = detail


def test_a_truncated_mac_table_never_reaches_storage():
    """A truncated FDB column must not reach replace_mac_entries as a complete table."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_macpartial_"), "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "fdb-sw", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=120,
                                  mac_table_interval_s=3600)
        stored_before = db.replace_mac_entries(device_id, [
            {"if_index": 10, "mac": "aa:bb:cc:00:00:01", "vlan": "10"},
            {"if_index": 10, "mac": "aa:bb:cc:00:00:02", "vlan": "10"},
            {"if_index": 20, "mac": "aa:bb:cc:00:00:03", "vlan": "20"},
        ])
        poller = NodePoller(db)
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": None)
        bridge = NodePoller._DOT1D_BASE_PORT_IF_INDEX
        qbridge = NodePoller._DOT1Q_FDB_PORT

        # The bridge-port map answers in full; the FDB column stops half way.
        seen = []
        _stub_columns(poller, {
            bridge: ({"1": 10, "2": 20}, True),
            qbridge: ({"10.170.187.204.0.0.1": 1}, False),
        }, seen)
        entries = poller.read_device_mac_table(device_id)
        check(entries is None,
              f"a forwarding-table column cut short reads as None, not as a "
              f"one-row table ({entries})")

        poller._run_mac_table(device_id)
        rows = db.mac_entries_for(device_id)
        present = [row["mac"] for row in rows if row["present"]]
        check(len(rows) == stored_before == 3 and len(present) == 3,
              f"...so the scheduled walk leaves all three stored MACs present "
              f"({len(present)} of {len(rows)} still present)")

        # Budget comes off mac_table_interval_s (1800s), not the 120s poll interval.
        fdb_deadlines = [deadline for oid, deadline in seen if oid == qbridge]
        budget = fdb_deadlines[0] if fdb_deadlines else None
        remaining = (budget - time.time()) if budget else 0.0
        check(remaining > 300,
              f"the FDB walk is given a budget off its own hourly cadence, not "
              f"half a two-minute poll interval ({remaining:.0f}s left)")

        # The same columns, finished: now the walk is authoritative again.
        _stub_columns(poller, {
            bridge: ({"1": 10, "2": 20}, True),
            qbridge: ({"10.170.187.204.0.0.9": 1}, True),
        }, [])
        entries = poller.read_device_mac_table(device_id)
        check(entries is not None and len(entries) == 1
              and entries[0]["mac"] == "aa:bb:cc:00:00:09",
              f"a walk that reached the end of the subtree still stores its "
              f"rows ({entries})")
        poller._run_mac_table(device_id)
        present = [row["mac"] for row in db.mac_entries_for(device_id)
                   if row["present"]]
        check(present == ["aabbcc000009"],      # nodesdb normalises on the way in
              f"...and ages out the three it genuinely no longer reports "
              f"({present})")
    finally:
        db.close()


def test_a_truncated_neighbour_or_vlan_column_never_reaches_storage():
    """A truncated LLDP/CDP or VLAN column must not contribute a blank-field row; both now leave storage alone."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_l2partial_"), "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "l2-sw", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=120,
                                  lldp_interval_s=3600, vlan_interval_s=3600)
        poller = NodePoller(db)
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": None)

        # --- LLDP: chassis id finishes, port id is cut short ---------------
        suffix = "0.1.1"
        columns = {NodePoller._LLDP_COLUMNS["chassis_id"]:
                   ({suffix: "aa:bb:cc:dd:ee:ff"}, True),
                   NodePoller._LLDP_COLUMNS["sys_name"]: ({suffix: "core-1"}, True),
                   NodePoller._LLDP_COLUMNS["port_id"]: ({}, False)}
        _stub_columns(poller, columns, [])
        entries = poller.read_device_neighbors(device_id)
        check(entries is None,
              f"an LLDP column cut short discards the whole pass rather than "
              f"storing neighbours with a blank port_id ({entries})")

        # Shown directly: the join really would produce a blanked row.
        device = db.device(device_id)
        rows, answered, complete = poller._walk_lldp(
            device, db.effective_config(device))
        check(answered and not complete and len(rows) == 1
              and rows[0]["chassis_id"] == "aa:bb:cc:dd:ee:ff"
              and rows[0]["port_id"] == "",
              f"...and the row it would have stored is indeed blanked ({rows})")

        columns[NodePoller._LLDP_COLUMNS["port_id"]] = ({suffix: "Gi0/24"}, True)
        _stub_columns(poller, columns, [])
        entries = poller.read_device_neighbors(device_id)
        check(entries is not None and len(entries) == 1
              and entries[0]["port_id"] == "Gi0/24",
              f"a pass whose every column finished still stores ({entries})")

        # --- VLAN: the static name column finishes, the egress bitmap does not
        vlan_columns = {
            nodeoids.DOT1D_BASE_PORT_IFINDEX: ({"1": 10}, True),
            nodeoids.DOT1Q_VLAN_STATIC_NAME: ({"10": "users"}, True),
            nodeoids.DOT1Q_VLAN_STATIC_EGRESS: ({"10": "\x80"}, False),
        }
        _stub_columns(poller, vlan_columns, [])
        result = poller.read_device_vlans(device_id)
        check(result is None,
              f"a VLAN column cut short discards the whole pass rather than "
              f"ageing out the memberships it never reached ({result})")

        vlan_columns[nodeoids.DOT1Q_VLAN_STATIC_EGRESS] = ({"10": "\x80"}, True)
        _stub_columns(poller, vlan_columns, [])
        result = poller.read_device_vlans(device_id)
        check(result is not None and [v["vlan"] for v in result["vlans"]] == [10],
              f"...while a finished VLAN pass still stores ({result})")
    finally:
        db.close()


def _counting_sessions(counts: dict):
    """Count _Session opens/closes and credential decrypts; returns the restore callable."""
    real_session, real_credential = nodepoll_mod._Session, nodepoll_mod.credential_for
    counts.update(opened=0, closed=0, decrypts=0)

    class CountingSession(real_session):
        def __init__(self, *args, **kwargs):
            counts["opened"] += 1
            super().__init__(*args, **kwargs)

        def close(self):
            counts["closed"] += 1
            return super().close()

    def counting_credential(config):
        counts["decrypts"] += 1
        return real_credential(config)

    nodepoll_mod._Session = CountingSession
    nodepoll_mod.credential_for = counting_credential

    def restore():
        nodepoll_mod._Session = real_session
        nodepoll_mod.credential_for = real_credential
    return restore


def test_the_custom_mib_read_opens_one_socket_and_decrypts_once():
    """_custom_mib_values must open one _Session and decrypt once for the whole batch, not per call: IP-MIB's 267 objects at 25/batch would otherwise cost eleven ports and twenty-two key derivations a poll."""
    agent = _OneInterfaceAgent(if_speed=1_000_000_000, if_high_speed=1000,
                               hc_out_answers=True)
    agent.start()
    db, poller, device = _walk_device("poller_review_mibsockets_", agent.port)
    counts: dict = {}
    restore = _counting_sessions(counts)
    try:
        oids = [f"1.3.6.1.4.1.9999.1.{index}.0" for index in range(267)]
        values = poller._custom_mib_values(device, db.effective_config(device),
                                           oids)
        batches = -(-len(oids) // poller._CUSTOM_MIB_BATCH)
        check(batches >= 10,
              f"the read really is split into batches ({batches} of "
              f"{poller._CUSTOM_MIB_BATCH})")
        check(counts["opened"] == 1,
              f"a 267-object MIB costs ONE UDP socket, not one per batch "
              f"({counts['opened']} opened)")
        check(counts["decrypts"] == 1,
              f"...and one credential decrypt, not one per batch "
              f"({counts['decrypts']} decrypts)")
        check(counts["closed"] == counts["opened"],
              f"...and the socket it did open is closed ({counts['closed']} "
              f"of {counts['opened']})")
        check(isinstance(values, dict),
              f"the varbind map still comes back ({type(values).__name__})")
    finally:
        restore()
        db.close()
        agent.stop()


def test_a_refused_credential_does_not_leak_the_interface_socket():
    """A refused credential (community with a comma) must not leak the interface socket _poll_interfaces already opened."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_ifleak_"), "nodes.db"))
    counts: dict = {}
    restore = _counting_sessions(counts)
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "comma-community",
                                  group_id=group_id, snmp_version=1,
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=0.3, snmp_retries=0)
        # Written past clean_community, which refuses this at save time now.
        with db._lock:
            db._conn.execute("UPDATE devices SET community = ? WHERE id = ?",
                             ("s3cret,alternate", device_id))
            db._conn.commit()
        poller = NodePoller(db)
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": None)
        device = db.device(device_id)
        poller._walk_indexes = lambda device, config, oid, raise_on_timeout=False: (
            [1, 2, 3], True, "")
        raised = ""
        try:
            poller._poll_interfaces(device, db.effective_config(device))
        except Exception as exc:
            raised = type(exc).__name__
        check(raised == "SnmpError",
              f"a comma-bearing community still refuses the interface read "
              f"({raised})")
        check(counts["opened"] == counts["closed"],
              f"...with no socket left open behind it ({counts['opened']} "
              f"opened, {counts['closed']} closed)")
    finally:
        restore()
        db.close()


def test_stopping_the_poller_drops_the_cached_walk_limits():
    """Stopping the poller must drop the cached walk limits, so a setting changed while off still reaches start_oid_walk."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_walkcache_"), "nodes.db"))
    try:
        poller = NodePoller(db)
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": None)
        settings = {**db.settings(), "enabled": True,
                    "snmp_bulk_max_repetitions": 10}
        db.save_settings(settings)
        poller._read_pool_settings(settings)
        check(poller._walk_limits()[1] == 10,
              f"the cache starts at the configured repetitions "
              f"({poller._walk_limits()[1]})")

        # `running` is read-only, so stubbed on the class for this one call
        # to reach reconfigure's disabled branch.
        real_running = NodePoller.running
        NodePoller.running = property(lambda self: True)
        try:
            poller.reconfigure({**settings, "enabled": False})
        finally:
            NodePoller.running = real_running
        db.save_settings({**settings, "snmp_bulk_max_repetitions": 40})
        check(poller._walk_settings is None,
              f"disabling polling drops the cached walk limits "
              f"({poller._walk_settings})")
        check(poller._walk_limits()[1] == 40,
              f"...so a walk started with the poller off reads the live "
              f"setting ({poller._walk_limits()[1]})")
    finally:
        db.close()


def test_only_an_unencodable_oid_is_reported_as_an_oid_fault():
    """Only an unencodable OID (SnmpBadOid) is reported as an OID fault; other ValueErrors still record the poll."""
    agent, db, poller, device_id = _setup_reassignable_device(
        "poller_review_narrowoid_", "narrow-oid-stub")
    try:
        _poll_once(poller, db, device_id)
        real = poller._poll_interfaces

        def raises_unrelated(device, config):
            raise ValueError("invalid literal for int() with base 10: 'n/a'")

        poller._poll_interfaces = raises_unrelated
        before = db.device(device_id)["last_poll_ts"]
        time.sleep(0.01)
        raised = ""
        try:
            _poll_once(poller, db, device_id)
        except Exception as exc:
            raised = f"{type(exc).__name__}: {exc}"
        row = db.device(device_id)
        error = row["snmp_error"] or ""
        check(not raised,
              f"an unrelated ValueError still does not take the poll with it "
              f"({raised})")
        check(row["last_poll_ts"] and row["last_poll_ts"] != before,
              "...record_poll still ran, so the device is not frozen")
        check("object identifier" not in error and "OID" not in error,
              f"...and it is NOT reported as an OID fault ({error!r})")
        check("n/a" in error,
              f"...while still saying what actually went wrong ({error!r})")
        poller._poll_interfaces = real

        # The genuine case still reads as one, through the dedicated class.
        raised = ""
        try:
            nodepoll_mod._assemble(nodepoll_mod.build_request, 1, "public",
                                   nodepoll_mod.PDU_GET, 1, ["1.3.-6.1"])
        except nodepoll_mod.SnmpBadOid as exc:
            raised = str(exc)
        check("negative arc" in raised,
              f"the encoder's refusal arrives as SnmpBadOid ({raised!r})")
        check(issubclass(nodepoll_mod.SnmpBadOid, ValueError)
              and not issubclass(nodepoll_mod.SnmpBadOid,
                                 nodepoll_mod.SnmpError),
              "...a ValueError and deliberately not an SnmpError, so it still "
              "travels past the poll's best-effort SnmpError arms")
    finally:
        agent.stop()
        db.close()


def test_deleting_a_device_drops_every_cache_keyed_on_it():
    """_forget_devices' own docstring says every per-device container is
    pruned. Five were not in its list, and _discovery_jobs was pruned
    nowhere at all: a finished sweep kept its settings dict, one _owners
    entry per address swept and a dead Thread for the life of the
    process, and drain() walks that dict every 50 ms."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_forget_"), "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("192.0.2.5", "doomed", group_id=group_id,
                                  poll_interval_s=999)
        poller = NodePoller(db)
        poller._schedule_pass()
        sets = (poller._auth_failing, poller._access_denied, poller._downgraded,
                poller._method_seeded, poller._arp_unanswered, poller._staggered)
        for members in sets:
            members.add(device_id)
        poller._snmp_failing_count[device_id] = 2
        poller._get_batch[device_id] = 12
        poller._credentials[device_id] = 0
        poller._discovery_jobs[1] = types.SimpleNamespace(
            running=False, target="192.0.2.0/24")
        poller._discovery_jobs[2] = types.SimpleNamespace(
            running=True, target="192.0.2.128/25")

        db.remove_device(device_id)
        poller._schedule_pass()

        leaked = [name for name, members in
                  (("_auth_failing", poller._auth_failing),
                   ("_access_denied", poller._access_denied),
                   ("_downgraded", poller._downgraded),
                   ("_method_seeded", poller._method_seeded),
                   ("_arp_unanswered", poller._arp_unanswered),
                   ("_staggered", poller._staggered),
                   ("_snmp_failing_count", poller._snmp_failing_count),
                   ("_get_batch", poller._get_batch),
                   ("_credentials", poller._credentials))
                  if device_id in members]
        check(not leaked,
              f"every per-device container forgets a deleted device ({leaked})")
        check(1 not in poller._discovery_jobs,
              "a finished discovery job is dropped with its settings dict, "
              "its address map and its dead thread")
        check(2 in poller._discovery_jobs,
              "...while a sweep still on the wire is kept")
    finally:
        db.close()


# ------------------------------------------- a secret in an error message

def test_a_refused_community_is_not_printed():
    """credential_for refuses a community containing a comma -- and put the
    community itself in the message, which _poll_device writes to
    devices.snmp_error, the device event log, the per-poll debug line, the
    API and any alert mail. _credential_label exists three screens above
    to prevent exactly this."""
    db = NodesDatabase(os.path.join(tmpdir("poller_review_secret_"), "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "comma-community",
                                  group_id=group_id, snmp_version=1,
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=0.3, snmp_retries=0)
        # Written past clean_community, which refuses this at save time now:
        # the fault is a database written before it did.
        secret = "s3cret,alternate"
        with db._lock:
            db._conn.execute("UPDATE devices SET community = ? WHERE id = ?",
                             (secret, device_id))
            db._conn.commit()
        poller = NodePoller(db)
        poller.log = types.SimpleNamespace(
            add=lambda category, message, target="", detail="": None)
        _poll_once(poller, db, device_id)
        error = db.device(device_id)["snmp_error"] or ""
        check("comma" in error,
              f"the refusal still reaches the operator ({error!r})")
        check(secret not in error and "s3cret" not in error,
              f"...without the community string in it ({error!r})")
    finally:
        db.close()


def main():
    test_counter_rate_width_matters()
    test_format_ticks_divides_by_a_hundred()
    test_reboot_note_is_human_units()
    test_reboot_uptimes_refuses_the_legacy_sentence()
    test_reboot_note_has_no_empty_duration()
    test_independent_octet_widths()
    test_utilization_clamped_at_sentinel()
    test_link_down_recorded_after_reboot_when_identity_unchanged()
    test_link_down_suppressed_after_reboot_when_identity_changed()
    test_link_down_recorded_without_reboot()
    test_fortipoll_walk_terminates_on_stuck_oid()
    test_interface_cap_is_a_note_not_an_error()
    test_a_column_walk_is_bounded_by_bytes_not_only_rows()
    test_a_column_walk_has_a_deadline_even_when_the_caller_gives_none()
    test_the_interface_read_opens_one_socket_and_decrypts_once()
    test_an_unencodable_oid_does_not_freeze_the_device()
    test_a_truncated_mac_table_never_reaches_storage()
    test_a_truncated_neighbour_or_vlan_column_never_reaches_storage()
    test_the_custom_mib_read_opens_one_socket_and_decrypts_once()
    test_a_refused_credential_does_not_leak_the_interface_socket()
    test_stopping_the_poller_drops_the_cached_walk_limits()
    test_only_an_unencodable_oid_is_reported_as_an_oid_fault()
    test_deleting_a_device_drops_every_cache_keyed_on_it()
    test_a_refused_community_is_not_printed()

    if FAILURES:
        print(f"\n{len(FAILURES)} test(s) failed:")
        for failure in FAILURES:
            print(f"  - {failure}")
        raise SystemExit(1)
    print("\nAll tests passed!")


if __name__ == "__main__":
    main()

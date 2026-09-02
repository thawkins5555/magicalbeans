"""End-to-end NodePoller test against a stub UDP SNMP agent (v2c only) —
plan section 6.3's "without a real agent" path. Exercises the full
_poll_device -> _snmp_get -> _poll_snmp_scalars/_poll_interfaces ->
nodesdb.record_poll/replace_interfaces/record_metric_sample chain with no
external dependency.

Not part of the shipped test suite — a throwaway verification script.
"""
import os
import socket
import sys
import tempfile
import threading
import time

import _paths  # noqa: F401  (puts the repo root on sys.path)

from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.snmppoll import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, decode_response, _tlv,
)
from netpath.trapdecode import (
    T_SEQUENCE, T_NULL, T_TIMETICKS, T_COUNTER32, T_COUNTER64, T_GAUGE32,
    T_NO_SUCH_OBJECT, T_END_OF_MIB_VIEW,
    enc_int, enc_octets, enc_unsigned, enc_varbind,
)
from netpath import nodeoids


class StubAgent:
    """A minimal SNMPv2c agent: sysDescr/sysName/sysUpTime/UCD-SNMP scalars,
    and a 2-interface IF-MIB/ifXTable table. State is mutable so the test
    can simulate an interface flapping, a reboot, or the agent going dark."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.alive = True
        self.uptime_ticks_base = 12345  # hundredths of a second
        self.started_at = time.time()
        self.if2_oper = "up"  # 'up' -> 1, 'down' -> 2
        self.if1_in = 1_000_000
        self.if2_in = 500_000

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def uptime_ticks(self) -> int:
        return self.uptime_ticks_base + int((time.time() - self.started_at) * 100)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if not self.alive:
                continue  # simulate device down: drop every packet
            try:
                reply = self._handle(data)
            except Exception as exc:  # pragma: no cover - debug aid
                print("stub agent error:", exc)
                continue
            if reply is not None:
                self.sock.sendto(reply, addr)

    def _response(self, version, community, request_id, varbinds_bytes: bytes) -> bytes:
        pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
                   _tlv(T_SEQUENCE, varbinds_bytes))
        return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(community) + pdu)

    def _handle(self, data: bytes):
        req = decode_response(data)  # same wire shape; decodes a request fine
        oids = [vb["oid"] for vb in req.varbinds]

        if req.pdu_tag == PDU_GET:
            parts = b"".join(enc_varbind(oid, self._value_for(oid)) for oid in oids)
            return self._response(req.version, "public", req.request_id, parts)

        if req.pdu_tag == PDU_GETNEXT:
            oid = oids[0]
            next_oid, next_val = self._next_for(oid)
            parts = enc_varbind(next_oid, next_val)
            return self._response(req.version, "public", req.request_id, parts)

        if req.pdu_tag == PDU_GETBULK:
            # error_index carries max_repetitions, the same third-integer
            # slot a real GetBulk-PDU uses (see snmppoll._pdu_bytes). Chain
            # the same lexicographic-successor step GETNEXT uses, once per
            # repetition — a GetBulk reply is exactly that, repeated.
            cursor = oids[0]
            parts = b""
            for _ in range(max(1, req.error_index or 1)):
                cursor, value = self._next_for(cursor)
                parts += enc_varbind(cursor, value)
            return self._response(req.version, "public", req.request_id, parts)

        return None

    # -- scalar / table data ------------------------------------------------

    def _value_for(self, oid: str) -> bytes:
        S = nodeoids.SYSTEM_SCALARS
        if oid == S["sys_descr"]:
            return enc_octets("Stub Agent Test Device v1.0")
        if oid == S["sys_object_id"]:
            return enc_octets("dummy")  # not a real OID encode; unused by test
        if oid == S["sys_uptime"]:
            return enc_unsigned(T_TIMETICKS, self.uptime_ticks())
        if oid == S["sys_contact"]:
            return enc_octets("test@example.com")
        if oid == S["sys_name"]:
            return enc_octets("stub-agent")
        if oid == S["sys_location"]:
            return enc_octets("lab")

        U = nodeoids.UCD_SNMP
        if oid == U["cpu_raw_idle"]:
            return enc_unsigned(T_GAUGE32, 60)  # 40% busy
        if oid == U["mem_avail_kb"]:
            return enc_unsigned(T_GAUGE32, 2_000_000)
        if oid == U["mem_total_kb"]:
            return enc_unsigned(T_GAUGE32, 8_000_000)
        if oid == U["load1"]:
            return _tlv(T_NO_SUCH_OBJECT, b"")

        IF = nodeoids.IF_TABLE
        IFX = nodeoids.IFX_TABLE
        for base, index in self._split_index(oid, IF):
            return self._if_value(base, index)
        for base, index in self._split_index(oid, IFX):
            return self._ifx_value(base, index)

        return _tlv(T_NO_SUCH_OBJECT, b"")

    @staticmethod
    def _split_index(oid: str, table: dict):
        for key, base in table.items():
            if oid.startswith(base + "."):
                suffix = oid[len(base) + 1:]
                try:
                    return [(key, int(suffix))]
                except ValueError:
                    return []
        return []

    def _if_value(self, key: str, index: int) -> bytes:
        if index not in (1, 2):
            return _tlv(T_NO_SUCH_OBJECT, b"")
        if key == "if_index":
            return enc_int(index)
        if key == "if_descr":
            return enc_octets(f"eth{index}")
        if key == "if_admin_status":
            return enc_int(1)
        if key == "if_oper_status":
            status = "up" if index == 1 else self.if2_oper
            return enc_int(1 if status == "up" else 2)
        if key == "if_phys_addr":
            return enc_octets(bytes([0, 0, 0, 0, 0, index]))
        if key == "if_speed":
            return enc_unsigned(T_GAUGE32, 1_000_000_000)
        if key == "if_in_octets":
            return enc_unsigned(T_COUNTER32, (self.if1_in if index == 1 else self.if2_in) % (2**32))
        if key == "if_out_octets":
            return enc_unsigned(T_COUNTER32, 100)
        if key in ("if_in_errors", "if_out_errors", "if_in_discards", "if_out_discards"):
            return enc_unsigned(T_COUNTER32, 0)
        return _tlv(T_NO_SUCH_OBJECT, b"")

    def _ifx_value(self, key: str, index: int) -> bytes:
        if index not in (1, 2):
            return _tlv(T_NO_SUCH_OBJECT, b"")
        if key == "if_alias":
            return enc_octets(f"alias{index}")
        if key == "if_high_speed":
            return enc_unsigned(T_GAUGE32, 1000)  # Mbps -> 1 Gbps
        if key == "if_hc_in_octets":
            return enc_unsigned(T_COUNTER64, self.if1_in if index == 1 else self.if2_in)
        if key == "if_hc_out_octets":
            return enc_unsigned(T_COUNTER64, 100)
        return _tlv(T_NO_SUCH_OBJECT, b"")

    def _next_for(self, oid: str):
        base = nodeoids.IF_TABLE["if_index"]
        if oid == base:
            return f"{base}.1", enc_int(1)
        if oid == f"{base}.1":
            return f"{base}.2", enc_int(2)
        if oid == f"{base}.2":
            return "1.3.6.1.2.1.2.2.1.2.1", enc_octets("out-of-subtree")
        return "9.9.9", _tlv(T_END_OF_MIB_VIEW, b"")


def main():
    tmp = tempfile.mkdtemp(prefix="nodes_e2e_")
    db_path = os.path.join(tmp, "nodes.db")
    db = NodesDatabase(db_path)

    agent = StubAgent()
    agent.start()
    time.sleep(0.1)

    from netpath.nodepoll import DEFAULT_SNMP_PORT
    import netpath.nodepoll as nodepoll_mod
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port  # redirect the poller at our stub

    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", "stub", group_id=group_id,
                              snmp_version=1, community="public",
                              poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)

    poller = NodePoller(db)

    def do_poll():
        device = db.device(device_id)
        config = db.effective_config(device)
        poller._poll_device(device, config)

    # --- poll 1: agent up, first-ever poll
    do_poll()
    device = db.device(device_id)
    assert device["status"] == "up", f"expected up, got {device['status']!r} ({device['snmp_error']!r})"
    assert device["sys_name"] == "stub-agent"
    assert device["sys_descr"] == "Stub Agent Test Device v1.0"
    print("poll 1: device up, identity captured OK")

    metrics = {row["key"]: row for row in db.metrics(device_id)}
    assert abs(metrics["cpu_pct"]["last_value"] - 40.0) < 0.01, metrics["cpu_pct"]["last_value"]
    assert abs(metrics["mem_pct"]["last_value"] - 75.0) < 0.01, metrics["mem_pct"]["last_value"]
    print("poll 1: cpu/mem metrics OK (cpu=40%, mem=75%)")

    ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
    assert set(ifaces) == {1, 2}, ifaces
    assert ifaces[1]["oper_status"] == "up" and ifaces[2]["oper_status"] == "up"
    assert ifaces[1]["in_bps"] is None, "first poll must not fabricate a rate"
    assert ifaces[1]["speed_bps"] == 1000 * 1_000_000, ifaces[1]["speed_bps"]
    print("poll 1: 2 interfaces discovered, first-poll rate correctly null, ifHighSpeed preferred OK")

    # --- poll 2: counters advanced -> a real rate should appear
    time.sleep(1.1)
    agent.if1_in += 125_000  # 125,000 bytes/sec-ish over ~1s
    do_poll()
    ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
    assert ifaces[1]["in_bps"] is not None and ifaces[1]["in_bps"] > 0, ifaces[1]["in_bps"]
    print(f"poll 2: interface counter rate computed OK (in_bps={ifaces[1]['in_bps']:.0f})")

    # --- poll 3: interface 2 goes down -> interface_down event must fire
    agent.if2_oper = "down"
    do_poll()
    iface2 = db.interface_id_for(device_id, 2)
    events = db.interface_events(iface2)
    kinds = [e["kind"] for e in events]
    assert "link_down" in kinds, f"expected link_down event, got {kinds}"
    print("poll 3: interface link_down event recorded OK (the bug this session found and fixed)")

    # --- poll 4: interface 2 comes back up -> link_up event
    agent.if2_oper = "up"
    do_poll()
    events = db.interface_events(iface2)
    kinds = [e["kind"] for e in events]
    assert "link_up" in kinds, f"expected link_up event, got {kinds}"
    print("poll 4: interface link_up event recorded OK")

    # --- poll 5,6,7: agent goes dark -> device must reach 'down' after
    #     down_after_failures (default 3) consecutive failed polls, not stay
    #     stuck in 'unknown' forever (the second bug this session found).
    agent.alive = False
    down_after = db.settings().get("down_after_failures", 3)
    last_status = None
    for i in range(down_after):
        do_poll()
        device = db.device(device_id)
        last_status = device["status"]
        print(f"  after failed poll {i + 1}: status={last_status!r} "
              f"consecutive_fail={device['consecutive_fail']}")
    assert last_status == "down", f"device never reached 'down', stuck at {last_status!r}"
    events = db.device_events(device_id, kinds=["down"])
    assert events, "no 'down' device_event was recorded"
    print("poll 5-7: device correctly reaches 'down' status after down_after_failures OK")

    # --- poll 8: agent comes back, and with a fresh uptime -> reboot detected
    agent.alive = True
    agent.uptime_ticks_base = 500  # small uptime = looks freshly restarted
    agent.started_at = time.time()
    do_poll()
    device = db.device(device_id)
    assert device["status"] == "up", device["status"]
    events = db.device_events(device_id, kinds=["up"])
    assert events, "no 'up' device_event recorded on recovery"
    reboot_events = db.device_events(device_id, kinds=["rebooted"])
    assert reboot_events, "no 'rebooted' device_event recorded despite uptime reset"
    print("poll 8: device recovers to 'up' and a 'rebooted' event fires OK")

    poller.shutdown()
    agent.stop()
    db.close()
    print("\nALL END-TO-END POLL TESTS PASSED")


if __name__ == "__main__":
    main()

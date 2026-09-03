"""Hardening of the receive-side collectors and decoders (workstream C).

One function per numbered step, run in order by main(). Where a step is about
what happens to a datagram on the wire the test sends a real one over UDP to
127.0.0.1 on a free high port, because that is the only way to prove a receive
thread survived it. Everything else drives the decoders and the database
classes directly.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import socket
import struct
import sys
import time

from _paths import free_udp_port, tmpdir

TMPDIR = tmpdir("collectors_hardening_")

from netpath import nfdecode
from netpath.collector import Collector
from netpath.flowdb import FlowDatabase
from netpath.snmptrapd import TrapCollector
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogd import SyslogCollector
from netpath.syslogdb import SyslogDatabase

FAILURES: list[str] = []


# ------------------------------------------------------------------ helpers

def v5_packet(count: int = 1, sampling: int = 0) -> bytes:
    """A NetFlow v5 datagram with `count` identical, decodable records."""
    now = int(time.time())
    header = struct.pack("!HHIIIIBBH", 5, count, 1000, now, 0, 0, 0, 0, sampling)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        0x0A000001, 0x0A000002, 0x0A0000FE,   # src, dst, next hop
        1, 2,                                  # in/out ifIndex
        10, 1500,                              # packets, octets
        500, 900,                              # first, last (ms of uptime)
        1234, 80, 0, 0x18, 6, 0,               # ports, pad, flags, proto, tos
        64500, 64501, 0, 0, 0,                 # AS numbers, masks, pad
    )
    return header + record * count


def wait_for(predicate, timeout_s: float = 5.0, step_s: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step_s)
    return False


def send_udp(port: int, payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
    finally:
        sock.close()


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILURES.append(message)


def db_path(name: str) -> str:
    return os.path.join(TMPDIR, name)


# ----------------------------------------------------------------------- C1

def test_c1_receive_threads_survive_bad_input() -> None:
    """A runt v5 datagram used to unwind DecodeError out of netflow-rx and kill
    the listener for the life of the process; the trap and syslog receivers had
    the same shape. Each collector must still be running, and still decoding,
    after being fed rubbish."""
    print("C1: receive loops never die on packet content")

    flow_db = FlowDatabase(db_path("c1-flows.db"))
    collector = Collector(flow_db)
    port = free_udp_port()
    assert collector.start({"port": port, "bind_address": "127.0.0.1"})
    try:
        send_udp(port, v5_packet())
        check(wait_for(lambda: collector.counters["packets"] == 1),
              "netflow: a good v5 packet is counted")

        # 18 bytes beginning 0x0005: the exact datagram from the review.
        send_udp(port, b"\x00\x05" + b"\x00" * 16)
        check(wait_for(lambda: collector.decoder.stats["errors"] >= 1),
              "netflow: the 18-byte runt is counted as an error, not raised")
        check(collector.running, "netflow: the receive thread is still alive")

        send_udp(port, v5_packet())
        check(wait_for(lambda: collector.counters["flows"] >= 2, 6.0),
              "netflow: the next good packet is still decoded and stored")
    finally:
        collector.stop()
        flow_db.close()

    # status_text tells a crash apart from an operator stop.
    check(collector.status_text() == "Collector stopped",
          "netflow: a deliberate stop still reads 'Collector stopped'")
    collector._crash = "netflow-rx: boom"
    check("stopped unexpectedly" in collector.status_text(),
          "netflow: a crashed thread reads 'stopped unexpectedly'")

    # Traps: a datagram that blows up downstream must be counted, not fatal.
    trap_db = SnmpTrapDatabase(db_path("c1-traps.db"))
    traps = TrapCollector(trap_db)
    trap_port = free_udp_port()
    assert traps.start({"port": trap_port, "bind_address": "127.0.0.1"})
    try:
        original = traps.decoder.decode

        def exploding(data, source):
            if data == b"boom":
                raise RuntimeError("decoder blew up")
            return original(data, source)

        traps.decoder.decode = exploding
        send_udp(trap_port, b"boom")
        check(wait_for(lambda: traps.counters["errors"] == 1),
              "traps: an exception on the receive path is counted, not fatal")
        check(traps.running, "traps: the receive thread is still alive")
        traps.decoder.decode = original
        send_udp(trap_port, b"\x30\x03\x02\x01\x00")     # undecodable, not fatal
        check(wait_for(lambda: traps.counters["undecodable"] >= 1),
              "traps: an undecodable datagram is still counted normally")
    finally:
        traps.stop()
        trap_db.close()

    syslog_db = SyslogDatabase(db_path("c1-syslog.db"))
    syslog = SyslogCollector(syslog_db)
    syslog_port = free_udp_port()
    assert syslog.start({"port": syslog_port, "bind_address": "127.0.0.1"})
    try:
        import netpath.syslogd as syslogd_mod
        original_parse = syslogd_mod.parse

        def exploding_parse(data, source):
            if data == b"boom":
                raise RuntimeError("parser blew up")
            return original_parse(data, source)

        syslogd_mod.parse = exploding_parse
        try:
            send_udp(syslog_port, b"boom")
            check(wait_for(lambda: syslog.counters["errors"] == 1),
                  "syslog: an exception on the receive path is counted, not fatal")
            check(syslog.running, "syslog: the receive thread is still alive")
        finally:
            syslogd_mod.parse = original_parse
        send_udp(syslog_port, b"<134>real message after the failure")
        check(wait_for(lambda: syslog.counters["stored"] >= 1, 6.0),
              "syslog: the next message is still parsed and stored")
    finally:
        syslog.stop()
        syslog_db.close()

    # The decoder itself no longer lets DecodeError escape.
    decoder = nfdecode.Decoder()
    check(decoder.decode(b"\x00\x05" + b"\x00" * 16, "10.0.0.1") == [],
          "nfdecode: a short v5 header returns [] instead of raising")
    check(decoder.decode(b"\x00\x09" + b"\x00" * 10, "10.0.0.1") == [],
          "nfdecode: a short v9 header returns [] instead of raising")
    check(decoder.decode(b"\x00\x0a" + b"\x00" * 8, "10.0.0.1") == [],
          "nfdecode: a short IPFIX header returns [] instead of raising")


TESTS = [
    test_c1_receive_threads_survive_bad_input,
]


def main() -> int:
    try:
        for test in TESTS:
            test()
            print()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED:")
        for item in FAILURES:
            print(f"  - {item}")
        return 1
    print("ALL COLLECTOR HARDENING ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

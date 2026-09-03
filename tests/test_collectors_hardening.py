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
import sqlite3
import struct
import sys
import time

from _paths import free_udp_port, tmpdir

TMPDIR = tmpdir("collectors_hardening_")

from netpath import kerneldrops, nfdecode, trapdecode
from netpath.collector import Collector
from netpath.flowdb import FlowDatabase
from netpath.snmptrapd import TrapCollector
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogd import SyslogCollector
from netpath.db import Database as NetPathDatabase
from netpath.ipamdb import IpamDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.syslogparse import LogEntry, parse

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


# ----------------------------------------------------------------------- C2

def ipfix_packet(sets: bytes, domain: int = 0) -> bytes:
    body = struct.pack("!HHIII", 10, 16 + len(sets), int(time.time()), 0, domain)
    return body + sets


def ipfix_set(set_id: int, payload: bytes) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(payload)) + payload


def v9_packet(sets: bytes, domain: int = 0) -> bytes:
    header = struct.pack("!HHIIII", 9, 1, 1000, int(time.time()), 0, domain)
    return header + sets


def test_c2_template_guards_and_bounded_caches() -> None:
    """A template with no fields (or with zero-length fields) has a record
    length of zero, and _read_data looped on it forever at 100% CPU with the
    collector still reporting `running`. 0xFFFF is variable-length in IPFIX
    only. Addresses must be picked by content, and every cache keyed on
    exporter-chosen data must be bounded."""
    print("C2: template guards, dual-stack addresses and bounded caches")

    # --- a zero-length template must not spin the receive thread ----------
    decoder = nfdecode.Decoder()
    zero_fields = (struct.pack("!HH", 257, 2)
                   + struct.pack("!HH", nfdecode.OCTETS, 0)
                   + struct.pack("!HH", nfdecode.PACKETS, 0))
    decoder.decode(v9_packet(ipfix_set(0, zero_fields)), "10.0.0.1")
    started = time.monotonic()
    flows = decoder.decode(v9_packet(ipfix_set(257, b"\x00" * 8)), "10.0.0.1")
    elapsed = time.monotonic() - started
    check(elapsed < 0.1 and flows == [],
          f"a zero-length-field template returns [] in {elapsed * 1000:.1f} ms")
    check(decoder.stats["bad_template"] >= 1,
          "the broken template is counted in stats['bad_template']")
    check(("10.0.0.1", 0, 257) not in decoder.templates,
          "the broken template is not cached")

    no_fields = struct.pack("!HH", 258, 0)
    before = decoder.stats["templates"]
    decoder.decode(v9_packet(ipfix_set(0, no_fields)), "10.0.0.1")
    check(decoder.stats["templates"] == before,
          "a template with count == 0 is refused rather than cached")

    # --- dual-stack template: the zero-filled v4 pair must not win --------
    decoder = nfdecode.Decoder()
    fields = [(nfdecode.SRC_IPV4, 4), (nfdecode.DST_IPV4, 4),
              (nfdecode.SRC_IPV6, 16), (nfdecode.DST_IPV6, 16),
              (nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]
    template = struct.pack("!HH", 300, len(fields))
    for field_id, size in fields:
        template += struct.pack("!HH", field_id, size)
    decoder.decode(ipfix_packet(ipfix_set(2, template)), "10.0.0.1")
    record = (b"\x00" * 4 + b"\x00" * 4
              + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
              + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
              + struct.pack("!I", 1500) + struct.pack("!I", 10))
    flows = decoder.decode(ipfix_packet(ipfix_set(300, record)), "10.0.0.1")
    check(len(flows) == 1 and flows[0].src_ip == "2001:db8::1"
          and flows[0].dst_ip == "2001:db8::2",
          "a dual-stack record with a zero-filled v4 pair decodes as IPv6 "
          f"(got {flows[0].src_ip if flows else 'nothing'})")

    # A real v4 address still wins over an absent v6 one.
    v4_record = (socket.inet_aton("10.1.1.1") + socket.inet_aton("10.1.1.2")
                 + b"\x00" * 32 + struct.pack("!I", 99) + struct.pack("!I", 1))
    flows = decoder.decode(ipfix_packet(ipfix_set(300, v4_record)), "10.0.0.1")
    check(len(flows) == 1 and flows[0].src_ip == "10.1.1.1",
          "an IPv4 record on the same template still decodes as IPv4")

    # --- 0xFFFF is variable-length in IPFIX only --------------------------
    decoder = nfdecode.Decoder()
    v9_template = (struct.pack("!HH", 400, 2)
                   + struct.pack("!HH", nfdecode.OCTETS, 0xFFFF)
                   + struct.pack("!HH", nfdecode.PACKETS, 4))
    decoder.decode(v9_packet(ipfix_set(0, v9_template)), "10.0.0.2")
    cached = decoder.templates.get(("10.0.0.2", 0, 400))
    check(cached is not None and cached.length == 0xFFFF + 4,
          "a v9 0xFFFF field is a fixed 65535-byte field, not variable-length")
    flows = decoder.decode(v9_packet(ipfix_set(400, b"AAAA" + b"BBBB")), "10.0.0.2")
    check(flows == [],
          "the short v9 record is dropped instead of decoding the next "
          "field's bytes as a counter")

    # --- bounded caches ---------------------------------------------------
    decoder = nfdecode.Decoder()
    for index in range(nfdecode.MAX_TEMPLATES + 200):
        one = struct.pack("!HH", 256, 1) + struct.pack("!HH", nfdecode.OCTETS, 4)
        decoder._read_templates(one, "10.0.0.3", index, options=False, ipfix=False)
    check(len(decoder.templates) <= nfdecode.MAX_TEMPLATES
          and decoder.templates.evictions >= 200,
          f"the template cache is capped at {nfdecode.MAX_TEMPLATES} "
          f"({len(decoder.templates)} held, {decoder.templates.evictions} evicted)")
    for index in range(nfdecode.MAX_SAMPLING + 200):
        decoder.sampling[f"192.0.2.{index}"] = 100
    check(len(decoder.sampling) <= nfdecode.MAX_SAMPLING,
          f"the sampling cache is capped at {nfdecode.MAX_SAMPLING}")

    trapdecode._KEY_CACHE.clear()
    for index in range(300):
        trapdecode.localized_key("MD5", "secretpass",
                                 b"engine" + index.to_bytes(2, "big"))
    check(len(trapdecode._KEY_CACHE) <= 256,
          f"300 distinct engine ids leave {len(trapdecode._KEY_CACHE)} key-cache "
          "entries, not 300")
    trapdecode._KEY_CACHE.clear()

    flow_db = FlowDatabase(db_path("c2-flows.db"))
    collector = Collector(flow_db)
    firsts = sum(1 for i in range(5000) if collector._first_from(f"10.9.{i // 256}.{i % 256}"))
    check(firsts == 5000 and len(collector._seen_exporters) <= 4096,
          f"the seen-exporter set is capped at 4096 "
          f"({len(collector._seen_exporters)} held)")
    flow_db.close()


# ----------------------------------------------------------------------- C3

def test_c3_kernel_drops_are_visible() -> None:
    """counters["dropped"] only counts loss the application caused. Datagrams
    the socket receive buffer threw away before anyone read them were
    invisible: the review offered 300,000 syslog messages, stored 93,412, and
    the strip reported no loss at all. On Linux the figure is the last column
    of /proc/net/udp{,6} for the bound port."""
    print("C3: kernel socket-buffer drops are counted and shown")

    if not kerneldrops.supported():
        # Not Linux (or no /proc): the key must simply be absent rather than
        # reporting a guessed zero.
        syslog_db = SyslogDatabase(db_path("c3-syslog.db"))
        syslog = SyslogCollector(syslog_db)
        assert syslog.start({"port": free_udp_port(), "bind_address": "127.0.0.1"})
        check("kernel_dropped" not in syslog.counters,
              "off Linux the kernel_dropped key is absent, not a guessed zero")
        syslog.stop()
        syslog_db.close()
        return

    # --- the reader itself, against a socket nobody drains ----------------
    victim = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    victim.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    victim.bind(("127.0.0.1", 0))
    victim_port = victim.getsockname()[1]
    reader = kerneldrops.KernelDrops(victim_port, interval_s=0.0)
    check(reader.poll(force=True) == 0, "a freshly bound port starts at zero drops")
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(5000):
        sender.sendto(b"x" * 512, ("127.0.0.1", victim_port))
    sender.close()
    drops = reader.poll(force=True)
    check(drops is not None and drops > 0,
          f"an undrained socket reports {drops} kernel drops")
    check(kerneldrops.KernelDrops(free_udp_port(), interval_s=0.0).poll(force=True) is None,
          "an unbound port reports None (unknown), not zero")
    victim.close()

    # --- a live collector surfaces it in counters and in the status strip --
    syslog_db = SyslogDatabase(db_path("c3-syslog.db"))
    syslog = SyslogCollector(syslog_db)
    port = free_udp_port()
    assert syslog.start({"port": port, "bind_address": "127.0.0.1",
                         "socket_buffer_kb": 1})
    try:
        check(syslog.counters.get("kernel_dropped") == 0,
              "the collector exposes counters['kernel_dropped'] on Linux")
        # A slow consumer is the condition the counter exists to report: the
        # sender is faster than this host can drain the socket.
        fast_enqueue = syslog._enqueue

        def slow_enqueue(data, source):
            time.sleep(0.002)
            return fast_enqueue(data, source)

        syslog._enqueue = slow_enqueue
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for index in range(6000):
            sender.sendto(b"<134>flood message %d" % index, ("127.0.0.1", port))
        sender.close()
        syslog._enqueue = fast_enqueue
        check(wait_for(lambda: syslog.counters.get("kernel_dropped", 0) > 0, 12.0),
              f"the collector reports kernel_dropped="
              f"{syslog.counters.get('kernel_dropped')} after a burst it "
              "could not drain")
        check("dropped by the kernel" in syslog.status_text(),
              "the status strip says so too")
    finally:
        syslog.stop()
        syslog_db.close()

    # The trap receiver and the flow collector expose the same key.
    trap_db = SnmpTrapDatabase(db_path("c3-traps.db"))
    traps = TrapCollector(trap_db)
    assert traps.start({"port": free_udp_port(), "bind_address": "127.0.0.1"})
    check(traps.counters.get("kernel_dropped") == 0,
          "the trap receiver exposes counters['kernel_dropped']")
    traps.stop()
    trap_db.close()

    flow_db = FlowDatabase(db_path("c3-flows.db"))
    collector = Collector(flow_db)
    assert collector.start({"port": free_udp_port(), "bind_address": "127.0.0.1"})
    check(collector.counters.get("kernel_dropped") == 0,
          "the flow collector exposes counters['kernel_dropped']")
    collector.stop()
    flow_db.close()


# ----------------------------------------------------------------------- C4

def fill_logs(db: SyslogDatabase, count: int, base_ts: float) -> None:
    for start in range(0, count, 5000):
        db.insert([
            LogEntry(ts=base_ts + index, source="10.0.0.1", host="core-sw-a",
                     app="LINK", severity=3, procid="", msgid="",
                     message=f"%LINK-3-UPDOWN: Interface Gi0/{index} changed "
                             f"state to down",
                     raw="raw line")
            for index in range(start, min(start + 5000, count))])


def test_c4_prune_does_not_rebuild_the_index() -> None:
    """Every syslog prune re-indexed the whole logs table under the write
    lock — 18.6 s to delete one row from a million, every fifteen minutes once
    retention bit, stalling the writer for the whole of it. And every trim
    VACUUMed on the shared connection."""
    print("C4: targeted FTS deletes and incremental reclamation")

    path = db_path("c4-syslog.db")
    syslog_db = SyslogDatabase(path)
    if not syslog_db.fts:
        check(True, "no FTS5 in this SQLite build; the delete path is skipped")
        syslog_db.close()
        return

    mode = syslog_db._conn.execute("PRAGMA auto_vacuum").fetchone()[0]
    check(mode == 2, f"a fresh syslog.db opens in incremental auto-vacuum "
                     f"(auto_vacuum={mode})")

    rows = 60_000
    started = time.monotonic()
    fill_logs(syslog_db, rows, time.time() - rows)
    print(f"    seeded {rows} rows in {time.monotonic() - started:.1f} s")

    total = syslog_db._conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
    oldest = syslog_db._conn.execute(
        "SELECT message FROM logs ORDER BY ts ASC LIMIT 1").fetchone()["message"]
    started = time.monotonic()
    removed = syslog_db.prune(retention_days=10_000, max_rows=total - 1)
    targeted_s = time.monotonic() - started
    check(removed == 1 and targeted_s < 0.5,
          f"pruning 1 row from {total} takes {targeted_s * 1000:.1f} ms")

    started = time.monotonic()
    with syslog_db._lock:
        syslog_db._conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
        syslog_db._conn.commit()
    rebuild_s = time.monotonic() - started
    check(targeted_s < rebuild_s / 10,
          f"that is not a function of table size: the rebuild it replaced "
          f"costs {rebuild_s * 1000:.0f} ms")

    # The index must still agree with the table after a targeted delete.
    found = syslog_db.search(0, time.time() + 60, {"q": "UPDOWN"}, limit=5)
    hits = found["rows"] if isinstance(found, dict) else found
    check(len(hits) == 5, "search still returns rows through the FTS index")
    needle = oldest.split(": ", 1)[1].split(" changed")[0]     # "Interface Gi0/0"
    found = syslog_db.search(0, time.time() + 60, {"q": needle}, limit=5)
    hits = found["rows"] if isinstance(found, dict) else found
    check(all(row["message"] != oldest for row in hits),
          "the pruned row is gone from the index as well as from the table")

    before = syslog_db.size_bytes()
    removed = syslog_db.trim_to_size(int(before * 0.6))
    after = syslog_db.size_bytes()
    check(removed > 0 and after < before,
          f"trim_to_size reclaims space without VACUUM "
          f"({before // 1024} KiB -> {after // 1024} KiB)")
    syslog_db.close()

    # --- an existing 4.35-era file is converted in place ------------------
    legacy = db_path("c4-legacy.db")
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, ts REAL NOT NULL,"
                 " source TEXT NOT NULL, host TEXT, facility INTEGER,"
                 " severity INTEGER, app TEXT, procid TEXT, msgid TEXT,"
                 " message TEXT NOT NULL, raw TEXT)")
    conn.executemany("INSERT INTO logs(ts, source, message) VALUES (?,?,?)",
                     [(float(i), "10.0.0.9", "old row %d" % i) for i in range(2000)])
    conn.commit()
    check(conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 0,
          "the fixture starts with auto_vacuum off, as a 4.35 file does")
    conn.close()
    reopened = SyslogDatabase(legacy)
    check(reopened._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2,
          "opening it converts it to incremental auto-vacuum, keeping its rows")
    check(reopened._conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"] == 2000,
          "and the existing rows survive the conversion")
    reopened.close()

    # --- the other four files open the same way ---------------------------
    for name, factory in (("snmptraps.db", SnmpTrapDatabase),
                          ("netflow.db", FlowDatabase),
                          ("ipam.db", IpamDatabase),
                          ("netpath.db", NetPathDatabase)):
        handle = factory(db_path("c4-" + name))
        mode = handle._conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        check(mode == 2, f"{name} opens in incremental auto-vacuum")
        handle.close()


# ----------------------------------------------------------------------- C5

def test_c5_drain_sources_can_be_caught_up() -> None:
    """The alert engine drained 500 rows per five-second tick per source —
    100 rows/s against a measured syslog ingest of ~11,800/s — with no inner
    loop, no catch-up and no lag indicator anywhere. The engine's own loop is
    workstream A's; the sources have to be able to say how far behind a
    reader is and to hand over more than one tick's worth at a time."""
    print("C5: sources can be sized and drained in catch-up batches")

    syslog_db = SyslogDatabase(db_path("c5-syslog.db"))
    fill_logs(syslog_db, 10_000, time.time() - 10_000)
    check(syslog_db.max_id() == 10_000,
          f"SyslogDatabase.max_id() sizes the backlog ({syslog_db.max_id()})")

    # Drained the way the engine will: a budget per tick until the cursor
    # reaches max_id. Ten thousand rows must not need twenty ticks.
    cursor, ticks = 0, 0
    high_water = syslog_db.max_id()
    while cursor < high_water and ticks < 10:
        rows = syslog_db.rows_since(cursor, limit=5000)
        if not rows:
            break
        cursor = rows[-1]["id"]
        ticks += 1
    check(cursor == high_water and ticks <= 3,
          f"10,000 rows drain in {ticks} tick(s) at a 5,000-row budget")
    check(len(syslog_db.rows_since(0)) == 500,
          "an unbudgeted caller still gets the old 500-row page")
    check(len(syslog_db.rows_since(0, limit=None)) == 10_000,
          "limit=None hands over the whole backlog for a caller that sized it")
    check(syslog_db.rows_since(high_water, limit=5000) == [],
          "a caught-up cursor reads nothing")
    syslog_db.close()

    trap_db = SnmpTrapDatabase(db_path("c5-traps.db"))
    now = time.time()
    for start in range(0, 2000, 500):
        trap_db.insert([
            trapdecode.Trap(ts=now + index, source="10.0.0.7", version=1,
                            community="public", trap_oid="1.3.6.1.6.3.1.1.5.3",
                            trap_name="linkDown", severity=3)
            for index in range(start, start + 500)])
    check(trap_db.max_id() == 2000,
          f"SnmpTrapDatabase.max_id() sizes the backlog ({trap_db.max_id()})")
    check(len(trap_db.traps_since(0, limit=1500)) == 1500,
          "traps_since honours an explicit per-tick budget")
    check(len(trap_db.traps_since(0)) == 500,
          "and still defaults to 500 for a caller that passes nothing")
    check(len(trap_db.traps_since(0, limit=None)) == 2000,
          "limit=None hands over the whole trap backlog")
    trap_db.close()


# ----------------------------------------------------------------------- C6

def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    raw = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def _int_tlv(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(length, "big"))


def _oid_tlv(oid: str) -> bytes:
    arcs = [int(part) for part in oid.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def v3_trap(user: str, engine_id: bytes, digest: bytes,
            trap_oid: str = "1.3.6.1.6.3.1.1.5.3") -> bytes:
    """An SNMPv3 authNoPriv snmpV2-Trap carrying `digest` as its
    msgAuthenticationParameters. A digest of the wrong bytes is exactly what a
    forger sends, and what the review offered 401 of."""
    header = _tlv(0x30, _int_tlv(1) + _int_tlv(65507)
                  + _tlv(0x04, b"\x01") + _int_tlv(3))     # msgFlags: auth
    usm = _tlv(0x30,
               _tlv(0x04, engine_id) + _int_tlv(1) + _int_tlv(100)
               + _tlv(0x04, user.encode()) + _tlv(0x04, digest) + _tlv(0x04, b""))
    varbinds = _tlv(0x30,
                    _tlv(0x30, _oid_tlv("1.3.6.1.2.1.1.3.0")
                         + _tlv(0x43, b"\x00\x01\x00\x00"))
                    + _tlv(0x30, _oid_tlv("1.3.6.1.6.3.1.1.4.1.0")
                           + _oid_tlv(trap_oid)))
    pdu = _tlv(0xA7, _int_tlv(1) + _int_tlv(0) + _int_tlv(0) + varbinds)
    scoped = _tlv(0x30, _tlv(0x04, engine_id) + _tlv(0x04, b"") + pdu)
    return _tlv(0x30, _int_tlv(3) + header + _tlv(0x04, usm) + scoped)


def test_c6_forged_v3_traps_are_dropped() -> None:
    """_verify_v3 computed the digest correctly and counted the failure, and
    then _enqueue stored the trap anyway: _accepted_community returns True
    unconditionally for v3 and nothing else looked at auth_state. The review
    sent 401 forged authNoPriv traps; all 401 were stored and all 401 became
    alert occurrences."""
    print("C6: a v3 trap whose authentication fails is not stored")

    settings = {"bind_address": "127.0.0.1",
                "v3_users": "noc / SHA / correcthorsebattery"}
    engine = b"\x80\x00\x1f\x88\x80" + b"engine"

    trap_db = SnmpTrapDatabase(db_path("c6-traps.db"))
    traps = TrapCollector(trap_db)
    port = free_udp_port()
    assert traps.start({**settings, "port": port})
    try:
        forged = v3_trap("noc", engine, b"\x00" * 12)
        for _ in range(401):
            send_udp(port, forged)
        check(wait_for(lambda: traps.counters["bad_auth"] >= 401, 15.0),
              f"401 forged traps are counted as bad_auth "
              f"({traps.counters['bad_auth']})")
        time.sleep(1.5)
        stored = trap_db.max_id()
        check(stored == 0, f"none of them reach the database (stored={stored})")
        check(traps.counters["traps"] == 0,
              "and none of them refresh the 'last trap' figure")
    finally:
        traps.stop()
        trap_db.close()

    # A user nobody configured cannot be checked: counted, and still kept,
    # because that is what a site with no v3 users has always had.
    trap_db = SnmpTrapDatabase(db_path("c6-unverified.db"))
    traps = TrapCollector(trap_db)
    port = free_udp_port()
    assert traps.start({**settings, "port": port})
    try:
        send_udp(port, v3_trap("someone-else", engine, b"\x00" * 12))
        check(wait_for(lambda: trap_db.max_id() == 1, 8.0),
              "a trap from an unconfigured v3 user is still stored")
        check(traps.counters["unverified"] == 1 and traps.counters["bad_auth"] == 0,
              "and counted as unverified, separately from bad_auth")
        row = trap_db.traps_since(0)[0]
        check(row["auth_state"] == "unverified",
              "with auth_state 'unverified' on the row")
    finally:
        traps.stop()
        trap_db.close()

    # The setting can be turned off for a site that needs to see them.
    trap_db = SnmpTrapDatabase(db_path("c6-permissive.db"))
    traps = TrapCollector(trap_db)
    port = free_udp_port()
    assert traps.start({**settings, "port": port, "reject_failed_auth": False})
    try:
        send_udp(port, v3_trap("noc", engine, b"\x00" * 12))
        check(wait_for(lambda: trap_db.max_id() == 1, 8.0),
              "reject_failed_auth=False stores the forged trap as before")
        check(traps.counters["bad_auth"] == 1,
              "and still counts it in bad_auth")
    finally:
        traps.stop()
        trap_db.close()

    from netpath import snmptrapdb as snmptrapdb_mod
    check(snmptrapdb_mod.DEFAULTS.get("reject_failed_auth") is True,
          "the setting ships on by default")


# ----------------------------------------------------------------------- C7

def test_c7_syslog_robustness() -> None:
    """The parser dropped only the first of several RFC 5424 structured-data
    elements, refused a 5424 message with an empty MSG, believed any device's
    clock, and read a PRI above 191; the framer treated any leading digits as
    an RFC 6587 length; TCP spawned an uncapped thread per connection; and one
    device in a debug loop could evict every other device's messages."""
    print("C7: syslog parsing, framing, throttling and repeat collapsing")

    now = time.time()

    relayed = (b'<165>1 2003-10-11T22:14:15.003Z host app - - '
               b'[timeQuality tzKnown="1" isSynced="0"]'
               b'[origin ip="10.1.1.1" software="rsyslogd"] real message')
    entry = parse(relayed, "10.1.1.1", now=now)
    check(entry.message == "real message",
          f"every structured-data element is stripped, not just the first "
          f"({entry.message!r})")

    escaped = (b'<165>1 2003-10-11T22:14:15.003Z m.example.com evntslog - ID47 '
               b'[exampleSDID@32473 eventSource="App\\]lication"] the message')
    check(parse(escaped, "10.1.1.1", now=now).message == "the message",
          "an escaped bracket inside a parameter still ends the element correctly")

    unterminated = (b'<165>1 2003-10-11T22:14:15.003Z host app - - '
                    b'[unterminated k="v" the rest')
    check(parse(unterminated, "10.1.1.1", now=now).message.startswith("[unterminated"),
          "an unterminated element is kept rather than guessed at")

    empty = parse(b'<165>1 2003-10-11T22:14:15.003Z host app - -', "10.1.1.1", now=now)
    check(empty.message == "" and empty.host == "host" and empty.app == "app",
          f"a 5424 heartbeat with an empty MSG parses its header "
          f"(host={empty.host!r} app={empty.app!r} msg={empty.message!r})")

    high = parse(b"<999>hi there", "10.1.1.1", now=now)
    check(high.facility == 1 and high.severity == 6
          and high.message == "<999>hi there",
          f"a PRI above 191 is message text, not facility {high.facility}")
    ok_pri = parse(b"<191>local7 debug", "10.1.1.1", now=now)
    check(ok_pri.facility == 23 and ok_pri.severity == 7,
          "191 itself is still a valid PRI")

    june = time.mktime((2026, 6, 2, 0, 30, 0, 0, 0, -1))
    far = parse(b"<134>Dec 31 23:59:00 sw1 x: y", "10.1.1.1", now=june)
    check(abs(far.ts - june) < 1.0,
          "a December timestamp read in June falls back to the arrival time")
    near = parse(b"<134>Jun  2 00:29:30 sw1 x: y", "10.1.1.1", now=june)
    check(abs(near.ts - (june - 30)) < 1.0,
          "a timestamp within the hour window is still believed")

    # --- rows already stored with a future timestamp can be pruned ---------
    syslog_db = SyslogDatabase(db_path("c7-future.db"))
    syslog_db.insert([LogEntry(ts=time.time() + 400 * 86400, source="10.9.9.9",
                               message="from a device set years ahead"),
                      LogEntry(ts=time.time(), source="10.9.9.9",
                               message="a normal message")])
    removed = syslog_db.prune(retention_days=30, max_rows=0)
    check(removed == 1 and syslog_db.max_id() >= 1,
          f"prune removes a row timestamped in the future ({removed} removed)")
    rows = syslog_db.rows_since(0, limit=None)
    check(len(rows) == 1 and rows[0]["message"] == "a normal message",
          "and leaves the good one alone")
    syslog_db.close()

    # --- consecutive duplicates collapse into one row ---------------------
    syslog_db = SyslogDatabase(db_path("c7-repeat.db"))
    syslog_db.collapse_repeats_s = 5.0
    base = time.time()
    for index in range(50):
        syslog_db.insert([LogEntry(ts=base + index * 0.01, source="10.2.2.2",
                                   severity=3, app="BGP",
                                   message="%BGP-3-NOTIFICATION: neighbour reset")])
    syslog_db.insert([LogEntry(ts=base + 1, source="10.2.2.2", severity=3,
                               app="BGP", message="something else")])
    rows = syslog_db.rows_since(0, limit=None)
    check(len(rows) == 2, f"50 identical lines collapse to one row plus the "
                          f"next different one ({len(rows)} rows)")
    check(rows[0]["repeat_count"] == 50,
          f"the row carries repeat_count={rows[0]['repeat_count']}")
    check(abs(rows[0]["ts"] - base) < 0.001,
          "and keeps the first occurrence's timestamp")
    counts = syslog_db._conn.execute(
        "SELECT SUM(n) AS n FROM log_counts").fetchone()["n"]
    check(counts == 51,
          f"the hourly timeline still counts every message that arrived ({counts})")
    # A different source in between must not break the run.
    syslog_db.close()

    # --- the per-source token bucket --------------------------------------
    syslog_db = SyslogDatabase(db_path("c7-rate.db"))
    syslog = SyslogCollector(syslog_db)
    port = free_udp_port()
    assert syslog.start({"port": port, "bind_address": "127.0.0.1",
                         "per_source_rate": 20})
    try:
        for index in range(500):
            syslog._enqueue(b"<134>flood %d" % index, "10.3.3.3")
        check(syslog.counters["throttled"] > 400,
              f"a source above its rate is throttled "
              f"({syslog.counters['throttled']} of 500)")
        check(syslog.counters["messages"] <= 25,
              f"only the bucket's worth got through "
              f"({syslog.counters['messages']})")
        for index in range(10):
            syslog._enqueue(b"<134>quiet %d" % index, "10.4.4.4")
        check(syslog.counters["messages"] <= 35 and syslog.counters["messages"] >= 15,
              "a different source is unaffected by the noisy one's bucket")
        check(len(syslog._buckets) == 2, "one bucket per source, and no more")
        # Bounded: five thousand distinct sources leave at most MAX_RATE_SOURCES.
        for index in range(5000):
            syslog._within_rate(f"10.20.{index // 256}.{index % 256}", time.time())
        check(len(syslog._buckets) <= 4096,
              f"the bucket table is bounded ({len(syslog._buckets)})")
        check("throttled" in syslog.status_text(),
              "the status strip says it is throttling")
    finally:
        syslog.stop()
        syslog_db.close()

    # --- rejected sources no longer refresh "last message just now" --------
    syslog_db = SyslogDatabase(db_path("c7-reject.db"))
    syslog = SyslogCollector(syslog_db)
    assert syslog.start({"port": free_udp_port(), "bind_address": "127.0.0.1",
                         "allowed_sources": "10.5.5.5"})
    try:
        syslog._enqueue(b"<134>from a source nobody allowed", "10.6.6.6")
        check(syslog.counters["rejected"] == 1
              and syslog.counters["messages"] == 0
              and syslog.counters["last_message"] == 0.0,
              "a rejected source is counted without refreshing 'last message'")
    finally:
        syslog.stop()
        syslog_db.close()

    # --- RFC 6587 framing and the TCP client cap --------------------------
    syslog_db = SyslogDatabase(db_path("c7-tcp.db"))
    syslog = SyslogCollector(syslog_db)
    tcp_port = free_udp_port()
    assert syslog.start({"port": free_udp_port(), "bind_address": "127.0.0.1",
                         "accept_udp": True, "accept_tcp": True,
                         "tcp_port": tcp_port, "max_tcp_clients": 4,
                         "collapse_repeats_s": 0})
    clients = []
    try:
        sock = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        clients.append(sock)
        # A newline-framed line that merely starts with a number.
        sock.sendall(b"123 packets dropped on Gi0/1\n<134>the next line\n")
        # ... and a real RFC 6587 frame.
        frame = b"<134>counted frame"
        sock.sendall(b"%d %s" % (len(frame), frame))
        check(wait_for(lambda: syslog_db.max_id() >= 3, 8.0),
              f"all three TCP messages are stored ({syslog_db.max_id()})")
        stored = [row["message"] for row in syslog_db.rows_since(0, limit=None)]
        check(any("packets dropped on Gi0/1" in text for text in stored),
              f"the numeric line is a message, not a length prefix ({stored})")
        check(any("counted frame" in text for text in stored),
              "and a real octet-counted frame is still framed correctly")

        for _ in range(8):
            try:
                clients.append(socket.create_connection(("127.0.0.1", tcp_port),
                                                        timeout=5))
            except OSError:
                break
            time.sleep(0.05)
        check(wait_for(lambda: syslog.counters["tcp_refused"] > 0, 8.0),
              f"connections past the cap are refused "
              f"({syslog.counters['tcp_refused']})")
        check(len(syslog._clients) <= 4,
              f"at most the cap's worth of client threads live "
              f"({len(syslog._clients)})")
        check(all("syslog-tcp-client" != thread.name for thread in syslog._threads),
              "client threads are kept out of the listener list")
    finally:
        for sock in clients:
            try:
                sock.close()
            except OSError:
                pass
        syslog.stop()
        syslog_db.close()


TESTS = [
    test_c1_receive_threads_survive_bad_input,
    test_c2_template_guards_and_bounded_caches,
    test_c3_kernel_drops_are_visible,
    test_c4_prune_does_not_rebuild_the_index,
    test_c5_drain_sources_can_be_caught_up,
    test_c6_forged_v3_traps_are_dropped,
    test_c7_syslog_robustness,
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

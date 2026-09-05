"""Regression coverage for the independent review's collector findings.

One crafted NetFlow options record used to permanently kill flow storage
while the status strip kept reading healthy (the critical finding); the
template cache was keyed on fields any unauthenticated sender controls
outright; a malformed SNMP trap could take 199 good ones down with it in one
batch; and syslog stored control and ANSI escape bytes verbatim. Each test
below proves one of those is now closed, the same way the neighbouring
hardening suites do it: build the actual malformed bytes, feed them to the
real decoder or a real listener on a loopback port, and check what came out
the other side.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on
failure.
"""
import shutil
import socket
import struct
import sys
import time

from _paths import free_udp_port, tmpdir

TMPDIR = tmpdir("collector_review_fixes_")

from netpath import eventlog, nfdecode, syslogparse, trapdecode
from netpath.collector import Collector
from netpath.flowdb import FlowDatabase
from netpath.snmptrapd import TrapCollector
from netpath.snmptrapdb import SnmpTrapDatabase

FAILURES: list[str] = []

INT64_MAX = 2 ** 63 - 1
INT64_MIN = -(2 ** 63)


# ------------------------------------------------------------------ helpers

def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILURES.append(message)


def wait_for(predicate, timeout_s: float = 6.0, step_s: float = 0.02) -> bool:
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


def db_path(name: str) -> str:
    import os
    return os.path.join(TMPDIR, name)


def v5_packet(count: int = 1) -> bytes:
    now = int(time.time())
    header = struct.pack("!HHIIIIBBH", 5, count, 1000, now, 0, 0, 0, 0, 0)
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


def v9_packet(sets: bytes, domain: int = 0) -> bytes:
    header = struct.pack("!HHIIII", 9, 1, 1000, int(time.time()), 0, domain)
    return header + sets


def ipfix_set(set_id: int, payload: bytes) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(payload)) + payload


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


def build_v1_trap_with_oversized_ints() -> bytes:
    """A v1 trap whose generic-trap, specific-trap and time-stamp fields are
    encoded as BER values far longer than any real SNMP field: the SNMP
    spec's own INTEGER is Integer32 and TimeTicks is 32-bit unsigned, but BER
    itself puts no limit on how many bytes a magnitude occupies -- exactly
    the gap the review found undecoded."""
    generic_raw = _tlv(0x02, b"\x7f" + b"\xff" * 19)     # 20-byte INTEGER
    specific_raw = _tlv(0x02, b"\x7f" + b"\xff" * 19)    # 20-byte INTEGER
    uptime_raw = _tlv(0x43, b"\xff" * 9)                 # 9-byte TimeTicks
    varbinds = _tlv(0x30, b"")
    pdu = _tlv(0xA4,
              _oid_tlv("1.3.6.1.4.1.9999")
              + _tlv(0x40, bytes([10, 0, 0, 1]))          # agent-addr
              + generic_raw + specific_raw + uptime_raw
              + varbinds)
    return _tlv(0x30, _int_tlv(0) + _tlv(0x04, b"public") + pdu)


# ----------------------------------------------------------------------- R1

def test_r1_options_sampling_rate_is_clamped() -> None:
    """FIX 1(b): an options record declared a sampling rate with no upper
    bound, and _set_sampling cached it verbatim. Every subsequent flow for
    that exporter/domain/sampler carried it as Flow.sampling, and binding it
    on the next flush raised OverflowError out of the write -- see R2 for
    what that did to the writer thread. The field width a template declares
    is itself attacker-chosen (8 bytes here), not the usual 4, which is what
    lets the value exceed even SQLite's int64 range in the first place."""
    print("R1: an implausible sampling rate is rejected, not cached")

    decoder = nfdecode.Decoder()
    exporter = "10.9.9.1"

    # An options template declaring SAMPLING_INTERVAL as an 8-byte field --
    # a legal but unusual width a real device would never pick, and exactly
    # what makes the declared value able to exceed int64 at all.
    options_body = (struct.pack("!HHH", 900, 0, 4)
                    + struct.pack("!HH", nfdecode.SAMPLING_INTERVAL, 8))
    decoder.decode(v9_packet(ipfix_set(1, options_body)), exporter)
    check(("10.9.9.1", 0, 900) in decoder.templates,
          "the options template itself is cached normally")

    huge_rate = struct.pack("!Q", 0xFFFFFFFFFFFFFFFF)   # 2**64 - 1
    before = decoder.stats["implausible_sampling"]
    decoder.decode(v9_packet(ipfix_set(900, huge_rate)), exporter)
    check(decoder.stats["implausible_sampling"] == before + 1,
          "the absurd rate is counted as rejected")
    check(decoder.sampling_for(exporter, 0, 0) == decoder.default_sampling,
          f"and never took effect (still the default, got "
          f"{decoder.sampling_for(exporter, 0, 0)})")
    check(not decoder.learned_rates,
          "so nothing is queued for the database to correct against it")

    # A plausible but still large rate close to the chosen ceiling is kept.
    plausible = struct.pack("!Q", nfdecode.MAX_PLAUSIBLE_SAMPLING)
    decoder.decode(v9_packet(ipfix_set(900, plausible)), exporter)
    check(decoder.sampling_for(exporter, 0, 0) == nfdecode.MAX_PLAUSIBLE_SAMPLING,
          "a rate at the chosen ceiling is still accepted")

    # A normal data flow from the same exporter never carries an
    # out-of-int64 sampling value, whatever the options record tried.
    decoder2 = nfdecode.Decoder()
    fields = [(nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]
    template = struct.pack("!HH", 700, len(fields))
    for field_id, size in fields:
        template += struct.pack("!HH", field_id, size)
    decoder2.decode(v9_packet(ipfix_set(0, template)), exporter)
    decoder2.decode(v9_packet(ipfix_set(1, options_body)), exporter)
    decoder2.decode(v9_packet(ipfix_set(900, huge_rate)), exporter)
    record = struct.pack("!I", 2000) + struct.pack("!I", 20)
    flows = decoder2.decode(v9_packet(ipfix_set(700, record)), exporter)
    check(len(flows) == 1, "the data flow still decodes")
    check(INT64_MIN <= flows[0].sampling <= INT64_MAX,
          f"and its sampling is within int64 (got {flows[0].sampling})")
    check(flows[0].sampling == decoder2.default_sampling,
          f"in fact it fell back to the default, not the rejected rate "
          f"(got {flows[0].sampling})")


# ----------------------------------------------------------------------- R2

def test_r2_writer_thread_survives_and_running_reflects_death() -> None:
    """FIX 1(a) and 1(c): an unguarded insert_flows/touch_exporters used to
    let any raise (an OverflowError from R1's bug among others) unwind out of
    the writer thread and end it for good, while `running` only checked the
    receive thread -- so the collector kept accepting packets and
    status_text() kept saying "last packet just now" with nothing being
    stored. This proves both halves: the writer survives a batch that
    raises, and `running`/status_text() still correctly reflect a writer
    that really does die."""
    print("R2: the writer thread survives a bad batch, and `running` means "
          "both threads")

    # --- half 1: a batch that raises must not end the writer thread -------
    flow_db = FlowDatabase(db_path("r2-flows.db"))
    log = eventlog.EventLog()
    collector = Collector(flow_db, log=log)
    port = free_udp_port()
    assert collector.start({"port": port, "bind_address": "127.0.0.1"})
    try:
        original_insert = flow_db.insert_flows

        def raising_insert(flows):
            raise OverflowError(
                "Python int too large to convert to SQLite INTEGER")

        flow_db.insert_flows = raising_insert
        send_udp(port, v5_packet())
        check(wait_for(lambda: collector.counters["errors"] >= 1),
              "a batch that raises is counted as an error")
        check(collector.running,
              "the writer thread is still alive after the failing batch")
        check(any(event.category == eventlog.ERROR
                  and "batch of flows" in event.message
                  for event in log.all()),
              "the failure is visible in the event log, not just stderr")

        flow_db.insert_flows = original_insert
        before = collector.counters["flows"]
        send_udp(port, v5_packet())
        check(wait_for(lambda: collector.counters["flows"] > before),
              "the writer keeps flushing once the batch succeeds again")
    finally:
        collector.stop()
        flow_db.close()

    # --- half 2: running/status_text must still catch a writer that really
    # does die, from a call site this fix does not (and should not have to)
    # guard, the same way an unforeseen failure would show up in production.
    flow_db = FlowDatabase(db_path("r2-crash.db"))
    log = eventlog.EventLog()
    collector = Collector(flow_db, log=log)
    port = free_udp_port()
    assert collector.start({"port": port, "bind_address": "127.0.0.1"})
    try:
        def boom():
            raise RuntimeError("writer thread killed for the test")

        collector._apply_learned_rates = boom
        send_udp(port, v5_packet())
        check(wait_for(lambda: not collector.running, 8.0),
              "running goes False once the writer thread actually ends")
        check(collector.counters["packets"] >= 1,
              "the receiver had already accepted a packet before the writer "
              "died -- the exact stale-green scenario this fix closes")
        check("stopped unexpectedly" in collector.status_text(),
              f"status_text says so ({collector.status_text()!r})")
    finally:
        collector.stop()
        flow_db.close()


# ----------------------------------------------------------------------- R3

def test_r3_template_cache_bounded_per_exporter() -> None:
    """FIX 2: domain and template_id come straight out of the packet body,
    not the source address. One source (no spoofing needed) varying the
    4-byte observation-domain field per packet used to mint unlimited
    distinct keys in the one cache every exporter shared, evicting every
    real exporter's templates well before their own resend cycle -- a few
    thousand 32-byte packets was enough."""
    print("R3: a flood of distinct observation domains cannot evict another "
          "exporter's template")

    decoder = nfdecode.Decoder()
    fields = [(nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]

    def template_bytes(template_id: int) -> bytes:
        body = struct.pack("!HH", template_id, len(fields))
        for field_id, size in fields:
            body += struct.pack("!HH", field_id, size)
        return body

    genuine = "10.0.0.1"
    decoder.decode(v9_packet(ipfix_set(0, template_bytes(500)), domain=0),
                   genuine)
    check((genuine, 0, 500) in decoder.templates,
          "the genuine exporter's template is cached")

    attacker = "10.0.0.2"
    for domain in range(5000):
        decoder.decode(
            v9_packet(ipfix_set(0, template_bytes(900)), domain=domain),
            attacker)

    check((genuine, 0, 500) in decoder.templates,
          "5,000 distinct observation domains from a second source do not "
          "evict the first exporter's template")
    check(len(decoder.templates) <= nfdecode.MAX_TEMPLATES_PER_EXPORTER + 1,
          f"the attacker's own flood is bounded to its own per-exporter cap "
          f"({len(decoder.templates)} total held)")

    data = struct.pack("!I", 100) + struct.pack("!I", 5)
    flows = decoder.decode(v9_packet(ipfix_set(500, data), domain=0), genuine)
    check(len(flows) == 1,
          "the genuine exporter's data flowset still decodes after the "
          "flood")
    check(decoder.stats["no_template"] == 0,
          "and its data was never counted as templateless")


# ----------------------------------------------------------------------- R4

def test_r4_field_count_cap_rejects_absurd_templates() -> None:
    """FIX 2 (second half): `count`/`field_count` come straight off the wire
    (up to 65535, a 16-bit value) with no cap on how many (id, len[,
    enterprise]) tuples a template accumulated -- unlike trapdecode.py's
    max_varbinds, which already bounds the equivalent for traps."""
    print("R4: a template declaring an absurd field count is rejected")

    decoder = nfdecode.Decoder()
    count = 5000
    body = struct.pack("!HH", 800, count)
    body += struct.pack("!HH", nfdecode.OCTETS, 4) * count
    started = time.monotonic()
    decoder.decode(v9_packet(ipfix_set(0, body)), "10.0.0.5")
    elapsed = time.monotonic() - started
    check(("10.0.0.5", 0, 800) not in decoder.templates,
          f"a template declaring {count} fields (cap is "
          f"{nfdecode.MAX_FIELDS_PER_TEMPLATE}) is rejected, not cached")
    check(decoder.stats["bad_template"] >= 1, "and counted as bad_template")
    check(elapsed < 1.0,
          f"walking the {count} field entries to keep the flowset offset in "
          f"sync costs {elapsed * 1000:.1f} ms, not a hang or a huge alloc")

    # a legitimate template right after is unaffected
    ok_fields = [(nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]
    ok_body = struct.pack("!HH", 801, len(ok_fields))
    for field_id, size in ok_fields:
        ok_body += struct.pack("!HH", field_id, size)
    decoder.decode(v9_packet(ipfix_set(0, ok_body)), "10.0.0.5")
    check(("10.0.0.5", 0, 801) in decoder.templates,
          "a normal template sent right after is still cached")

    # the options-template path enforces the same cap
    opt_count = 5000
    opt_body = struct.pack("!HHH", 802, 0, opt_count * 4)
    opt_body += struct.pack("!HH", nfdecode.SAMPLING_INTERVAL, 4) * opt_count
    decoder.decode(v9_packet(ipfix_set(1, opt_body)), "10.0.0.5")
    check(("10.0.0.5", 0, 802) not in decoder.templates,
          "the options-template path enforces the same field-count cap")
    check(decoder.stats["bad_template"] >= 2,
          "and counts it the same way")


# ----------------------------------------------------------------------- R5

def test_r5_v1_oversized_integer_clamped_and_batch_survives() -> None:
    """FIX 3: trapdecode's v1 generic/specific and TimeTicks-uptime fields
    decoded a BER magnitude with no limit, and snmptrapd batched up to 200
    traps into one executemany -- so the OverflowError one poisoned trap's
    oversized field caused took the other 199 down with it, silently
    (stderr only, `except Exception: traceback.print_exc()`, invisible in
    the event log every other error path in that module uses)."""
    print("R5: an oversized v1 INTEGER decodes clamped, and one poisoned "
          "row does not cost the rest of its batch")

    decoder = trapdecode.Decoder()
    trap = decoder.decode(build_v1_trap_with_oversized_ints(), "10.0.0.9")
    check(trap is not None, "the crafted trap still decodes rather than "
                            "raising out of decode()")
    check(trapdecode._INT32_MIN <= trap.generic <= trapdecode._INT32_MAX,
          f"generic is clamped to Integer32 (got {trap.generic})")
    check(trapdecode._INT32_MIN <= trap.specific <= trapdecode._INT32_MAX,
          f"specific is clamped to Integer32 (got {trap.specific})")
    check(0 <= trap.uptime <= trapdecode._UINT32_MAX,
          f"uptime is clamped to 32-bit TimeTicks (got {trap.uptime})")
    check(INT64_MIN <= trap.generic <= INT64_MAX
          and INT64_MIN <= trap.specific <= INT64_MAX
          and trap.uptime <= INT64_MAX,
          "and, the thing that actually matters, all three are well within "
          "SQLite's int64 bind range")

    # A batch with one row the database itself cannot store must not cost
    # the other 199: _insert_batch retries one at a time.
    trap_db = SnmpTrapDatabase(db_path("r5-traps.db"))
    log = eventlog.EventLog()
    collector = TrapCollector(trap_db, log=log)
    good = [trapdecode.Trap(ts=time.time(), source="10.0.0.1", version=1,
                            community="public", trap_oid="1.3.6.1.6.3.1.1.5.3",
                            trap_name="linkDown", severity=3)
            for _ in range(199)]
    poisoned = trapdecode.Trap(ts=time.time(), source="10.0.0.1", version=1,
                               community="public",
                               trap_oid="1.3.6.1.6.3.1.1.5.3",
                               trap_name="linkDown", severity=3,
                               generic=10 ** 30)
    batch = good + [poisoned]

    stored = collector._insert_batch(batch)
    check(stored == 199,
          f"the 199 good traps are stored despite the one poisoned row "
          f"({stored})")
    check(trap_db.max_id() == 199, "and they actually reached the database")
    check(any(event.category == eventlog.ERROR
              and "failed to insert" in event.message for event in log.all()),
          "the batch failure is visible in the event log, not stderr")
    check(collector.counters["errors"] >= 1, "and counted")
    trap_db.close()


# ----------------------------------------------------------------------- R6

def test_r6_syslog_strips_control_and_ansi_bytes() -> None:
    """FIX 4: `.strip("\\r\\n\\x00 ")` only trimmed the ends. Embedded NULs,
    CR/LF and ANSI/VT100 escape sequences (which all open with ESC, 0x1B)
    reached the stored message and raw column unmodified from any
    unauthenticated sender on UDP/514 -- a terminal-escape-injection
    primitive for any CLI or export consumer, not a stored-XSS issue (the
    web UI already escapes correctly on render)."""
    print("R6: syslogparse strips embedded control and ANSI escape bytes")

    check(syslogparse._strip_control("a\x1bb\x00c\x7fd\x01e") == "a b c d e",
          "the helper replaces every C0 control byte and DEL with a space, "
          "rather than deleting it")
    check(syslogparse._strip_control("a\r\n\r\nb") == "a b",
          "a run of several control bytes collapses to one space, not one "
          "space per byte")

    msg = (b"<134>Sep  5 00:00:00 host app: before "
          b"\x1b[31mRED\x1b[0m after \x00 null \r\n end")
    entry = syslogparse.parse(msg, "10.0.0.1")
    check("\x1b" not in entry.message,
          "the ESC byte that opens an ANSI escape is gone from the message")
    check("\x00" not in entry.message, "an embedded NUL is gone")
    check("\r" not in entry.message and "\n" not in entry.message,
          "embedded CR/LF are gone too, not just trimmed off the ends")
    check("before" in entry.message and "RED" in entry.message
          and "after" in entry.message and "null" in entry.message
          and "end" in entry.message,
          f"the readable text around the stripped bytes survives "
          f"({entry.message!r})")
    check("\x1b" not in entry.raw and "\x00" not in entry.raw
          and "\r" not in entry.raw and "\n" not in entry.raw,
          "raw is cleaned the same way -- there is no verbatim copy sitting "
          "in a CLI or export path")
    check(entry.facility == 16 and entry.severity == 6,
          f"the PRI itself still parses correctly ({entry.facility}/"
          f"{entry.severity})")

    # A device that legitimately packs a multi-line block (a stack trace, a
    # config diff) into one syslog datagram must not have its words welded
    # together: deleting the embedded newline outright would turn "line
    # one\nline two" into "line oneline two", corrupting the message the
    # same way the injection this fix closes would have. Replacing with a
    # space keeps the word boundary.
    stack = (b"<134>Sep  5 00:00:02 host app: line one\nline two\nline three")
    multi = syslogparse.parse(stack, "10.0.0.1")
    check("oneline" not in multi.message and "twoline" not in multi.message,
          f"embedded newlines do not weld adjacent words together "
          f"({multi.message!r})")
    check("line one" in multi.message and "line two" in multi.message
          and "line three" in multi.message,
          f"each line's own words stay intact and space-separated "
          f"({multi.message!r})")

    plain = syslogparse.parse(b"<134>Sep  5 00:00:01 host app: plain message",
                              "10.0.0.1")
    check(plain.message == "plain message",
          "a normal message with nothing to strip is unaffected")


TESTS = [
    test_r1_options_sampling_rate_is_clamped,
    test_r2_writer_thread_survives_and_running_reflects_death,
    test_r3_template_cache_bounded_per_exporter,
    test_r4_field_count_cap_rejects_absurd_templates,
    test_r5_v1_oversized_integer_clamped_and_batch_survives,
    test_r6_syslog_strips_control_and_ansi_bytes,
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
    print("ALL COLLECTOR REVIEW FIX ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The syslog TCP listener's two RFC 6587 framings (octet counting and
newline framing) against a real SyslogCollector on a loopback socket.
Proves MAX_TCP_MESSAGE_BYTES bounds the per-connection buffer: an oversized
declared octet count or an unterminated line is rejected and counted rather
than growing memory without limit. 514/tcp is unauthenticated by design, so
this bound is the only thing between a hostile connection and the heap.
"""
import socket
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.syslogd import MAX_TCP_MESSAGE_BYTES, SyslogCollector
from netpath.syslogdb import SyslogDatabase

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{(': ' + str(detail)) if detail else ''}")
    if not ok:
        FAILURES.append(label)


def start_collector() -> tuple[SyslogCollector, SyslogDatabase, int]:
    db = SyslogDatabase(":memory:")
    collector = SyslogCollector(db)
    ok = collector.start({"accept_udp": False, "accept_tcp": True, "port": 0,
                          "tcp_port": 0, "bind_address": "127.0.0.1"})
    assert ok, collector.error
    port = collector._tcp.getsockname()[1]
    return collector, db, port


print(f"T1  syslog TCP framer: MAX_TCP_MESSAGE_BYTES ({MAX_TCP_MESSAGE_BYTES:,}) is enforced, "
      f"and is visible in the collector's own counters")

# ---------------------------------------------------- oversized octet count

collector, db, port = start_collector()
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    declared_length = 2_000_000_000     # far past the cap, still <=10 digits
    sock.sendall(f"{declared_length} <13>".encode())
    time.sleep(0.3)
    check("a connection declaring an oversized octet count is closed rather than kept open",
          sock.recv(16) == b"", "expected EOF")
    check("...and it is counted as tcp_oversized, not silently absorbed",
          collector.counters["tcp_oversized"] == 1, collector.counters)
    check("...without touching the counters an ordinary message would (messages/errors/dropped)",
          collector.counters["messages"] == 0 and collector.counters["errors"] == 0
          and collector.counters["dropped"] == 0, collector.counters)
    sock.close()
finally:
    collector.stop()
    db.close()

# ------------------------------------------------------- slow-drip sender
#
# The refusal above happens on the *declared* length alone, before any of the
# body is read — this is what closes the slow-drip path: trickling bytes in
# after the prefix cannot matter, because the connection is already gone.
# Confirmed here by actually trickling a few chunks in and checking the
# collector's own counters never move past the one refusal.

collector, db, port = start_collector()
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(f"{2_000_000_000} <13>".encode())
    for _ in range(5):
        try:
            sock.sendall(b"A" * 4096)
        except OSError:
            break                        # the peer already closed -- expected
        time.sleep(0.1)
    check("a slow-drip sender behind an oversized declared length is still refused, "
          "not merely delayed", collector.counters["tcp_oversized"] == 1, collector.counters)
    check("...and nothing it drips afterward is counted as a message",
          collector.counters["messages"] == 0, collector.counters)
    sock.close()
finally:
    collector.stop()
    db.close()

# --------------------------------------------- newline-framing runaway line

collector, db, port = start_collector()
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"A" * (MAX_TCP_MESSAGE_BYTES + 100))    # no newline anywhere
    time.sleep(0.3)
    check("a newline-framed line past the cap with no terminator is counted as tcp_oversized",
          collector.counters["tcp_oversized"] == 1, collector.counters)
    # Newline framing can resynchronise (the next '\n' is still findable), so
    # the connection is expected to stay open and useful afterward — unlike
    # the octet-count case above.
    sock.sendall(b"<134>Jan  1 00:00:00 host app: recovered\n")
    time.sleep(0.3)
    check("...and the connection stays open: a real message right after it still parses",
          collector.counters["messages"] == 1, collector.counters)
    sock.close()
finally:
    collector.stop()
    db.close()

# ------------------------------------------------ a legitimate large message
#
# The cap must not be so tight that a real message with a sizeable payload
# (a big RFC 5424 structured-data value, say) gets refused alongside the
# pathological ones.

collector, db, port = start_collector()
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    body = (b'<134>1 2024-01-01T00:00:00Z host app 1 msgid '
           b'[e k="' + b"x" * 500_000 + b'"] tail')
    assert len(body) < MAX_TCP_MESSAGE_BYTES
    sock.sendall(f"{len(body)} ".encode() + body)
    time.sleep(0.5)
    check(f"a legitimate {len(body):,}-byte octet-framed message, under the cap, is accepted",
          collector.counters["messages"] == 1 and collector.counters["tcp_oversized"] == 0,
          collector.counters)
    sock.close()
finally:
    collector.stop()
    db.close()


# ------------------------------------------- the allow list, per connection
#
# allowed_sources was applied in _enqueue, per message. A source outside it
# still took one of the (default 64) client slots and one thread, for up to
# 30 seconds an idle period — so anyone who could reach the port could hold
# every slot while `rejected` climbed and the counters read as if the allow
# list were working.

print("\nT2  syslog TCP: the allow list is consulted before a slot is taken")

db = SyslogDatabase(":memory:")
collector = SyslogCollector(db)
assert collector.start({"accept_udp": False, "accept_tcp": True, "port": 0,
                        "tcp_port": 0, "bind_address": "127.0.0.1",
                        "allowed_sources": "10.99.99.99",
                        "max_tcp_clients": 4})
port = collector._tcp.getsockname()[1]
hoggers = []
try:
    for _ in range(8):
        hog = socket.create_connection(("127.0.0.1", port), timeout=5)
        hoggers.append(hog)
    deadline = time.time() + 3.0
    while time.time() < deadline and collector.counters["rejected"] < 8:
        time.sleep(0.05)
    check("a connection from a source outside the allow list is refused at "
          "accept() and counted",
          collector.counters["rejected"] >= 8, collector.counters)
    check("...so it never takes one of the client slots",
          collector.counters["tcp_clients"] == 0, collector.counters)
    check("...and none of them is counted as a slot refusal, which would say "
          "the transport was full rather than the sender unknown",
          collector.counters["tcp_refused"] == 0, collector.counters)
    check("nothing is stored from a refused connection",
          collector.counters["messages"] == 0, collector.counters)
finally:
    for hog in hoggers:
        try:
            hog.close()
        except OSError:
            pass
    collector.stop()
    db.close()

# The default (empty allow list, auto_accept on) is unchanged.
collector, db, port = start_collector()
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"<134>Sep  5 00:00:00 host app: hello\n")
    deadline = time.time() + 3.0
    while time.time() < deadline and collector.counters["messages"] < 1:
        time.sleep(0.05)
    check("with no allow list configured a connection is accepted exactly as "
          "before", collector.counters["messages"] == 1, collector.counters)
    check("...and it holds a client slot while it is open",
          collector.counters["tcp_clients"] == 1, collector.counters)
    sock.close()
finally:
    collector.stop()
    db.close()


# ------------------------------------- the rate buckets under several threads
#
# _buckets is reached from the UDP receive thread and from every
# syslog-tcp-client thread at once. get/move_to_end against another thread's
# eviction loop could raise KeyError for a key just evicted, and the message
# was dropped as a receive error.

print("\nT3  syslog rate buckets survive being hammered from many threads")

import threading  # noqa: E402

from netpath.syslogd import MAX_RATE_SOURCES  # noqa: E402

db = SyslogDatabase(":memory:")
collector = SyslogCollector(db)
assert collector.start({"accept_udp": True, "accept_tcp": False, "port": 0,
                        "bind_address": "127.0.0.1", "per_source_rate": 1000})
errors = []
try:
    def hammer(offset):
        try:
            now = time.time()
            for i in range(5_000):
                source = f"10.{(i + offset) % 256}.{(i // 256) % 256}.1"
                collector._within_rate(source, now)
                collector._enqueue(b"<134>x", source)
        except Exception as exc:                     # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check("no exception escapes 80,000 bucket updates from 16 threads",
          not errors, errors[:3])
    check(f"and the bucket table stays bounded at MAX_RATE_SOURCES "
          f"({MAX_RATE_SOURCES})",
          len(collector._buckets) <= MAX_RATE_SOURCES, len(collector._buckets))
    accepted = collector.counters["messages"] + collector.counters["throttled"]
    check("every message is counted exactly once, none lost to a torn +=",
          accepted == 80_000, dict(collector.counters))
finally:
    collector.stop()
    db.close()


# ---------------------------------------------------------------- T4
#
# T3 above passes with the lock neutered: 80,000 racing updates never lost
# one here, so its invariant cannot fail on demand. This asks the same fact
# deterministically, of each counter and the thread it arrives on.

print("\nT4  the counter lock is really taken, and really guards all of them")

db = SyslogDatabase(":memory:")
collector = SyslogCollector(db)
try:
    check("the lock is named for what it guards, not for the buckets alone",
          hasattr(collector, "_counter_lock"),
          [n for n in vars(collector) if n.endswith("_lock")])

    def blocks_on_the_lock(label, call):
        """True when `call`, run on a worker, cannot finish while the main
        thread holds the counter lock -- and finishes once it is released."""
        state = []
        with collector._counter_lock:
            worker = threading.Thread(
                target=lambda: (call(), state.append("finished")))
            worker.start()
            worker.join(0.3)
            blocked = worker.is_alive()
        worker.join(5.0)
        check(f"T4 {label} waits on the counter lock", blocked, state)
        check(f"T4 ...and completes once it is released",
              state == ["finished"], state)

    collector._rate = 1000.0     # _within_rate short-circuits at rate 0
    blocks_on_the_lock("_within_rate (the bucket path this lock already had)",
                       lambda: collector._within_rate("10.9.9.9", time.time()))
    blocks_on_the_lock("_note_error, from the receive threads",
                       lambda: collector._note_error(OSError("receive failed")))
    blocks_on_the_lock("_note_oversized, from a TCP client thread",
                       lambda: collector._note_oversized("10.9.9.9", 999_999))

    # The accept loop's two have no method of their own to ask.
    before = dict(collector.counters)
    blocks_on_the_lock(
        "the accept loop's tcp_clients write",
        lambda: collector.finish_stop(time.monotonic() + 1.0))

    check("T4 errors was actually counted, not merely locked around",
          collector.counters["errors"] == 1, collector.counters["errors"])
    check("T4 tcp_oversized too",
          collector.counters["tcp_oversized"] == 1,
          collector.counters["tcp_oversized"])
    check("T4 and tcp_clients was reset through the same lock",
          collector.counters["tcp_clients"] == 0,
          (before.get("tcp_clients"), collector.counters["tcp_clients"]))
finally:
    collector.stop()
    db.close()


if FAILURES:
    print(f"\nFAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    raise SystemExit(1)
print("\nall syslog TCP framer checks passed")

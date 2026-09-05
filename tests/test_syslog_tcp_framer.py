"""The syslog TCP listener's two RFC 6587 framings, against a memory-safety
gap neither had: nothing bounded how large a single message's declared
length (octet counting) or unterminated line (newline framing) could grow
the per-connection buffer to before this file's own MAX_TCP_MESSAGE_BYTES
existed. 514/tcp takes input from anyone who can open a connection, with no
authentication ahead of it — the same unauthenticated-by-design shape as
514/udp and 162/udp.

Measured before the fix (a real SyslogCollector on a loopback socket, one
connection, tracemalloc watching this process's own traced allocations):
declaring an octet count of 2 GB and then trickling 1 MB/s toward it left
the collector holding 42 MB (peak 82.5 MB — `buffer += chunk` briefly holds
both the old and new buffer at once) after only 50 MB had been sent, with
every counter — messages, errors, rejected, dropped — still at zero. Nothing
told an operator it was happening, and `_max_tcp_clients` (default 64) bounds
how many connections can each be doing this at once but not how large any
one of them grows.
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


if FAILURES:
    print(f"\nFAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    raise SystemExit(1)
print("\nall syslog TCP framer checks passed")

"""The socket-based ICMP path ipam_scan.ping_once/ping_many use in place of
one `ping` subprocess per probe (see the module comment in ipam_scan.py
above _PING_MODE_ENV).

Covers: the checksum and wire framing (build/parse round trip, independent
of any real network), capability detection falling back to the subprocess
path when a socket cannot be opened at all, the NETPATH_PING_MODE override
(the mechanism the demo harness needs to keep its scripted `ping` shim in
charge), and — where this host actually has ICMP socket access — that a
real probe still works and that sweep()'s probes-per-second pacing still
holds when the probe itself is now cheap instead of a subprocess spawn.

A locked-down host with no ICMP socket access at all (no CAP_NET_RAW, no
ping_group_range) still runs every check here: the ones that need a real
socket skip individually rather than the whole suite exiting SKIP, since
the checksum/framing/override checks do not need one.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import ipam_scan

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def reset_capability_cache():
    """Every test here either forces NETPATH_PING_MODE or wants a fresh
    detection, so each one starts from "not yet checked" rather than
    inheriting whatever an earlier test (or module import) cached."""
    ipam_scan._icmp_kind_cache = "unchecked"
    os.environ.pop(ipam_scan._PING_MODE_ENV, None)


def checksum_and_framing():
    # RFC 1071's own property: the checksum of a buffer that already
    # contains its own correct checksum field is zero.
    request = ipam_scan._build_echo_request(0x1234, 7, b"payload!")
    check(ipam_scan._icmp_checksum(request) == 0,
         "a checksummed request self-checks to zero")

    # A single flipped bit must not still self-check to zero.
    tampered = bytearray(request)
    tampered[8] ^= 0x01                 # inside the identifier field
    check(ipam_scan._icmp_checksum(bytes(tampered)) != 0,
         "a corrupted request does not still self-check to zero")

    # A known vector: an all-zero 8-byte header checksums to 0xFFFF (the
    # one's-complement of zero), the same value ping(8) would compute for
    # an empty echo request with a zero checksum field.
    check(ipam_scan._icmp_checksum(b"\x00" * 8) == 0xFFFF,
         "checksum of an all-zero buffer is 0xFFFF")

    # build -> reply -> parse round trip, entirely off the wire format,
    # no socket involved. A device's reply is the same bytes with the
    # type byte changed from Echo Request (8) to Echo Reply (0) — the
    # payload (our token) comes back unchanged, as ping(8) requires.
    token = os.urandom(8)
    sent = ipam_scan._build_echo_request(0xBEEF, 3, token)
    reply = bytes([ipam_scan._ICMP_ECHO_REPLY]) + sent[1:]
    parsed = ipam_scan._parse_icmp_reply(reply, has_ip_header=False)
    check(parsed is not None, "a well-formed reply parses")
    icmp_type, _code, identifier, sequence, payload = parsed
    check((icmp_type, identifier, sequence, payload) ==
         (ipam_scan._ICMP_ECHO_REPLY, 0xBEEF, 3, token),
         f"parsed reply matches what was sent: {parsed}")

    # SOCK_RAW hands back the IP header too (20 bytes here, no options) —
    # _parse_icmp_reply must skip exactly that many bytes, using the IHL
    # nibble rather than assuming 20.
    ip_header = bytes([0x45]) + b"\x00" * 19   # IHL=5 -> 20-byte header
    parsed_raw = ipam_scan._parse_icmp_reply(ip_header + reply, has_ip_header=True)
    check(parsed_raw == parsed,
         "the same reply parses the same whether or not an IP header precedes it")

    # Too short to be anything.
    check(ipam_scan._parse_icmp_reply(b"\x00\x01\x02", has_ip_header=False) is None,
         "a too-short packet parses as None, not a crash")
    check(ipam_scan._parse_icmp_reply(b"\x45" + b"\x00" * 10, has_ip_header=True) is None,
         "a too-short raw packet (header included) parses as None too")


def capability_detection_and_fallback():
    reset_capability_cache()
    real_socket = socket.socket

    # A host with neither an unprivileged ping socket nor CAP_NET_RAW:
    # every attempt to open one raises, and detection must come back None
    # rather than propagating that error.
    def always_refused(*args, **kwargs):
        raise OSError("EPERM (simulated): Operation not permitted")

    socket.socket = always_refused
    try:
        check(ipam_scan._detect_icmp_socket_kind() is None,
             "capability detection returns None when every socket() call is refused")
    finally:
        socket.socket = real_socket

    # ping_once must still return a plain bool in that situation — falling
    # back to the subprocess path — not raise. There is no `ping` binary
    # on this machine (confirmed by test_nodediscover_e2e.py's own
    # comment), so subprocess.run itself fails with FileNotFoundError,
    # which ping_once already turns into False; either way this call must
    # not raise past the refused socket.
    reset_capability_cache()
    socket.socket = always_refused
    try:
        result = ipam_scan.ping_once("127.0.0.1", timeout_ms=200)
        check(result is False,
             "ping_once falls back cleanly (to False, no ping binary here) "
             "when no ICMP socket can be opened at all")
    finally:
        socket.socket = real_socket
    reset_capability_cache()

    # Detection runs once and is cached, not repeated per probe: patch
    # socket.socket to count calls, then probe several times.
    calls = []
    def counting(*args, **kwargs):
        calls.append(1)
        return real_socket(*args, **kwargs)

    reset_capability_cache()
    socket.socket = counting
    try:
        ipam_scan._icmp_socket_kind()
        after_first = len(calls)
        for _ in range(5):
            ipam_scan._icmp_socket_kind()
        check(len(calls) == after_first,
             f"capability is detected once and cached, not per call "
             f"({after_first} then {len(calls)} socket() calls for 6 checks)")
    finally:
        socket.socket = real_socket
    reset_capability_cache()


def mode_override():
    reset_capability_cache()

    # NETPATH_PING_MODE=subprocess must win even when a real ICMP socket
    # is available — this is the switch the demo harness needs (see the
    # module comment in ipam_scan.py) so a simulated device's loopback
    # address is never reached directly.
    os.environ[ipam_scan._PING_MODE_ENV] = "subprocess"
    try:
        check(ipam_scan._icmp_socket_kind() is None,
             "NETPATH_PING_MODE=subprocess forces the subprocess path "
             "regardless of what capability detection would say")
    finally:
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)

    # NETPATH_PING_MODE=socket demands the fast path and raises rather
    # than silently returning None when it is not actually available —
    # useful for a deployment to confirm it landed.
    reset_capability_cache()
    real_socket = socket.socket
    socket.socket = lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
    os.environ[ipam_scan._PING_MODE_ENV] = "socket"
    try:
        raised = False
        try:
            ipam_scan._icmp_socket_kind()
        except OSError:
            raised = True
        check(raised,
             "NETPATH_PING_MODE=socket raises rather than silently "
             "falling back when no socket can actually be opened")
    finally:
        socket.socket = real_socket
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)
    reset_capability_cache()

    # An unrecognised value behaves like "auto" (detect, don't demand,
    # don't force off) rather than raising on a typo.
    os.environ[ipam_scan._PING_MODE_ENV] = "yolo"
    try:
        try:
            kind = ipam_scan._icmp_socket_kind()
            check(True, f"an unrecognised NETPATH_PING_MODE behaves as auto (kind={kind!r})")
        except OSError as exc:
            check(False, f"an unrecognised NETPATH_PING_MODE must not raise: {exc}")
    finally:
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)
    reset_capability_cache()


def subprocess_path_still_works():
    """With the fast path switched off, ping_once/ping_many must still go
    through subprocess.run exactly as before — the fallback this whole
    change depends on for Windows, IPv6, and any locked-down host."""
    os.environ[ipam_scan._PING_MODE_ENV] = "subprocess"
    real_run = subprocess.run
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        out = "64 bytes from 10.0.0.9: icmp_seq=1 ttl=64 time=4.20 ms\n"
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    subprocess.run = fake_run
    try:
        ok = ipam_scan.ping_once("10.0.0.9", timeout_ms=500)
        check(ok is True, "ping_once (subprocess mode) reports success from a 0 exit code")
        check(len(calls) == 1 and calls[0][-1] == "10.0.0.9",
             f"ping_once shelled out to the ping command: {calls}")

        calls.clear()
        sent, received, rtt = ipam_scan.ping_many("10.0.0.9", count=3, timeout_ms=500)
        check((sent, received) == (3, 3),
             f"ping_many (subprocess mode) still sends/counts 3 probes: {(sent, received)}")
        check(rtt is not None and abs(rtt - 4.20) < 1e-6,
             f"ping_many still parses the RTT out of ping's own output: {rtt}")
        check(len(calls) == 3, f"ping_many still spawns one subprocess per probe: {len(calls)}")

        def fake_run_fail(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")

        subprocess.run = fake_run_fail
        check(ipam_scan.ping_once("10.0.0.9", timeout_ms=500) is False,
             "a nonzero exit code (subprocess mode) is still a failed probe")
    finally:
        subprocess.run = real_run
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)
        reset_capability_cache()


def real_socket_probe_and_rate_limit():
    """Everything below needs an actual ICMP socket on this host — skipped
    (not failed) where neither an unprivileged ping socket nor CAP_NET_RAW
    is available, since that is exactly the "fall back to subprocess"
    case the tests above already cover directly."""
    reset_capability_cache()
    kind = ipam_scan._icmp_socket_kind()
    if kind is None:
        print("SKIP  real_socket_probe_and_rate_limit: no ICMP socket access on this "
             "host (checked both SOCK_DGRAM and SOCK_RAW); the subprocess "
             "fallback is exercised separately above")
        return

    # 127.0.0.0/8 is entirely local; the kernel answers ICMP for any
    # address in it. A real, un-mocked probe against one must succeed...
    sent, received, rtt = ipam_scan.ping_many("127.0.0.3", count=3, timeout_ms=500)
    check((sent, received) == (3, 3) and rtt is not None,
         f"a real {kind}-socket probe of a loopback address succeeds: "
         f"sent={sent} received={received} rtt={rtt}")

    # ...and a real, un-mocked probe of an address nothing answers on
    # (TEST-NET-1, RFC 5737) must cleanly time out rather than hang or
    # raise, still within roughly one timeout window.
    started = time.monotonic()
    ok = ipam_scan.ping_once("192.0.2.77", timeout_ms=250)
    elapsed = time.monotonic() - started
    check(ok is False, "a real probe of an address nothing answers reports failure")
    check(elapsed < 1.0,
         f"…and gives up at roughly its own timeout, not some larger one ({elapsed:.2f}s)")

    # sweep()'s probes-per-second pacing (ipam_scan.py's own comment: "a
    # burst of hundreds of ICMP echo requests... has knocked over legacy
    # PLC and RTU stacks") must still hold now that the probe itself is a
    # socket instead of a subprocess — batching the ICMP must not turn
    # into batching past this limit. 24 loopback addresses (all real,
    # all answered by the kernel) at 40/s cannot finish in under ~0.55 s;
    # unpaced the same 24 real probes finish far faster, since a socket
    # round trip to loopback is sub-millisecond.
    addresses = [f"127.0.0.{i}" for i in range(1, 25)]
    started = time.monotonic()
    result = ipam_scan.sweep(addresses, timeout_ms=500, probes_per_second=40)
    elapsed = time.monotonic() - started
    check(elapsed >= 0.55,
         f"24 addresses at 40/s takes at least ~0.55s even with a fast probe "
         f"(took {elapsed:.2f}s)")
    check(all(result.values()) and len(result) == 24,
         f"…and every one of them is still reported alive ({sum(result.values())}/24)")

    started = time.monotonic()
    ipam_scan.sweep(addresses, timeout_ms=500, probes_per_second=0)
    unpaced = time.monotonic() - started
    check(unpaced < 0.4,
         f"…while unpaced, the same 24 real probes are genuinely fast now "
         f"({unpaced:.2f}s), confirming the 0.55s above was the pacing, not the probe")


def selector_valueerror_falls_back():
    """select.select() raises ValueError, not OSError, for any file
    descriptor >= 1024 — a busy process (a 1,000-device fleet, many
    workers/fds) hits this routinely. _ping_many_socket now waits through
    selectors.DefaultSelector (epoll on Linux, no fd ceiling) specifically
    to sidestep that, but the fallback in ping_once/ping_many has to
    degrade cleanly to the subprocess path on a ValueError from that wait
    too — not just an OSError — for whatever the selector backend still
    throws unexpectedly. Needs a real ICMP socket to reach the wait loop
    at all; skipped where none is available, same as
    real_socket_probe_and_rate_limit above."""
    reset_capability_cache()
    kind = ipam_scan._icmp_socket_kind()
    if kind is None:
        print("SKIP  selector_valueerror_falls_back: no ICMP socket access on this "
             "host (checked both SOCK_DGRAM and SOCK_RAW)")
        return

    class ExplodingSelector:
        """Stands in for selectors.DefaultSelector: register() is a no-op,
        select() raises ValueError the moment the wait loop calls it —
        exactly the fd>=1024 failure mode select.select() has, reproduced
        without actually needing 1,000+ open descriptors in this test."""

        def register(self, *_args, **_kwargs):
            pass

        def select(self, *_args, **_kwargs):
            raise ValueError("simulated: fd >= 1024")

        def close(self):
            pass

    real_selector_cls = ipam_scan.selectors.DefaultSelector
    real_run = subprocess.run
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        out = "64 bytes from 10.0.0.9: icmp_seq=1 ttl=64 time=1.00 ms\n"
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    ipam_scan.selectors.DefaultSelector = ExplodingSelector
    subprocess.run = fake_run
    try:
        result = ipam_scan.ping_once("127.0.0.1", timeout_ms=200)
        check(result is True,
             "ping_once falls back to the subprocess path (and reports its "
             "result) when the wait loop raises ValueError, rather than "
             "raising into the caller")
        check(len(calls) == 1,
             f"...and actually went through subprocess.run to get it: {calls}")

        calls.clear()
        sent, received, rtt = ipam_scan.ping_many("127.0.0.1", count=2, timeout_ms=200)
        check((sent, received) == (2, 2),
             f"ping_many also falls back cleanly on the same ValueError: "
             f"sent={sent} received={received}")
        check(len(calls) == 2,
             f"...one subprocess per probe, as the fallback always does: {calls}")
    finally:
        ipam_scan.selectors.DefaultSelector = real_selector_cls
        subprocess.run = real_run
        reset_capability_cache()


def main() -> int:
    checksum_and_framing()
    capability_detection_and_fallback()
    mode_override()
    subprocess_path_still_works()
    real_socket_probe_and_rate_limit()
    selector_valueerror_falls_back()

    print()
    if FAILURES:
        print(f"FAILURES: {len(FAILURES)}")
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

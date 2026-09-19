"""The subprocess ping fallback (netpath.ipam_scan.ping_once/ping_many),
used for IPv6 and wherever the ICMP socket path is unavailable:

1. ping.exe exits 0 for "Destination host unreachable" -- an intermediate
   router's ICMP error, not a reply from the target -- so exit code alone
   must not be read as "up". A genuine IPv4 reply needs TTL= too (unaffected
   by Windows localising "time=" into other field names); IPv6 replies carry
   no TTL= at all, so that address family is exit-code-only still (a known,
   documented gap, not fixed here).
2. subprocess.run(text=True) with no `errors=` raises UnicodeDecodeError on
   a byte invalid in the decode encoding; the OEM code page on a localised
   Windows server can produce exactly that in ping's own output. errors=
   "replace" must be passed through, and a reply carrying a replacement
   character must not raise or falsely count as a good reply.

Section 3 proves the same `errors="replace"` passthrough for
netpath.tracer's own ping()/_run() subprocess calls -- a second call site
with the same OEM-code-page exposure, not covered by ipam_scan's tests.
"""
import subprocess
import sys

import _paths  # noqa: F401
from netpath import ipam_scan, tracer

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def _fixture(returncode: int, stdout: str, stderr: str = ""):
    def fake_run(*args, **kwargs):
        check("the fallback still asks for text output", kwargs.get("text") is True)
        check("...and passes errors='replace' so a bad byte cannot raise",
              kwargs.get("errors") == "replace")
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    return fake_run


def with_fake_run(fake_run, thunk):
    # ipam_scan does `import subprocess` at module scope, so this is the
    # same module object it calls subprocess.run() on.
    real_run = subprocess.run
    subprocess.run = fake_run
    try:
        return thunk()
    finally:
        subprocess.run = real_run


# ---------------------------------------------------- 1. genuine reply only

WIN_REPLY = "Reply from 10.0.0.1: bytes=32 time=1ms TTL=64\r\n"
WIN_UNREACHABLE = ("Reply from 10.0.0.254: Destination host unreachable.\r\n")
WIN_TIMEOUT = "Request timed out.\r\n"

# Force the subprocess path: ping_once/ping_many try a real ICMP socket
# first wherever the platform allows one, and this fixture is only about
# the fallback (IPv6, or the socket API unavailable — see ipam_scan.py's
# own module docstring on _icmp_socket_kind).
was_windows = ipam_scan.IS_WINDOWS
was_icmp_kind = ipam_scan._icmp_socket_kind
ipam_scan._icmp_socket_kind = lambda: None
ipam_scan.IS_WINDOWS = True
try:
    ok = with_fake_run(_fixture(0, WIN_REPLY), lambda: ipam_scan.ping_once("10.0.0.1"))
    check("a genuine reply (exit 0, TTL= present) counts as up", ok is True)

    ok = with_fake_run(_fixture(0, WIN_UNREACHABLE), lambda: ipam_scan.ping_once("10.0.0.1"))
    check("exit 0 with 'Destination host unreachable' and no TTL= is NOT up "
          "(the bug this closes)", ok is False)

    ok = with_fake_run(_fixture(1, WIN_TIMEOUT), lambda: ipam_scan.ping_once("10.0.0.1"))
    check("a genuine timeout (nonzero exit) is not up", ok is False)

    sent, received, avg = with_fake_run(
        _fixture(0, WIN_UNREACHABLE),
        lambda: ipam_scan.ping_many("10.0.0.1", count=3, timeout_ms=200))
    check("ping_many does not count an exit-0 unreachable reply as received",
          received == 0, (sent, received, avg))

    sent, received, avg = with_fake_run(
        _fixture(0, WIN_REPLY),
        lambda: ipam_scan.ping_many("10.0.0.1", count=3, timeout_ms=200))
    check("ping_many counts a genuine reply on every probe",
          received == 3 and avg == 1.0, (sent, received, avg))
finally:
    ipam_scan.IS_WINDOWS = was_windows
    ipam_scan._icmp_socket_kind = was_icmp_kind


# ------------------------ 1b. IPv6: ping.exe's reply carries no TTL= field

WIN_V6_REPLY = "Reply from 2001:db8::1: time=1ms\r\n"
WIN_V6_UNREACHABLE = "Reply from 2001:db8::1: Destination host unreachable.\r\n"

ipam_scan.IS_WINDOWS = True
ipam_scan._icmp_socket_kind = lambda: None
try:
    ok = with_fake_run(_fixture(0, WIN_V6_REPLY),
                       lambda: ipam_scan.ping_once("2001:db8::1"))
    check("an IPv6 reply (exit 0, no TTL= field at all) still counts as up",
          ok is True)

    # Known limitation, not a fix: ping.exe gives no locale-independent way
    # to tell an IPv6 "unreachable" from a real reply, so this still reads
    # as up on exit code alone -- documenting current behaviour, not a claim
    # it is correct.
    ok = with_fake_run(_fixture(0, WIN_V6_UNREACHABLE),
                       lambda: ipam_scan.ping_once("2001:db8::1"))
    check("an IPv6 exit-0 unreachable reply is (still) read as up -- documented, unfixed",
          ok is True)
finally:
    ipam_scan.IS_WINDOWS = was_windows
    ipam_scan._icmp_socket_kind = was_icmp_kind


# ------------------------------------------------- 2. tolerant of a bad byte

def fake_run_decoding(*args, **kwargs):
    """Mimics what the real subprocess.run(text=True, errors=...) does: the
    child's raw bytes are decoded with whatever `errors` the caller passed
    -- 0xFF is not a valid UTF-8 continuation byte, so this raises exactly
    the UnicodeDecodeError a bad OEM code page would, unless errors=
    'replace' (or similar) was actually passed through."""
    check("the ping fallback passes errors='replace' (decoding fixture)",
          kwargs.get("errors") == "replace")
    raw = b"Reply from 10.0.0.1: bytes=32 time=1ms TTL=\xff4\r\n"
    stdout = raw.decode("utf-8", errors=kwargs.get("errors") or "strict")
    return subprocess.CompletedProcess(args, 0, stdout, "")


ipam_scan.IS_WINDOWS = True
ipam_scan._icmp_socket_kind = lambda: None
try:
    raised = False
    try:
        ok = with_fake_run(fake_run_decoding, lambda: ipam_scan.ping_once("10.0.0.1"))
    except UnicodeDecodeError:
        raised = True
        ok = None
    check("a reply with a byte invalid for the decode encoding does not raise",
          not raised, ok)
    # The bad byte lands in the RTT digits, after the intact "TTL=" marker,
    # so replacing it with U+FFFD (rather than raising) still lets a real
    # reply be recognised as one.
    check("...and the reply is still recognised as genuine", ok is True)
finally:
    ipam_scan.IS_WINDOWS = was_windows
    ipam_scan._icmp_socket_kind = was_icmp_kind

# --------------------------------- 3. tracer's own ping()/_run() call sites

def fake_run_tracer_decoding(*args, **kwargs):
    check("tracer's ping() passes errors='replace' too",
          kwargs.get("errors") == "replace")
    raw = b"Reply from 10.0.0.1: bytes=32 time=\xff1ms TTL=64\r\n"
    stdout = raw.decode("utf-8", errors=kwargs.get("errors") or "strict")
    return subprocess.CompletedProcess(args, 0, stdout, "")


with_fake_run(fake_run_tracer_decoding, lambda: tracer.ping("10.0.0.1"))

was_ttracer_run = subprocess.run
try:
    def fake_traceroute_run(*args, **kwargs):
        check("tracer._run() (the traceroute path) passes errors='replace'",
              kwargs.get("errors") == "replace")
        raw = b"1  10.0.0.1  \xff1.234 ms\r\n"
        stdout = raw.decode("utf-8", errors=kwargs.get("errors") or "strict")
        return subprocess.CompletedProcess(args, 0, stdout, "")
    subprocess.run = fake_traceroute_run
    raised = False
    try:
        tracer._run(["traceroute", "10.0.0.1"], budget=5.0)
    except UnicodeDecodeError:
        raised = True
    check("a byte invalid for the decode encoding does not raise there either",
          not raised)
finally:
    subprocess.run = was_ttracer_run

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

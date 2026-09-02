"""Shared plumbing for the end-to-end suites: the repo root on sys.path so
`netpath` imports from any working directory, a free loopback UDP port, and a
stub SNMP agent spawned as a child process on that port.

Every suite is a plain script (stdlib only, like the application): run it
directly, or all of them through run_all.py."""
import os
import socket
import subprocess
import sys
import tempfile
import threading

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
STUBS_DIR = os.path.join(TESTS_DIR, "stubs")

for _p in (REPO_ROOT, TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tmpdir(prefix: str) -> str:
    return tempfile.mkdtemp(prefix=prefix)


def spawn_stub(script: str, *args: str, timeout_s: float = 10.0):
    """Starts tests/stubs/<script> on a free loopback UDP port and returns
    (process, port) once the stub has printed its "listening" banner, so the
    socket is bound before the caller sends anything. Kill the process in a
    finally block. The banner is the contract every stub honours: one line
    on stdout, flushed, after bind()."""
    port = free_udp_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(STUBS_DIR, script), str(port), *args],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    banner = _read_line(proc, timeout_s)
    if not banner or "listening" not in banner.lower():
        proc.kill()
        raise RuntimeError(f"{script} did not come up on 127.0.0.1:{port}: {banner!r}")
    # Keep draining what the stub prints after the banner (some log every
    # dropped request); a full pipe would block the stub on its own print.
    threading.Thread(target=_drain, args=(proc,), daemon=True).start()
    return proc, port


def _read_line(proc, timeout_s: float) -> str:
    box = []

    def reader():
        try:
            box.append(proc.stdout.readline())
        except Exception as exc:  # pragma: no cover
            box.append(f"<{exc}>")

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout_s)
    return box[0] if box else ""


def _drain(proc) -> None:
    try:
        for _line in proc.stdout:
            pass
    except Exception:  # the pipe closes when the stub is killed
        pass

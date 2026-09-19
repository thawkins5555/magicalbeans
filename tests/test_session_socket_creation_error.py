"""socket.socket() in _Session.__init__ was unguarded -- a failure to
create a UDP socket (port/handle exhaustion under a large pool) escaped as a
bare OSError, past every SnmpError handler _poll_device has, so record_poll
never ran and the device's status froze at whatever it last was. Now
re-raised as SnmpError, the same type every other SNMP failure already is."""
import socket
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodepoll import _Session
from netpath.snmppoll import SnmpError

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def main():
    real_socket = socket.socket

    def exploding_socket(*a, **k):
        raise OSError(24, "Too many open files")

    socket.socket = exploding_socket
    try:
        try:
            _Session("192.0.2.1", 161, 1.0, 1)
            check(False, "socket creation failure should raise")
        except SnmpError:
            check(True, "a socket-creation OSError is re-raised as SnmpError")
        except OSError:
            check(False, "a bare OSError escaped instead of SnmpError")
    finally:
        socket.socket = real_socket

    # A real socket still opens normally once sockets are available again.
    session = _Session("192.0.2.1", 161, 1.0, 1)
    check(session.sock is not None, "a normal session still opens its socket")
    session.close()

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

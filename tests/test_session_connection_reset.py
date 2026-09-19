"""On Windows, a UDP send to a closed/unreachable port makes the next
recvfrom raise ConnectionResetError (an ICMP port-unreachable reported as a
reset) -- _Session.request used to catch it as a plain OSError and raise
SnmpError, misreporting "no reply" as a generic error. netpath/udpsock.py's
receive loop already treats the same exception as no answer; _Session now
does too, as an SnmpTimeout for that attempt."""
import socket
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodepoll import _Session
from netpath.snmppoll import SnmpError, SnmpTimeout, build_request, PDU_GET

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


class _ResetSocket:
    """Standing in for a real UDP socket: sendto is a no-op, recvfrom
    always raises the exception recvfrom() raises when a previous
    datagram drew an ICMP port-unreachable."""

    def __init__(self, exc):
        self.exc = exc

    def settimeout(self, *a):
        pass

    def sendto(self, *a):
        pass

    def recvfrom(self, *a):
        raise self.exc

    def close(self):
        pass


def main():
    packet = build_request(1, "public", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])

    session = _Session("192.0.2.1", 161, 0.2, 1)
    session.sock = _ResetSocket(ConnectionResetError(10054, "forcibly closed"))
    try:
        session.request(packet, expect_request_id=1)
        check(False, "a ConnectionResetError on every attempt should raise")
    except SnmpTimeout:
        check(True, "ConnectionResetError on recvfrom raises SnmpTimeout, "
                    "not a generic SnmpError")
    except SnmpError as exc:
        check(False, f"raised a generic SnmpError instead of SnmpTimeout ({exc})")

    # A reset on attempt 1 does not abort the whole exchange -- the retry
    # still sends a second datagram, exactly as a plain timeout would.
    class _CountingResetSocket(_ResetSocket):
        def __init__(self, exc):
            super().__init__(exc)
            self.sent = 0

        def sendto(self, *a):
            self.sent += 1

    session2 = _Session("192.0.2.1", 161, 0.2, 1)   # retries=1: 2 attempts
    sock2 = _CountingResetSocket(ConnectionResetError(10054, "forcibly closed"))
    session2.sock = sock2
    try:
        session2.request(packet, expect_request_id=1)
        check(False, "a reset on every attempt should still raise, eventually")
    except SnmpTimeout:
        check(sock2.sent == 2,
              f"a reset on attempt 1 still lets attempt 2 send "
              f"({sock2.sent} datagram(s) sent)")
    except SnmpError as exc:
        check(False, f"raised a generic SnmpError instead of SnmpTimeout ({exc})")

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

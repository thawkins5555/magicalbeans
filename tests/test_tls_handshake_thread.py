"""The TLS handshake must not run inside accept() on the single
serve_forever thread. Before the fix, one idle TCP connection to a TLS
listener stalled the handshake there indefinitely (no timeout applied),
so nobody else could be accepted -- no sign-in needed to cause it.

Plain script; the TLS half skips itself when this environment has no way
to mint a certificate. The plain-HTTP half needs no certificate and pins
that this fix left that path untouched.
"""
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("tls_handshake_")

from netpath.web import Service, WebServer

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")


def new_service(tag):
    d = os.path.join(TMPDIR, tag)
    os.makedirs(d, exist_ok=True)
    return Service(*[os.path.join(d, name + ".db") for name in DB_NAMES])


def plain_http_unaffected():
    """Control: no certfile means self.httpd.socket is never wrapped in
    ssl at all, so this path cannot have been touched by the fix."""
    service = new_service("plain")
    port = free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port,
                       certfile=None, keyfile=None)
    assert server.start(block=False), server.error
    try:
        check("plain HTTP: the listening socket is a plain socket, not TLS",
              not isinstance(server.httpd.socket, ssl.SSLSocket))
        idle = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            start = time.time()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/session")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            elapsed = time.time() - start
            check("plain HTTP: a second client is served promptly while an "
                  "idle connection sits open",
                  resp.status == 200 and elapsed < 2.0, (resp.status, elapsed))
        finally:
            idle.close()
    finally:
        server.stop()
        service.shutdown()


def tls_idle_connection_does_not_stall_accept():
    """The reproduction: a raw TCP connection to the TLS port that
    completes the three-way handshake and then never sends a single TLS
    byte -- exactly what used to hang the handshake inside accept() with
    no timeout, stalling every later connection behind it."""
    if not shutil.which("openssl"):
        print("SKIP: no openssl binary here, so no certificate to serve TLS with")
        return
    certfile = os.path.join(TMPDIR, "cert.pem")
    keyfile = os.path.join(TMPDIR, "key.pem")
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                       "-nodes", "-keyout", keyfile, "-out", certfile,
                       "-days", "2", "-subj", "/CN=127.0.0.1"],
                      check=True, capture_output=True, timeout=30)
    except Exception as exc:
        print(f"SKIP: could not mint a certificate here ({exc})")
        return

    service = new_service("tls")
    port = free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port,
                       certfile=certfile, keyfile=keyfile)
    assert server.start(block=False), server.error
    try:
        check("TLS: the listening socket is wrapped in ssl",
              isinstance(server.httpd.socket, ssl.SSLSocket))
        idle = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            start = time.time()
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            tls_sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
            try:
                tls_sock.sendall(b"GET /api/session HTTP/1.1\r\n"
                                 b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
                chunks = []
                while True:
                    data = tls_sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                elapsed = time.time() - start
                answer = b"".join(chunks)
                check("TLS: a real client's handshake and request complete "
                      "promptly with an idle non-TLS connection open on the "
                      "same listener (the defect stalled accept() here)",
                      answer.startswith(b"HTTP/1.1 200") and elapsed < 5.0,
                      (answer[:20], elapsed))
            finally:
                tls_sock.close()
        finally:
            idle.close()
    finally:
        server.stop()
        service.shutdown()


def main() -> int:
    plain_http_unaffected()
    tls_idle_connection_does_not_stall_accept()

    print()
    if FAILS:
        print(f"FAILURES: {len(FAILS)}")
        for item in FAILS:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

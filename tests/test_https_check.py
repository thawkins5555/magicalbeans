"""The per-destination HTTPS availability check (netpath/httpcheck.py) and
the worker that schedules it (monitor.HttpsChecker).

A loopback HTTPS server with a self-signed certificate stands in for the
destination's web page: 200, 503, a slow page, a redirect chain, a chain that
is too long, and an untrusted certificate with and without the per-destination
"accept untrusted certificate" opt-out. The certificate is written by openssl;
with no openssl on the machine there is nothing to serve TLS with, so the
suite exits 77 (SKIP) rather than failing.

Proxy environment variables are cleared first: urllib honours them, and a
proxy in front of 127.0.0.1 would be measuring the proxy rather than the check.
"""
import os
import subprocess
import ssl
import sys
import threading
import time

import _paths  # noqa: F401

for _var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
             "all_proxy", "ALL_PROXY"):
    os.environ.pop(_var, None)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from netpath import httpcheck                                        # noqa: E402
from netpath import monitor as monitor_mod                           # noqa: E402
from netpath.db import Database                                      # noqa: E402

TMPDIR = _paths.tmpdir("https_check_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def make_cert() -> tuple[str, str]:
    """A throwaway self-signed certificate, or ("", "") if none can be made."""
    cert = os.path.join(TMPDIR, "cert.pem")
    key = os.path.join(TMPDIR, "key.pem")
    base = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1",
            "-subj", "/CN=localhost"]
    for command in (base + ["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                    base):
        try:
            done = subprocess.run(command, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return "", ""
        if done.returncode == 0 and os.path.isfile(cert) and os.path.isfile(key):
            return cert, key
    return "", ""


CERT, KEY = make_cert()
if not CERT:
    print("SKIP: no openssl, so no certificate to serve TLS with")
    raise SystemExit(77)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):        # the suite's output is the log
        pass

    def _body(self, code: int, text: bytes = b"ok", location: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(text)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(text)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._body(200)
        elif path == "/broken":
            self._body(503, b"service unavailable")
        elif path == "/slow":
            time.sleep(3.0)
            self._body(200)
        elif path == "/big":
            self._body(200, b"x" * (httpcheck.MAX_BODY_BYTES * 2))
        elif path.startswith("/hop"):
            # /hop4 -> /hop3 -> ... -> /hop0 -> /
            step = int(path[len("/hop"):] or 0)
            self._body(302, b"moved", "/" if step <= 0 else f"/hop{step - 1}")
        elif path == "/downgrade":
            self._body(302, b"moved", "http://127.0.0.1:1/")
        else:
            self._body(404, b"no such path")


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT, KEY)
server.socket = context.wrap_socket(server.socket, server_side=True)
PORT = server.socket.getsockname()[1]
BASE = f"https://127.0.0.1:{PORT}"
threading.Thread(target=server.serve_forever, name="https-stub", daemon=True).start()

try:
    print("httpcheck.check: a page that answers")
    result = httpcheck.check(f"{BASE}/", timeout_s=5.0, insecure=True)
    check("200 is available", result.ok and result.status_code == 200, result)
    check("a latency is measured", (result.latency_ms or 0) > 0, result)
    check("no error text on a healthy page", result.error == "", result)

    print("httpcheck.check: a page that answers badly")
    result = httpcheck.check(f"{BASE}/broken", timeout_s=5.0, insecure=True)
    check("503 is unavailable, with the code in the reason",
          not result.ok and result.status_code == 503 and result.error == "HTTP 503",
          result)
    result = httpcheck.check(f"{BASE}/nope", timeout_s=5.0, insecure=True)
    check("404 is unavailable too", not result.ok and result.status_code == 404, result)

    print("httpcheck.check: the certificate")
    result = httpcheck.check(f"{BASE}/", timeout_s=5.0, insecure=False)
    check("a self-signed certificate is refused by default",
          not result.ok and result.error.startswith("TLS:"), result)
    check("...and the opt-out is what accepts it",
          httpcheck.check(f"{BASE}/", timeout_s=5.0, insecure=True).ok)

    print("httpcheck.check: timeouts")
    started = time.monotonic()
    result = httpcheck.check(f"{BASE}/slow", timeout_s=0.75, insecure=True)
    elapsed = time.monotonic() - started
    check("a page slower than the timeout is unavailable, reason 'timeout'",
          not result.ok and result.error == "timeout", result)
    check("...and the check returned near the timeout, not the page's own delay",
          elapsed < 2.5, elapsed)

    print("httpcheck.check: redirects")
    result = httpcheck.check(f"{BASE}/hop3", timeout_s=5.0, insecure=True)
    check("a chain of four redirects is followed to the 200",
          result.ok and result.status_code == 200, result)
    check("...and the final URL is reported", result.final_url.endswith("/"),
          result.final_url)
    result = httpcheck.check(f"{BASE}/hop8", timeout_s=5.0, insecure=True)
    check("a chain longer than five redirects is refused",
          not result.ok and "redirect" in result.error, result)
    result = httpcheck.check(f"{BASE}/downgrade", timeout_s=5.0, insecure=True)
    check("a redirect off HTTPS is refused",
          not result.ok and "non-HTTPS" in result.error, result)

    print("httpcheck.check: the body is capped, not swallowed whole")
    result = httpcheck.check(f"{BASE}/big", timeout_s=5.0, insecure=True)
    check("a page larger than the 64 KiB cap is still available",
          result.ok and result.status_code == 200, result)

    print("httpcheck.check: what never reaches the network")
    result = httpcheck.check("http://example.invalid/", timeout_s=1.0)
    check("a plain http:// URL is refused without a request",
          not result.ok and "https://" in result.error, result)
    result = httpcheck.check("", timeout_s=1.0)
    check("an empty URL is refused", not result.ok, result)
    result = httpcheck.check("https://no-such-host.invalid/", timeout_s=5.0)
    check("a name that does not resolve reports DNS",
          not result.ok and result.error.startswith("DNS:"), result)

    # ------------------------------------------------------------- the worker
    print("monitor.HttpsChecker: schedules, records and reports")
    db = Database(os.path.join(TMPDIR, "netpath.db"))
    with_page = db.add_target("10.80.0.1", label="has a page", interval_s=5)
    without = db.add_target("10.80.0.2", label="no page", interval_s=5)
    db.update_target(with_page, https_url=f"{BASE}/", https_insecure=1)

    calls = []
    real_check = monitor_mod.check_https

    def fake_check(url, timeout_s=10.0, insecure=False):
        calls.append((url, timeout_s, insecure))
        return httpcheck.HttpsResult(True, 200, 12.5, "", url)

    monitor_mod.check_https = fake_check
    checker = monitor_mod.HttpsChecker(db, log=None)
    try:
        checker.start()
        deadline = time.time() + 10
        while time.time() < deadline and not db.last_https_checks([with_page]):
            time.sleep(0.05)
        rows = db.last_https_checks([with_page, without])
        check("the destination with a URL got a check recorded",
              with_page in rows, list(rows))
        check("the destination without one did not", without not in rows, list(rows))
        check("the check ran against the stored URL and its opt-out",
              calls and calls[0][0] == f"{BASE}/" and calls[0][2] is True, calls)
        check("the recorded row carries the result",
              rows[with_page]["ok"] == 1 and rows[with_page]["status_code"] == 200
              and abs(rows[with_page]["latency_ms"] - 12.5) < 0.001,
              dict(rows[with_page]))
        check("status_text names how many pages are watched",
              "1 web page(s)" in checker.status_text(), checker.status_text())
    finally:
        checker.shutdown()
        monitor_mod.check_https = real_check

    print("netpath.db: the checks are the target's, and go with it")
    failing = httpcheck.HttpsResult(False, 503, 30.0, "HTTP 503", f"{BASE}/broken")
    db.record_https_check(with_page, failing)
    now = time.time()
    between = db.https_checks_between(with_page, now - 3600, now + 3600)
    check("https_checks_between returns the rows in the window",
          len(between) >= 2 and between[-1]["error"] == "HTTP 503", len(between))
    last = db.last_https_checks([with_page])[with_page]
    check("last_https_checks returns the newest row",
          last["ok"] == 0 and last["status_code"] == 503, dict(last))
    db.remove_target(with_page)
    check("removing the destination removes its checks",
          db.https_checks_between(with_page, 0, now + 3600) == [],
          db.https_checks_between(with_page, 0, now + 3600))

    print("netpath.db: prune drops checks past the retention window")
    kept = db.add_target("10.80.0.3", label="pruned", interval_s=60)
    db.record_https_check(kept, failing)
    import sqlite3
    conn = sqlite3.connect(db.path)
    conn.execute("UPDATE https_checks SET ts=? WHERE target_id=?",
                 (time.time() - 30 * 86400, kept))
    conn.commit()
    conn.close()
    db.prune(1.0)
    check("a check older than the retention is gone",
          db.https_checks_between(kept, 0, time.time() + 3600) == [],
          db.https_checks_between(kept, 0, time.time() + 3600))
    db.close()

    # ---------------------------------------------------------------------
    # A credential in the URL is refused, and stripped from one already stored
    #
    # `https://admin:pass@host/` could never be checked: http.client is handed
    # the whole netloc and answers "nonnumeric port: pass@host" -- with the
    # password in it. That sentence is stored in https_checks.error, served as
    # https_error to every netpath:read account and written to the event log
    # beside the URL. So the boundary refuses one, and the single funnel every
    # caller inside the checker goes through drops the userinfo from the URLs
    # that are already in the database.
    from netpath.monitor import https_url_for
    from netpath.web import api as web_api

    for _bad in ("https://admin:hunter2@switch.example/",
                 "https://admin@switch.example:8443/status"):
        try:
            web_api._validate_target_url(_bad)
            refused = ""
        except ValueError as exc:
            refused = str(exc)
        check("a web page URL carrying a credential is refused: %s" % _bad,
              refused == "https_url must not contain a username or password",
              refused)
    check("...while an ordinary one is still accepted",
          web_api._validate_target_url("https://switch.example:8443/status")
          == "https://switch.example:8443/status")

    class _Row(dict):
        def keys(self):
            return list(dict.keys(self))

    check("a stored credential never reaches the check or the log",
          https_url_for(_Row(https_url="https://admin:hunter2@switch.example:8443/x"))
          == "https://switch.example:8443/x",
          https_url_for(_Row(https_url="https://admin:hunter2@switch.example:8443/x")))
    check("...and a URL with no credential is handed on unchanged",
          https_url_for(_Row(https_url="https://switch.example/x"))
          == "https://switch.example/x")
    # ----------------------------------------------------------------------
    # This sweep used to be handed what was left of the traces deadline, and
    # _delete_batches checks that before its FIRST batch: on any netpath.db
    # busy enough to spend it, the table was swept zero rows a pass.
    db = Database(os.path.join(TMPDIR, "prune_budget.db"))
    starved = db.add_target("10.80.0.4", label="starved", interval_s=60)
    for _ in range(6):
        db.record_https_check(starved, failing)
    old_ts = time.time() - 30 * 86400
    conn = sqlite3.connect(db.path)
    conn.execute("UPDATE https_checks SET ts=?", (old_ts,))
    # Old traces too, so the traces sweep has work it will not finish.
    for n in range(6):
        conn.execute("INSERT INTO traces(target_id, started_ts, status,"
                     " reached) VALUES (?,?,?,1)", (starved, old_ts, "ok"))
    conn.commit()
    conn.close()

    before = db.https_checks_between(starved, 0, time.time() + 3600)
    check("the starved-sweep fixture has rows to prune", len(before) == 6,
          len(before))

    # budget_s=0: the state a busy install's traces sweep leaves behind.
    db.prune(1.0, budget_s=0.0)
    after = db.https_checks_between(starved, 0, time.time() + 3600)
    check("old https_checks are still swept when the traces sweep had no "
          "budget left to share", after == [], len(after))

    with sqlite3.connect(db.path) as trace_conn:
        left = trace_conn.execute(
            "SELECT COUNT(*) FROM traces WHERE started_ts < ?",
            (time.time() - 86400,)).fetchone()[0]
    check("...and the traces sweep really was starved, so this is the "
          "shared-deadline case and not a fixture that pruned everything",
          left == 6, left)
    check("...which prune() reports rather than hides",
          db.last_prune_incomplete is True, db.last_prune_incomplete)
    db.close()

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.shutdown()
    server.server_close()

raise SystemExit(1 if FAILS else 0)

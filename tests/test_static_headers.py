"""The static handler and the response path, driven over a real socket.

Nothing tested any of this before: not the security headers, not the 304
path, not the content type, not the traversal guard. Each of these was a
finding of the serving-layer review, and each is one request to pin.

  * a revalidated response (304) carries the same security headers as the
    200 it stands in for — it used to carry none, and revalidation is the
    steady state for every script and stylesheet;
  * a script is text/javascript with a charset whatever the host's registry
    says, because every response is `nosniff` and a script served as
    text/plain is refused outright;
  * gzip is sent when asked for, with Vary, and never when not asked for or
    when the client says `gzip;q=0`; JSON is compressed too;
  * the ETag is a content hash, so identical bytes revalidate as identical;
  * HEAD returns the headers of the GET with no body;
  * a path that escapes static/ is refused;
  * the sign-in page and everything it links load before there is a session.
"""

import gzip
import http.client
import json
import os
import sys

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("static_headers_")

from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=port, certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{port}")

failures = []
SECURITY = ("Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy")


def request(method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs, raw


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


def login():
    status, hdrs, raw = request("POST", "/api/login",
                                {"Content-Type": "application/json"},
                                json.dumps({"username": DEFAULT_USER,
                                            "password": DEFAULT_PASSWORD}).encode())
    assert status == 200, (status, raw)
    token = hdrs["set-cookie"].split("sw_session=")[1].split(";")[0]
    # The seeded account owes a password change before it may use the API.
    status, _, raw = request("POST", "/api/password",
                             {"Content-Type": "application/json",
                              "Cookie": f"sw_session={token}"},
                             json.dumps({"current_password": DEFAULT_PASSWORD,
                                         "new_password": "StaticSuitePass2026"}).encode())
    assert status == 200, (status, raw)
    status, hdrs, raw = request("POST", "/api/login",
                                {"Content-Type": "application/json"},
                                json.dumps({"username": DEFAULT_USER,
                                            "password": "StaticSuitePass2026"}).encode())
    assert status == 200, (status, raw)
    return hdrs["set-cookie"].split("sw_session=")[1].split(";")[0]


try:
    # -------------------------------------------------- before any session
    print("public files")
    for path in ("/login", "/tokens.css", "/app.css", "/login.js", "/favicon.svg"):
        status, hdrs, _ = request("GET", path)
        check(f"{path} is served before sign-in", status == 200, status)
    status, hdrs, _ = request("GET", "/app.js")
    check("/app.js is not served before sign-in", status == 302, status)

    token = login()
    auth = {"Cookie": f"sw_session={token}"}

    # ---------------------------------------------------------- the 200
    print("a script, identity")
    status, hdrs, body = request("GET", "/app.js", auth)
    check("200", status == 200, status)
    check("content type is text/javascript with charset",
          hdrs.get("content-type") == "text/javascript; charset=utf-8", hdrs.get("content-type"))
    check("no Content-Encoding when none was asked for", "content-encoding" not in hdrs)
    check("Vary: Accept-Encoding on a compressible type", hdrs.get("vary") == "Accept-Encoding")
    check("Cache-Control no-cache", hdrs.get("cache-control") == "no-cache")
    etag = hdrs.get("etag", "")
    check("ETag is a quoted 32-hex content hash", len(etag) == 34 and etag[0] == etag[-1] == '"'
          and all(c in "0123456789abcdef" for c in etag[1:-1]), etag)
    for name in SECURITY:
        check(f"{name} on the 200", name.lower() in hdrs)
    check("body length matches Content-Length", len(body) == int(hdrs["content-length"]))
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "netpath", "web", "static", "app.js"), "rb") as fh:
        check("body is the file on disk", body == fh.read())

    # ---------------------------------------------------------- the 304
    print("revalidation")
    status, hdrs304, body = request("GET", "/app.js", {**auth, "If-None-Match": etag})
    check("304 on a matching ETag", status == 304, status)
    check("304 has no body", body == b"")
    for name in SECURITY:
        check(f"{name} on the 304", name.lower() in hdrs304)
    check("304 repeats the ETag", hdrs304.get("etag") == etag)
    status, _, _ = request("GET", "/app.js", {**auth, "If-None-Match": f'W/{etag}, "other"'})
    check("304 on a weak, listed ETag", status == 304, status)
    status, _, _ = request("GET", "/app.js", {**auth, "If-None-Match": '"stale"'})
    check("200 on a stale ETag", status == 200, status)

    # ---------------------------------------------------------- versioned
    print("versioned URL")
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "netpath", "web", "static", "app.js"), "rb") as fh:
        on_disk = fh.read()
    status, hdrs_plain, body_plain = request("GET", "/app.js", auth)
    check("unversioned request unchanged: Cache-Control no-cache",
          hdrs_plain.get("cache-control") == "no-cache", hdrs_plain.get("cache-control"))
    check("unversioned request unchanged: ETag still present", "etag" in hdrs_plain)
    check("unversioned request unchanged: body matches the file on disk", body_plain == on_disk)
    status, hdrsv, bodyv = request("GET", "/app.js?v=4.47.0", auth)
    check("versioned 200", status == 200, status)
    check("versioned Cache-Control is public, max-age=31536000, immutable",
          hdrsv.get("cache-control") == "public, max-age=31536000, immutable",
          hdrsv.get("cache-control"))
    check("versioned body is byte-identical to the unversioned file", bodyv == body_plain)
    status, hdrsv2, _ = request("GET", "/app.js?v=4.47.0",
                                {**auth, "If-None-Match": etag})
    check("a versioned request ignores If-None-Match and still 200s",
          status == 200 and hdrsv2.get("cache-control") == "public, max-age=31536000, immutable",
          status)
    status, hdrs_html, _ = request("GET", "/?v=4.47.0", auth)
    check("index.html stays no-store even with ?v=", hdrs_html.get("cache-control") == "no-store",
          hdrs_html.get("cache-control"))

    # ---------------------------------------------------------- gzip
    print("compression")
    status, hdrs, body = request("GET", "/app.js", {**auth, "Accept-Encoding": "gzip, deflate"})
    check("gzip when asked", hdrs.get("content-encoding") == "gzip", hdrs.get("content-encoding"))
    check("Vary still present", hdrs.get("vary") == "Accept-Encoding")
    check("gzip body decodes to the file", gzip.decompress(body) == request("GET", "/app.js", auth)[2])
    check("gzip is smaller", len(body) < 0.4 * int(request("GET", "/app.js", auth)[1]["content-length"]),
          f"{len(body)} bytes")
    check("Content-Length is the compressed length", len(body) == int(hdrs["content-length"]))
    status, hdrs, _ = request("GET", "/app.js", {**auth, "Accept-Encoding": "gzip;q=0, identity"})
    check("identity when gzip is refused with q=0", "content-encoding" not in hdrs)
    status, hdrs, _ = request("GET", "/app.js", {**auth, "Accept-Encoding": "br"})
    check("identity when only brotli is offered", "content-encoding" not in hdrs)
    status, hdrs, _ = request("GET", "/favicon.svg", {**auth, "Accept-Encoding": "gzip"})
    check("a small file is not compressed", "content-encoding" not in hdrs
          if int(hdrs["content-length"]) < 1024 else hdrs.get("content-encoding") == "gzip",
          hdrs.get("content-length"))
    status, hdrs, body = request("GET", "/api/state", {**auth, "Accept-Encoding": "gzip"})
    check("JSON is compressed too", hdrs.get("content-encoding") == "gzip", hdrs.get("content-encoding"))
    payload = json.loads(gzip.decompress(body))
    check("and still parses", "session" in payload)
    check("API stays no-store", hdrs.get("cache-control") == "no-store")
    check("/api/state no longer carries the settings blocks",
          "nodes_settings" not in payload and "config_version" in payload,
          sorted(k for k in payload if k.endswith("_settings")))
    status, hdrs, body = request("GET", "/api/config", {**auth, "Accept-Encoding": "gzip"})
    config = json.loads(gzip.decompress(body))
    check("/api/config carries them, compressed",
          hdrs.get("content-encoding") == "gzip" and "nodes_settings" in config
          and config.get("config_version") == payload.get("config_version"))
    # What this guards is the settings blocks staying out of the poll payload,
    # so it is measured against the endpoint that does carry them rather than
    # against a fixed byte count: a bare ceiling drifts with whatever else the
    # platform reports (Windows adds a platform block, and 5,065 bytes there
    # failed a 5,000-byte limit while the blocks it exists to catch were absent).
    state_len = int(request("GET", "/api/state", auth)[1]["content-length"])
    config_len = int(request("GET", "/api/config", auth)[1]["content-length"])
    check("the live payload stays smaller than the settings payload, identity",
          state_len < config_len and state_len < 8000,
          f"state {state_len} vs config {config_len}")
    # A settings save moves the version, which is how the browser learns
    # to refetch config without polling it.
    before = config["config_version"]
    request("POST", "/api/settings", {**auth, "Content-Type": "application/json"},
            json.dumps({"scope": "syslog", "values": {}}).encode())
    after = json.loads(request("GET", "/api/state", auth)[2])["config_version"]
    check("a settings save bumps config_version", after == before + 1, f"{before} -> {after}")

    # ---------------------------------------------------------- keep-alive
    print("keep-alive")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/app.js", headers={**auth, "If-None-Match": etag})
    r1 = conn.getresponse(); r1.read()
    conn.request("GET", "/api/state", headers=auth)
    r2 = conn.getresponse(); raw2 = r2.read()
    conn.request("GET", "/tokens.css", headers=auth)
    r3 = conn.getresponse(); r3.read()
    conn.close()
    check("HTTP/1.1", r1.version == 11, r1.version)
    check("a 304, a JSON 200 and a static 200 on one connection",
          (r1.status, r2.status, r3.status) == (304, 200, 200), (r1.status, r2.status, r3.status))
    check("the JSON on the shared connection parses", "session" in json.loads(raw2))
    # A POST refused before its handler runs — here, the wrong content type,
    # a 415 — must not leave its body in the stream for the next request.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/api/nodes/devices", body=b'{"ip": "10.0.0.1"}',
                 headers={**auth, "Content-Type": "text/plain"})
    r1 = conn.getresponse(); r1.read()
    conn.request("GET", "/api/state", headers=auth)
    r2 = conn.getresponse(); raw2 = r2.read()
    conn.close()
    check("a refused POST is followed cleanly by a GET on the same connection",
          r1.status == 415 and r2.status == 200 and "session" in json.loads(raw2),
          (r1.status, r2.status))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/api/login", body=b'{"username": "x", "password": "y"}',
                 headers={"Content-Type": "application/json"})
    r1 = conn.getresponse(); r1.read()
    conn.request("GET", "/login", headers={})
    r2 = conn.getresponse(); r2.read()
    conn.close()
    check("a failed sign-in is followed cleanly by a GET on the same connection",
          r1.status in (401, 429) and r2.status == 200, (r1.status, r2.status))

    # ---------------------------------------------------------- HEAD
    print("HEAD")
    status, hdrs, body = request("HEAD", "/app.js", auth)
    check("HEAD 200 with no body", status == 200 and body == b"")
    check("HEAD carries the GET's Content-Length", int(hdrs["content-length"]) > 1000)
    check("HEAD carries the ETag", hdrs.get("etag") == etag)

    # ---------------------------------------------------------- shell
    print("html")
    status, hdrs, _ = request("GET", "/", auth)
    check("index.html is no-store", hdrs.get("cache-control") == "no-store")
    check("index.html has no ETag", "etag" not in hdrs)
    check("index.html is text/html with charset",
          hdrs.get("content-type") == "text/html; charset=utf-8", hdrs.get("content-type"))
    status, hdrs, _ = request("GET", "/tokens.css", auth)
    check("css type", hdrs.get("content-type") == "text/css; charset=utf-8", hdrs.get("content-type"))

    # ---------------------------------------------------------- traversal
    print("traversal")
    for path in ("/../server.py", "/static/../../auth.py", "/%2e%2e/server.py", "/vendor/../../api.py"):
        status, _, _ = request("GET", path, auth)
        check(f"{path} refused", status in (404, 400), status)
    status, _, _ = request("GET", "/vendor/xterm.css", auth)
    check("a real vendor file is served", status == 200, status)

    print("FAILED: " + ", ".join(failures) if failures else "ALL STATIC HANDLER ASSERTIONS PASSED")
finally:
    server.stop()
    service.shutdown()

sys.exit(1 if failures else 0)

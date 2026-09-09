"""The WEB button's device relay end to end: a real Service, a real
WebServer, and a stub "device" web server on loopback.

Proves what the relay promises. An `http` device is framed message by message
— its `Host:` points at the device, the addresses it names in its answers come
back on the relay's own origin, and bodies cross byte for byte — while an
`https` device, and anything the framer will not touch, is carried unread.
The destination comes from the device row and cannot be named by the caller; the listening port admits one address; the relay closes
on idle, on nobody connecting, on sign-out and when the permission goes away;
the caps and the port range refuse rather than fail; another account cannot
close your tunnel; and every open and close leaves a device event and an
audit row carrying byte counts and no content.

Everything binds 127.0.0.1, which is what keeps Windows Firewall out of it.
"""
import hashlib
import http.client
import http.server
import json
import os
import socket
import threading
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("web_relay_")

from netpath import permissions, webrelay
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label
          + (f"  {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


# ------------------------------------------------------------ a device, sort of

BODY = (b"<html><body>SappiWhere stub device management page. "
        + b"x" * 5000 + b"</body></html>")


class StubDeviceHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):                                     # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("X-Stub-Path", self.path)
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):                         # keep the run quiet
        pass


stub = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StubDeviceHandler)
stub.daemon_threads = True
stub_port = stub.server_address[1]
threading.Thread(target=stub.serve_forever, daemon=True).start()
print(f"stub device on 127.0.0.1:{stub_port}")

# ------------------------------------------------------------------- the app

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()
# Relays follow the UI's own bind address (webrelay.relay_bind_host), so
# pinning the UI here is what keeps every relay on loopback — and a loopback
# bind is the one Windows Firewall does not prompt for. The range is left
# ephemeral except in the exhaustion section, which sets its own.
service.settings["web_host"] = "127.0.0.1"
service.settings["web_relay_port_range"] = "0"

web_port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{web_port}")

ADMIN_PASSWORD = "RelaySuiteAdmin2026"


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    status = response.status
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return status, payload, cookie


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    status, payload, cookie = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return cookie.split("sw_session=")[1].split(";")[0]


def make_user(username, grants, password="RelaySuiteUser2026"):
    from netpath.auth import hash_password
    service.app_db.add_user(username, hash_password(password), must_change=False)
    service.app_db.set_permissions(username, grants)
    return login(username, password)


def fetch_through(port, path="/", timeout=15.0):
    """One raw HTTP/1.1 GET straight at a relay port, read to EOF. Deliberately
    not http.client: what is under test is that the bytes cross unaltered, so
    the test writes the request itself."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                     f"Connection: close\r\n\r\n".encode("ascii"))
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


# The server and the device are both on loopback in this suite, so the relay
# is opened naming a hostname for the server: telling "the address the browser
# used" apart from "the device's own address" is the whole point of the fix.
SERVER_NAME = "sappiwhere.example"

raw_devices = []


def raw_device(handler):
    """A stub device that speaks bytes: `handler(conn)` gets each accepted
    connection and writes whatever the test needs to see carried."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    raw_devices.append(srv)

    def serve(conn):
        try:
            handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def accept():
        while True:
            try:
                conn, _addr = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return srv.getsockname()[1]


def read_head(sock, buf):
    """One complete message head off a socket, taken out of `buf`."""
    while buf.find(b"\r\n\r\n") == -1:
        data = sock.recv(65536)
        if not data:
            return b""
        buf += data
    cut = buf.find(b"\r\n\r\n")
    head = bytes(buf[:cut + 4])
    del buf[:cut + 4]
    return head


def read_body(sock, buf, count):
    while len(buf) < count:
        data = sock.recv(65536)
        if not data:
            break
        buf += data
    body = bytes(buf[:count])
    del buf[:count]
    return body


def read_line(sock, buf):
    while buf.find(b"\r\n") == -1:
        data = sock.recv(65536)
        if not data:
            return b""
        buf += data
    cut = buf.find(b"\r\n")
    line = bytes(buf[:cut])
    del buf[:cut + 2]
    return line


def read_chunked(sock, buf):
    body = bytearray()
    while True:
        size = int(read_line(sock, buf).split(b";")[0] or b"0", 16)
        if size == 0:
            read_line(sock, buf)
            return bytes(body)
        body += read_body(sock, buf, size)
        read_line(sock, buf)


def headers(head, name):
    wanted = name.lower().encode() + b":"
    return [line.split(b":", 1)[1].strip().decode("latin-1")
            for line in head.split(b"\r\n")[1:]
            if line.lower().startswith(wanted)]


def read_all(sock):
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            return b"".join(chunks)
        chunks.append(data)


def wait_until(predicate, seconds):
    """True as soon as `predicate` holds, False when `seconds` run out. Every
    caller passes twice the patched constant it is waiting on, so a loaded
    machine does not fail a timing assertion that is really about ordering."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


device_id = None
try:
    token = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # ------------------------------------------------- the device's web fields
    print("device web fields")
    status, payload, _ = call("POST", "/api/nodes/devices",
                              {"ip": "127.0.0.1", "name": "stub-device",
                               "web_scheme": "http", "web_port": stub_port},
                              token=token)
    check("a device can be added with its web scheme and port", status == 200,
          (status, payload))
    device_id = payload.get("id")

    status, payload, _ = call("GET", f"/api/nodes/devices/{device_id}", token=token)
    device_json = payload.get("device", payload)
    check("the fields round-trip through the device JSON",
          device_json.get("web_scheme") == "http"
          and device_json.get("web_port") == stub_port,
          device_json)
    check("and the JSON says which port the relay will dial",
          device_json.get("web_port_effective") == stub_port,
          device_json.get("web_port_effective"))

    for bad in (0, 70000, "ftp"):
        field = "web_scheme" if bad == "ftp" else "web_port"
        # 0 is the one that is not a refusal: it is how a form clears the
        # override and puts the device back on its scheme's default port.
        status, payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                                  {field: bad}, token=token)
        expected = 200 if bad == 0 else 400
        check(f"{field}={bad!r} is answered {expected}", status == expected,
              (status, payload))
    status, _payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                               {"web_port": stub_port}, token=token)
    assert status == 200

    # ---------------------------------------------------------- opening one
    print("opening a relay")
    status, relay, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    check("POST /api/web/devices/<id>/relay is answered 200", status == 200,
          (status, relay))
    check("its URL names the host the browser reached this server on",
          str(relay.get("url", "")).startswith(f"http://127.0.0.1:"), relay.get("url"))
    check("the session id starts with 'r', so _route cannot turn it into an int",
          str(relay.get("session_id", "")).startswith("r"), relay.get("session_id"))
    check("the relay names the device's port, not the browser's",
          relay.get("device_port") == stub_port, relay.get("device_port"))
    check("and the one address it will admit",
          relay.get("client_ip") == "127.0.0.1", relay.get("client_ip"))
    relay_port = relay["port"]
    check("the URL's port is the relay's port",
          f":{relay_port}/" in relay["url"], relay["url"])

    # ------------------------------------------------------ bytes across it
    print("carrying bytes")
    answer = fetch_through(relay_port)
    check("a GET through the relay comes back byte for byte",
          BODY in answer and b"200 OK" in answer.split(b"\r\n")[0],
          answer[:80])
    check("and the device saw the path it was sent",
          b"X-Stub-Path: /" in answer, answer[:200])

    results = {}

    def concurrent(index):
        try:
            results[index] = fetch_through(relay_port, f"/page-{index}")
        except Exception as exc:                          # recorded, not raised
            results[index] = repr(exc).encode()

    threads = [threading.Thread(target=concurrent, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    check("six connections at once are all answered in full",
          len(results) == 6 and all(BODY in body for body in results.values()),
          {i: body[:60] for i, body in results.items()})
    check("each one reached its own path",
          all(f"X-Stub-Path: /page-{i}".encode() in body
              for i, body in results.items()))

    live = service.web_relays.get(relay["session_id"])
    check("the byte counters moved in both directions",
          live is not None and live.info()["bytes_to_device"] > 0
          and live.info()["bytes_from_device"] > len(BODY),
          live.info() if live else None)

    # ------------------------------------------------------------- listing
    status, payload, _ = call("GET", "/api/web/relays", token=token)
    check("GET /api/web/relays lists it", status == 200
          and any(row["session_id"] == relay["session_id"]
                  for row in payload.get("relays", [])),
          (status, payload))

    # ------------------------------------------------------- who is admitted
    print("the address gate")
    check("_admit takes the operator's own address",
          live._admit(("127.0.0.1", 51000)))
    check("_admit takes it through an IPv4-mapped IPv6 peer, like every other "
          "allow list here", live._admit(("::ffff:127.0.0.1", 51000)))
    check("_admit refuses any other address",
          not live._admit(("10.4.4.4", 51000)))
    before = len([row for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"]) if "refused" in row["detail"]])
    live._audit_refusal(("10.4.4.4", 51000))
    live._audit_refusal(("10.4.4.5", 51000))
    after = [row for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"]) if "refused" in row["detail"]]
    check("a refused source is audited once per relay, not once per attempt",
          len(after) - before == 1, [row["detail"] for row in after])

    # ------------------------------------------------------------- closing
    print("closing")
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{relay['session_id']}", {}, token=token)
    check("DELETE closes it", status == 200, (status, payload))
    check("and it is gone from the registry",
          service.web_relays.get(relay["session_id"]) is None)
    refused = None
    try:
        fetch_through(relay_port, timeout=3)
    except OSError as exc:
        refused = exc
    check("the port stops answering", refused is not None, refused)

    events = [row["detail"] for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"])]
    check("the device's own event list carries the open and the close",
          any("opened" in detail for detail in events)
          and any("closed" in detail for detail in events), events)
    check("the close event carries byte counts and no content",
          any("bytes to the device" in detail for detail in events)
          and not any(b"SappiWhere stub" in detail.encode() for detail in events),
          events)

    # ----------------------------------------------------------- the audit log
    status, payload, _ = call("GET", "/api/audit?limit=500", token=token)
    actions = [row.get("action") for row in payload.get("events", [])]
    check("web.relay.open and web.relay.close are both in the audit log",
          "web.relay.open" in actions and "web.relay.close" in actions,
          sorted(set(a for a in actions if a and a.startswith("web."))))

    # ------------------------------------------------- what the relay carries
    print("reading the headers")

    def relay_to(port, scheme="http"):
        """A relay pointed at a raw stub. Opened on the registry rather than
        through the API so the test can say which name the browser reached
        this server on, which is the one thing loopback cannot show."""
        status, _payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                                   {"web_scheme": scheme, "web_port": port},
                                   token=token)
        assert status == 200
        return service.web_relays.open(device_id, DEFAULT_USER, "127.0.0.1",
                                       host_header=f"{SERVER_NAME}:{web_port}")

    # The reported bug: a device rebuilding its redirect from the Host it was
    # sent, which named this server and had dropped the relay's port.
    box = {}
    seen = []

    def redirector(conn):
        buf = bytearray()
        while True:
            head = read_head(conn, buf)
            if not head:
                return
            seen.append(head)
            path = head.split(b" ")[1]
            where = (f"http://{SERVER_NAME}/home.asp" if path == b"/one"
                     else f"http://127.0.0.1:{box['port']}/status.asp")
            conn.sendall(
                f"HTTP/1.1 302 Found\r\n"
                f"Location: {where}\r\n"
                f"Content-Location: http://{SERVER_NAME}/index.asp\r\n"
                f"Refresh: 5; url=http://127.0.0.1:{box['port']}/reboot.asp\r\n"
                f"Set-Cookie: sid=abc; Domain={SERVER_NAME}; Path=/\r\n"
                f"Set-Cookie: dev=xyz; Domain=127.0.0.1; Path=/\r\n"
                f"X-Kept: http://elsewhere.example/untouched\r\n"
                f"Content-Length: 0\r\n\r\n".encode("latin-1"))

    box["port"] = raw_device(redirector)
    relay = relay_to(box["port"])
    origin = f"http://{SERVER_NAME}:{relay['port']}"
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    buf = bytearray()
    heads = []
    for path in ("/one", "/two"):
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}:"
                     f"{relay['port']}\r\n\r\n".encode("ascii"))
        heads.append(read_head(sock, buf))
    sock.close()

    check("the device is asked for its own address, not this server's name",
          headers(seen[0], "Host") == [f"127.0.0.1:{box['port']}"],
          headers(seen[0], "Host"))
    check("a Location naming this server comes back on the relay's origin",
          headers(heads[0], "Location") == [f"{origin}/home.asp"],
          headers(heads[0], "Location"))
    check("a Location naming the device's own address does too",
          headers(heads[1], "Location") == [f"{origin}/status.asp"],
          headers(heads[1], "Location"))
    check("both requests on the one keep-alive connection were rewritten",
          len(seen) == 2 and all(headers(head, "Host")
                                 == [f"127.0.0.1:{box['port']}"]
                                 for head in seen), len(seen))
    check("Content-Location is rewritten too",
          headers(heads[0], "Content-Location") == [f"{origin}/index.asp"],
          headers(heads[0], "Content-Location"))
    check("and Refresh, without disturbing its delay",
          headers(heads[0], "Refresh") == [f"5; url={origin}/reboot.asp"],
          headers(heads[0], "Refresh"))
    check("a cookie scoped to either name is scoped to nothing, so the "
          "browser keeps it on the relay's origin",
          headers(heads[0], "Set-Cookie")
          == ["sid=abc; Path=/", "dev=xyz; Path=/"],
          headers(heads[0], "Set-Cookie"))
    check("a header naming anywhere else is left exactly as it was",
          headers(heads[0], "X-Kept") == ["http://elsewhere.example/untouched"],
          headers(heads[0], "X-Kept"))
    service.web_relays.close(relay["session_id"], "test teardown")

    # The whole request head names the device, not the relay. Before 5.4 the
    # browser's Host, Origin and Referer all named the relay and agreed there;
    # moving Host alone left them disagreeing at the device, which is what an
    # embedded UI checks before it accepts a login POST.
    echoed = []

    def echo_head(conn):
        buf = bytearray()
        while True:
            head = read_head(conn, buf)
            if not head:
                return
            length = headers(head, "Content-Length")
            if length:
                read_body(conn, buf, int(length[0]))
            echoed.append(head)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    echo_port = raw_device(echo_head)
    relay = relay_to(echo_port)
    device_origin = f"http://127.0.0.1:{echo_port}"
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    buf = bytearray()
    sock.sendall(
        f"POST /login.asp HTTP/1.1\r\nHost: {SERVER_NAME}:{relay['port']}\r\n"
        f"Origin: http://{SERVER_NAME}:{relay['port']}\r\n"
        f"Referer: http://{SERVER_NAME}:{relay['port']}/login.asp\r\n"
        f"Content-Length: 3\r\n\r\nabc".encode("ascii"))
    read_head(sock, buf)
    sock.sendall(f"GET http://{SERVER_NAME}:{relay['port']}/abs HTTP/1.1\r\n"
                 f"Host: {SERVER_NAME}:{relay['port']}\r\n\r\n".encode("ascii"))
    read_head(sock, buf)
    sock.close()
    check("Origin is pointed at the device, and carries no path",
          headers(echoed[0], "Origin") == [device_origin],
          headers(echoed[0], "Origin"))
    check("Referer is too, path and all",
          headers(echoed[0], "Referer") == [f"{device_origin}/login.asp"],
          headers(echoed[0], "Referer"))
    check("so Host, Origin and Referer name one authority at the device",
          headers(echoed[0], "Host") == [f"127.0.0.1:{echo_port}"]
          and {value.split("//")[-1].split("/")[0]
               for value in headers(echoed[0], "Origin")
               + headers(echoed[0], "Referer")} == {f"127.0.0.1:{echo_port}"},
          echoed[0])
    check("and a request target written out in full moves with them",
          echoed[1].split(b" ")[1] == f"{device_origin}/abs".encode("ascii"),
          echoed[1].split(b"\r\n")[0])
    service.web_relays.close(relay["session_id"], "test teardown")

    # The device those three are for: it refuses a POST whose Origin is not
    # its own Host.
    def picky(conn):
        buf = bytearray()
        while True:
            head = read_head(conn, buf)
            if not head:
                return
            length = headers(head, "Content-Length")
            if length:
                read_body(conn, buf, int(length[0]))
            agrees = ((headers(head, "Origin") or [""])[0]
                      == "http://" + (headers(head, "Host") or [""])[0])
            conn.sendall((b"HTTP/1.1 200 OK" if agrees
                          else b"HTTP/1.1 403 Forbidden")
                         + b"\r\nContent-Length: 0\r\n\r\n")

    relay = relay_to(raw_device(picky))
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    buf = bytearray()
    sock.sendall(
        f"POST /login.asp HTTP/1.1\r\nHost: {SERVER_NAME}:{relay['port']}\r\n"
        f"Origin: http://{SERVER_NAME}:{relay['port']}\r\n"
        f"Content-Length: 3\r\n\r\nabc".encode("ascii"))
    posted = read_head(sock, buf)
    sock.close()
    check("a device that compares Origin against Host accepts the login POST",
          posted.startswith(b"HTTP/1.1 200"), posted.split(b"\r\n")[0])
    service.web_relays.close(relay["session_id"], "test teardown")

    # A device on plain HTTP sending the browser to https is saying its UI is
    # somewhere this tunnel does not go. Rewriting that onto the relay's own
    # http origin would only bring the browser back here, and round again.
    https_box = {}

    def to_https(conn):
        buf = bytearray()
        while True:
            head = read_head(conn, buf)
            if not head:
                return
            conn.sendall(
                f"HTTP/1.1 302 Found\r\n"
                f"Location: https://127.0.0.1:{https_box['port']}/\r\n"
                f"Content-Length: 0\r\n\r\n".encode("latin-1"))

    https_box["port"] = raw_device(to_https)
    relay = relay_to(https_box["port"])
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    buf = bytearray()
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {SERVER_NAME}:{relay['port']}"
                 f"\r\n\r\n".encode("ascii"))
    bounced = read_head(sock, buf)
    sock.close()
    check("a Location on a scheme this tunnel does not carry is left naming "
          "the device, not turned into a redirect back into the tunnel",
          headers(bounced, "Location")
          == [f"https://127.0.0.1:{https_box['port']}/"],
          headers(bounced, "Location"))
    service.web_relays.close(relay["session_id"], "test teardown")

    # Content-Length and Transfer-Encoding together are two framings that can
    # disagree; which one the device honours is its own business, so the head
    # is not read and nothing in it is rewritten.
    BOTH = (f"HTTP/1.1 200 OK\r\nLocation: http://{SERVER_NAME}/home.asp\r\n"
            f"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"hello").encode("latin-1")

    def two_framings(conn):
        buf = bytearray()
        if read_head(conn, buf):
            conn.sendall(BOTH)

    relay = relay_to(raw_device(two_framings))
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {SERVER_NAME}:{relay['port']}\r\n"
                 f"Connection: close\r\n\r\n".encode("ascii"))
    both_answer = read_all(sock)
    sock.close()
    check("a head carrying both framings goes blind rather than picking one, "
          "so it crosses exactly as the device wrote it",
          both_answer == BOTH, both_answer[:160])
    service.web_relays.close(relay["session_id"], "test teardown")

    # Bodies: streamed, never held whole, never altered.
    PAYLOAD = os.urandom(300 * 1024)
    DIGEST = hashlib.sha256(PAYLOAD).hexdigest()

    def bulk(conn):
        buf = bytearray()
        while True:
            head = read_head(conn, buf)
            if not head:
                return
            common = (f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream"
                      f"\r\nLocation: http://{SERVER_NAME}/home.asp\r\n")
            if head.split(b" ")[1] == b"/plain":
                conn.sendall((common + f"Content-Length: {len(PAYLOAD)}\r\n\r\n")
                             .encode("latin-1") + PAYLOAD)
            else:
                conn.sendall((common + "Transfer-Encoding: chunked\r\n\r\n")
                             .encode("latin-1"))
                for start in range(0, len(PAYLOAD), 7000):
                    piece = PAYLOAD[start:start + 7000]
                    conn.sendall(b"%x\r\n" % len(piece) + piece + b"\r\n")
                conn.sendall(b"0\r\n\r\n")

    relay = relay_to(raw_device(bulk))
    origin = f"http://{SERVER_NAME}:{relay['port']}"
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=30)
    buf = bytearray()
    sock.sendall(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")
    plain_head = read_head(sock, buf)
    plain = read_body(sock, buf, int(headers(plain_head, "Content-Length")[0]))
    sock.sendall(b"GET /chunked HTTP/1.1\r\nHost: x\r\n\r\n")
    chunked_head = read_head(sock, buf)
    chunked = read_chunked(sock, buf)
    sock.close()
    check("a counted body crosses byte for byte",
          hashlib.sha256(plain).hexdigest() == DIGEST, len(plain))
    check("and a chunked one does as well",
          hashlib.sha256(chunked).hexdigest() == DIGEST, len(chunked))
    check("both of their heads were rewritten on the way past",
          headers(plain_head, "Location") == [f"{origin}/home.asp"]
          and headers(chunked_head, "Location") == [f"{origin}/home.asp"],
          (headers(plain_head, "Location"), headers(chunked_head, "Location")))
    service.web_relays.close(relay["session_id"], "test teardown")

    # An upgrade: nothing after the 101 is HTTP, so nothing after it is read.
    UPGRADE = (b"\x81\x7e\x0f\xa0GET /ws HTTP/1.1\r\nHost: "
               + SERVER_NAME.encode() + b"\r\n\r\n" + os.urandom(4000))
    upgraded = []

    def websocket(conn):
        buf = bytearray()
        if not read_head(conn, buf):
            return
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        got = bytearray(buf)
        while len(got) < len(UPGRADE):
            data = conn.recv(65536)
            if not data:
                break
            got += data
        upgraded.append(bytes(got))
        conn.sendall(bytes(got))

    relay = relay_to(raw_device(websocket))
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    buf = bytearray()
    sock.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                 b"Connection: Upgrade\r\n\r\n")
    upgrade_head = read_head(sock, buf)
    sock.sendall(UPGRADE)
    echoed = read_body(sock, buf, len(UPGRADE))
    sock.close()
    check("a 101 crosses as the device wrote it",
          upgrade_head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"),
          upgrade_head[:60])
    check("and what follows it is carried unread in both directions",
          upgraded == [UPGRADE] and echoed == UPGRADE,
          (len(upgraded), len(echoed)))
    service.web_relays.close(relay["session_id"], "test teardown")

    # A start line that is not one: the byte pump is the floor.
    GARBLE = (b"NOT-HTTP AT ALL\r\n\r\n" + b"\x00\x01\x02" * 400
              + b"\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")

    def garbler(conn):
        buf = bytearray()
        if read_head(conn, buf):
            conn.sendall(GARBLE)

    relay = relay_to(raw_device(garbler))
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check("an unparseable status line is carried whole, not corrupted or "
          "dropped", read_all(sock) == GARBLE)
    sock.close()
    service.web_relays.close(relay["session_id"], "test teardown")

    # https: the blind tunnel, exactly as it was.
    tls_seen = []

    def unread(conn):
        buf = bytearray()
        head = read_head(conn, buf)
        if not head:
            return
        tls_seen.append(head)
        conn.sendall(f"HTTP/1.1 302 Found\r\nLocation: http://{SERVER_NAME}"
                     f"/home.asp\r\nSet-Cookie: sid=abc; Domain={SERVER_NAME}"
                     f"\r\nContent-Length: 0\r\n\r\n".encode("latin-1"))

    relay = relay_to(raw_device(unread), scheme="https")
    check("an https relay still hands out an https URL",
          relay["url"] == f"https://{SERVER_NAME}:{relay['port']}/", relay["url"])
    sock = socket.create_connection(("127.0.0.1", relay["port"]), timeout=15)
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\n"
                 f"Connection: close\r\n\r\n".encode("ascii"))
    tls_answer = read_all(sock)
    sock.close()
    check("an https device is still sent the browser's own Host, unread",
          headers(tls_seen[0], "Host") == [SERVER_NAME], tls_seen)
    check("and its answer comes back untouched, tunnel and all",
          headers(tls_answer, "Location") == [f"http://{SERVER_NAME}/home.asp"]
          and headers(tls_answer, "Set-Cookie")
          == [f"sid=abc; Domain={SERVER_NAME}"], tls_answer[:200])
    service.web_relays.close(relay["session_id"], "test teardown")

    status, _payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                               {"web_scheme": "http", "web_port": stub_port},
                               token=token)
    assert status == 200

    # ------------------------------------------------------------- the caps
    print("the caps")
    saved = (webrelay.MAX_SESSIONS, webrelay.MAX_SESSIONS_PER_USER)
    webrelay.MAX_SESSIONS_PER_USER = 2
    opened = []
    for _ in range(2):
        status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                                  {}, token=token)
        assert status == 200, (status, payload)
        opened.append(payload["session_id"])
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("a third relay for one account is refused 400", status == 400,
          (status, payload))
    check("and the refusal says which cap was reached",
          "2 web tunnels" in str(payload.get("error", "")), payload)

    webrelay.MAX_SESSIONS_PER_USER = 8
    webrelay.MAX_SESSIONS = len(opened)
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("the application-wide cap is refused 400 too", status == 400,
          (status, payload))
    webrelay.MAX_SESSIONS, webrelay.MAX_SESSIONS_PER_USER = saved
    for session_id in opened:
        service.web_relays.close(session_id, "test teardown")

    # --------------------------------------------------- a spent port range
    print("a spent port range")
    single = free_tcp_port()
    service.settings["web_relay_port_range"] = f"{single}-{single}"
    status, first, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    check("a one-port range still opens the first relay",
          status == 200 and first.get("port") == single, (status, first))
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("and refuses the second with 400, naming the range", status == 400
          and str(single) in str(payload.get("error", "")), (status, payload))
    service.web_relays.close(first["session_id"], "test teardown")
    service.settings["web_relay_port_range"] = "0"

    # -------------------------------------------------- what closes a relay
    print("what closes a relay")
    saved_window = webrelay.FIRST_CONNECT_WINDOW_S
    webrelay.FIRST_CONNECT_WINDOW_S = 1
    status, unused, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=token)
    assert status == 200, (status, unused)
    check("a relay nobody connects to closes inside its first-connect window",
          wait_until(lambda: service.web_relays.get(unused["session_id"]) is None,
                     2 * webrelay.FIRST_CONNECT_WINDOW_S + 2))
    webrelay.FIRST_CONNECT_WINDOW_S = saved_window

    saved_idle = webrelay.IDLE_TIMEOUT_S
    webrelay.IDLE_TIMEOUT_S = 1
    status, idler, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    assert status == 200, (status, idler)
    fetch_through(idler["port"])                 # so the idle clock, not the
    check("a relay with no traffic closes on the idle timeout",  # window, applies
          wait_until(lambda: service.web_relays.get(idler["session_id"]) is None,
                     2 * webrelay.IDLE_TIMEOUT_S + 3))
    webrelay.IDLE_TIMEOUT_S = saved_idle

    saved_ticks = webrelay.PERMISSION_EVERY_TICKS
    webrelay.PERMISSION_EVERY_TICKS = 1
    revoked_token = make_user("revokee", {"nodes": "read", "web": "write"})
    status, doomed, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=revoked_token)
    check("an account holding web:write can open one", status == 200,
          (status, doomed))
    service.app_db.set_permissions("revokee", {"nodes": "read"})
    check("revoking the permission closes the relay within a few ticks",
          wait_until(lambda: service.web_relays.get(doomed["session_id"]) is None,
                     2 * webrelay.PERMISSION_EVERY_TICKS + 4))
    webrelay.PERMISSION_EVERY_TICKS = saved_ticks

    signed_out = make_user("signout", {"nodes": "read", "web": "write"})
    status, orphan, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=signed_out)
    assert status == 200, (status, orphan)
    call("POST", "/api/logout", {}, token=signed_out)
    check("signing out takes the relay with it",
          wait_until(lambda: service.web_relays.get(orphan["session_id"]) is None, 6))

    # -------------------------------------------------------------- the gates
    print("the gates")
    nodes_only = make_user("nodesonly", {"nodes": "write"})
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=nodes_only)
    check("nodes:write with no web grant is refused 403", status == 403,
          (status, payload))
    status, payload, _ = call("GET", "/api/web/relays", token=nodes_only)
    check("and cannot list relays either", status == 403, (status, payload))

    other = make_user("otherweb", {"nodes": "read", "web": "write"})
    status, theirs, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=other)
    assert status == 200, (status, theirs)
    intruder = make_user("intruder", {"nodes": "read", "web": "write"})
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{theirs['session_id']}", {}, token=intruder)
    check("another account's DELETE is refused 403", status == 403,
          (status, payload))
    check("and the relay is still open",
          service.web_relays.get(theirs["session_id"]) is not None)
    status, payload, _ = call("GET", "/api/web/relays", token=intruder)
    check("a non-administrator's list shows only their own relays",
          all(row["username"] == "intruder"
              for row in payload.get("relays", [])), payload)
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{theirs['session_id']}", {}, token=token)
    check("an administrator may close it", status == 200, (status, payload))

    # --------------------------------------------------------------- shutdown
    print("shutdown")
    status, lingering, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                                {}, token=token)
    assert status == 200, (status, lingering)
    held = socket.create_connection(("127.0.0.1", lingering["port"]), timeout=10)
    held.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    held.recv(64)                       # a connection still open and idle
    started = time.time()
    service.web_relays.shutdown()
    elapsed = time.time() - started
    check("shutdown() ends every relay inside its budget",
          elapsed <= 2 * webrelay.SHUTDOWN_BUDGET_S and service.web_relays.count == 0,
          f"{elapsed:.2f}s, {service.web_relays.count} left")
    try:
        held.close()
    except OSError:
        pass

    print("FAILED: " + ", ".join(failures) if failures
          else "ALL WEB RELAY ASSERTIONS PASSED")
finally:
    for _srv in raw_devices:
        try:
            _srv.close()
        except OSError:
            pass
    server.stop()
    stub.shutdown()
    service.shutdown()

if failures:
    raise SystemExit(1)

"""The web server.

Standard library only: `http.server` with a threading mixin, plus `ssl` when a
certificate is configured. That keeps the deployment to "install PySide6 or
don't" rather than pulling a web framework and its dependency tree onto a
machine whose job is watching the network.

There is no authentication yet. Bind to an interface you trust, or to
127.0.0.1 and reach it through something that does authenticate, until the
TACACS work lands.
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from collections import deque

from . import api
from .service import Service

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# (method, compiled path, handler). A trailing group is passed to the handler.
ROUTES = [
    ("POST", r"^/api/login$", api.post_login),
    ("POST", r"^/api/logout$", api.post_logout),
    ("POST", r"^/api/heartbeat$", api.post_heartbeat),
    ("GET", r"^/api/session$", api.get_session),
    ("GET", r"^/api/users$", api.get_users),
    ("POST", r"^/api/users$", api.post_user),
    ("DELETE", r"^/api/users$", api.delete_user),
    ("POST", r"^/api/password$", api.post_password),
    ("GET", r"^/api/state$", api.get_state),
    ("GET", r"^/api/netpath/targets$", api.get_targets),
    ("POST", r"^/api/netpath/targets$", api.post_target),
    ("PUT", r"^/api/netpath/targets/(\d+)$", api.put_target),
    ("DELETE", r"^/api/netpath/targets/(\d+)$", api.delete_target),
    ("POST", r"^/api/netpath/targets/(\d+)/trace$", api.trace_now),
    ("GET", r"^/api/netpath/timeline$", api.get_timeline),
    ("GET", r"^/api/netpath/topology$", api.get_topology),
    ("GET", r"^/api/netflow/overview$", api.get_flow_overview),
    ("GET", r"^/api/netflow/records$", api.get_flow_records),
    ("POST", r"^/api/netflow/collector$", api.post_collector),
    ("POST", r"^/api/netflow/testpacket$", api.post_test_packet),
    ("GET", r"^/api/syslog/overview$", api.get_syslog_overview),
    ("GET", r"^/api/syslog/search$", api.get_syslog_search),
    ("POST", r"^/api/syslog/collector$", api.post_syslog_collector),
    ("POST", r"^/api/syslog/test$", api.post_syslog_test),
    ("GET", r"^/api/ipam/search$", api.get_ipam_search),
    ("GET", r"^/api/ipam/subnets$", api.get_ipam_subnets),
    ("POST", r"^/api/ipam/subnets$", api.post_ipam_subnet),
    ("PUT", r"^/api/ipam/subnets/(\d+)$", api.put_ipam_subnet),
    ("DELETE", r"^/api/ipam/subnets/(\d+)$", api.delete_ipam_subnet),
    ("POST", r"^/api/ipam/subnets/(\d+)/scan$", api.post_ipam_subnet_scan),
    ("POST", r"^/api/ipam/subnets/(\d+)/clear$", api.post_ipam_subnet_clear),
    ("GET", r"^/api/ipam/hosts$", api.get_ipam_hosts),
    ("GET", r"^/api/ipam/conflicts$", api.get_ipam_conflicts),
    ("POST", r"^/api/ipam/conflicts/(\d+)/resolve$", api.post_ipam_conflict_resolve),
    ("GET", r"^/api/ipam/dhcp/servers$", api.get_ipam_dhcp_servers),
    ("POST", r"^/api/ipam/dhcp/servers$", api.post_ipam_dhcp_server),
    ("PUT", r"^/api/ipam/dhcp/servers/(\d+)$", api.put_ipam_dhcp_server),
    ("DELETE", r"^/api/ipam/dhcp/servers/(\d+)$", api.delete_ipam_dhcp_server),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/poll$", api.post_ipam_dhcp_server_poll),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/test$", api.post_ipam_dhcp_server_test),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/credential$", api.post_ipam_dhcp_server_credential),
    ("DELETE", r"^/api/ipam/dhcp/servers/(\d+)/credential$", api.delete_ipam_dhcp_server_credential),
    ("GET", r"^/api/ipam/dhcp/scopes$", api.get_ipam_dhcp_scopes),
    ("GET", r"^/api/ipam/dhcp/leases$", api.get_ipam_dhcp_leases),
    ("GET", r"^/api/ipam/dhcp/scope-history$", api.get_ipam_dhcp_scope_history),
    ("GET", r"^/api/debug$", api.get_debug),
    ("POST", r"^/api/debug/clear$", api.post_debug_clear),
    ("POST", r"^/api/settings$", api.post_settings),
    ("POST", r"^/api/maintenance$", api.post_maintenance),
    ("POST", r"^/api/update$", api.post_update),
]

COMPILED = [(method, re.compile(pattern), handler)
            for method, pattern, handler in ROUTES]

# Reachable without a session: the sign-in page and what it needs to render.
PUBLIC_PATHS = {"/login", "/login.html", "/login.js", "/app.css", "/favicon.ico"}
PUBLIC_API = {"/api/login", "/api/session"}

SESSION_COOKIE = "sw_session"


class AccessLog:
    """Recent requests and per-client totals, for the service console.

    Bounded: this is a live view, not an audit trail. Static files are counted
    but kept out of the recent list, which would otherwise be nothing but the
    five scripts every page load fetches.
    """

    def __init__(self, capacity: int = 400):
        self._lock = threading.Lock()
        self.recent: deque = deque(maxlen=capacity)
        self.clients: dict[str, dict] = {}
        self.total = 0
        self.errors = 0
        self.active = 0
        self.peak_active = 0
        self.started_at = time.time()

    def record(self, client: str, method: str, path: str, status: int,
               ms: float, agent: str) -> None:
        with self._lock:
            self.total += 1
            if status >= 400:
                self.errors += 1
            entry = {"ts": time.time(), "client": client, "method": method,
                     "path": path, "status": status, "ms": ms}
            if not path.startswith(("/app.", "/netpath.js", "/netflow.js",
                                    "/syslog.js", "/debug.js", "/settings.js")):
                self.recent.appendleft(entry)
            info = self.clients.setdefault(client, {
                "requests": 0, "first_seen": time.time(), "last_seen": 0.0,
                "agent": agent, "errors": 0})
            info["requests"] += 1
            info["last_seen"] = time.time()
            if agent:
                info["agent"] = agent
            if status >= 400:
                info["errors"] += 1

    def opened(self) -> None:
        with self._lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)

    def closed(self) -> None:
        with self._lock:
            self.active = max(0, self.active - 1)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total": self.total, "errors": self.errors,
                "active": self.active, "peak_active": self.peak_active,
                "recent": list(self.recent),
                "clients": {name: dict(info) for name, info in self.clients.items()},
            }

    def clear(self) -> None:
        with self._lock:
            self.recent.clear()
            self.clients.clear()
            self.total = self.errors = 0


class Handler(BaseHTTPRequestHandler):
    server_version = "SappiWhere"
    sys_version = ""
    service: Service = None      # set on the server instance
    access: AccessLog = None

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt, *args):
        return  # the event log is the log; stderr noise helps nobody

    def setup(self):
        super().setup()
        if self.access:
            self.access.opened()

    def finish(self):
        try:
            super().finish()
        finally:
            if self.access:
                self.access.closed()

    def _send(self, code: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self._status = code
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # No external resources are loaded, so this can be strict.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        headers = {"Cache-Control": "no-store"}
        headers.update(extra_headers or {})
        self._send(code, body, "application/json; charset=utf-8", headers)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # -------------------------------------------------------------- routing

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # ------------------------------------------------------------ sessions

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def _set_session_cookie(self, token: str, clear: bool = False) -> dict:
        """HttpOnly so script cannot read it, SameSite=Strict so it is not sent
        on a cross-site request, Secure only under TLS because a Secure cookie
        is dropped outright over plain HTTP."""
        attributes = [f"{SESSION_COOKIE}={'' if clear else token}",
                      "Path=/", "HttpOnly", "SameSite=Strict"]
        if getattr(self.server, "is_tls", False):
            attributes.append("Secure")
        attributes.append("Max-Age=0" if clear else "Max-Age=%d"
                          % self.service.sessions.max_seconds)
        return {"Set-Cookie": "; ".join(attributes)}

    def _dispatch(self, method: str) -> None:
        started = time.perf_counter()
        try:
            self._route(method)
        finally:
            if self.access:
                self.access.record(
                    self.client_address[0], method, urlparse(self.path).path,
                    getattr(self, "_status", 0),
                    (time.perf_counter() - started) * 1000,
                    self.headers.get("User-Agent", "")[:120])

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # Query parameters starting with an underscore are ours, not the
        # caller's; strip anything that arrives claiming to be one.
        params = {k: v for k, v in params.items() if not k.startswith("_")}

        token = self._cookie(SESSION_COOKIE)
        session = self.service.sessions.get(token) if token else None
        params["_client"] = self.client_address[0]
        params["_agent"] = self.headers.get("User-Agent", "")
        if session:
            params["_token"] = token
            params["_username"] = session["username"]
            # A write is something a person chose to do — add a target, change
            # a setting, send a test packet — as opposed to the state poll
            # every open tab makes on its own every couple of seconds. Only
            # the former counts as presence for the idle timeout; otherwise a
            # tab left open in the background would never time out.
            if method in ("POST", "PUT", "DELETE"):
                self.service.sessions.touch(token)

        if not session and path not in PUBLIC_PATHS and path not in PUBLIC_API:
            if path.startswith("/api/"):
                self._json({"error": "Not signed in", "authenticated": False}, 401)
            else:
                self._send(302, b"", "text/plain", {"Location": "/login"})
            return

        # A cross-site form can send a POST but cannot set this content type
        # without a preflight the browser will refuse. With SameSite=Strict on
        # the cookie that is belt and braces, but both are cheap.
        if method in ("POST", "PUT", "DELETE"):
            content_type = (self.headers.get("Content-Type") or "").split(";")[0]
            if content_type.strip() != "application/json":
                self._json({"error": "Requests must be application/json"}, 415)
                return

        for route_method, pattern, handler in COMPILED:
            if route_method != method:
                continue
            match = pattern.match(path)
            if not match:
                continue
            try:
                body = self._body() if method in ("POST", "PUT", "DELETE") else {}
                args = [int(group) for group in match.groups()]
                result = handler(self.service, params, body, *args)

                headers = None
                if path == "/api/login":
                    headers = self._set_session_cookie(result.pop("token"))
                elif path == "/api/logout":
                    headers = self._set_session_cookie("", clear=True)
                self._json(result, extra_headers=headers)
            except PermissionError as exc:
                self._json({"error": str(exc)}, 401)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
            except Exception as exc:
                traceback.print_exc()
                self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
            return

        if path.startswith("/api/"):
            self._json({"error": "No such endpoint"}, 404)
            return
        self._static(path)

    def _static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        if path == "/login":
            path = "/login.html"
        # Resolve inside the static directory and refuse anything that escapes.
        candidate = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        if not candidate.startswith(STATIC_DIR) or not os.path.isfile(candidate):
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        content_type, _ = mimetypes.guess_type(candidate)
        stat = os.stat(candidate)
        etag = f'"{int(stat.st_mtime)}-{stat.st_size}"'

        # An update replaces the files underneath a browser that already has
        # the old ones. The shell is never cached so a reload always picks up
        # new script tags, and the scripts carry a validator so the browser can
        # tell stale from current instead of guessing.
        if candidate.endswith(".html"):
            cache = {"Cache-Control": "no-store"}
        else:
            cache = {"Cache-Control": "no-cache", "ETag": etag}
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self._status = 304
                return

        with open(candidate, "rb") as handle:
            body = handle.read()
        self._send(200, body, content_type or "application/octet-stream", cache)


class WebServer:
    def __init__(self, service: Service, host: str = "0.0.0.0", port: int = 8443,
                 certfile: str | None = None, keyfile: str | None = None):
        self.service = service
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.access = AccessLog()
        self.error: str | None = None

    @property
    def scheme(self) -> str:
        return "https" if self.certfile else "http"

    @property
    def url(self) -> str:
        shown = "localhost" if self.host in ("0.0.0.0", "") else self.host
        return f"{self.scheme}://{shown}:{self.port}/"

    @property
    def running(self) -> bool:
        return self.httpd is not None

    def start(self, block: bool = True) -> bool:
        """Bring the listener up. Returns False and sets `error` if it cannot."""
        self.error = None
        handler = type("BoundHandler", (Handler,),
                       {"service": self.service, "access": self.access})
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
            self.httpd.daemon_threads = True

            self.httpd.is_tls = bool(self.certfile)
            if self.certfile:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.certfile, self.keyfile or self.certfile)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.httpd.socket = context.wrap_socket(self.httpd.socket,
                                                        server_side=True)
        except (OSError, ssl.SSLError) as exc:
            hint = ""
            if getattr(exc, "errno", None) in (48, 98, 10048):
                hint = " — another process already holds this port"
            elif getattr(exc, "errno", None) in (13, 1):
                hint = " — ports below 1024 need administrator rights"
            self.error = f"Could not bind {self.host}:{self.port}: {exc}{hint}"
            self.httpd = None
            return False

        self.access.started_at = time.time()
        if block:
            self.httpd.serve_forever()
        else:
            self._thread = threading.Thread(target=self.httpd.serve_forever,
                                            name="sappiwhere-web", daemon=True)
            self._thread.start()
        return True

    def restart(self, host: str | None = None, port: int | None = None,
                certfile: str | None = None, keyfile: str | None = None) -> bool:
        self.stop()
        if host is not None:
            self.host = host
        if port is not None:
            self.port = int(port)
        if certfile is not None:
            self.certfile = certfile or None
        if keyfile is not None:
            self.keyfile = keyfile or None
        return self.start(block=False)

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

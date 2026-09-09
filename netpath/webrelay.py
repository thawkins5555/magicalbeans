"""The WEB button's TCP relay: a short-lived listener on this host that
carries one device's own web interface to the browser.

An `http` device is framed message by message, so the relay can hand the
browser back URLs on its own origin instead of the device's or this
server's; an `https` device — and any `http` message the framer cannot
account for — is carried unread, byte for byte, as everything was before.
"""

from __future__ import annotations

import logging
import random
import re
import secrets
import socket
import sys
import threading
import time

from . import permissions, udpsock
from .eventlog import NODES

log = logging.getLogger(__name__)

# --------------------------------------------------------------- the limits
#
# The same ten seconds sshterm uses: a device that hasn't handshaked by then
# isn't reachable, and the tab should be told rather than left spinning.
CONNECT_TIMEOUT_S = 10
# Presence, not "the tab is open" — mirrors auth.py's SessionStore.touch and
# the SSH terminal's idle figure.
IDLE_TIMEOUT_S = 900
# Bounds a relay nobody ever connects to (popup blocker ate the window, the
# POST's answer never arrived, or a caller opened a door and walked away) —
# without it such a relay holds a port for the full idle timeout.
FIRST_CONNECT_WINDOW_S = 60
# Relays across the whole application. Each is a listening socket, two
# threads, and up to MAX_CONNECTIONS_PER_SESSION more while a page loads.
MAX_SESSIONS = 16
# Per signed-in account, so one account cannot spend the whole cap itself and
# lock every other operator out.
MAX_SESSIONS_PER_USER = 4
# Generous on purpose (a browser opens several sockets per page, a device's
# UI may hold more for long-polling) — what it stops is a page spending the
# process's file handles.
MAX_CONNECTIONS_PER_SESSION = 32
# Somebody driving a device's page is present by the same rule a POST is, but
# a touch per chunk would be a write per 64 KB.
TOUCH_INTERVAL_S = 30
# The web session is re-read every tick (a dict lookup); the permission is a
# database read, so it gets its own slower cadence.
PERMISSION_EVERY_TICKS = 5
# Total budget for every session, not each — sessions stop concurrently.
SHUTDOWN_BUDGET_S = 3.0
# Large enough that a page of images is a handful of reads per socket, small
# enough that one relay cannot pin megabytes per connection.
CHUNK_BYTES = 64 * 1024
# A named range rather than "any free port": on Windows the first bind of an
# unopened port prompts, and a fixed window is one firewall rule, not one a week.
DEFAULT_PORT_RANGE = "40000-40999"

WEB_SCHEMES = ("http", "https")
DEFAULT_WEB_PORTS = {"http": 80, "https": 443}

# Session ids start with a letter because server.py's _route turns an
# all-digit path group into an int before it reaches the handler.
_SESSION_PREFIX = "r"


def parse_port_range(text: str) -> tuple[int, int]:
    """`"40000-40999"` -> (40000, 40999). `"0"` means any free port the OS
    offers — the escape hatch for a host where the range is already spoken for."""
    raw = str(text or "").strip() or DEFAULT_PORT_RANGE
    if raw == "0":
        return (0, 0)
    low_text, sep, high_text = raw.partition("-")
    try:
        low = int(low_text.strip())
        high = int(high_text.strip()) if sep else low
    except ValueError:
        raise ValueError(
            'The relay port range must be written "low-high", for example '
            '40000-40999, or "0" for any free port.') from None
    if not (1 <= low <= 65535 and 1 <= high <= 65535):
        raise ValueError("Relay ports must be between 1 and 65535.")
    if low > high:
        raise ValueError("The relay port range must start below where it ends.")
    return (low, high)


def relay_bind_host(web_host: str) -> str:
    """Where a relay listens, given where the UI listens.

    Follows the UI exactly: binding everything while the UI is pinned to
    loopback would put a door into the management plane on an interface the
    operator deliberately kept the application off.
    """
    host = str(web_host or "").strip()
    return "0.0.0.0" if host in ("", "*") else host


_HOST_CHARS = re.compile(r"^[A-Za-z0-9.\-\[\]:]+$")


def url_host(host_header: str, fallback: str) -> str:
    """The host part of a `Host:` header, without its port.

    Has to name whatever the browser typed — hostname, NAT address,
    localhost — since that's the only address it's known to reach.
    """
    host = str(host_header or "").strip()
    if not host or not _HOST_CHARS.match(host):
        return fallback
    if host.startswith("["):
        end = host.find("]")
        return host[:end + 1] if end != -1 else fallback
    return host.rsplit(":", 1)[0] if ":" in host else host


def device_web_target(row) -> tuple[str, str, int]:
    """(address, scheme, port) for a device row — the only place a relay's
    destination is ever decided, so a caller cannot name one."""
    keys = row.keys()
    scheme = (row["web_scheme"] if "web_scheme" in keys else None) or "http"
    if scheme not in WEB_SCHEMES:
        scheme = "http"
    port = row["web_port"] if "web_port" in keys else None
    return row["ip"], scheme, int(port) if port else DEFAULT_WEB_PORTS[scheme]


# ------------------------------------------------------- reading the headers
#
# What the relay carries for an `http` device, so a device that rebuilds its
# own URLs from the `Host:` it was sent (which is this server's name and the
# relay's port) stops answering `Location: https://<this server>/home.asp`
# and sending the browser to the management interface's own port.
#
# Every one of these gives up by returning None, and giving up means the
# whole connection goes back to the byte pump for good. The pump is the
# floor: a device that works today cannot be broken by a parser.

# A head this long is a device speaking something that is not HTTP/1.
MAX_HEAD_BYTES = 64 * 1024
# A chunk size is a hex number and perhaps an extension; nothing else.
MAX_LINE_BYTES = 8 * 1024

_REQUEST_LINE = re.compile(rb"^([A-Za-z]+) (\S+) (HTTP/1\.[01])$")
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] (\d{3})(?: [^\r\n]*)?$")
_HEADER_LINE = re.compile(rb"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([^\r\n]*?)[ \t]*$")
_DIGITS = re.compile(rb"^[0-9]+$")
_ABSOLUTE_URL = re.compile(r"^(https?)://([^/?#]*)([/?#].*)?$", re.IGNORECASE)
_REFRESH_URL = re.compile(r"""(\burl\s*=\s*)(["']?)([^"';\s]*)\2""", re.IGNORECASE)
# The four ways a device names an address in a header. A body is never
# rewritten: it is streamed, and a page's own links are the browser's to
# resolve against the origin these put it on.
REWRITTEN_HEADERS = (b"location", b"content-location", b"refresh", b"set-cookie")
# The two ways a browser names the authority it reached. They have to move
# with `Host:`, since a device that checks one against the other refuses a
# POST whose origin is not its own.
REQUEST_HEADERS = (b"origin", b"referer")


def _host_name(authority: str) -> str:
    """The bare name in an authority, lowercased and unbracketed."""
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        end = host.find("]")
        return host[1:end].lower() if end != -1 else host.lower()
    return host.split(":", 1)[0].lower()


def _is_ours(match, names, origin: str) -> bool:
    """Whether an absolute URL names one of `names` on the scheme this tunnel
    carries. A device on plain HTTP answering `https://<itself>/` is saying
    its UI is somewhere this tunnel does not go, and moving that onto the
    relay's own `http` origin would only send the browser round again."""
    return (match is not None and _host_name(match.group(2)) in names
            and match.group(1).lower() == origin.split(":", 1)[0])


def map_url(value: str, names, origin: str) -> str:
    """An absolute URL naming the device or this server, on this tunnel's own
    scheme, moved onto the relay's origin. A relative URL, one naming
    anywhere else, and one on the other scheme all come back exactly as they
    were written."""
    match = _ABSOLUTE_URL.match(value.strip())
    if not _is_ours(match, names, origin):
        return value
    return origin + (match.group(3) or "/")


def map_origin(value: str, names, origin: str) -> str:
    """The same, for a header that is an origin and not a URL: no path is
    added, since an origin carrying one matches nothing."""
    match = _ABSOLUTE_URL.match(value.strip())
    return origin if _is_ours(match, names, origin) else value


def map_refresh(value: str, names, origin: str) -> str:
    """`Refresh: 5; url=<somewhere>` — the delay is left alone."""
    delay, sep, rest = value.partition(";")
    if not sep:
        return value
    return delay + sep + _REFRESH_URL.sub(
        lambda m: m.group(1) + m.group(2)
        + map_url(m.group(3), names, origin) + m.group(2), rest)


def map_cookie(value: str, names) -> str:
    """A cookie the device scoped to its own name, or to this server's, is
    scoped to nothing instead. Host-only is the one scope a browser will
    accept on the relay's origin whatever that origin turns out to be
    called — and an address is a scope a browser refuses outright."""
    parts = value.split(";")
    kept = [parts[0]]
    for part in parts[1:]:
        key, sep, domain = part.partition("=")
        if (sep and key.strip().lower() == "domain"
                and domain.strip().lstrip(".").lower() in names):
            continue
        kept.append(part)
    return ";".join(kept)


def _split_head(head: bytes):
    """(start line, raw header lines, (lowercased name, value) pairs) for a
    complete head, or None for one this will not touch."""
    lines = head[:-4].split(b"\r\n")
    fields = []
    for line in lines[1:]:
        # An empty line is a bare CR or LF inside the head; a leading space
        # is the obsolete line folding no current sender emits.
        if not line or line[:1] in (b" ", b"\t"):
            return None
        match = _HEADER_LINE.match(line)
        if match is None:
            return None
        fields.append((match.group(1).lower(), match.group(2)))
    return lines[0], lines[1:], fields


def _body_plan(fields, *, is_response: bool, code: int = 0, method: str = ""):
    """("none" | "length" | "chunked" | "eof", byte count) for the body that
    follows a head, or None when its length cannot be told from the head."""
    encodings = [value for name, value in fields if name == b"transfer-encoding"]
    lengths = [value for name, value in fields if name == b"content-length"]
    if is_response and (code < 200 or code in (204, 304) or method == "HEAD"):
        return ("none", 0)
    if encodings:
        # Both headers is two framings that can disagree, and which one the
        # device honours is its own business — so read neither.
        if lengths or len(encodings) > 1 or encodings[0].rsplit(
                b",", 1)[-1].strip().lower() != b"chunked":
            return None
        return ("chunked", 0)
    if lengths:
        seen = {value.strip() for value in lengths}
        if len(seen) != 1 or not _DIGITS.match(next(iter(seen))):
            return None
        return ("length", int(seen.pop()))
    # A request without either carries no body at all; a response carries
    # one until the socket closes, which ends the connection anyway.
    return ("eof", 0) if is_response else ("none", 0)


def _rebuild(start: bytes, lines, replaced: dict) -> bytes:
    out = [start]
    for index, line in enumerate(lines):
        value = replaced.get(index)
        out.append(line if value is None
                   else line.split(b":", 1)[0] + b": " + value)
    return b"\r\n".join(out) + b"\r\n\r\n"


def frame_request(head: bytes, authority: bytes, names, origin: str):
    """(head, body kind, body length, method) for one request, with every
    place its head names the relay — `Host:`, `Origin:`, `Referer:`, and a
    request target written out in full — pointed at the device instead, so
    the device builds its URLs against its own address and the three it may
    compare still agree there, as they did when nothing was read at all.
    None sends the connection to the byte pump."""
    parts = _split_head(head)
    if parts is None:
        return None
    start, lines, fields = parts
    match = _REQUEST_LINE.match(start)
    if match is None or match.group(1).upper() == b"CONNECT":
        return None
    plan = _body_plan(fields, is_response=False)
    if plan is None:
        return None
    target = match.group(2)
    if not target.startswith(b"/"):
        start = b" ".join((
            match.group(1),
            map_url(target.decode("latin-1"), names, origin).encode("latin-1"),
            match.group(3)))
    replaced = {}
    for index, (name, value) in enumerate(fields):
        if name == b"host":
            replaced[index] = authority
            continue
        if name not in REQUEST_HEADERS:
            continue
        text = value.decode("latin-1")
        mapped = (map_origin if name == b"origin" else map_url)(
            text, names, origin)
        if mapped != text:
            replaced[index] = mapped.encode("latin-1")
    return (_rebuild(start, lines, replaced), plan[0], plan[1],
            match.group(1).upper().decode("ascii"))


def frame_response(head: bytes, take_method, names, origin: str):
    """(head, body kind, body length, "") for one response, with every
    address it names mapped back onto the relay's origin.

    `take_method` is called — once, and only for a final response — for the
    method of the request being answered, since a `HEAD` answer carries no
    body however its head is framed.
    """
    parts = _split_head(head)
    if parts is None:
        return None
    start, lines, fields = parts
    match = _STATUS_LINE.match(start)
    if match is None:
        return None
    code = int(match.group(1))
    if code == 101:
        return None                 # an upgrade: nothing after this is HTTP
    method = "" if code < 200 else take_method()
    plan = _body_plan(fields, is_response=True, code=code, method=method)
    if plan is None:
        return None
    replaced = {}
    for index, (name, value) in enumerate(fields):
        if name not in REWRITTEN_HEADERS:
            continue
        text = value.decode("latin-1")
        if name == b"set-cookie":
            mapped = map_cookie(text, names)
        elif name == b"refresh":
            mapped = map_refresh(text, names, origin)
        else:
            mapped = map_url(text, names, origin)
        if mapped != text:
            replaced[index] = mapped.encode("latin-1")
    return _rebuild(start, lines, replaced), plan[0], plan[1], ""


class _HttpConnection:
    """What the two directions of one framed connection share: the switch
    that sends both back to the byte pump, and the methods still waiting to
    be answered."""

    def __init__(self):
        self.blind = threading.Event()
        self._lock = threading.Lock()
        self._methods: list[str] = []

    def sent(self, method: str) -> None:
        with self._lock:
            self._methods.append(method)

    def take(self) -> str:
        with self._lock:
            return self._methods.pop(0) if self._methods else ""


# Returned by _read_head for "there is no head here": distinct from None,
# which is the connection ending cleanly.
_BLIND = object()


def _close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _listen(host: str, port: int) -> socket.socket:
    """No SO_REUSEADDR: on Windows it would let an unrelated process bind the
    same port and steal connections. SO_EXCLUSIVEADDRUSE is the Windows way
    to keep the port exclusive while held."""
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                         socket.SOCK_STREAM)
    if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        sock.bind((host, port))
        sock.listen(16)
    except OSError:
        sock.close()
        raise
    # So closing the listener isn't the only thing that can end the accept
    # loop, on a platform where close() doesn't unblock accept().
    sock.settimeout(0.5)
    return sock


class WebRelayRegistry:
    """Every live relay, so shutdown can end them, the caps can be enforced
    and one bind cannot race another onto the same port."""

    def __init__(self, service):
        self.service = service
        self._lock = threading.Lock()
        self._sessions: dict[str, "WebRelaySession"] = {}
        self._stopping = False

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # -------------------------------------------------------------- opening

    def open(self, device_id: int, username: str, client_ip: str,
             token: str = "", host_header: str = "") -> dict:
        """Bind a relay to one device and return what the browser needs.

        Every refusal here is a ValueError, which the request layer answers
        400: a spent cap and an exhausted port range are both "not now",
        not "not allowed" and not a fault.
        """
        device = self.service.nodes_db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        target_ip, scheme, target_port = device_web_target(device)
        client_ip = udpsock.normalise_source(str(client_ip or ""))
        if not client_ip:
            raise ValueError(
                "The relay could not tell which address you are connecting "
                "from, and it will only admit that one address.")
        low, high = parse_port_range(
            self.service.settings.get("web_relay_port_range", DEFAULT_PORT_RANGE))
        bind_host = relay_bind_host(self.service.settings.get("web_host", "0.0.0.0"))

        # Whole admission decision under one lock: two clicks arriving
        # together must not both pass a cap that only one of them fits.
        with self._lock:
            if self._stopping:
                raise ValueError("The server is shutting down.")
            if len(self._sessions) >= MAX_SESSIONS:
                raise ValueError(
                    f"There are already {MAX_SESSIONS} web tunnels open. "
                    f"Close one and try again.")
            mine = sum(1 for live in self._sessions.values()
                       if live.app_user == (username or ""))
            if mine >= MAX_SESSIONS_PER_USER:
                raise ValueError(
                    f"You already have {MAX_SESSIONS_PER_USER} web tunnels "
                    f"open. Close one and try again.")
            listener, port = self._bind(bind_host, low, high)
            session = WebRelaySession(
                self, listener, port, device_id=device_id, target_ip=target_ip,
                target_port=target_port, scheme=scheme, username=username or "",
                client_ip=client_ip, token=token or "",
                host=url_host(host_header, "127.0.0.1"))
            self._sessions[session.session_id] = session
        # Threads start outside the lock: a watchdog tick takes it to close.
        session.start()
        return session.info()

    def _bind(self, host: str, low: int, high: int):
        """A listening socket on a free port in the configured range, tried
        in a random order so two relays opened together rarely collide and
        retry. Called under the lock."""
        if low == 0:
            try:
                sock = _listen(host, 0)
            except OSError as exc:
                raise ValueError(f"No port could be opened for the tunnel: {exc}")
            return sock, sock.getsockname()[1]
        candidates = list(range(low, high + 1))
        random.shuffle(candidates)
        taken = {live.port for live in self._sessions.values()}
        for port in candidates:
            if port in taken:
                continue
            try:
                return _listen(host, port), port
            except OSError:
                continue
        raise ValueError(
            f"Every port between {low} and {high} is in use, so no tunnel "
            f"could be opened. Close an open tunnel, or widen the relay port "
            f"range under Settings.")

    # -------------------------------------------------------------- reading

    def get(self, session_id: str):
        with self._lock:
            return self._sessions.get(str(session_id or ""))

    def status(self, username: str | None = None) -> list[dict]:
        """Every live relay, or one account's. Ordered oldest first so a list
        does not reshuffle between polls."""
        with self._lock:
            live = list(self._sessions.values())
        rows = [session.info() for session in live
                if username is None or session.app_user == username]
        return sorted(rows, key=lambda row: row["opened_ts"])

    # -------------------------------------------------------------- closing

    def close(self, session_id: str, reason: str) -> bool:
        session = self.get(session_id)
        if session is None:
            return False
        session.stop(reason)
        return True

    def _forget(self, session: "WebRelaySession") -> None:
        with self._lock:
            if self._sessions.get(session.session_id) is session:
                del self._sessions[session.session_id]

    def shutdown(self) -> None:
        """End every relay before the databases close (a closing relay writes
        a device event). Concurrent, under one shared budget — sixteen
        sequential stops would be an operator's Ctrl+C apparently hanging."""
        with self._lock:
            self._stopping = True
            live = list(self._sessions.values())
        if not live:
            return
        deadline = time.time() + SHUTDOWN_BUDGET_S
        stoppers = []
        for session in live:
            thread = threading.Thread(
                target=session.stop, args=("the server is shutting down",),
                name=f"relay-stop-{session.device_id}", daemon=True)
            thread.start()
            stoppers.append(thread)
        for thread in stoppers:
            thread.join(timeout=max(0.0, deadline - time.time()))


class WebRelaySession:
    """One open door: a listening socket, an accept thread, a watchdog, and
    a pair of threads per connection carrying bytes in each direction.

    Blocking threads rather than one selector, deliberately: Windows'
    select() takes a fixed-size FD_SET (512 by default) with no portable
    poll/epoll alternative in the standard library, and sixteen relays of
    thirty-two connections is 1,024 sockets.
    """

    def __init__(self, registry: WebRelayRegistry, listener: socket.socket,
                 port: int, *, device_id: int, target_ip: str, target_port: int,
                 scheme: str, username: str, client_ip: str, token: str,
                 host: str):
        self.registry = registry
        self.service = registry.service
        self.session_id = _SESSION_PREFIX + secrets.token_urlsafe(18)
        self.listener = listener
        self.port = port
        self.device_id = device_id
        self.target_ip = target_ip
        self.target_port = target_port
        self.scheme = scheme
        self.app_user = username
        # Normalised the way every other allow list here is (a dual-stack
        # listener reports an IPv4 peer as "::ffff:10.0.0.1").
        self.client_ip = client_ip
        # A tunnel outlives the request that opened it, so this is what the
        # watchdog re-reads: sign out, expiry or a deleted account takes it.
        self.token = token
        # Everything the framer needs about the two ends: the origin a
        # device's answers are moved onto, the names that get moved (this
        # server's, as the browser reached it, and the device's own), and the
        # authority the device is told to build its own URLs against.
        self.origin = f"{scheme}://{host}:{port}"
        self.url = self.origin + "/"
        self.relay_names = frozenset(
            name for name in (str(host).strip("[]").lower(),
                              str(target_ip).strip("[]").lower()) if name)
        authority = (f"[{target_ip}]:{target_port}" if ":" in target_ip
                     else f"{target_ip}:{target_port}")
        self.device_authority = authority.encode("latin-1")
        self.device_origin = f"{scheme}://{authority}"
        self.opened_ts = time.time()
        self._last_traffic = self.opened_ts
        self._last_touch = 0.0
        self._stopped = threading.Event()
        self._stop_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self.bytes_to_device = 0
        self.bytes_from_device = 0
        self.connections_total = 0
        self._live_connections = 0
        # A pump parked in recv() only notices `_stopped` between chunks, so
        # closing these is what actually ends a relay a browser still holds
        # open — and why shutdown() can promise a budget at all.
        self._live_sockets: set[socket.socket] = set()
        # A scanner or a second operator's browser should leave one audit
        # line, not one per packet.
        self._audited_refusal = False
        self._watch_failed = False
        self._threads: list[threading.Thread] = []

    # ----------------------------------------------------------------- info

    def info(self) -> dict:
        with self._counter_lock:
            to_device, from_device = self.bytes_to_device, self.bytes_from_device
            total, live = self.connections_total, self._live_connections
        return {
            "session_id": self.session_id, "url": self.url, "port": self.port,
            "scheme": self.scheme, "device_id": self.device_id,
            "device_ip": self.target_ip, "device_port": self.target_port,
            "username": self.app_user, "client_ip": self.client_ip,
            "opened_ts": self.opened_ts, "last_traffic_ts": self._last_traffic,
            "expires_s": self._effective_idle_s(),
            "first_connect_s": FIRST_CONNECT_WINDOW_S,
            "connections": total, "connections_live": live,
            "bytes_to_device": to_device, "bytes_from_device": from_device,
        }

    # ----------------------------------------------------------------- start

    def start(self) -> None:
        self._audit(f"Web tunnel opened by {self.app_user} on port {self.port}",
                    f"To {self.target_ip}:{self.target_port} ({self.scheme}), "
                    f"reachable only from {self.client_ip}.")
        for target, name in ((self._accept_loop, "accept"), (self._watch, "watch")):
            thread = threading.Thread(target=target, daemon=True,
                                      name=f"relay-{name}-{self.device_id}")
            thread.start()
            self._threads.append(thread)

    # ---------------------------------------------------------------- accept

    def _admit(self, addr) -> bool:
        """Whether a connection to this relay is the operator's own browser.

        The only gate on the port, and it is an address, not a credential:
        nothing the browser sends is trusted, so there is nothing in it to
        check — the framer reads headers, it does not believe them.
        """
        return udpsock.normalise_source(str(addr[0])) == self.client_ip

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, addr = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._admit(addr):
                conn.close()
                self._audit_refusal(addr)
                continue
            with self._counter_lock:
                if self._live_connections >= MAX_CONNECTIONS_PER_SESSION:
                    conn.close()
                    continue
                self._live_connections += 1
                self.connections_total += 1
            thread = threading.Thread(
                target=self._serve, args=(conn,), daemon=True,
                name=f"relay-conn-{self.device_id}")
            thread.start()

    def _audit_refusal(self, addr) -> None:
        if self._audited_refusal:
            return
        self._audited_refusal = True
        self._audit(
            f"Web tunnel on port {self.port} refused a connection from "
            f"{addr[0]} (it admits only {self.client_ip})",
            "The connection was closed without a byte being carried.")

    # ----------------------------------------------------------------- serve

    def _serve(self, client: socket.socket) -> None:
        """One admitted connection: dial the device, then carry both
        directions until either end hangs up."""
        device = None
        try:
            device = socket.create_connection(
                (self.target_ip, self.target_port), CONNECT_TIMEOUT_S)
            device.settimeout(None)
            client.settimeout(None)
            with self._counter_lock:
                self._live_sockets.update((client, device))
            # One framing state for the connection, shared by its two
            # directions; None is the blind tunnel every device had before.
            state = _HttpConnection() if self.scheme == "http" else None
            up = threading.Thread(
                target=self._pump, args=(client, device, True, state),
                daemon=True, name=f"relay-up-{self.device_id}")
            up.start()
            self._pump(device, client, False, state)
            up.join(timeout=CONNECT_TIMEOUT_S)
            client.close()   # bounded either way: the up-pump's recv ends here
            up.join(timeout=CONNECT_TIMEOUT_S)
        except OSError:
            # A device that will not answer is reported by the browser as a
            # failed page load, which is what it is.
            pass
        finally:
            with self._counter_lock:
                self._live_sockets.discard(client)
                self._live_sockets.discard(device)
                self._live_connections = max(0, self._live_connections - 1)
            for sock in (client, device):
                try:
                    if sock is not None:
                        sock.close()
                except OSError:
                    pass

    def _pump(self, src: socket.socket, dst: socket.socket, to_device: bool,
              state: "_HttpConnection | None" = None) -> None:
        """Carry one direction. Without a framing state the bytes are counted
        and never looked at, which is what an `https` device needs and what
        every device got before 5.4."""
        try:
            if state is None:
                self._copy(src, dst, to_device, b"")
            else:
                self._frame(src, dst, to_device, state)
        except OSError:
            pass
        # Half-close rather than close: the other direction may still have a
        # response to deliver.
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        if to_device:
            # The browser hung up; a device that ignores half-close would
            # otherwise hold this connection's slot until the idle timeout.
            threading.Timer(CONNECT_TIMEOUT_S, lambda: _close_quietly(dst)).start()

    def _forward(self, dst: socket.socket, data: bytes, to_device: bool) -> None:
        dst.sendall(data)
        self._note_traffic(len(data), to_device)

    def _copy(self, src: socket.socket, dst: socket.socket, to_device: bool,
              pending: bytes) -> None:
        """The byte pump: whatever arrives, on to the other end. `pending` is
        what a framer had already read and not yet forwarded."""
        if pending:
            self._forward(dst, pending, to_device)
        while not self._stopped.is_set():
            data = src.recv(CHUNK_BYTES)
            if not data:
                break
            self._forward(dst, data, to_device)

    def _blindly(self, src, dst, to_device: bool, state, buf) -> None:
        """Back to the pump, for this connection and for good: the other
        direction checks the switch before it frames anything else."""
        state.blind.set()
        self._copy(src, dst, to_device, bytes(buf))

    def _frame(self, src: socket.socket, dst: socket.socket, to_device: bool,
               state: "_HttpConnection") -> None:
        """One direction of an `http` session, message by message: the head
        read whole and rewritten, the body streamed through untouched."""
        buf = bytearray()
        while not self._stopped.is_set():
            if state.blind.is_set():
                return self._copy(src, dst, to_device, bytes(buf))
            head = self._read_head(src, buf, state)
            if head is None:                    # the connection ended
                if buf:
                    self._forward(dst, bytes(buf), to_device)
                return
            if head is _BLIND:
                return self._blindly(src, dst, to_device, state, buf)
            framed = (frame_request(head, self.device_authority,
                                    self.relay_names, self.device_origin)
                      if to_device
                      else frame_response(head, state.take, self.relay_names,
                                          self.origin))
            if framed is None:
                buf[:0] = head       # not a byte of it has moved either way
                return self._blindly(src, dst, to_device, state, buf)
            rewritten, kind, length, method = framed
            if to_device:
                # Before the forward, so the answer cannot arrive first.
                state.sent(method)
            self._forward(dst, rewritten, to_device)
            if kind == "eof":
                return self._copy(src, dst, to_device, bytes(buf))
            if kind == "length" and not self._stream(src, dst, to_device,
                                                     buf, length):
                return
            if kind == "chunked" and not self._stream_chunked(src, dst,
                                                              to_device, buf):
                return self._blindly(src, dst, to_device, state, buf)

    def _read_head(self, src: socket.socket, buf: bytearray, state):
        """The next head, taken off `buf`. None when the connection ended
        first, `_BLIND` when there is no head here to be had."""
        while True:
            cut = buf.find(b"\r\n\r\n")
            if cut != -1:
                head = bytes(buf[:cut + 4])
                del buf[:cut + 4]
                return head
            if len(buf) > MAX_HEAD_BYTES:
                return _BLIND
            data = src.recv(CHUNK_BYTES)
            if not data:
                return None
            buf += data
            # The other direction may have given up while this one waited.
            if state.blind.is_set():
                return _BLIND

    def _stream(self, src: socket.socket, dst: socket.socket, to_device: bool,
                buf: bytearray, remaining: int) -> bool:
        """`remaining` body bytes, forwarded as they arrive. Never held
        whole: these carry firmware images."""
        while remaining > 0:
            if buf:
                take = min(remaining, len(buf))
                self._forward(dst, bytes(buf[:take]), to_device)
                del buf[:take]
                remaining -= take
                continue
            data = src.recv(min(CHUNK_BYTES, remaining))
            if not data:
                return False
            self._forward(dst, data, to_device)
            remaining -= len(data)
        return True

    def _read_line(self, src: socket.socket, buf: bytearray):
        while True:
            cut = buf.find(b"\r\n")
            if cut != -1:
                line = bytes(buf[:cut + 2])
                del buf[:cut + 2]
                return line
            if len(buf) > MAX_LINE_BYTES:
                return None
            data = src.recv(CHUNK_BYTES)
            if not data:
                return None
            buf += data

    def _stream_chunked(self, src: socket.socket, dst: socket.socket,
                        to_device: bool, buf: bytearray) -> bool:
        """A chunked body, its framing bytes included, passed through exactly
        as the sender wrote them. False when it stops making sense — and by
        then everything read has already been forwarded, so the caller can
        go blind without a byte being lost or repeated."""
        while True:
            line = self._read_line(src, buf)
            if line is None:
                return False
            self._forward(dst, line, to_device)
            try:
                size = int(line[:-2].split(b";", 1)[0].strip(), 16)
            except ValueError:
                return False
            if size < 0:
                return False
            if size == 0:
                break
            if not self._stream(src, dst, to_device, buf, size + 2):
                return False
        while True:                  # trailers, then the closing blank line
            line = self._read_line(src, buf)
            if line is None:
                return False
            self._forward(dst, line, to_device)
            if line == b"\r\n":
                return True

    def _note_traffic(self, count: int, to_device: bool) -> None:
        now = time.time()
        self._last_traffic = now
        with self._counter_lock:
            if to_device:
                self.bytes_to_device += count
            else:
                self.bytes_from_device += count
        if self.token and now - self._last_touch >= TOUCH_INTERVAL_S:
            self._last_touch = now
            try:
                self.service.sessions.touch(self.token)
            except Exception:
                pass

    # ----------------------------------------------------------------- watch

    def _effective_idle_s(self) -> float:
        """IDLE_TIMEOUT_S, capped to the live web session timeout — a tunnel
        must not advertise a window longer than the sign-in containing it."""
        if not self.token:
            return float(IDLE_TIMEOUT_S)
        try:
            return float(min(IDLE_TIMEOUT_S, self.service.sessions.idle_seconds))
        except Exception:
            return float(IDLE_TIMEOUT_S)

    def _watch(self) -> None:
        ticks = 0
        while not self._stopped.wait(1.0):
            ticks += 1
            try:
                if self._watch_tick(ticks):
                    return
            except Exception:
                # This one loop enforces idle timeout, first-connect window,
                # sign-out and the permission check; it must not silently
                # disable all four on one failed tick.
                if not self._watch_failed:
                    self._watch_failed = True
                    log.exception("The web relay watchdog for device %s failed "
                                  "a tick; it keeps running", self.device_id)

    def _watch_tick(self, ticks: int) -> bool:
        """One beat. True when the relay is over and the loop should end."""
        now = time.time()
        if not self.connections_total:
            if now - self.opened_ts >= FIRST_CONNECT_WINDOW_S:
                self.stop(f"nothing connected within "
                          f"{int(FIRST_CONNECT_WINDOW_S)} seconds")
                return True
        else:
            idle = self._effective_idle_s()
            if now - self._last_traffic >= idle:
                self.stop(f"idle for {max(1, round(idle / 60))} minute(s)")
                return True
        if self.token and self.service.sessions.get(self.token) is None:
            self.stop(f"{self.app_user} is no longer signed in")
            return True
        if ticks % PERMISSION_EVERY_TICKS == 0 and not self._has_web_write():
            self.stop(f"{self.app_user} no longer holds Web write access")
            return True
        return False

    def _has_web_write(self) -> bool:
        try:
            granted = self.service.app_db.permissions_for(self.app_user).get("web")
        except Exception:
            return True           # a database that cannot answer is not a verdict
        return permissions.allows(granted, permissions.WRITE)

    # ----------------------------------------------------------------- close

    def stop(self, reason: str = "") -> None:
        with self._stop_lock:
            if self._stopped.is_set():
                return
            self._stopped.set()
        # The listener first: it's what the accept thread is parked on.
        try:
            self.listener.close()
        except OSError:
            pass
        with self._counter_lock:
            live = list(self._live_sockets)
            self._live_sockets.clear()
        for sock in live:
            try:
                sock.close()
            except OSError:
                pass
        self.registry._forget(self)
        self._audit_close(reason)

    # ----------------------------------------------------------------- audit

    def _audit(self, headline: str, detail: str) -> None:
        """One line in both places a relay is recorded: the device's own
        event list and the NODES log."""
        try:
            self.service.nodes_db.record_device_event(self.device_id, "web",
                                                      headline)
            self.service.log.add(NODES, headline, target=self.target_ip,
                                 detail=detail)
        except Exception:
            # Shutdown races the databases closing.
            pass

    def _audit_close(self, reason: str) -> None:
        seconds = max(0, int(time.time() - self.opened_ts))
        spell = f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"
        with self._counter_lock:
            to_device, from_device = self.bytes_to_device, self.bytes_from_device
            total = self.connections_total
        # Counts go in the headline, not just the log detail: how much
        # crossed is the only thing there is to say — no content is kept.
        self._audit(
            f"Web tunnel on port {self.port} closed after {spell}"
            + (f" ({reason})" if reason else "")
            + f"; {total} connection(s), {to_device} bytes to the device and "
              f"{from_device} back",
            f"Opened by {self.app_user} from {self.client_ip}.")

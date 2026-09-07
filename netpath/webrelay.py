"""The WEB button's TCP relay: a short-lived listener on this host that
carries bytes, unread, to one device's own web interface.

Before 5.1 the button pointed the browser straight at `http://<ip>/`, which
only works from a machine with a route to the management plane. This opens a
port here instead, so the operator's browser talks to this server and this
server talks to the device — the same reachability the poller already has.

What that costs is what shapes this module. The listener is a door into the
management plane, so: the target comes from the device row and never from the
caller; only the operator's own client address is admitted; the door closes on
idle, on nobody arriving, on sign-out, on the permission going away and on
shutdown; and there are caps so one account cannot open doors until the
process runs out of ports. Bytes are copied and never inspected — a device on
https carries its own TLS through this untouched, which is also why the audit
trail can only ever say how many bytes went each way.
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
# How long the relay waits for the device's web server to answer a TCP
# connect. The same ten seconds sshterm uses, for the same reason: a device
# that has not completed a handshake in that long is not reachable, and the
# browser tab wants to be told rather than left spinning.
CONNECT_TIMEOUT_S = 10
# No bytes either way for this long ends the relay. Presence, not "the tab is
# open" — the same rule auth.py's SessionStore.touch applies, and the same
# figure the SSH terminal uses. _watch_tick takes whichever of this and the
# live session_idle_minutes is smaller, so a relay never advertises a longer
# window than the sign-in containing it.
IDLE_TIMEOUT_S = 900
# How long a relay that nobody ever connects to may hold its port. The click
# handler opens the window and sets its location the moment the POST answers,
# so this is measured in round trips; what it bounds is the other case — a
# popup blocker that ate the window, a POST whose answer never arrived, or a
# caller driving the API directly who opened a door and walked away. Without
# it such a relay holds a port and a slot for the full idle timeout.
FIRST_CONNECT_WINDOW_S = 60
# Relays across the whole application. Each is a listening socket, two
# threads, and up to MAX_CONNECTIONS_PER_SESSION more while a page loads.
MAX_SESSIONS = 16
# And per signed-in account, so one account cannot spend the application-wide
# cap on its own and lock every other operator out.
MAX_SESSIONS_PER_USER = 4
# Concurrent connections through one relay. A browser opens several sockets
# per page (six per origin is the usual limit) and a device's UI may hold a
# couple more for long-polling, so this is generous on purpose: what it stops
# is a page — or a script behind one — spending the process's file handles.
MAX_CONNECTIONS_PER_SESSION = 32
# How often traffic refreshes the *web* session. Somebody driving a device's
# management page is present by the same rule a POST is, but a touch per
# chunk would be a write per 64 KB.
TOUCH_INTERVAL_S = 30
# How often the watchdog re-reads the permission (it re-reads the web session
# every tick, which is a dictionary lookup; the permission is a database
# read). Five seconds from revoked to closed.
PERMISSION_EVERY_TICKS = 5
# How long `WebRelayRegistry.shutdown()` may take in total, for every session
# rather than for each — sessions are stopped concurrently inside it.
SHUTDOWN_BUDGET_S = 3.0
# The copy buffer. Large enough that a page of images is a handful of reads
# per socket, small enough that one relay cannot pin megabytes per connection.
CHUNK_BYTES = 64 * 1024
# The ports a relay may bind, as an operator writes it in Settings. A named
# range rather than "any free port" by default because a firewall rule has to
# name something: on Windows the first bind of an unopened port prompts, and
# a fixed thousand-port window is one rule instead of a prompt a week.
DEFAULT_PORT_RANGE = "40000-40999"

# The schemes a device's web interface may be reached over, and the port each
# implies when the device row does not name one.
WEB_SCHEMES = ("http", "https")
DEFAULT_WEB_PORTS = {"http": 80, "https": 443}

# Session ids start with a letter because server.py's _route turns an
# all-digit path group into an int before it reaches the handler; a token that
# happened to be all digits would arrive as a number and match nothing.
_SESSION_PREFIX = "r"


def parse_port_range(text: str) -> tuple[int, int]:
    """`"40000-40999"` -> (40000, 40999). `"0"` means "any free port the
    operating system offers" — the escape hatch for a host where the range is
    already spoken for. Raises ValueError with the sentence an operator
    should read."""
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

    The relay has to be reachable by the same browser that reached the UI, so
    it follows it exactly: every address when the UI is on every address,
    and the same single address when the UI is pinned to one. Binding
    everything while the UI is pinned to loopback would put a door into the
    management plane on an interface the operator deliberately kept the
    application off.
    """
    host = str(web_host or "").strip()
    return "0.0.0.0" if host in ("", "*") else host


_HOST_CHARS = re.compile(r"^[A-Za-z0-9.\-\[\]:]+$")


def url_host(host_header: str, fallback: str) -> str:
    """The host part of a `Host:` header, without its port.

    The URL handed back has to name whatever the browser typed — a hostname,
    a NAT address, `localhost` — because that is the only address it is known
    to be able to reach. An IPv6 literal keeps its brackets, since that is
    what a URL wants.
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


def _close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _listen(host: str, port: int) -> socket.socket:
    """One bind attempt. No SO_REUSEADDR: on Linux it would let this bind a
    port in TIME_WAIT that another relay just gave up, and on Windows it is
    worse than that — it lets an unrelated process bind the same port and
    steal connections. SO_EXCLUSIVEADDRUSE is the Windows way to say the
    opposite: nobody else gets this port while it is held."""
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
    # Half a second, so closing the listener is not the only thing that can
    # end the accept loop: a platform where close() does not unblock accept()
    # would otherwise leave the thread parked for the life of the process.
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

        # The whole admission decision under one lock: two clicks arriving
        # together must not both pass a cap that only one of them fits, and
        # must not both pick the same free port and have the second bind fail.
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
        a device event). Concurrent, under one shared budget: a session's stop
        waits on its own pump threads, and sixteen of those in a row would be
        an operator's Ctrl+C apparently doing nothing."""
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

    Blocking threads rather than one selector over every socket, deliberately.
    Windows' `select()` takes a fixed-size FD_SET (512 by default) and, unlike
    poll/epoll, there is no portable alternative in the standard library —
    sixteen relays of thirty-two connections is 1,024 sockets, which is past
    it before the application's own listener is counted.
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
        # The one address this relay will speak to, normalised the way every
        # other allow list in this application is (a dual-stack listener
        # reports an IPv4 peer as "::ffff:10.0.0.1").
        self.client_ip = client_ip
        # The web session this relay hangs off. A tunnel outlives the request
        # that opened it, so this is what the watchdog re-reads: sign out,
        # expiry or a deleted account must take the tunnel with it.
        self.token = token
        self.url = f"{scheme}://{host}:{port}/"
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
        # Every socket a live connection is using. A pump parked in recv()
        # only notices `_stopped` between chunks, so closing these is what
        # actually ends a relay that a browser is still holding open — and
        # it is why shutdown() can promise a budget at all.
        self._live_sockets: set[socket.socket] = set()
        # Whether a refused source has already been audited: a scanner or a
        # second operator's browser should leave one line, not one per packet.
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
        the bytes are never read, so there is nothing in them to check. That
        is why every other bound on this relay — the window before the first
        connection, the idle close, the permission re-check — matters as much
        as this does.
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
        """One admitted connection: dial the device, then copy in both
        directions until either end hangs up."""
        device = None
        try:
            device = socket.create_connection(
                (self.target_ip, self.target_port), CONNECT_TIMEOUT_S)
            device.settimeout(None)
            client.settimeout(None)
            with self._counter_lock:
                self._live_sockets.update((client, device))
            up = threading.Thread(
                target=self._pump, args=(client, device, True), daemon=True,
                name=f"relay-up-{self.device_id}")
            up.start()
            self._pump(device, client, False)
            up.join(timeout=CONNECT_TIMEOUT_S)
            client.close()   # bounded either way: the up-pump's recv ends here
            up.join(timeout=CONNECT_TIMEOUT_S)
        except OSError:
            # A device that will not answer is reported by the browser as a
            # failed page load, which is what it is; nothing here can render
            # an error into a connection whose protocol it does not read.
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

    def _pump(self, src: socket.socket, dst: socket.socket, to_device: bool) -> None:
        """Copy one direction. The bytes are counted and never looked at:
        this carries whatever the device's web server speaks, TLS included,
        so there is nothing here that could inspect a request even if it
        wanted to."""
        try:
            while not self._stopped.is_set():
                data = src.recv(CHUNK_BYTES)
                if not data:
                    break
                dst.sendall(data)
                self._note_traffic(len(data), to_device)
        except OSError:
            pass
        # Half-close rather than close: the other direction may still have a
        # response to deliver, which is exactly how a browser sending a
        # request body and then waiting behaves.
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        if to_device:
            # The browser hung up; a device that ignores half-close would
            # otherwise hold this connection's slot until the idle timeout.
            threading.Timer(CONNECT_TIMEOUT_S, lambda: _close_quietly(dst)).start()

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
                # This one loop enforces the idle timeout, the first-connect
                # window, sign-out and the permission check; a failed tick
                # must not silently disable all four.
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
        # The listener first: it is what the accept thread is parked on, and
        # closing it is what stops another connection arriving mid-teardown.
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
        event list and the NODES log. Byte counts, never content — there is
        no content here to record, which is the point."""
        try:
            self.service.nodes_db.record_device_event(self.device_id, "web",
                                                      headline)
            self.service.log.add(NODES, headline, target=self.target_ip,
                                 detail=detail)
        except Exception:
            # Shutdown races the databases closing; an audit line lost on the
            # way out is not worth a traceback in the console.
            pass

    def _audit_close(self, reason: str) -> None:
        seconds = max(0, int(time.time() - self.opened_ts))
        spell = f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"
        with self._counter_lock:
            to_device, from_device = self.bytes_to_device, self.bytes_from_device
            total = self.connections_total
        # The counts go in the headline, not only in the log detail: the
        # device's own event list is where an operator looks to see what this
        # tunnel did, and how much crossed is the only thing there is to say
        # about it — the bytes themselves were never read.
        self._audit(
            f"Web tunnel on port {self.port} closed after {spell}"
            + (f" ({reason})" if reason else "")
            + f"; {total} connection(s), {to_device} bytes to the device and "
              f"{from_device} back",
            f"Opened by {self.app_user} from {self.client_ip}.")

"""Interactive SSH sessions for the terminal window — a real shell over a
WebSocket, distinct from ConfigRX's narrow pull-the-config-and-hang-up use.
`SshSessionRegistry` tracks live `SshSession`s (paramiko + a pump thread and
a heartbeat that re-checks authorisation and idle timeout every second).
Credentials/keystrokes are never logged; frames are JSON (control) and
binary (terminal bytes) — see INTERNALS.
"""

from __future__ import annotations

import json
import logging
import threading
import time

from . import configrx, hostkeys, permissions
from .eventlog import NODES

log = logging.getLogger(__name__)

# --------------------------------------------------------------- the limits
#
# Connect timeout: ConfigRX's, for the same reason — a device that has not
# answered the TCP/banner/auth exchange in ten seconds is not reachable, and
# an operator staring at a blank terminal wants to be told so.
CONNECT_TIMEOUT_S = 10
# How long a socket may sit between the 101 and its `open` message. The
# page sends `open` from its `onopen` handler, so this is measured in
# round trips; what it bounds is the other case — a laptop that slept with
# the terminal open, a proxy that dropped the TCP connection without a FIN,
# or a client that never intended to send one. Without it such a socket
# holds its slot against both caps for the life of the process, and four of
# them lock an account out of its own terminals.
HANDSHAKE_TIMEOUT_S = 15
# Idle timeout: no *keystrokes* for this long ends the session (mirrors
# auth.py's SessionStore.touch "presence, not tab open" rule). _watch_tick
# uses whichever of this and the live session_idle_minutes is smaller, so
# raising the web session timeout past this still gets the full 15 minutes.
IDLE_TIMEOUT_S = 900
# Concurrent sessions across the whole application. Each one costs a socket,
# a paramiko transport and three threads; sixteen is far past what a team of
# operators uses at once and well short of anything the process would feel.
MAX_SESSIONS = 16
# And per signed-in account, so one account cannot spend the application-wide
# cap on its own — sixteen sockets that never get past the login prompt would
# otherwise lock every other operator out. Four terminals is more than anyone
# watches at once.
MAX_SESSIONS_PER_USER = 4
# Failed logins allowed per signed-in account and device. Not per socket:
# a socket is free to open, so a per-socket cap is no cap at all — close
# the window, open another, and the counter starts again. Without a real
# one the page is an unthrottled password oracle against every device this
# app can reach; five is the room a mistyped password needs and no more.
# Every failure is audited, and the cap ends the session.
MAX_AUTH_ATTEMPTS = 5
# How long a refused login is remembered against that pair. Once the cap is
# spent the account cannot try this device again until the newest failure
# has aged out, and a new socket is refused before the device is contacted
# at all. Five minutes is a cooling-off an operator who mistyped notices
# and a guessing loop cannot outrun. A successful login clears the count:
# the pair has proved itself, and the operator who fumbled four passwords
# should not be locked out an hour later.
AUTH_FAILURE_WINDOW_S = 300
# How often keystrokes refresh the *web* session. A shell being typed into is
# presence by the same rule server.py applies to a POST, but a touch per
# keystroke would be a write per character; twice a minute is plenty.
TOUCH_INTERVAL_S = 30
# How often the liveness watchdog re-reads the permission (it re-reads the
# web session every tick, which is one dictionary lookup; the permission is a
# database read). Five seconds from revoked to closed.
PERMISSION_EVERY_TICKS = 5

# The SSH username arrives on the socket and is named in the device event
# log; RFC 4253 sets no length, but nothing real is longer than this.
MAX_USERNAME_CHARS = 128

# Consecutive watchdog permission reads that may fail before the shell is
# closed anyway. A database that cannot answer is not a verdict — but it is
# not an indefinite reprieve either, and at one read every
# PERMISSION_EVERY_TICKS seconds this is about a minute.
MAX_PERMISSION_ERRORS = 12
# How long `SshSessionRegistry.shutdown()` may take in total — for every
# session, not for each one. Sessions are stopped concurrently inside it:
# stopping one takes its socket's I/O lock, which its own output pump can
# be holding for up to wsock.SEND_TIMEOUT_S against a browser that stopped
# reading, and sixteen of those in a row is four minutes of an operator's
# Ctrl+C apparently doing nothing while the poller and the databases wait.
SHUTDOWN_BUDGET_S = 3.0
# The grace after the budget in which sockets that were shut down by force
# — which takes no lock, and is what fails a parked write at once — are
# given to finish and let go of their slots.
SHUTDOWN_GRACE_S = 0.5
# The largest terminal output frame. Channel reads are capped at this, so a
# device dumping a 4 MB `show tech-support` arrives as a stream of frames a
# browser can render as it goes rather than one it must buffer whole.
MAX_OUTPUT_BYTES = 64 * 1024

# Close codes, matching the page's own table.
CLOSE_NORMAL = 1000
CLOSE_UNAUTHORIZED = 4401
CLOSE_IDLE = 4408
CLOSE_TOO_MANY = 4429

_MAX_COLS = 500
_MAX_ROWS = 300

# wsock's opcodes, restated rather than imported: netpath.web imports the
# Service, which imports this module, so importing back into netpath.web
# here would close the circle at start-up.
_OP_TEXT = 0x1
_OP_BINARY = 0x2

# The control messages a person has to produce, and so the only ones that
# count as presence. `resize` is not one of them: a window manager nudging
# a page nobody is watching sends it, and IDLE_TIMEOUT_S is about
# keystrokes — see its comment.
_INPUT_TYPES = ("open", "auth", "trust")


def _int_in(value, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def stored_host_key(service, host: str, port: int) -> dict | None:
    """What the shared store holds for this device, as plain JSON-able
    fields, or None."""
    row = hostkeys.HostKeyStore(service.configrx_db).stored(host, port)
    if not row:
        return None
    return {"fingerprint": row["fingerprint"], "key_type": row["key_type"],
            "first_seen_ts": row["first_seen_ts"]}


class SshSessionRegistry:
    """Every live terminal session, so shutdown can end them and the cap can
    be enforced. Sessions add and remove themselves; nothing else touches
    the set."""

    def __init__(self, service):
        self.service = service
        self._lock = threading.Lock()
        self._sessions: set = set()
        self._stopping = False
        # Handed from begin_stop() to finish_stop(); empty at every other
        # moment, so a teardown that never reaches finish_stop leaks nothing.
        self._stoppers: list[threading.Thread] = []
        self._closing: list = []
        # Refused logins, keyed by (app user, device id) rather than by
        # socket — see MAX_AUTH_ATTEMPTS. Each entry is the timestamps still
        # inside the window (at most the cap's worth is kept) and whether the
        # refusal that follows has already been audited, so a client that
        # reconnects in a loop leaves one line rather than one per socket.
        # Entries whose failures have all aged out are dropped, so this does
        # not grow with the devices an account has ever mistyped a password
        # for.
        self._auth_failures: dict = {}

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def open(self, ws, device_id: int, username: str, client_ip: str,
             token: str = "") -> None:
        """Run one session to completion on the calling thread (the request
        handler's own thread, which has nothing else to do until the socket
        closes). `token` is the web session this terminal belongs to: the
        session watches it, and ends when it does."""
        session = SshSession(self, ws, device_id, username, client_ip, token)
        with self._lock:
            if self._stopping:
                ws.close(CLOSE_NORMAL, "Server shutting down")
                return
            mine = sum(1 for live in self._sessions
                       if live.app_user == session.app_user)
            if len(self._sessions) >= MAX_SESSIONS:
                self._refuse(ws, f"There are already {MAX_SESSIONS} SSH sessions "
                                 f"open. Close one and try again.")
                return
            if mine >= MAX_SESSIONS_PER_USER:
                self._refuse(ws, f"You already have {MAX_SESSIONS_PER_USER} SSH "
                                 f"sessions open. Close one and try again.")
                return
            self._sessions.add(session)
        try:
            session.run()
        finally:
            with self._lock:
                self._sessions.discard(session)

    # ------------------------------------------------------ refused logins

    def _fresh_failures(self, key) -> list:
        """The failure times still inside the window for one (account,
        device) pair, dropping every entry — this one included — that has
        aged out entirely. Called under the lock."""
        now = time.time()
        spent = []
        for other, entry in self._auth_failures.items():
            entry["times"] = [when for when in entry["times"]
                              if now - when < AUTH_FAILURE_WINDOW_S]
            if not entry["times"]:
                spent.append(other)
        for other in spent:
            del self._auth_failures[other]
        entry = self._auth_failures.get(key)
        return entry["times"] if entry else []

    def record_auth_failure(self, app_user: str, device_id: int) -> int:
        """Count one refused login against this account and device, and
        return how many now stand within the window. That number is what
        the audit line says, so a pattern spread over several sockets reads
        as one run of attempts rather than as five ones."""
        key = (app_user or "", int(device_id))
        with self._lock:
            times = self._fresh_failures(key)
            times.append(time.time())
            del times[:-MAX_AUTH_ATTEMPTS]      # only the cap's worth matters
            self._auth_failures[key] = {"times": times, "announced": False}
            return len(times)

    def clear_auth_failures(self, app_user: str, device_id: int) -> None:
        """A login this device accepted: the pair has proved itself."""
        with self._lock:
            self._auth_failures.pop((app_user or "", int(device_id)), None)

    def auth_cooldown(self, app_user: str, device_id: int) -> tuple[float, bool]:
        """How long this account must wait before trying this device again,
        and whether this refusal is the first to be audited — a client
        reconnecting in a loop should leave one line, not one per socket.
        (0.0, False) when there is nothing to wait for."""
        key = (app_user or "", int(device_id))
        with self._lock:
            times = self._fresh_failures(key)
            if len(times) < MAX_AUTH_ATTEMPTS:
                return 0.0, False
            left = max(0.0, AUTH_FAILURE_WINDOW_S - (time.time() - times[-1]))
            entry = self._auth_failures[key]
            first = not entry["announced"]
            entry["announced"] = True
            return left, first

    @staticmethod
    def _refuse(ws, message: str) -> None:
        """Say why, then close with the code the page's table calls "too
        many" — whichever of the two caps was reached."""
        ws.send_text(json.dumps({"type": "error", "message": message}))
        ws.close(CLOSE_TOO_MANY, "Too many SSH sessions")

    def shutdown(self) -> None:
        """End every session before the databases close (a running session
        writes a closing device event). Concurrent, under one shared budget —
        serially, sixteen sessions each blocked on a stuck socket would be
        minutes; anything still live when the budget runs out is force-closed.
        """
        self.begin_stop()
        self.finish_stop(time.monotonic() + SHUTDOWN_BUDGET_S)

    def begin_stop(self) -> None:
        """Start closing every session and return at once. The stoppers run
        on threads of their own, so by the time finish_stop() waits they have
        already been closing for however long the rest of the teardown took.

        Idempotent, and it has to be: Service.shutdown() signals every
        subsystem, waits out any restart still queued, then signals again —
        and a second pass that re-snapshotted the sessions would replace the
        stopper threads the first pass launched, leaving finish_stop() with
        nothing to wait for.
        """
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            live = list(self._sessions)
        self._closing = live
        self._stoppers = [
            threading.Thread(target=session.stop,
                             args=("The server is shutting down",),
                             name=f"ssh-stop-{session.device_id}", daemon=True)
            for session in live]
        for thread in self._stoppers:
            thread.start()

    def finish_stop(self, deadline: float) -> None:
        """Wait for the stoppers begin_stop() launched, until `deadline` (a
        time.monotonic() value); anything still live past it is force-closed
        with unblock() and given SHUTDOWN_GRACE_S to notice."""
        stoppers, self._stoppers = self._stoppers, []
        live, self._closing = self._closing, []
        for thread in stoppers:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self.count:
            for session in live:
                session.unblock()
            deadline += SHUTDOWN_GRACE_S
        while time.monotonic() < deadline and self.count:
            time.sleep(0.05)


class SshSession:
    def __init__(self, registry: SshSessionRegistry, ws, device_id: int,
                 username: str, client_ip: str, token: str = ""):
        self.registry = registry
        self.service = registry.service
        self.ws = ws
        self.device_id = device_id
        self.app_user = username or ""
        self.client_ip = client_ip or ""
        # The web session this terminal hangs off. A shell outlives the
        # request that opened it, so this is what the watchdog re-reads:
        # sign out, expiry or a deleted account must take the shell with it.
        self.token = token or ""
        self.host = ""
        self.port = 22
        self.cols = 80
        self.rows = 24
        self.client = None
        self.channel = None
        self._stopped = threading.Event()
        self._stop_lock = threading.Lock()
        # When the slot was taken (the 101 has already been answered), and
        # whether the `open` message that turns it into a session has
        # arrived. The handshake deadline is measured from the first and
        # closed by the second — from the upgrade, not from the last frame,
        # so a client that sends anything else forever still gives the slot
        # back.
        self._started_at = time.time()
        self._open_seen = False
        # Whether the watchdog has already reported a failed tick; one line
        # per session, not one a second.
        self._watch_failed = False
        # Consecutive permission reads that raised, so failing open has an end.
        self._permission_errors = 0
        self._last_input = time.time()
        self._last_touch = 0.0
        self._auth_failures = 0
        self._opened_at = 0.0
        self._audited_open = False
        # The credential in play. `_password` is held only between the page
        # sending it (or ConfigRX's being decrypted) and the connect that
        # uses it, and is dropped in the `finally` of that connect.
        self._username = ""
        self._password: str | None = None
        self._credential_from_store = False

    # ------------------------------------------------------------ messaging

    def _send(self, payload: dict) -> None:
        self.ws.send_text(json.dumps(payload))

    def _status(self, state: str, message: str = "") -> None:
        self._send({"type": "status", "state": state, "message": message})

    def _error(self, message: str) -> None:
        self._send({"type": "error", "message": message})

    def _next_control(self) -> dict | None:
        """The next JSON control message. Terminal bytes arriving before the
        shell exists are discarded: they are whatever the operator typed at
        a terminal that is not connected to anything yet."""
        while not self._stopped.is_set():
            message = self.ws.recv()
            if message is None:
                return None
            opcode, payload = message
            if opcode != _OP_TEXT:
                continue
            try:
                decoded = json.loads(payload.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(decoded, dict):
                # Only a message somebody had to type refreshes the idle
                # timer; a `resize` arriving on its own is traffic, not
                # presence.
                if decoded.get("type") in _INPUT_TYPES:
                    self._last_input = time.time()
                return decoded
        return None

    # ----------------------------------------------------------------- run

    def run(self) -> None:
        # The watchdog starts here, not once a shell exists: from this line
        # on the session is counted against both caps, and everything that
        # bounds a terminal's life — the handshake deadline, the sign-out
        # check and the permission check — has to cover the window before
        # `open` as well. A shell can be waiting in that window across a
        # sign-out, and a socket that never sends `open` used to hold its
        # slot, its thread and its authorisation for the life of the
        # process.
        watchdog = threading.Thread(target=self._idle_watch,
                                    name=f"ssh-idle-{self.device_id}",
                                    daemon=True)
        watchdog.start()
        try:
            self._run()
        except Exception as exc:                     # never leak a traceback
            self._error(f"SSH session failed: {exc}")
        finally:
            self.stop()
            self._audit_close()

    def _run(self) -> None:
        device = self.service.nodes_db.device(self.device_id)
        if not device:
            self._error("No such device")
            self.ws.close(CLOSE_NORMAL, "No such device")
            return
        self.host = device["ip"]

        # Wait for `open`, applying any `resize` that overtakes it. The page
        # measures its terminal as it opens the socket, and a notice
        # appearing between the two (a device with no stored credential says
        # so) changes that measurement — so the size can legitimately arrive
        # first. Anything else before `open` is discarded.
        while True:
            opening = self._next_control()
            if not opening:
                self.ws.close(CLOSE_NORMAL, "No open message")
                return
            kind = opening.get("type")
            if kind in ("open", "resize"):
                self.cols = _int_in(opening.get("cols"), 20, _MAX_COLS, self.cols)
                self.rows = _int_in(opening.get("rows"), 5, _MAX_ROWS, self.rows)
            if kind == "open":
                self._open_seen = True       # the handshake deadline is met
                break

        if not configrx.paramiko_available():
            self._error(configrx.PARAMIKO_MISSING)
            self.ws.close(CLOSE_NORMAL, "paramiko missing")
            return

        config = self.service.configrx_db.device_config(self.device_id)
        self.port = _int_in(config["ssh_port"] if config else 22, 1, 65535, 22)
        reason = self._load_stored_credential(config)

        while not self._stopped.is_set():
            # Checked before the credentials are even asked for, so a socket
            # opened after the cap was spent — this one or any other — is
            # refused without the device hearing about it.
            cooling, first = self.registry.auth_cooldown(self.app_user,
                                                         self.device_id)
            if cooling > 0:
                self._refuse_after_failures(cooling, first)
                return
            if self._password is None:
                if not self._ask_for_credentials(reason):
                    return

            outcome, detail = self._connect()
            if outcome == "connected":
                self._shell()
                return
            if outcome == "auth-failed":
                if self._auth_failures >= MAX_AUTH_ATTEMPTS:
                    self._error("Too many failed logins")
                    self.ws.close(CLOSE_NORMAL, "Too many failed logins")
                    return
                reason = "auth-failed"
                continue
            if outcome == "changed":
                if not self._await_trust(detail):
                    return
                continue
            return                                    # reported already

    def _refuse_after_failures(self, seconds: float, announce: bool) -> None:
        """This account is locked out on this device. Close 4429 and audit
        the refusal once per cooling-off period, not once per reconnect."""
        minutes = max(1, -(-int(seconds) // 60))
        self._error(f"Too many failed logins for this device. Try again in "
                    f"about {minutes} minute(s).")
        if announce:
            self._audit(
                f"SSH login refused before it was attempted: "
                f"{MAX_AUTH_ATTEMPTS} recent failures for {self.app_user} "
                f"on this device (from {self.client_ip})",
                f"No connection was made; about {minutes} minute(s) to wait.")
        self.ws.close(CLOSE_TOO_MANY, "Too many failed logins")

    def _ask_for_credentials(self, reason: str) -> bool:
        """Ask the page for a username and password and wait for them.
        False when the socket closed instead of answering."""
        self._send({"type": "need-credentials", "reason": reason,
                    "username": self._username})
        while True:
            message = self._next_control()
            if not message:
                return False
            if message.get("type") != "auth":
                continue
            # Clamped before it can reach an event-log row: a WebSocket text
            # frame may be MAX_MESSAGE_BYTES (2 MiB) and _audit_auth_failure
            # names the username that was tried. No account name is longer.
            username = str(message.get("username", "") or "")[:MAX_USERNAME_CHARS]
            if not username:
                self._error("A username is required.")
                continue
            self._username = username
            self._password = str(message.get("password", "") or "")
            self._credential_from_store = False
            return True

    def _load_stored_credential(self, config) -> str:
        """ConfigRX's credential for this device, if it has one. Returns the
        `need-credentials` reason when there is nothing usable — the page
        then asks the operator."""
        if not config or not config["ssh_username"] or not config["ssh_password_enc"]:
            self._username = (config["ssh_username"] if config else "") or ""
            return "none-stored"
        self._username = config["ssh_username"]
        from . import dpapi
        try:
            self._password = dpapi.unprotect(
                bytes(config["ssh_password_enc"])).decode("utf-8")
        except Exception:
            self._password = None
            return "decrypt-failed"
        self._credential_from_store = True
        return ""

    # ------------------------------------------------------------- connect

    def _connect(self) -> tuple[str, object]:
        """One connect attempt. Returns (outcome, detail) where outcome is
        'connected', 'auth-failed', 'changed' (detail is a
        `hostkeys.HostKeyChanged`) or 'failed' (already reported to the
        page)."""
        import paramiko

        self._status("connecting", f"Connecting to {self.host}:{self.port}…")
        store = hostkeys.HostKeyStore(self.service.configrx_db)
        client = paramiko.SSHClient()
        try:
            store.prepare(client, self.host, self.port)
        except Exception:
            pass
        policy = store.policy(self.host, self.port)
        client.set_missing_host_key_policy(policy)

        # The plaintext lives in a local for the length of the connect and
        # is dropped in the `finally` below, exactly as ConfigRX's backup
        # path does it. `self._password` is cleared the moment the attempt
        # resolves — the one exception is a changed host key, where the
        # operator's answer is about the device's identity, not about their
        # password, and re-typing it after clicking Trust would be theatre.
        password = self._password
        try:
            client.connect(
                self.host, port=self.port, username=self._username,
                password=password, timeout=CONNECT_TIMEOUT_S,
                banner_timeout=CONNECT_TIMEOUT_S, auth_timeout=CONNECT_TIMEOUT_S,
                look_for_keys=False, allow_agent=False)
        except (hostkeys.HostKeyChanged, paramiko.BadHostKeyException) as exc:
            # Either the policy refused a key that differs from the stored
            # one, or — when `prepare` had loaded that key into the client —
            # paramiko refused the handshake itself before the policy was
            # ever consulted. The store maps both to one exception, so there
            # is one shape to send and one path to `trust`.
            client.close()
            return "changed", store.as_changed(exc, self.host, self.port)
        except paramiko.AuthenticationException:
            client.close()
            self._password = None
            self._audit_auth_failure()
            if self._credential_from_store:
                self._error("The SSH credential stored in ConfigRX for this "
                            "device was refused.")
            else:
                self._error("Authentication failed.")
            self._credential_from_store = False
            return "auth-failed", None
        except Exception as exc:
            client.close()
            self._password = None
            self._error(configrx._connect_error_text(exc))
            return "failed", None
        finally:
            password = None

        self._password = None
        self.client = client
        # "This same key was presented again just now" — the store's own
        # usage contract, which ConfigRX's backup path already follows. The
        # policy touches the row only on the path where `prepare` could not
        # rebuild the stored key; on the ordinary one paramiko checks the
        # key itself and the policy is never reached, so without this a
        # device that is SSHed to daily but never backed up shows a
        # last_seen_ts frozen at its first connection — which the ConfigRX
        # dialog reads as a key nobody has confirmed since it was pinned.
        try:
            store.record_seen(self.host, self.port)
        except Exception:
            pass                     # a sighting lost is not a failed connect
        # The policy is the only thing that knows whether this was a first
        # sighting: it is what stored the key, and it kept the fingerprint.
        if policy.stored_new:
            self._send({"type": "hostkey", "event": "new",
                        "key_type": policy.stored_type,
                        "fingerprint": policy.stored_new})
        try:
            self.channel = client.invoke_shell(
                term="xterm-256color", width=self.cols, height=self.rows)
        except Exception as exc:
            self._error(f"Could not open a shell on {self.host}: {exc}")
            client.close()
            self.client = None
            return "failed", None
        self.channel.settimeout(None)
        # The device accepted this account's credential, so the refused
        # logins standing against the pair are spent: an operator who
        # fumbled four passwords and then got in must not be locked out an
        # hour later by the count they left behind.
        self.registry.clear_auth_failures(self.app_user, self.device_id)
        self._status("connected", f"Connected to {self.host}:{self.port}")
        self._audit_open()
        return "connected", None

    def _await_trust(self, change: hostkeys.HostKeyChanged) -> bool:
        """Tell the page the key changed and wait for its answer. True when
        the operator trusted the new key and a reconnect should follow."""
        self._send({"type": "hostkey", "event": "changed",
                    "key_type": change.key_type,
                    "fingerprint": change.new_fingerprint,
                    "old_fingerprint": change.old_fingerprint,
                    "old_first_seen": change.old_first_seen})
        while True:
            message = self._next_control()
            if not message:
                return False
            if message.get("type") != "trust":
                continue
            granted = self.service.app_db.permissions_for(self.app_user).get("ssh")
            if not permissions.allows(granted, permissions.WRITE):
                self._error("Trusting a changed host key needs SSH write access.")
                self.ws.close(CLOSE_UNAUTHORIZED, "No SSH write access")
                return False
            if change.new_key is None:
                self._error("The new host key is no longer available — "
                            "reconnect and try again.")
                return False
            store = hostkeys.HostKeyStore(self.service.configrx_db)
            store.trust(self.host, self.port, change.new_key, self.app_user)
            self.service.nodes_db.record_device_event(
                self.device_id, "ssh",
                f"SSH host key replaced by {self.app_user} "
                f"({change.old_fingerprint} → {change.new_fingerprint})")
            self.service.log.add(
                NODES, f"SSH host key for {self.host} trusted by {self.app_user}",
                target=self.host,
                detail=f"Was {change.old_fingerprint}, now "
                       f"{change.new_fingerprint} ({change.key_type}).")
            return True

    # --------------------------------------------------------------- shell

    def _shell(self) -> None:
        pump = threading.Thread(target=self._pump,
                                name=f"ssh-out-{self.device_id}", daemon=True)
        pump.start()
        while not self._stopped.is_set():
            message = self.ws.recv()
            if message is None:
                break
            opcode, payload = message
            if opcode == _OP_BINARY:                 # keystrokes
                # The idle timer is refreshed here and nowhere else in this
                # loop: a shell is ended by nobody *typing* at it, and a
                # `resize` from a window a monitor nudged is not somebody
                # typing. Otherwise a root shell on a core switch stays open
                # for as long as any client keeps sending anything at all.
                self._last_input = time.time()
                self._touch_web_session()
                try:
                    self.channel.sendall(payload)
                except Exception:
                    break
                continue
            try:
                control = json.loads(payload.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(control, dict):
                continue
            if control.get("type") == "resize":
                self.cols = _int_in(control.get("cols"), 20, _MAX_COLS, self.cols)
                self.rows = _int_in(control.get("rows"), 5, _MAX_ROWS, self.rows)
                try:
                    self.channel.resize_pty(width=self.cols, height=self.rows)
                except Exception:
                    pass
        self.stop()

    def _touch_web_session(self) -> None:
        """Someone is typing, so the web session is not idle either. Rate-
        limited — a shell is a lot of keystrokes and each touch costs a lock
        and a clock read."""
        now = time.time()
        if not self.token or now - self._last_touch < TOUCH_INTERVAL_S:
            return
        self._last_touch = now
        try:
            self.service.sessions.touch(self.token)
        except Exception:
            pass

    def _pump(self) -> None:
        """Channel → socket. Ends when the device hangs up, which is also
        how a `logout` closes the browser's terminal."""
        channel = self.channel
        try:
            while not self._stopped.is_set():
                data = channel.recv(MAX_OUTPUT_BYTES)
                if not data:
                    break
                if not self.ws.send_binary(data):
                    break
        except Exception:
            pass
        if not self._stopped.is_set():
            self._status("closed", "The device closed the session")
            self.stop()

    # ---------------------------------------------------------------- idle

    def _idle_watch(self) -> None:
        """Once a second: still signed in, still holds `ssh` write, socket
        past its `open` message, anyone typed lately. Authorisation is not
        settled once at the upgrade — a shell can outlive the sign-in that
        opened it by hours."""
        ticks = 0
        while not self._stopped.wait(1.0):
            ticks += 1
            try:
                if self._watch_tick(ticks):
                    return
            except Exception:
                # This one loop enforces the idle timeout, sign-out and permission
                # checks; a failed tick must not silently disable all three.
                if not self._watch_failed:
                    self._watch_failed = True
                    log.exception("The SSH session watchdog for device %s "
                                  "failed a tick; it keeps running",
                                  self.device_id)

    def _effective_idle_s(self) -> float:
        """IDLE_TIMEOUT_S, capped to the live web session timeout — a shell
        must not advertise a window longer than the login containing it."""
        if not self.token:
            return IDLE_TIMEOUT_S
        return min(IDLE_TIMEOUT_S, self.service.sessions.idle_seconds)

    def _watch_tick(self, ticks: int) -> bool:
        """One beat of the watchdog. True when the session is over and the
        loop should end."""
        # Checked ahead of sign-out/permission below, and only once a shell
        # exists, so a terminal timeout reads as itself rather than as "you
        # were signed out" when both would otherwise fire the same tick.
        if self._open_seen:
            effective_idle_s = self._effective_idle_s()
            if time.time() - self._last_input >= effective_idle_s:
                minutes = max(1, round(effective_idle_s / 60))
                self._status("closed", f"Closed after {minutes} minute(s) idle")
                self.ws.close(CLOSE_IDLE, f"Idle timeout ({minutes}m)")
                self.stop()
                return True
        if self.token and self.service.sessions.get(self.token) is None:
            self._end_unauthorized(
                "You were signed out",
                f"SSH session closed: {self.app_user} is no longer signed in")
            return True
        if ticks % PERMISSION_EVERY_TICKS == 0 and not self._has_ssh_write():
            self._end_unauthorized(
                "SSH access was revoked",
                f"SSH session closed: {self.app_user} no longer holds "
                f"SSH write access")
            return True
        # Read the module globals each time: the tests shorten them, and
        # operator-facing constants are worth being able to change.
        if not self._open_seen:
            if time.time() - self._started_at < HANDSHAKE_TIMEOUT_S:
                return False
            self._status("closed", f"No terminal was opened within "
                                   f"{int(HANDSHAKE_TIMEOUT_S)} seconds")
            self.ws.close(CLOSE_IDLE, "Handshake timeout")
            self.stop()
            return True
        return False

    def _has_ssh_write(self) -> bool:
        try:
            granted = self.service.app_db.permissions_for(self.app_user).get("ssh")
        except Exception:
            # A database that cannot answer is not a verdict — for a while.
            # Failing open forever would mean a revoked grant never ends a
            # live shell, which is the one thing this check exists to do.
            self._permission_errors += 1
            if self._permission_errors < MAX_PERMISSION_ERRORS:
                return True
            if self._permission_errors == MAX_PERMISSION_ERRORS:
                log.warning("Cannot read SSH permissions for %s after %d "
                            "attempts; closing the session",
                            self.app_user, self._permission_errors)
            return False
        self._permission_errors = 0
        return permissions.allows(granted, permissions.WRITE)

    def _end_unauthorized(self, message: str, audit: str) -> None:
        """The shell is no longer authorised: say so on the socket, close
        4401 — the code the page's table already means "not authorised" —
        and leave a line saying why."""
        self._status("closed", message)
        self.ws.close(CLOSE_UNAUTHORIZED, message)
        self._audit(audit, f"{message} ({self.app_user} from {self.client_ip}).")
        self.stop()

    # --------------------------------------------------------------- close

    def unblock(self) -> None:
        """Shut the socket down without taking its I/O lock, so a thread
        parked in a send or a read fails at once. The last resort of
        `SshSessionRegistry.shutdown()`: it costs the operator the closing
        notice on the page, which is why it is not the first."""
        try:
            self.ws.unblock()
        except Exception:
            pass

    def stop(self, message: str = "") -> None:
        with self._stop_lock:
            if self._stopped.is_set():
                return
            self._stopped.set()
        if message:
            try:
                self._status("closed", message)
            except Exception:
                pass
        for closeable in (self.channel, self.client):
            try:
                if closeable is not None:
                    closeable.close()
            except Exception:
                pass
        try:
            self.ws.close(CLOSE_NORMAL, "Session ended")
        except Exception:
            pass

    # -------------------------------------------------------------- audit

    def _audit(self, headline: str, detail: str) -> None:
        """One line in both places the terminal is audited: the device's own
        event list and the NODES log. Never a password, never a keystroke."""
        try:
            self.service.nodes_db.record_device_event(self.device_id, "ssh",
                                                      headline)
            self.service.log.add(NODES, headline, target=self.host, detail=detail)
        except Exception:
            # Shutdown races the database closing; an audit line lost on the
            # way out is not worth a traceback in the console.
            pass

    def _audit_auth_failure(self) -> None:
        """A refused login, counted and recorded. The SSH username is named
        (it is what was tried), the password never is — and the count is
        what turns a stream of these into something an operator can see.
        The count comes from the registry, keyed by account and device, so
        it does not start again with every new socket."""
        self._auth_failures = self.registry.record_auth_failure(
            self.app_user, self.device_id)
        self._audit(
            f"SSH login as {self._username or '(no user)'} refused "
            f"(attempt {self._auth_failures} of {MAX_AUTH_ATTEMPTS}; requested "
            f"by {self.app_user} from {self.client_ip})",
            f"Attempt {self._auth_failures} of {MAX_AUTH_ATTEMPTS} on "
            f"port {self.port}.")

    def _audit_open(self) -> None:
        if self._audited_open:
            return
        self._audited_open = True
        self._opened_at = time.time()
        detail = (f"SSH session opened by {self.app_user} from {self.client_ip}")
        self.service.nodes_db.record_device_event(self.device_id, "ssh", detail)
        self.service.log.add(NODES, f"SSH session to {self.host} opened by "
                                    f"{self.app_user}", target=self.host,
                             detail=f"From {self.client_ip}, "
                                    f"port {self.port}, user {self._username}.")

    def _audit_close(self) -> None:
        if not self._audited_open:
            return
        seconds = max(0, int(time.time() - self._opened_at))
        spell = f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"
        try:
            self.service.nodes_db.record_device_event(
                self.device_id, "ssh",
                f"SSH session closed after {spell} "
                f"(opened by {self.app_user} from {self.client_ip})")
            self.service.log.add(
                NODES, f"SSH session to {self.host} closed after {spell}",
                target=self.host, detail=f"Opened by {self.app_user} "
                                         f"from {self.client_ip}.")
        except Exception:
            # Shutdown races the database closing; an audit line lost on the
            # way out is not worth a traceback in the console.
            pass

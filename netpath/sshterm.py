"""Interactive SSH sessions for the terminal window.

ConfigRX already opens SSH connections to these devices, but for one narrow
purpose: log in, turn the pager off, ask for the running config, hang up.
That boundary is deliberate and stays where it is (see configrx._pull_config).
This module is the other thing entirely — a real shell, whatever the operator
types, driven from a browser tab over a WebSocket.

The shape:

* One `SshSessionRegistry` on the Service, holding the live sessions so the
  application can end them on shutdown and refuse the seventeenth.
* One `SshSession` per socket, owning the paramiko client and the shell
  channel. Two threads: the request handler's own thread reads the WebSocket
  and writes keystrokes into the channel; a pump thread reads channel output
  and writes binary frames back. A third, tiny, timer thread hangs up on an
  idle session.
* The credential is ConfigRX's stored one for that device when there is one
  — decrypted at connect time and dropped immediately, exactly as the backup
  path does — and otherwise typed into the page and sent once over the
  socket. Neither is stored by this module, written to any log, or included
  in any event or error text. Keystrokes are never logged either: what is
  audited is that a session happened, by whom, from where, and for how long.
* Host keys come from the shared store (hostkeys.HostKeyStore, also used by
  ConfigRX backups). First connection stores the key and says so; a changed
  key refuses the connection and offers the operator both fingerprints.

The protocol these frames carry is documented in INTERNALS; the short
version is JSON text frames for control, binary frames for terminal bytes,
in both directions.
"""

from __future__ import annotations

import json
import threading
import time

from . import configrx, hostkeys, permissions
from .eventlog import NODES

# --------------------------------------------------------------- the limits
#
# Connect timeout: ConfigRX's, for the same reason — a device that has not
# answered the TCP/banner/auth exchange in ten seconds is not reachable, and
# an operator staring at a blank terminal wants to be told so.
CONNECT_TIMEOUT_S = 10
# Idle timeout: no *keystrokes* for this long ends the session, mirroring
# the web session's own "presence, not the tab being open" rule (auth.py's
# SessionStore.touch). A shell left open on a switch overnight is a real
# risk; a shell being watched is never idle for a quarter of an hour.
IDLE_TIMEOUT_S = 900
# Concurrent sessions across the whole application. Each one costs a socket,
# a paramiko transport and three threads; sixteen is far past what a team of
# operators uses at once and well short of anything the process would feel.
MAX_SESSIONS = 16
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


def _int_in(value, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def fingerprint(key) -> str:
    """The store's fingerprint spelling, so one connection is described the
    same way everywhere."""
    return hostkeys.fingerprint(key)


class _KeyChange:
    """A host key that no longer matches what is on file, however we found
    out: the store's own `HostKeyChanged`, or paramiko's
    `BadHostKeyException` when the stored key was loaded into the client and
    the handshake refused it. Both become this, so the protocol has one
    shape to send and one path to `trust`."""

    def __init__(self, old_fingerprint: str, new_fingerprint: str,
                 key_type: str, old_first_seen, new_key):
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        self.key_type = key_type
        self.old_first_seen = old_first_seen
        self.new_key = new_key


def stored_host_key(service, host: str, port: int) -> dict | None:
    """What the shared store holds for this device, as plain JSON-able
    fields, or None. Tolerant of a store that keeps its keys somewhere this
    function does not know about — the terminal page shows this as an
    informational line, and not having it is not a failure."""
    try:
        store = hostkeys.HostKeyStore(service.configrx_db)
        record = None
        if hasattr(store, "record"):
            record = store.record(host, port)
        elif hasattr(service.configrx_db, "host_key"):
            record = service.configrx_db.host_key(host, port)
        if not record:
            return None
        return {"fingerprint": record["fingerprint"],
                "key_type": record["key_type"],
                "first_seen_ts": record["first_seen_ts"]}
    except Exception:
        return None


class SshSessionRegistry:
    """Every live terminal session, so shutdown can end them and the cap can
    be enforced. Sessions add and remove themselves; nothing else touches
    the set."""

    def __init__(self, service):
        self.service = service
        self._lock = threading.Lock()
        self._sessions: set = set()
        self._stopping = False

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def open(self, ws, device_id: int, username: str, client_ip: str) -> None:
        """Run one session to completion on the calling thread (the request
        handler's own thread, which has nothing else to do until the socket
        closes)."""
        session = SshSession(self, ws, device_id, username, client_ip)
        with self._lock:
            if self._stopping:
                ws.close(CLOSE_NORMAL, "Server shutting down")
                return
            if len(self._sessions) >= MAX_SESSIONS:
                ws.send_text(json.dumps({
                    "type": "error",
                    "message": f"There are already {MAX_SESSIONS} SSH sessions "
                               f"open. Close one and try again."}))
                ws.close(CLOSE_TOO_MANY, "Too many SSH sessions")
                return
            self._sessions.add(session)
        try:
            session.run()
        finally:
            with self._lock:
                self._sessions.discard(session)

    def shutdown(self) -> None:
        """End every session. Called before the databases close, because a
        session that is still running will write a closing device event."""
        with self._lock:
            self._stopping = True
            live = list(self._sessions)
        for session in live:
            session.stop("The server is shutting down")
        deadline = time.time() + 3.0
        while time.time() < deadline and self.count:
            time.sleep(0.05)


class SshSession:
    def __init__(self, registry: SshSessionRegistry, ws, device_id: int,
                 username: str, client_ip: str):
        self.registry = registry
        self.service = registry.service
        self.ws = ws
        self.device_id = device_id
        self.app_user = username or ""
        self.client_ip = client_ip or ""
        self.host = ""
        self.port = 22
        self.cols = 80
        self.rows = 24
        self.client = None
        self.channel = None
        self._stopped = threading.Event()
        self._stop_lock = threading.Lock()
        self._last_input = time.time()
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
                self._last_input = time.time()
                return decoded
        return None

    # ----------------------------------------------------------------- run

    def run(self) -> None:
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

        opening = self._next_control()
        if not opening or opening.get("type") != "open":
            self.ws.close(CLOSE_NORMAL, "No open message")
            return
        self.cols = _int_in(opening.get("cols"), 20, _MAX_COLS, 80)
        self.rows = _int_in(opening.get("rows"), 5, _MAX_ROWS, 24)

        if not configrx.paramiko_available():
            self._error(configrx.PARAMIKO_MISSING)
            self.ws.close(CLOSE_NORMAL, "paramiko missing")
            return

        config = self.service.configrx_db.device_config(self.device_id)
        self.port = _int_in(config["ssh_port"] if config else 22, 1, 65535, 22)
        reason = self._load_stored_credential(config)

        idler = threading.Thread(target=self._idle_watch,
                                 name=f"ssh-idle-{self.device_id}", daemon=True)
        idler.start()

        while not self._stopped.is_set():
            if self._password is None:
                if not self._ask_for_credentials(reason):
                    return

            outcome, detail = self._connect()
            if outcome == "connected":
                self._shell()
                return
            if outcome == "auth-failed":
                reason = "auth-failed"
                continue
            if outcome == "changed":
                if not self._await_trust(detail):
                    return
                continue
            return                                    # reported already

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
            username = str(message.get("username", "") or "")
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
        'connected', 'auth-failed', 'changed' (detail is a _KeyChange) or
        'failed' (already reported to the page)."""
        import paramiko

        self._status("connecting", f"Connecting to {self.host}:{self.port}…")
        store = hostkeys.HostKeyStore(self.service.configrx_db)
        client = paramiko.SSHClient()
        try:
            store.prepare(client, self.host, self.port)
        except Exception:
            pass
        known_before = self._known_host_key(client)
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
        except hostkeys.HostKeyChanged as exc:
            client.close()
            return "changed", _KeyChange(
                getattr(exc, "old_fingerprint", ""),
                getattr(exc, "new_fingerprint", ""),
                getattr(exc, "key_type", ""),
                getattr(exc, "old_first_seen", None),
                getattr(exc, "new_key", None))
        except paramiko.BadHostKeyException as exc:
            # The stored key was loaded into the client, so paramiko refused
            # the handshake itself before the policy was ever consulted.
            client.close()
            record = stored_host_key(self.service, self.host, self.port) or {}
            return "changed", _KeyChange(
                record.get("fingerprint") or fingerprint(exc.expected_key),
                fingerprint(exc.key), exc.key.get_name(),
                record.get("first_seen_ts"), exc.key)
        except paramiko.AuthenticationException:
            client.close()
            self._password = None
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
        if not known_before:
            key = self._remote_key(client)
            if key is not None:
                self._send({"type": "hostkey", "event": "new",
                            "key_type": key.get_name(),
                            "fingerprint": fingerprint(key)})
        try:
            self.channel = client.invoke_shell(
                term="xterm-256color", width=self.cols, height=self.rows)
        except Exception as exc:
            self._error(f"Could not open a shell on {self.host}: {exc}")
            client.close()
            self.client = None
            return "failed", None
        self.channel.settimeout(None)
        self._status("connected", f"Connected to {self.host}:{self.port}")
        self._audit_open()
        return "connected", None

    def _known_host_key(self, client):
        """The key `prepare` loaded into this client, if any — the "have we
        seen this device before" test, asked of the client rather than of
        the store so it holds for whichever store is installed."""
        try:
            name = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
            return client.get_host_keys().lookup(name)
        except Exception:
            return None

    @staticmethod
    def _remote_key(client):
        try:
            return client.get_transport().get_remote_server_key()
        except Exception:
            return None

    def _await_trust(self, change: _KeyChange) -> bool:
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
            self._last_input = time.time()
            if opcode == _OP_BINARY:                 # keystrokes
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
        while not self._stopped.wait(1.0):
            # Read the module global each time: the tests shorten it, and an
            # operator-facing constant is worth being able to change.
            if time.time() - self._last_input < IDLE_TIMEOUT_S:
                continue
            minutes = int(IDLE_TIMEOUT_S // 60) or 1
            self._status("closed", f"Closed after {minutes} minute(s) idle")
            self.ws.close(CLOSE_IDLE, "Idle timeout")
            self.stop()
            return

    # --------------------------------------------------------------- close

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

"""A stub SSH device: a real paramiko server on loopback, in-process.

There is no `sshd` in the test environment and there never will be, so both
things that speak SSH here — ConfigRX's config capture and the interactive
terminal — are exercised paramiko-against-paramiko. Password authentication
always succeeds (what is under test is never the password); every byte the
client writes is recorded in `sent_bytes`, which is how a test proves that
nothing beyond the intended commands was ever sent.

Modes:
  slow    — answers "Building configuration..." then PAUSES several seconds
            before streaming the config (the exact shape of the reported bug)
  paged   — streams the config a screen at a time behind a --More-- marker
  hang    — prints the banner and then never returns its prompt

`host_key=` takes a paramiko key, so a test can restart a device on the same
port with a different identity and watch the host-key check refuse it; it
defaults to one RSA key generated once per process. `host=`/`port=` pin the
listener, for a test that needs two devices at different addresses (the
whole 127/8 loopback range answers here) or the same address twice.

Imported, not spawned: unlike the SNMP stubs there is no child process and
no "listening" banner — construct `StubDevice()` and read `.port`.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

import paramiko

HOST_KEY = paramiko.RSAKey.generate(2048)
PROMPT = "stub-switch#"
CONFIG_LINES = [f"interface GigabitEthernet0/{n}\n description port {n}\n"
                f" switchport mode access\n switchport access vlan {100 + n}\n!"
                for n in range(1, 41)]
CONFIG = ("Current configuration : 4821 bytes\n!\nversion 15.2\n"
          "hostname stub-switch\n!\n" + "\n".join(CONFIG_LINES) + "\nend\n")


class _Server(paramiko.ServerInterface):
    def __init__(self):
        self.shell = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True

    def check_channel_pty_request(self, *a, **k):
        return True


class StubDevice:
    def __init__(self, mode: str = "slow", pause_s: float = 4.0, page: int = 20,
                 host_key=None, host: str = "127.0.0.1", port: int = 0):
        self.mode = mode
        self.pause_s = pause_s
        self.page = page
        self.host_key = host_key or HOST_KEY
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.host = host
        self.sock.bind((host, port))
        self.sock.listen(4)
        # A blocked accept() holds the listening port even after close(), so
        # the loop wakes up regularly instead and close() joins it — that is
        # what lets a test restart a device on its own port with a new key.
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.sent_bytes: list[bytes] = []          # everything the client wrote
        self._transports: list = []                # live sessions, for close()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        """Stop listening AND drop every live session: a test that restarts a
        device on the same port needs the port actually free, and both a
        blocked accept() and an accepted connection hold it."""
        self._stop.set()
        self._thread.join(timeout=3)
        try:
            self.sock.close()
        except OSError:
            pass
        for transport in list(self._transports):
            try:
                transport.close()
            except Exception:
                pass
        self._transports.clear()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        transport = paramiko.Transport(conn)
        self._transports.append(transport)
        transport.add_server_key(self.host_key)
        server = _Server()
        try:
            transport.start_server(server=server)
            channel = transport.accept(10)
            if channel is None:
                return
            server.shell.wait(10)
            channel.send("\r\nStub Switch, line 0\r\n\r\n" + PROMPT)
            self._shell(channel)
        except Exception:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    def _readline(self, channel) -> str:
        buf = b""
        while not buf.endswith(b"\n") and not buf.endswith(b"\r"):
            data = channel.recv(1)
            if not data:
                return ""
            self.sent_bytes.append(data)
            buf += data
        return buf.decode("utf-8", "replace").strip()

    def _shell(self, channel):
        while True:
            line = self._readline(channel)
            if not line:
                return
            if line in ("exit", "quit", "logout"):
                channel.send(line + "\r\n")
                channel.close()
                return
            channel.send(line + "\r\n")            # the echo
            if "show" not in line and "export" not in line:
                channel.send(PROMPT)               # e.g. terminal length 0
                continue
            if self.mode == "hang":
                channel.send("Building configuration...\r\n")
                time.sleep(60)
                return
            channel.send("Building configuration...\r\n")
            time.sleep(self.pause_s)
            if self.mode == "paged":
                self._send_paged(channel)
            else:
                channel.send(CONFIG.replace("\n", "\r\n"))
            channel.send("\r\n" + PROMPT)

    def _send_paged(self, channel):
        lines = CONFIG.split("\n")
        for i in range(0, len(lines), self.page):
            channel.send("\r\n".join(lines[i:i + self.page]) + "\r\n")
            if i + self.page < len(lines):
                channel.send(" --More-- ")
                key = channel.recv(1)             # the keypress we send
                self.sent_bytes.append(key)
                channel.send("\b" * 10 + " " * 10 + "\b" * 10)

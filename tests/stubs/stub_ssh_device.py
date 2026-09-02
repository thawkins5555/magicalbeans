"""A stub SSH device for exercising ConfigRX's capture path.

Modes:
  slow    — answers "Building configuration..." then PAUSES several seconds
            before streaming the config (the exact shape of the reported bug)
  paged   — streams the config a screen at a time behind a --More-- marker
  hang    — prints the banner and then never returns its prompt
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/

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
                 host_key=None):
        self.mode = mode
        self.pause_s = pause_s
        self.page = page
        # The key this device presents. Defaults to the module-level one, so
        # every stub in a run is the same host as far as a client is
        # concerned; pass a freshly generated key to be a DIFFERENT host on
        # the same address and port, which is what a host-key change is.
        self.host_key = host_key or HOST_KEY
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.sent_bytes: list[bytes] = []          # everything the client wrote
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        transport = paramiko.Transport(conn)
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

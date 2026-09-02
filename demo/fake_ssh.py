#!/usr/bin/env python3
"""Fake SSH devices for exercising ConfigRX's capture logic.

Each persona listens on its own loopback port and behaves like a device
shell: a login banner, a prompt, an acknowledgement of the vendor's
pager-off command, and a scripted reply to its show-config command.
Personas cover the cases ConfigRX's _read_until_prompt / _capture_problem
claim to handle: a Cisco that thinks for seconds after "Building
configuration...", a device that ignores pager-off and pages anyway, one
that hangs up mid-config, one whose banner ends in a menu rather than a
prompt, and one that rejects the command.

    python3 demo/fake_ssh.py [--base-port 2201]

Accepts any username with password "demo". Needs paramiko (not a
SappiWhere dependency for anything but ConfigRX). Never used by the app
itself; demo/configrx_probe.py drives it.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

import paramiko

CISCO_CONFIG = "\n".join(
    ["!", "! Last configuration change at 10:11:12 UTC", "version 15.2",
     "hostname acc-sw-001", "!"]
    + [f"interface GigabitEthernet1/0/{i}\n switchport mode access\n switchport access vlan {100 + i % 5}\n spanning-tree portfast"
       for i in range(1, 49)]
    + ["!", "line vty 0 4", " transport input ssh", "!", "end"])
FORTI_CONFIG = "\n".join(
    ["#config-version=FGT60F-7.2.5-FW-build1517-230523:opmode=0:vdom=0",
     "config system global", "    set hostname \"fw-01\"", "end"]
    + [f"config firewall policy\n    edit {i}\n        set srcintf \"port1\"\n        set dstintf \"port2\"\n    next\nend"
       for i in range(1, 40)])
MIKROTIK_CONFIG = "\n".join(
    ["# sep/02/2026 10:00:00 by RouterOS 7.14", "# software id = ABCD-1234",
     "/interface bridge", "add name=bridge1", "/ip address",
     "add address=10.10.1.1/24 interface=bridge1"])

PERSONAS = {
    "cisco":         {"banner": "acc-sw-001 line 2\n\nacc-sw-001#", "prompt": "acc-sw-001#",
                      "pager_off": ["terminal length 0"], "show": "show running-config",
                      "config": CISCO_CONFIG, "mode": "slow-build"},
    "cisco-pager":   {"banner": "acc-sw-002#", "prompt": "acc-sw-002#",
                      "pager_off": [], "show": "show running-config",
                      "config": CISCO_CONFIG, "mode": "pager"},
    "cisco-truncate": {"banner": "acc-sw-003#", "prompt": "acc-sw-003#",
                       "pager_off": ["terminal length 0"], "show": "show running-config",
                       "config": CISCO_CONFIG, "mode": "truncate"},
    "fortinet":      {"banner": "fw-01 # ", "prompt": "fw-01 #",
                      "pager_off": ["config system console", "set output standard", "end"],
                      "show": "show full-configuration", "config": FORTI_CONFIG, "mode": "normal"},
    "mikrotik":      {"banner": "\n  MMM      MMM       KKK\n[admin@rtr] > ", "prompt": "[admin@rtr] >",
                      "pager_off": [], "show": "/export", "config": MIKROTIK_CONFIG, "mode": "normal"},
    "menu":          {"banner": "Welcome\n1) Status\n2) Config\nSelect an option:", "prompt": "",
                      "pager_off": ["terminal length 0"], "show": "show running-config",
                      "config": CISCO_CONFIG, "mode": "normal"},
    "unprivileged":  {"banner": "acc-sw-004>", "prompt": "acc-sw-004>",
                      "pager_off": ["terminal length 0"], "show": "show running-config",
                      "config": "", "mode": "reject"},
}

HOST_KEY = paramiko.RSAKey.generate(2048)


class _Server(paramiko.ServerInterface):
    def __init__(self):
        self.shell = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if password == "demo" else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


def _read_line(chan) -> str | None:
    buf = b""
    chan.settimeout(30)
    while not buf.endswith(b"\n"):
        try:
            data = chan.recv(1024)
        except socket.timeout:
            return None
        if not data:
            return None
        buf += data
    return buf.decode("utf-8", "replace").strip("\r\n")


def _send_config(chan, persona):
    mode = persona["mode"]
    lines = persona["config"].split("\n")
    if mode == "reject":
        chan.send("% Invalid input detected at '^' marker.\r\n" + persona["prompt"])
        return
    if mode == "slow-build":
        chan.send("Building configuration...\r\n")
        time.sleep(3.0)          # a real Cisco thinks here; silence-based readers give up
        chan.send("\r\nCurrent configuration : %d bytes\r\n" % len(persona["config"]))
    if mode == "pager":
        for i, line in enumerate(lines):
            chan.send(line + "\r\n")
            if i and i % 20 == 0:
                chan.send(" --More-- ")
                chan.recv(1)     # wait for the keypress
                chan.send("\b" * 10 + " " * 10 + "\b" * 10)
        chan.send(persona["prompt"])
        return
    if mode == "truncate":
        for line in lines[: len(lines) // 3]:
            chan.send(line + "\r\n")
        chan.close()
        return
    for line in lines:
        chan.send(line + "\r\n")
    chan.send(persona["prompt"])


def _session(client_sock, persona):
    t = paramiko.Transport(client_sock)
    t.add_server_key(HOST_KEY)
    server = _Server()
    try:
        t.start_server(server=server)
        chan = t.accept(20)
        if chan is None:
            return
        server.shell.wait(10)
        chan.send(persona["banner"])
        while True:
            line = _read_line(chan)
            if line is None:
                break
            if line in persona["pager_off"]:
                chan.send("\r\n" + persona["prompt"])
            elif line == persona["show"]:
                chan.send("\r\n")
                _send_config(chan, persona)
                if persona["mode"] == "truncate":
                    break
            elif line == "":
                chan.send("\r\n" + persona["prompt"])
            else:
                chan.send("\r\n% Invalid input detected at '^' marker.\r\n" + persona["prompt"])
    except Exception as exc:  # pragma: no cover - demo aid
        print("session error:", exc, file=sys.stderr)
    finally:
        try:
            t.close()
        except Exception:
            pass


def serve(name, persona, port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=_session, args=(client, persona), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-port", type=int, default=2201)
    args = ap.parse_args()
    for i, (name, persona) in enumerate(PERSONAS.items()):
        port = args.base_port + i
        threading.Thread(target=serve, args=(name, persona, port), daemon=True).start()
        print(f"{name}: 127.0.0.1:{port}")
    print("listening", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

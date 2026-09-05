#!/usr/bin/env python3
"""Fake SSH devices for exercising ConfigRX's capture logic.

Each persona listens on its own loopback port and behaves like a device
shell: a login banner, a prompt, an acknowledgement of the vendor's
pager-off command, and a scripted reply to its show-config command.
Personas cover the cases ConfigRX's _read_until_prompt / _capture_problem
claim to handle: a Cisco that thinks for seconds after "Building
configuration...", a device that ignores pager-off and pages anyway, one
that hangs up mid-config, one whose banner ends in a menu rather than a
prompt, one that rejects the command, several Cisco platforms with
different pager-off/show verbs (NX-OS, IOS-XR, an SG/CBS switch that
rejects its own pager-off and pages instead), a WLC whose privileged
prompt ends '>' with no enable step, and an ASA that must escalate via
`enable` + a stored secret before it will do anything at all.

    python3 demo/fake_ssh.py [--base-port 2201] [--host-key PATH]

Accepts any username with password "demo". Needs paramiko (not a
SappiWhere dependency for anything but ConfigRX). Never used by the app
itself; demo/configrx_probe.py drives it.
"""
from __future__ import annotations

import argparse
import pathlib
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
NXOS_CONFIG = "\n".join(
    ["!Command: show running-config", "!Running configuration last done at: Wed Sep  2 10:00:00 2026",
     "!Time: Wed Sep  2 10:00:01 2026", "version 9.3(10) Bios:version 05.33 ", "hostname switch",
     "vdc switch id 1", "  limit-resource vlan minimum 16 maximum 4094", "feature lacp", "feature lldp"]
    + [f"interface Ethernet1/{i}\n  switchport access vlan {100 + i % 8}\n  spanning-tree port type edge"
       for i in range(1, 97)]
    + ["!", "line console", "line vty", "boot nxos bootflash:/nxos.9.3.10.bin"])
IOSXR_CONFIG = "\n".join(
    ["!! IOS XR Configuration 7.5.2", "!! Last configuration change at 10:11:12 UTC",
     "hostname router", "logging console debugging", "vrf default", "!"]
    + [f"interface GigabitEthernet0/0/0/{i}\n description edge link {i}\n ipv4 address 10.{i}.0.1 255.255.255.0\n no shutdown"
       for i in range(1, 81)]
    + ["!", "router static", " address-family ipv4 unicast", "!", "end"])
CISCO_SB_CONFIG = "\n".join(
    ["!Current Configuration:", "!System Description \"SG350-28, 2.5.8.5\"", "!System Software Version \"2.5.8.5\"",
     "vlan database", "vlan 10,20,30", "exit"]
    + [f"interface gi1/0/{i}\n switchport mode access\n switchport access vlan {10 + (i % 3) * 10}"
       for i in range(1, 65)]
    + ["!", "interface vlan 1", " ip address dhcp", "exit"])
ASA_CONFIG = "\n".join(
    [": Saved", ":", "ASA Version 9.16(4)10 ", "hostname ciscoasa", "domain-name example.local",
     "enable password $sha512$5000$rQ8= pbkdf2", "names", "!"]
    + [f"interface GigabitEthernet0/{i}\n nameif net{i}\n security-level {i * 5}\n ip address 10.{i}.0.1 255.255.255.0"
       for i in range(0, 8)]
    + [f"object network host-{i}\n host 172.16.0.{i}" for i in range(1, 150)]
    + ["!", "access-list outside_access_in extended permit tcp any any eq https",
       "route outside 0.0.0.0 0.0.0.0 203.0.113.1 1", ": end"])
WLC_CONFIG = "\n".join(
    ["System Inventory", "System Name.............................. WLC-01",
     "System Location.......................... HQ", "System Description....................... Cisco Controller",
     "Software Version.......................... 8.10.185.0", "802.11b Network State...................... Enabled"]
    + [f"WLAN Identifier.................................. {i}\nProfile Name..................................... corp-wlan-{i}\nNetwork Name (SSID)............................ CORP-{i}\nStatus........................................... Enabled"
       for i in range(1, 65)]
    + ["Number of Access Point.................... 48", "Configuration saved..."])

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
    # Same commands as "cisco" (NX-OS and IOS-XR share IOS's pager-off/show
    # verbs), on a differently-shaped banner and config.
    "cisco-nxos":    {"banner": "Cisco Nexus Operating System (NX-OS) Software\n\nswitch#",
                      "prompt": "switch#", "pager_off": ["terminal length 0"],
                      "show": "show running-config", "config": NXOS_CONFIG, "mode": "normal"},
    "cisco-iosxr":   {"banner": "RP/0/RP0/CPU0:router#", "prompt": "RP/0/RP0/CPU0:router#",
                      "pager_off": ["terminal length 0"], "show": "show running-config",
                      "config": IOSXR_CONFIG, "mode": "normal"},
    # A Small Business switch that rejects whatever pager-off command it is
    # sent (modelling both a vendor mismatch and a firmware that dropped the
    # command) and pages anyway — proving the generic --More-- fallback in
    # _read_until_prompt captures the config regardless.
    "cisco-sb-reject-then-page": {
        "banner": "sg350#", "prompt": "sg350#", "pager_off": ["terminal datadump"],
        "pager_off_rejected": True, "show": "show running-config",
        "config": CISCO_SB_CONFIG, "mode": "pager"},
    # Lands at user EXEC ('>'); "enable" + the right secret escalates to
    # privileged EXEC ('#'), only after which pager-off/show are accepted.
    "cisco-asa":     {"banner": "ciscoasa> ", "prompt": "ciscoasa>", "unpriv_prompt": "ciscoasa>",
                      "priv_prompt": "ciscoasa#", "enable_command": "enable",
                      "enable_password_prompt": "Password: ", "enable_secret": "demo",
                      "pager_off": ["terminal pager 0"], "show": "show running-config",
                      "show_requires_priv": True, "config": ASA_CONFIG, "mode": "normal"},
    # Prompt ends '>' but IS already privileged — no enable_command, and the
    # vendor table (cisco-wlc) knows it, so _pull_config never tries to
    # escalate here.
    "cisco-wlc":     {"banner": "(Cisco Controller) > ", "prompt": "(Cisco Controller) >",
                      "pager_off": ["config paging disable"], "show": "show run-config",
                      "config": WLC_CONFIG, "mode": "normal"},
}

DEFAULT_HOST_KEY_PATH = pathlib.Path(__file__).with_name("fake_ssh_host_key")
# Resolved by main(), not at import: importing this module for its PERSONAS
# (tests/test_configrx_cisco_platforms.py does) must not write a key file.
HOST_KEY = None


def load_host_key(path) -> paramiko.RSAKey:
    """One key per machine, kept on disk. A fresh key every start made every
    restart of these personas look to ConfigRX exactly like a MITM — which is
    the host-key check working, but it left the demo unable to back anything
    up a second time without an operator forgetting the key by hand."""
    path = pathlib.Path(path)
    try:
        return paramiko.RSAKey(filename=str(path))
    except (FileNotFoundError, paramiko.SSHException):
        key = paramiko.RSAKey.generate(2048)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            key.write_private_key_file(str(path))
        except OSError as exc:
            print(f"cannot keep the host key at {path} ({exc}); using a fresh "
                  "one, so ConfigRX will report it as changed", file=sys.stderr,
                  flush=True)
        return key


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


def _send_config(chan, persona, prompt):
    mode = persona["mode"]
    lines = persona["config"].split("\n")
    if mode == "reject":
        chan.send("% Invalid input detected at '^' marker.\r\n" + prompt)
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
        chan.send(prompt)
        return
    if mode == "truncate":
        for line in lines[: len(lines) // 3]:
            chan.send(line + "\r\n")
        chan.close()
        return
    for line in lines:
        chan.send(line + "\r\n")
    chan.send(prompt)


def _session(client_sock, persona):
    t = paramiko.Transport(client_sock)
    t.add_server_key(HOST_KEY or load_host_key(DEFAULT_HOST_KEY_PATH))
    server = _Server()
    try:
        t.start_server(server=server)
        chan = t.accept(20)
        if chan is None:
            return
        server.shell.wait(10)
        chan.send(persona["banner"])
        # Only a vendor whose login shell is not already privileged EXEC
        # (cisco-asa) carries an enable_command; every other persona starts —
        # and stays — "privileged" as far as show_requires_priv is concerned.
        prompt = persona["prompt"]
        privileged = not persona.get("enable_command")
        awaiting_enable_password = False
        while True:
            line = _read_line(chan)
            if line is None:
                break
            if awaiting_enable_password:
                awaiting_enable_password = False
                if line == persona.get("enable_secret", ""):
                    privileged = True
                    prompt = persona.get("priv_prompt", prompt)
                    chan.send("\r\n" + prompt)
                else:
                    prompt = persona.get("unpriv_prompt", persona["prompt"])
                    chan.send("\r\n% Access denied\r\n" + prompt)
                continue
            if persona.get("enable_command") and line == persona["enable_command"]:
                awaiting_enable_password = True
                chan.send("\r\n" + persona.get("enable_password_prompt", "Password: "))
                continue
            if line in persona["pager_off"]:
                if persona.get("pager_off_rejected"):
                    chan.send("\r\n% Unrecognized command\r\n" + prompt)
                else:
                    chan.send("\r\n" + prompt)
            elif line == persona["show"]:
                if persona.get("show_requires_priv") and not privileged:
                    chan.send("\r\nERROR: % Invalid input\r\n" + prompt)
                    continue
                chan.send("\r\n")
                _send_config(chan, persona, prompt)
                if persona["mode"] == "truncate":
                    break
            elif line == "":
                chan.send("\r\n" + prompt)
            else:
                chan.send("\r\n% Invalid input detected at '^' marker.\r\n" + prompt)
    except Exception as exc:  # pragma: no cover - demo aid
        print("session error:", exc, file=sys.stderr)
    finally:
        try:
            t.close()
        except Exception:
            pass


def bind(port):
    """A listening socket on the loopback, bound before anything is
    announced. Binding here rather than inside the serving thread is what
    makes the "listening" line below mean something: a port already in use
    used to raise on the thread, print a traceback nobody was reading, and
    leave the parent announcing readiness for a persona that was not there —
    which a caller then met as a connection refused, several steps later,
    against a device it had been told was up."""
    srv = socket.socket()
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        # Windows only, and the opposite of what the name suggests to a POSIX
        # reader: there SO_REUSEADDR lets a second process bind a port another
        # is already listening on and quietly take its connections, so binding
        # early would detect nothing. This asks for the behaviour POSIX gives
        # SO_REUSEADDR by default — a port in use is an error.
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    return srv


def serve(srv, persona):
    while True:
        client, _ = srv.accept()
        threading.Thread(target=_session, args=(client, persona), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-port", type=int, default=2201)
    ap.add_argument("--host-key", default=DEFAULT_HOST_KEY_PATH,
                    help="where to keep the persistent host key "
                         "(default: beside this script)")
    args = ap.parse_args()
    global HOST_KEY
    HOST_KEY = load_host_key(args.host_key)
    bound = []
    for i, (name, persona) in enumerate(PERSONAS.items()):
        port = args.base_port + i
        try:
            bound.append((name, persona, port, bind(port)))
        except OSError as exc:
            for _, _, _, srv in bound:
                srv.close()
            print(f"{name}: cannot bind 127.0.0.1:{port} — {exc}", file=sys.stderr,
                  flush=True)
            print("Another fake_ssh is probably already on this range; pass "
                  "--base-port to move out of its way.", file=sys.stderr, flush=True)
            return 1
    for name, persona, port, srv in bound:
        threading.Thread(target=serve, args=(srv, persona), daemon=True).start()
        print(f"{name}: 127.0.0.1:{port}")
    print("listening", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main() or 0)

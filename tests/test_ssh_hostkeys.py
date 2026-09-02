"""The shared SSH host-key store: what it remembers, what it refuses, and
what ConfigRX's backup path does with both.

Everything here is paramiko-on-paramiko — the stub SSH device (a real
paramiko server) presents a real host key, and the store is exercised through
`paramiko.SSHClient` exactly as ConfigRX and the SSH terminal drive it, rather
than by calling the policy in isolation. The interesting cases are only
reachable that way: paramiko checks a loaded key itself and raises its own
BadHostKeyException, which is a different code path from the policy's.

A "changed host key" is produced honestly: the stub is closed and a new one is
started on the SAME port with a freshly generated key, which is what a rebuilt
device (or something sitting in the middle) looks like from here. The stub
picks a free port itself, so the pinning shim below is how it is asked to come
back on the port it had — the stub file itself stays what workstream A ships.
"""
import base64
import hashlib
import http.client
import json
import os
import shutil
import sys
import time
import types

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("ssh_hostkeys_")

# DPAPI before anything that stores a credential is imported: the real one is
# Windows-only, and _backup_device decrypts through this module attribute.
import netpath.dpapi as dpapi_mod  # noqa: E402
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda plaintext: b"FAKE:" + plaintext
dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

try:
    import paramiko  # noqa: E402
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from netpath import configrx, hostkeys  # noqa: E402
from netpath.configrxdb import ConfigRxDatabase  # noqa: E402
from netpath.hostkeys import HostKeyChanged, HostKeyStore  # noqa: E402
from netpath.nodesdb import NodesDatabase  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def start_stub(port=None, host_key=None, **kwargs):
    """The stub, optionally on a port it has already used.

    StubDevice binds port 0 and reports what it got, which is right for every
    other use of it. A host key is remembered per (host, port), so proving a
    CHANGED key means bringing a second stub up on the first one's port —
    done by lending the stub a socket class for the duration of its
    constructor, rather than by growing the shared stub a test-only argument:

    * bind() pins the port when one is asked for;
    * close() shuts the listening socket down first. Closing it is not
      enough on its own — the stub's accept() thread is blocked on that
      socket, which keeps the port bound until the call returns, and a
      shutdown() is what returns it. Without this the second stub cannot
      have the first one's port at all.
    """
    real = stub_ssh_device.socket

    class _TestSocket(real.socket):
        def bind(self, address):
            real.socket.bind(self, (address[0], port or address[1]))

        def close(self):
            try:
                self.shutdown(real.SHUT_RDWR)
            except OSError:
                pass
            real.socket.close(self)

    stub_ssh_device.socket = types.SimpleNamespace(
        socket=_TestSocket, SOL_SOCKET=real.SOL_SOCKET, SO_REUSEADDR=real.SO_REUSEADDR)
    try:
        deadline = time.time() + 5
        while True:
            try:
                return stub_ssh_device.StubDevice(host_key=host_key, **kwargs)
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
    finally:
        stub_ssh_device.socket = real


def connect(store, host, port):
    """One connection through the store, the way both callers drive it.
    Raises HostKeyChanged for either shape of refusal."""
    client = paramiko.SSHClient()
    store.prepare(client, host, port)
    policy = store.policy(host, port)
    client.set_missing_host_key_policy(policy)
    try:
        client.connect(host, port=port, username="u", password="p",
                       look_for_keys=False, allow_agent=False, timeout=10)
    except (HostKeyChanged, paramiko.BadHostKeyException) as exc:
        raise store.as_changed(exc, host, port) from None
    store.record_seen(host, port)
    return client, policy


db = ConfigRxDatabase(os.path.join(TMPDIR, "configrx.db"))
store = HostKeyStore(db)
HOST = "127.0.0.1"

# ------------------------------------------------------------ 1. fingerprint

key = paramiko.RSAKey.generate(2048)
fp = hostkeys.fingerprint(key)
expected = "SHA256:" + base64.b64encode(
    hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
check("fingerprint is OpenSSH's SHA256:<base64> form", fp == expected, fp)
check("fingerprint has no base64 padding", not fp.endswith("="), fp)
check("fingerprint is 43 base64 characters after the prefix",
      len(fp) == len("SHA256:") + 43, fp)
check("the same key fingerprints the same twice", hostkeys.fingerprint(key) == fp)
check("a different key fingerprints differently",
      hostkeys.fingerprint(paramiko.ECDSAKey.generate()) != fp)
check("port 22 keys under the bare host, another port under [host]:port",
      (hostkeys.host_key_name(HOST, 22), hostkeys.host_key_name(HOST, 2222))
      == (HOST, "[127.0.0.1]:2222"))

# --------------------------------------------- 2. the first connection stores

first_key = paramiko.RSAKey.generate(2048)
device = start_stub(host_key=first_key, mode="slow", pause_s=0.1)
port = device.port
check("nothing is stored before the first connection", store.stored(HOST, port) is None)

client, policy = connect(store, HOST, port)
client.close()
row = store.stored(HOST, port)
check("the first connection stored the key", row is not None)
check("the policy reports that it stored one",
      bool(policy.stored_new) and policy.stored_new == hostkeys.fingerprint(first_key),
      policy.stored_new)
check("the stored fingerprint is the key the device presented",
      row and row["fingerprint"] == hostkeys.fingerprint(first_key))
check("the stored row carries the key type", row and row["key_type"] == "ssh-rsa",
      row and row["key_type"])
check("nobody is recorded as having trusted it", row and not row["trusted_by"],
      row and row["trusted_by"])
first_seen = row["first_seen_ts"]

# ------------------------------------- 3. the same key again is not an event

time.sleep(0.05)
client, policy = connect(store, HOST, port)
client.close()
again = store.stored(HOST, port)
check("the same key again stores nothing new", policy.stored_new == "", policy.stored_new)
check("the same key again touches last_seen_ts",
      again["last_seen_ts"] > row["last_seen_ts"],
      f"{row['last_seen_ts']} -> {again['last_seen_ts']}")
check("the same key again leaves first_seen_ts alone",
      again["first_seen_ts"] == first_seen)
check("the same key again does not change the fingerprint",
      again["fingerprint"] == row["fingerprint"])

# --------------------------------- 4. a different key on the same host:port

device.close()
second_key = paramiko.RSAKey.generate(2048)
device = start_stub(port=port, host_key=second_key, mode="slow", pause_s=0.1)
check("the replacement stub is on the same port", device.port == port,
      f"{device.port} != {port}")

changed = None
try:
    client, policy = connect(store, HOST, port)
    client.close()
except HostKeyChanged as exc:
    changed = exc
check("a changed host key is refused", changed is not None)
if changed:
    check("it names the old fingerprint",
          changed.old_fingerprint == hostkeys.fingerprint(first_key),
          changed.old_fingerprint)
    check("it names the new fingerprint",
          changed.new_fingerprint == hostkeys.fingerprint(second_key),
          changed.new_fingerprint)
    check("the two fingerprints differ",
          changed.old_fingerprint != changed.new_fingerprint)
    check("it carries when the old key was first seen",
          changed.old_first_seen == first_seen, changed.old_first_seen)
    check("it carries the new key's type", changed.key_type == "ssh-rsa", changed.key_type)
    check("it carries the new key itself, so it can be trusted without reconnecting",
          changed.new_key is not None
          and changed.new_key.asbytes() == second_key.asbytes())
    check("its message names both fingerprints and the device",
          changed.old_fingerprint in changed.message()
          and changed.new_fingerprint in changed.message()
          and HOST in changed.message(), changed.message())
check("a refused connection changes nothing in the store",
      store.stored(HOST, port)["fingerprint"] == hostkeys.fingerprint(first_key))

# The same RSA key type on both sides, deliberately: the comparison is on the
# key's BYTES. A comparison by get_name() would have called this unchanged.
check("the refusal was on the bytes, not the type",
      changed is not None and changed.key_type == store.stored(HOST, port)["key_type"])

# ------------------------------------------------- 5. trusting the new key

store.trust(HOST, port, changed.new_key, by="tester")
trusted = store.stored(HOST, port)
check("trust replaced the stored key",
      trusted["fingerprint"] == hostkeys.fingerprint(second_key))
check("trust recorded who did it", trusted["trusted_by"] == "tester", trusted["trusted_by"])
check("trust reset first seen to the new key's arrival",
      trusted["first_seen_ts"] >= first_seen)
client, policy = connect(store, HOST, port)
client.close()
check("the next connection to the trusted key succeeds", policy.stored_new == "")
check("and it is still the trusted key that is stored",
      store.stored(HOST, port)["fingerprint"] == hostkeys.fingerprint(second_key))

# ------------------------- 6. a key of a different type is refused just the same

device.close()
ecdsa_key = paramiko.ECDSAKey.generate()
device = start_stub(port=port, host_key=ecdsa_key, mode="slow", pause_s=0.1)
changed = None
try:
    client, _policy = connect(store, HOST, port)
    client.close()
except HostKeyChanged as exc:
    changed = exc
check("a key of another type on the same host:port is refused too", changed is not None)
if changed:
    check("the refusal names the new key's type",
          changed.key_type == "ecdsa-sha2-nistp256", changed.key_type)
    check("and still names the stored RSA fingerprint",
          changed.old_fingerprint == hostkeys.fingerprint(second_key))

# --------------------------------------------------------------- 7. forget

check("forget removes the stored key", store.forget(HOST, port) is True)
check("nothing is stored afterwards", store.stored(HOST, port) is None)
check("forgetting twice is a no-op, not an error", store.forget(HOST, port) is False)
client, policy = connect(store, HOST, port)
client.close()
check("the next connection after a forget stores the key it is offered",
      policy.stored_new == hostkeys.fingerprint(ecdsa_key), policy.stored_new)
store.forget(HOST, port)
device.close()

# ------------------------------------------- 8. ConfigRX's backup path

nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
device_id = nodes_db.add_device(HOST, name="Stub Switch")

backup_key = paramiko.RSAKey.generate(2048)
device = start_stub(host_key=backup_key, mode="slow", pause_s=0.1)
port = device.port
db.update_device_config(device_id, backup_enabled=True, ssh_port=port,
                        vendor_override="cisco")
db.set_credential(device_id, "backupuser", dpapi_mod.protect(b"a stub password"))

worker = configrx.ConfigRxWorker(db, nodes_db)
worker._backup_device(device_id)

config = db.device_config(device_id)
backups = db.backups_for(device_id)
check("the first backup succeeded", config["last_backup_status"].startswith("changed"),
      f"{config['last_backup_status']} / {config['last_backup_error']}")
check("the first backup says the host key was stored on first connection",
      config["last_backup_status"] == "changed (host key stored on first connection)",
      config["last_backup_status"])
check("the first backup stored a config", len(backups) == 1, len(backups))
check("and it stored the device's host key",
      (db.host_key(HOST, port) or {})["fingerprint"] == hostkeys.fingerprint(backup_key))

# A second backup of an unchanged config: same key, so no note this time.
worker._backup_device(device_id)
config = db.device_config(device_id)
check("a second backup does not repeat the host-key note",
      config["last_backup_status"] == "unchanged", config["last_backup_status"])

# Now the device presents a different key.
device.close()
rebuilt_key = paramiko.RSAKey.generate(2048)
device = start_stub(port=port, host_key=rebuilt_key, mode="slow", pause_s=0.1)
worker._backup_device(device_id)
config = db.device_config(device_id)
error = config["last_backup_error"] or ""
check("a backup against a changed host key fails",
      config["last_backup_status"] == "error", config["last_backup_status"])
check("the failure names the device, both fingerprints and the first-seen date",
      error.startswith(f"Host key for {HOST} changed (was ")
      and hostkeys.fingerprint(backup_key) in error
      and hostkeys.fingerprint(rebuilt_key) in error
      and "first seen" in error, error)
check("the failure says what to do about it",
      "Trust it from the SSH window or forget it in ConfigRX." in error, error)
check("no backup was stored from the changed device",
      len(db.backups_for(device_id)) == 1, len(db.backups_for(device_id)))
check("the stored key was not replaced by the one that was refused",
      db.host_key(HOST, port)["fingerprint"] == hostkeys.fingerprint(backup_key))
check("nothing was run on the device it refused to trust",
      b"".join(device.sent_bytes) == b"", repr(b"".join(device.sent_bytes)))

# Trusting the new key lets the backup through again — the SSH window's
# Trust button and this are the same store write.
store.trust(HOST, port, rebuilt_key, by="tester")
worker._backup_device(device_id)
config = db.device_config(device_id)
check("a backup after trusting the new key succeeds",
      config["last_backup_status"] in ("changed", "unchanged"),
      f"{config['last_backup_status']} / {config['last_backup_error']}")
check("and the note is not repeated for a key that was trusted, not discovered",
      "host key" not in (config["last_backup_status"] or ""), config["last_backup_status"])

# ------------------------------------- 9. removing the device keeps the key

# A host key belongs to an address and port, not to a device row. Removing
# the device must not quietly reset the trust anchor: another device row may
# already be recorded at the same address, and re-adding this one has to be
# refused if what answers there is not what answered before. Only ConfigRX's
# Forget takes a key away.
check("the host key is there before the device is removed",
      db.host_key(HOST, port) is not None)
db.forget_device(device_id)
check("removing a device forgets its ConfigRX config",
      db.device_config(device_id) is None)
check("...and its stored backups", db.backups_for(device_id) == [])
check("...and leaves the remembered host key alone",
      db.host_key(HOST, port) is not None)
check("the key left behind is still the trusted one, unchanged",
      db.host_key(HOST, port)["fingerprint"] == hostkeys.fingerprint(rebuilt_key))

device.close()

# ----------------------------- 10. the routes: who may forget, who may not

# The two rules the store depends on, proved through the real web server
# rather than by calling the handlers: a Nodes removal does not touch a host
# key, and Forget belongs to ConfigRX write — the permission that already
# decides which port and which credential the next connection uses. `ssh`
# write is a shell on a device, not authority over what this app trusts.
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER  # noqa: E402
from netpath.web import Service, WebServer  # noqa: E402

ROUTE_HOST = "192.0.2.10"
ROUTE_PORT = 2222
route_key = paramiko.RSAKey.generate(2048)


def remember_route_key():
    db.store_host_key(ROUTE_HOST, ROUTE_PORT, route_key.get_name(),
                      route_key.get_base64(), hostkeys.fingerprint(route_key))


# The same database files these tests have been using, so the service shares
# the store above. No service.start(): nothing here polls anything.
service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error

try:
    def call(method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Cookie"] = f"sw_session={token}"
        conn.request(method, path,
                     body=json.dumps(body).encode() if body is not None else None,
                     headers=headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, raw

    def login(username, password):
        conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
        conn.request("POST", "/api/login",
                     body=json.dumps({"username": username,
                                      "password": password}).encode(),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        cookie = dict(response.getheaders()).get("Set-Cookie", "")
        conn.close()
        assert "sw_session=" in cookie, cookie
        return cookie.split("sw_session=")[1].split(";")[0]

    admin_token = login(DEFAULT_USER, DEFAULT_PASSWORD)
    accounts = {
        # ssh write, plus configrx READ so the dialog can still show the key.
        "shelluser": {"ssh": "write", "configrx": "read", "nodes": "read"},
        "cxuser": {"configrx": "write"},
        "nodesuser": {"nodes": "write"},
    }
    tokens = {}
    for username, grants in accounts.items():
        status, payload = call("POST", "/api/users",
                               {"username": username,
                                "password": "Corr3ct-Horse-Battery",
                                "grants": grants}, token=admin_token)
        assert status == 200, (username, status, payload)
        tokens[username] = login(username, "Corr3ct-Horse-Battery")

    group_id = service.nodes_db.ensure_default_group()
    route_device = service.nodes_db.add_device(ROUTE_HOST, name="Route Switch",
                                               group_id=group_id)
    service.configrx_db.update_device_config(route_device, ssh_port=ROUTE_PORT)
    remember_route_key()

    status, payload = call("GET", f"/api/ssh/devices/{route_device}/hostkey",
                           token=tokens["shelluser"])
    check("a configrx-read account can see the stored key",
          status == 200 and (payload.get("host_key") or {}).get("fingerprint")
          == hostkeys.fingerprint(route_key), (status, payload))

    status, payload = call("DELETE", f"/api/ssh/devices/{route_device}/hostkey",
                           token=tokens["shelluser"])
    check("Forget is refused to an account that holds only ssh write",
          status == 403, (status, payload))
    check("...and the key is still there afterwards",
          db.host_key(ROUTE_HOST, ROUTE_PORT) is not None)

    status, payload = call("DELETE", f"/api/ssh/devices/{route_device}/hostkey",
                           token=tokens["cxuser"])
    check("Forget is allowed to an account with configrx write",
          status == 200 and payload.get("removed") == 1, (status, payload))
    check("...and the key is gone", db.host_key(ROUTE_HOST, ROUTE_PORT) is None)

    remember_route_key()
    status, payload = call("DELETE", f"/api/nodes/devices/{route_device}",
                           token=tokens["nodesuser"])
    check("a nodes-write account may remove the device", status == 200,
          (status, payload))
    check("...and removing it does not take the host key with it",
          db.host_key(ROUTE_HOST, ROUTE_PORT) is not None)
    check("...though the ConfigRX config for it is gone",
          db.device_config(route_device) is None)

    # The bulk form goes through the same forget_device.
    bulk_device = service.nodes_db.add_device(ROUTE_HOST, name="Route Switch 2",
                                              group_id=group_id)
    status, payload = call("POST", "/api/nodes/devices/bulk-delete",
                           {"device_ids": [bulk_device]},
                           token=tokens["nodesuser"])
    check("a bulk removal succeeds too",
          status == 200 and payload.get("removed") == 1, (status, payload))
    check("...and leaves the host key at that address alone",
          db.host_key(ROUTE_HOST, ROUTE_PORT) is not None)
finally:
    server.stop()
    service.shutdown()

db.close()
nodes_db.close()
shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

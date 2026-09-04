"""ConfigRX on Cisco platforms beyond plain IOS/IOS-XE: NX-OS and IOS-XR
(same commands, different banner), an SG/CBS switch that rejects its own
pager-off command and pages instead, a WLC whose privileged prompt ends
'>' with no enable step, and an ASA that must escalate via `enable` and a
stored secret before it will run anything at all.

Drives the real `_pull_config` -> `_clean_output` -> `_capture_problem`
chain (nothing here reimplements ConfigRX's capture logic) against every
Cisco persona in demo/fake_ssh.py's PERSONAS, shared verbatim with
`stubs.stub_ssh_device.StubDevice(persona=...)` rather than a second,
drifting copy of the same scripted device. Each persona proves either a
stored capture with the config's own text present, or the exact refusal
message this release promises: cisco-truncate and unprivileged (both
pre-existing failure shapes, re-checked here on the vendor path a real
Cisco device also uses) and cisco-asa given the WRONG enable secret.

The final section is the one end-to-end case that goes through a real
`Service`, a real (portable, passphrase-file-backed) secret store, and
`ConfigRxWorker.backup_now` rather than calling `_pull_config` directly —
proving the enable secret this file's DB column stores is the one the
worker actually decrypts and sends.
"""
import os
import stat
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("configrx_cisco_")

try:
    import paramiko  # noqa: E402
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from demo import fake_ssh  # noqa: E402
from netpath import configrx, configrx_vendors  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def connect(port, password="demo"):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="tester", password=password,
                   timeout=10, look_for_keys=False, allow_agent=False)
    return client


# -------------------------------------------------- 1. every Cisco persona
# name -> (vendor key, enable secret to offer, a substring the stored
# capture must contain when it succeeds).
CISCO_PERSONAS = {
    "cisco":                      ("cisco", "", "hostname acc-sw-001"),
    "cisco-pager":                ("cisco", "", "hostname acc-sw-001"),
    "cisco-truncate":             ("cisco", "", None),
    "unprivileged":               ("cisco", "", None),
    "cisco-nxos":                 ("cisco-nxos", "", "hostname switch"),
    "cisco-iosxr":                ("cisco-iosxr", "", "IOS XR Configuration"),
    "cisco-sb-reject-then-page":  ("cisco-sb", "", "SG350-28"),
    "cisco-asa":                  ("cisco-asa", "demo", "hostname ciscoasa"),
    "cisco-wlc":                  ("cisco-wlc", "", "System Name"),
}
DOCUMENTED_REFUSAL = {
    "cisco-truncate": "The device closed the connection before the config finished",
    "unprivileged": "too short to be a config",
}

print("every Cisco persona in demo.fake_ssh.PERSONAS")
missing = set(CISCO_PERSONAS) - set(fake_ssh.PERSONAS)
check("this suite's persona list matches demo.fake_ssh.PERSONAS (nothing renamed/removed there)",
      not missing, missing)

for name, (vendor_key, enable_secret, marker) in CISCO_PERSONAS.items():
    persona = fake_ssh.PERSONAS[name]
    vendor = configrx_vendors.resolve(vendor_key)
    check(f"{name}: vendor '{vendor_key}' is registered", vendor is not None)
    if vendor is None:
        continue
    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        raw, ended = configrx._pull_config(client, vendor, max_s=15, enable_secret=enable_secret)
        client.close()
        cleaned = configrx._clean_output(raw)
        problem = configrx._capture_problem(cleaned, ended)
        if name in DOCUMENTED_REFUSAL:
            check(f"{name}: refused with the documented message",
                  DOCUMENTED_REFUSAL[name] in problem, problem)
        else:
            check(f"{name}: STORED (no capture problem)", problem == "", problem)
            check(f"{name}: the captured text is this persona's own config",
                  marker in cleaned, cleaned[:200])
    finally:
        device.close()

# ---------------------------------- 2. cisco-asa with the WRONG enable secret
print("cisco-asa: a wrong enable secret never reaches privileged mode")
device = stub_ssh_device.StubDevice(persona=fake_ssh.PERSONAS["cisco-asa"])
try:
    client = connect(device.port)
    raw, ended = configrx._pull_config(client, configrx_vendors.resolve("cisco-asa"),
                                       max_s=15, enable_secret="not-the-secret")
    client.close()
    cleaned = configrx._clean_output(raw)
    problem = configrx._capture_problem(cleaned, ended)
    check("ended on the enable-failed path", ended == "enable-failed", ended)
    check("refused with the documented message",
          problem == "The account did not reach privileged mode — check the enable secret",
          problem)
finally:
    device.close()

# ------------- 3. the safety boundary: only the fixed commands are ever sent
print("cisco-asa: only enable, the stored secret, pager-off and show are ever sent")
device = stub_ssh_device.StubDevice(persona=fake_ssh.PERSONAS["cisco-asa"])
try:
    client = connect(device.port)
    configrx._pull_config(client, configrx_vendors.resolve("cisco-asa"), max_s=15,
                          enable_secret="demo")
    client.close()
    sent = b"".join(device.sent_bytes).decode("utf-8", "replace")
    check("sent bytes are exactly the four fixed lines, in order, nothing else",
          sent == "enable\ndemo\nterminal pager 0\nshow running-config\n", repr(sent))
finally:
    device.close()

# ------------------------- 4. WLC: '>' prompt is privileged, no escalation
print("cisco-wlc: a trailing-space '>' banner is learned as a prompt and never escalated")
learned = configrx._learn_prompt(fake_ssh.PERSONAS["cisco-wlc"]["banner"])
check("_learn_prompt strips the trailing space and keeps the trailing '>'",
      learned == "(Cisco Controller) >", repr(learned))
device = stub_ssh_device.StubDevice(persona=fake_ssh.PERSONAS["cisco-wlc"])
try:
    client = connect(device.port)
    raw, ended = configrx._pull_config(client, configrx_vendors.resolve("cisco-wlc"), max_s=15)
    client.close()
    sent = b"".join(device.sent_bytes).decode("utf-8", "replace")
    check("no 'enable' was ever sent to a vendor with no enable_command",
          "enable" not in sent, repr(sent))
finally:
    device.close()

# ---------------------------------------------- 5. the enable_secret_enc column
print("configrxdb: enable_secret_enc storage and the has_credential contract")
import netpath.dpapi as dpapi_mod  # noqa: E402
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda plaintext: b"FAKE:" + plaintext
dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

from netpath.configrxdb import ConfigRxDatabase  # noqa: E402
from netpath.nodesdb import NodesDatabase  # noqa: E402

cdb = ConfigRxDatabase(os.path.join(TMPDIR, "column.configrx.db"))
ndb = NodesDatabase(os.path.join(TMPDIR, "column.nodes.db"))
dev = ndb.add_device("127.0.0.9", name="col-test")
cdb.set_credential(dev, "u", dpapi_mod.protect(b"pw"))
check("set_credential with no 4th argument leaves enable_secret_enc alone (NULL)",
      cdb.device_config(dev)["enable_secret_enc"] is None)
cdb.set_enable_secret(dev, dpapi_mod.protect(b"demo"))
check("set_enable_secret stores it",
      dpapi_mod.unprotect(cdb.device_config(dev)["enable_secret_enc"]) == b"demo")
cdb.set_credential(dev, "u", dpapi_mod.protect(b"pw2"))
check("a later set_credential call with no 4th argument still leaves it untouched",
      cdb.device_config(dev)["enable_secret_enc"] is not None)
cdb.set_credential(dev, "u", dpapi_mod.protect(b"pw3"), enable_secret_enc=None)
check("set_credential's 4th argument, passed explicitly, does clear it",
      cdb.device_config(dev)["enable_secret_enc"] is None)
cdb.set_enable_secret(dev, dpapi_mod.protect(b"again"))
cdb.clear_enable_secret(dev)
check("clear_enable_secret clears it", cdb.device_config(dev)["enable_secret_enc"] is None)
check("has_credential's own signal (ssh_password_enc) is unaffected by any of the above",
      cdb.device_config(dev)["ssh_password_enc"] is not None)


# ----------------------------------------------------- 6. end to end: a real
#                                                     Service + backup_now
print("end to end: a real Service, a real secret store, ConfigRxWorker.backup_now")

_passphrase_path = os.path.join(TMPDIR, "passphrase.txt")
with open(_passphrase_path, "w", encoding="utf-8") as fh:
    fh.write("configrx-cisco-platforms suite passphrase, not used anywhere else\n")
os.chmod(_passphrase_path, stat.S_IRUSR | stat.S_IWUSR)
os.environ["NETPATH_SECRET_PASSPHRASE_FILE"] = _passphrase_path

import netpath.secretstore as secretstore  # noqa: E402
secretstore._salt_path = lambda: os.path.join(TMPDIR, "install.salt")
secretstore._key_cache.clear()

# Reload dpapi so it re-reads secretstore.configured() rather than keeping
# whatever a module-level import cached before the env var above was set,
# and so this section runs against the REAL implementation, not the
# reversible stand-in section 5 installed on the same module object.
import importlib
import netpath.dpapi as dpapi
importlib.reload(dpapi)
check("the real secret store is now configured", dpapi.available() is True)

from netpath.web import Service  # noqa: E402

service = Service(
    os.path.join(TMPDIR, "e2e.netpath.db"), os.path.join(TMPDIR, "e2e.flows.db"),
    os.path.join(TMPDIR, "e2e.syslog.db"), os.path.join(TMPDIR, "e2e.app.db"),
    os.path.join(TMPDIR, "e2e.ipam.db"), os.path.join(TMPDIR, "e2e.snmptraps.db"),
    os.path.join(TMPDIR, "e2e.nodes.db"), os.path.join(TMPDIR, "e2e.alerts.db"),
    os.path.join(TMPDIR, "e2e.wireless.db"), os.path.join(TMPDIR, "e2e.configrx.db"))

asa = stub_ssh_device.StubDevice(persona=fake_ssh.PERSONAS["cisco-asa"])
try:
    # The global "enabled" setting is what gates _loop()'s own periodic
    # due-scan (not whether the worker thread is running at all — backup_now
    # below neither reads nor needs it) — switched off for the one Service
    # this file ever starts so that scan can never fire during setup below.
    # It used to seem enough that the scan's first pass runs "immediately"
    # on a device-less database and the next is 30s away, but "immediately"
    # only means the thread has been asked to start, not that it has
    # actually been scheduled: under load that first pass can land anywhere
    # from microseconds to whole seconds later, including squarely inside
    # the window between update_device_config below (which makes the device
    # due) and set_credential (which the scan cannot know is still coming).
    # A scan landing there queued a doomed backup of its own — no stored
    # credential yet — which then set last_backup_status to "error" before
    # backup_now's own, correctly-credentialed backup ever got a chance,
    # and the wait loop below took that first, unrelated status for the
    # answer the moment it saw anything other than None.
    service.configrx_db.save_settings({"enabled": False})
    service.configrx.start()
    try:
        device_id = service.nodes_db.add_device("127.0.0.1", name="e2e-asa")
        service.configrx_db.update_device_config(
            device_id, backup_enabled=True, ssh_port=asa.port, vendor_override="cisco-asa")
        service.configrx_db.set_credential(
            device_id, "backupuser", dpapi.protect(b"a stub ssh password"),
            enable_secret_enc=dpapi.protect(b"demo"))

        check("backup_now queues the backup", service.configrx.backup_now(device_id) is True)
        deadline = time.time() + 15
        config = service.configrx_db.device_config(device_id)
        while config["last_backup_status"] is None and time.time() < deadline:
            time.sleep(0.1)
            config = service.configrx_db.device_config(device_id)
        check("the backup finished as changed (the enable secret worked)",
              (config["last_backup_status"] or "").startswith("changed"),
              f"{config['last_backup_status']} / {config['last_backup_error']}")
        backups = service.configrx_db.backups_for(device_id)
        check("a backup row exists", len(backups) == 1, len(backups))
        if backups:
            content = service.configrx_db.backup_content(backups[0]["id"])
            check("the stored backup is this ASA's own running-config",
                  "hostname ciscoasa" in (content or ""), (content or "")[:200])
    finally:
        service.configrx.stop()
finally:
    asa.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

"""ConfigRX of Ubiquiti airOS radios (NanoBeam/NanoStation/LiteBeam/PowerBeam/
airFiber): the fix for "Unrecognized vendor '(none)'" -- configrx.VENDORS had
no "ubiquiti" entry at all, so a device auto-detected (or manually set) as
that vendor could never resolve to something ConfigRX knew how to back up.
Drives the real _pull_config -> _clean_output -> _capture_problem chain
against a fake airOS busybox shell (demo/fake_ssh.py's "ubiquiti-airos"
persona) via stubs.stub_ssh_device.StubDevice, as
test_configrx_industrial.py does for the other documentation-sourced
vendors, then one end-to-end case through a real ConfigRxWorker proving the
capture is actually stored, not merely accepted by _capture_problem.
"""
import os

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

try:
    import paramiko  # noqa: E402
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from demo import fake_ssh  # noqa: E402
from netpath import configrx  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

TMPDIR = _paths.tmpdir("configrx_ubiquiti_")
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


print("ubiquiti: the vendor key is registered")
vendor = configrx.resolve("ubiquiti")
check("registered (this is the bug: it used to be None here)", vendor is not None)
if vendor is not None:
    check("show_config is the documented airOS command",
          vendor.show_config == "cat /tmp/system.cfg", vendor)
    check("no pager_off and no enable_command -- a busybox shell has neither",
          vendor.pager_off == () and vendor.enable_command == "", vendor)

print("ubiquiti: the persona exists in demo.fake_ssh.PERSONAS")
persona = fake_ssh.PERSONAS.get("ubiquiti-airos")
check("persona exists", persona is not None)

if vendor is not None and persona is not None:
    print("ubiquiti: a real airOS capture is accepted, not refused as too short")
    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        raw, ended = configrx._pull_config(client, vendor, max_s=15)
        client.close()
        cleaned = configrx._clean_output(raw)
        problem = configrx._capture_problem(cleaned, ended)
        check("STORED (no capture problem)", problem == "", problem)
        check("the captured text is system.cfg's own key=value content",
              "wireless.1.ssid=PtP-Link-01" in cleaned, cleaned[:200])
    finally:
        device.close()

    print("ubiquiti: only 'cat /tmp/system.cfg' is ever sent -- no pager-off, no enable")
    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        configrx._pull_config(client, vendor, max_s=15)
        client.close()
        sent = b"".join(device.sent_bytes).decode("utf-8", "replace")
        check("sent bytes are exactly the one fixed command, nothing else",
              sent == "cat /tmp/system.cfg\n", repr(sent))
    finally:
        device.close()

    # ------------------------------------------------------- end to end
    print("end to end: ConfigRxWorker.backup_now resolves 'ubiquiti' and stores the capture")
    import netpath.dpapi as dpapi_mod  # noqa: E402
    # A reversible stand-in, same convention test_configrx_cisco_platforms.py
    # uses for its own non-secret-store sections: what matters here is the
    # vendor resolution and storage path, not DPAPI itself.
    dpapi_mod.available = lambda: True
    dpapi_mod.protect = lambda plaintext: b"FAKE:" + plaintext
    dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

    from netpath.configrx import ConfigRxWorker  # noqa: E402
    from netpath.configrxdb import ConfigRxDatabase  # noqa: E402
    from netpath.nodesdb import NodesDatabase  # noqa: E402

    cdb = ConfigRxDatabase(os.path.join(TMPDIR, "ubiquiti.configrx.db"))
    ndb = NodesDatabase(os.path.join(TMPDIR, "ubiquiti.nodes.db"))
    worker = ConfigRxWorker(cdb, ndb)

    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        device_id = ndb.add_device("127.0.0.1", name="nanobeam-01")
        cdb.update_device_config(device_id, backup_enabled=True, ssh_port=device.port,
                                 vendor_override="ubiquiti")
        cdb.set_credential(device_id, "ubnt", dpapi_mod.protect(b"demo"))
        # Called directly rather than via the worker's own thread pool: this
        # is a synchronous method with no dependency on start()/_executor,
        # and calling it inline keeps this section's failure mode a plain
        # assertion instead of a poll loop racing a background thread.
        worker._backup_device(device_id)
        config = cdb.device_config(device_id)
        check("the backup finished as changed",
              (config["last_backup_status"] or "").startswith("changed"),
              f"{config['last_backup_status']} / {config['last_backup_error']}")
        backups = cdb.backups_for(device_id)
        check("a backup row exists", len(backups) == 1, len(backups))
        if backups:
            content = cdb.backup_content(backups[0]["id"])
            check("the stored backup is this device's own system.cfg",
                  "wireless.1.ssid=PtP-Link-01" in (content or ""), (content or "")[:200])
    finally:
        device.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

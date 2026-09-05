"""The config-search index gap: a device backed up as `unchanged` never
reached configrx.ConfigRxWorker._backup_device's indexing call, because
that call sat inside `if backup_id is not None:` — the branch taken only
when a capture DIFFERS from the last stored one. A device whose config is
stable (the normal steady state of a well-run network) was invisible to
cross-device search permanently: replace_search_lines has exactly one
caller in the whole codebase, and nothing ever ran it for an unchanged
capture.

Reproduced here two ways, matching how it was found live:

  1. End to end, driving the real SSH capture path (stub_ssh_device +
     demo.fake_ssh's "cisco" persona) through ConfigRxWorker.backup_now
     twice: the first capture is `changed` (a device's first-ever backup
     always is — nothing to compare against yet), the second is
     `unchanged` (same persona, same output). BEFORE THE FIX, the device
     had a stored backup and zero config_lines rows at that point, and
     `configrx_search.search()` found nothing — silent, total, and (short
     of the config actually changing) permanent. This section proves the
     fix instead: the device is searchable after the UNCHANGED capture,
     not just the first CHANGED one.

  2. Directly against ConfigRxDatabase, isolating the exact mechanics:
     - has_search_lines() reads back False right after a bare add_backup
       (nothing indexes on its own — that has always been, and remains,
       ConfigRxWorker's job), reproducing the exact state the live
       instance was found in ("backups had a stored capture and
       config_lines had 0 rows").
     - backfill_one_device() closes that gap for one device, respecting
       the stored `redacted` flag on its latest backup exactly the way
       ConfigRxWorker._backup_device's own store_secrets branch does.
     - start_search_backfill() closes it for a whole fleet: chunked (a
       small SEARCH_BACKFILL_CHUNK_DEVICES here, to actually exercise more
       than one chunk without a fleet-sized fixture), and resumable — an
       interruption mid-fleet is picked up again from the persisted
       cursor rather than restarting, and a device already indexed by the
       time its chunk is reached (a real capture landed for it while the
       backfill was still walking earlier devices) is left alone rather
       than redundantly replaced.
"""
from __future__ import annotations

import os
import stat
import time

import _paths  # noqa: F401

TMPDIR = _paths.tmpdir("configrx_search_backfill_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ---------------------------------------------------- 1. end to end, real SSH

try:
    import paramiko  # noqa: F401
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from demo import fake_ssh  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

_passphrase_path = os.path.join(TMPDIR, "passphrase.txt")
with open(_passphrase_path, "w", encoding="utf-8") as fh:
    fh.write("configrx-search-backfill suite passphrase, not used anywhere else\n")
os.chmod(_passphrase_path, stat.S_IRUSR | stat.S_IWUSR)
os.environ["NETPATH_SECRET_PASSPHRASE_FILE"] = _passphrase_path

import netpath.secretstore as secretstore  # noqa: E402
secretstore._salt_path = lambda: os.path.join(TMPDIR, "install.salt")
secretstore._key_cache.clear()

import importlib  # noqa: E402
import netpath.dpapi as dpapi  # noqa: E402
importlib.reload(dpapi)
check("the real secret store is configured", dpapi.available() is True)

from netpath import configrx_search as cs  # noqa: E402
from netpath.web import Service  # noqa: E402

print("end to end: an UNCHANGED capture is searchable, not just the first CHANGED one")
service = Service(
    os.path.join(TMPDIR, "e2e.netpath.db"), os.path.join(TMPDIR, "e2e.flows.db"),
    os.path.join(TMPDIR, "e2e.syslog.db"), os.path.join(TMPDIR, "e2e.app.db"),
    os.path.join(TMPDIR, "e2e.ipam.db"), os.path.join(TMPDIR, "e2e.snmptraps.db"),
    os.path.join(TMPDIR, "e2e.nodes.db"), os.path.join(TMPDIR, "e2e.alerts.db"),
    os.path.join(TMPDIR, "e2e.wireless.db"), os.path.join(TMPDIR, "e2e.configrx.db"))

device = stub_ssh_device.StubDevice(persona=fake_ssh.PERSONAS["cisco"])
try:
    # See test_configrx_cisco_platforms.py's identical comment: switched off
    # so the periodic due-scan can never race backup_now below with its own,
    # doomed (no credential yet) backup attempt.
    service.configrx_db.save_settings({"enabled": False})
    service.configrx.start()
    try:
        device_id = service.nodes_db.add_device("127.0.0.1", name="e2e-unchanged")
        service.configrx_db.update_device_config(
            device_id, backup_enabled=True, ssh_port=device.port, vendor_override="cisco")
        service.configrx_db.set_credential(
            device_id, "backupuser", dpapi.protect(b"a stub ssh password"))

        def run_backup_and_wait(expect_prefix: str) -> str:
            before = service.configrx_db.device_config(device_id)["last_backup_ts"]
            check(f"backup_now queues ({expect_prefix})",
                  service.configrx.backup_now(device_id) is True)
            deadline = time.time() + 15
            config = service.configrx_db.device_config(device_id)
            while config["last_backup_ts"] == before and time.time() < deadline:
                time.sleep(0.1)
                config = service.configrx_db.device_config(device_id)
            status = config["last_backup_status"] or ""
            check(f"backup finished as {expect_prefix} ({status})",
                  status.startswith(expect_prefix),
                  f"{status} / {config['last_backup_error']}")
            return status

        run_backup_and_wait("changed")
        backups = service.configrx_db.backups_for(device_id)
        check("one backup stored after the first (changed) capture",
              len(backups) == 1, len(backups))
        check("the device is searchable after its first capture",
              service.configrx_db.has_search_lines(device_id))

        # A device's first-ever capture always indexes (add_backup's hash
        # comparison can never call it "unchanged" — there is nothing yet
        # to compare against), so simply capturing twice would prove
        # nothing: the SECOND (unchanged) capture would find the index
        # already populated by the first either way, fixed or not.
        #
        # What reproduces the reported bug is a device that already has a
        # stored backup with NO index behind it — an install upgrading
        # into this feature with backups predating config_lines, or one
        # whose backfill has not reached it yet. Simulated here by
        # removing this device's index rows while leaving its backup in
        # place, then polling again with nothing about the device's
        # config having changed.
        with service.configrx_db._lock:
            service.configrx_db._delete_search_lines(device_id)
            service.configrx_db._conn.commit()
        check("(test setup) simulating a pre-existing install: index rows "
              "removed, the backup itself left alone",
              not service.configrx_db.has_search_lines(device_id))

        run_backup_and_wait("unchanged")
        backups = service.configrx_db.backups_for(device_id)
        check("still exactly one backup row (unchanged does not add one)",
              len(backups) == 1, len(backups))
        check("THE FIX: the device is STILL searchable after an UNCHANGED "
              "capture — this is the assertion that failed before the fix "
              "(has_search_lines/config_lines stayed empty forever once a "
              "device's first capture was its last CHANGED one)",
              service.configrx_db.has_search_lines(device_id))

        result = cs.search(service.configrx_db, "hostname acc-sw-001", mode="text")
        check("configrx_search actually finds a line from this device "
              "after nothing but an unchanged poll",
              any(m["device_id"] == device_id for m in result["matches"]), result)
    finally:
        service.configrx.stop()
finally:
    device.close()


# --------------------------------------------- 2. ConfigRxDatabase directly

from netpath.configrxdb import ConfigRxDatabase  # noqa: E402
from netpath import configrxdb  # noqa: E402

print("has_search_lines reproduces the exact live symptom: a stored backup, zero index rows")
db = ConfigRxDatabase(os.path.join(TMPDIR, "direct.configrx.db"))
db.add_backup(1, "hostname sw1\ninterface Gi0/1\n")
check("a bare add_backup does not index on its own (that is ConfigRxWorker's "
      "job, or the backfill below) — reproduces \"backups had a stored "
      "capture and config_lines had 0 rows\"",
      db.has_search_lines(1) is False)
check("and so it is not searchable", cs.search(db, "interface Gi0/1", mode="text")["matches"] == [])

print("backfill_one_device closes the gap for one device")
db.backfill_one_device(1)
check("now indexed", db.has_search_lines(1) is True)
result = cs.search(db, "interface Gi0/1", mode="text")
check("and now searchable", any(m["device_id"] == 1 for m in result["matches"]), result)

print("backfill_one_device is a no-op once a device is already indexed")
calls = []
_orig_replace = db.replace_search_lines
db.replace_search_lines = lambda *a, **kw: (calls.append((a, kw)), _orig_replace(*a, **kw))[-1]
db.backfill_one_device(1)
check("replace_search_lines was not called again for an already-indexed device",
      calls == [], calls)
db.replace_search_lines = _orig_replace

print("backfill_one_device respects the stored `redacted` flag, same as "
      "ConfigRxWorker._backup_device's own store_secrets branch")
verbatim = ("hostname sw-secret\nsnmp-server community s3cr3t-value RO\n")
db.add_backup(2, verbatim, redacted=False)   # store_secrets was ON at capture time
db.backfill_one_device(2)
check("indexed", db.has_search_lines(2) is True)
result = cs.search(db, "s3cr3t-value", mode="text")
check("the real secret is not findable through the backfilled index either",
      not any(m["device_id"] == 2 for m in result["matches"]), result)
result = cs.search(db, "snmp-server community", mode="text")
check("the redacted line IS findable (directive survives redaction)",
      any(m["device_id"] == 2 and "<redacted>" in m["line"] for m in result["matches"]), result)

print("backfill_one_device does nothing for a device with no stored backup at all")
db.backfill_one_device(999)
check("no rows appear for a device that was never backed up",
      db.has_search_lines(999) is False)


# -------------------------------------- 3. start_search_backfill: the sweep

print("start_search_backfill: chunked and resumable across a small fleet")
fleet_db = ConfigRxDatabase(os.path.join(TMPDIR, "fleet.configrx.db"))
# A small chunk size so 5 devices actually exercise more than one chunk,
# without needing a fleet-sized fixture to prove the same mechanics.
configrxdb.SEARCH_BACKFILL_CHUNK_DEVICES = 2
DEVICE_IDS = [10, 11, 12, 13, 14]
for device_id in DEVICE_IDS:
    fleet_db.add_backup(device_id, f"hostname sw{device_id}\ninterface Gi0/1\n")
check("none of the fleet is indexed yet (bare add_backup, no worker involved)",
      all(not fleet_db.has_search_lines(d) for d in DEVICE_IDS))

fleet_db.start_search_backfill()
deadline = time.time() + 10
while (fleet_db._search_backfill_thread is not None
      and fleet_db._search_backfill_thread.is_alive() and time.time() < deadline):
    time.sleep(0.05)
check("the backfill thread finished within the deadline",
      fleet_db._search_backfill_thread is None or not fleet_db._search_backfill_thread.is_alive())
check("every device in the fleet is now indexed",
      all(fleet_db.has_search_lines(d) for d in DEVICE_IDS),
      {d: fleet_db.has_search_lines(d) for d in DEVICE_IDS})
check("the resume cursor is left at the fleet's highest device_id (a "
      "permanent high-water mark, not cleared back to 0 — see "
      "_write_search_backfill_cursor's own docstring for why a device_id "
      "once walked never needs walking again)",
      fleet_db._read_search_backfill_cursor() == max(DEVICE_IDS),
      fleet_db._read_search_backfill_cursor())

print("start_search_backfill is a cheap no-op once the fleet is fully indexed")
calls = []
_orig_backfill_one = fleet_db.backfill_one_device
fleet_db.backfill_one_device = lambda d: (calls.append(d), _orig_backfill_one(d))[-1]
fleet_db.start_search_backfill()
deadline = time.time() + 2
while (fleet_db._search_backfill_thread is not None
      and fleet_db._search_backfill_thread.is_alive() and time.time() < deadline):
    time.sleep(0.02)
check("no device was touched a second time — a fully-indexed fleet costs "
      "nothing on a later Start/Stop of the worker",
      calls == [], calls)
fleet_db.backfill_one_device = _orig_backfill_one

print("an interrupted backfill resumes from the persisted cursor, not from scratch")
resume_db = ConfigRxDatabase(os.path.join(TMPDIR, "resume.configrx.db"))
configrxdb.SEARCH_BACKFILL_CHUNK_DEVICES = 2
RESUME_IDS = [20, 21, 22, 23, 24, 25]
for device_id in RESUME_IDS:
    resume_db.add_backup(device_id, f"hostname sw{device_id}\n")
# Simulate close() landing mid-fleet: run one chunk's worth directly, then
# signal stop exactly like close() does, rather than racing a real
# background thread for a precise interruption point.
cursor = resume_db._read_search_backfill_cursor()
resume_db._search_backfill_stop.clear()
first_chunk = [r["device_id"] for r in resume_db._conn.execute(
    "SELECT DISTINCT device_id FROM backups WHERE device_id > ? ORDER BY device_id LIMIT ?",
    (cursor, configrxdb.SEARCH_BACKFILL_CHUNK_DEVICES)).fetchall()]
for device_id in first_chunk:
    resume_db.backfill_one_device(device_id)
with resume_db._lock:
    resume_db._write_search_backfill_cursor(first_chunk[-1])
    resume_db._conn.commit()
check("exactly one chunk's worth indexed so far",
      [resume_db.has_search_lines(d) for d in RESUME_IDS] ==
      [True] * len(first_chunk) + [False] * (len(RESUME_IDS) - len(first_chunk)),
      {d: resume_db.has_search_lines(d) for d in RESUME_IDS})
check("the persisted cursor is where this chunk stopped, not 0 and not the end",
      resume_db._read_search_backfill_cursor() == first_chunk[-1])

# Now let it finish, the way the next process start would.
resume_db.start_search_backfill()
deadline = time.time() + 10
while (resume_db._search_backfill_thread is not None
      and resume_db._search_backfill_thread.is_alive() and time.time() < deadline):
    time.sleep(0.05)
check("resuming from the persisted cursor finishes the rest of the fleet, "
      "not the whole thing again",
      all(resume_db.has_search_lines(d) for d in RESUME_IDS),
      {d: resume_db.has_search_lines(d) for d in RESUME_IDS})

configrxdb.SEARCH_BACKFILL_CHUNK_DEVICES = 200   # restore the real default


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

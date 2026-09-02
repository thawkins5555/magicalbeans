"""The application must open databases written by the previous release.

4.34.0 could not: an index on a column the migration adds was also in the
schema script, which runs first, so every existing nodes.db failed to open.
Every other suite starts from empty files and never sees an upgrade.

Two parts. The first always runs: a fresh nodes.db is rebuilt into its 4.33
shape (the mac_entries table without first_seen_ts/present, and without the
index on them) and reopened. The second needs git history: the previous
main commit is exported with `git archive`, every database is created by
that tree's own Service, and the current Service is started on them — the
exact path that failed. It is skipped, loudly, when git cannot export."""
import os
import sqlite3
import subprocess
import sys
import time

from _paths import REPO_ROOT, tmpdir

from netpath.alertsdb import AlertsDatabase
from netpath.nodesdb import NodesDatabase

PREVIOUS_RELEASE = "b0217ed"      # 4.33.1 on main, the last commit before 4.34.0
DB_NAMES = ("netpath.db", "flows.db", "syslog.db", "app.db", "ipam.db",
            "snmptraps.db", "nodes.db", "alerts.db", "wireless.db", "configrx.db")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------ part 1: the 4.33 shape
work = tmpdir("upgrade_prev_")
nodes_path = os.path.join(work, "nodes.db")
db = NodesDatabase(nodes_path)
gid = db.ensure_default_group()
device_id = db.add_device("10.0.0.7", name="old-sw", group_id=gid)
db.replace_mac_entries(device_id, [{"if_index": 3, "mac": "aa:bb:cc:dd:ee:07", "vlan": "7"}],
                       now=time.time() - 600)
db.close()

conn = sqlite3.connect(nodes_path)
conn.executescript("""
    DROP INDEX IF EXISTS ix_mac_entries_mac_present;
    CREATE TABLE mac_entries_433 (
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        if_index  INTEGER NOT NULL,
        mac       TEXT NOT NULL,
        vlan      TEXT NOT NULL DEFAULT '',
        seen_ts   REAL NOT NULL,
        PRIMARY KEY (device_id, if_index, mac, vlan)
    );
    INSERT INTO mac_entries_433 SELECT device_id, if_index, mac, vlan, seen_ts FROM mac_entries;
    DROP TABLE mac_entries;
    ALTER TABLE mac_entries_433 RENAME TO mac_entries;
    CREATE INDEX IF NOT EXISTS ix_mac_entries_mac ON mac_entries(mac);
    CREATE INDEX IF NOT EXISTS ix_mac_entries_seen ON mac_entries(seen_ts);
""")
conn.commit()
cols = {r[1] for r in conn.execute("PRAGMA table_info(mac_entries)")}
conn.close()
check("the fixture really is the 4.33 shape", "present" not in cols and "first_seen_ts" not in cols, cols)

try:
    db = NodesDatabase(nodes_path)
except sqlite3.OperationalError as exc:
    check("a 4.33 nodes.db opens with the current code", False, exc)
    db = None
if db is not None:
    check("a 4.33 nodes.db opens with the current code", True)
    cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(mac_entries)").fetchall()}
    check("...and the migration added the two columns", {"present", "first_seen_ts"} <= cols, cols)
    idx = {r["name"] for r in db._conn.execute("PRAGMA index_list(mac_entries)").fetchall()}
    check("...and the index on them", "ix_mac_entries_mac_present" in idx, idx)
    rows = db.mac_entries_for(device_id)
    check("existing rows read as present with first_seen backfilled",
          len(rows) == 1 and rows[0]["present"] == 1 and rows[0]["first_seen_ts"] == rows[0]["seen_ts"],
          [dict(r) for r in rows])
    check("the Find box still finds them", len(db.mac_locations("aabbcc")) == 1)
    db.close()
    db = NodesDatabase(nodes_path)      # a second open must be a no-op migration
    check("reopening an already-migrated database is fine", True)
    db.close()

alerts_path = os.path.join(work, "alerts.db")
AlertsDatabase(alerts_path).close()
check("alerts.db opens twice (its 4.34 index is migration-only)",
      AlertsDatabase(alerts_path).close() is None)

# ------------------------------------------- part 2: the previous release
old = os.path.join(work, "old")
os.makedirs(old, exist_ok=True)
exported = False
try:
    archive = subprocess.run(["git", "archive", PREVIOUS_RELEASE], cwd=REPO_ROOT,
                             capture_output=True, timeout=60)
    if archive.returncode == 0:
        subprocess.run(["tar", "-x", "-C", old], input=archive.stdout, check=True, timeout=60)
        exported = os.path.isfile(os.path.join(old, "netpath", "__init__.py"))
except (OSError, subprocess.SubprocessError):
    exported = False

if not exported:
    print(f"SKIP  git could not export {PREVIOUS_RELEASE}; the previous-release start is not run here")
else:
    dbdir = os.path.join(work, "prev")
    os.makedirs(dbdir)
    paths = [os.path.join(dbdir, n) for n in DB_NAMES]
    seed = subprocess.run([sys.executable, "-c", f"""
import sys; sys.path.insert(0, {old!r})
from netpath.web import Service
import netpath
svc = Service(*{paths!r}); svc.start()
gid = svc.nodes_db.ensure_default_group()
d = svc.nodes_db.add_device("10.0.0.8", name="prev-sw", group_id=gid)
svc.nodes_db.replace_mac_entries(d, [{{"if_index": 1, "mac": "aabbccddee08", "vlan": ""}}])
svc.shutdown()
print(netpath.__version__)
"""], capture_output=True, text=True, timeout=120)
    check("the previous release created its databases",
          seed.returncode == 0 and seed.stdout.strip(), seed.stderr[-400:])
    if seed.returncode == 0:
        print(f"      previous release: {seed.stdout.strip().splitlines()[-1]}")
        started = subprocess.run([sys.executable, "-c", f"""
import sys; sys.path.insert(0, {REPO_ROOT!r})
from netpath.web import Service
svc = Service(*{paths!r}); svc.start()
rows = svc.nodes_db.mac_locations("aabbcc")
svc.shutdown()
print("locations", len(rows), "present", rows[0]["present"] if rows else None)
"""], capture_output=True, text=True, timeout=120)
        check("the current release starts on the previous release's databases",
              started.returncode == 0, started.stderr[-600:])
        check("...and the previous release's MAC rows survive as present",
              "locations 1 present 1" in started.stdout, started.stdout[-200:])

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

"""The application must open databases written by the previous release.

4.34.0 could not: an index on a column the migration adds was also in the
schema script, which runs first, so every existing nodes.db failed to open.
Every other suite starts from empty files and never sees an upgrade.

Three parts. The first always runs: a fresh nodes.db is rebuilt into its
4.33 shape (the mac_entries table without first_seen_ts/present, and without
the index on them) and reopened. The second needs git history: the previous
main commit is exported with `git archive`, every database is created by
that tree's own Service, and the current Service is started on them — the
exact path that failed. It is skipped, loudly, when git cannot export. The
third is the other upgrade that has no fresh-install equivalent: accounts
that still live in a legacy netpath.db and the permissions the migration
owes them."""
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

# 4.37.0 replaces the alerts index that backs the engine's per-tick hand-
# resolve lookup: ix_alerts_dedup_state led with dedup_key, which that query
# does not constrain, so it could not range-scan `state='resolved' AND
# resolved_ts >= ?`. The swap happens in _migrate, so an existing alerts.db
# is where it has to be proved — a fresh one has never had the old index at
# all. The fixture is put back into the 4.36 shape by hand for that reason.
conn = sqlite3.connect(alerts_path)
conn.executescript("""
    DROP INDEX IF EXISTS ix_alerts_state_resolved;
    CREATE INDEX IF NOT EXISTS ix_alerts_dedup_state
        ON alerts(dedup_key, state, resolved_ts);
""")
conn.commit()
old_idx = {r[1] for r in conn.execute("PRAGMA index_list(alerts)")}
conn.close()
check("the fixture really is the 4.36 index shape",
      "ix_alerts_dedup_state" in old_idx
      and "ix_alerts_state_resolved" not in old_idx, old_idx)

alerts_db = AlertsDatabase(alerts_path)
new_idx = {r["name"] for r in
           alerts_db._conn.execute("PRAGMA index_list(alerts)").fetchall()}
check("...and the migration creates the index the per-tick query needs",
      "ix_alerts_state_resolved" in new_idx, new_idx)
check("...and drops the one it replaces",
      "ix_alerts_dedup_state" not in new_idx, new_idx)
# The predicate comes from the database class itself rather than being
# spelled out again here: a copy would go on passing after the real one
# changed, which is the one thing this check exists to catch.
plan = " ".join(str(r[-1]) for r in alerts_db._conn.execute(
    "EXPLAIN QUERY PLAN SELECT dedup_key, MAX(resolved_ts) FROM alerts"
    f" WHERE state = 'resolved' AND {AlertsDatabase._OPERATOR_RESOLVE_SQL}"
    " AND resolved_ts >= 0 GROUP BY dedup_key").fetchall())
# The index has to be USED; whether the planner calls that SEARCH or
# "SCAN ... USING INDEX" (a covering-index scan is a perfectly good plan for
# this GROUP BY) varies by SQLite build, and asserting one of those spellings
# made the test a report on the local sqlite3 rather than on the schema.
check("...and the hand-resolve query is served by it",
      "ix_alerts_state_resolved" in plan, plan)
alerts_db.close()

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

# ------------------------------- part 3: permissions after the migration
# On an install that predates app.db the accounts are still in netpath.db
# when AppDatabase opens: Service copies them across with migrate_from()
# straight afterwards. A permission backfill inside the constructor would
# therefore grant against an empty users table — and spend its one-time
# marker doing it — so the accounts an upgrade owes access to would get
# none, ever. backfill_permissions() is the call that runs after the
# accounts are final, and this is the path it exists for.
from netpath.appdb import AppDatabase, migrate_from      # noqa: E402
from netpath import permissions as perms                 # noqa: E402

mig = os.path.join(work, "migrate")
os.makedirs(mig, exist_ok=True)
legacy_path = os.path.join(mig, "netpath.db")
legacy = sqlite3.connect(legacy_path)
legacy.executescript("""
    CREATE TABLE users (
        username     TEXT PRIMARY KEY,
        password     TEXT NOT NULL,
        created_ts   REAL NOT NULL,
        updated_ts   REAL NOT NULL,
        last_login   REAL,
        must_change  INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
""")
legacy.execute("INSERT INTO users(username, password, created_ts, updated_ts,"
               " must_change) VALUES ('olduser', 'not-a-real-hash', 1.0, 1.0, 0)")
legacy.execute("INSERT INTO settings(key, value) VALUES ('web_port', '8443')")
legacy.commit()
legacy.close()

app_db = AppDatabase(os.path.join(mig, "app.db"))
check("a fresh app.db knows nothing about the legacy account yet",
      app_db.permissions_for("olduser") == {}, app_db.permissions_for("olduser"))
migrate_from(app_db, legacy_path)
app_db.backfill_permissions()
granted = app_db.permissions_for("olduser")
check("an account migrated out of netpath.db holds write on every module",
      all(granted.get(module) == "write" for module in perms.MODULES), granted)
check("...ssh among them", granted.get("ssh") == "write", granted)

# And exactly once, in both halves: taking a permission away again sticks,
# whether the second call comes in the same process or after a restart.
app_db.set_permissions("olduser", {module: "write" for module in perms.MODULES
                                   if module != "ssh"})
app_db.backfill_permissions()
check("a second backfill grants nothing back",
      "ssh" not in app_db.permissions_for("olduser"),
      app_db.permissions_for("olduser"))
app_db.close()

restarted = AppDatabase(os.path.join(mig, "app.db"))
restarted.backfill_permissions()
check("...nor does the next start",
      "ssh" not in restarted.permissions_for("olduser"),
      restarted.permissions_for("olduser"))
restarted.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

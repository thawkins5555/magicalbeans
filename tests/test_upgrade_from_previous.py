"""The application must open databases written by the previous release; every
other suite starts from empty files and never sees an upgrade. Three parts:
a fresh nodes.db rebuilt into its pre-migration shape and reopened; the
previous main commit exported with `git archive`, its Service creating every
database, and the current Service started on them (skipped loudly when git
cannot export); and legacy netpath.db accounts receiving migrated permissions."""
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


def _safe_print(text: str) -> None:
    """print(), but never raises on a character this console's encoding
    cannot hold. Several check() calls below print a captured subprocess's
    stderr/stdout straight into the failure detail (`seed.stderr[-400:]`,
    `started.stdout[-200:]`, and the plain f-string a few lines further
    down) — that subprocess is the *previous release*, running under
    whatever its own environment defaulted its stdout encoding to (cp1252,
    same as this one, whenever neither end is a real terminal), so its
    output can contain anything, including a byte sequence this console
    cannot draw. tests/run_all.py hit exactly this printing a captured
    suite's own tail back out and was fixed the same way; this file needs
    its own copy of the fix because it runs as its own process with its own
    console encoding, not through that reconfigure.

    check() itself is made safe, rather than only reconfiguring this file's
    streams once at the top, because check() -- like every suite's own copy
    of it -- is exactly the kind of small helper that gets copied wholesale
    into the next test file rather than imported; a fix that only lives in
    a separate top-of-file block would not travel with it.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def check(name, ok, detail=""):
    _safe_print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
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
    _safe_print(f"SKIP  git could not export {PREVIOUS_RELEASE}; the previous-release start is not run here")
else:
    dbdir = os.path.join(work, "prev")
    os.makedirs(dbdir)
    paths = [os.path.join(dbdir, n) for n in DB_NAMES]
    seed = subprocess.run([sys.executable, "-c", f"""
import sys; sys.path.insert(0, {old!r})
import time
from netpath.web import Service
import netpath
svc = Service(*{paths!r}); svc.start()
gid = svc.nodes_db.ensure_default_group()
d = svc.nodes_db.add_device("10.0.0.8", name="prev-sw", group_id=gid)
svc.nodes_db.replace_mac_entries(d, [{{"if_index": 1, "mac": "aabbccddee08", "vlan": ""}}])
# The tables 5.0.0 moves out of nodes.db, seeded here so the upgrade start
# below has a real split to perform rather than an empty one.
mid = svc.nodes_db.record_metric_sample(d, "cpu_pct", "CPU", "%", "gauge", time.time(), 12.0)
fid = svc.nodes_db.add_mib_file("PREV.mib", "PREV-MIB", 1, [], "", "PREV DEFINITIONS")
svc.nodes_db.replace_mib_objects(fid, [{{"name": "prevObj", "oid": "1.3.6.1.4.1.4242.1"}}])
svc.nodes_db.update_device(d, mib_file_id=fid)
hour = int(time.time() // 3600) * 3600
svc.nodes_db._conn.executemany(
    "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax) VALUES (?,?,?,?,?,?)",
    [(mid, hour - (i + 2) * 3600, 6, 1.0, 5.0, 9.0) for i in range(24)])
svc.nodes_db._conn.commit()
svc.shutdown()
print(netpath.__version__)
"""], capture_output=True, text=True, timeout=120)
    check("the previous release created its databases",
          seed.returncode == 0 and seed.stdout.strip(), seed.stderr[-400:])
    if seed.returncode == 0:
        _safe_print(f"      previous release: {seed.stdout.strip().splitlines()[-1]}")
        started = subprocess.run([sys.executable, "-c", f"""
import sys; sys.path.insert(0, {REPO_ROOT!r})
from netpath.web import Service
svc = Service(*{paths!r}); svc.start()
rows = svc.nodes_db.mac_locations("aabbcc")
nodes = svc.nodes_db
# The 5.0.0 split runs on its own thread; join it before reading, since
# shutdown() would close the databases these figures come from.
if svc._nodes_split_thread is not None:
    svc._nodes_split_thread.join(timeout=60)
report = (nodes._private_setting("split_state"),
          len(nodes.series_db.metrics_for_keys(["cpu_pct"])),
          nodes.series_db._conn.execute(
              "SELECT COUNT(*) FROM samples_hourly").fetchone()[0],
          any(r["filename"] == "PREV.mib" for r in nodes.mib_files()),
          any(o["name"] == "prevObj" for o in nodes.mib_objects()))
svc.shutdown()
print("locations", len(rows), "present", rows[0]["present"] if rows else None)
print("split", report[0])
print("metrics", report[1])
print("rollups", report[2])
print("prevmib", report[3], report[4])
"""], capture_output=True, text=True, timeout=120)
        check("the current release starts on the previous release's databases",
              started.returncode == 0, started.stderr[-600:])
        check("...and the previous release's MAC rows survive as present",
              "locations 1 present 1" in started.stdout, started.stdout[-200:])
        check("...and the 5.0.0 nodes split ran to completion on that start",
              "split done" in started.stdout, started.stdout[-400:])
        check("...carrying the metric and its 24 hourly rollups across",
              "metrics 1" in started.stdout and "rollups 24" in started.stdout,
              started.stdout[-400:])
        check("...and the uploaded MIB file with its object",
              "prevmib True True" in started.stdout, started.stdout[-400:])

# ------------------------------- part 3: permissions after the migration
# On an install that predates app.db the accounts are still in netpath.db
# when AppDatabase opens: Service copies them across with migrate_from()
# straight afterwards. A permission backfill inside the constructor would
# therefore grant against an empty users table — and spend its one-time
# marker doing it — so the accounts an upgrade owes access to would get
# none, ever. backfill_permissions() is the call that runs after the
# accounts are final, and this is the path it exists for.
from netpath.appdb import (ADMIN_BACKFILL_MARKER, AppDatabase,   # noqa: E402
                          POST_SSH_MODULES, SSH_BACKFILL_MARKER, migrate_from)
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

# ------------------- part 4: a module added to an install that ALREADY has
# permissions. Part 3 covers the install that predates user_permissions
# entirely, where _backfill_full_permissions hands out every module in
# MODULES and so covers a new one for free. The far commoner upgrade is the
# one it does NOT cover: an install whose accounts already have rows, where
# only the named per-module backfills run. 4.54 shipped `mapper` with no
# such backfill, so every account on every upgraded install had no row for
# it — and app.js hides a tab the account cannot read, so the new module was
# invisible, to the administrator included, with nothing saying why. This is
# that path.
existing = os.path.join(work, "existing")
os.makedirs(existing, exist_ok=True)
existing_db = os.path.join(existing, "app.db")
# Opened and closed once first, deliberately: _needs_full_backfill is decided
# in _before_schema by whether user_permissions existed BEFORE this open, so
# a brand-new file always says "yes" and _backfill_full_permissions would
# hand every account write on every module -- including mapper, masking the
# very gap this part exists to test. The second open sees the table the first
# one created and takes the per-module path a real upgraded install takes.
AppDatabase(existing_db).close()
have_perms = AppDatabase(existing_db)
# An install that already went through the earlier permission backfills:
# mark them spent, the way a real 4.53 app.db would have them.
have_perms.set_meta(SSH_BACKFILL_MARKER, "1")
have_perms.set_meta(ADMIN_BACKFILL_MARKER, "1")
for name in ("noc", "viewer", "billing"):
    have_perms.add_user(name, "not-a-real-hash")
have_perms.set_permissions("noc", {"nodes": "write", "alerts": "write"})
have_perms.set_permissions("viewer", {"nodes": "read"})
have_perms.set_permissions("billing", {"settings": "write"})
check("no account has a mapper row before the backfill",
      all("mapper" not in have_perms.permissions_for(n)
          for n in ("noc", "viewer", "billing")),
      [have_perms.permissions_for(n) for n in ("noc", "viewer", "billing")])

have_perms.backfill_permissions()
check("an account with nodes:write gets mapper:write",
      have_perms.permissions_for("noc").get("mapper") == "write",
      have_perms.permissions_for("noc"))
check("...an account with nodes:read gets mapper:read, not write",
      have_perms.permissions_for("viewer").get("mapper") == "read",
      have_perms.permissions_for("viewer"))
check("...and an account with no Nodes access gets no mapper row at all",
      "mapper" not in have_perms.permissions_for("billing"),
      have_perms.permissions_for("billing"))

# Same one-time contract the other two backfills keep.
have_perms.set_permissions("noc", {"nodes": "write", "alerts": "write"})
have_perms.backfill_permissions()
check("revoking mapper sticks across a second backfill",
      "mapper" not in have_perms.permissions_for("noc"),
      have_perms.permissions_for("noc"))
have_perms.close()

# ------------------- part 5: adding a module must not break the ssh backfill
# _backfill_ssh_permission grants ssh to whoever "holds write on everything
# else". Every module appended after ssh has to be excluded from that test,
# because no pre-existing account has a row for it — include one and the
# test is true of nobody, and the backfill silently grants ssh to no one on
# the very upgrade it exists for. `admin` was excluded by hand in 4.37;
# `mapper` was NOT when it was added in 4.54, which is the regression this
# pins. POST_SSH_MODULES is the single list both the code and this check
# read, so the next module added is a one-line change in one place.
check("every module appended after ssh is excluded from its backfill test",
      all(module in POST_SSH_MODULES for module in ("ssh", "admin", "mapper", "web")),
      POST_SSH_MODULES)

fresh_ssh = os.path.join(work, "sshgrant")
os.makedirs(fresh_ssh, exist_ok=True)
ssh_path = os.path.join(fresh_ssh, "app.db")
AppDatabase(ssh_path).close()          # same reason as part 4's first open
ssh_db = AppDatabase(ssh_path)
ssh_db.add_user("sysadmin", "not-a-real-hash")
# Write on every module that predates ssh — and, as on any real upgraded
# install, no row at all for ssh, admin or mapper.
ssh_db.set_permissions("sysadmin", {module: "write" for module in perms.MODULES
                                    if module not in POST_SSH_MODULES})
ssh_db.backfill_permissions()
check("an account holding write on every older module still earns ssh",
      ssh_db.permissions_for("sysadmin").get("ssh") == "write",
      ssh_db.permissions_for("sysadmin"))
# 5.1's `web` has no backfill of its own, on purpose: it opens a listening
# port on this host that carries bytes to a device's management page, which
# nobody could do before, so nobody inherits it — not even the account that
# just earned `ssh` here for holding write on everything older. A missing
# row already means no access, which is what makes "no backfill" a complete
# implementation rather than an omission.
check("no account is granted web on upgrade, not even a full-write one",
      "web" not in ssh_db.permissions_for("sysadmin"),
      ssh_db.permissions_for("sysadmin"))
ssh_db.close()

# A fresh install is the other half of that claim: Service._ensure_default_user
# grants the seeded admin `{m: WRITE for m in permissions.MODULES}`, so `web`
# being in that tuple is exactly what makes the relay reachable out of the box
# on a new install while an upgraded one starts with nobody holding it. Both
# facts are checked here rather than one, because either alone would be
# consistent with the feature shipping unreachable.
check("web is in MODULES, so the fresh-install grant covers it",
      "web" in perms.MODULES, perms.MODULES)
fresh_web = os.path.join(work, "webgrant")
os.makedirs(fresh_web, exist_ok=True)
web_db = AppDatabase(os.path.join(fresh_web, "app.db"))
web_db.backfill_permissions()          # no users at all: nothing to grant
check("a backfill on an empty database grants nobody web",
      web_db.usernames_with("web", "write") == [],
      web_db.usernames_with("web", "write"))
web_db.close()

# ------------------- part 6: 5.0.0's nodes.db index changes on a 4.54 file
# The neighbour match's two case-insensitive joins were LOWER() on both
# sides, which is an expression and so cannot use any index: every map GET
# and every neighbours read folded every row of `devices` (twice) and
# `interfaces` (once) per neighbour row. They are collated comparisons now,
# against two NOCASE indexes _migrate creates -- and _migrate drops three
# older indexes that only ever duplicated the leading column of their own
# table's PRIMARY KEY. A 4.54 file is where both have to be proved: a fresh
# one never had the duplicates, and gets the new indexes from the same
# _migrate on its first open.
indexes = os.path.join(work, "indexes")
os.makedirs(indexes, exist_ok=True)
idx_path = os.path.join(indexes, "nodes.db")
NodesDatabase(idx_path).close()
conn = sqlite3.connect(idx_path)
conn.executescript("""
    DROP INDEX IF EXISTS ix_devices_sys_name_nocase;
    DROP INDEX IF EXISTS ix_interfaces_phys_addr_nocase;
    CREATE INDEX IF NOT EXISTS ix_vlans_device ON vlans(device_id);
    CREATE INDEX IF NOT EXISTS ix_vlan_ports_device ON vlan_ports(device_id);
    CREATE INDEX IF NOT EXISTS ix_port_vlans_device ON port_vlans(device_id);
""")
conn.commit()
before = {r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'ix_%'")}
conn.close()
check("the fixture really is the 4.54 index shape",
      "ix_vlans_device" in before and "ix_devices_sys_name_nocase" not in before, before)

idx_db = NodesDatabase(idx_path)
after = {r["name"] for r in idx_db._conn.execute(
    "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'ix_%'").fetchall()}
check("...and the migration adds the two NOCASE indexes the neighbour match needs",
      {"ix_devices_sys_name_nocase", "ix_interfaces_phys_addr_nocase"} <= after, after)
check("...and drops the three that duplicated a PRIMARY KEY's leading column",
      not ({"ix_vlans_device", "ix_vlan_ports_device", "ix_port_vlans_device"} & after),
      after)
# The SQL comes from the class, not a copy: a copy would go on passing
# after the real one changed, which is the one thing this exists to catch.
plan = " ".join(str(r[-1]) for r in idx_db._conn.execute(
    "EXPLAIN QUERY PLAN " + NodesDatabase._NEIGHBOR_MATCH_SQL).fetchall())
check("...and the neighbour match is served by them, not by a scan per row",
      "ix_devices_sys_name_nocase" in plan and "ix_interfaces_phys_addr_nocase" in plan,
      plan)
check("...and the sysName join's other half still uses the index it always had",
      "ix_devices_name_ip" in plan, plan)
idx_db.close()

reopened = NodesDatabase(idx_path)
again = {r["name"] for r in reopened._conn.execute(
    "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'ix_%'").fetchall()}
check("reopening an already-migrated database changes nothing", again == after, again)
reopened.close()

# ------------------- part 7: 5.3.0's optic power rules on a 5.2 alerts.db
# The two migrations that carry an existing install across the change, in
# the order they must run. The fixture is a 5.2-shaped alerts.db built by
# hand: the six new rules absent, the two old ones still carrying their
# global numbers (one of them tuned AND muted by the operator), and
# dampen_new_builtin_siblings_1 already recorded -- which is exactly why
# 5.3.0 needs a SECOND named entry for that same method. Without it the six
# new rules arrive enabled and emailing on an install whose operator
# deliberately silenced the one rule they read the same metric as.
optic = os.path.join(work, "optic")
os.makedirs(optic, exist_ok=True)
optic_path = os.path.join(optic, "alerts.db")
AlertsDatabase(optic_path).close()
conn = sqlite3.connect(optic_path)
conn.executescript("""
    DELETE FROM rules WHERE key IN (
        'sfp_rx_power_low_alarm', 'sfp_rx_power_high', 'sfp_rx_power_high_alarm',
        'sfp_tx_power_low_alarm', 'sfp_tx_power_high', 'sfp_tx_power_high_alarm');
    UPDATE rules SET threshold = -22.0, clear_threshold = -20.0
        WHERE key = 'sfp_rx_power_low';
    -- tuned AND muted: this site's optics run near the old global floor
    UPDATE rules SET threshold = -15.0, clear_threshold = -13.0, notify = 0
        WHERE key = 'sfp_tx_power_low';
    -- an unrelated rule the operator also tuned, which nothing here may touch
    UPDATE rules SET threshold = 95.0, clear_threshold = 85.0 WHERE key = 'cpu_high';
    -- Two optic power alerts the 5.2 engine raised off its global number, on
    -- a switch that publishes no bands of its own. From 5.3.0 the evaluator
    -- never reaches those ports again, so nothing left to itself would ever
    -- clear these; the acked one goes too.
    INSERT INTO alerts (rule_id, dedup_key, entity_kind, entity_id,
                        entity_label, severity, message, state,
                        opened_ts, last_ts)
        SELECT id, 'sfp_rx_power_low:interface:9:7', 'interface', '9:7',
               'ex-4300 / ge-0/0/7', 4, 'low light', 'open', 1000.0, 1000.0
          FROM rules WHERE key = 'sfp_rx_power_low';
    INSERT INTO alerts (rule_id, dedup_key, entity_kind, entity_id,
                        entity_label, severity, message, state, acked_by,
                        opened_ts, last_ts)
        SELECT id, 'sfp_tx_power_low:interface:9:8', 'interface', '9:8',
               'ex-4300 / ge-0/0/8', 4, 'low light', 'acked', 'jo',
               1000.0, 1000.0
          FROM rules WHERE key = 'sfp_tx_power_low';
    -- ...and one that has nothing to do with optics, which must stay open
    INSERT INTO alerts (rule_id, dedup_key, entity_kind, entity_id,
                        entity_label, severity, message, state,
                        opened_ts, last_ts)
        SELECT id, 'cpu_high:device:9', 'device', '9', 'ex-4300', 3,
               'cpu hot', 'open', 1000.0, 1000.0
          FROM rules WHERE key = 'cpu_high';
    DELETE FROM schema_migrations WHERE name IN (
        'dampen_optic_power_siblings_1', 'clear_optic_power_thresholds_1',
        'resolve_unpublished_optic_power_alerts_1');
""")
conn.commit()
before = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
keys = {r[0] for r in conn.execute("SELECT key FROM rules")}
conn.close()
check("the fixture really is the 5.2 shape: six new rules absent, the "
      "older dampen migration already recorded",
      "sfp_rx_power_low_alarm" not in keys
      and "dampen_new_builtin_siblings_1" in before
      and "dampen_optic_power_siblings_1" not in before, (sorted(before), sorted(keys)))

optic_db = AlertsDatabase(optic_path)
EIGHT = ("sfp_rx_power_low", "sfp_rx_power_low_alarm", "sfp_rx_power_high",
         "sfp_rx_power_high_alarm", "sfp_tx_power_low", "sfp_tx_power_low_alarm",
         "sfp_tx_power_high", "sfp_tx_power_high_alarm")
rows = {key: optic_db.rule_by_key(key) for key in EIGHT}
check("all eight optic power rules exist after the upgrade",
      all(rows[key] is not None for key in EIGHT),
      [key for key in EIGHT if rows[key] is None])
check("every one of them has a NULL threshold and clear_threshold -- "
      "including the two that carried an operator's own numbers, which the "
      "engine no longer reads and which would otherwise sit on the Rules "
      "page reading as the live limit",
      all(rows[key]["threshold"] is None and rows[key]["clear_threshold"] is None
          for key in EIGHT),
      {key: (rows[key]["threshold"], rows[key]["clear_threshold"]) for key in EIGHT})
check("the three new siblings of the MUTED tx rule inherit notify = 0: an "
      "operator who silenced one rule over a metric does not get three new "
      "ones emailing them about the same reading",
      all(rows[key]["notify"] == 0 for key in
          ("sfp_tx_power_low_alarm", "sfp_tx_power_high",
           "sfp_tx_power_high_alarm")),
      {key: rows[key]["notify"] for key in EIGHT})
check("...and the rx siblings, whose own sibling was never muted, stay on",
      all(rows[key]["notify"] == 1 and rows[key]["enabled"] == 1 for key in
          ("sfp_rx_power_low_alarm", "sfp_rx_power_high",
           "sfp_rx_power_high_alarm")),
      {key: (rows[key]["enabled"], rows[key]["notify"]) for key in EIGHT})
check("the comparisons land right way round on the new rules",
      all(rows[key]["comparison"] == ("below" if "_low" in key else "above")
          for key in EIGHT),
      {key: rows[key]["comparison"] for key in EIGHT})
cpu = optic_db.rule_by_key("cpu_high")
check("an unrelated rule the operator tuned is untouched",
      (cpu["threshold"], cpu["clear_threshold"]) == (95.0, 85.0), dict(cpu))


def alert_row(db, dedup):
    return db._conn.execute(
        "SELECT state, resolved_by, rollup_note FROM alerts WHERE dedup_key = ?",
        (dedup,)).fetchone()


rx_alert = alert_row(optic_db, "sfp_rx_power_low:interface:9:7")
tx_alert = alert_row(optic_db, "sfp_tx_power_low:interface:9:8")
check("an optic power alert standing open from 5.2 is resolved by the "
      "upgrade: the rule now reads the optic's own limits, this port "
      "publishes none, and no tick will ever reach it again",
      rx_alert is not None and rx_alert["state"] == "resolved"
      and rx_alert["resolved_by"] == "", dict(rx_alert) if rx_alert else None)
check("...the ACKED one too -- an operator who ticked it off is no more "
      "able to clear it than one who did not",
      tx_alert is not None and tx_alert["state"] == "resolved",
      dict(tx_alert) if tx_alert else None)
check("...each carrying a note saying why, rather than vanishing",
      rx_alert is not None and "publishes none" in (rx_alert["rollup_note"] or ""),
      rx_alert["rollup_note"] if rx_alert else None)
cpu_alert = alert_row(optic_db, "cpu_high:device:9")
check("an open alert of an unrelated rule is left alone",
      cpu_alert is not None and cpu_alert["state"] == "open",
      dict(cpu_alert) if cpu_alert else None)
temp = optic_db.rule_by_key("sfp_temp_high")
check("sfp_temp_high keeps its own threshold: only optical POWER moved to "
      "published limits",
      temp["threshold"] == 70.0, dict(temp))
optic_db.close()

reopened = AlertsDatabase(optic_path)
again = {key: dict(reopened.rule_by_key(key)) for key in EIGHT}
check("reopening the upgraded database changes nothing -- both migrations "
      "are recorded and the dampen half is idempotent by construction",
      again == {key: dict(rows[key]) for key in EIGHT} or
      all(again[key]["threshold"] is None and again[key]["notify"] ==
          rows[key]["notify"] for key in EIGHT),
      {key: (again[key]["threshold"], again[key]["notify"]) for key in EIGHT})
reopened.close()

# ------- part 8: the second dampen pass must not reach the temperature pair
# dampen_optic_power_siblings_1 exists for 5.3.0's six optic keys, but the
# method it re-runs walks the whole of _NEW_SIBLING_OF -- including the
# temperature pair dampen_new_builtin_siblings_1 already settled in 4.54.
# The state below is the one that gets hurt: nothing was inherited then
# (both rules pristine), the operator has since muted temp_chassis_high and
# deliberately left temp_chassis_critical enabled at its shipped numbers.
# A second pass over that pair reads the sibling as touched and the new row
# as untouched, and silently reverts their choice.
temps = os.path.join(work, "temps")
os.makedirs(temps, exist_ok=True)
temps_path = os.path.join(temps, "alerts.db")
AlertsDatabase(temps_path).close()
conn = sqlite3.connect(temps_path)
conn.executescript("""
    UPDATE rules SET notify = 0 WHERE key = 'temp_chassis_high';
    DELETE FROM schema_migrations WHERE name IN (
        'dampen_optic_power_siblings_1', 'clear_optic_power_thresholds_1',
        'resolve_unpublished_optic_power_alerts_1');
""")
conn.commit()
critical_before = conn.execute(
    "SELECT enabled, notify, threshold FROM rules"
    " WHERE key = 'temp_chassis_critical'").fetchone()
conn.close()
check("the fixture really is the state that gets hurt: the sibling muted, "
      "Critical enabled and still on its shipped numbers",
      critical_before == (1, 1, 85.0), critical_before)

temps_db = AlertsDatabase(temps_path)
critical = temps_db.rule_by_key("temp_chassis_critical")
check("an operator who muted Chassis temperature high and deliberately left "
      "Chassis temperature critical on keeps it: 5.3.0's optic dampen pass "
      "is about the optic keys and must not re-decide a temperature pair "
      "4.54 already settled",
      critical["enabled"] == 1 and critical["notify"] == 1, dict(critical))
check("...at its own shipped numbers, unshifted",
      (critical["threshold"], critical["clear_threshold"]) == (85.0, 78.0),
      dict(critical))
high = temps_db.rule_by_key("temp_chassis_high")
check("...and the muted sibling is left exactly as the operator set it",
      high["notify"] == 0 and high["enabled"] == 1, dict(high))
temps_db.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

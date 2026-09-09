"""Every hot read in every store, timed and with its query plan recorded.

Deliberately not a test_*.py: what a query costs depends on the disk and the
CPU under it, so this prints numbers rather than asserting them (run_all.py
only picks up test_*.py).

    python3 tests/bench_db_search.py [scale ...] [--repeats N]

Each `scale` figure is one run: every store is seeded to `scale` times the
base volume below and every query is timed `--repeats` times (default 15,
after one warm-up that is not counted). Defaults to `1 4 16`, which puts the
Nodes fleet at 500, 2,000 and 8,000 devices — 2,000 is the size the comment
at nodesdb.py:1282-1289 records its ~13 ms text search against, so that tier
is what proves or disproves the number rather than an approximation of it.

The `plan` column is the FIRST line of `EXPLAIN QUERY PLAN` for the query
that was actually run — captured with sqlite3's trace callback while the
method executes, so it can never drift from the SQL the module builds. That
makes this a baseline of whether each read SCANs or SEARCHes, which is the
fact a later index would have to change. Where a method runs several
statements (flowdb.flows probes for a bound first; stats() asks two
questions) the longest SELECT is the one explained.

Base volumes per scale, against the retention caps each module ships:

    devices     500     no cap; 2,000 is the tier nodesdb's comment cites
    alerts    3,000     retention_days 180, max_alerts_db_mb 128
    syslog   10,000     retention_days 30, max_rows 20,000,000
    traps     5,000     retention_days 90, max_rows 5,000,000
    hosts     2,000     host_retention_days 30
    audit     5,000     never pruned — there is no retention key for it
    mib objs  2,000     no cap
    flows    25,000     retention_days 14, max_flows 5,000,000

The top default tier is a fraction of those caps on purpose: it is where the
shapes separate, and it finishes in minutes. A run against the cap is one
argument away (`python3 tests/bench_db_search.py 200`).
"""
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)
from _paths import tmpdir

from netpath.alertsdb import AlertsDatabase
from netpath.appdb import AppDatabase
from netpath.flowdb import FlowDatabase
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath import syslogparse
from netpath import trapdecode

BASE = {
    "devices": 500,
    "alerts": 3_000,
    "syslog": 10_000,
    "traps": 5_000,
    "hosts": 2_000,
    "audit": 5_000,
    "mib_objects": 2_000,
    "flows": 25_000,
}
IFACES_PER_DEVICE = 4
VENDORS = ("Cisco", "Juniper", "Arista", "Moxa")
DAY = 86400.0

# A real sysDescr is a banner, not a label, and the seven-column LIKE this
# bench exists to price is a full scan whose cost is the width of the row.
# A 40-character placeholder would have made every text search look cheap
# for a reason that has nothing to do with the query.
SYS_DESCR = (
    "%s Internetwork Operating System Software, IOS (tm) C3560 Software "
    "(C3560-IPSERVICESK9-M), Version 12.2(55)SE%d, RELEASE SOFTWARE (fc2), "
    "Copyright (c) 1986-2019 by cisco Systems, Inc., Compiled Mon "
    "%02d-Feb-19 03:%02d by prod_rel_team")

# The two text searches nodesdb's own comment is about: a word that lands in
# the columns it added (vendor/sys_descr), and an address prefix, which takes
# the same seven-column LIKE but is refused the MAC branch by
# looks_like_mac_search — digits and dots are an address in every case that
# matters.
WORD = "Moxa"
IP_PREFIX = "10.0.1."


# ------------------------------------------------------------ query plans

def plan_of(store, call):
    """The first EXPLAIN QUERY PLAN line for what `call` actually ran.

    sqlite3's trace callback hands back the statement with its parameters
    already substituted, so the plan is taken against the exact SQL the
    module built — no second, hand-copied version of the query to drift.
    """
    seen = []
    conn = store._conn
    conn.set_trace_callback(seen.append)
    try:
        call()
    finally:
        conn.set_trace_callback(None)
    selects = [sql for sql in seen if sql.lstrip()[:6].upper() == "SELECT"]
    if not selects:
        return "-"
    with store._lock:
        try:
            rows = conn.execute(
                "EXPLAIN QUERY PLAN " + max(selects, key=len)).fetchall()
        except Exception as exc:            # a plan is never worth a crash
            return "explain failed: %s" % exc
    return rows[0]["detail"] if rows else "-"


# ---------------------------------------------------------------- seeding

def seed_nodes(path, devices):
    db = NodesDatabase(path)
    group_id = db.ensure_default_group()
    device_groups = [db.add_device_group("site-%02d" % n) for n in range(20)]
    ids = db.add_devices_bulk([
        {"ip": "10.%d.%d.%d" % (n // 65025, n // 255 % 255, n % 255),
         "name": "sw-%04d.site%02d" % (n, n % 20),
         "group_id": group_id,
         "device_group_id": device_groups[n % len(device_groups)],
         "overrides": {}}
        for n in range(devices)])
    now = time.time()
    # The identity columns and the alias addresses in two statements rather
    # than seed_identity/record_address per device: both commit per call, and
    # the fixture is not what is being measured. One alias each is the shape
    # nodesdb.py:1297-1305 measured the alias subquery against.
    with db._lock:
        db._conn.executemany(
            "UPDATE devices SET sys_descr=?, sys_name=?, sys_location=?,"
            " sys_contact=?, vendor=?, vendor_detected=?, status=?"
            " WHERE id=?",
            [(SYS_DESCR % (VENDORS[n % 4], n % 9, 1 + n % 28, n % 60),
              "sw-%04d" % n, "Site-%02d rack %d" % (n % 20, n % 12),
              "netops@example.invalid", VENDORS[n % 4], VENDORS[n % 4],
              ("up", "up", "up", "down")[n % 4], device_id)
             for n, device_id in enumerate(ids)])
        db._conn.executemany(
            "INSERT INTO device_addresses(device_id, ip, source, seen_ts)"
            " VALUES (?,?,'snmp',?)",
            [(device_id, "192.168.%d.%d" % (n // 255 % 255, n % 255), now)
             for n, device_id in enumerate(ids)])
        db._conn.executemany(
            "INSERT INTO interfaces(device_id, if_index, descr, alias,"
            " speed_bps, admin_status, oper_status, last_seen_ts)"
            " VALUES (?,?,?,?,?,'up','up',?)",
            [(device_id, port + 1, "GigabitEthernet0/%d" % (port + 1),
              "access-%d" % (port + 1), 1000000000, now)
             for device_id in ids for port in range(IFACES_PER_DEVICE)])
        db._conn.commit()
    return db


def seed_mibs(nodes_db, objects):
    """MIB objects hang off NodesDatabase.mib_db, which its constructor opens
    as a sibling file — nodesmibdb is never opened directly by anything."""
    per_file = 500
    files = max(1, objects // per_file)
    for index in range(files):
        file_id = nodes_db.add_mib_file(
            "BENCH-%03d-MIB.txt" % index, "BENCH-%03d-MIB" % index,
            per_file, [], "")
        nodes_db.replace_mib_objects(file_id, [
            {"name": "benchObject%03d%04d" % (index, n),
             "oid": "1.3.6.1.4.1.9999.%d.%d" % (index, n),
             "description": "Bench object %d in file %d" % (n, index),
             "syntax": "INTEGER"}
            for n in range(per_file)])


def seed_alerts(path, rows):
    db = AlertsDatabase(path)
    rule_id = db.add_rule("bench.rule", "Bench rule", "threshold", "device")
    now = time.time()
    states = ("open", "open", "open", "acked", "resolved")
    with db._lock:
        db._conn.executemany(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, detail, state, count,"
            " opened_ts, last_ts, last_notified_ts, extra_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'{}')",
            [(rule_id, "bench:%d" % n, "device", str(n),
              "sw-%04d" % (n % 2000), 1 + n % 4,
              "Interface GigabitEthernet0/%d on %s is down"
              % (1 + n % 48, VENDORS[n % 4]),
              "link down for %d minutes" % (n % 600),
              states[n % len(states)], 1 + n % 5,
              now - 180 * DAY + n * (180 * DAY / max(rows, 1)),
              now - 180 * DAY + n * (180 * DAY / max(rows, 1)) + 60,
              None if n % 3 == 0 else now - 7200)
             for n in range(rows)])
        db._conn.commit()
    return db


# Six message shapes rather than one, so a search term is selective. A term
# every row contains would make the LIKE fallback look free: it walks
# ix_logs_ts newest-first and stops at LIMIT, so with a universal term it
# stops after 300 rows however large the table is, while FTS still has to
# match and then order. SYSLOG_COMMON lands in one shape in six;
# SYSLOG_RARE in one row in a thousand, which is the case an index exists
# for at all.
SYSLOG_TEMPLATES = (
    "%(vendor)s neighbor %(ip)s Down BGP Notification sent to peer",
    "Interface GigabitEthernet0/%(port)d changed state to down",
    "sshd: Accepted publickey for netops from %(ip)s port %(port)d",
    "kernel: martian source %(ip)s on eth0",
    "%%SYS-5-CONFIG_I: Configured from console by netops on %(vendor)s",
    "snmpd: Connection from UDP: [%(ip)s]:%(port)d",
)
SYSLOG_COMMON = "Notification"
SYSLOG_RARE = "quarantined"
SYSLOG_RARE_EVERY = 997


def seed_syslog(path, rows):
    db = SyslogDatabase(path)
    now = time.time()
    step = 30 * DAY / max(rows, 1)
    batch = []
    for n in range(rows):
        fields = {"vendor": VENDORS[n % 4], "port": 1 + n % 48,
                  "ip": "10.%d.%d.%d" % (n // 65025, n // 255 % 255, n % 255)}
        message = SYSLOG_TEMPLATES[n % len(SYSLOG_TEMPLATES)] % fields
        if n % SYSLOG_RARE_EVERY == 0:
            message += " host %s pending review" % SYSLOG_RARE
        batch.append(syslogparse.LogEntry(
            ts=now - 30 * DAY + n * step,
            source="10.0.%d.%d" % (n // 255 % 255, n % 255),
            host="sw-%04d" % (n % 2000), facility=1 + n % 20,
            severity=n % 8, app=("sshd", "bgpd", "kernel", "snmpd")[n % 4],
            procid=str(1000 + n % 500), msgid="",
            message="%s seq %d" % (message, n), raw=""))
        if len(batch) >= 5000:
            db.insert(batch)
            batch = []
    if batch:
        db.insert(batch)
    return db


def seed_traps(path, rows):
    db = SnmpTrapDatabase(path)
    now = time.time()
    step = 90 * DAY / max(rows, 1)
    batch = []
    for n in range(rows):
        batch.append(trapdecode.Trap(
            ts=now - 90 * DAY + n * step,
            source="10.0.%d.%d" % (n // 255 % 255, n % 255),
            version=2, community="public",
            trap_oid="1.3.6.1.6.3.1.1.5.%d" % (1 + n % 6),
            trap_name=("linkDown", "linkUp", "coldStart", "warmStart",
                       "authenticationFailure", "egpNeighborLoss")[n % 6],
            trap_kind=("link", "system", "auth")[n % 3],
            severity=n % 8, uptime=n * 100,
            varbinds=[], raw=b"",
            varbind_text="ifIndex=%d ifDescr=GigabitEthernet0/%d "
                         "ifAdminStatus=up vendor=%s"
                         % (1 + n % 48, 1 + n % 48, VENDORS[n % 4])))
        if len(batch) >= 5000:
            db.insert(batch)
            batch = []
    if batch:
        db.insert(batch)
    return db


def seed_ipam(path, rows):
    db = IpamDatabase(path)
    subnet_id = db.add_subnet("10.0.0.0/8", "Bench estate", "100")
    now = time.time()
    with db._lock:
        db._conn.executemany(
            "INSERT INTO hosts(ip, subnet_id, mac, alive, first_seen,"
            " last_seen, last_up, last_mac_ts) VALUES (?,?,?,?,?,?,?,?)",
            [("10.%d.%d.%d" % (n // 65025, n // 255 % 255, n % 255),
              subnet_id, "00:1b:%02x:%02x:%02x:%02x"
              % (n >> 24 & 255, n >> 16 & 255, n >> 8 & 255, n & 255),
              1 if n % 3 else 0, now - 30 * DAY, now - n, now - n, now - n)
             for n in range(rows)])
        db._conn.commit()
    return db


def seed_app(path, rows):
    db = AppDatabase(path)
    now = time.time()
    actions = ("device.update", "settings.change", "login", "alert.ack",
               "password.change")
    with db._lock:
        db._conn.executemany(
            "INSERT INTO audit(ts, username, client, action, target, detail)"
            " VALUES (?,?,?,?,?,?)",
            [(now - 365 * DAY + n * (365 * DAY / max(rows, 1)),
              ("admin", "operator", "netops")[n % 3],
              "10.0.0.%d" % (n % 255), actions[n % len(actions)],
              "device:10.0.%d.%d" % (n // 255 % 255, n % 255),
              "poll_interval_s: 300 -> %d on a %s"
              % (60 + n % 240, VENDORS[n % 4]))
             for n in range(rows)])
        db._conn.commit()
    return db


def seed_flows(path, rows):
    db = FlowDatabase(path)
    now = time.time()
    step = 14 * DAY / max(rows, 1)
    with db._lock:
        db._conn.executemany(
            "INSERT INTO flows(exporter, version, ts_start, ts_end, src_ip,"
            " dst_ip, src_port, dst_port, protocol, tos, in_if, out_if,"
            " src_as, dst_as, packets, bytes, sampling)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [("10.0.0.%d" % (n % 4), 9, now - 14 * DAY + n * step,
              now - 14 * DAY + n * step,
              "192.168.%d.%d" % (n // 251 % 256, n % 251),
              "8.8.%d.%d" % (n % 7, n % 13), 1024 + n % 4001,
              (80, 443, 53, 22)[n % 4], (6, 17)[n % 2], n % 8, n % 12,
              n % 12, 64500 + n % 5, 64600 + n % 5, 1 + n % 9,
              100 + n % 9973, (1, 2, 10)[n % 3])
             for n in range(rows)])
        db._conn.commit()
    return db


# ----------------------------------------------------------------- timing

def without_fts(syslog, t0, t1, text):
    """`search` down its LIKE fallback, whatever this host's SQLite can do.

    `_can_index` reads `self.fts`, which `_enable_fts` sets False on a build
    without FTS5 or with SQLite older than the trigram tokenizer. Flipping
    it here is what bench_flow_overview.py does to `_rollup_plan` for the
    same reason: measure the other path without keeping a second copy of the
    query in the bench.
    """
    real = syslog.fts
    syslog.fts = False
    try:
        return syslog.search(t0, t1, {"text": text})
    finally:
        syslog.fts = real


def count_of(result):
    """How many rows a call handed back, whatever shape it used to say so."""
    if result is None:
        return 0
    if isinstance(result, bool):
        return int(result)
    if isinstance(result, int):
        return result
    if isinstance(result, tuple):           # flowdb.flows -> (rows, bounded)
        return count_of(result[0])
    if isinstance(result, dict):
        # stats() answers with the table's own row count; open_summary()
        # has no such field, so its key count is the honest answer.
        return result.get("rows", len(result))
    try:
        return len(result)
    except TypeError:
        return 1


def percentile(values, fraction):
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * fraction))
    return ordered[index]


def time_case(store, label, query, call, repeats):
    result = call()                          # warm-up, not counted
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        call()
        samples.append((time.perf_counter() - started) * 1000.0)
    return {
        "store": store, "query": query, "rows": count_of(result),
        "mean": sum(samples) / len(samples),
        "p95": percentile(samples, 0.95),
        "plan": label,
    }


HEADER = ("%-11s %-44s %9s %9s %9s  %s"
          % ("store", "query", "rows", "mean ms", "p95 ms", "plan"))


def row(result):
    return ("%-11s %-44s %9s %9.2f %9.2f  %s"
            % (result["store"], result["query"][:44],
               "{:,}".format(result["rows"]), result["mean"], result["p95"],
               result["plan"]))


# -------------------------------------------------------------------- cases

def cases(stores):
    """(store label, query label, store-for-EXPLAIN, callable) per row.

    The store handed over for EXPLAIN is the one whose connection actually
    runs the statement — mib_objects is forwarded to NodesDatabase.mib_db's
    own file, not to nodes.db.
    """
    nodes = stores["nodes"]
    alerts = stores["alerts"]
    syslog = stores["syslog"]
    traps = stores["traps"]
    ipam = stores["ipam"]
    app = stores["app"]
    flows = stores["flows"]
    now = time.time()

    return [
        ("nodesdb", "devices(text='%s')" % WORD, nodes,
         lambda: nodes.devices(text=WORD)),
        ("nodesdb", "devices_count(text='%s')" % WORD, nodes,
         lambda: nodes.devices_count(text=WORD)),
        ("nodesdb", "devices(text='%s')" % IP_PREFIX, nodes,
         lambda: nodes.devices(text=IP_PREFIX)),
        ("nodesdb", "devices_count(text='%s')" % IP_PREFIX, nodes,
         lambda: nodes.devices_count(text=IP_PREFIX)),
        ("nodesmibdb", "mib_objects()", nodes.mib_db,
         lambda: nodes.mib_objects()),

        ("alertsdb", "alerts(text='%s', limit=300)" % WORD, alerts,
         lambda: alerts.alerts(text=WORD, limit=300)),
        ("alertsdb", "count_alerts(text='%s')" % WORD, alerts,
         lambda: alerts.count_alerts(text=WORD)),
        ("alertsdb", "open_summary()", alerts, alerts.open_summary),
        ("alertsdb", "open_count()", alerts, alerts.open_count),
        ("alertsdb", "alerts_due_renotify(now - 1h)", alerts,
         lambda: alerts.alerts_due_renotify(now - 3600)),

        # The same search down both paths. `_can_index` gates on `self.fts`,
        # so forcing it False is what the LIKE fallback sees on a host whose
        # SQLite has no FTS5 — the same trick bench_flow_overview.py uses to
        # get the pre-rollup query path. Timing two different search terms
        # instead would compare selectivity, not the two paths.
        ("syslogdb", "search('%s' 1-in-6) FTS" % SYSLOG_COMMON, syslog,
         lambda: syslog.search(now - 30 * DAY, now, {"text": SYSLOG_COMMON})),
        ("syslogdb", "search('%s' 1-in-6) LIKE" % SYSLOG_COMMON, syslog,
         lambda: without_fts(syslog, now - 30 * DAY, now, SYSLOG_COMMON)),
        ("syslogdb", "search('%s' 1-in-997) FTS" % SYSLOG_RARE, syslog,
         lambda: syslog.search(now - 30 * DAY, now, {"text": SYSLOG_RARE})),
        ("syslogdb", "search('%s' 1-in-997) LIKE" % SYSLOG_RARE, syslog,
         lambda: without_fts(syslog, now - 30 * DAY, now, SYSLOG_RARE)),
        ("syslogdb", "stats()", syslog, syslog.stats),

        # snmptrapdb has no FTS at all: _scan_clause is six leading-wildcard
        # LIKEs and every free-text search takes it.
        ("snmptrapdb", "search(text='GigabitEthernet0/7')", traps,
         lambda: traps.search(now - 90 * DAY, now,
                              {"text": "GigabitEthernet0/7"})),
        # Two terms, so _scan_clause emits twelve LIKEs rather than six.
        ("snmptrapdb", "search(text='linkDown ifAdminStatus')", traps,
         lambda: traps.search(now - 90 * DAY, now,
                              {"text": "linkDown ifAdminStatus"})),
        ("snmptrapdb", "stats()", traps, traps.stats),

        ("ipamdb", "search_hosts('10.0.1.')", ipam,
         lambda: ipam.search_hosts("10.0.1.")),
        ("ipamdb", "search_hosts('00:1b:00')", ipam,
         lambda: ipam.search_hosts("00:1b:00")),

        ("appdb", "audit_query(q='%s')" % VENDORS[3], app,
         lambda: app.audit_query(now - 365 * DAY, now, q=VENDORS[3])),
        ("appdb", "audit_query(action='device.update')", app,
         lambda: app.audit_query(now - 365 * DAY, now,
                                 action="device.update")),

        ("flowdb", "flows(24h, order='bytes')", flows,
         lambda: flows.flows(now - DAY, now, {}, limit=200, order="bytes")),
        ("flowdb", "flows(24h, dst_port=443)", flows,
         lambda: flows.flows(now - DAY, now, {"dst_port": "443"},
                             limit=200, order="bytes")),
    ]


# --------------------------------------------------------------------- a run

def run(folder, scale, repeats):
    sizes = {key: base * scale for key, base in BASE.items()}
    data = os.path.join(folder, "scale-%d" % scale)
    os.makedirs(data, exist_ok=True)

    started = time.monotonic()
    nodes = seed_nodes(os.path.join(data, "nodes.db"), sizes["devices"])
    seed_mibs(nodes, sizes["mib_objects"])
    stores = {
        "nodes": nodes,
        "alerts": seed_alerts(os.path.join(data, "alerts.db"), sizes["alerts"]),
        "syslog": seed_syslog(os.path.join(data, "syslog.db"), sizes["syslog"]),
        "traps": seed_traps(os.path.join(data, "snmptraps.db"), sizes["traps"]),
        "ipam": seed_ipam(os.path.join(data, "ipam.db"), sizes["hosts"]),
        "app": seed_app(os.path.join(data, "app.db"), sizes["audit"]),
        "flows": seed_flows(os.path.join(data, "flows.db"), sizes["flows"]),
    }
    seeded_s = time.monotonic() - started

    print("\nscale x%d: %s devices (x%d interfaces), %s alerts, %s syslog, "
          "%s traps," % (scale, "{:,}".format(sizes["devices"]),
                         IFACES_PER_DEVICE, "{:,}".format(sizes["alerts"]),
                         "{:,}".format(sizes["syslog"]),
                         "{:,}".format(sizes["traps"])))
    print("          %s hosts, %s audit rows, %s MIB objects, %s flows "
          "(seeded in %.1f s)"
          % ("{:,}".format(sizes["hosts"]), "{:,}".format(sizes["audit"]),
             "{:,}".format(sizes["mib_objects"]), "{:,}".format(sizes["flows"]),
             seeded_s))
    print("          syslog FTS index: %s; %d repeats per query"
          % ("on" if stores["syslog"].stats()["fts"] else "OFF", repeats))
    print("  " + HEADER)
    try:
        for store_label, query_label, explain_store, call in cases(stores):
            plan = plan_of(explain_store, call)
            print("  " + row(time_case(store_label, plan, query_label, call,
                                       repeats)))
    finally:
        for store in stores.values():
            try:
                store.close()
            except Exception:
                pass


def main(argv):
    scales = []
    repeats = 15
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--repeats":
            index += 1
            repeats = int(argv[index])
        elif item.startswith("--"):
            print(__doc__)
            return 2
        else:
            scales.append(int(item.replace("_", "")))
        index += 1
    scales = scales or [1, 4, 16]

    folder = tmpdir("bench_db_search_")
    print("scratch: %s" % folder)
    try:
        for scale in scales:
            run(folder, scale, repeats)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

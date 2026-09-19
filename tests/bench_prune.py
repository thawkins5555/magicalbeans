"""What every retention prune costs, and how long it freezes a reader.

Deliberately not a test_*.py: what a delete costs depends on the disk under
it, so this prints numbers rather than asserting them (run_all.py only picks
up test_*.py).

    python3 tests/bench_prune.py [rows ...] [--no-inserts] [--insert-batch N]

Each `rows` figure is one run: every store is seeded to that many rows in its
highest-volume table (the smaller tables get the share of it their real
proportions suggest), spread across twice the shipped retention window so
about half of what is stored is past the cutoff, and then its shipped prune
is timed.

The column that matters is the last one. Every store in this application
guards ONE sqlite connection with ONE RLock, and every prune here takes that
lock for the whole DELETE. WAL would let a second connection read straight
through a delete; the lock is what actually freezes the page, so the lock is
what this measures. A second thread issues a trivial read every 5 ms while
the prune runs and keeps the worst wait it saw: that figure is "the page
froze for a moment", and a wall-clock total for the prune cannot show it —
a two-second prune that lets go between chunks is invisible to a reader, and
a 300 ms prune that holds the lock throughout is not.

The read is `SELECT 1`, which costs nothing, so everything the stall column
reports is time spent waiting for the prune to let go. A real page read pays
its own query time on top.

The inserts section is the other half of the same question: the lead is
adding retention indexes, and an index that makes a prune cheap makes every
poll's write more expensive. Both numbers belong in the same run — throughput
into the same table before the prune and again after it, so the index cost is
recorded beside its benefit rather than in a different report.
"""
import os
import sys
import threading
import time

import _paths
from _paths import tmpdir

from _old_series_maintenance import old_compact_rollup, old_prune_by_band
from netpath.alertsdb import AlertsDatabase
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.nodesseriesdb import (NodesSeriesDatabase, SCOPE_DEVICE,
                                   SCOPE_INTERFACE)
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.syslogparse import LogEntry

DAY = 86400.0
HOUR = 3600.0
WRITE_BATCH = 50_000

# The shipped caps, read out of each module's DEFAULTS so this bench keeps
# telling the truth if one of them moves. Retention is what decides which
# rows a prune deletes; the row caps are the second stage.
SAMPLE_DAYS = 3.0           # nodesdb DEFAULTS["sample_retention_days"]
ROLLUP_DAYS = 400.0         # nodesdb DEFAULTS["rollup_retention_days"]
SAMPLE_CAP = 5_000          # nodesdb DEFAULTS["sample_row_cap_per_metric"]
EVENT_DAYS = 180.0          # nodesdb DEFAULTS["event_retention_days"]
DISCOVERY_DAYS = 30.0       # nodesdb DEFAULTS["discovery_retention_days"]
MAC_DAYS = 7.0              # nodesdb DEFAULTS["mac_table_retention_days"]
SYSLOG_DAYS = 30.0          # syslogdb DEFAULTS["retention_days"]
SYSLOG_MAX_ROWS = 20_000_000
TRAP_DAYS = 90.0            # snmptrapdb DEFAULTS["retention_days"]
TRAP_MAX_ROWS = 5_000_000
ALERT_DAYS = 180.0          # alertsdb DEFAULTS["retention_days"]
IPAM_HOST_DAYS = 30.0       # ipamdb DEFAULTS["host_retention_days"]
IPAM_CONFLICT_DAYS = 90.0   # ipamdb DEFAULTS["conflict_retention_days"]
IPAM_SCAN_DAYS = 30.0       # ipamdb DEFAULTS["scan_history_days"]
IPAM_DHCP_DAYS = 35.0       # ipamdb DEFAULTS["dhcp_history_days"]

METRICS = 200               # metrics the samples are spread over
DEVICES = 50
VLANS = 4000                # distinct VLAN ids one device can carry


# ------------------------------------------------------------------ reader

class Reader(threading.Thread):
    """A trivial read every 5 ms against the store's own lock, keeping the
    longest wait. See the module docstring for why the lock, not the file,
    is the thing that freezes a page."""

    INTERVAL_S = 0.005

    def __init__(self, store):
        super().__init__(daemon=True)
        self.store = store
        self.worst = 0.0
        self.reads = 0
        self._done = threading.Event()

    def run(self) -> None:
        while not self._done.is_set():
            started = time.perf_counter()
            with self.store._lock:
                self.store._conn.execute("SELECT 1").fetchone()
            self.worst = max(self.worst, time.perf_counter() - started)
            self.reads += 1
            self._done.wait(self.INTERVAL_S)

    def stop(self) -> None:
        self._done.set()
        self.join(timeout=10)


def timed(store, prune):
    """(deleted, seconds, worst reader stall in seconds) for one prune.

    perf_counter rather than the monotonic clock the other benches use:
    time.monotonic() ticks every 15.6 ms on Windows, which is the same
    order as the thing being measured, so half the prunes here would read
    as 0.000 s and every stall under a tick would vanish.
    """
    reader = Reader(store)
    reader.start()
    time.sleep(0.05)                      # let the reader settle into cadence
    started = time.perf_counter()
    deleted = prune()
    elapsed = time.perf_counter() - started
    reader.stop()
    return int(deleted or 0), elapsed, reader.worst


def count(store, table: str) -> int:
    with store._lock:
        return store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def fill(store, sql: str, rows) -> None:
    """`rows` through executemany in transactions of WRITE_BATCH, which is
    how every bulk writer in the application does it."""
    batch = []
    with store._lock:
        for row in rows:
            batch.append(row)
            if len(batch) >= WRITE_BATCH:
                store._conn.executemany(sql, batch)
                store._conn.commit()
                batch = []
        if batch:
            store._conn.executemany(sql, batch)
        store._conn.commit()


def spread(n: int, days: float, now: float):
    """`n` timestamps evenly across twice `days`, so half of them are past a
    `days` cutoff — the steady state a store that has been up longer than its
    retention window actually sits in."""
    span = 2 * days * DAY
    step = span / max(1, n)
    base = now - span
    return (base + i * step for i in range(n))


# ------------------------------------------------------------------- cases

class Case:
    """One prune: the store it runs against, the tables it empties, and the
    reader whose stall is being measured."""

    def __init__(self, store_label, table, store, prune, tables=None):
        self.store_label = store_label
        self.table = table
        self.store = store
        self.prune = prune
        self.tables = tables or (table,)

    def rows(self) -> int:
        return sum(count(self.store, table) for table in self.tables)


def series_store(folder, rows):
    db = NodesSeriesDatabase(os.path.join(folder, "nodes_series.db"))
    now = time.time()
    metric_ids = [db.record_metric_sample(i % DEVICES, f"bench.{i}",
                                          f"metric {i}", "u", "gauge", now, 0.0)
                  for i in range(METRICS)]
    fill(db, "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
         ((metric_ids[i % METRICS], ts, float(i % 1000))
          for i, ts in enumerate(spread(rows, SAMPLE_DAYS, now))))
    hourly = max(1, rows // 4)
    fill(db, "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
             " vavg, vmax) VALUES (?,?,?,?,?,?)",
         ((metric_ids[i % METRICS], int(ts // 3600) * 3600 + i, 60,
           0.0, float(i % 100), 100.0)
          for i, ts in enumerate(spread(hourly, ROLLUP_DAYS, now))))

    def insert_probe(n):
        base = time.time() + 1.0
        fill(db, "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                 " VALUES (?,?,?)",
             ((metric_ids[i % METRICS], base + i * 0.001, float(i)) for i in range(n)))

    cases = [Case("nodes_series.db", "samples", db,
                  lambda: db.prune(sample_days=SAMPLE_DAYS,
                                   rollup_days=ROLLUP_DAYS,
                                   max_samples_per_metric=SAMPLE_CAP),
                  tables=("samples", "samples_hourly"))]
    return db, cases, insert_probe


def syslog_store(folder, rows):
    db = SyslogDatabase(os.path.join(folder, "syslog.db"))
    now = time.time()

    def entries(count_, base_ts):
        for i, ts in enumerate(base_ts):
            yield LogEntry(ts=ts, source=f"10.0.{i // 251 % 256}.{i % 251}",
                           host=f"sw-{i % 500}", facility=i % 24,
                           severity=i % 8, app=("bgp", "ospf", "sshd")[i % 3],
                           procid=str(1000 + i % 9000), msgid="",
                           message=f"interface Gi0/{i % 48} changed state {i}",
                           raw="")

    # Through insert(), not raw SQL: the FTS index is written on the way in,
    # and the FTS delete is most of what prune() then has to do.
    written = 0
    stamps = list(spread(rows, SYSLOG_DAYS, now))
    while written < rows:
        chunk = min(10_000, rows - written)
        db.insert(list(entries(chunk, stamps[written:written + chunk])))
        written += chunk

    def insert_probe(n):
        base = time.time() + 1.0
        db.insert(list(entries(n, [base + i * 0.001 for i in range(n)])))

    cases = [Case("syslog.db", "logs", db,
                  lambda: db.prune(SYSLOG_DAYS, SYSLOG_MAX_ROWS),
                  tables=("logs", "log_counts"))]
    return db, cases, insert_probe


def trap_store(folder, rows):
    db = SnmpTrapDatabase(os.path.join(folder, "snmptraps.db"))
    now = time.time()
    sql = ("INSERT INTO traps(ts, source, version, community, trap_oid,"
           " trap_name, trap_kind, severity, is_inform, varbind_n, varbinds,"
           " varbind_text, raw_len) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")

    def rows_for(stamps):
        for i, ts in enumerate(stamps):
            yield (ts, f"10.1.{i // 251 % 256}.{i % 251}", 1, "public",
                   f"1.3.6.1.6.3.1.1.5.{i % 6}",
                   ("linkDown", "linkUp", "coldStart")[i % 3],
                   ("linkDown", "linkUp", "coldStart")[i % 3], i % 8, 0, 2,
                   '[{"oid":"1.3.6.1.2.1.2.2.1.1","value":"%d"}]' % i,
                   f"ifIndex {i}", 128)

    fill(db, sql, rows_for(spread(rows, TRAP_DAYS, now)))

    def insert_probe(n):
        base = time.time() + 1.0
        fill(db, sql, rows_for([base + i * 0.001 for i in range(n)]))

    cases = [Case("snmptraps.db", "traps", db,
                  lambda: db.prune(TRAP_DAYS, TRAP_MAX_ROWS),
                  tables=("traps", "trap_counts"))]
    return db, cases, insert_probe


def alerts_store(folder, rows):
    db = AlertsDatabase(os.path.join(folder, "alerts.db"))
    now = time.time()
    rule_id = db.add_rule("bench.cpu", "Bench CPU", "threshold", "device")
    sql = ("INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
           " entity_label, severity, message, state, opened_ts, last_ts,"
           " resolved_ts) VALUES (?,?,?,?,?,?,?,'resolved',?,?,?)")

    def rows_for(stamps):
        for i, ts in enumerate(stamps):
            yield (rule_id, f"cpu:{i}", "device", str(i % DEVICES),
                   f"sw-{i % DEVICES}", i % 8, f"CPU high on port {i % 48}",
                   ts - 60.0, ts, ts)

    fill(db, sql, rows_for(spread(rows, ALERT_DAYS, now)))

    def insert_probe(n):
        base = time.time() + 1.0
        fill(db, sql, rows_for([base + i * 0.001 for i in range(n)]))

    cases = [Case("alerts.db", "alerts", db, lambda: db.prune(ALERT_DAYS))]
    return db, cases, insert_probe


def nodes_store(folder, rows):
    """nodes.db only: this store's own series file is left empty so the
    nodesdb.prune row measures the event tables it is responsible for
    rather than re-measuring the samples row above it."""
    db = NodesDatabase(os.path.join(folder, "nodes.db"))
    now = time.time()
    group_id = db.ensure_default_group()
    device_ids = [db.add_device(f"10.20.{i // 251}.{i % 251}", f"sw-{i}",
                                group_id=group_id) for i in range(DEVICES)]
    ports = 48
    fill(db, "INSERT INTO interfaces(device_id, if_index, descr, last_seen_ts)"
             " VALUES (?,?,?,?)",
         ((device_ids[i // ports], i % ports + 1, f"Gi0/{i % ports + 1}", now)
          for i in range(DEVICES * ports)))
    with db._lock:
        interface_ids = [r[0] for r in
                         db._conn.execute("SELECT id FROM interfaces").fetchall()]

    events = ("INSERT INTO device_events(device_id, ts, kind, detail)"
              " VALUES (?,?,?,?)")

    def event_rows(stamps):
        for i, ts in enumerate(stamps):
            yield (device_ids[i % DEVICES], ts,
                   ("up", "down", "snmp_error", "rebooted")[i % 4], "bench")

    fill(db, events, event_rows(spread(rows, EVENT_DAYS, now)))
    fill(db, "INSERT INTO interface_events(interface_id, ts, kind, detail)"
             " VALUES (?,?,?,?)",
         ((interface_ids[i % len(interface_ids)], ts,
           ("link_up", "link_down")[i % 2], "bench")
          for i, ts in enumerate(spread(max(1, rows // 2), EVENT_DAYS, now))))
    fill(db, "INSERT INTO discovery_jobs(kind, target, state, started_ts,"
             " finished_ts) VALUES ('subnet',?,'done',?,?)",
         ((f"10.{i % 256}.0.0/24", ts, ts + 30.0)
          for i, ts in enumerate(spread(max(1, rows // 100), DISCOVERY_DAYS, now))))

    mac_rows = max(1, rows // 2)
    fill(db, "INSERT INTO mac_entries(device_id, if_index, mac, vlan, seen_ts,"
             " first_seen_ts, present) VALUES (?,?,?,?,?,?,1)",
         ((device_ids[i % DEVICES], i % ports + 1,
           "aa:bb:%02x:%02x:%02x:%02x" % (i >> 24 & 255, i >> 16 & 255,
                                          i >> 8 & 255, i & 255),
           str(i % 8 + 1), ts, ts - DAY)
          for i, ts in enumerate(spread(mac_rows, MAC_DAYS, now))))
    fill(db, "INSERT INTO neighbors(device_id, if_index, protocol, rem_index,"
             " chassis_id, port_id, sys_name, seen_ts, first_seen_ts, present)"
             " VALUES (?,?,?,?,?,?,?,?,?,1)",
         ((device_ids[i % DEVICES], i % ports + 1, ("lldp", "cdp")[i % 2],
           str(i), f"00:11:22:{i & 255:02x}", f"Gi0/{i % 48}", f"peer-{i}",
           ts, ts - DAY)
          for i, ts in enumerate(spread(max(1, rows // 10), MAC_DAYS, now))))
    # The three VLAN tables are keyed on (device, vlan) and (device, port), so
    # a bench asked for more rows than a 50-device fleet has distinct keys
    # would fail on the PK rather than measure anything. Each is capped at its
    # own real ceiling; the rows column reports what was actually stored.
    vlans = min(max(1, rows // 20), DEVICES * VLANS)
    fill(db, "INSERT INTO vlans(device_id, vlan, name, seen_ts, first_seen_ts,"
             " present) VALUES (?,?,?,?,?,1)",
         ((device_ids[i // VLANS], i % VLANS + 1, f"vlan{i % VLANS + 1}",
           ts, ts - DAY)
          for i, ts in enumerate(spread(vlans, MAC_DAYS, now))))
    fill(db, "INSERT INTO vlan_ports(device_id, if_index, mode, native_vlan,"
             " seen_ts, first_seen_ts, present) VALUES (?,?,?,?,?,?,1)",
         ((device_ids[i // VLANS], i % VLANS + 1,
           ("trunk", "access")[i % 2], i % VLANS + 1, ts, ts - DAY)
          for i, ts in enumerate(spread(vlans, MAC_DAYS, now))))
    port_vlans = min(max(1, rows // 5), DEVICES * VLANS * ports)
    fill(db, "INSERT INTO port_vlans(device_id, if_index, vlan, tagged,"
             " seen_ts, first_seen_ts, present) VALUES (?,?,?,?,?,?,1)",
         ((device_ids[i // VLANS % DEVICES], i // (VLANS * DEVICES) % ports + 1,
           i % VLANS + 1, i % 2, ts, ts - DAY)
          for i, ts in enumerate(spread(port_vlans, MAC_DAYS, now))))

    def insert_probe(n):
        base = time.time() + 1.0
        fill(db, events, event_rows([base + i * 0.001 for i in range(n)]))

    older = MAC_DAYS * DAY
    cases = [
        Case("nodes.db", "device+if events", db,
             lambda: db.prune(sample_days=SAMPLE_DAYS, rollup_days=ROLLUP_DAYS,
                              event_days=EVENT_DAYS,
                              discovery_days=DISCOVERY_DAYS,
                              max_samples_per_metric=SAMPLE_CAP),
             tables=("device_events", "interface_events", "discovery_jobs")),
        Case("nodes.db", "mac_entries", db, lambda: db.prune_mac_entries(older)),
        Case("nodes.db", "neighbors", db, lambda: db.prune_neighbors(older)),
        Case("nodes.db", "vlans", db, lambda: db.prune_vlans(older)),
        Case("nodes.db", "vlan_ports", db, lambda: db.prune_vlan_ports(older)),
        Case("nodes.db", "port_vlans", db, lambda: db.prune_port_vlans(older)),
    ]
    return db, cases, insert_probe


def ipam_store(folder, rows):
    db = IpamDatabase(os.path.join(folder, "ipam.db"))
    now = time.time()
    with db._lock:
        subnet_id = db._conn.execute(
            "INSERT INTO subnets(cidr, label, enabled, created_ts)"
            " VALUES ('10.0.0.0/22','bench',1,?)", (now,)).lastrowid
        server_id = db._conn.execute(
            "INSERT INTO dhcp_servers(address, label, enabled, created_ts)"
            " VALUES ('10.0.0.5','bench',1,?)", (now,)).lastrowid
        db._conn.commit()

    host_rows = max(1, rows // 10)
    fill(db, "INSERT OR REPLACE INTO hosts(ip, subnet_id, mac, alive,"
             " first_seen, last_seen) VALUES (?,?,?,0,?,?)",
         ((f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", subnet_id,
           "aa:00:%02x:%02x:%02x:%02x" % (i >> 24 & 255, i >> 16 & 255,
                                          i >> 8 & 255, i & 255),
           ts - DAY, ts)
          for i, ts in enumerate(spread(host_rows, IPAM_HOST_DAYS, now))))
    fill(db, "INSERT INTO conflicts(ip, mac_a, mac_b, source, detected_ts,"
             " last_seen_ts, resolved_ts) VALUES (?,?,?,'arp',?,?,?)",
         ((f"10.0.{i >> 8 & 255}.{i & 255}", f"aa:00:00:00:00:{i & 255:02x}",
           f"bb:00:00:00:00:{i & 255:02x}", ts - DAY, ts, ts)
          for i, ts in enumerate(spread(max(1, rows // 50), IPAM_CONFLICT_DAYS, now))))
    scan_sql = ("INSERT INTO scans(subnet_id, started_ts, finished_ts,"
                " addresses, alive, conflicts, status) VALUES (?,?,?,?,?,0,'done')")

    def scan_rows(stamps):
        for i, ts in enumerate(stamps):
            yield (subnet_id, ts, ts + 12.0, 1024, i % 900)

    fill(db, scan_sql, scan_rows(spread(max(1, rows // 10), IPAM_SCAN_DAYS, now)))
    fill(db, "INSERT INTO dhcp_scope_history(server_id, scope_id, leased,"
             " reserved, total, polled_ts) VALUES (?,?,?,?,?,?)",
         ((server_id, f"10.0.{i % 64}.0", i % 250, 4, 254, ts)
          for i, ts in enumerate(spread(max(1, rows // 10), IPAM_DHCP_DAYS, now))))

    def insert_probe(n):
        base = time.time() + 1.0
        fill(db, scan_sql, scan_rows([base + i * 0.001 for i in range(n)]))

    cases = [
        Case("ipam.db", "hosts", db, lambda: db.prune_hosts(IPAM_HOST_DAYS)),
        Case("ipam.db", "conflicts", db,
             lambda: db.prune_conflicts(IPAM_CONFLICT_DAYS)),
        Case("ipam.db", "scans", db, lambda: db.prune_scans(IPAM_SCAN_DAYS)),
        Case("ipam.db", "dhcp_scope_history", db,
             lambda: db.prune_scope_history(IPAM_DHCP_DAYS)),
    ]
    return db, cases, insert_probe


def delete_store(folder, rows):
    """Deleting one device, the old way beside the new one.

    Not a retention prune, but the same question and the same answer: this
    is the other delete whose size is set by how long a device has been
    polled, and until 5.10 it ran as one transaction under both Nodes
    locks. Two devices are seeded identically; the first is deleted the way
    remove_device used to (one DELETE per file, one commit each), the
    second through request_device_removal + purge_step. The reader runs
    against nodes_series.db, where the rows are.
    """
    db = NodesDatabase(os.path.join(folder, "nodes.db"))
    series = db.series_db
    now = time.time()
    group_id = db.ensure_default_group()
    ports = 48
    devices = []
    for which in range(2):
        device_id = db.add_device(f"10.30.0.{which + 1}", f"sw-del-{which}",
                                  group_id=group_id)
        devices.append(device_id)
        metric_ids = [series.record_metric_sample(
            device_id, f"bench.{i}", f"metric {i}", "u", "gauge", now, 0.0)
            for i in range(METRICS)]
        fill(series, "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                     " VALUES (?,?,?)",
             ((metric_ids[i % METRICS], now - i, float(i % 1000))
              for i in range(rows)))
        fill(series, "INSERT OR REPLACE INTO samples_hourly(metric_id, hour,"
                     " n, vmin, vavg, vmax) VALUES (?,?,?,?,?,?)",
             ((metric_ids[i % METRICS], int(now) - i * 3600, 60, 0.0,
               float(i % 100), 100.0)
              for i in range(max(1, rows // 4))))
        fill(db, "INSERT INTO interfaces(device_id, if_index, descr,"
                 " last_seen_ts) VALUES (?,?,?,?)",
             ((device_id, i + 1, f"Gi0/{i + 1}", now) for i in range(ports)))
        fill(db, "INSERT INTO device_events(device_id, ts, kind, detail)"
                 " VALUES (?,?,'down','bench')",
             ((device_id, now - i) for i in range(max(1, rows // 10))))
        fill(db, "INSERT INTO mac_entries(device_id, if_index, mac, vlan,"
                 " seen_ts, first_seen_ts, present) VALUES (?,?,?,'1',?,?,1)",
             ((device_id, i % ports + 1, "aa:bb:%08x" % i, now, now)
              for i in range(max(1, rows // 10))))

    def unbatched():
        """remove_device as it stood before 5.10.0.

        Counted with total_changes, not rowcount: most of what this deletes
        goes through ON DELETE CASCADE, which rowcount does not see, and a
        row that says 201 beside the batched row's half-million reads as a
        different amount of work rather than the same work done differently.
        """
        before = series._conn.total_changes + db._conn.total_changes
        series.delete_metrics_for_devices([devices[0]])
        with db._lock:
            db._conn.execute("DELETE FROM devices WHERE id = ?", (devices[0],))
            db._conn.commit()
        return series._conn.total_changes + db._conn.total_changes - before

    def batched():
        db.request_device_removal([devices[1]])
        removed = 0
        while db.purges_pending():
            step = db.purge_step(budget_s=30.0)
            removed += step["rows_removed_now"]
            if not step["purged"] and not step["rows_removed_now"]:
                break
        return removed

    def insert_probe(n):
        base = time.time() + 1.0
        metric_id = series.record_metric_sample(
            devices[0], "bench.probe", "probe", "u", "gauge", base, 0.0)
        fill(series, "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                     " VALUES (?,?,?)",
             ((metric_id, base + i * 0.001, float(i)) for i in range(n)))

    cases = [
        Case("nodes.db", "delete: one hold", series, unbatched,
             tables=("samples", "samples_hourly")),
        Case("nodes.db", "delete: purge_step", series, batched,
             tables=("samples", "samples_hourly")),
    ]
    return db, cases, insert_probe


# nodesseriesdb first: `samples` is the highest-volume table in the product,
# so its row is the headline this whole bench exists for.
STORES = (("nodes_series.db", series_store),
          ("syslog.db", syslog_store),
          ("snmptraps.db", trap_store),
          ("alerts.db", alerts_store),
          ("nodes.db", nodes_store),
          ("device delete", delete_store),
          ("ipam.db", ipam_store))


# ------------------------------------------------------------------- driver

def throughput(probe, n: int) -> float:
    started = time.perf_counter()
    probe(n)
    return n / max(time.perf_counter() - started, 1e-9)


def run(folder: str, rows: int, insert_batch: int) -> None:
    print(f"\n{rows:,} rows per store, spread across twice each store's shipped "
          f"retention window\n")
    print(f"  {'store':<16} {'table':<18} {'rows':>10} {'deleted':>10} "
          f"{'prune s':>9} {'max reader stall':>17}")
    inserts = []
    for label, builder in STORES:
        run_folder = os.path.join(folder, label.replace(".", "_"))
        os.makedirs(run_folder, exist_ok=True)
        started = time.perf_counter()
        store, cases, probe = builder(run_folder, rows)
        seeded = time.perf_counter() - started
        print(f"  -- {label} seeded in {seeded:.1f} s, "
              f"{store.size_bytes() / 1e6:.0f} MB")
        before = throughput(probe, insert_batch) if insert_batch else 0.0
        for case in cases:
            had = case.rows()
            deleted, elapsed, stall = timed(case.store, case.prune)
            print(f"  {case.store_label:<16} {case.table:<18} {had:>10,} "
                  f"{deleted:>10,} {elapsed:>9.3f} {stall * 1000:>14.1f} ms")
        after = throughput(probe, insert_batch) if insert_batch else 0.0
        inserts.append((label, before, after, store.size_bytes()))
        store.close()

    if not insert_batch:
        return
    print(f"\n  inserts: {insert_batch:,} rows into each store's hot table, "
          f"before and after its prune")
    print(f"  {'store':<16} {'before rows/s':>15} {'after rows/s':>15} "
          f"{'change':>9} {'MB':>7}")
    for label, before, after, size in inserts:
        print(f"  {label:<16} {before:>15,.0f} {after:>15,.0f} "
              f"{after / max(before, 1e-9):>8.2f}x {size / 1e6:>6.0f}")


# ---------------------------------------------- history maintenance, at scale
#
# The STORES cases above seed nodes_series.db's `samples` to METRICS=200,
# spread over whatever `rows` is asked for -- fine for the other six stores,
# but 200 metrics never reproduces the cost maintenance bands by metric id
# are meant to fix: a range scan across a band of 200 metrics is cheap
# regardless of whether it can seek. This mode seeds a fleet-scale metric
# count instead and times each maintenance stage on its own, printing the
# hold-time distribution per stage -- what a poller or a reader queued
# behind this store actually feels, not the stage's total wall time.
#
# _trim_hourly is unbatched by design: at 10,000 metrics, one 3.4 s hold
# beat a batched ~110 s of near-continuous lock duty for the same rows, so
# the number below is a single-hold baseline, not a regression to chase.

LARGE_METRICS = 10_000
# 10,000 metrics x 1,440 raw samples is a realistic fleet-scale scenario (a
# day at a 60 s poll); the hourly depth is a round 30 days.
LARGE_RAW_PER_METRIC = 1_440
LARGE_HOURLY_PER_METRIC = 24 * 30
LARGE_POLL_INTERVAL_S = 60.0


class HoldSpy:
    """test_prune_lock_hold.py's SpyLock, minus the reader-thread plumbing
    this single-threaded bench doesn't need: every uninterrupted hold on the
    wrapped lock, timed. The maximum is not a property of a batching scheme
    -- an automatic WAL checkpoint can land inside any one commit -- so the
    median and 90th percentile are what a tuning change actually moves.
    """

    def __init__(self, inner):
        self._inner = inner
        self._local = threading.local()
        self.holds: list[float] = []

    def acquire(self, *args, **kwargs):
        got = self._inner.acquire(*args, **kwargs)
        if got:
            depth = getattr(self._local, "depth", 0)
            if depth == 0:
                self._local.since = time.perf_counter()
            self._local.depth = depth + 1
        return got

    def release(self):
        depth = getattr(self._local, "depth", 0) - 1
        self._local.depth = depth
        if depth == 0:
            self.holds.append(time.perf_counter() - self._local.since)
        self._inner.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def large_timed(store, label, call):
    """Times `call` against a fresh HoldSpy, so every figure printed is this
    call's own -- not store.lock_stats(), whose counters are cumulative
    since open and would carry over whatever the seeding phase (or an
    earlier stage) did.
    """
    spy = HoldSpy(store._lock)
    store._lock = spy
    started = time.perf_counter()
    result = call()
    elapsed = time.perf_counter() - started
    store._lock = spy._inner
    holds = sorted(spy.holds) or [0.0]
    median = holds[len(holds) // 2]
    p90 = holds[min(len(holds) - 1, int(len(holds) * 0.9))]
    stats = {"acquisitions": len(holds), "median_s": median, "p90_s": p90,
             "max_hold_s": holds[-1]}
    print(f"  {label:<28} {elapsed * 1000:>9.1f} ms   "
          f"lock: {stats['acquisitions']:>5} acq, "
          f"median {median * 1000:>7.1f} ms, "
          f"p90 {p90 * 1000:>7.1f} ms, "
          f"max {holds[-1] * 1000:>7.1f} ms")
    return result, stats


def large_seed(folder, label, metrics, raw_per_metric, hourly_per_metric,
              poll_interval_s, now):
    db = NodesSeriesDatabase(os.path.join(folder, f"{label}.db"))
    with db._lock:
        # One metric in 20 is device-level, the rest per-port -- roughly
        # nodesseriesdb's own real-world proportion the other way round.
        db._conn.executemany(
            "INSERT INTO metrics(device_id, key, label, unit, kind, scope)"
            " VALUES (?,?,?,?,'gauge',?)",
            [(1 + i % DEVICES, f"bench.{i}", f"metric {i}", "u",
              SCOPE_DEVICE if i % 20 == 0 else SCOPE_INTERFACE)
             for i in range(metrics)])
        db._conn.commit()
        metric_ids = [row[0] for row in db._conn.execute(
            "SELECT id FROM metrics ORDER BY id").fetchall()]
    raw_step = max(1.0, poll_interval_s)
    fill(db, "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
             " VALUES (?,?,?)",
         ((mid, now - s * raw_step, float((s + mid) % 1000))
          for mid in metric_ids for s in range(raw_per_metric)))
    fill(db, "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
             " vavg, vmax) VALUES (?,?,60,0.0,?,?)",
         ((mid, int(now // HOUR) * HOUR - h * HOUR, float(h % 100),
           float(h % 100) * 2)
          for mid in metric_ids for h in range(hourly_per_metric)))
    return db


def large_series_bench(folder, metrics: int, raw_per_metric: int,
                       hourly_per_metric: int, poll_interval_s: float,
                       oracle: bool = False) -> None:
    now = time.time()
    raw_step = max(1.0, poll_interval_s)
    latest_complete = int(now // HOUR) * HOUR - HOUR
    cutoff = now - (raw_per_metric * raw_step) / 2
    trim_floor = max(1, hourly_per_metric * metrics // 4)

    print(f"\nseeding {metrics:,} metrics, {raw_per_metric:,} raw samples "
          f"and {hourly_per_metric:,} rollups each"
          f"{' (new + old, for --oracle)' if oracle else ''} ...")
    started = time.perf_counter()
    new_db = large_seed(folder, "nodes_series_new", metrics, raw_per_metric,
                        hourly_per_metric, poll_interval_s, now)
    old_db = (large_seed(folder, "nodes_series_old", metrics, raw_per_metric,
                         hourly_per_metric, poll_interval_s, now)
              if oracle else None)
    print(f"  seeded in {time.perf_counter() - started:.1f} s, "
          f"{new_db.size_bytes() / 1e6:,.0f} MB each")

    if oracle:
        print(f"  {'stage':<24} {'old p90 hold':>13}   {'new p90 hold':>13}")

    def stage(label, old_call, new_call):
        if oracle:
            (_, old_stats) = large_timed(old_db, f"{label} (old)", old_call)
            (_, new_stats) = large_timed(new_db, f"{label} (new)", new_call)
            print(f"  {label:<24} {old_stats['p90_s']*1000:>10.1f} ms   "
                  f"{new_stats['p90_s']*1000:>10.1f} ms")
        else:
            large_timed(new_db, label, new_call)

    # 1. One hour of roll-up: force the watermark to exactly one pending
    # hour so max_hours=1 does real work, not "nothing to do".
    new_db._set_private_setting(new_db._ROLLUP_WATERMARK, latest_complete)
    if oracle:
        old_db._set_private_setting(old_db._ROLLUP_WATERMARK, latest_complete)
    stage("compact_rollup (1 hour)",
          lambda: old_compact_rollup(old_db, max_hours=1) if oracle else None,
          lambda: new_db.compact_rollup(max_hours=1))

    # 2. One prune band: the age-based delete alone, not the whole prune()
    # (which also covers rollups and the cap, timed separately below).
    stage("prune band (age cutoff)",
          lambda: old_prune_by_band(old_db, "samples", "ts < ?", (cutoff,))
                  if oracle else None,
          lambda: new_db._prune_by_band("samples", "ts < ?", (cutoff,)))

    # 3. The row cap: unchanged code, no "old" to compare against.
    large_timed(new_db, "cap_samples_per_metric",
               lambda: new_db.cap_samples_per_metric(max(1, raw_per_metric // 4)))

    # 4. The hourly trim: also unchanged (see the module docstring above),
    # so likewise a single measurement rather than an old/new split.
    large_timed(new_db, "_trim_hourly",
               lambda: new_db._trim_hourly(trim_floor))

    new_db.close()
    if old_db is not None:
        old_db.close()


def main(argv) -> int:
    sizes = []
    insert_batch = 20_000
    large = None
    oracle = False
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--no-inserts":
            insert_batch = 0
        elif item == "--insert-batch":
            index += 1
            insert_batch = int(argv[index].replace("_", ""))
        elif item == "--large":
            # An optional metric count may follow; otherwise LARGE_METRICS.
            if index + 1 < len(argv) and argv[index + 1].lstrip("-").isdigit():
                index += 1
                large = int(argv[index].replace("_", ""))
            else:
                large = LARGE_METRICS
        elif item == "--oracle":
            oracle = True
        else:
            sizes.append(int(item.replace("_", "")))
        index += 1
    folder = tmpdir("bench_prune_")
    print(f"scratch: {folder}")
    if large is not None:
        # A dedicated, fleet-scale run -- the STORES loop below stays at its
        # own METRICS=200 for everyone comparing its existing numbers.
        # --oracle seeds a second, identical store and runs the pre-rewrite
        # bodies against it alongside the live code, old vs new.
        large_series_bench(folder, large, LARGE_RAW_PER_METRIC,
                           LARGE_HOURLY_PER_METRIC, LARGE_POLL_INTERVAL_S,
                           oracle=oracle)
        return 0
    for rows in sizes or [200_000]:
        run(folder, rows, insert_batch)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

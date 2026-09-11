"""A retention prune must not hold its store's lock for its whole duration.

Every store in this application guards ONE sqlite connection with ONE RLock,
and every read takes that lock as well as every write. So the cost of a prune
to a page is not what the prune takes — it is the longest single stretch the
prune keeps the lock, because that is how long a request that wants the same
store waits. tests/bench_prune.py measures that on real volumes; this suite
asserts the property on volumes small enough to run on every commit:

  * the holds sit where sqlitebase's TRIM_LOCK_TARGET_S says they should —
    checked at the median and the ninth decile, because SQLite's automatic
    WAL checkpoint lands inside one commit or another whatever the batch
    size and the maximum is therefore nobody's property to promise;
  * the lock is genuinely handed back many times over the sweep;
  * a reader polling every 5 ms, which is what bench_prune's stall column
    measures, never waits anywhere near the sweep's length;
  * and none of that changed WHICH rows go. Each case records the rows it
    expects to survive before the prune and compares after, so a batching
    bug that dropped a row early or left one behind fails here rather than
    quietly changing retention.
"""
import os
import sys
import tempfile
import threading
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.nodesdb import NodesDatabase
from netpath.nodesseriesdb import NodesSeriesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.sqlitebase import TRIM_LOCK_TARGET_S
from netpath import syslogdb
from netpath.syslogdb import SyslogDatabase
from netpath.syslogparse import LogEntry

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(errors="replace")

TMPDIR = tempfile.mkdtemp(prefix="prune_lock_")
DAY = 86400.0
PASSED = []

# What a batch's hold is allowed to be, at the ninth decile rather than at
# the maximum. The maximum is not a property of this change: SQLite runs an
# automatic WAL checkpoint inside whichever commit crosses its page
# threshold, and that commit holds the store lock while it copies the log
# back — so any batch may be the unlucky one, at any batch size, batched or
# not. What batching controls is where the whole distribution sits, and that
# is what these bound. TRIM_LOCK_TARGET_S is the figure _delete_batches aims
# at; the slack is for a first batch issued before the adaptation has seen a
# timing, plus whatever a loaded box adds.
HOLD_CEILING_S = TRIM_LOCK_TARGET_S * 4
MEDIAN_CEILING_S = TRIM_LOCK_TARGET_S * 2


def ok(message: str):
    PASSED.append(message)
    print(f"✓ {message}")


class SpyLock:
    """The store's RLock, with every uninterrupted hold timed.

    Reentrant like the lock it wraps, and depth-counted per thread, so a
    nested `with self._lock` inside an outer one is one hold and not two —
    what a waiting reader experiences is the outer span.
    """

    def __init__(self, inner):
        self._inner = inner
        self._local = threading.local()
        self.holds = []            # (thread ident, seconds held)

    def holds_of(self, ident):
        """Only the sweep's own holds. The reader takes this lock too, and
        its holds are microseconds; counting them would put the median of
        every case at nothing at all and say so approvingly."""
        return sorted(held for who, held in self.holds if who == ident)

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
            self.holds.append((threading.get_ident(),
                               time.perf_counter() - self._local.since))
        self._inner.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False

    def stats(self):
        inner = getattr(self._inner, "stats", None)
        return inner() if callable(inner) else {}


class Reader(threading.Thread):
    """bench_prune's reader: a trivial read every 5 ms, worst wait kept.

    `SELECT 1` costs nothing, so everything it records is time spent queued
    behind the prune.
    """

    INTERVAL_S = 0.005
    daemon = True

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.worst = 0.0
        self.reads = 0
        self._done = threading.Event()

    def run(self):
        while not self._done.is_set():
            started = time.perf_counter()
            with self.store._lock:
                self.store._conn.execute("SELECT 1").fetchone()
            self.worst = max(self.worst, time.perf_counter() - started)
            self.reads += 1
            self._done.wait(self.INTERVAL_S)

    def stop(self):
        self._done.set()
        self.join(timeout=10)


def spread(n: int, days: float, now: float, gap_s: float = 7200.0):
    """`n` distinct timestamps across twice `days`, with a `gap_s` hole
    straddling the `days` cutoff.

    The hole is the point. A prune calls time.time() for itself, seconds
    after this seeding did, so a row sitting within that drift of the cutoff
    would make "which rows should survive" a race rather than a fact. With
    two hours of empty either side, the expected surviving set below is
    exactly the newer half, whenever the prune happens to run.
    """
    window = days * DAY
    half = n // 2
    older, newer = half, n - half
    cutoff = now - window
    return ([now - 2 * window + i * ((window - gap_s) / max(1, older))
             for i in range(older)] +
            [cutoff + gap_s + i * ((window - gap_s) / max(1, newer))
             for i in range(newer)])


def surviving(store, sql):
    with store._lock:
        return {row[0] for row in store._conn.execute(sql).fetchall()}


def measure(label, store, prune, id_sql, expect_kept, min_holds=6):
    """Run one prune under a spy lock and a reader, and check all four rules."""
    spy = SpyLock(store._lock)
    store._lock = spy
    reader = Reader(store)
    reader.start()
    time.sleep(0.05)                       # let the reader settle into cadence
    started = time.perf_counter()
    removed = prune()
    total = time.perf_counter() - started
    reader.stop()
    store._lock = spy._inner

    holds = spy.holds_of(threading.get_ident()) or [0.0]
    longest = holds[-1]
    median = holds[len(holds) // 2]
    p90 = holds[min(len(holds) - 1, int(len(holds) * 0.9))]
    print(f"  {label}: removed {removed} in {total * 1000:.0f} ms over "
          f"{len(holds)} lock hold(s); holds median {median * 1000:.0f} ms, "
          f"p90 {p90 * 1000:.0f} ms, max {longest * 1000:.0f} ms; "
          f"reader's worst wait {reader.worst * 1000:.0f} ms "
          f"across {reader.reads} reads")

    assert removed > 0, (label, removed)
    assert reader.reads > 5, (label, reader.reads)

    kept = surviving(store, id_sql)
    assert kept == expect_kept, (
        label, len(kept), len(expect_kept), sorted(kept ^ expect_kept)[:10])
    ok(f"{label}: the batched sweep kept exactly the {len(kept)} row(s) the "
       f"unbatched predicate would have kept")

    # Many holds, not one: this is the batching itself.
    assert len(holds) >= min_holds, (label, len(holds), min_holds)
    ok(f"{label}: the sweep handed the lock back {len(holds)} times "
       f"instead of holding it once")

    assert median < MEDIAN_CEILING_S, (label, median, MEDIAN_CEILING_S)
    assert p90 < HOLD_CEILING_S, (label, p90, HOLD_CEILING_S)
    ok(f"{label}: the typical hold is {median * 1000:.0f} ms and nine in ten "
       f"are under {p90 * 1000:.0f} ms, against a "
       f"{TRIM_LOCK_TARGET_S * 1000:.0f} ms target")

    # The claim, on the thing this change actually controls: no freeze a
    # reader can hit is the whole sweep any more. Even the checkpoint
    # outlier has to be a minority of it.
    assert p90 < total * 0.5, (label, p90, total)
    assert longest < total * 0.9, (label, longest, total)
    ok(f"{label}: nine holds in ten are under {p90 / total * 100:.0f}% of the "
       f"sweep and even the worst is {longest / total * 100:.0f}%, where an "
       f"unbatched DELETE's is 100%")

    # And the same thing as a request feels it. Bounded loosely on purpose:
    # a Python lock is not fair and _delete_batches reacquires immediately,
    # so a reader can lose several rounds in a row and its worst wait is
    # several batches rather than one. What must not happen — and is what
    # bench_prune measured before this change — is the reader being shut out
    # for the whole sweep.
    assert reader.worst < total * 0.8, (label, reader.worst, total)
    ok(f"{label}: a reader's worst wait was "
       f"{reader.worst / total * 100:.0f}% of the sweep across "
       f"{reader.reads} reads, not all of it")


# ============================================================ syslog.db: logs
print("\nsyslogdb.prune keeps the FTS index honest without freezing the store")

now = time.time()
syslog_db = SyslogDatabase(os.path.join(TMPDIR, "syslog.db"))


def log_entries(stamps):
    return [LogEntry(ts=ts, source=f"10.0.{i // 251 % 256}.{i % 251}",
                     host=f"sw-{i % 500}", facility=i % 24, severity=i % 8,
                     app=("bgp", "ospf", "sshd")[i % 3],
                     procid=str(1000 + i % 9000), msgid="",
                     message=f"interface Gi0/{i % 48} changed state {i}",
                     raw="")
            for i, ts in enumerate(stamps)]


# Sized FROM the shipped chunk rather than fixed, so this exercises whatever
# syslogdb is actually tuned to. Half the rows are pruned, so twenty chunks'
# worth of rows is ten batches of real work — enough for "no single hold is
# most of the sweep" to be a claim about batching rather than about there
# having been only two batches. A fixed row count silently stops testing
# anything the day somebody retunes PRUNE_CHUNK, which is exactly what
# happened when it moved from 10,000 to 50,000.
SYSLOG_ROWS = max(120_000, syslogdb.PRUNE_CHUNK * 20)
SYSLOG_DAYS = 30.0
stamps = spread(SYSLOG_ROWS, SYSLOG_DAYS, now)
for start in range(0, SYSLOG_ROWS, 10_000):
    syslog_db.insert(log_entries(stamps[start:start + 10_000]))
# One device with a clock a year ahead, which is the case that stops an id
# range standing in for an age range on this store: these rows arrive last,
# so they hold the highest ids while being the ones the future-dated sweep
# has to reach.
syslog_db.insert(log_entries([now + 400 * DAY + i for i in range(20)]))

expected = set(range(SYSLOG_ROWS // 2 + 1, SYSLOG_ROWS + 1))
measure("syslog logs", syslog_db,
        lambda: syslog_db.prune(SYSLOG_DAYS, 0),
        "SELECT id FROM logs", expected)

assert not syslog_db.last_prune_incomplete, "a 30 s budget is not tight here"
ok("syslogdb reports the sweep finished inside its budget")

# The whole reason syslog is the expensive one: an orphaned FTS row is a
# corrupt search index, and batching is exactly where one would appear.
with syslog_db._lock:
    syslog_db._conn.execute("INSERT INTO logs_fts(logs_fts) "
                            "VALUES('integrity-check')")
    indexed = syslog_db._conn.execute(
        "SELECT COUNT(*) AS n FROM logs_fts").fetchone()["n"]
    stored = syslog_db._conn.execute(
        "SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
assert indexed == stored, (indexed, stored)
ok(f"logs_fts passes integrity-check and holds exactly the {stored} indexed "
   f"row(s) logs does")

hits = syslog_db.search(now - 400 * DAY, now + 400 * DAY,
                        {"text": "interface"}, limit=SYSLOG_ROWS)
assert len(hits) == stored, (len(hits), stored)
assert all(row["ts"] >= now - SYSLOG_DAYS * DAY for row in hits), \
    "a full-text search returned a pruned row"
ok(f"a full-text search after the prune returns all {len(hits)} surviving "
   f"row(s) and no pruned one")

# The row cap is the second stage, and it picks by ts, not by id.
cap = stored - 40_000
kept_ids = surviving(syslog_db,
                     f"SELECT id FROM logs ORDER BY ts DESC LIMIT {cap:d}")
measure("syslog row cap", syslog_db,
        lambda: syslog_db.prune(SYSLOG_DAYS, cap),
        "SELECT id FROM logs", kept_ids)
syslog_db.close()


# ========================================================= snmptraps.db: traps
print("\nsnmptrapdb.prune ages out traps in batches")

now = time.time()
trap_db = SnmpTrapDatabase(os.path.join(TMPDIR, "snmptraps.db"))
TRAP_ROWS = 200_000
TRAP_DAYS = 90.0
with trap_db._lock:
    trap_db._conn.executemany(
        "INSERT INTO traps(ts, source, version, community, trap_oid,"
        " trap_name, trap_kind, severity, is_inform, varbind_n, varbinds,"
        " varbind_text, raw_len) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(ts, f"10.1.{i // 251 % 256}.{i % 251}", 1, "public",
          f"1.3.6.1.6.3.1.1.5.{i % 6}", "linkDown", "linkDown", i % 8, 0, 2,
          '[{"oid":"1.3.6.1.2.1.2.2.1.1","value":"%d"}]' % i,
          f"ifIndex {i} " + "padding " * 20, 128)
         for i, ts in enumerate(spread(TRAP_ROWS, TRAP_DAYS, now))])
    trap_db._conn.commit()

measure("snmp traps", trap_db,
        lambda: trap_db.prune(TRAP_DAYS, 0),
        "SELECT id FROM traps",
        set(range(TRAP_ROWS // 2 + 1, TRAP_ROWS + 1)))
trap_db.close()


# ============================================================ alerts.db: alerts
print("\nalertsdb.prune ages out resolved alerts in batches")

now = time.time()
alerts_db = AlertsDatabase(os.path.join(TMPDIR, "alerts.db"))
ALERT_ROWS = 150_000
ALERT_DAYS = 180.0
rule_id = alerts_db.add_rule("lock.cpu", "Lock CPU", "threshold", "device")
with alerts_db._lock:
    alerts_db._conn.executemany(
        "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
        " entity_label, severity, message, state, opened_ts, last_ts,"
        " resolved_ts) VALUES (?,?,'device',?,?,?,?,'resolved',?,?,?)",
        [(rule_id, f"cpu:{i}", str(i % 500), f"sw-{i % 500}", i % 8,
          f"device sw-{i % 500} stopped answering " + "detail " * 20,
          ts - 60.0, ts, ts)
         for i, ts in enumerate(spread(ALERT_ROWS, ALERT_DAYS, now))])
    # One alert older than every other and still open: it must survive, which
    # is the rule an id-range sweep over the oldest ids would have broken.
    alerts_db._conn.execute(
        "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
        " entity_label, severity, message, state, opened_ts, last_ts,"
        " resolved_ts) VALUES (?,'still-open','device','9','sw-9',2,"
        " 'never resolved','open',?,?,NULL)",
        (rule_id, now - 10 * ALERT_DAYS * DAY, now - 10 * ALERT_DAYS * DAY))
    alerts_db._conn.commit()

expected = set(range(ALERT_ROWS // 2 + 1, ALERT_ROWS + 2))   # + the open one
measure("resolved alerts", alerts_db,
        lambda: alerts_db.prune(ALERT_DAYS),
        "SELECT id FROM alerts", expected)
assert surviving(alerts_db,
                 "SELECT id FROM alerts WHERE state = 'open'") == {ALERT_ROWS + 1}
ok("the oldest alert of all survives because nobody has resolved it")
alerts_db.close()


# ===================================================== nodes.db: mac_entries
print("\nnodesdb.prune_mac_entries ages out the forwarding tables in batches")

now = time.time()
nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
MAC_ROWS = 400_000
MAC_DAYS = 7.0
group_id = nodes_db.ensure_default_group()
device_ids = [nodes_db.add_device(f"10.20.{i // 251}.{i % 251}", f"sw-{i}",
                                  group_id=group_id) for i in range(50)]
with nodes_db._lock:
    nodes_db._conn.executemany(
        "INSERT INTO mac_entries(device_id, if_index, mac, vlan, seen_ts,"
        " first_seen_ts, present) VALUES (?,?,?,?,?,?,1)",
        [(device_ids[i % 50], i % 48 + 1,
          "aa:bb:%02x:%02x:%02x:%02x" % (i >> 24 & 255, i >> 16 & 255,
                                         i >> 8 & 255, i & 255),
          str(i % 8 + 1), ts, ts - DAY)
         for i, ts in enumerate(spread(MAC_ROWS, MAC_DAYS, now))])
    nodes_db._conn.commit()

expected = surviving(
    nodes_db, "SELECT rowid FROM mac_entries WHERE seen_ts > %r"
              % (now - MAC_DAYS * DAY,))
assert len(expected) == MAC_ROWS - MAC_ROWS // 2, len(expected)
measure("mac_entries", nodes_db,
        lambda: nodes_db.prune_mac_entries(MAC_DAYS * DAY),
        "SELECT rowid FROM mac_entries", expected)

# The family shares one body, so one of the other four proves the delegation
# rather than re-proving the batching.
NEIGHBOR_ROWS = 200_000
with nodes_db._lock:
    nodes_db._conn.executemany(
        "INSERT INTO neighbors(device_id, if_index, protocol, rem_index,"
        " chassis_id, port_id, sys_name, seen_ts, first_seen_ts, present)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        [(device_ids[i % 50], i % 48 + 1, ("lldp", "cdp")[i % 2], str(i),
          f"00:11:22:{i & 255:02x}", f"Gi0/{i % 48}", f"peer-{i}", ts, ts - DAY)
         for i, ts in enumerate(spread(NEIGHBOR_ROWS, MAC_DAYS, now))])
    nodes_db._conn.commit()
expected = surviving(
    nodes_db, "SELECT rowid FROM neighbors WHERE seen_ts > %r"
              % (now - MAC_DAYS * DAY,))
measure("neighbors", nodes_db,
        lambda: nodes_db.prune_neighbors(MAC_DAYS * DAY),
        "SELECT rowid FROM neighbors", expected)

# A retention of zero or less still means "prune nothing", as it always did.
assert nodes_db.prune_vlans(0) == 0
assert nodes_db.prune_vlan_ports(-1) == 0
assert nodes_db.prune_port_vlans(0) == 0
assert nodes_db.prune_mac_entries(0) == 0
ok("a retention of zero or less still prunes nothing, on every table in "
   "the family")

# And a table with nothing past the cutoff is a no-op that costs no batches.
assert nodes_db.prune_neighbors(365 * DAY) == 0
ok("a sweep with nothing to delete returns 0 without a delete loop")
nodes_db.close()


# ================================================== nodes.db: device_events
#
# The by-age sweep the maintenance timer runs every 15 minutes, and that the
# Settings panel's "delete all stored events" button runs with a cutoff of
# `now` — on the HTTP request thread, over the whole table.
print("\nnodesdb.prune ages out the event log in batches")

now = time.time()
nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes_events.db"))
EVENT_ROWS = 300_000
EVENT_DAYS = 180.0
group_id = nodes_db.ensure_default_group()
device_ids = [nodes_db.add_device(f"10.30.{i // 251}.{i % 251}", f"sw-{i}",
                                  group_id=group_id) for i in range(200)]
with nodes_db._lock:
    nodes_db._conn.executemany(
        "INSERT INTO device_events(device_id, ts, kind, detail)"
        " VALUES (?,?,?,?)",
        [(device_ids[i % 200], ts, ("down", "up")[i % 2], "stopped answering")
         for i, ts in enumerate(spread(EVENT_ROWS, EVENT_DAYS, now))])
    nodes_db._conn.commit()

expected = set(range(EVENT_ROWS // 2 + 1, EVENT_ROWS + 1))
measure("device_events", nodes_db,
        lambda: nodes_db.prune(event_days=EVENT_DAYS, discovery_days=30),
        "SELECT id FROM device_events", expected)

# And the button: event_days=0 is a cutoff of "now", i.e. every row.
measure("device_events, delete-everything", nodes_db,
        lambda: nodes_db.prune(event_days=0, discovery_days=0),
        "SELECT id FROM device_events", set())
nodes_db.close()


# ================================================= nodes_series.db: samples
#
# The largest table in the product, behind the same single lock every chart
# read and every record_poll write takes.
print("\nnodesseriesdb.prune ages out raw samples and rollups in batches")

now = time.time()
series_db = NodesSeriesDatabase(os.path.join(TMPDIR, "nodes_series.db"))
SAMPLE_ROWS = 300_000
SAMPLE_DAYS = 3.0
METRICS = 5_000
with series_db._lock:
    series_db._conn.executemany(
        "INSERT INTO metrics(device_id, key, label, unit, kind)"
        " VALUES (?,?,?,?,'gauge')",
        [(i % 250, f"if_{i // 250}_in", "In", "bps") for i in range(METRICS)])
    series_db._conn.commit()
    metric_ids = [row[0] for row in
                  series_db._conn.execute("SELECT id FROM metrics ORDER BY id")]
    # metric_id cycles, so a contiguous rowid batch spans every metric —
    # the layout that makes the chunk size matter here (see
    # SAMPLE_PRUNE_CHUNK).
    series_db._conn.executemany(
        "INSERT INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        [(metric_ids[i % METRICS], ts, float(i))
         for i, ts in enumerate(spread(SAMPLE_ROWS, SAMPLE_DAYS, now))])
    series_db._conn.commit()

expected = surviving(series_db, "SELECT rowid FROM samples WHERE ts > %r"
                                % (now - SAMPLE_DAYS * DAY,))
assert len(expected) == SAMPLE_ROWS - SAMPLE_ROWS // 2, len(expected)
measure("samples", series_db,
        lambda: series_db.prune(sample_days=SAMPLE_DAYS, rollup_days=400),
        "SELECT rowid FROM samples", expected)

# The hourly rollups are the second table the same sweep ages out.
ROLLUP_ROWS = 200_000
ROLLUP_DAYS = 400.0
with series_db._lock:
    series_db._conn.executemany(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?,?,4,1.0,2.0,3.0)",
        [(metric_ids[i % METRICS], int(hour))
         for i, hour in enumerate(spread(ROLLUP_ROWS, ROLLUP_DAYS, now))])
    series_db._conn.commit()
expected = surviving(series_db, "SELECT rowid FROM samples_hourly WHERE hour > %r"
                                % (now - ROLLUP_DAYS * DAY,))
measure("samples_hourly", series_db,
        lambda: series_db.prune(sample_days=SAMPLE_DAYS, rollup_days=ROLLUP_DAYS),
        "SELECT rowid FROM samples_hourly", expected)

# "Delete all stored samples" from the Settings maintenance panel.
measure("samples, delete-everything", series_db,
        lambda: series_db.prune(sample_days=0, rollup_days=0),
        "SELECT rowid FROM samples", set())
assert surviving(series_db, "SELECT rowid FROM samples_hourly") == set()
ok("a retention of 0 still empties both tables, as the button promises")
series_db.close()


print(f"\nALL {len(PASSED)} PRUNE-LOCK-HOLD ASSERTIONS PASSED")

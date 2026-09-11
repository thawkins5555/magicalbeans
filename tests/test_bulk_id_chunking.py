"""Every `WHERE id IN (?,?,…)` built from a caller's list is split into
chunks, so a long selection cannot hit SQLite's bind-parameter ceiling.

One statement binds at most SQLITE_MAX_VARIABLE_NUMBER parameters: 32,766 on
SQLite 3.32 and newer, but 999 on anything older, and this application does
not choose which SQLite its Python was linked against. A bulk action built as
one statement therefore works on one operator's install and answers 500 —
"too many SQL variables" — on another's. sqlitebase.id_chunks exists for
exactly that and the bulk writers in alertsdb and configrxdb now go through
it, inside their existing single lock and single commit: the split is a
statement-size detail, not a transaction boundary.

The chunk size is shrunk to 3 here rather than 1,500 rows being written: what
is under test is that the loop exists and that a result assembled from
several chunks is the same result, which a small chunk proves on ten rows.
`id_chunks`' own default is read at import time, so the module's name for it
is what gets replaced, not the constant behind it.
"""
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertsdb as alertsdb_module
from netpath import configrxdb as configrxdb_module
from netpath.alertsdb import AlertsDatabase
from netpath.configrxdb import ConfigRxDatabase
from netpath.sqlitebase import id_chunks

TMP = _paths.tmpdir("bulk_id_chunking_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class tiny_chunks:
    """Shrink one module's id_chunks to `size` ids per statement."""

    def __init__(self, module, size=3):
        self.module, self.size, self.calls = module, size, []

    def __enter__(self):
        self.real = self.module.id_chunks

        def chunked(ids, size=self.size):
            batches = list(id_chunks(ids, size))
            self.calls.append(len(batches))
            return batches

        self.module.id_chunks = chunked
        return self

    def __exit__(self, *exc):
        self.module.id_chunks = self.real
        return False


check("id_chunks splits at the size it is given and drops nothing",
      [list(c) for c in id_chunks(list(range(7)), 3)]
      == [[0, 1, 2], [3, 4, 5], [6]],
      [list(c) for c in id_chunks(list(range(7)), 3)])
check("an empty list is no chunks at all, not one empty statement",
      list(id_chunks([])) == [])


# ------------------------------------------------------------- alerts.db

alerts = AlertsDatabase(os.path.join(TMP, "alerts.db"))
rule_id = alerts.add_rule("chunk.cpu", "Chunk CPU", "threshold", "device")
now = time.time()


def open_ten(prefix):
    ids = []
    for i in range(10):
        row, _opened = alerts.open_or_increment(
            rule_id, f"{prefix}:{i}", "device", str(i), f"sw-{i}", 2,
            "cpu high", "", now + i)
        ids.append(row["id"])
    return ids


ids = open_ten("resolve")
with tiny_chunks(alertsdb_module) as spy:
    resolved = alerts.resolve_many(ids, by="admin")
check("resolve_many resolves every id across several chunks",
      resolved == 10 and spy.calls == [4], (resolved, spy.calls))
check("...and every one of them really is resolved",
      all(alerts.alert(i)["state"] == "resolved" for i in ids))

ids = open_ten("ack")
with tiny_chunks(alertsdb_module) as spy:
    acked = alerts.acknowledge_many(ids, by="admin")
check("acknowledge_many acknowledges every id across several chunks",
      acked == 10 and spy.calls == [4], (acked, spy.calls))
with tiny_chunks(alertsdb_module) as spy:
    unacked = alerts.unacknowledge_many(ids)
check("unacknowledge_many puts every one of them back to open",
      unacked == 10 and spy.calls == [4]
      and all(alerts.alert(i)["state"] == "open" for i in ids),
      (unacked, spy.calls))

# A row that does not qualify is still skipped, chunked or not: the count is
# rows actually changed, not ids offered.
alerts.resolve_many(ids[:4], by="admin")
with tiny_chunks(alertsdb_module):
    again = alerts.resolve_many(ids, by="admin")
check("an id that is already resolved is not counted a second time",
      again == 6, again)

ids = open_ten("family:member")
with tiny_chunks(alertsdb_module) as spy:
    rows = alerts.resolve_by_dedup_prefix("family:member:", by="admin")
check("resolve_by_dedup_prefix reads back every resolved row, oldest first,"
      " across several chunks",
      [row["id"] for row in rows] == ids and spy.calls == [4],
      ([row["id"] for row in rows], ids, spy.calls))
check("...and every returned row carries the resolution it was given",
      all(row["state"] == "resolved" and row["resolved_by"] == "admin"
          for row in rows))

# The real ceiling, unshrunk: a selection accumulated across Alerts pages is
# a Set that survives paging, so an operator can genuinely send thousands.
big = list(range(500_000, 502_000))
check("two thousand ids that match nothing is a no-op, not an"
      " OperationalError",
      alerts.resolve_many(big) == 0 and alerts.acknowledge_many(big) == 0
      and alerts.unacknowledge_many(big) == 0)
alerts.close()


# ----------------------------------------------------------- configrx.db

configrx = ConfigRxDatabase(os.path.join(TMP, "configrx.db"))
backup_ids = []
for i in range(10):
    backup_id, _sha = configrx.add_backup(1, f"hostname sw-1\n! revision {i}\n")
    backup_ids.append(backup_id)
check("the fixture stored ten distinct backups", len(set(backup_ids)) == 10,
      backup_ids)

with tiny_chunks(configrxdb_module) as spy:
    removed = configrx.delete_backups(backup_ids[:7])
check("delete_backups removes every id across several chunks",
      removed == 7 and spy.calls == [3], (removed, spy.calls))
check("...and leaves the ones it was not given",
      len(configrx.backups_for(1)) == 3, len(configrx.backups_for(1)))

# prune's per-device stale list is the one that is not operator-driven: an
# install that ran with no count cap for a year and then sets one produces a
# list of every backup past the newest N, in one statement.
for i in range(10, 30):
    configrx.add_backup(1, f"hostname sw-1\n! revision {i}\n")
with tiny_chunks(configrxdb_module) as spy:
    removed = configrx.prune(retention_days=3650,
                             retention_count_per_device=5)
check("prune's stale list is chunked too",
      removed == 18 and spy.calls and max(spy.calls) > 1,
      (removed, spy.calls))
check("...and keeps exactly the newest five",
      len(configrx.backups_for(1)) == 5, len(configrx.backups_for(1)))
configrx.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

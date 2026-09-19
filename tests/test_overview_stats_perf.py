"""SnmpTrapDatabase.stats() / SyslogDatabase.stats() used to run one
combined `COUNT(*), MIN(ts), MAX(ts)` query, which forces SQLite to SCAN the
whole index even though MIN(ts)/MAX(ts) alone are index SEARCHes. Split into
three queries, the row count stays an exact COUNT(*) (log_counts/trap_counts
are not exact enough to replace it -- a prune's cutoff usually falls
mid-hour) while lo/hi become fast index probes. Pins: the split answers the
same numbers a seeded store's old combined query would, and EXPLAIN QUERY
PLAN shows SEARCH (not SCAN) for the lo/hi probes.

House style: a plain script, FAILS collects failed check() names, exit 1 if
anything failed.
"""
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath import syslogparse
from netpath import trapdecode

TMPDIR = _paths.tmpdir("overview_stats_perf_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def query_plan(conn, sql) -> str:
    return " | ".join(row[3] for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}"))


# ==================================================================== traps
print("snmptrapdb.stats()")

snmp = SnmpTrapDatabase(os.path.join(TMPDIR, "traps.db"))
now = time.time()
for i in range(50):
    snmp.insert([trapdecode.Trap(
        ts=now - i * 10, source=f"10.70.0.{i % 5 + 1}", version=1,
        community="public", trap_oid="1.3.6.1.6.3.1.1.5.3", trap_name="linkDown",
        trap_kind="link_down", severity=5, generic=2, specific=0,
        enterprise="", agent_addr="10.70.0.1", uptime=0, is_inform=False,
        varbinds=[])])

old_row = snmp._conn.execute(
    "SELECT COUNT(*) AS rows, MIN(ts) AS lo, MAX(ts) AS hi FROM traps").fetchone()
stats = snmp.stats()
check("stats()'s rows/lo/hi match the old combined query on a seeded store",
      (stats["rows"], stats["lo"], stats["hi"])
      == (old_row["rows"], old_row["lo"], old_row["hi"]),
      (stats, dict(old_row)))

check("MIN(ts) alone is an index SEARCH, not a SCAN",
      "SEARCH" in query_plan(snmp._conn, "SELECT MIN(ts) FROM traps"))
check("MAX(ts) alone is an index SEARCH, not a SCAN",
      "SEARCH" in query_plan(snmp._conn, "SELECT MAX(ts) FROM traps"))
check("...while the old combined query was a full SCAN (why it was slow)",
      "SCAN" in query_plan(
          snmp._conn,
          "SELECT COUNT(*) AS rows, MIN(ts) AS lo, MAX(ts) AS hi FROM traps"))
snmp.close()


# =================================================================== syslog
print("\nsyslogdb.stats()")

syslog = SyslogDatabase(os.path.join(TMPDIR, "syslog.db"))
for i in range(50):
    syslog.insert([syslogparse.LogEntry(
        ts=now - i * 10, source=f"10.70.1.{i % 5 + 1}", severity=6,
        app="sshd", message=f"seed {i}")])

old_row = syslog._conn.execute(
    "SELECT COUNT(*) AS rows, MIN(ts) AS lo, MAX(ts) AS hi FROM logs").fetchone()
stats = syslog.stats()
check("stats()'s rows/lo/hi match the old combined query on a seeded store",
      (stats["rows"], stats["lo"], stats["hi"])
      == (old_row["rows"], old_row["lo"], old_row["hi"]),
      (stats, dict(old_row)))

check("MIN(ts) alone is an index SEARCH, not a SCAN",
      "SEARCH" in query_plan(syslog._conn, "SELECT MIN(ts) FROM logs"))
check("MAX(ts) alone is an index SEARCH, not a SCAN",
      "SEARCH" in query_plan(syslog._conn, "SELECT MAX(ts) FROM logs"))
syslog.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

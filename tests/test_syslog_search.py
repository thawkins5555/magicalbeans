"""Tier 0 fix T0-2: syslogdb._fts_query() honours the app's universal `*`
prefix convention (`interfac*`) instead of quoting the asterisk literally
and matching nothing. Covers the query-builder in isolation (so the
assertions hold whether or not this SQLite build has FTS5/trigram) and an
end-to-end search against a real logs_fts index when one is available."""
import os

from _paths import spawn_stub, tmpdir  # noqa: F401  (repo root on sys.path)

TMP = tmpdir("syslog_search_")

from netpath.syslogdb import SyslogDatabase
from netpath.syslogparse import LogEntry

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------- 1. the query builder

# A trailing `*` becomes an FTS5 prefix operator on the quoted phrase.
check("trailing * becomes a prefix query",
      SyslogDatabase._fts_query("interfac*") == '"interfac"*',
      SyslogDatabase._fts_query("interfac*"))

# Plain terms are unaffected -- same quoting as before.
check("a plain term is quoted, unchanged",
      SyslogDatabase._fts_query("interface") == '"interface"',
      SyslogDatabase._fts_query("interface"))

# Several terms: only the ones ending in * get the prefix marker.
check("mixed plain and prefix terms",
      SyslogDatabase._fts_query("error interfac*") == '"error" AND "interfac"*',
      SyslogDatabase._fts_query("error interfac*"))

# A `*` anywhere but the end does not break the query -- it is dropped,
# not quoted literally (a literal `*` can never match real content).
check("leading * is stripped, not quoted literally",
      SyslogDatabase._fts_query("*view") == '"view"',
      SyslogDatabase._fts_query("*view"))
check("embedded * is stripped, not quoted literally",
      SyslogDatabase._fts_query("inter*face") == '"interface"',
      SyslogDatabase._fts_query("inter*face"))
check("a lone * does not crash the builder",
      SyslogDatabase._fts_query("*") == '""',
      SyslogDatabase._fts_query("*"))

# Injection attempts: quotes, NEAR, AND are still just literal text --
# quoting swallows FTS5 syntax exactly as before the wildcard change.
check("a literal double-quote is stripped, not smuggled into the query",
      SyslogDatabase._fts_query('foo"bar') == '"foobar"',
      SyslogDatabase._fts_query('foo"bar'))
check("NEAR is treated as a literal search term",
      SyslogDatabase._fts_query("NEAR") == '"NEAR"',
      SyslogDatabase._fts_query("NEAR"))
check("AND is treated as a literal search term",
      SyslogDatabase._fts_query("AND") == '"AND"',
      SyslogDatabase._fts_query("AND"))
check("a quote-and-NEAR injection attempt stays one literal, quoted term",
      SyslogDatabase._fts_query('"x" NEAR "y"')
      == '"x" AND "NEAR" AND "y"',
      SyslogDatabase._fts_query('"x" NEAR "y"'))


# ------------------------------------------------- 2. end-to-end, real FTS

db_path = os.path.join(TMP, "syslog.db")
db = SyslogDatabase(db_path)
try:
    if not db.fts:
        print("SKIP: no FTS5/trigram in this SQLite build; query-builder"
              " checks above still cover the fix")
    else:
        base_ts = 1_700_000_000.0
        db.insert([
            LogEntry(ts=base_ts, source="10.0.0.1", host="core-sw-a", app="LINK",
                     severity=3, procid="", msgid="",
                     message="%LINK-3-UPDOWN: Interface Gi0/1 changed state to down",
                     raw="raw line 1"),
            LogEntry(ts=base_ts + 1, source="10.0.0.2", host="core-sw-b", app="OSPF",
                     severity=6, procid="", msgid="",
                     message="neighbor state change to FULL", raw="raw line 2"),
        ])
        db.start_index_backfill()

        def search_text(text):
            return db.search(base_ts - 10, base_ts + 10, {"text": text})

        rows = search_text("interface")
        check("unprefixed 'interface' still matches the substring",
              len(rows) == 1 and "Interface" in rows[0]["message"], rows)

        rows = search_text("interfac*")
        check("'interfac*' now matches (used to quote the literal '*'"
              " and return zero rows)",
              len(rows) == 1 and "Interface" in rows[0]["message"], rows)

        rows = search_text("*interfac")
        check("a leading '*' does not break the search",
              len(rows) == 1 and "Interface" in rows[0]["message"], rows)

        rows = search_text('"quoted" NEAR term*')
        check("quote/NEAR injection alongside a prefix term does not error",
              isinstance(rows, list), rows)

        rows = search_text("neighbor*")
        check("a prefix term matches a different row than 'interfac*' did",
              len(rows) == 1 and rows[0]["app"] == "OSPF", rows)
finally:
    db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

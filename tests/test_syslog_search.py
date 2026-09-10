"""syslogdb._fts_query() honours the app's universal `*`
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


# --------------------------------- 3. host search widened by resolved IPs
#
# `logs.host` is only what the device put in the syslog header -- often
# blank. The API resolves the typed fragment to device IPs and hands them in
# as filters["host_ips"]; the host clause must then accept a row by source.

db = SyslogDatabase(os.path.join(TMP, "syslog_hosts.db"))
try:
    T = 1_700_100_000.0
    WIN = (T - 10, T + 10)

    def row(ts, source, host, message):
        return LogEntry(ts=ts, source=source, host=host, severity=6,
                        message=message, raw=message)

    many_ips = [f"10.9.{i // 256}.{i % 256}" for i in range(1, 602)]
    db.insert([
        row(T, "10.0.0.1", "", "blank host, source resolves"),
        row(T + 1, "10.0.0.2", "core-sw-b", "self-reported host"),
        row(T + 2, "10.0.0.3", "", "blank host, unrelated source"),
        row(T + 3, many_ips[-1], "", "blank host, ip in second chunk"),
        row(T - 100, "10.0.0.1", "", "resolves, but outside the window"),
    ])

    def hosts(filters, window=WIN):
        return sorted(r["message"] for r in db.search(*window, filters))

    check("blank self-reported host, source in host_ips: found",
          hosts({"host": "core-sw", "host_ips": ["10.0.0.1"]})
          == ["blank host, source resolves"],
          hosts({"host": "core-sw", "host_ips": ["10.0.0.1"]}))
    check("self-reported host still matches the LIKE alongside host_ips",
          hosts({"host": "core-sw-b", "host_ips": ["10.0.0.1"]})
          == ["blank host, source resolves", "self-reported host"],
          hosts({"host": "core-sw-b", "host_ips": ["10.0.0.1"]}))
    check("host_ips absent: only the LIKE, as before",
          hosts({"host": "core-sw"}) == ["self-reported host"],
          hosts({"host": "core-sw"}))
    check("host_ips empty: same rows as absent",
          hosts({"host": "core-sw", "host_ips": []})
          == hosts({"host": "core-sw"}),
          hosts({"host": "core-sw", "host_ips": []}))
    check("host_ips without host is not a filter of its own",
          len(hosts({"host_ips": ["10.0.0.1"]})) == 4,
          hosts({"host_ips": ["10.0.0.1"]}))
    where_plain = db._where(*WIN, {"host": "x"})
    check("no host_ips: the WHERE is byte-identical to the plain host clause",
          db._where(*WIN, {"host": "x", "host_ips": []}) == where_plain
          and db._where(*WIN, {"host": "x", "host_ips": None}) == where_plain
          and where_plain[0] == "l.ts >= ? AND l.ts <= ? AND l.host LIKE ?",
          where_plain)

    # 601 IPs -> two IN chunks. The match lives in the second chunk, and the
    # out-of-window row with a first-chunk source must stay out: a chunk
    # OR-ed at the wrong nesting level would let it through.
    wide = {"host": "nomatch", "host_ips": ["10.0.0.1", *many_ips]}
    check("more than 500 IPs still matches (second chunk)",
          hosts(wide) == ["blank host, ip in second chunk",
                          "blank host, source resolves"],
          hosts(wide))
    sql, params = db._where(*WIN, wide)
    check("chunks are OR-ed inside the host parenthesis, under the time AND",
          sql.startswith("l.ts >= ? AND l.ts <= ? AND (l.host LIKE ? OR l.source IN (")
          and sql.count(" OR l.source IN (") == 2 and sql.endswith("))")
          and len(params) == 2 + 1 + 602, sql[:120])
    check("the histogram takes the same widened clause",
          sum(b["total"] for b in db.histogram(WIN[0], WIN[1], 3600, wide)) == 2,
          db.histogram(WIN[0], WIN[1], 3600, wide))
    check("...and the out-of-window row stays out of the histogram",
          sum(b["total"] for b in db.histogram(T - 200, T - 50, 3600, wide)) == 1,
          db.histogram(T - 200, T - 50, 3600, wide))
finally:
    db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

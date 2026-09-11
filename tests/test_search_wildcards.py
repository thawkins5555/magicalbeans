"""`_` and `%` typed into a search box mean those characters, not LIKE's
wildcards.

Every search in this product ends in a `LIKE ?` with an operator's text bound
to it. Without `ESCAPE`, a `_` in the needle silently means "any single
character" and a `%` means "anything" — so an engineer hunting `core_sw_2`
got `core-sw-1` back beside it with nothing on screen saying why, and a
single `%` returned the lot.

The stores with a search suite of their own are covered there
(test_device_search_fields, test_ipam_dhcp_search, test_syslog_search); this
suite covers the rest — the reverse-DNS cache, the Alerts list filter, the
NetFlow record filter and the trap store's own filters and free-text scan —
and the shared helper all of them now build the needle with.
"""
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.appdb import AppDatabase
from netpath.flowdb import FlowDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.sqlitebase import LIKE_ESCAPE, like_contains, like_prefix

TMP = _paths.tmpdir("search_wildcards_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------- 1. the helpers

check("like_contains escapes the backslash first, so an escape cannot be"
      " built out of the operator's own text",
      like_contains(r"a\_b") == r"%a\\\_b%", like_contains(r"a\_b"))
check("like_prefix does the same without the leading %",
      like_prefix("50%") == r"50\%%", like_prefix("50%"))
check("ordinary text is untouched apart from the wrapping",
      like_contains("core-sw") == "%core-sw%", like_contains("core-sw"))
check("the clause constant is the one SQLite spelling of the escape",
      LIKE_ESCAPE == "ESCAPE '\\'", LIKE_ESCAPE)


# --------------------------------------- 2. appdb.search_hostnames (cache)

app_db = AppDatabase(os.path.join(TMP, "app.db"))
app_db.set_hostname("10.0.0.1", "core-sw-1")
app_db.set_hostname("10.0.0.2", "core_sw_2")
app_db.set_hostname("10.0.0.3", "cafe%till")


def names(query):
    return sorted(r["hostname"] for r in app_db.search_hostnames(query))


check("an underscore in a hostname search matches an underscore",
      names("core_sw") == ["core_sw_2"], names("core_sw"))
check("a per-cent sign matches the name that has one, not every name",
      names("%") == ["cafe%till"], names("%"))
check("...and a hyphen still finds the hyphenated one",
      names("core-sw") == ["core-sw-1"], names("core-sw"))
check("an address fragment still matches on the IP column",
      names("10.0.0.") == ["cafe%till", "core-sw-1", "core_sw_2"],
      names("10.0.0."))

# audit_query has escaped its needle since it was written; it now shares the
# helper, and must still answer exactly.
app_db.audit("admin", "127.0.0.1", "device.update", "target_1")
app_db.audit("admin", "127.0.0.1", "device.update", "targetX1")
rows = app_db.audit_query(0, time.time() + 60, q="target_1")
check("audit_query still takes its free-text needle literally",
      [r["target"] for r in rows] == ["target_1"], [r["target"] for r in rows])
app_db.close()


# --------------------------------------- 3. alertsdb's list filter

alerts_db = AlertsDatabase(os.path.join(TMP, "alerts.db"))
rule_id = alerts_db.add_rule("wild.cpu", "Wildcards", "threshold", "device")
now = time.time()
for entity_id, label, message in (
        ("1", "core-sw-1", "cpu high on core-sw-1"),
        ("2", "core_sw_2", "cpu high on core_sw_2"),
        ("3", "edge-ap-9", "link at 50% of capacity")):
    alerts_db.open_or_increment(rule_id, f"cpu:{entity_id}", "device",
                                entity_id, label, 2, message, "", now)


def labels(**kwargs):
    return sorted(r["entity_label"] for r in alerts_db.alerts(**kwargs))


check("an underscore in the Alerts device filter is an underscore",
      labels(device_text="core_sw") == ["core_sw_2"],
      labels(device_text="core_sw"))
check("...and the count beside the list agrees",
      alerts_db.count_alerts(device_text="core_sw") == 1,
      alerts_db.count_alerts(device_text="core_sw"))
check("a per-cent sign in the Alerts text filter is not 'every alert'",
      labels(text="%") == ["edge-ap-9"], labels(text="%"))
check("...and it finds the message that really contains one",
      labels(text="50%") == ["edge-ap-9"], labels(text="50%"))
check("the text filter still searches the label as well as the message",
      labels(text="core_sw") == ["core_sw_2"], labels(text="core_sw"))
alerts_db.close()


# --------------------------------------- 4. flowdb's record filter

flow_db = FlowDatabase(os.path.join(TMP, "flows.db"))
with flow_db._lock:
    flow_db._conn.executemany(
        "INSERT INTO flows(exporter, version, ts_start, ts_end, src_ip,"
        " dst_ip, src_port, dst_port, protocol, tos, tcp_flags, in_if,"
        " out_if, src_as, dst_as, next_hop, packets, bytes, sampling,"
        " domain, sampler_id)"
        " VALUES (?,9,?,?,?,?,1024,443,6,0,0,1,2,0,0,'',10,1000,1,0,0)",
        [("10.0.0.1", now - 10, now, "10.1.2.3", "192.168.0.10"),
         ("10.0.0.1", now - 10, now, "10.1.2.33", "192.168.0.11")])
    flow_db._conn.commit()


def sources(needle):
    rows, _capped = flow_db.flows(now - 60, now + 60, {"src_ip": needle})
    return sorted(r["src_ip"] for r in rows)


check("an underscore in the NetFlow address filter is an underscore",
      sources("10.1.2.3_") == [], sources("10.1.2.3_"))
check("...and the address that really is there still matches",
      sources("10.1.2.33") == ["10.1.2.33"], sources("10.1.2.33"))
check("a per-cent sign in the NetFlow address filter is not 'every flow'",
      sources("%") == [], sources("%"))
check("a dotted fragment still matches both",
      sources("10.1.2.3") == ["10.1.2.3", "10.1.2.33"], sources("10.1.2.3"))
where, params = flow_db._where(0, 1, {"dst_ip": "192.168.0.1_"})
check("the destination half is escaped too",
      where.count(LIKE_ESCAPE) == 1 and params[-1] == r"%192.168.0.1\_%",
      (where, params))
flow_db.close()

# ------------------------------- 5. snmptrapdb's filters and free-text scan

trap_db = SnmpTrapDatabase(os.path.join(TMP, "traps.db"))
with trap_db._lock:
    trap_db._conn.executemany(
        "INSERT INTO traps(ts, source, version, community, engine_id,"
        " security, auth_state, trap_oid, trap_name, trap_kind, severity,"
        " generic, specific, enterprise, agent_addr, uptime, is_inform,"
        " varbind_n, varbinds, varbind_text, raw_len, raw)"
        " VALUES (?,?,1,?,'','','',?,?,'linkDown',4,0,0,'','',0,0,0,'[]',?,"
        "0,NULL)",
        [(now - 10, "core-sw-2", "pub-lic", "1.3.6.1.2.1", "linkDown",
          "ifDescr Gi1/0/1"),
         (now - 10, "core_sw_2", "pub_lic", "1.3.6.1.4.1", "coldStart",
          "ifDescr Gi2/0/1")])
    trap_db._conn.commit()


def trap_sources(filters):
    return sorted(row["source"] for row in
                  trap_db.search(now - 60, now + 60, filters))


check("an underscore in the trap Source filter is an underscore",
      trap_sources({"source": "core_sw"}) == ["core_sw_2"],
      trap_sources({"source": "core_sw"}))
check("a per-cent sign in the trap Source filter is not every trap",
      trap_sources({"source": "%"}) == [], trap_sources({"source": "%"}))
check("the hyphenated source is still found by its own text",
      trap_sources({"source": "core-sw"}) == ["core-sw-2"],
      trap_sources({"source": "core-sw"}))
check("the trap Community filter escapes too",
      trap_sources({"community": "pub_lic"}) == ["core_sw_2"],
      trap_sources({"community": "pub_lic"}))
check("...and a lone per-cent there matches nothing",
      trap_sources({"community": "%"}) == [], trap_sources({"community": "%"}))
check("the trap OID/name filter escapes both of its halves",
      trap_sources({"oid": "%"}) == [], trap_sources({"oid": "%"}))
check("...while a real OID fragment still matches",
      trap_sources({"oid": "1.3.6.1.2"}) == ["core-sw-2"],
      trap_sources({"oid": "1.3.6.1.2"}))
check("the free-text scan across every trap column escapes each term",
      trap_sources({"text": "core_sw"}) == ["core_sw_2"],
      trap_sources({"text": "core_sw"}))
check("...and a bare per-cent typed into it returns nothing",
      trap_sources({"text": "%"}) == [], trap_sources({"text": "%"}))
where, params = trap_db._where(0, 1, {"source": "a_b"})
check("the trap where-clause carries the escape once per LIKE",
      where.count(LIKE_ESCAPE) == 1 and params[-1] == r"%a\_b%",
      (where, params))
trap_db.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

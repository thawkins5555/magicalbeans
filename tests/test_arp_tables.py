"""ARP-cache walks and ARP-table history: the two IP-MIB tables and the
fallback between them, index parsing, invalid(2) rows, MAC normalisation,
the row-cap guard, present/absent history across two walks, the
update-in-place key, pruning, arp_locations by MAC and by IP, and the
arp_table_interval_s gate — the ARP counterpart of test_mac_tables.py,
which established the harness this one reuses."""
import socket
import sqlite3
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("arp_tables_")

import netpath.nodepoll as nodepoll_mod
from netpath import nodeoids
from netpath.nodesdb import ADDRESS_SEARCH_MIN_CHARS, NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.web import Service, api


def stub_stat(port: int, command: bytes) -> str:
    """Talks the stub's own STATS/RESET/HIDE control protocol directly —
    plain UDP, no SNMP framing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(command, ("127.0.0.1", port))
    try:
        return s.recv(256).decode("utf-8", "replace")
    finally:
        s.close()


def request_count(port: int) -> int:
    return int(stub_stat(port, b"STATS"))


def reset_count(port: int) -> None:
    stub_stat(port, b"RESET")


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, port: int, *, version: int = 1,
                   name: str = "rtr") -> int:
    """A device polling the stub at `port`, v1 (0) or v2c (1), one socket's
    worth of retries so a wrong branch fails fast rather than slowly."""
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=version, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    did = db.add_device("127.0.0.1", name=name, group_id=gid)
    db.seed_identity(did, sys_descr="", sys_name=name,
                     sys_object_id="1.3.6.1.4.1.99999.1", vendor="generic")
    return did


class CapturingLog:
    """Enough of eventlog to count what _run_arp_table says."""

    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append((category, message))


FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def by_ip(entries):
    return {e["ip"]: e for e in (entries or [])}


# ---------------------------------------------- 1. the legacy table alone
stub, port = spawn_stub("stub_agent_l2.py", "arp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("legacy")
    did = device_against(db, port, name="legacy-rtr")
    poller = NodePoller(db)
    entries = poller.read_device_arp_table(did)
    rows = by_ip(entries)
    check("ipNetToMediaTable: the three good rows come back and nothing else",
          set(rows) == {"10.0.0.5", "10.0.0.6", "10.0.1.9"}, entries)
    check("the ifIndex and the IP are both recovered from the row index",
          rows.get("10.0.0.5", {}).get("if_index") == 1
          and rows.get("10.0.1.9", {}).get("if_index") == 2, entries)
    check("an invalid(2) row is dropped", "10.0.1.66" not in rows, entries)
    check("a four-octet PhysAddress (not a MAC) is dropped",
          "10.0.0.7" not in rows, entries)
    check("entry_type carries the MIB's own word",
          rows.get("10.0.0.5", {}).get("entry_type") == "dynamic"
          and rows.get("10.0.0.6", {}).get("entry_type") == "static", entries)
    check("a MAC whose six bytes are all printable still decodes to the bytes",
          rows.get("10.0.1.9", {}).get("mac") == "41:42:43:44:45:46", entries)

    stored = db.replace_arp_entries(did, entries)
    stored_rows = {r["ip"]: dict(r) for r in db.arp_entries_for(did)}
    check("replace_arp_entries stores every good row", stored == 3 == len(stored_rows),
          (stored, stored_rows))
    check("...with the MAC in normalize_mac's form: lowercase, no separators",
          stored_rows.get("10.0.0.6", {}).get("mac") == "aabbccddeeff"
          and stored_rows.get("10.0.1.9", {}).get("mac") == "414243444546",
          stored_rows)
    check("arp_entries_for(device, if_index) narrows to one interface",
          [r["ip"] for r in db.arp_entries_for(did, 2)] == ["10.0.1.9"],
          [dict(r) for r in db.arp_entries_for(did, 2)])
    db.close()
finally:
    stub.kill()

# ---------------------------------------- 2. the successor table as fallback
stub, port = spawn_stub("stub_agent_l2.py", "arp_physical")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("modern")
    did = device_against(db, port, name="modern-rtr")
    poller = NodePoller(db)
    entries = poller.read_device_arp_table(did)
    rows = by_ip(entries)
    check("ipNetToPhysicalTable is walked when the legacy table has no rows",
          entries is not None and len(entries) == 4, entries)
    check("its ifIndex.addrType.addrLen.<arcs> index recovers an IPv4 address",
          rows.get("10.0.0.5", {}).get("if_index") == 1
          and rows.get("10.0.0.5", {}).get("mac") == "00:11:22:33:44:55", entries)
    check("...and an IPv6 one, stored compressed",
          rows.get("fe80::1", {}).get("if_index") == 1
          and rows.get("fe80::1", {}).get("mac") == "00:11:22:33:44:55", entries)
    check("a local(5) row is kept, and says so",
          rows.get("10.0.1.1", {}).get("entry_type") == "local", entries)
    check("an invalid(2) row is dropped here too", "10.0.1.66" not in rows, entries)
    check("a dns(16)-typed address is skipped, not stored as a guess",
          all(r["if_index"] in (1, 2) for r in entries)
          and not any(m["mac"] == "00:00:00:00:00:99" for m in entries), entries)
    db.replace_arp_entries(did, entries)
    check("an IPv6 neighbour is searchable by its address",
          [r["ip"] for r in db.arp_locations("fe80::1")] == ["fe80::1"],
          [dict(r) for r in db.arp_locations("fe80::1")])
    check("...and by a colon-bearing prefix, which also reads as a MAC prefix",
          {r["ip"] for r in db.arp_locations("fe80:")} == {"fe80::1"},
          [dict(r) for r in db.arp_locations("fe80:")])
    db.close()
finally:
    stub.kill()

# ------------------------------------------ 3. both tables: legacy wins
stub, port = spawn_stub("stub_agent_l2.py", "arp_both")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("both")
    did = device_against(db, port, name="both-rtr")
    poller = NodePoller(db)
    reset_count(port)
    entries = poller.read_device_arp_table(did)
    rows = by_ip(entries)
    check("a device answering both tables yields the legacy rows only",
          set(rows) == {"10.0.0.5", "10.0.0.6", "10.0.1.9"}, entries)
    check("...so the successor-only row never appears (a fallback, not a merge)",
          "10.0.9.9" not in rows and "fe80::1" not in rows, entries)
    check("...and nothing is double-counted",
          entries is not None and len(entries) == len(rows), entries)
    check("...and the successor table was not even walked",
          request_count(port) <= 4, request_count(port))
    db.close()
finally:
    stub.kill()

# ----------------------------------------------- 4. neither table at all
stub, port = spawn_stub("stub_agent_l2.py", "no_arp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("none")
    did = device_against(db, port, name="l2-only-sw")
    log = CapturingLog()
    poller = NodePoller(db, log=log)
    check("a device answering neither table reads as None, not []",
          poller.read_device_arp_table(did) is None)
    db.replace_arp_entries(did, [{"if_index": 1, "ip": "10.9.9.9",
                                  "mac": "00:00:00:00:09:09"}], now=time.time())
    before = [dict(r) for r in db.arp_entries_for(did)]
    for _ in range(3):
        poller._arp_running.add(did)
        poller._run_arp_table(did)
    after = [dict(r) for r in db.arp_entries_for(did)]
    check("_run_arp_table leaves the stored table alone for such a device",
          before == after, (before, after))
    said = [m for c, m in log.lines if "neither" in m]
    check("...and says so ONCE across three walks, not once per walk",
          len(said) == 1 and f"#{did}" in said[0], log.lines)
    check("...at NODES level, not as an error",
          all(c != "ERROR" for c, _ in log.lines), log.lines)
    check("...without counting a walk", poller.counters["arp_walks"] == 0,
          poller.counters)
    check("...and nothing is left marked running", did not in poller._arp_running)
    db.close()
finally:
    stub.kill()

# ---------------------------------- 5. GETBULK cost and the row-cap guard
stub, port = spawn_stub("stub_agent_l2.py", "arp_big")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("big")
    did = device_against(db, port, name="big-rtr")
    log = CapturingLog()
    poller = NodePoller(db, log=log)
    reset_count(port)
    entries = poller.read_device_arp_table(did)
    bulk_requests = request_count(port)
    check("GETBULK: a 120-row cache returns every row",
          entries is not None and len(entries) == 120,
          len(entries) if entries else entries)
    check("...in a handful of requests (two columns, 40 rows each)",
          bulk_requests <= 8, bulk_requests)
    print(f"  120-row ARP cache: GETBULK cost {bulk_requests} request(s)")

    # The cap. _walk_column stops at snmp_walk_max_rows and reports the
    # walk incomplete; a walker that stored the 50 rows it got would mark
    # the other 70 absent — live hosts aged out every cycle.
    db.replace_arp_entries(did, entries, now=time.time())
    db.save_settings({**db.settings(), "snmp_walk_max_rows": 50})
    capped = poller.read_device_arp_table(did)
    check("a walk that hit snmp_walk_max_rows returns None, never a partial table",
          capped is None, capped if capped is None else len(capped))
    poller._arp_running.add(did)
    poller._run_arp_table(did)
    still = db.arp_entries_for(did)
    check("...so _run_arp_table stores nothing and every row stays present",
          len(still) == 120 and all(r["present"] for r in still),
          (len(still), sum(1 for r in still if not r["present"])))
    cut = [m for c, m in log.lines if "cut short" in m]
    check("...and says why, naming the cap",
          len(cut) == 1 and "cap" in cut[0], log.lines)
    poller._arp_running.add(did)
    poller._run_arp_table(did)
    check("...once, not once per attempt",
          len([m for c, m in log.lines if "cut short" in m]) == 1, log.lines)

    db.save_settings({**db.settings(), "snmp_walk_max_rows": 16384})
    poller._arp_running.add(did)
    poller._run_arp_table(did)
    check("raising the cap stores the table again and logs the recovery",
          poller.counters["arp_walks"] == 1
          and any("again" in m for c, m in log.lines), log.lines)
    db.close()
finally:
    stub.kill()

# --------------------------------------------- 6. history: present/absent
stub, port = spawn_stub("stub_agent_l2.py", "arp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("history")
    did = device_against(db, port, name="hist-rtr")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Vlan10", "phys_addr": "00:00:5e:00:01:0a"},
        {"if_index": 2, "descr": "Vlan20", "phys_addr": "00:00:5e:00:01:14"}])
    poller = NodePoller(db)

    walk1_ts = time.time()
    entries = poller.read_device_arp_table(did)
    stored = db.replace_arp_entries(did, entries, now=walk1_ts)
    check("first walk stores every row, all present",
          stored == len(entries)
          and all(r["present"] for r in db.arp_entries_for(did)),
          [dict(r) for r in db.arp_entries_for(did)])
    first_pass = {r["ip"]: dict(r) for r in db.arp_entries_for(did)}

    stub_stat(port, b"HIDE 10.0.0.5")
    entries2 = poller.read_device_arp_table(did)
    check("the hidden IP no longer walks",
          all(e["ip"] != "10.0.0.5" for e in entries2), entries2)
    walk2_ts = walk1_ts + 60.0
    db.replace_arp_entries(did, entries2, now=walk2_ts)
    rows = {r["ip"]: dict(r) for r in db.arp_entries_for(did)}
    check("the row count is unchanged — nothing is deleted, just marked",
          len(rows) == len(first_pass), (len(rows), len(first_pass)))
    gone = rows.get("10.0.0.5", {})
    check("the expired entry's row is present=0", gone and not gone["present"], gone)
    check("...with the OLD seen_ts kept, not refreshed",
          gone.get("seen_ts") == first_pass["10.0.0.5"]["seen_ts"], gone)
    check("...and first_seen_ts untouched",
          gone.get("first_seen_ts") == first_pass["10.0.0.5"]["first_seen_ts"], gone)
    present_now = {ip: r for ip, r in rows.items() if ip != "10.0.0.5"}
    check("rows still present got a fresh seen_ts",
          present_now and all(r["seen_ts"] == walk2_ts for r in present_now.values()),
          present_now)
    check("...and kept their original first_seen_ts",
          all(r["first_seen_ts"] == first_pass[ip]["first_seen_ts"]
              for ip, r in present_now.items()), present_now)

    # The key is (device, interface, ip): a host replaced behind the same
    # address is the same row with a new MAC, not a second row.
    walk3_ts = walk2_ts + 60.0
    db.replace_arp_entries(did, [
        {"if_index": 1, "ip": "10.0.0.6", "mac": "02:00:00:00:00:66",
         "entry_type": "dynamic"},
    ], now=walk3_ts)
    changed = [dict(r) for r in db.arp_entries_for(did) if r["ip"] == "10.0.0.6"]
    check("a MAC change behind an IP updates ONE row in place",
          len(changed) == 1 and changed[0]["mac"] == "020000000066"
          and changed[0]["present"] == 1 and changed[0]["seen_ts"] == walk3_ts,
          changed)
    check("...keeping the ORIGINAL first_seen_ts",
          changed and changed[0]["first_seen_ts"] == first_pass["10.0.0.6"]["first_seen_ts"],
          (changed, first_pass["10.0.0.6"]))
    check("...and refreshing entry_type as data (it was static)",
          changed and changed[0]["entry_type"] == "dynamic", changed)
    check("nothing else was invented: still one row per (interface, ip)",
          len(db.arp_entries_for(did)) == len(first_pass),
          [dict(r) for r in db.arp_entries_for(did)])

    # ---- arp_locations, by either kind of needle
    locs = db.arp_locations("00:11:22:33:44:55")
    check("arp_locations by full MAC finds the stale row, flagged not present",
          len(locs) == 1 and locs[0]["ip"] == "10.0.0.5" and not locs[0]["present"],
          [dict(r) for r in locs])
    check("...and joins the interface description",
          locs and locs[0]["if_descr"] == "Vlan10", [dict(r) for r in locs])
    # "41-42-43", not "4142.43": digits-and-dots is an address by
    # looks_like_mac_search's own rule, and that rule is reused, not
    # re-decided, here.
    check("arp_locations by MAC prefix, any separator style",
          {r["ip"] for r in db.arp_locations("41-42-43")} == {"10.0.1.9"},
          [dict(r) for r in db.arp_locations("41-42-43")])
    check("arp_locations by IP is not read as a MAC",
          [r["mac"] for r in db.arp_locations("10.0.0.6")] == ["020000000066"],
          [dict(r) for r in db.arp_locations("10.0.0.6")])
    check("arp_locations by IP prefix",
          {r["ip"] for r in db.arp_locations("10.0.0")} == {"10.0.0.5", "10.0.0.6"},
          [dict(r) for r in db.arp_locations("10.0.0")])
    check("a needle that is neither returns nothing rather than everything",
          db.arp_locations("core-rtr") == [] and db.arp_locations("") == [])
    check("a MAC prefix shorter than four hex digits is not a search",
          db.arp_locations("00:1") == [])
    # The address side had no floor: "1" ran `ip LIKE '1%'`, which on a
    # real table is every 1.x, 10.x, 100.x and 1000:: row up to the limit.
    check("an address prefix under the floor is not a search either",
          ADDRESS_SEARCH_MIN_CHARS == 3
          and db.arp_locations("1") == [] and db.arp_locations("10") == []
          and db.arp_locations("fe") == [],
          [dict(r) for r in db.arp_locations("1")])
    check("...and the first prefix at the floor names a whole first octet",
          {r["ip"] for r in db.arp_locations("10.")}
          == {"10.0.0.5", "10.0.0.6", "10.0.1.9"},
          [dict(r) for r in db.arp_locations("10.")])
    ordered = db.arp_locations("10.0.0")
    check("present rows sort before stale ones",
          [bool(r["present"]) for r in ordered] == [True, False],
          [dict(r) for r in ordered])

    # ---- pruning: only rows past the retention window go. Two rows are
    # stale by now: 10.0.0.5 (hidden at walk 2) and 10.0.1.9 (the walk-3
    # store above carried 10.0.0.6 alone, so everything else aged).
    conn = sqlite3.connect(db.path)
    conn.execute("UPDATE arp_entries SET seen_ts = ? WHERE present = 0",
                 (time.time() - 8 * 86400,))
    conn.commit()
    conn.close()
    stale_before = sum(1 for r in db.arp_entries_for(did) if not r["present"])
    present_before = sum(1 for r in db.arp_entries_for(did) if r["present"])
    removed = db.prune_arp_entries(7 * 86400)
    after_rows = db.arp_entries_for(did)
    check("pruning removes exactly the stale rows past the window",
          removed == stale_before == 2 and len(after_rows) == present_before == 1
          and all(r["present"] for r in after_rows),
          (removed, stale_before, present_before, len(after_rows)))
    check("prune_arp_entries(0) is a no-op, like its MAC counterpart",
          db.prune_arp_entries(0) == 0)

    # ---- a walk that sees an empty cache ages everything; a failed one
    # (None) must never reach the store.
    db.replace_arp_entries(did, [], now=walk3_ts + 60.0)
    check("an empty walk marks every row absent (a genuine empty cache)",
          all(not r["present"] for r in db.arp_entries_for(did)),
          [dict(r) for r in db.arp_entries_for(did)])
    db.close()
finally:
    stub.kill()

# ----------------------------------------- 7. the interval gate and default
db = new_db("schedule")
gid = db.ensure_default_group()
did_default = db.add_device("10.0.0.70", name="default-rtr", group_id=gid)
poller = NodePoller(db)
device_default = db.device(did_default)
config_default = db.effective_config(device_default)
check("the shipped default is 0: off, so an upgrade walks nothing",
      config_default.get("arp_table_interval_s") == 0, config_default)
poller._maybe_walk_arp_table(device_default, config_default, time.time())
check("...and _maybe_walk_arp_table never schedules a due time for it",
      did_default not in poller._next_arp_walk, poller._next_arp_walk)
check("arp_walk_enabled_count sees no device opted in", db.arp_walk_enabled_count() == 0)

db.update_group(gid, arp_table_interval_s=900)
config_inherited = db.effective_config(db.device(did_default))
check("a profile value is inherited",
      config_inherited.get("arp_table_interval_s") == 900, config_inherited)
did_off = db.add_device("10.0.0.71", name="opted-out-rtr", group_id=gid,
                        arp_table_interval_s=0)
config_off = db.effective_config(db.device(did_off))
check("a device's explicit 0 beats the profile's 900",
      config_off.get("arp_table_interval_s") == 0, config_off)
check("arp_walk_enabled_count counts the profile's devices minus the opt-out",
      db.arp_walk_enabled_count() == 1, db.arp_walk_enabled_count())
now = time.time()
poller._maybe_walk_arp_table(db.device(did_default), config_inherited, now)
check("_maybe_walk_arp_table schedules a first walk within one interval",
      did_default in poller._next_arp_walk
      and now <= poller._next_arp_walk[did_default] <= now + 900,
      poller._next_arp_walk)
poller._maybe_walk_arp_table(db.device(did_off), config_off, now)
check("...and leaves the opted-out device alone",
      did_off not in poller._next_arp_walk, poller._next_arp_walk)
db.remove_device(did_default)
poller._forget_devices({did_off})
check("_forget_devices drops the removed device's schedule",
      did_default not in poller._next_arp_walk, poller._next_arp_walk)
db.close()

# ------------------------------------------------- 8. the API payloads
# The three read handlers, called directly against just enough of Service
# — test_mac_tables.py's own idiom for get_nodes_mac_search.
db = new_db("api")
gid = db.ensure_default_group()
did = db.add_device("10.0.0.80", name="api-rtr", group_id=gid)
db.replace_interfaces(did, [
    {"if_index": 7, "descr": "Vlan10", "phys_addr": "00:00:5e:00:01:0a"}])
seen1 = time.time()
db.replace_arp_entries(did, [
    {"if_index": 7, "ip": "10.0.10.5", "mac": "aa:bb:cc:dd:ee:ff", "entry_type": "dynamic"},
    {"if_index": 9, "ip": "10.0.20.5", "mac": "00:11:22:33:44:55", "entry_type": "static"},
], now=seen1)
seen2 = seen1 + 30.0
db.replace_arp_entries(did, [
    {"if_index": 9, "ip": "10.0.20.5", "mac": "00:11:22:33:44:55", "entry_type": "static"},
], now=seen2)   # the first row aged out of the cache: marked absent, kept
db.save_settings({**db.settings(), "mac_table_retention_days": 3.5})


class Svc:
    nodes_db = db
    node_poller = None
    nodes_settings = db.settings()


payload = api.get_nodes_arp_search(Svc, {"q": "AA-BB-CC-DD-EE-FF"}, None)
loc = payload["locations"][0] if payload["locations"] else {}
check("arp-search by MAC: the payload carries device, interface, ip, mac and type",
      len(payload["locations"]) == 1
      and loc.get("device_id") == did and loc.get("device_name") == "api-rtr"
      and loc.get("if_index") == 7 and loc.get("if_descr") == "Vlan10"
      and loc.get("ip") == "10.0.10.5" and loc.get("mac") == "aabbccddeeff"
      and loc.get("entry_type") == "dynamic", payload)
check("...and present=False with the seen_ts of the walk that last saw it",
      loc.get("present") is False and loc.get("seen_ts") == seen1
      and loc.get("first_seen_ts") == seen1, loc)
check("...and echoes the needle, retention_days and the enabled count",
      payload.get("needle") == "AA-BB-CC-DD-EE-FF"
      and payload.get("retention_days") == 3.5
      and payload.get("enabled_devices") == 0, payload)
by_ip = api.get_nodes_arp_search(Svc, {"q": "10.0.20"}, None)
check("arp-search by IP prefix, with the 'Interface N' fallback for an unknown ifIndex",
      [l["ip"] for l in by_ip["locations"]] == ["10.0.20.5"]
      and by_ip["locations"][0]["if_descr"] == "Interface 9"
      and by_ip["locations"][0]["present"] is True, by_ip)
check("arp-search refuses what arp_locations refuses, with an empty list",
      api.get_nodes_arp_search(Svc, {"q": "api-rtr"}, None)["locations"] == []
      and api.get_nodes_arp_search(Svc, {}, None)["locations"] == [])
check("...including a one-keystroke address prefix",
      api.get_nodes_arp_search(Svc, {"q": "1"}, None)["locations"] == []
      and api.get_nodes_arp_search(Svc, {"q": "10"}, None)["locations"] == [],
      api.get_nodes_arp_search(Svc, {"q": "1"}, None))


# One search used to be one query per hit on top of its own: device() for
# every row, two hundred and one statements for a short prefix. A second
# device's rows make the hits span devices, and the store is counted. It
# opts out of the walk so the profile's enabled count, checked below,
# stays what this section already says it is.
did2 = db.add_device("10.0.0.81", name="api-rtr-2", group_id=gid,
                     arp_table_interval_s=0)
db.replace_arp_entries(did2, [
    {"if_index": 3, "ip": "10.0.30.5", "mac": "00:11:22:33:44:66", "entry_type": "dynamic"},
    {"if_index": 3, "ip": "10.0.30.6", "mac": "00:11:22:33:44:77", "entry_type": "dynamic"},
], now=seen2)


class CountingDb:
    """nodes_db with the per-device and the batched read counted."""

    def __init__(self, real):
        self._real = real
        self.calls = {"device": 0, "devices_by_ids": 0}

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if name in self.calls:
            def counted(*args, **kwargs):
                self.calls[name] += 1
                return attr(*args, **kwargs)
            return counted
        return attr


class CountingSvc(Svc):
    nodes_db = CountingDb(db)


spanning = api.get_nodes_arp_search(CountingSvc, {"q": "10.0"}, None)
check("arp-search across two devices names each hit's own device",
      {(l["ip"], l["device_name"]) for l in spanning["locations"]}
      == {("10.0.10.5", "api-rtr"), ("10.0.20.5", "api-rtr"),
          ("10.0.30.5", "api-rtr-2"), ("10.0.30.6", "api-rtr-2")}, spanning)
check("...from one batched device read, not one query per row",
      CountingSvc.nodes_db.calls == {"device": 0, "devices_by_ids": 1},
      CountingSvc.nodes_db.calls)
CountingSvc.nodes_db.calls = {"device": 0, "devices_by_ids": 0}
by_mac = api.get_nodes_mac_search(CountingSvc, {"q": "00:11:22:33:44"}, None)
check("the MAC search, same loop, is batched the same way",
      by_mac["locations"] == []   # no forwarding-table rows here, only ARP
      and CountingSvc.nodes_db.calls == {"device": 0, "devices_by_ids": 1},
      (by_mac, CountingSvc.nodes_db.calls))

table = api.get_nodes_device_arp(Svc, {}, None, did)
check("device arp: enabled is False and interval_s 0 for a device nobody opted in",
      table.get("enabled") is False and table.get("interval_s") == 0, table)
check("...but the stored rows still come back, labelled by interface, if_index-ordered",
      [(e["ip"], e["local_port"], e["present"]) for e in table["entries"]]
      == [("10.0.10.5", "Vlan10", False), ("10.0.20.5", "if 9", True)], table)
db.update_group(gid, arp_table_interval_s=900)
Svc.nodes_settings = db.settings()
table = api.get_nodes_device_arp(Svc, {}, None, did)
check("device arp: enabled once the profile sets an interval (the device stays blank)",
      table.get("enabled") is True and table.get("interval_s") == 900
      and db.device(did)["arp_table_interval_s"] is None, table)
check("arp-search's enabled count follows",
      api.get_nodes_arp_search(Svc, {"q": "10.0"}, None)["enabled_devices"] == 1)

export = api.get_nodes_device_arp_export(Svc, {}, None, did)
# The BOM _csv_text leads with (for Excel) is not a column name.
lines = export["csv"].lstrip("\ufeff").splitlines()
check("device arp export: the header names the columns in order",
      lines and lines[0] == "if_index,local_port,ip,mac,entry_type,present,seen_ts,first_seen_ts",
      lines[:1])
check("...and a row carries the same fields",
      export["count"] == 2 and len(lines) == 3
      and lines[1].startswith("7,Vlan10,10.0.10.5,aabbccddeeff,dynamic,False,")
      and lines[2].startswith("9,if 9,10.0.20.5,001122334455,static,True,"), lines)
try:
    api.get_nodes_device_arp(Svc, {}, None, did + 1000)
    check("device arp for a device that does not exist is refused", False)
except Exception as error:   # api._require's own NotFound
    check("device arp for a device that does not exist is refused", True, error)
db.close()

# ------------------------------- 9. the fallback gate is "empty", not "failed"
# read_device_arp_table promises that a walk stopped by a timeout or an
# error returns None from EITHER table rather than falling through to the
# successor table; the code checked "no rows" before "complete", so a
# timeout on the first GETBULK (an empty result too) read as a clean empty
# legacy table and walked ipNetToPhysicalTable instead. No stub can time
# out on demand, so the column walk is replaced on the instance with one
# that answers in _walk_column_detail's own shapes and records what it
# was asked for.
db = new_db("gate")
did = device_against(db, 0, name="gate-rtr")
log = CapturingLog()
poller = NodePoller(db, log=log)
LEGACY, MODERN = (nodeoids.IP_NET_TO_MEDIA_PHYS_ADDRESS,
                  nodeoids.IP_NET_TO_PHYSICAL_PHYS_ADDRESS)
MODERN_ROWS = {"1.1.4.10.0.0.5": bytes.fromhex("001122334455")}
LEGACY_ROWS = {"1.10.0.0.6": bytes.fromhex("aabbccddeeff")}
asked = []


def scripted(answers):
    """A _walk_column_detail answering each phys-address column from
    `answers` — (rows, complete, reason) — and refusing any other OID."""
    def walk(device, config, base_oid, **kwargs):
        asked.append(base_oid)
        return answers[base_oid]
    return walk


poller._walk_column = lambda device, config, base_oid, **kwargs: {}
timeout = "timed out (table walk cut short after 0 row(s))"

asked.clear()
poller._walk_column_detail = scripted({LEGACY: ({}, False, timeout),
                                       MODERN: (MODERN_ROWS, True, "")})
entries, status, detail = poller._read_arp_table_detail(did)
check("a timeout on the legacy table's first request is None, not a fallback",
      entries is None and status == poller._ARP_INCOMPLETE
      and detail.startswith("ipNetToMediaTable:") and "timed out" in detail,
      (entries, status, detail))
check("...and the successor table was never asked", asked == [LEGACY], asked)

asked.clear()
poller._walk_column_detail = scripted({LEGACY: ({}, False, "SNMP error: genErr"),
                                       MODERN: (MODERN_ROWS, True, "")})
entries, status, detail = poller._read_arp_table_detail(did)
check("an SNMP error on it is None the same way",
      entries is None and status == poller._ARP_INCOMPLETE and asked == [LEGACY],
      (entries, status, detail, asked))

asked.clear()
poller._walk_column_detail = scripted({LEGACY: ({}, True, ""),
                                       MODERN: (MODERN_ROWS, True, "")})
entries, status, detail = poller._read_arp_table_detail(did)
check("a genuinely complete, genuinely empty legacy walk is the fallback's case",
      entries is not None and status == poller._ARP_OK
      and [e["ip"] for e in entries] == ["10.0.0.5"] and asked == [LEGACY, MODERN],
      (entries, status, detail, asked))

asked.clear()
poller._walk_column_detail = scripted({LEGACY: ({}, True, ""),
                                       MODERN: ({}, False, timeout)})
entries, status, detail = poller._read_arp_table_detail(did)
check("a timeout on the successor table is None too, not 'answers neither'",
      entries is None and status == poller._ARP_INCOMPLETE
      and detail.startswith("ipNetToPhysicalTable:"), (entries, status, detail))

asked.clear()
poller._walk_column_detail = scripted({LEGACY: ({}, True, ""),
                                       MODERN: ({}, True, "")})
entries, status, detail = poller._read_arp_table_detail(did)
check("both complete and empty is still 'answers neither table'",
      entries is None and status == poller._ARP_UNANSWERED, (entries, status, detail))

# Storage and the log, across the cycles a transient timeout produces: a
# modern agent answering both tables must not alternate sources.
poller._walk_column_detail = scripted({LEGACY: (LEGACY_ROWS, True, ""),
                                       MODERN: (MODERN_ROWS, True, "")})
poller._arp_running.add(did)
poller._run_arp_table(did)
first = {r["ip"]: dict(r) for r in db.arp_entries_for(did)}
poller._walk_column_detail = scripted({LEGACY: ({}, False, timeout),
                                       MODERN: (MODERN_ROWS, True, "")})
poller._arp_running.add(did)
poller._run_arp_table(did)
second = {r["ip"]: dict(r) for r in db.arp_entries_for(did)}
check("a cycle whose legacy walk times out leaves the stored table exactly alone",
      set(first) == {"10.0.0.6"} and second == first, (first, second))
said = [m for c, m in log.lines]
check("...and the log says the walk was cut short, naming the timeout",
      any("cut short" in m and "timed out" in m for m in said)
      and not any("neither" in m for m in said), said)
check("...without counting the failed walk", poller.counters["arp_walks"] == 1,
      poller.counters)
db.close()

# ---------------------- 10. the sweep and the setting, through the real paths
# Two wires the suites above never pulled. prune_arp_entries has a test
# (section 6) and so does the column (section 7), and both would stay
# green with the call dropped from Service.run_maintenance or the key
# dropped from the routes' allow-lists — _pick discards an unknown key
# without a word. So: the real maintenance sweep, and the real handlers,
# on a real Service, the way test_lldp_topology.py drives prune_neighbors.
DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")
svc_dir = f"{TMP}/service"
import os
os.makedirs(svc_dir, exist_ok=True)
service = Service(*[os.path.join(svc_dir, name + ".db") for name in DB_NAMES])
try:
    nodes = service.nodes_db
    gid = nodes.ensure_default_group()
    stale = nodes.add_device("10.0.0.90", name="stale-rtr", group_id=gid)
    fresh = nodes.add_device("10.0.0.91", name="fresh-rtr", group_id=gid)
    for did_ in (stale, fresh):
        nodes.replace_arp_entries(did_, [
            {"if_index": 1, "ip": "10.0.40.5", "mac": "00:11:22:33:44:88",
             "entry_type": "dynamic"}], now=time.time())
    retention_days = float(service.nodes_settings.get("mac_table_retention_days", 7))
    conn = sqlite3.connect(nodes.path)
    conn.execute("UPDATE arp_entries SET seen_ts = ? WHERE device_id = ?",
                 (time.time() - (retention_days + 1) * 86400, stale))
    conn.commit()
    conn.close()
    service.run_maintenance(force=True)
    check("run_maintenance prunes a stale device's ARP rows",
          nodes.arp_entries_for(stale) == [], [dict(r) for r in nodes.arp_entries_for(stale)])
    check("...and leaves a freshly-walked device's rows alone",
          len(nodes.arp_entries_for(fresh)) == 1, [dict(r) for r in nodes.arp_entries_for(fresh)])

    # The setting, written and read back through the handlers only.
    api.put_nodes_group(service, {}, {"arp_table_interval_s": 900}, gid)
    groups = {g["id"]: g for g in api.get_nodes_groups(service, {}, None)["groups"]}
    check("PUT profile sets arp_table_interval_s and GET profiles echoes it",
          groups.get(gid, {}).get("arp_table_interval_s") == 900, groups.get(gid))
    check("...and a device on the profile inherits it, as the ARP route reports",
          api.get_nodes_device_arp(service, {}, None, fresh)["interval_s"] == 900
          and api.get_nodes_device(service, {}, None, fresh)["device"]["arp_table_interval_s"] is None,
          api.get_nodes_device_arp(service, {}, None, fresh))
    api.put_nodes_device(service, {}, {"arp_table_interval_s": 300}, fresh)
    device = api.get_nodes_device(service, {}, None, fresh)["device"]
    check("PUT device sets its own arp_table_interval_s and GET device echoes it",
          device.get("arp_table_interval_s") == 300
          and device["effective_config"].get("arp_table_interval_s") == 300
          and api.get_nodes_device_arp(service, {}, None, fresh)["interval_s"] == 300,
          device)
    api.put_nodes_device(service, {}, {"arp_table_interval_s": 0}, fresh)
    check("...and an explicit 0 through PUT opts the device out of the profile's 900",
          api.get_nodes_device_arp(service, {}, None, fresh) | {"entries": []}
          == {"entries": [], "enabled": False, "interval_s": 0},
          api.get_nodes_device_arp(service, {}, None, fresh))
    posted = api.post_nodes_device(service, {}, {
        "ip": "10.0.0.92", "name": "posted-rtr", "group_id": gid,
        "arp_table_interval_s": 600})["id"]
    check("POST device carries arp_table_interval_s onto the new row",
          api.get_nodes_device(service, {}, None, posted)["device"]["arp_table_interval_s"] == 600,
          api.get_nodes_device(service, {}, None, posted))
    new_gid = api.post_nodes_group(service, {}, {"name": "posted-profile",
                                                 "arp_table_interval_s": 1200})["id"]
    groups = {g["id"]: g for g in api.get_nodes_groups(service, {}, None)["groups"]}
    check("POST profile carries it too",
          groups.get(new_gid, {}).get("arp_table_interval_s") == 1200, groups.get(new_gid))
finally:
    service.shutdown()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

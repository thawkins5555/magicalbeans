"""GETBULK table walks and MAC-table history: request counts, the tooBig
fallback, the v1-stays-GETNEXT rule, the row cap, present/absent history
across a walk, and the API payload's history fields — plan 4.34.0
Workstream B."""
import socket
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("mac_tables_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.web import api


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


def device_against(db: NodesDatabase, port: int, *, version: int,
                   name: str = "sw") -> int:
    """A device polling the stub at `port`, v1 (0) or v2c (1), one socket's
    worth of retries so a wrong branch fails fast rather than slowly."""
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=version, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    did = db.add_device("127.0.0.1", name=name, group_id=gid)
    db.seed_identity(did, sys_descr="", sys_name=name,
                     sys_object_id="1.3.6.1.4.1.9.1.1208", vendor="cisco")
    return did


FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------- 1. request counts
stub, port = spawn_stub("stub_agent_fdb.py", "big")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("counts")
    did = device_against(db, port, version=1, name="big-sw")
    poller = NodePoller(db)

    reset_count(port)
    entries = poller.read_device_mac_table(did)
    getbulk_requests = request_count(port)
    check("GETBULK: 90-row FDB + 6 ports returns every row",
          entries is not None and len(entries) == 90, len(entries) if entries else entries)
    check("GETBULK: costs at most 6 requests (was ~100 under GETNEXT)",
          getbulk_requests <= 6, getbulk_requests)
    print(f"  90-row FDB + 6 ports: GETBULK cost {getbulk_requests} request(s)")

    db.save_settings({**db.settings(), "snmp_bulk_max_repetitions": 0})
    reset_count(port)
    entries_fallback = poller.read_device_mac_table(did)
    getnext_requests = request_count(port)
    check("snmp_bulk_max_repetitions=0 falls back to GETNEXT, same rows",
          entries_fallback is not None and len(entries_fallback) == 90,
          len(entries_fallback) if entries_fallback else entries_fallback)
    check("...and costs roughly one request per row (the pre-4.34 shape)",
          getnext_requests >= 90, getnext_requests)
    print(f"  90-row FDB + 6 ports: GETNEXT cost {getnext_requests} request(s)")
    check("GETBULK is the cheaper path by a wide margin",
          getbulk_requests * 5 < getnext_requests,
          (getbulk_requests, getnext_requests))
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------ 2. tooBig fallback
stub, port = spawn_stub("stub_agent_fdb.py", "bulk-toobig")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("toobig")
    did = device_against(db, port, version=1, name="toobig-sw")
    poller = NodePoller(db)
    reset_count(port)
    entries = poller.read_device_mac_table(did)
    check("a tooBig reply is survived: every row still comes back",
          entries is not None and len(entries) == 90, len(entries) if entries else entries)
    print(f"  tooBig fallback: {request_count(port)} request(s), "
          f"{len(entries) if entries else 0} row(s)")
    db.close()
finally:
    stub.kill()

# --------------------------------------------------- 3. v1 stays on GETNEXT
stub, port = spawn_stub("stub_agent_fdb.py", "big")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("v1walk")
    did = device_against(db, port, version=0, name="v1-sw")
    poller = NodePoller(db)
    reset_count(port)
    entries = poller.read_device_mac_table(did)
    v1_requests = request_count(port)
    check("a v1 device gets every row too",
          entries is not None and len(entries) == 90, len(entries) if entries else entries)
    check("...but pays the GETNEXT-per-row cost: GETBULK does not exist in v1",
          v1_requests >= 90, v1_requests)
    db.close()
finally:
    stub.kill()

# ----------------------------------------------------- 4. the row cap
stub, port = spawn_stub("stub_agent_fdb.py", "big")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cap")
    did = device_against(db, port, version=1, name="cap-sw")
    db.save_settings({**db.settings(), "snmp_walk_max_rows": 10})
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)
    values = poller._walk_column(device, config, poller._DOT1D_FDB_PORT)
    check("snmp_walk_max_rows caps a single _walk_column call",
          len(values) == 10, len(values))
    db.close()
finally:
    stub.kill()

# --------------------------------------------- 5. history: present/absent
stub, port = spawn_stub("stub_agent_fdb.py", "dot1q")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("history")
    did = device_against(db, port, version=1, name="hist-sw")
    poller = NodePoller(db)

    walk1_ts = time.time()
    entries = poller.read_device_mac_table(did)
    stored = db.replace_mac_entries(did, entries, now=walk1_ts)
    check("first walk stores every row, all present",
          stored == len(entries)
          and all(r["present"] for r in db.mac_entries_for(did)),
          db.mac_entries_for(did))
    first_pass = {(r["mac"], r["vlan"], r["if_index"]): dict(r)
                  for r in db.mac_entries_for(did)}

    stub_stat(port, b"HIDE 00:11:22:33:44:55")
    entries2 = poller.read_device_mac_table(did)
    check("the hidden MAC no longer walks",
          all(e["mac"] != "00:11:22:33:44:55" for e in entries2), entries2)
    walk2_ts = walk1_ts + 60.0
    stored2 = db.replace_mac_entries(did, entries2, now=walk2_ts)
    rows = {(r["mac"], r["vlan"], r["if_index"]): dict(r)
           for r in db.mac_entries_for(did)}

    check("the row count is unchanged — nothing is deleted, just marked",
          len(rows) == len(first_pass), (len(rows), len(first_pass)))
    absent = {k: r for k, r in rows.items() if k[0] == "001122334455"}
    present_now = {k: r for k, r in rows.items() if k[0] != "001122334455"}
    check("the vanished MAC's row(s) are present=0",
          absent and all(not r["present"] for r in absent.values()), absent)
    check("...with the OLD seen_ts kept, not refreshed",
          all(r["seen_ts"] == first_pass[k]["seen_ts"] for k, r in absent.items()),
          absent)
    check("...and first_seen_ts untouched",
          all(r["first_seen_ts"] == first_pass[k]["first_seen_ts"]
              for k, r in absent.items()), absent)
    check("rows still present got a fresh seen_ts",
          present_now and all(r["seen_ts"] == walk2_ts
                              for r in present_now.values()), present_now)
    check("...and kept their original first_seen_ts",
          all(r["first_seen_ts"] == first_pass[k]["first_seen_ts"]
              for k, r in present_now.items()), present_now)

    locs = db.mac_locations("00:11:22:33:44:55")
    check("mac_locations still finds the stale MAC, flagged not present",
          locs and all(not l["present"] for l in locs), locs)

    # present rows sort before stale ones, for a prefix shared by one of
    # each: two synthetic addresses under the same OUI, one walked away
    # and one still there.
    order_ts = walk2_ts + 1.0
    db.replace_mac_entries(did, [
        {"if_index": 9, "mac": "00:1a:2b:00:00:01", "vlan": ""},
        {"if_index": 9, "mac": "00:1a:2b:00:00:02", "vlan": ""},
    ], now=order_ts)
    db.replace_mac_entries(did, [
        {"if_index": 9, "mac": "00:1a:2b:00:00:02", "vlan": ""},
    ], now=order_ts + 1.0)
    ordered = db.mac_locations("001a2b")
    check("mac_locations orders present rows before stale ones",
          len(ordered) == 2 and ordered[0]["present"] == 1
          and not ordered[1]["present"], [dict(r) for r in ordered])

    # A MAC moving port: stale on the old port, present on the new one.
    walk3_ts = walk2_ts + 60.0
    db.replace_mac_entries(did, [{"if_index": 1, "mac": "aa:bb:cc:dd:ee:ff",
                                  "vlan": "10"}], now=walk3_ts)
    moved = db.mac_entries_for(did)
    moved_mac = [r for r in moved if r["mac"] == "aabbccddeeff"]
    check("a MAC that moved port leaves one stale row and one present row",
          len(moved_mac) == 2
          and sum(1 for r in moved_mac if r["present"]) == 1
          and sum(1 for r in moved_mac if not r["present"]) == 1,
          [dict(r) for r in moved_mac])

    # prune_mac_entries removes only rows past the retention window — age
    # every currently-stale row past it and leave the present one alone.
    import sqlite3
    stale_before_ids = [dict(r) for r in db.mac_entries_for(did) if not r["present"]]
    conn = sqlite3.connect(db.path)
    conn.execute("UPDATE mac_entries SET seen_ts = ? WHERE present = 0",
                 (time.time() - 8 * 86400,))
    conn.commit()
    conn.close()
    stale_before = len(stale_before_ids)
    present_before = sum(1 for r in db.mac_entries_for(did) if r["present"])
    removed = db.prune_mac_entries(7 * 86400)
    after_rows = db.mac_entries_for(did)
    check("pruning removes exactly the stale rows past the window",
          removed == stale_before and len(after_rows) == present_before
          and all(r["present"] for r in after_rows),
          (removed, stale_before, present_before, len(after_rows)))

    db.close()
finally:
    stub.kill()

# ---------------------------------------------------- 6. the API payload
db = new_db("api")
did = db.add_device("10.0.0.9", name="api-sw", group_id=db.ensure_default_group())
seen1 = time.time()
db.replace_mac_entries(did, [{"if_index": 1, "mac": "aa:bb:cc:dd:ee:ff", "vlan": "10"}],
                       now=seen1)
seen2 = seen1 + 30.0
db.replace_mac_entries(did, [], now=seen2)   # the walk saw nothing this time: mark absent
db.save_settings({**db.settings(), "mac_table_retention_days": 3.5})


class Svc:
    nodes_db = db
    node_poller = None
    nodes_settings = db.settings()


payload = api.get_nodes_mac_search(Svc, {"q": "aa:bb:cc:dd:ee:ff"}, None)
loc = payload["locations"][0] if payload["locations"] else {}
check("the payload carries present",
      "present" in loc and loc["present"] is False, loc)
check("the payload carries seen_ts (the walk that last actually saw it,"
      " not the one that marked it absent)",
      "seen_ts" in loc and loc["seen_ts"] == seen1, loc)
check("the payload carries first_seen_ts",
      "first_seen_ts" in loc and loc["first_seen_ts"] == seen1, loc)
check("the payload carries retention_days from settings",
      payload.get("retention_days") == 3.5, payload)
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

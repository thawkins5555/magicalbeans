"""Every address a device answers on is searchable, and says which device.

merge_devices already keeps the folded-away row's IP as an alias of the
survivor, but the Nodes search read only the devices table's own columns, so
typing that address answered "nothing found" and the merge looked like it had
thrown one of the two addresses away. Covers the search itself (devices() and
devices_count() asked the same question so a page and its total cannot
disagree, and no device counted twice when both a column and an alias match),
the bulk read the device list uses to carry the addresses, and what the
operator actually sees: the addresses on the list JSON and in the CSV export,
through a real Service + WebServer over loopback like test_csv_export.py.
"""
import csv
import http.client
import io
import json
import os
from urllib.parse import urlencode

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.nodesdb import NodesDatabase
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("device_address_search_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def names(rows):
    return sorted(r["name"] for r in rows)


# ------------------------------------------------- the search, at the database
print("1. searching for an address that belongs to a merged device")
db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
winner_id = db.add_device("10.20.0.1", "core-a")
loser_id = db.add_device("10.20.0.2", "core-a-dup")
edge_id = db.add_device("10.20.0.3", "edge-b")
db.record_device_addresses(winner_id, ["10.20.9.9"], "ipAddrTable")

check("an alias address finds its device before any merge",
      names(db.devices(text="10.20.9.9")) == ["core-a"],
      names(db.devices(text="10.20.9.9")))
check("the second device is still found by its own address",
      names(db.devices(text="10.20.0.2")) == ["core-a-dup"],
      names(db.devices(text="10.20.0.2")))

db.merge_devices(loser_id, winner_id)

check("after the merge the folded-away address finds the survivor",
      names(db.devices(text="10.20.0.2")) == ["core-a"],
      names(db.devices(text="10.20.0.2")))
check("...and devices_count agrees with it",
      db.devices_count(text="10.20.0.2") == len(db.devices(text="10.20.0.2")),
      (db.devices_count(text="10.20.0.2"), len(db.devices(text="10.20.0.2"))))
check("the survivor's own address still finds it",
      names(db.devices(text="10.20.0.1")) == ["core-a"],
      names(db.devices(text="10.20.0.1")))
check("an address no device has ever answered on finds nothing",
      db.devices(text="10.20.0.99") == [], names(db.devices(text="10.20.0.99")))

# A device whose primary column AND an alias both match the same term is one
# device, not two: the clause asks a subquery, not a join.
both = db.devices(text="10.20.0.")
check("a term matching both a column and an alias returns each device once",
      names(both) == ["core-a", "edge-b"], names(both))
check("...and the count matches, so paging cannot disagree with the total",
      db.devices_count(text="10.20.0.") == len(both),
      (db.devices_count(text="10.20.0."), len(both)))
first = db.devices(text="10.20.0.", limit=1, offset=0)
check("a limited page of the same search is a page of that same set",
      len(first) == 1 and first[0]["name"] == names(both)[0],
      [r["name"] for r in first])

# A MAC search still layers with it rather than replacing it.
db._conn.execute(
    "INSERT INTO mac_entries(device_id, if_index, mac, seen_ts, present)"
    " VALUES (?, 1, 'aabbccddeeff', ?, 1)", (edge_id, 1e9))
db._conn.commit()
check("MAC-table search is unchanged by the added address branch",
      names(db.devices(text="aabbccddeeff")) == ["edge-b"],
      names(db.devices(text="aabbccddeeff")))

print("2. the bulk address read")
bulk = db.addresses_for_devices([winner_id, edge_id, winner_id])
check("one call answers for every device asked about",
      sorted(r["ip"] for r in bulk.get(winner_id, ())) == ["10.20.0.2", "10.20.9.9"],
      {k: [r["ip"] for r in v] for k, v in bulk.items()})
check("a device with no alias is simply absent", edge_id not in bulk, list(bulk))
check("no ids asked, no query run", db.addresses_for_devices([]) == {})
check("it says the same as the per-device read",
      [r["ip"] for r in bulk[winner_id]]
      == [r["ip"] for r in db.device_addresses(winner_id)],
      [r["ip"] for r in db.device_addresses(winner_id)])
db.close()

# ---------------------------------------------------- what the operator sees
service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "web-nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    data = None
    if method == "GET":
        if body:
            path = f"{path}?{urlencode(body)}"
    else:
        data = json.dumps(body).encode() if body is not None else None
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": username, "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


def parse_csv(text):
    if text.startswith("﻿"):
        text = text[1:]
    return list(csv.reader(io.StringIO(text)))


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    print("3. the device list carries every address")
    status, keep = call("POST", "/api/nodes/devices",
                        {"ip": "10.30.0.1", "name": "dist-a"}, token=admin)
    check("setup: surviving device created", status == 200, (status, keep))
    status, fold = call("POST", "/api/nodes/devices",
                        {"ip": "10.30.0.2", "name": "dist-a-dup"}, token=admin)
    check("setup: duplicate device created", status == 200, (status, fold))
    service.nodes_db.record_device_addresses(keep["id"], ["10.30.9.9"], "ipAddrTable")
    status, merged = call("POST", f"/api/nodes/devices/{fold['id']}/merge",
                          {"into": keep["id"]}, token=admin)
    check("setup: the merge answers with the survivor",
          status == 200 and merged.get("device_id") == keep["id"], (status, merged))

    status, listed = call("GET", "/api/nodes/devices", {"q": "10.30.0.2"}, token=admin)
    check("searching the list for the folded-away address answers 200",
          status == 200, (status, listed))
    check("...with the surviving device, once",
          [d["ip"] for d in listed.get("devices", [])] == ["10.30.0.1"], listed)
    check("...and a total that agrees with the rows returned",
          listed.get("total") == len(listed.get("devices", [])), listed)
    found = listed["devices"][0]
    check("the row lists every address the device answers on",
          sorted(a["ip"] for a in found["addresses"])
          == ["10.30.0.1", "10.30.0.2", "10.30.9.9"], found.get("addresses"))
    check("...with its configured address marked as the primary one",
          [a["ip"] for a in found["addresses"] if a["primary"]] == ["10.30.0.1"],
          found.get("addresses"))

    status, paged = call("GET", "/api/nodes/devices",
                         {"q": "10.30.0.2", "limit": 1, "offset": 0}, token=admin)
    check("a paged read of the same search agrees on the total",
          status == 200 and paged.get("total") == 1
          and [d["ip"] for d in paged.get("devices", [])] == ["10.30.0.1"],
          (status, paged))

    print("4. the CSV export names them too")
    status, payload = call("GET", "/api/nodes/devices/export.csv",
                           {"q": "10.30.0.2"}, token=admin)
    check("the export honours the same search", status == 200 and payload.get("count") == 1,
          (status, payload))
    rows = parse_csv(payload["csv"])
    header = rows[0]
    check("the export has an addresses column", "addresses" in header, header)
    cell = rows[1][header.index("addresses")]
    check("...listing every address of the merged device",
          all(ip in cell for ip in ("10.30.0.1", "10.30.0.2", "10.30.9.9")), cell)
    check("...and the ip column still holds the configured address alone",
          rows[1][header.index("ip")] == "10.30.0.1", rows[1])

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")

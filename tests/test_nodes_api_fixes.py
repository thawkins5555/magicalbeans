"""Nodes API contracts a 5.9.1 review found broken, each pinned by the
request that gave the wrong answer: the duplicates route reads one page and
one batch of device rows rather than an unclamped list and two queries per
pair; applying a batch of upstream suggestions is one read, not three per
assignment; the three device sub-routes that skipped their existence check
answer 400 for an unknown id like every sibling; a MIB object's OID must be
dotted ASCII decimal before it is stored; and the projections the browser
asks for (`?if_index=` on a port table, `?fields=index`/`?fields=list` on
the device list) return the same shape with less of it.

Real `Service` and `WebServer` over loopback HTTP, because the route table
and the permission gate sit between the socket and the handler.
"""
import http.client
import json
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer
from netpath.web.api.nodes import _DEVICE_LIST_FIELDS, _device_json

TMPDIR = _paths.tmpdir("nodes_api_fixes_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"), initial_admin_password="admin")
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=60)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path,
                 body=json.dumps(body).encode() if body is not None else None,
                 headers=headers)
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
                 body=json.dumps({"username": username,
                                  "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


class Counter:
    """Counts calls to one store method, passing everything through."""

    def __init__(self, obj, name):
        self.obj, self.name, self.n = obj, name, 0
        self.real = getattr(obj, name)

    def __enter__(self):
        self.n = 0
        setattr(self.obj, self.name, self._counted)
        return self

    def __exit__(self, *exc):
        setattr(self.obj, self.name, self.real)

    def _counted(self, *a, **kw):
        self.n += 1
        return self.real(*a, **kw)


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    group_id = service.nodes_db.ensure_default_group()

    # ------------------------------------------- 1. /api/nodes/duplicates
    #
    # 70 devices reporting the same sys_name is 2,415 candidate pairs — a
    # fresh vendor batch or a templated hostname, the case the feature
    # exists to find.
    dup_ids = []
    for n in range(1, 71):
        device_id = service.nodes_db.add_device(f"203.0.113.{n}", name=f"dup{n}",
                                                group_id=group_id)
        service.nodes_db.seed_identity(device_id, sys_name="SWITCH")
        dup_ids.append(device_id)

    with Counter(service.nodes_db, "device") as per_device:
        status, payload = call("GET", "/api/nodes/duplicates?limit=1000000",
                               token=admin)
    pairs = payload.get("duplicates", []) if status == 200 else []
    check("an unclamped ?limit on /api/nodes/duplicates is capped",
          status == 200 and 0 < len(pairs) <= 2000, (status, len(pairs)))
    check("...and the page's device rows are read in one batch, not two "
          "queries per pair", per_device.n == 0, per_device.n)

    status, payload = call("GET", "/api/nodes/duplicates", token=admin)
    check("the default page is unchanged at 200 pairs",
          status == 200 and len(payload["duplicates"]) == 200,
          (status, len(payload.get("duplicates", []))))
    check("...and every pair still carries both names and both addresses",
          all(p.get("a_name") and p.get("b_name") and p.get("a_ip")
              and p.get("b_ip") for p in payload["duplicates"]))

    # ------------------------------ 2. upstream-suggestions apply is batched
    core = service.nodes_db.add_device("203.0.113.200", name="core",
                                       group_id=group_id)
    assignments = [{"device_id": d, "upstream_id": core} for d in dup_ids[:50]]
    with Counter(service.nodes_db, "device") as per_device:
        status, payload = call("POST", "/api/nodes/upstream-suggestions/apply",
                               {"assignments": assignments}, token=admin)
    check("a batch of upstream assignments applies", status == 200
          and payload.get("updated") == 50, (status, payload))
    check("...in one read of the devices it names, not three per assignment",
          per_device.n == 0, per_device.n)
    check("...and every assignment really landed",
          all(service.nodes_db.device(d)["upstream_id"] == core
              for d in dup_ids[:50]))

    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply",
                           {"assignments": [{"device_id": dup_ids[0],
                                             "upstream_id": 999999}]},
                           token=admin)
    check("an upstream that does not exist is still refused", status == 400,
          (status, payload))
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply",
                           {"assignments": [{"device_id": core,
                                             "upstream_id": dup_ids[0]}]},
                           token=admin)
    check("...and so is a batch that would close a cycle", status == 400
          and "cycle" in str(payload.get("error", "")).lower(), (status, payload))

    # ------------------------------------ 3. an unknown device id is a 400
    for method, path in [("POST", "/api/nodes/devices/999999/identify"),
                         ("DELETE", "/api/nodes/devices/999999/identify"),
                         ("DELETE", "/api/nodes/devices/999999/oid-walk"),
                         ("GET", "/api/nodes/devices/999999/oid-walk")]:
        status, payload = call(method, path, token=admin)
        check(f"{method} {path.split('/')[-1]} on an unknown device is a 404, "
              f"not a 200 naming a job that never ran", status == 404,
              (method, path, status, payload))

    # --------------------------------------- 4. a MIB object's OID is numeric
    mib_id = service.nodes_db.add_mib_file("TEST-MIB.mib", "TEST-MIB", 1, [], "")
    service.nodes_db.replace_mib_objects(mib_id, [
        {"name": "testObject", "oid": "1.3.6.1.4.1.99.1"}])
    obj_id = service.nodes_db.mib_objects(mib_id)[0]["id"]

    for bad, why in [("1.3.6.1.4.1.-7", "a negative arc spins the BER encoder"),
                     ("1.3.6.1.4.1.²", "a superscript digit int() refuses"),
                     ("1.3.6.1.4.1.٣", "an Arabic-Indic digit"),
                     ("enterprises.9", "a name rather than a number"),
                     ("", "nothing at all")]:
        status, payload = call("PUT", f"/api/nodes/mibs/{mib_id}/objects/{obj_id}",
                               {"oid": bad}, token=admin)
        check(f"a MIB object OID with {why} is refused", status == 400,
              (bad, status, payload))
    check("...and none of them was stored",
          service.nodes_db.mib_objects(mib_id)[0]["oid"] == "1.3.6.1.4.1.99.1",
          service.nodes_db.mib_objects(mib_id)[0]["oid"])

    status, payload = call("PUT", f"/api/nodes/mibs/{mib_id}/objects/{obj_id}",
                           {"oid": "1.3.6.1.4.1.99.2"}, token=admin)
    check("an ordinary dotted OID is still accepted and stored",
          status == 200
          and service.nodes_db.mib_objects(mib_id)[0]["oid"] == "1.3.6.1.4.1.99.2",
          (status, payload))

    # -------------------------- 5. GET .../interfaces?if_index=<n> (contract)
    ports = service.nodes_db.add_device("203.0.113.201", name="ports",
                                        group_id=group_id)
    service.nodes_db.replace_interfaces(ports, [
        {"if_index": n, "descr": f"GigabitEthernet0/{n}", "alias": f"port {n}",
         "admin_status": "up", "oper_status": "up" if n % 2 else "down"}
        for n in range(1, 41)])

    status, whole = call("GET", f"/api/nodes/devices/{ports}/interfaces",
                         token=admin)
    check("the whole port table is unchanged", status == 200
          and len(whole["interfaces"]) == 40, (status, len(whole.get("interfaces", []))))
    status, one = call("GET", f"/api/nodes/devices/{ports}/interfaces?if_index=7",
                       token=admin)
    check("?if_index=<n> returns just that interface", status == 200
          and len(one["interfaces"]) == 1
          and one["interfaces"][0]["if_index"] == 7, (status, one))
    check("...with the same shape the whole table uses",
          one["interfaces"][0] == [i for i in whole["interfaces"]
                                   if i["if_index"] == 7][0]
          and set(one) == set(whole), (sorted(one), sorted(whole)))
    status, none = call("GET", f"/api/nodes/devices/{ports}/interfaces?if_index=999",
                        token=admin)
    check("an if_index the device does not have is an empty list, not an error",
          status == 200 and none["interfaces"] == [], (status, none))

    # ----------------- 5b. PUT .../interfaces/<n>/priority (priority ports)
    status, before = call("GET", f"/api/nodes/devices/{ports}/interfaces?if_index=7",
                          token=admin)
    check("a port starts unflagged", status == 200
          and before["interfaces"][0]["priority"] is False, (status, before))

    status, put = call("PUT", f"/api/nodes/devices/{ports}/interfaces/7/priority",
                       {"priority": True}, token=admin)
    check("PUT .../priority answers 200 with the flag it set",
          status == 200 and put == {"device_id": ports, "if_index": 7,
                                    "priority": True}, (status, put))
    check("...and it is stored", service.nodes_db.priority_if_indexes(ports) == {7},
          service.nodes_db.priority_if_indexes(ports))
    check("priority_device_ids of an empty iterable is an empty set",
          service.nodes_db.priority_device_ids([]) == set(),
          service.nodes_db.priority_device_ids([]))
    check("...and ids the flag does not cover are not returned",
          service.nodes_db.priority_device_ids([core]) == set(),
          service.nodes_db.priority_device_ids([core]))

    status, list_payload = call("GET", "/api/nodes/devices?fields=list", token=admin)
    list_rows = {r["id"]: r for r in list_payload.get("devices", [])}
    check("the device-list projection flags the starred device",
          status == 200 and list_rows.get(ports, {}).get("priority_port") is True,
          (status, list_rows.get(ports)))
    check("...and leaves an unflagged device alone",
          list_rows.get(core, {}).get("priority_port") is False,
          list_rows.get(core))

    status, flagged = call("GET", f"/api/nodes/devices/{ports}/interfaces?if_index=7",
                           token=admin)
    check("the interface JSON now carries priority: true",
          status == 200 and flagged["interfaces"][0]["priority"] is True,
          (status, flagged))
    status, other = call("GET", f"/api/nodes/devices/{ports}/interfaces?if_index=8",
                         token=admin)
    check("a different port is unaffected", status == 200
          and other["interfaces"][0]["priority"] is False, (status, other))

    status, csv_payload = call(
        "GET", f"/api/nodes/devices/{ports}/interfaces/export.csv", token=admin)
    csv_lines = csv_payload["csv"].lstrip("﻿").splitlines()
    csv_header = csv_lines[0].split(",")
    priority_col = csv_header.index("Priority")
    flagged_row = next(line.split(",") for line in csv_lines[1:]
                       if line.split(",")[0] == "7")
    unflagged_row = next(line.split(",") for line in csv_lines[1:]
                         if line.split(",")[0] == "8")
    check("the interfaces CSV export gains a Priority column",
          "Priority" in csv_header, csv_header)
    check("...'yes' for the flagged port, 'no' for one that is not",
          flagged_row[priority_col] == "yes" and unflagged_row[priority_col] == "no",
          (flagged_row, unflagged_row))

    status, unset = call("PUT", f"/api/nodes/devices/{ports}/interfaces/7/priority",
                         {"priority": False}, token=admin)
    check("clearing the flag answers priority: false",
          status == 200 and unset["priority"] is False, (status, unset))
    check("...and priority_if_indexes agrees",
          service.nodes_db.priority_if_indexes(ports) == set(),
          service.nodes_db.priority_if_indexes(ports))

    status, cleared_list = call("GET", "/api/nodes/devices?fields=list", token=admin)
    cleared_rows = {r["id"]: r for r in cleared_list.get("devices", [])}
    check("...and the device-list star is gone once cleared",
          status == 200 and cleared_rows.get(ports, {}).get("priority_port") is False,
          (status, cleared_rows.get(ports)))

    status, missing = call(
        "PUT", "/api/nodes/devices/999999/interfaces/7/priority",
        {"priority": True}, token=admin)
    check("an unknown device is a 404, like every other device sub-route",
          status == 404, (status, missing))

    status, no_such_if = call(
        "PUT", f"/api/nodes/devices/{ports}/interfaces/9999/priority",
        {"priority": True}, token=admin)
    check("an if_index not on that device is a 404, not a silent insert",
          status == 404, (status, no_such_if))
    check("...and nothing was stored for it",
          9999 not in service.nodes_db.priority_if_indexes(ports),
          service.nodes_db.priority_if_indexes(ports))

    service.app_db.add_user("nodes-viewer", hash_password("NodesViewerPW2026"),
                            must_change=False)
    service.app_db.set_permissions("nodes-viewer", {"nodes": "read"})
    nodes_viewer = login("nodes-viewer", "NodesViewerPW2026")
    status, refused = call(
        "PUT", f"/api/nodes/devices/{ports}/interfaces/7/priority",
        {"priority": True}, token=nodes_viewer)
    check("a nodes:read account is refused PUT .../priority (needs write)",
          status == 403, (status, refused))

    # A device delete cascades interface_flags, like interface_thresholds --
    # nodesdb._PURGE_TABLES.
    call("PUT", f"/api/nodes/devices/{ports}/interfaces/9/priority",
        {"priority": True}, token=admin)
    service.nodes_db.bulk_remove_devices([ports])
    check("deleting the device takes its interface_flags rows with it",
          service.nodes_db.priority_if_indexes(ports) == set(),
          service.nodes_db.priority_if_indexes(ports))

    # --------------------------- 6. GET /api/nodes/devices?fields=index
    INDEX_KEYS = {"id", "ip", "name", "sys_name", "display_name_source",
                  "device_group_id", "status"}
    status, payload = call("GET", "/api/nodes/devices?fields=index", token=admin)
    rows = payload.get("devices", []) if status == 200 else []
    check("?fields=index returns every device", status == 200
          and len(rows) == payload.get("total"), (status, len(rows),
                                                  payload.get("total")))
    check("...with exactly the seven columns a device lookup needs",
          bool(rows) and all(set(r) == INDEX_KEYS for r in rows),
          sorted(rows[0]) if rows else rows)
    check("...and nothing heavier riding along",
          all("sys_descr" not in r and "community" not in r
              and "addresses" not in r for r in rows))

    status, paged = call("GET", "/api/nodes/devices?fields=index&limit=10&offset=5",
                         token=admin)
    check("...and paging means what it means on the full route",
          status == 200 and len(paged["devices"]) == 10
          and paged["limit"] == 10 and paged["offset"] == 5
          and paged["total"] == payload["total"], (status, paged.get("limit"),
                                                   paged.get("offset")))
    status, full = call("GET", "/api/nodes/devices?limit=10&offset=5", token=admin)
    check("...over the same rows in the same order as the full projection",
          [d["id"] for d in full["devices"]] == [d["id"] for d in paged["devices"]],
          ([d["id"] for d in full["devices"]][:4],
           [d["id"] for d in paged["devices"]][:4]))

    # ------------------------- 6b. row.keys() batching, and ?fields=list
    class CountingKeysRow:
        """Wraps a real sqlite3.Row so .keys() calls can be counted without
        changing what indexing returns."""
        def __init__(self, row):
            self._row = row
            self.keys_calls = 0

        def keys(self):
            self.keys_calls += 1
            return self._row.keys()

        def __getitem__(self, key):
            return self._row[key]

    # A few fields _device_json builds through other helpers (override_fields,
    # _v3_level_fields, device_web_target) each read row.keys() once on their
    # own account -- not the ~25-calls-per-row bug this pins, so the proof is
    # the DELTA between the two calls below, not an absolute count: handing
    # in a precomputed key set must save _device_json's own one call, and
    # nothing here should still scale with the number of defensively-keyed
    # fields in its dict literal.
    raw_row = service.nodes_db.device(dup_ids[0])
    wrapped = CountingKeysRow(raw_row)
    _device_json(wrapped, reveal=False)
    without_keys = wrapped.keys_calls

    wrapped2 = CountingKeysRow(raw_row)
    _device_json(wrapped2, reveal=False, keys=frozenset(raw_row.keys()))
    with_keys = wrapped2.keys_calls

    check("_device_json's own ~25 defensively-keyed fields cost it exactly "
          "one row.keys() call, not one per field",
          without_keys == with_keys + 1,
          (without_keys, with_keys))
    check("...a handful of calls total, not one that scales with the "
          "number of columns in the dict literal",
          without_keys <= 5, without_keys)

    LIST_KEYS = set(_DEVICE_LIST_FIELDS)
    status, list_payload = call("GET", "/api/nodes/devices?fields=list", token=admin)
    list_rows = list_payload.get("devices", []) if status == 200 else []
    check("?fields=list returns every device", status == 200
          and len(list_rows) == list_payload.get("total"),
          (status, len(list_rows), list_payload.get("total")))
    check("...with exactly the columns the Nodes table draws",
          bool(list_rows) and all(set(r) == LIST_KEYS for r in list_rows),
          sorted(list_rows[0]) if list_rows else list_rows)

    status, full_unpaged = call("GET", "/api/nodes/devices", token=admin)
    full_by_id = {d["id"]: d for d in full_unpaged["devices"]}
    check("...and every value in the projection is identical to the full row's",
          all(full_by_id[r["id"]][k] == r[k] for r in list_rows for k in LIST_KEYS),
          "value mismatch between fields=list and the full projection")

    status, list_paged = call(
        "GET", "/api/nodes/devices?fields=list&limit=10&offset=5", token=admin)
    check("...and paging means what it means on the full route",
          status == 200 and len(list_paged["devices"]) == 10
          and list_paged["limit"] == 10 and list_paged["offset"] == 5
          and list_paged["total"] == full_unpaged["total"],
          (status, list_paged.get("limit"), list_paged.get("offset")))

    # ------------------------- 7. poll_overrun is out of the dialog's log
    #
    # (B2) A slow poll cycle is operational noise in the device dialog's
    # event list, not an event an operator is hunting for -- but the alert
    # engine reads device_events() directly, so the row must still exist.
    overrun_dev = service.nodes_db.add_device("203.0.113.210", name="overrun",
                                              group_id=group_id)
    service.nodes_db.record_device_event(overrun_dev, "poll_overrun", "took 12.4s")
    service.nodes_db.record_device_event(overrun_dev, "down", "no response")
    status, dialog = call("GET", f"/api/nodes/devices/{overrun_dev}/events", token=admin)
    kinds = [e["kind"] for e in dialog.get("device_events", [])] if status == 200 else []
    check("the device dialog's event feed omits poll_overrun",
          status == 200 and "poll_overrun" not in kinds and "down" in kinds,
          (status, kinds))
    stored_kinds = [e["kind"] for e in service.nodes_db.device_events(device_id=overrun_dev)]
    check("...but nodes_db.device_events() itself still returns it, for alerting",
          "poll_overrun" in stored_kinds, stored_kinds)
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

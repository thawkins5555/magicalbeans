"""Nodes API contracts a 5.9.1 review found broken, each pinned by the
request that gave the wrong answer: the duplicates route reads one page and
one batch of device rows rather than an unclamped list and two queries per
pair; applying a batch of upstream suggestions is one read, not three per
assignment; the three device sub-routes that skipped their existence check
answer 400 for an unknown id like every sibling; a MIB object's OID must be
dotted ASCII decimal before it is stored; and the two projections the
browser asks for (`?if_index=` on a port table, `?fields=index` on the
device list) return the same shape with less of it.

Real `Service` and `WebServer` over loopback HTTP, because the route table
and the permission gate sit between the socket and the handler.
"""
import http.client
import json
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

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
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
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
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

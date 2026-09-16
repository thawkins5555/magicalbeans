"""nodepoll._refresh_default_gateway: ipCidrRouteNextHop under dest/mask
0.0.0.0 read first, ipRouteNextHop.0.0.0.0 GET as a fallback for a box that
only fills the older table, and nodesdb.set_default_gateway/_device_json
carrying the result through to the API.

No real SNMP session: _walk_column and _snmp_get are replaced on the
NodePoller instance directly, the way tests/test_psu_state.py does.
"""
import sys
import types

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import nodeoids
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase
from netpath.snmppoll import SnmpError
from netpath.web.api import _device_json

TMPDIR = _paths.tmpdir("default_gateway_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _FakeDB:
    def __init__(self):
        self.stored = {}

    def set_default_gateway(self, device_id, text):
        self.stored[device_id] = text


def new_poller():
    return NodePoller(_FakeDB())


def device(id=1):
    return {"id": id, "ip": "10.0.0.1"}


CONFIG = {"poll_interval_s": 120, "snmp_enabled": True}


def raiser(*a, **kw):
    raise SnmpError("no route table")


def get_response(varbinds):
    return lambda *a, **kw: types.SimpleNamespace(varbinds=varbinds)


print("1. two next hops from the walk")
poller = new_poller()
poller._walk_column = lambda *a, **kw: {"0.10.0.0.1": "10.0.0.1", "0.10.0.0.2": "10.0.0.2"}
poller._snmp_get = lambda *a, **kw: (_ for _ in ()).throw(AssertionError("GET not needed"))
poller._refresh_default_gateway(device(1), CONFIG)
check("both hops stored, sorted and comma-joined",
      poller.db.stored.get(1) == "10.0.0.1, 10.0.0.2", poller.db.stored)

print("2. walk empty, GET answers")
poller = new_poller()
poller._walk_column = lambda *a, **kw: {}
poller._snmp_get = get_response(
    [{"oid": nodeoids.IP_ROUTE_NEXTHOP_DEFAULT, "type": "IpAddress", "value": "10.0.0.9"}])
poller._refresh_default_gateway(device(2), CONFIG)
check("the GET's own hop is stored", poller.db.stored.get(2) == "10.0.0.9", poller.db.stored)

print("3. both reads raise SnmpError")
poller = new_poller()
poller._walk_column = raiser
poller._snmp_get = raiser
poller._refresh_default_gateway(device(3), CONFIG)
check("the stored value is left alone, not overwritten with empty",
      3 not in poller.db.stored, poller.db.stored)

print("4. walk answers only 0.0.0.0")
poller = new_poller()
poller._walk_column = lambda *a, **kw: {"0.10.0.0.1": "0.0.0.0"}
poller._snmp_get = lambda *a, **kw: (_ for _ in ()).throw(AssertionError("GET not needed"))
poller._refresh_default_gateway(device(4), CONFIG)
check("an answered read with no default route stores the empty string",
      poller.db.stored.get(4) == "", poller.db.stored)

print("5. GET also answers 0.0.0.0")
poller = new_poller()
poller._walk_column = lambda *a, **kw: {}
poller._snmp_get = get_response(
    [{"oid": nodeoids.IP_ROUTE_NEXTHOP_DEFAULT, "type": "IpAddress", "value": "0.0.0.0"}])
poller._refresh_default_gateway(device(5), CONFIG)
check("GET's own 0.0.0.0 is also normalised to empty",
      poller.db.stored.get(5) == "", poller.db.stored)

print("6. walk raises, GET has nothing usable")
poller = new_poller()
poller._walk_column = raiser
poller._snmp_get = get_response(
    [{"oid": nodeoids.IP_ROUTE_NEXTHOP_DEFAULT, "type": "noSuchInstance", "value": None}])
poller._refresh_default_gateway(device(6), CONFIG)
check("an answered-but-empty GET stores the empty string too",
      poller.db.stored.get(6) == "", poller.db.stored)

print("7. _device_json carries default_gateway")
db = NodesDatabase(f"{TMPDIR}/nodes.db")
did = db.add_device("10.40.0.1", "core-a")
row = db.device(did)
check("unset reads as the empty string, not null",
      _device_json(row)["default_gateway"] == "", _device_json(row))
db.set_default_gateway(did, "10.40.0.254")
row = db.device(did)
check("a stored gateway rides through the device JSON",
      _device_json(row)["default_gateway"] == "10.40.0.254", _device_json(row))
db.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

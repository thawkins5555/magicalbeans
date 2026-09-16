"""netpath/nodepoll.py's _poll_stack_power: CISCO-STACKWISE-MIB
(nodeoids.CSW_*) walked into stack_power_port(_admin|_limit_a).<idx>,
stack_power_stack_*.<n> and stack_power_*_w.<ent>; its own probe-once-
remember latch, separate from vendor_sensor_capable and gated to enterprise
arc 9 (Cisco) by _poll_vendor_sensors; and api.get_nodes_device_stack_power
assembling the same stored metrics back into the device dialog's shape.

Also covers built-in rule seeding: a fresh AlertsDatabase ships both
stack_power_cable_down and stack_power_trap, and a database that predates
them gains both on reopen (alertsdb._seed_rules is INSERT OR IGNORE).

No real SNMP session: _walk_column is replaced on the NodePoller instance
directly, the style tests/test_psu_state.py already uses. self.db is the
same small in-memory fake, extended to also carry label/unit/last_ts so
api.get_nodes_device_stack_power (stored data only) can read it back.
"""
import os
import sys

import _paths  # noqa: F401  (repo root on sys.path)

from netpath import nodeoids
from netpath.nodepoll import NodePoller
from netpath.web import api as webapi

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _FakeDB:
    def __init__(self):
        self.sample_calls = []
        self.capable_calls = []
        self._store: dict[int, dict[str, dict]] = {}

    def metrics(self, device_id):
        return list(self._store.get(device_id, {}).values())

    def record_metric_samples(self, device_id, samples):
        self.sample_calls.append((device_id, list(samples)))
        store = self._store.setdefault(device_id, {})
        for key, label, unit, kind, ts, value in samples:
            store[key] = {"key": key, "label": label, "unit": unit,
                         "last_value": value, "last_ts": ts}

    def replace_interface_thresholds(self, device_id, source, rows):
        pass

    def set_vendor_sensor_capable(self, device_id, capable):
        self.capable_calls.append((device_id, capable))

    def samples_dict(self, device_id):
        return {k: v["last_value"] for k, v in self._store.get(device_id, {}).items()}

    def labels_dict(self, device_id):
        return {k: v["label"] for k, v in self._store.get(device_id, {}).items()}


def new_poller():
    return NodePoller(_FakeDB())


def device(sys_object_id, vendor_sensor_capable=None, id=1):
    return {"id": id, "ip": "10.0.0.1", "sys_object_id": sys_object_id,
           "sensor_capable": None, "vendor_sensor_capable": vendor_sensor_capable}


CONFIG = {"poll_interval_s": 120, "snmp_enabled": True}
CISCO_OID = "1.3.6.1.4.1.9.1.1208"
JUNIPER_OID = "1.3.6.1.4.1.2636.1.1.1.2.87"

P_OPER = nodeoids.CSW_STACK_POWER_PORT_OPER_STATUS
P_NEIGHBOR = nodeoids.CSW_STACK_POWER_PORT_NEIGHBOR_SWITCH
P_LINK = nodeoids.CSW_STACK_POWER_PORT_LINK_STATUS
P_LIMIT = nodeoids.CSW_STACK_POWER_PORT_LIMIT_A
P_NAME = nodeoids.CSW_STACK_POWER_PORT_NAME
SW_NUM = nodeoids.CSW_SWITCH_NUM_CURRENT
SW_BUDGET = nodeoids.CSW_SWITCH_POWER_BUDGET
SW_COMMITTED = nodeoids.CSW_SWITCH_POWER_COMMITED
SW_ALLOCATED = nodeoids.CSW_SWITCH_POWER_ALLOCATED
ST_MODE = nodeoids.CSW_STACK_POWER_MODE
ST_MEMBERS = nodeoids.CSW_STACK_POWER_NUM_MEMBERS
ST_TYPE = nodeoids.CSW_STACK_POWER_TYPE
ST_NAME = nodeoids.CSW_STACK_POWER_NAME


def table_walker(columns: dict, calls: list | None = None):
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        if calls is not None:
            calls.append(oid)
        return dict(columns.get(oid, {}))
    return fake


FULL_STACK = {
    P_OPER: {"1001.1": 1, "1001.2": 1},
    P_LINK: {"1001.1": 1, "1001.2": 2},
    P_NEIGHBOR: {"1001.1": 3, "1001.2": 0},
    P_LIMIT: {"1001.1": 30, "1001.2": 30},
    P_NAME: {"1001.1": "PORT-1", "1001.2": "PORT-2"},
    SW_NUM: {"1001": 1},
    SW_BUDGET: {"1001": 1100},
    SW_COMMITTED: {"1001": 300},
    SW_ALLOCATED: {"1001": 320},
    ST_MODE: {"1": 2},
    ST_MEMBERS: {"1": 3},
    ST_TYPE: {"1": 1},
    ST_NAME: {"1": "Power Stack 1"},
}

# ------------------------------------------------------------- basic walk
poller = new_poller()
poller._walk_column = table_walker(FULL_STACK)
dev = device(CISCO_OID)
poller._poll_stack_power(1, dev, CONFIG, 1_700_000_000.0)
samples = poller.db.samples_dict(1)
labels = poller.db.labels_dict(1)

check("port 1 (enabled, up) -> state 0, idx = ent*1000+port",
      samples.get("stack_power_port.1001001") == 0.0, samples)
check("...labelled with the switch, port name and neighbour",
      labels.get("stack_power_port.1001001") ==
      "Switch 1 stack power PORT-1 -> switch 3", labels)
check("port 2 (enabled, down) -> state 2, the cable fault",
      samples.get("stack_power_port.1001002") == 2.0, samples)
check("...neighbour 0 (none) is omitted from the label",
      labels.get("stack_power_port.1001002") == "Switch 1 stack power PORT-2",
      labels)
check("admin metric passes the raw OperStatus through",
      samples.get("stack_power_port_admin.1001001") == 1.0
      and samples.get("stack_power_port_admin.1001002") == 1.0, samples)
check("limit metric is the published over-current threshold",
      samples.get("stack_power_port_limit_a.1001001") == 30.0, samples)
check("stack info: type/mode/members, named after the stack",
      samples.get("stack_power_stack_type.1") == 1.0
      and samples.get("stack_power_stack_mode.1") == 2.0
      and samples.get("stack_power_stack_members.1") == 3.0
      and labels.get("stack_power_stack_type.1") == "Power Stack 1", samples)
check("switch info: budget/committed/allocated, labelled 'Switch N'",
      samples.get("stack_power_budget_w.1001") == 1100.0
      and samples.get("stack_power_committed_w.1001") == 300.0
      and samples.get("stack_power_allocated_w.1001") == 320.0
      and labels.get("stack_power_budget_w.1001") == "Switch 1", samples)
check("capability latches answered",
      poller._stack_power_capable.get(1) == 1, poller._stack_power_capable)

# ---------------------------------------------------- disabled port -> 0
poller_dis = new_poller()
poller_dis._walk_column = table_walker({
    **FULL_STACK,
    P_OPER: {"1001.1": 2},          # administratively disabled
    P_LINK: {"1001.1": 2},          # ...and the link happens to read down too
})
poller_dis._poll_stack_power(2, device(CISCO_OID, id=2), CONFIG, 1_700_000_000.0)
check("an admin-disabled port reads 0 regardless of link -- deliberately "
      "off is not a fault",
      poller_dis.db.samples_dict(2).get("stack_power_port.1001001") == 0.0,
      poller_dis.db.samples_dict(2))

# ---------------------------------------------------- non-Cisco never probed
walked_nc = []
poller_nc = new_poller()
poller_nc._walk_column = table_walker(FULL_STACK, walked_nc)
poller_nc._poll_vendor_sensors(3, device(JUNIPER_OID, id=3), CONFIG, 1_700_000_000.0)
check("a non-Cisco device's _poll_vendor_sensors never walks a CSW_* OID",
      not any(oid.startswith("1.3.6.1.4.1.9.9.500") for oid in walked_nc), walked_nc)
check("...and no stack_power_* metric is ever written",
      not any(k.startswith("stack_power_") for k in poller_nc.db.samples_dict(3)),
      poller_nc.db.samples_dict(3))

# ---------------------------------------- unanswered probe latched + reprobed
walked_u = []
poller_u = new_poller()
poller_u._walk_column = table_walker({}, walked_u)
dev_u = device(CISCO_OID, id=4)
poller_u._poll_stack_power(4, dev_u, CONFIG, 1_700_000_000.0)
check("a device answering none of the tables writes nothing",
      poller_u.db.samples_dict(4) == {}, poller_u.db.samples_dict(4))
check("...and is latched not-yet-capable",
      poller_u._stack_power_capable.get(4) == 0, poller_u._stack_power_capable)
walked_u.clear()
poller_u._poll_stack_power(4, dev_u, CONFIG, 1_700_000_010.0)   # 10s later
check("inside the hourly reprobe window, nothing is walked again", walked_u == [])
walked_u.clear()
poller_u._poll_stack_power(4, dev_u, CONFIG, 1_700_000_000.0 + 3601.0)
check("past the hourly reprobe window, it tries again",
      P_OPER in walked_u, walked_u)

# -------------------------------------------------------- vanished port
poller_v = new_poller()
poller_v._walk_column = table_walker(FULL_STACK)
dev_v = device(CISCO_OID, id=5)
poller_v._poll_stack_power(5, dev_v, CONFIG, 1_700_000_000.0)
before = poller_v.db.samples_dict(5).get("stack_power_port.1001002")
poller_v._walk_column = table_walker({
    **FULL_STACK,
    P_OPER: {"1001.1": 1},   # port 2 gone from the walk entirely
    P_LINK: {"1001.1": 1},
})
call_count_before = len(poller_v.db.sample_calls)
poller_v._poll_stack_power(5, dev_v, CONFIG, 1_700_000_010.0)
after_keys = poller_v.db.sample_calls[call_count_before][1] if \
    len(poller_v.db.sample_calls) > call_count_before else []
check("a port that vanishes from the walk gets no new sample this poll",
      not any(row[0] == "stack_power_port.1001002" for row in after_keys), after_keys)
check("...and its last stored state stands",
      poller_v.db.samples_dict(5).get("stack_power_port.1001002") == before,
      poller_v.db.samples_dict(5))

# ---------------------------------------------------------------- API assembly
class _FakeNodesDB:
    def __init__(self, db):
        self._db = db

    def device(self, device_id):
        return {"id": device_id}

    def metrics(self, device_id):
        return self._db.metrics(device_id)


class _FakeService:
    def __init__(self, db):
        self.nodes_db = _FakeNodesDB(db)


resp = webapi.get_nodes_device_stack_power(_FakeService(poller.db), {}, {}, 1)
check("present is true once any stack_power_* metric exists", resp["present"] is True)
check("one stack assembled, named and typed from stored metrics",
      len(resp["stacks"]) == 1 and resp["stacks"][0]["number"] == 1
      and resp["stacks"][0]["name"] == "Power Stack 1"
      and resp["stacks"][0]["mode_text"] == "redundant"
      and resp["stacks"][0]["topology"] == "ring"
      and resp["stacks"][0]["members"] == 3, resp["stacks"])
check("one switch assembled with its three power numbers",
      len(resp["switches"]) == 1 and resp["switches"][0]["switch"] == 1
      and resp["switches"][0]["budget_w"] == 1100.0
      and resp["switches"][0]["committed_w"] == 300.0
      and resp["switches"][0]["allocated_w"] == 320.0, resp["switches"])
ports_by_name = {p["name"]: p for p in resp["ports"]}
check("two ports, switch/name/neighbour recovered from the stored label",
      ports_by_name.get("PORT-1", {}).get("switch") == 1
      and ports_by_name.get("PORT-1", {}).get("neighbour_switch") == 3
      and ports_by_name.get("PORT-2", {}).get("neighbour_switch") == 0,
      resp["ports"])
check("PORT-1 reads ok, enabled, up, with its limit",
      ports_by_name.get("PORT-1", {}).get("state") == 0
      and ports_by_name.get("PORT-1", {}).get("state_text") == "ok"
      and ports_by_name.get("PORT-1", {}).get("admin_text") == "enabled"
      and ports_by_name.get("PORT-1", {}).get("link_text") == "up"
      and ports_by_name.get("PORT-1", {}).get("limit_a") == 30.0, resp["ports"])
check("PORT-2 reads cable down",
      ports_by_name.get("PORT-2", {}).get("state") == 2
      and ports_by_name.get("PORT-2", {}).get("state_text") == "cable down"
      and ports_by_name.get("PORT-2", {}).get("link_text") == "down", resp["ports"])

resp_dis = webapi.get_nodes_device_stack_power(_FakeService(poller_dis.db), {}, {}, 2)
dis_port = resp_dis["ports"][0] if resp_dis["ports"] else {}
check("an admin-disabled port reads state_text 'disabled', not 'ok'",
      dis_port.get("state_text") == "disabled" and dis_port.get("admin_text") == "disabled",
      resp_dis["ports"])

resp_empty = webapi.get_nodes_device_stack_power(_FakeService(_FakeDB()), {}, {}, 9)
check("present is false for a device with no stack power metrics at all",
      resp_empty == {"present": False, "stacks": [], "switches": [], "ports": []},
      resp_empty)

# --------------------------------------------------- built-in rule seeding
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netpath.alertsdb import AlertsDatabase   # noqa: E402

TMPDIR = _paths.tmpdir("stack_power_rules_")
fresh = AlertsDatabase(os.path.join(TMPDIR, "fresh.db"))
check("a fresh database ships stack_power_cable_down",
      fresh.rule_by_key("stack_power_cable_down") is not None)
check("...and stack_power_trap",
      fresh.rule_by_key("stack_power_trap") is not None)
fresh.close()

existing_path = os.path.join(TMPDIR, "existing.db")
existing = AlertsDatabase(existing_path)
existing._conn.execute(
    "DELETE FROM rules WHERE key IN ('stack_power_cable_down', 'stack_power_trap')")
existing._conn.commit()
check("...deleted from a database predating this release",
      existing.rule_by_key("stack_power_cable_down") is None
      and existing.rule_by_key("stack_power_trap") is None)
existing.close()
reopened = AlertsDatabase(existing_path)
check("reopening seeds stack_power_cable_down back in",
      reopened.rule_by_key("stack_power_cable_down") is not None)
check("...and stack_power_trap",
      reopened.rule_by_key("stack_power_trap") is not None)
reopened.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

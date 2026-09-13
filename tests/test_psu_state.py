"""netpath/nodepoll.py's _poll_vendor_sensors PSU half: nodeoids.PSU_TABLES
read into psu_state.<idx> (0 ok / 1 warning / 2 failed), Cisco's two-table
fallback (ENVMON then FRU, class-filtered to power-supply rows), and the
pulled-supply clear rule: a not-present/off-admin row writes nothing while
its key has never existed, but writes one explicit 0 once it has, so an
open psu_failed alert on a pulled supply clears instead of going stale.

No real SNMP session: _walk_column is replaced on the NodePoller instance
directly, the way tests/test_swversion_entity_walk.py does. self.db is the
same small in-memory fake test_sensor_tables.py uses, recording what was
written -- polling-and-stored-rows coverage only.
"""
import sys

import _paths  # noqa: F401  (repo root on sys.path)

from netpath import nodeoids
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _FakeDB:
    def __init__(self):
        self.sample_calls = []
        self.capable_calls = []
        self._existing: dict[int, set] = {}

    def metrics(self, device_id):
        return [{"key": k} for k in self._existing.get(device_id, set())]

    def record_metric_samples(self, device_id, samples):
        self.sample_calls.append((device_id, list(samples)))
        for row in samples:
            self._existing.setdefault(device_id, set()).add(row[0])

    def replace_interface_thresholds(self, device_id, source, rows):
        pass

    def set_vendor_sensor_capable(self, device_id, capable):
        self.capable_calls.append((device_id, capable))

    def samples_dict(self, device_id):
        out = {}
        for did, samples in self.sample_calls:
            if did == device_id:
                for key, label, unit, kind, ts, value in samples:
                    out[key] = value
        return out

    def seed_existing(self, device_id, key):
        self._existing.setdefault(device_id, set()).add(key)


def new_poller():
    return NodePoller(_FakeDB())


def device(sys_object_id, sensor_capable=None, vendor_sensor_capable=None, id=1):
    return {"id": id, "ip": "10.0.0.1", "sys_object_id": sys_object_id,
           "sensor_capable": sensor_capable,
           "vendor_sensor_capable": vendor_sensor_capable}


CONFIG = {"poll_interval_s": 120, "snmp_enabled": True}
CISCO_OID = "1.3.6.1.4.1.9.1.1208"
JUNIPER_OID = "1.3.6.1.4.1.2636.1.1.1.2.87"
UBIQUITI_OID = "1.3.6.1.4.1.41112.1.6"
VMWARE_OID = "1.3.6.1.4.1.6876.4.1"


def table_walker(columns: dict):
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        return dict(columns.get(oid, {}))
    return fake


# ----------------------------------------------------- Cisco ENVMON states

envmon, fru = nodeoids.PSU_TABLES[9]
poller = new_poller()
poller._walk_column = table_walker({
    envmon.state: {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5},
    envmon.name: {"1": "PSU1", "2": "PSU2", "3": "PSU3", "4": "PSU4", "5": "PSU5"},
})
dev = device(CISCO_OID)
poller._poll_vendor_sensors(1, dev, CONFIG, 1_700_000_000.0)
samples = poller.db.samples_dict(1)
check("Cisco ENVMON: normal(1) -> ok(0)", samples.get("psu_state.1") == 0.0, samples)
check("...warning(2) -> warning(1)", samples.get("psu_state.2") == 1.0, samples)
check("...critical(3) -> failed(2)", samples.get("psu_state.3") == 2.0, samples)
check("...shutdown(4) -> failed(2)", samples.get("psu_state.4") == 2.0, samples)
check("...notPresent(5) writes nothing at all for a bay never seen before",
      "psu_state.5" not in samples, samples)
check("vendor_sensor_capable latches true", poller.db.capable_calls == [(1, True)],
      poller.db.capable_calls)

# --------------------------------------- Cisco FRU: class-filtered chassis PSU
poller_fru = new_poller()
poller_fru._walk_column = table_walker({
    fru.state: {"10": 2, "11": 9, "12": 8, "20": 2},   # on, onButFanFail, failed, on
    fru.name: {"10": "PSU-0", "11": "PSU-1", "12": "PSU-2", "20": "Fan Tray"},
    fru.class_col: {"10": 6, "11": 6, "12": 6, "20": 4},   # 4 = fan, not powerSupply
})
dev_fru = device(CISCO_OID)
poller_fru._poll_vendor_sensors(2, dev_fru, CONFIG, 1_700_000_000.0)
samples_fru = poller_fru.db.samples_dict(2)
check("Cisco FRU: on(2) on a powerSupply-class row -> ok(0)",
      samples_fru.get("psu_state.10") == 0.0, samples_fru)
check("...onButFanFail(9) -> warning(1)", samples_fru.get("psu_state.11") == 1.0, samples_fru)
check("...failed(8) -> failed(2)", samples_fru.get("psu_state.12") == 2.0, samples_fru)
check("...a non-PSU FRU row (entPhysicalClass != powerSupply) is not "
      "written at all, however it reads",
      "psu_state.20" not in samples_fru, samples_fru)

# ---------------------------------------- pulled-supply clears an open alert
poller_clear = new_poller()
poller_clear.db.seed_existing(3, "psu_state.1")   # was written a previous poll
poller_clear._walk_column = table_walker({
    envmon.state: {"1": 5},   # now notPresent
    envmon.name: {"1": "PSU1"},
})
dev_clear = device(CISCO_OID)
poller_clear._poll_vendor_sensors(3, dev_clear, CONFIG, 1_700_000_000.0)
samples_clear = poller_clear.db.samples_dict(3)
check("a supply that was present and now reads notPresent writes an "
      "explicit 0 to its EXISTING key, so an open alert clears rather "
      "than going stale",
      samples_clear.get("psu_state.1") == 0.0, samples_clear)

# ------------------------------------------------------- Juniper class filter
jn = nodeoids.PSU_TABLES[2636]
poller_jn = new_poller()
poller_jn._walk_column = table_walker({
    jn.state: {"1": 6, "2": 8, "3": 2},        # online, offline, empty
    jn.name: {"1": "PEM 0", "2": "PEM 1", "3": "PEM 2"},
    jn.class_col: {"1": 7, "2": 18, "3": 7},   # powerEntryModule/powerSupplyModule
})
dev_jn = device(JUNIPER_OID)
poller_jn._poll_vendor_sensors(4, dev_jn, CONFIG, 1_700_000_000.0)
samples_jn = poller_jn.db.samples_dict(4)
check("Juniper: online(6) -> ok(0)", samples_jn.get("psu_state.1") == 0.0, samples_jn)
check("...offline(8) -> failed(2)", samples_jn.get("psu_state.2") == 2.0, samples_jn)
check("...empty(2) is skipped, no key written for a bay never seen before",
      "psu_state.3" not in samples_jn, samples_jn)

# --------------------------------------------------------- Ubiquiti skip_when
ub = nodeoids.PSU_TABLES[41112]
poller_ub = new_poller()
poller_ub._walk_column = table_walker({
    ub.state: {"1": 1, "2": 1},                        # both read "up"
    ub.skip_when_col: {"1": 1, "2": 3},                 # 2 is standby
})
dev_ub = device(UBIQUITI_OID)
poller_ub._poll_vendor_sensors(5, dev_ub, CONFIG, 1_700_000_000.0)
samples_ub = poller_ub.db.samples_dict(5)
check("Ubiquiti: an ordinary supply reading up(1) -> ok(0)",
      samples_ub.get("psu_state.1") == 0.0, samples_ub)
check("...a supply flagged standby in the sibling column is skipped "
      "entirely, whatever its oper status reads",
      "psu_state.2" not in samples_ub, samples_ub)

# ------------------------------------------------------- MikroTik extra_scalars
mk = nodeoids.PSU_TABLES[14988]
poller_mk = new_poller()
poller_mk._walk_column = table_walker({
    mk.state: {"0": 1},                              # primary ok
    mk.extra_scalars[0][0]: {"0": 0},                 # backup failed
})
dev_mk = device("1.3.6.1.4.1.14988.1.1")
poller_mk._poll_vendor_sensors(6, dev_mk, CONFIG, 1_700_000_000.0)
samples_mk = poller_mk.db.samples_dict(6)
check("MikroTik: primary and backup PSU are two independent scalars",
      samples_mk.get("psu_state.0") == 0.0 and samples_mk.get("psu_state.2") == 2.0,
      samples_mk)

# --------------------------------------------------------------- VMware class
vm = nodeoids.PSU_TABLES[6876]
poller_vm = new_poller()
poller_vm._walk_column = table_walker({
    vm.state: {"1": 2, "2": 4, "3": 2},         # normal, failed, normal
    vm.name: {"1": "PS1", "2": "PS2", "3": "Fan1"},
    vm.class_col: {"1": 3, "2": 3, "3": 4},     # 3 = powerSupply, 4 = fan
})
dev_vm = device(VMWARE_OID)
poller_vm._poll_vendor_sensors(7, dev_vm, CONFIG, 1_700_000_000.0)
samples_vm = poller_vm.db.samples_dict(7)
check("VMware: normal(2) on a powerSupply row -> ok(0)",
      samples_vm.get("psu_state.1") == 0.0, samples_vm)
check("...failed(4) -> failed(2)", samples_vm.get("psu_state.2") == 2.0, samples_vm)
check("...a fan row under the same shared table is not treated as a PSU",
      "psu_state.3" not in samples_vm, samples_vm)

# --------------------------------------------------- capability latch: nothing
poller_none = new_poller()
poller_none._walk_column = table_walker({})
dev_none = device(CISCO_OID)
poller_none._poll_vendor_sensors(8, dev_none, CONFIG, 1_700_000_000.0)
check("a device answering neither table is latched incapable, once",
      poller_none.db.capable_calls == [(8, False)], poller_none.db.capable_calls)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

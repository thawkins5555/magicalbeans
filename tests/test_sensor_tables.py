"""netpath/nodepoll.py's _poll_vendor_sensors: nodeoids.SENSOR_TABLES read
into temp_sensor_c.<idx>/temp_sensor_state.<idx>, and the published limits
that go with them (via _poll_vendor_sensor_thresholds) into
interface_thresholds with metric_root='temp_sensor_c'.

No real SNMP session: _walk_column is replaced on the NodePoller instance
directly, the way tests/test_swversion_entity_walk.py does -- this suite is
about the table-driven walk and its scaling/skip/state rules, not the wire
format. self.db is a small in-memory fake recording what was written, since
this is polling-and-stored-rows coverage only (alertrules/alertengine are
covered elsewhere).
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
        self.threshold_calls = []
        self.capable_calls = []
        self._existing: dict[int, set] = {}

    def metrics(self, device_id):
        return [{"key": k} for k in self._existing.get(device_id, set())]

    def record_metric_samples(self, device_id, samples):
        self.sample_calls.append((device_id, list(samples)))
        for row in samples:
            self._existing.setdefault(device_id, set()).add(row[0])

    def replace_interface_thresholds(self, device_id, source, rows):
        self.threshold_calls.append((device_id, source, rows))

    def set_vendor_sensor_capable(self, device_id, capable):
        self.capable_calls.append((device_id, capable))

    def samples_dict(self, device_id):
        out = {}
        for did, samples in self.sample_calls:
            if did == device_id:
                for key, label, unit, kind, ts, value in samples:
                    out[key] = value
        return out


def new_poller():
    return NodePoller(_FakeDB())


def device(sys_object_id, sensor_capable=None, vendor_sensor_capable=None, id=1):
    return {"id": id, "ip": "10.0.0.1", "sys_object_id": sys_object_id,
           "sensor_capable": sensor_capable,
           "vendor_sensor_capable": vendor_sensor_capable}


CONFIG = {"poll_interval_s": 120, "snmp_enabled": True}
CISCO_OID = "1.3.6.1.4.1.9.1.1208"
JUNIPER_OID = "1.3.6.1.4.1.2636.1.1.1.2.87"
HP_OID = "1.3.6.1.4.1.11.2.3.7.11.144"
FORTINET_OID = "1.3.6.1.4.1.12356.101.1.10001"
ARUBA_CX_OID = "1.3.6.1.4.1.47196.4.1.1.3.11.1.2"
NETGEAR_OID = "1.3.6.1.4.1.4526.100.4.11"
APC_OID = "1.3.6.1.4.1.318.1.3.2.11"
SOPHOS_OID = "1.3.6.1.4.1.2604.5.1"


def only(base_oid, mapping):
    """A fake _walk_column that answers `mapping` for exactly `base_oid`
    and {} for everything else -- most cases here need only one column."""
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        return dict(mapping) if oid == base_oid else {}
    return fake


def table_walker(columns: dict):
    """A fake _walk_column dispatching on a {oid: {suffix: value}} map."""
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        return dict(columns.get(oid, {}))
    return fake


# ------------------------------------------------ Cisco ENVMON: full table

t = nodeoids.SENSOR_TABLES[9]
poller = new_poller()
poller._walk_column = table_walker({
    t.value: {"1": 45, "2": 80},
    t.name: {"1": "Inlet", "2": "Outlet"},
    t.thresholds["high_alarm"]: {"1": 70, "2": 90},
    t.state: {"1": 2, "2": 4},   # warning, shutdown
})
dev = device(CISCO_OID)
poller._poll_vendor_sensors(1, dev, CONFIG, 1_700_000_000.0)
samples = poller.db.samples_dict(1)
check("Cisco ENVMON: both sensors' readings land as temp_sensor_c.<idx>",
      samples.get("temp_sensor_c.1") == 45.0 and samples.get("temp_sensor_c.2") == 80.0,
      samples)
check("...and their states normalise to the common 0..3 scale",
      samples.get("temp_sensor_state.1") == 1.0 and samples.get("temp_sensor_state.2") == 3.0,
      samples)
thresholds = {(r["if_index"], r["metric_root"]): r
             for _did, _src, rows in poller.db.threshold_calls for r in rows}
check("published high_alarm limits are written with metric_root=temp_sensor_c",
      thresholds[(1, "temp_sensor_c")]["high_alarm"] == 70.0
      and thresholds[(2, "temp_sensor_c")]["high_alarm"] == 90.0,
      thresholds)
check("vendor_sensor_capable is latched true on a device that answered",
      poller.db.capable_calls == [(1, True)], poller.db.capable_calls)

# --- Rev1 value column empty: falls back to the deprecated plain one
poller2 = new_poller()
poller2._walk_column = table_walker({
    t.value_fallback: {"1": 33},
})
dev2 = device(CISCO_OID)
poller2._poll_vendor_sensors(2, dev2, CONFIG, 1_700_000_000.0)
samples2 = poller2.db.samples_dict(2)
check("Cisco ENVMON: Rev1 empty falls back to the deprecated value column",
      samples2.get("temp_sensor_c.1") == 33.0, samples2)

# --- notPresent(5)/notFunctioning(6) states are skipped, not written
poller3 = new_poller()
poller3._walk_column = table_walker({
    t.value: {"1": 20},
    t.state: {"1": 5},
})
dev3 = device(CISCO_OID)
poller3._poll_vendor_sensors(3, dev3, CONFIG, 1_700_000_000.0)
samples3 = poller3.db.samples_dict(3)
check("a notPresent state is skipped entirely, not written as a fourth level",
      "temp_sensor_state.1" not in samples3, samples3)

# ------------------------------------------ sensor_capable gate (arc overlap)

# MikroTik has entries in BOTH SENSOR_TABLES and PSU_TABLES on the same arc;
# a device already confirmed ENTITY-SENSOR-capable must skip the vendor
# temperature table (index collision) but still poll PSU.
mk_temp = nodeoids.SENSOR_TABLES[14988]
mk_psu = nodeoids.PSU_TABLES[14988]
poller4 = new_poller()
poller4._walk_column = table_walker({
    mk_temp.value: {"0": 350},          # would become temp_sensor_c.0 if run
    mk_psu.state: {"0": 1},             # ok
})
dev4 = device("1.3.6.1.4.1.14988.1.1", sensor_capable=1)
poller4._poll_vendor_sensors(4, dev4, CONFIG, 1_700_000_000.0)
samples4 = poller4.db.samples_dict(4)
check("a device already ENTITY-SENSOR-capable does not also poll the vendor "
      "temperature table (would collide on the same small integer index)",
      not any(k.startswith("temp_sensor_c") for k in samples4), samples4)
check("...but its PSU table still runs independently",
      samples4.get("psu_state.0") == 0.0, samples4)

# ------------------------------------------------------- MikroTik fallback
poller5 = new_poller()
poller5._walk_column = table_walker({
    mk_temp.value_fallback: {"0": 410},   # only the older scalar answers
})
dev5 = device("1.3.6.1.4.1.14988.1.1")
poller5._poll_vendor_sensors(5, dev5, CONFIG, 1_700_000_000.0)
samples5 = poller5.db.samples_dict(5)
check("MikroTik: primary scalar empty falls back to the processor one, "
      "scaled by 0.1 (tenths of a degree)",
      samples5.get("temp_sensor_c.0") == 41.0, samples5)

# --------------------------------------------------------------- HP ProCurve
hp = nodeoids.SENSOR_TABLES[11]
poller6 = new_poller()
poller6._walk_column = table_walker({
    hp.value: {"1": "45C"},
    hp.thresholds["high_alarm"]: {"1": "70C"},
    hp.state: {"1": 2},   # no -> normal
})
dev6 = device(HP_OID)
poller6._poll_vendor_sensors(6, dev6, CONFIG, 1_700_000_000.0)
samples6 = poller6.db.samples_dict(6)
check("HP: a string reading like '45C' is parsed by its numeric prefix",
      samples6.get("temp_sensor_c.1") == 45.0, samples6)
thresholds6 = {(r["if_index"], r["metric_root"]): r
              for _did, _src, rows in poller6.db.threshold_calls for r in rows}
check("...and so is its threshold string",
      thresholds6[(1, "temp_sensor_c")]["high_alarm"] == 70.0, thresholds6)
check("...over temp 'no' maps to normal (0)",
      samples6.get("temp_sensor_state.1") == 0.0, samples6)

# --------------------------------------------------------------- Fortinet
ft = nodeoids.SENSOR_TABLES[12356]
poller7 = new_poller()
poller7._walk_column = table_walker({
    ft.value: {"1": "45.0 C", "2": "3200 RPM"},
    ft.name: {"1": "Temp1 (temp)", "2": "Fan1"},
})
dev7 = device(FORTINET_OID)
poller7._poll_vendor_sensors(7, dev7, CONFIG, 1_700_000_000.0)
samples7 = poller7.db.samples_dict(7)
check("Fortinet: only rows whose name contains 'temp' are kept -- the fan "
      "row is dropped",
      samples7.get("temp_sensor_c.1") == 45.0 and "temp_sensor_c.2" not in samples7,
      samples7)

# --------------------------------------------------------------- Aruba CX
cx = nodeoids.SENSOR_TABLES[47196]
poller8 = new_poller()
poller8._walk_column = table_walker({
    cx.value: {"1": 45230, "2": 50000, "3": 41000},
    cx.name: {"1": "Sensor1", "2": "Sensor2", "3": "Sensor3"},
    cx.state: {"1": "normal", "2": "critical fault", "3": "unknown"},
})
dev8 = device(ARUBA_CX_OID)
poller8._poll_vendor_sensors(8, dev8, CONFIG, 1_700_000_000.0)
samples8 = poller8.db.samples_dict(8)
check("Aruba CX: millidegree scale (0.001) applied to the reading",
      round(samples8.get("temp_sensor_c.1"), 3) == 45.23, samples8)
check("...'normal' state -> 0",
      samples8.get("temp_sensor_state.1") == 0.0, samples8)
check("...a string containing 'critical' -> 2, even mixed with other words",
      samples8.get("temp_sensor_state.2") == 2.0, samples8)
check("...an unrecognised string falls to the declared default (1, warning)",
      samples8.get("temp_sensor_state.3") == 1.0, samples8)

# ------------------------------------------------------------ Juniper skip
jn = nodeoids.SENSOR_TABLES[2636]
poller9 = new_poller()
poller9._walk_column = table_walker({
    jn.value: {"1": 45, "2": 0},
    jn.name: {"1": "FPC 0", "2": "PSU 0"},
    jn.state: {"1": 2, "2": 6},   # running -> 0, down -> 2
})
dev9 = device(JUNIPER_OID)
poller9._poll_vendor_sensors(9, dev9, CONFIG, 1_700_000_000.0)
samples9 = poller9.db.samples_dict(9)
check("Juniper: a row reading 0 C (not applicable on this table) is skipped",
      "temp_sensor_c.2" not in samples9 and samples9.get("temp_sensor_c.1") == 45.0,
      samples9)
check("...its state still comes through independently (down -> critical)",
      samples9.get("temp_sensor_state.2") == 2.0, samples9)

# --------------------------------------------------------------- APC -1 skip
apc = nodeoids.SENSOR_TABLES[318]
poller10 = new_poller()
poller10._walk_column = table_walker({
    apc.value: {"1": 22, "2": -1},
    apc.thresholds["high_warn"]: {"1": 30},
    apc.thresholds["high_alarm"]: {"1": 35},
    apc.state: {"1": 1},
})
dev10 = device(APC_OID)
poller10._poll_vendor_sensors(10, dev10, CONFIG, 1_700_000_000.0)
samples10 = poller10.db.samples_dict(10)
check("APC: an unpopulated probe port (-1) is skipped entirely",
      "temp_sensor_c.2" not in samples10 and samples10.get("temp_sensor_c.1") == 22.0,
      samples10)
thresholds10 = {(r["if_index"], r["metric_root"]): r
               for _did, _src, rows in poller10.db.threshold_calls for r in rows}
check("...its high_warn/high_alarm band is published",
      thresholds10[(1, "temp_sensor_c")]["high_warn"] == 30.0
      and thresholds10[(1, "temp_sensor_c")]["high_alarm"] == 35.0, thresholds10)

# ------------------------------------------------------- Sophos extra scalars
so = nodeoids.SENSOR_TABLES[2604]
poller11 = new_poller()
poller11._walk_column = table_walker({
    so.value: {"0": 350},
    so.extra_scalars[0][0]: {"0": 420},
})
dev11 = device(SOPHOS_OID)
poller11._poll_vendor_sensors(11, dev11, CONFIG, 1_700_000_000.0)
samples11 = poller11.db.samples_dict(11)
check("Sophos: NPU and CPU are two independent always-read scalars, not a "
      "fallback pair -- both show up under their own index",
      samples11.get("temp_sensor_c.0") == 35.0 and samples11.get("temp_sensor_c.2") == 42.0,
      samples11)

# ----------------------------------------------------- Netgear global range
ng = nodeoids.SENSOR_TABLES[4526]
poller12 = new_poller()
poller12._walk_column = table_walker({
    ng.value: {"1": 30, "2": 55},
    ng.threshold_scalars["high_alarm"]: {"0": 65},
    ng.state: {"1": 1, "2": 4},   # normal, shutdown
})
dev12 = device(NETGEAR_OID)
poller12._poll_vendor_sensors(12, dev12, CONFIG, 1_700_000_000.0)
thresholds12 = {(r["if_index"], r["metric_root"]): r
               for _did, _src, rows in poller12.db.threshold_calls for r in rows}
check("Netgear: one global range scalar applies identically to every row",
      thresholds12[(1, "temp_sensor_c")]["high_alarm"] == 65.0
      and thresholds12[(2, "temp_sensor_c")]["high_alarm"] == 65.0, thresholds12)
samples12 = poller12.db.samples_dict(12)
check("...state 4 (shutdown) maps to the top of the common scale",
      samples12.get("temp_sensor_state.2") == 3.0, samples12)

# --------------------------------------------------- capability latch: nothing
poller13 = new_poller()
poller13._walk_column = only("nothing", {})
dev13 = device(CISCO_OID)
poller13._poll_vendor_sensors(13, dev13, CONFIG, 1_700_000_000.0)
check("a device answering nothing at all is latched incapable, once",
      poller13.db.capable_calls == [(13, False)], poller13.db.capable_calls)

# ------------------------------------------------------------ cadence gate
poller14 = new_poller()
calls = {"n": 0}


def counting(device, config, oid, raise_on_timeout=False, deadline=None):
    calls["n"] += 1
    return {"1": 40} if oid == t.value else {}


poller14._walk_column = counting
dev14 = device(CISCO_OID)
poller14._poll_vendor_sensors(14, dev14, CONFIG, 1_700_000_000.0)
first_calls = calls["n"]
poller14._poll_vendor_sensors(14, dev14, CONFIG, 1_700_000_000.0 + 1.0)
check("a second poll one second later does not re-walk (inside "
      "_SENSOR_REFRESH_S)", calls["n"] == first_calls, calls)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

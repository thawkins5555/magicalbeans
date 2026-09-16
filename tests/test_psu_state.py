"""netpath/nodepoll.py's _poll_vendor_sensors PSU half: nodeoids.PSU_TABLES
read into psu_state.<idx> (0 ok / 1 warning / 2 failed / 3 not present),
Cisco's two-table fallback (ENVMON then FRU, class-filtered to power-supply
rows), the pulled-supply alert rule: a not-present/off-admin row writes
nothing while its key has never existed, but writes an explicit 3 (not
present) once it has, so an open psu_failed alert on a pulled supply stays
open instead of clearing, and the per-poll PSU cadence (state column every
call, static name/class columns cached).

No real SNMP session: _walk_column_detail is replaced on the NodePoller
instance directly (both _walk_column and _walk_column_status funnel
through it, the tests/test_poller_behaviour.py convention). self.db is the
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
        self._existing: dict[int, dict] = {}   # device_id -> {key: label}

    def metrics(self, device_id):
        return [{"key": k, "label": lbl}
                for k, lbl in self._existing.get(device_id, {}).items()]

    def record_metric_samples(self, device_id, samples):
        self.sample_calls.append((device_id, list(samples)))
        for row in samples:
            self._existing.setdefault(device_id, {})[row[0]] = row[1]

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

    def seed_existing(self, device_id, key, label=None):
        self._existing.setdefault(device_id, {})[key] = label or key


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
    """Stubs _walk_column_detail, which _walk_column/_walk_column_status
    both funnel through (the tests/test_poller_behaviour.py convention),
    so both wrappers see the same fake table. Every OID answers complete."""
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        return dict(columns.get(oid, {})), True, ""
    return fake


# ----------------------------------------------------- Cisco ENVMON states

envmon, fru = nodeoids.PSU_TABLES[9]
poller = new_poller()
poller._walk_column_detail = table_walker({
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
poller_fru._walk_column_detail = table_walker({
    fru.state: {"10": 2, "11": 9, "12": 8, "20": 2, "13": 1, "14": 3},
        # on, onButFanFail, failed, on, offEnvOther, offAdmin
    fru.name: {"10": "PSU-0", "11": "PSU-1", "12": "PSU-2", "20": "Fan Tray",
              "13": "PSU-3", "14": "PSU-4"},
    fru.class_col: {"10": 6, "11": 6, "12": 6, "20": 4, "13": 6, "14": 6},
        # 4 = fan, not powerSupply; the rest are powerSupply-class
})
dev_fru = device(CISCO_OID)
poller_fru._poll_vendor_sensors(2, dev_fru, CONFIG, 1_700_000_000.0)
samples_fru = poller_fru.db.samples_dict(2)
check("Cisco FRU: on(2) on a powerSupply-class row -> ok(0)",
      samples_fru.get("psu_state.10") == 0.0, samples_fru)
check("...onButFanFail(9) -> warning(1)", samples_fru.get("psu_state.11") == 1.0, samples_fru)
check("...failed(8) -> failed(2)", samples_fru.get("psu_state.12") == 2.0, samples_fru)
check("...offEnvOther(1) -> failed(2), no input", samples_fru.get("psu_state.13") == 2.0, samples_fru)
check("...offAdmin(3) -> warning(1), deliberately off", samples_fru.get("psu_state.14") == 1.0, samples_fru)
check("...a non-PSU FRU row (entPhysicalClass != powerSupply) is not "
      "written at all, however it reads",
      "psu_state.20" not in samples_fru, samples_fru)

# ---------------------------------------- pulled-supply clears an open alert
poller_clear = new_poller()
poller_clear.db.seed_existing(3, "psu_state.1")   # was written a previous poll
poller_clear._walk_column_detail = table_walker({
    envmon.state: {"1": 5},   # now notPresent
    envmon.name: {"1": "PSU1"},
})
dev_clear = device(CISCO_OID)
poller_clear._poll_vendor_sensors(3, dev_clear, CONFIG, 1_700_000_000.0)
samples_clear = poller_clear.db.samples_dict(3)
check("a supply that was present and now reads notPresent writes an "
      "explicit 3 (not present) to its EXISTING key, so psu_failed opens "
      "on a removed/unpowered supply instead of clearing",
      samples_clear.get("psu_state.1") == 3.0, samples_clear)

# ------------------------------------------------------- Juniper class filter
jn = nodeoids.PSU_TABLES[2636]
poller_jn = new_poller()
poller_jn._walk_column_detail = table_walker({
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
poller_ub._walk_column_detail = table_walker({
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
poller_mk._walk_column_detail = table_walker({
    mk.state: {"0": 1},                              # primary ok
    mk.extra_scalars[0][0]: {"0": 0},                 # backup absent reads false(0)
})
dev_mk = device("1.3.6.1.4.1.14988.1.1")
poller_mk._poll_vendor_sensors(6, dev_mk, CONFIG, 1_700_000_000.0)
samples_mk = poller_mk.db.samples_dict(6)
check("MikroTik: the primary is ok and a backup reading false writes nothing "
      "(a board with one supply must not alert on the second)",
      samples_mk.get("psu_state.0") == 0.0 and "psu_state.2" not in samples_mk,
      samples_mk)
poller_mk2 = new_poller()
poller_mk2._walk_column_detail = table_walker({
    mk.state: {"0": 1},
    mk.extra_scalars[0][0]: {"0": 1},                 # backup present and ok
})
poller_mk2._poll_vendor_sensors(6, dev_mk, CONFIG, 1_700_000_000.0)
check("...and a backup reading true is its own ok row",
      poller_mk2.db.samples_dict(6).get("psu_state.2") == 0.0, poller_mk2.db.samples_dict(6))

# --------------------------------------------------------------- VMware class
vm = nodeoids.PSU_TABLES[6876]
poller_vm = new_poller()
poller_vm._walk_column_detail = table_walker({
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
poller_none._walk_column_detail = table_walker({})
dev_none = device(CISCO_OID)
poller_none._poll_vendor_sensors(8, dev_none, CONFIG, 1_700_000_000.0)
check("a device answering neither table is latched incapable, once",
      poller_none.db.capable_calls == [(8, False)], poller_none.db.capable_calls)

# ------------------------------------------- per-poll PSU cadence (section 2)
def recording_walker(columns: dict, calls: list):
    """Same _walk_column_detail stub shape as table_walker, plus a record
    of every OID asked for."""
    def fake(device, config, oid, raise_on_timeout=False, deadline=None):
        calls.append(oid)
        return dict(columns.get(oid, {})), True, ""
    return fake

temp_table = nodeoids.SENSOR_TABLES[9]
walked = []
poller_cad = new_poller()
poller_cad._walk_column_detail = recording_walker({
    envmon.state: {"1": 1}, envmon.name: {"1": "PSU1"},
    temp_table.value: {"1": 42}, temp_table.state: {"1": 1},
}, walked)
dev_cad = device(CISCO_OID, sensor_capable=None, vendor_sensor_capable=None, id=9)
poller_cad._poll_vendor_sensors(9, dev_cad, CONFIG, 1_700_000_000.0)
check("cadence: first call walks the PSU state column", envmon.state in walked, walked)
check("cadence: first call walks the temperature table", temp_table.value in walked, walked)

walked.clear()
dev_cad2 = device(CISCO_OID, sensor_capable=None, vendor_sensor_capable=True, id=9)
poller_cad._poll_vendor_sensors(9, dev_cad2, CONFIG, 1_700_000_060.0)
check("cadence: second call, 60s later, still walks the PSU state column",
      envmon.state in walked, walked)
check("cadence: second call does NOT walk the temperature table (not due)",
      temp_table.value not in walked, walked)
check("cadence: second call does NOT re-walk the PSU name column (cache hit)",
      envmon.name not in walked, walked)

# a latched-incapable device waits the hourly reprobe, PSU state included
walked_nc = []
poller_nc = new_poller()
poller_nc._walk_column_detail = recording_walker({}, walked_nc)
dev_nc = device(CISCO_OID, vendor_sensor_capable=None, id=10)
poller_nc._poll_vendor_sensors(10, dev_nc, CONFIG, 1_700_000_000.0)
walked_nc.clear()
dev_nc2 = device(CISCO_OID, vendor_sensor_capable=0, id=10)
poller_nc._poll_vendor_sensors(10, dev_nc2, CONFIG, 1_700_000_060.0)
check("cadence: a latched-incapable device walks nothing on the second call, 60s later",
      walked_nc == [], walked_nc)

# ------------------------------------------------ static-column cache rules
walked_c = []
cols_c = {envmon.state: {"1": 1}, envmon.name: {}}   # name walk timed out
poller_c = new_poller()
poller_c._walk_column_detail = recording_walker(cols_c, walked_c)
dev_c = device(CISCO_OID, vendor_sensor_capable=True, id=11)
poller_c._poll_vendor_sensors(11, dev_c, CONFIG, 1_700_000_000.0)
check("cache: an empty static walk is not cached",
      (11, envmon.state) not in poller_c._vendor_psu_static, poller_c._vendor_psu_static)
cols_c[envmon.name] = {"1": "PSU1"}
walked_c.clear()
poller_c._poll_vendor_sensors(11, dev_c, CONFIG, 1_700_000_060.0)
check("cache: the name column is walked again on the next poll after an empty answer",
      envmon.name in walked_c, walked_c)
check("cache: a full answer is cached",
      (11, envmon.state) in poller_c._vendor_psu_static)
walked_c.clear()
poller_c._poll_vendor_sensors(11, dev_c, CONFIG, 1_700_000_120.0)
check("cache: inside the TTL the name column is not walked", envmon.name not in walked_c, walked_c)
walked_c.clear()
poller_c._poll_vendor_sensors(11, dev_c, CONFIG, 1_700_000_060.0 + 300.0)
check("cache: after _SENSOR_REFRESH_S the name column is walked again",
      envmon.name in walked_c, walked_c)
poller_c._forget_vendor_psu_static(11)
check("cache: _forget_vendor_psu_static drops the device's entries",
      not any(k[0] == 11 for k in poller_c._vendor_psu_static))
walked_c.clear()
poller_c._poll_vendor_sensors(11, dev_c, CONFIG, 1_700_000_400.0)
check("cache: a dropped entry is rebuilt on the next poll", envmon.name in walked_c, walked_c)

# ---------------------------------- vanish detection (5.35.0): a FRU row
# that stops being mentioned in the walk at all, not one that reports
# notPresent in it. Cisco's fan tables (primary/fallback) exercise the fan
# half; the FRU PSU table (class-filtered chassis PSU rows) exercises the
# PSU half.
fan_primary, fan_fallback = nodeoids.FAN_TABLES[9]

# --- PSU: a FRU supply present in poll 1, gone from a COMPLETE walk in poll 2
poller_pv = new_poller()
poller_pv._walk_column_detail = table_walker({
    fru.state: {"10": 2}, fru.name: {"10": "PSU-0"}, fru.class_col: {"10": 6},
})
dev_pv = device(CISCO_OID, id=20)
poller_pv._poll_vendor_sensors(20, dev_pv, CONFIG, 1_700_000_000.0)
check("PSU vanish, poll 1: the FRU supply is present and ok",
      poller_pv.db.samples_dict(20).get("psu_state.10") == 0.0,
      poller_pv.db.samples_dict(20))
poller_pv._walk_column_detail = table_walker({})   # complete, no rows at all
poller_pv.db.sample_calls.clear()
poller_pv._poll_vendor_sensors(20, dev_pv, CONFIG, 1_700_000_060.0)
psu_vanish_sample = next(
    (s for _did, samples in poller_pv.db.sample_calls for s in samples
     if _did == 20 and s[0] == "psu_state.10"), None)
check("PSU vanish, poll 2: a complete walk no longer mentioning the supply "
      "writes _PSU_STATE_ABSENT (3.0) under its stored label",
      psu_vanish_sample is not None and psu_vanish_sample[1] == "PSU-0"
      and psu_vanish_sample[5] == 3.0, psu_vanish_sample)

# --- PSU: the same disappearance, but the walk that would have shown it is
# cut short -- must change nothing at all.
poller_pc = new_poller()
poller_pc._walk_column_detail = table_walker({
    fru.state: {"10": 2}, fru.name: {"10": "PSU-0"}, fru.class_col: {"10": 6},
})
dev_pc = device(CISCO_OID, id=21)
poller_pc._poll_vendor_sensors(21, dev_pc, CONFIG, 1_700_000_000.0)
poller_pc._walk_column_detail = lambda *a, **kw: ({}, False, "cut short")
poller_pc.db.sample_calls.clear()
poller_pc._poll_vendor_sensors(21, dev_pc, CONFIG, 1_700_000_060.0)
check("PSU vanish, cut-short walk: no new sample is written for the bay",
      not any(s[0] == "psu_state.10" for _did, samples in poller_pc.db.sample_calls
              for s in samples if _did == 21),
      poller_pc.db.sample_calls)
check("...and the remembered seen set is left exactly as poll 1 left it, "
      "not cleared by the walk that could not confirm anything",
      poller_pc._vendor_psu_seen.get((21, fru.state)) == {"10"},
      poller_pc._vendor_psu_seen)

# --- Fan: a FRU tray present in poll 1, gone from a COMPLETE walk in poll 2
poller_fv = new_poller()
poller_fv._walk_column_detail = table_walker({
    fan_primary.state: {"1": 2}, fan_primary.name: {"1": "Fan Tray 1"},
    fan_primary.class_col: {"1": 7},
})
dev_fv = device(CISCO_OID, id=22)
poller_fv._poll_vendor_sensors(22, dev_fv, CONFIG, 1_700_000_000.0)
check("fan vanish, poll 1: the FRU fan tray is present and ok",
      poller_fv.db.samples_dict(22).get("fan_state.1") == 0.0,
      poller_fv.db.samples_dict(22))
poller_fv._walk_column_detail = table_walker({})   # complete, no rows at all
poller_fv.db.sample_calls.clear()
poller_fv._poll_vendor_sensors(22, dev_fv, CONFIG, 1_700_000_060.0)
fan_vanish_sample = next(
    (s for _did, samples in poller_fv.db.sample_calls for s in samples
     if _did == 22 and s[0] == "fan_state.1"), None)
check("fan vanish, poll 2: a complete walk no longer mentioning the tray "
      "writes _PSU_STATE_ABSENT (3.0) under its stored label",
      fan_vanish_sample is not None and fan_vanish_sample[1] == "Fan Tray 1"
      and fan_vanish_sample[5] == 3.0, fan_vanish_sample)

# --- Fan: the same disappearance, but cut short -- changes nothing, and
# never spills onto the fallback (ENVMON) table's own key either.
poller_fc = new_poller()
poller_fc._walk_column_detail = table_walker({
    fan_primary.state: {"1": 2}, fan_primary.name: {"1": "Fan Tray 1"},
    fan_primary.class_col: {"1": 7},
})
dev_fc = device(CISCO_OID, id=23)
poller_fc._poll_vendor_sensors(23, dev_fc, CONFIG, 1_700_000_000.0)
poller_fc._walk_column_detail = lambda *a, **kw: ({}, False, "cut short")
poller_fc.db.sample_calls.clear()
poller_fc._poll_vendor_sensors(23, dev_fc, CONFIG, 1_700_000_060.0)
check("fan vanish, cut-short walk: no new sample is written for the tray",
      not any(s[0] == "fan_state.1" for _did, samples in poller_fc.db.sample_calls
              for s in samples if _did == 23),
      poller_fc.db.sample_calls)
check("...the primary table's remembered seen set is untouched",
      poller_fc._vendor_psu_seen.get((23, fan_primary.state)) == {"1"},
      poller_fc._vendor_psu_seen)
check("...and the fallback table's own key was never even seeded by it",
      (23, fan_fallback.state) not in poller_fc._vendor_psu_seen,
      poller_fc._vendor_psu_seen)

# --- PSU: state column intact but the class column times out once the
# static cache has expired (5.35.0 review fix) -- must not read as "no rows
# survived class-filtering" and wipe the seen set with ABSENT(3.0)s. Only
# fru.class_col is failed; fan_primary shares that OID, so its rows read
# incomplete too and its own seen set (untested here) is equally untouched.
poller_ctx = new_poller()
ctx_cols = {fru.state: {"10": 2}, fru.name: {"10": "PSU-0"}, fru.class_col: {"10": 6}}
poller_ctx._walk_column_detail = table_walker(ctx_cols)
dev_ctx = device(CISCO_OID, id=25)
poller_ctx._poll_vendor_sensors(25, dev_ctx, CONFIG, 1_700_000_000.0)


def fake_class_timeout(device, config, oid, raise_on_timeout=False, deadline=None):
    if oid == fru.class_col:
        return {}, False, "cut short"
    return dict(ctx_cols.get(oid, {})), True, ""


poller_ctx._walk_column_detail = fake_class_timeout
poller_ctx.db.sample_calls.clear()
poller_ctx._poll_vendor_sensors(25, dev_ctx, CONFIG, 1_700_000_000.0 + 301.0)
check("class-column timeout, state intact: no ABSENT sample is written",
      not any(s[0] == "psu_state.10" for _did, samples in poller_ctx.db.sample_calls
              for s in samples if _did == 25),
      poller_ctx.db.sample_calls)
check("...and the seen set is left exactly as poll 1 left it",
      poller_ctx._vendor_psu_seen.get((25, fru.state)) == {"10"},
      poller_ctx._vendor_psu_seen)

# --- a partial (incomplete) class walk must not be cached as complete ----
# (5.35.0 review fix): caching it forced static_complete True on the next
# poll's cache hit, so an unreached supply read as filtered-out-and-gone.
poller_pcache = new_poller()
pcache_cols = {fru.state: {"10": 2, "11": 2}, fru.name: {"10": "PSU-0", "11": "PSU-1"},
              fru.class_col: {"10": 6, "11": 6}}
poller_pcache._walk_column_detail = table_walker(pcache_cols)
dev_pcache = device(CISCO_OID, id=26)
poller_pcache._poll_vendor_sensors(26, dev_pcache, CONFIG, 1_700_000_000.0)
poller_pcache._forget_vendor_psu_static(26)


def one_of_two_class_rows(device, config, oid, raise_on_timeout=False, deadline=None):
    if oid == fru.class_col:
        return {"10": 6}, False, "cut short"   # only 1 of 2 rows reached
    return dict(pcache_cols.get(oid, {})), True, ""


poller_pcache._walk_column_detail = one_of_two_class_rows
poller_pcache.db.sample_calls.clear()
poller_pcache._poll_vendor_sensors(26, dev_pcache, CONFIG, 1_700_000_060.0)
check("partial class walk: not cached as complete",
      (26, fru.state) not in poller_pcache._vendor_psu_static,
      poller_pcache._vendor_psu_static)

poller_pcache._walk_column_detail = table_walker(pcache_cols)
poller_pcache.db.sample_calls.clear()
poller_pcache._poll_vendor_sensors(26, dev_pcache, CONFIG, 1_700_000_120.0)
check("...poll 60s later, everything complete: the unreached supply reads "
      "ok, not a stale ABSENT off a cached partial class map",
      poller_pcache.db.samples_dict(26).get("psu_state.11") == 0.0,
      poller_pcache.db.samples_dict(26))

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

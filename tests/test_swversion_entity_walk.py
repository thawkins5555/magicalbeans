"""netpath/nodepoll.py's _poll_software_version: the two bounded walks it
adds behind the vendor GET (a vendor's own table column, else ENTITY-MIB's
chassis row) are gated to at most once a day per device, again sooner on a
sysDescr change or a reboot, and a poll that does not walk returns no keys
so a stored value is never overwritten with nothing.

No real SNMP session: _identity_extras_detail (the one GET),
_identity_extras (the targeted per-index GET) and _walk_column (both
bounded walks) are replaced on the NodePoller instance directly, the way
tests/test_snmpv3_diagnostics.py replaces pieces of the poller rather than
running a whole device against a stub agent -- this suite is about the
walk gate, not the wire format.
"""
import sys

import _paths  # noqa: F401  (repo root on sys.path)

import netpath.nodepoll as nodepoll_mod
from netpath import nodeoids
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _FakeDB:
    """_poll_software_version and its helpers never touch self.db."""


class _FakeClock:
    """A settable stand-in for time.time(), so the 24h/reboot gate can be
    driven without a real day passing or a real clock's jitter."""
    def __init__(self, start: float):
        self.now = start

    def __call__(self) -> float:
        return self.now


def new_poller() -> NodePoller:
    return NodePoller(_FakeDB())


DEVICE = {"id": 1, "ip": "10.0.0.1"}
CONFIG = {"poll_interval_s": 120}

_real_time = nodepoll_mod.time.time

# ------------------------------------------------------- ENTITY-MIB fallback

clock = _FakeClock(1_700_000_000.0)
nodepoll_mod.time.time = clock

poller = new_poller()
poller._identity_extras_detail = lambda device, config, oids: ({}, True)

ENT_SW = nodeoids.ENT_PHYSICAL_SOFTWARE_REV
ENT_FW = nodeoids.ENT_PHYSICAL_FIRMWARE_REV
calls = {"class_walk": 0, "sw_walk": 0, "targeted_get": 0}


def fake_walk_column(device, config, base_oid, raise_on_timeout=False, deadline=None):
    if base_oid == poller._ENT_PHYSICAL_CLASS:
        calls["class_walk"] += 1
        return {"1": 3, "2": 9}  # index 1 is the chassis (class 3)
    if base_oid == ENT_SW:
        calls["sw_walk"] += 1
        return {}
    return {}


def fake_identity_extras(device, config, oids):
    calls["targeted_get"] += 1
    return {f"{ENT_SW}.1": "V200R019C00SPC500", f"{ENT_FW}.1": ""}


poller._walk_column = fake_walk_column
poller._identity_extras = fake_identity_extras

identity = {"vendor_arc": None, "sys_descr": "Some switch nobody wrote a rule for",
           "sys_uptime_ticks": 500000}

result = poller._poll_software_version(DEVICE, CONFIG, identity)
check("vendor GET empty: the ENTITY-MIB walk runs and the chassis row's "
      "value is stored",
      result.get("sw_version") == "V200R019C00SPC500" and
      result.get("sw_source") == "entPhysicalSoftwareRev", result)
check("...walking entPhysicalClass once to find it",
      calls["class_walk"] == 1, calls)
check("...and GETting the chassis row's software/firmware revs, not "
      "walking the whole column",
      calls["targeted_get"] == 1 and calls["sw_walk"] == 0, calls)

clock.now += 60  # a poll a minute later, same device, same sysDescr
result2 = poller._poll_software_version(DEVICE, CONFIG, identity)
check("a second poll within 24h does not walk again, and returns no keys "
      "so the stored value survives",
      result2 == {} and calls["class_walk"] == 1 and calls["targeted_get"] == 1,
      (result2, calls))

clock.now += 120  # still well inside 24h
rebooted_identity = {**identity, "sys_uptime_ticks": 100}
result3 = poller._poll_software_version(DEVICE, CONFIG, rebooted_identity)
check("a reboot (uptime dropped) re-walks even though the gate's 24h has "
      "not elapsed -- as a GET, since the chassis index from the first "
      "walk is cached",
      calls["class_walk"] == 1 and calls["targeted_get"] == 2, calls)
check("...and answers the chassis row again",
      result3.get("sw_version") == "V200R019C00SPC500", result3)

# ------------------------------------------------------------ column vendor

poller2 = new_poller()
poller2._identity_extras_detail = lambda device, config, oids: ({}, True)

DELL_SW = nodeoids.SW_VERSION_COLUMNS[6027][0][0]
column_calls = {"dell": 0, "class_walk": 0}


def fake_walk_column_dell(device, config, base_oid, raise_on_timeout=False, deadline=None):
    if base_oid == DELL_SW:
        column_calls["dell"] += 1
        return {"1": "10.5.1.6"}
    if base_oid == poller2._ENT_PHYSICAL_CLASS:
        column_calls["class_walk"] += 1
        return {}
    return {}


poller2._walk_column = fake_walk_column_dell

dell_identity = {"vendor_arc": 6027, "sys_descr": "Dell Networking S4048",
                 "sys_uptime_ticks": 1000}
dell_result = poller2._poll_software_version(DEVICE, CONFIG, dell_identity)
check("a column vendor (Dell) reads the walked column, not ENTITY-MIB",
      dell_result.get("sw_version") == "10.5.1.6" and
      dell_result.get("sw_source") == "vendor_oid", dell_result)
check("...and never pays for the entPhysicalClass walk once the column "
      "answered",
      column_calls["dell"] == 1 and column_calls["class_walk"] == 0,
      column_calls)
dell_again = poller2._poll_software_version(DEVICE, CONFIG, dell_identity)
check("...and a second poll within the day does not walk the column again",
      dell_again == {} and column_calls["dell"] == 1, (dell_again, column_calls))

# ------------------------------------------------------------------ sysDescr

poller3 = new_poller()
poller3._identity_extras_detail = lambda device, config, oids: ({}, True)
descr_calls = {"class_walk": 0}


def fake_walk_column_descr(device, config, base_oid, raise_on_timeout=False, deadline=None):
    if base_oid == poller3._ENT_PHYSICAL_CLASS:
        descr_calls["class_walk"] += 1
        return {}
    return {}


poller3._walk_column = fake_walk_column_descr
poller3._identity_extras = lambda device, config, oids: {}

base_identity = {"vendor_arc": None, "sys_descr": "Widget v1", "sys_uptime_ticks": 10}
poller3._poll_software_version(DEVICE, CONFIG, base_identity)
changed_identity = {**base_identity, "sys_descr": "Widget v2"}
poller3._poll_software_version(DEVICE, CONFIG, changed_identity)
check("a sysDescr change (a new image, or a different device on the IP) "
      "re-walks inside the 24h window too",
      descr_calls["class_walk"] == 2, descr_calls)

# ------------------------------------------ firmware-only column + no answer

poller4 = new_poller()
poller4._identity_extras_detail = lambda device, config, oids: ({}, True)
VERTIV_FW = nodeoids.SW_VERSION_COLUMNS[476][0][1]
vertiv_calls = {"fw": 0, "class_walk": 0}


def fake_walk_column_vertiv(device, config, base_oid, raise_on_timeout=False, deadline=None):
    if base_oid == VERTIV_FW:
        vertiv_calls["fw"] += 1
        return {"1": "UPS 4.1.2"}
    if base_oid == poller4._ENT_PHYSICAL_CLASS:
        vertiv_calls["class_walk"] += 1
        return {"1": "3"}
    return {}


poller4._walk_column = fake_walk_column_vertiv
poller4._identity_extras = lambda device, config, oids: {
    f"{ENT_SW}.1": "AGENT 9.9", f"{ENT_FW}.1": ""}
vertiv = poller4._poll_software_version(
    DEVICE, CONFIG, {"vendor_arc": 476, "sys_descr": "Liebert GXT4", "sys_uptime_ticks": 10})
check("a firmware-only column vendor keeps its column firmware when the "
      "ENTITY walk then supplies the software version",
      vertiv.get("fw_version") == "UPS 4.1.2" and vertiv.get("sw_version") == "AGENT 9.9"
      and vertiv_calls == {"fw": 1, "class_walk": 1}, (vertiv, vertiv_calls))

poller5 = new_poller()
poller5._identity_extras_detail = lambda device, config, oids: ({}, False)
silent_calls = {"walks": 0}


def fake_walk_column_silent(device, config, base_oid, raise_on_timeout=False, deadline=None):
    silent_calls["walks"] += 1
    return {}


poller5._walk_column = fake_walk_column_silent
silent = poller5._poll_software_version(
    DEVICE, CONFIG, {"vendor_arc": None, "sys_descr": "x", "sys_uptime_ticks": 10})
check("a GET that got no reply at all suppresses the walk and keeps the stored values",
      silent == {} and silent_calls["walks"] == 0, (silent, silent_calls))

nodepoll_mod.time.time = _real_time

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

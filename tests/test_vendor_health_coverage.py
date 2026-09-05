"""The vendor-health coverage sweep's two additions to nodeoids.VENDOR_HEALTH:
CISCO-ENVMON-MIB temperature (Cisco had none at all — 862 of the review's
2,000-device estate are Cisco 2960X access switches) and JUNIPER-MIB
jnxOperatingBuffer memory (Juniper had cpu_pct/temp_chassis_c but no
mem_pct). Both decoded off real BER wire responses through the actual poll
path (nodepoll._poll_vendor_health), not asserted by inspection.
"""
from _paths import spawn_stub, tmpdir

TMP = tmpdir("vendor_health_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


# ------------------------------------------------------------------- Cisco

stub, port = spawn_stub("stub_agent_vendor_health.py", "cisco")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cisco")
    did = device_against(db, "cisco-sw-1")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, _uptime, metrics = poller._poll_snmp_scalars(device, config)
    values = {key: value for key, label, unit, kind, value in metrics}
    check("the device identifies as Cisco (enterprise arc 9)",
          identity.get("vendor_arc") == 9, identity)
    check("cpu_pct from cpmCPUTotal5minRev, first row (column_first): 30, not 50",
          values.get("cpu_pct") == 30.0, values)
    check("temp_chassis_c from ciscoEnvMonTemperatureStatusValue, worst row "
          "(column_max): 52, not 45 -- the metric Cisco had zero of before "
          "this sweep",
          values.get("temp_chassis_c") == 52.0, values)
    db.close()
finally:
    stub.kill()

# ----------------------------------------------------------------- Juniper

stub, port = spawn_stub("stub_agent_vendor_health.py", "juniper")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("juniper")
    did = device_against(db, "juniper-sw-1")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, _uptime, metrics = poller._poll_snmp_scalars(device, config)
    values = {key: value for key, label, unit, kind, value in metrics}
    check("the device identifies as Juniper (enterprise arc 2636)",
          identity.get("vendor_arc") == 2636, identity)
    check("cpu_pct from jnxOperatingCPU, first row (column_first): 20, not 40",
          values.get("cpu_pct") == 20.0, values)
    check("temp_chassis_c from jnxOperatingTemp, worst row (column_max): "
          "44, not 38 -- unchanged by this sweep, checked as a regression",
          values.get("temp_chassis_c") == 44.0, values)
    check("mem_pct from jnxOperatingBuffer, worst row (column_max): 70, "
          "not 55 -- the metric Juniper had none of before this sweep",
          values.get("mem_pct") == 70.0, values)
    db.close()
finally:
    stub.kill()

# ------------------------------------------- vendor_arc persisted, either way

# The Rockwell finding: a device identified by sysDescr text alone (a PLC on
# a generic net-snmp agent, say) gets vendor_arc=None from vendorid.decide()
# -- and VENDOR_HEALTH is keyed by arc, so nothing could ever be looked up
# for it, no matter how good the vendor-specific OID knowledge is. That was
# invisible to a device pane because vendor_arc was computed fresh every
# poll and thrown away. This section proves it now survives to the device
# row, both when a real arc was found and when it deliberately was not.

stub, port = spawn_stub("stub_agent_vendor_health.py", "cisco")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("vendor_arc_real")
    did = device_against(db, "cisco-sw-2")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)
    identity, uptime_ticks, _metrics = poller._poll_snmp_scalars(device, config)
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity=identity, uptime_ticks=uptime_ticks,
                   status="up", reachable=True)
    check("a device identified from a real sysObjectID arc persists that "
          "arc on the device row (9, Cisco)",
          db.device(did)["vendor_arc"] == 9, dict(db.device(did)))
    db.close()
finally:
    stub.kill()

db = new_db("vendor_arc_none")
did = device_against(db, "rockwell-plc-1")
synthetic_identity = {
    "sys_descr": "Rockwell Automation 1756-EN2T/B EtherNet/IP Bridge",
    "sys_name": "plc-1", "sys_object_id": "1.3.6.1.4.1.8072.3.2.10",
    "sys_contact": "", "sys_location": "",
    "vendor": "rockwellAutomation", "vendor_detected": "rockwellAutomation",
    "vendor_source": "sysDescr", "vendor_confidence": "low",
    "vendor_arc": None,   # the exact case vendorid.decide() produces for this
}
db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
              snmp_error="", identity=synthetic_identity, uptime_ticks=None,
              status="up", reachable=True)
row = db.device(did)
check("a device named with confidence from sysDescr text alone, with no "
      "real enterprise arc behind it, persists vendor_arc as NULL -- "
      "distinguishable from the real-arc case above by more than "
      "vendor_source alone (both say 'sysDescr')",
      row["vendor_source"] == "sysDescr" and row["vendor_confidence"] == "low"
      and row["vendor_arc"] is None, dict(row))
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

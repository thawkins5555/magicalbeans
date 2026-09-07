"""Device dialog HARDWARE SENSORS / DOM-SFP SENSORS backing: nodepoll's
read_hardware() and read_dom_all(), the api.py routes that expose them, and
the "answers nothing" cases both must handle cleanly.

Covers: read_hardware's three sections (polled metrics filtered to the
hardware-ish keys; every ENTITY-SENSOR-MIB row, named from entPhysicalName
where the device offers it and mapped to a port through the same
containment chain read_dom() walks, including a sensor reached only by
entPhysicalContainedIn rather than its own alias row; CISCO-ENVMON-MIB,
gated on detected_vendor == "cisco" and never walked otherwise);
read_dom_all()'s one-set-of-walks device-wide DOM table and its agreement
with read_dom() on value/unit/status for the same sensor; the two api.py
routes; a device with no SNMP and a device with no sensors at all.
"""
import socket
import time

from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.web import api

TMP = tmpdir("hw_dom_sensors_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_nodes_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def stub_stat(port: int, command: bytes) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(command, ("127.0.0.1", port))
    try:
        return s.recv(256).decode("utf-8", "replace")
    finally:
        s.close()


def request_count(port: int) -> int:
    return int(stub_stat(port, b"STATS"))


def reset_count(port: int) -> None:
    stub_stat(port, b"RESET")


def device_against(db: NodesDatabase, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


def mark_cisco(db: NodesDatabase, did: int) -> None:
    """Sets vendor_detected without a real identify walk -- the idiom
    test_vendor_health_coverage.py's synthetic-identity section uses.
    detected_vendor() reads vendor_detected first, so this alone is enough
    to drive read_hardware's ENVMON gate."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)


class FakeService:
    """Just enough of web.Service for the two route functions under test:
    both only touch .nodes_db and .node_poller."""
    def __init__(self, nodes_db, node_poller):
        self.nodes_db = nodes_db
        self.node_poller = node_poller


# ======================================================= § 1 read_hardware

stub, port = spawn_stub("stub_agent_ups_env.py", "hardware")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("hardware")
    did = device_against(db, "hw-1")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"},
                                {"if_index": 2, "descr": "Gi0/2"}])
    poller = NodePoller(db)

    # --- metrics section: only the hardware-ish keys, cpu/mem first -----
    now = time.time()
    db.record_metric_samples(did, [
        ("mem_pct", "Memory", "%", "gauge", now, 61.0),
        ("cpu_pct", "CPU", "%", "gauge", now, 12.0),
        ("temp_chassis_c", "Chassis temperature", "°C", "gauge", now, 41.5),
        ("ping_loss_pct", "Packet loss", "%", "gauge", now, 0.0),
        ("if_in_bps.1", "Gi0/1 in", "bps", "counter_rate", now, 1000.0),
    ])
    result = poller.read_hardware(did)
    keys = [m["key"] for m in result["metrics"]]
    check("read_hardware's metrics keep only cpu_pct/mem_pct/temp_*, "
          "never a ping or interface-counter key",
          keys == ["cpu_pct", "mem_pct", "temp_chassis_c"], keys)
    check("cpu_pct and mem_pct come first regardless of insertion order",
          result["metrics"][0]["key"] == "cpu_pct"
          and result["metrics"][0]["value"] == 12.0, result["metrics"])

    # --- sensors section: every ENTITY-SENSOR-MIB row, named/mapped ----
    sensors = {s["entity"]: s for s in result["sensors"]}
    check("every entity the device answers is present, including the "
          "nonoperational one read_dom's own filter would drop",
          set(sensors) == {1, 2, 3, 4, 5}, sorted(sensors))
    check("entity 1 is named from entPhysicalName, not entPhysicalDescr, "
          "when the device populates it",
          sensors[1]["label"] == "Gi0/1 SFP module", sensors[1])
    check("entity 1 maps to ifIndex 1 (its own entAliasMappingIdentifier "
          "row), with the stored interface's descr as if_name",
          sensors[1]["if_index"] == 1 and sensors[1]["if_name"] == "Gi0/1",
          sensors[1])
    check("entity 5 has no alias row of its own, but is contained in "
          "entity 1 -- the chain-resolution case -- so it also maps to "
          "ifIndex 1",
          sensors[5]["if_index"] == 1, sensors[5])
    check("entity 5's type name comes from entPhySensorType (5 = current)",
          sensors[5]["type"] == "current" and sensors[5]["value"] == 35.0,
          sensors[5])
    check("entities 2-4 map to no port at all",
          all(sensors[e]["if_index"] is None for e in (2, 3, 4)), sensors)
    check("entity 3's nonoperational status is reported, not hidden",
          sensors[3]["status"] == "nonoperational", sensors[3])

    # --- envmon: gated on detected_vendor, off by default ---------------
    check("a device not identified as Cisco gets no ENVMON walk at all, "
          "even though this stub would answer one",
          result["envmon"] == [], result["envmon"])

    reset_count(port)
    before = request_count(port)
    poller.read_hardware(did)
    after = request_count(port)

    mark_cisco(db, did)
    reset_count(port)
    cisco_result = poller.read_hardware(did)
    cisco_requests = request_count(port)
    check("...but once detected_vendor is cisco, ENVMON is walked (more "
          "requests than the non-Cisco run needed)",
          cisco_requests > after - before, (cisco_requests, after - before))

    envmon = {row["kind"]: row for row in cisco_result["envmon"]}
    check("supply status decodes descr + the shared state enum",
          envmon.get("supply") == {"kind": "supply", "label": "PSU 1",
                                   "value": None, "unit": "", "status": "normal"},
          envmon.get("supply"))
    check("fan status the same way, a different state",
          envmon.get("fan") == {"kind": "fan", "label": "Fan tray 1",
                                "value": None, "unit": "", "status": "warning"},
          envmon.get("fan"))
    check("temperature status also carries value/threshold",
          envmon.get("temperature") == {
              "kind": "temperature", "label": "Hot spot", "value": 55,
              "unit": "°C", "threshold": 70, "status": "critical"},
          envmon.get("temperature"))
    db.close()
finally:
    stub.kill()

# ======================================================= § 2 read_dom_all

stub, port = spawn_stub("stub_agent_ups_env.py", "hardware")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("dom_all")
    did = device_against(db, "hw-2")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"},
                                {"if_index": 2, "descr": "Gi0/2"}])
    poller = NodePoller(db)

    rows = poller.read_dom_all(did)
    by_entity_label = {r["label"]: r for r in rows}
    check("read_dom_all keeps only the port-mapped rows -- 2 of the "
          "device's 5 sensors -- not the whole-device sensor list again",
          len(rows) == 2, rows)
    check("every row carries the port it belongs to",
          all(r["if_index"] == 1 and r["if_name"] == "Gi0/1" for r in rows),
          rows)

    dom_rows = poller.read_dom(did, 1)
    dom_by_value = {r["value"]: r for r in dom_rows}
    all_by_value = {r["value"]: r for r in rows}
    check("read_dom (the interface dialog's own one-port read) sees the "
          "same two readings on ifIndex 1 as read_dom_all",
          set(dom_by_value) == set(all_by_value) == {45.1, 35.0},
          (sorted(dom_by_value), sorted(all_by_value)))
    for value in (45.1, 35.0):
        check(f"value {value}: read_dom and read_dom_all agree on unit/status "
              f"(only label sourcing differs -- read_dom never reads "
              f"entPhysicalName, by design; see read_dom_all's docstring)",
              dom_by_value[value]["unit"] == all_by_value[value]["unit"]
              and dom_by_value[value]["status"] == all_by_value[value]["status"],
              (dom_by_value[value], all_by_value[value]))
    check("read_dom's own row for entity 1 still names it from "
          "entPhysicalDescr ('Xcvr temp') -- untouched, per the interface "
          "dialog's DOM section staying exactly as it was",
          dom_by_value[45.1]["label"] == "Xcvr temp", dom_by_value[45.1])
    check("read_dom_all's row for the same entity prefers entPhysicalName",
          all_by_value[45.1]["label"] == "Gi0/1 SFP module", all_by_value[45.1])
    db.close()
finally:
    stub.kill()

# ==================================================== § 3 API route shapes

stub, port = spawn_stub("stub_agent_ups_env.py", "hardware")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("api")
    did = device_against(db, "hw-3")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"}])
    poller = NodePoller(db)
    service = FakeService(db, poller)

    hw = api.get_nodes_device_hardware(service, {}, {}, did)
    check("the hardware route answers the same three-list shape "
          "read_hardware itself returns",
          set(hw) == {"metrics", "sensors", "envmon"}
          and len(hw["sensors"]) == 5, hw if set(hw) != {"metrics", "sensors", "envmon"} else "")

    dom = api.get_nodes_device_dom_all(service, {}, {}, did)
    check("the device-wide dom route wraps read_dom_all's rows in "
          "{'sensors': [...]}, the same envelope get_nodes_device_dom uses",
          list(dom) == ["sensors"] and len(dom["sensors"]) == 2, dom)

    try:
        api.get_nodes_device_hardware(service, {}, {}, did + 999)
        check("an unknown device 404s (raises) rather than answering empty",
              False)
    except ValueError as exc:
        check("an unknown device 404s (raises) rather than answering empty",
              "No such device" in str(exc), str(exc))
    db.close()
finally:
    stub.kill()

# ============================================ § 4 nothing to answer, cleanly

# No ENTITY-SENSOR-MIB, no CISCO-ENVMON, no stored metrics at all.
stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("empty")
    did = device_against(db, "plain-switch")
    poller = NodePoller(db)

    result = poller.read_hardware(did)
    check("a device that answers no sensor of any kind gets three empty "
          "lists, never an exception",
          result == {"metrics": [], "sensors": [], "envmon": []}, result)
    check("read_dom_all agrees: empty, not an error",
          poller.read_dom_all(did) == [], poller.read_dom_all(did))

    mark_cisco(db, did)
    reset_count(port)
    cisco_empty = poller.read_hardware(did)
    check("even a Cisco-identified device with no ENVMON support answers "
          "an empty envmon list rather than raising",
          cisco_empty["envmon"] == [], cisco_empty)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------- ping-only: no SNMP at all

stub, port = spawn_stub("stub_agent_ups_env.py", "hardware")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("ping_only")
    did = device_against(db, "ping-only-1")
    db.update_device(did, snmp_enabled=0)
    poller = NodePoller(db)

    reset_count(port)
    result = poller.read_hardware(did)
    check("a ping-only device (snmp disabled) gets empty sensors/envmon "
          "without ever querying the device",
          result["sensors"] == [] and result["envmon"] == []
          and request_count(port) == 0, (result, request_count(port)))
    check("read_dom_all agrees, and also costs nothing",
          poller.read_dom_all(did) == [] and request_count(port) == 0,
          request_count(port))
    db.close()
finally:
    stub.kill()

# ============ § 5 per-port DOM metrics, interfaces.media and the API (5.1.0)

# The same walk that has always produced temp_optic_c now also writes one
# metric per reading per port, and marks the ports a sensor mapped to as
# carrying an optic -- the only signal this app has for the SFP badge,
# since IF-MIB has no media column.
stub, port = spawn_stub("stub_agent_ups_env.py", "hardware")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("per_port")
    did = device_against(db, "hw-4")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"},
                                {"if_index": 2, "descr": "Gi0/2"}])
    # Port 2 is stale: it was an optic on some earlier walk and no longer
    # is. This walk has to clear it, or a badge outlives the transceiver.
    db.update_interface_media(did, [{"if_index": 2, "media": "optic"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    metrics = {m["key"]: m["last_value"] for m in db.metrics(did)}

    check("the port-mapped transceiver temperature is written per port as "
          "sfp_temp_c.<ifIndex>",
          metrics.get("sfp_temp_c.1") == 45.1, sorted(metrics))
    check("...and still feeds the device-wide temp_optic_c unchanged",
          metrics.get("temp_optic_c") == 45.1, sorted(metrics))
    check("the amperes reading reached only through entPhysicalContainedIn "
          "becomes sfp_bias_ma.1 in milliamps: 35 A -> 35000 mA",
          metrics.get("sfp_bias_ma.1") == 35000.0, metrics.get("sfp_bias_ma.1"))
    check("this device answers no voltage or optical-power sensor, so none "
          "of those keys is invented for it",
          not [k for k in metrics
               if k.startswith(("sfp_volt", "sfp_rx_dbm", "sfp_tx_dbm"))],
          sorted(metrics))
    check("the label names the port, so an alert on this key can say which "
          "one it is",
          {m["key"]: m["label"] for m in db.metrics(did)}.get("sfp_temp_c.1")
          == "Gi0/1 optic temperature",
          {m["key"]: m["label"] for m in db.metrics(did)})

    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("the port the sensors mapped to is marked 'optic'",
          media.get(1) == "optic", media)
    check("...and the port that mapped nothing this walk is cleared, not "
          "left showing a badge for an optic that has gone",
          media.get(2) is None, media)

    ifaces = api.get_nodes_device_interfaces(
        FakeService(db, poller), {}, {}, did)["interfaces"]
    by_index = {i["if_index"]: i for i in ifaces}
    check("the interface route carries media, which is what the SFP badge "
          "in the interface list reads",
          by_index[1]["media"] == "optic" and by_index[2]["media"] is None,
          ifaces)
    db.close()
finally:
    stub.kill()

# --- a walk that answered nothing must never strip the badge --------------
stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("media_keep")
    did = device_against(db, "hw-5")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"}])
    db.update_interface_media(did, [{"if_index": 1, "media": "optic"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    check("a device that answers no sensor table at all keeps the media it "
          "already had -- a timeout is not evidence the optic was pulled",
          db.interfaces(did)[0]["media"] == "optic",
          db.interfaces(did)[0]["media"])
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

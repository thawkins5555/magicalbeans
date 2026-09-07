"""CISCO-ENTITY-SENSOR-MIB fallback: the DOM/SFP and hardware-sensor reads
on gear that populates 1.3.6.1.4.1.9.9.91 instead of RFC 3433's
1.3.6.1.2.1.99, which is what every Cisco switch in the field actually does
and why both dialog sections were empty on an all-Cisco fleet.

Covers: the fallback gate (detected vendor OR a Cisco sysObjectID, and
nothing at all for anyone else -- asserted with a request count, since an
ungated fallback would cost every non-Cisco device a second dead walk);
dBm(14) decoding through the ordinary RFC 3433 arithmetic in both the IOS
and the NX-OS encoding of the same kind of reading; the entPhysicalName ->
ifDescr fallback that maps a sensor to its port when the device answers no
entAliasMappingIdentifier row whatsoever; read_hardware / read_dom_all /
read_dom agreeing over the Cisco table; _poll_environment's classification
and its hourly re-probe of a device that once answered nothing; and the two
Nodes event-log lines that say why a read came back empty.
"""
import socket
import time

from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

TMP = tmpdir("cisco_entity_sensor_")

FAILS = []

CISCO_SYS_OBJECT_ID = "1.3.6.1.4.1.9.1.1"
PORT_DESCR = "TenGigabitEthernet1/1/1"


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


def record_identity(db: NodesDatabase, did: int, **identity) -> None:
    """Writes identity columns without a real identify walk -- the idiom
    test_hardware_dom_sensors.py's mark_cisco uses, widened here because
    the two halves of the fallback gate (vendor_detected, sys_object_id)
    have to be exercised one at a time."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity=identity, uptime_ticks=None,
                   status="up", reachable=True)


def mark_cisco(db: NodesDatabase, did: int) -> None:
    record_identity(db, did, vendor_detected="cisco")


class CaptureLog:
    """Just enough of eventlog to read back what the poller wrote."""

    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append(message)


# ============================================== § 1 the fallback gate

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    # One device per database: devices.ip is unique and every one of these
    # has to be the same 127.0.0.1 the stub is listening on.
    oid_db = new_nodes_db("gate_sysoid")
    by_oid = device_against(oid_db, "by-sysoid")
    oid_db.replace_interfaces(by_oid, [{"if_index": 1, "descr": PORT_DESCR}])
    record_identity(oid_db, by_oid, sys_object_id=CISCO_SYS_OBJECT_ID)
    oid_sensors = NodePoller(oid_db).read_hardware(by_oid)["sensors"]
    check("a Cisco sysObjectID alone is enough to try the Cisco table -- "
          "a switch polled but never identified still gets its sensors",
          len(oid_sensors) == 6, oid_sensors)
    oid_db.close()

    vendor_db = new_nodes_db("gate_vendor")
    by_vendor = device_against(vendor_db, "by-vendor")
    vendor_db.replace_interfaces(by_vendor, [{"if_index": 1, "descr": PORT_DESCR}])
    mark_cisco(vendor_db, by_vendor)
    vendor_sensors = NodePoller(vendor_db).read_hardware(by_vendor)["sensors"]
    check("detected_vendor == cisco alone is enough too, with no "
          "sysObjectID stored at all",
          len(vendor_sensors) == 6, vendor_sensors)
    vendor_db.close()

    # --- and nothing for anyone else --------------------------------------
    plain_db = new_nodes_db("gate_plain")
    plain = device_against(plain_db, "not-cisco")
    plain_db.replace_interfaces(plain, [{"if_index": 1, "descr": PORT_DESCR}])
    poller = NodePoller(plain_db)
    reset_count(port)
    plain_sensors = poller.read_hardware(plain)["sensors"]
    plain_requests = request_count(port)
    check("a device that is neither identified as Cisco nor answering a "
          "Cisco sysObjectID gets nothing from this stub",
          plain_sensors == [], plain_sensors)
    check("...and pays exactly ONE request for it: the standard "
          "entPhySensorValue walk it always did, with no second walk of a "
          "vendor table that could only time out",
          plain_requests == 1, plain_requests)
    check("read_dom_all agrees for the same device, still empty",
          poller.read_dom_all(plain) == [], poller.read_dom_all(plain))
    plain_db.close()
finally:
    stub.kill()

# ================================= § 2 read_hardware over the Cisco table

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("hardware")
    did = device_against(db, "cisco-sw")
    db.replace_interfaces(did, [{"if_index": 1, "descr": PORT_DESCR}])
    mark_cisco(db, did)
    poller = NodePoller(db)

    sensors = {s["entity"]: s for s in poller.read_hardware(did)["sensors"]}
    check("every CISCO-ENTITY-SENSOR-MIB row is read: five optic sensors "
          "plus the chassis inlet probe",
          set(sensors) == {1010, 1011, 1012, 1013, 1014, 2000}, sorted(sensors))
    check("each row says which MIB it came out of",
          all(s["source"] == "CISCO-ENTITY-SENSOR-MIB" for s in sensors.values()),
          {e: s["source"] for e, s in sensors.items()})
    check("celsius(8) decodes as it always did: 33 C",
          sensors[1010]["value"] == 33.0 and sensors[1010]["unit"] == "°C"
          and sensors[1010]["type"] == "temperature", sensors[1010])
    check("voltsDC(4) through a milli scale: 3299 -> 3.299 V DC",
          sensors[1011]["value"] == 3.299 and sensors[1011]["unit"] == "V DC",
          sensors[1011])
    check("amperes(5) through milli AND one decimal of precision: "
          "62 -> 0.0062 A",
          sensors[1012]["value"] == 0.0062 and sensors[1012]["unit"] == "A",
          sensors[1012])
    check("dBm(14) in the IOS shape (units, precision 1, -24) is -2.4 dBm "
          "under the ordinary RFC 3433 arithmetic -- no special case",
          sensors[1013]["value"] == -2.4 and sensors[1013]["unit"] == "dBm"
          and sensors[1013]["type"] == "optical power", sensors[1013])
    check("dBm(14) in the NX-OS shape (milli, precision 0, -5500) is "
          "-5.5 dBm through the same arithmetic",
          sensors[1014]["value"] == -5.5 and sensors[1014]["unit"] == "dBm",
          sensors[1014])
    check("the Cisco table has no units-display column, so the unit text "
          "comes from the type enum for every row",
          all(s["unit"] for s in sensors.values()),
          {e: s["unit"] for e, s in sensors.items()})

    # --- the name fallback, both of its two ways ---------------------------
    check("the temperature sensor names its own port in entPhysicalName "
          "('Te1/1/1 Module Temperature Sensor'), so its first word matches "
          "the stored ifDescr through the abbreviation table",
          sensors[1010]["if_index"] == 1
          and sensors[1010]["if_name"] == PORT_DESCR, sensors[1010])
    check("the four sensors named only 'Supply Voltage' and the like reach "
          "the same port by climbing entPhysicalContainedIn to the module "
          "entity, whose own name matches",
          all(sensors[e]["if_index"] == 1 for e in (1011, 1012, 1013, 1014)),
          {e: sensors[e]["if_index"] for e in (1011, 1012, 1013, 1014)})
    check("the chassis inlet probe matches no interface and stays unmapped",
          sensors[2000]["if_index"] is None, sensors[2000])
    check("this device answers no entAliasMappingIdentifier row at all -- "
          "the standard mapping is genuinely empty, so the name fallback is "
          "the only thing that mapped anything",
          poller._entity_port_map(db.device(did),
                                  poller.working_config(db.device(did)))[1] == 0)
    db.close()
finally:
    stub.kill()

# ==================================== § 3 read_dom_all and read_dom agree

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("dom")
    did = device_against(db, "cisco-sw-2")
    db.replace_interfaces(did, [{"if_index": 1, "descr": PORT_DESCR}])
    mark_cisco(db, did)
    poller = NodePoller(db)

    rows = poller.read_dom_all(did)
    check("read_dom_all keeps the five port-mapped rows and drops the "
          "chassis probe -- this is the DOM table, not the sensor list",
          len(rows) == 5 and all(r["if_index"] == 1 for r in rows), rows)
    check("every row carries the stored interface name",
          all(r["if_name"] == PORT_DESCR for r in rows), rows)

    dom = poller.read_dom(did, 1)
    check("read_dom, the interface dialog's own one-port read, sees exactly "
          "the same five readings",
          sorted(r["value"] for r in dom) == sorted(r["value"] for r in rows),
          (sorted(r["value"] for r in dom), sorted(r["value"] for r in rows)))
    by_value = {r["value"]: r for r in dom}
    all_by_value = {r["value"]: r for r in rows}
    check("...and agrees with it on unit and status for every one",
          all(by_value[v]["unit"] == all_by_value[v]["unit"]
              and by_value[v]["status"] == all_by_value[v]["status"]
              for v in by_value), (dom, rows))
    check("read_dom labels its rows from entPhysicalDescr, the contract the "
          "interface dialog has always had",
          by_value[-2.4]["label"] == "Transmit Power", by_value[-2.4])
    check("read_dom(did, 2) -- a port with no sensors on it -- is empty, "
          "not the whole table",
          poller.read_dom(did, 2) == [], poller.read_dom(did, 2))
    db.close()
finally:
    stub.kill()

# ============================== § 4 _poll_environment and the hourly latch

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("environment")
    did = device_against(db, "cisco-sw-3")
    db.replace_interfaces(did, [{"if_index": 1, "descr": PORT_DESCR}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    now = time.time()
    poller._poll_environment(did, device, config, set(), now)
    metrics = {m["key"]: m for m in db.metrics(did)}
    check("the Cisco table counts toward sensor capability just as the "
          "standard one does",
          db.device(did)["sensor_capable"] == 1, db.device(did)["sensor_capable"])
    check("the port-mapped optic temperature lands in temp_optic_c",
          "temp_optic_c" in metrics
          and metrics["temp_optic_c"]["last_value"] == 33.0, sorted(metrics))
    check("the unmapped chassis probe lands in temp_chassis_c, and never "
          "in temp_ambient_c -- nothing on this device reports humidity",
          "temp_chassis_c" in metrics
          and metrics["temp_chassis_c"]["last_value"] == 41.0
          and "temp_ambient_c" not in metrics, sorted(metrics))

    # --- the per-port DOM keys (5.1.0) ------------------------------------
    # One key per reading per port, so a rule can fire on the port that is
    # actually failing. The two dBm rows are told apart by their sensor
    # names alone -- dBm(14) says "optical power", never which direction.
    def value(key):
        row = metrics.get(key)
        return row["last_value"] if row else None

    check("Transmit Power becomes sfp_tx_dbm on this port, from the "
          "sensor's own name",
          value("sfp_tx_dbm.1") == -2.4, sorted(metrics))
    check("Receive Power becomes sfp_rx_dbm on the same port",
          value("sfp_rx_dbm.1") == -5.5, sorted(metrics))
    check("bias current is converted out of ENTITY-SENSOR-MIB's amperes "
          "into the milliamps an optic is quoted in: 0.0062 A -> 6.2 mA",
          value("sfp_bias_ma.1") == 6.2, value("sfp_bias_ma.1"))
    check("voltsDC becomes sfp_volt in volts, unconverted",
          value("sfp_volt.1") == 3.299, value("sfp_volt.1"))
    check("the port-mapped temperature is BOTH the per-port sfp_temp_c "
          "and the device-wide temp_optic_c it has always been",
          value("sfp_temp_c.1") == 33.0
          and metrics["temp_optic_c"]["last_value"] == 33.0, sorted(metrics))
    check("every sfp_* key names port 1 -- the chassis inlet probe maps to "
          "no port, so it produces none of them, and there is no "
          "device-level sfp_* key either",
          [k for k in metrics if k.startswith("sfp_")
           and not k.endswith(".1")] == [], sorted(metrics))
    check("each key carries the port's ifDescr and the unit an operator "
          "reads it in",
          metrics["sfp_rx_dbm.1"]["label"] == f"{PORT_DESCR} Rx power"
          and metrics["sfp_rx_dbm.1"]["unit"] == "dBm"
          and metrics["sfp_bias_ma.1"]["unit"] == "mA",
          (metrics["sfp_rx_dbm.1"]["label"], metrics["sfp_bias_ma.1"]["unit"]))
    check("the port the sensors mapped to is marked as carrying an optic, "
          "which is what the SFP badge in the interface list reads",
          db.interfaces(did)[0]["media"] == "optic",
          db.interfaces(did)[0]["media"])
    db.close()
finally:
    stub.kill()

# --------- a device latched incapable, then identified as Cisco afterwards

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("latch")
    did = device_against(db, "late-identified")
    db.replace_interfaces(did, [{"if_index": 1, "descr": PORT_DESCR}])
    poller = NodePoller(db)
    config = db.effective_config(db.device(did))

    now = time.time()
    poller._poll_environment(did, db.device(did), config, set(), now)
    check("a device not yet known to be Cisco answers nothing and latches "
          "sensor_capable=0, exactly as before",
          db.device(did)["sensor_capable"] == 0, db.device(did)["sensor_capable"])

    reset_count(port)
    poller._poll_environment(did, db.device(did), config, set(),
                            now + NodePoller._SENSOR_REFRESH_S + 1.0)
    check("past the ordinary cadence window it is still not re-walked: the "
          "hourly re-probe is the gate now, not the 5-minute one",
          request_count(port) == 0, request_count(port))

    # What the re-probe exists for: identification arrives after the latch.
    mark_cisco(db, did)
    reset_count(port)
    poller._poll_environment(did, db.device(did), config, set(),
                            now + NodePoller._SENSOR_REPROBE_S + 1.0)
    check("an hour on it IS asked again, and now that it is known to be "
          "Cisco the fallback answers -- the latch opens",
          request_count(port) > 0 and db.device(did)["sensor_capable"] == 1,
          (request_count(port), db.device(did)["sensor_capable"]))
    metrics = {m["key"]: m for m in db.metrics(did)}
    check("...and the readings are recorded on that same re-probe",
          "temp_optic_c" in metrics
          and metrics["temp_optic_c"]["last_value"] == 33.0, sorted(metrics))

    # Poll now drops the cadence stamp, so an operator never has to wait
    # out the window to see whether a change of credentials helped.
    reset_count(port)
    poller._sensor_read[did] = time.time()
    poller.poll_now(did)
    check("poll_now clears the sensor cadence stamp so the next poll walks "
          "again rather than waiting out the window",
          did not in poller._sensor_read, poller._sensor_read)
    db.close()
finally:
    stub.kill()

# ===================================================== § 5 diagnostics

stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")   # neither table
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("diag_nothing")
    did = device_against(db, "answers-nothing")
    db.replace_interfaces(did, [{"if_index": 1, "descr": PORT_DESCR}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    poller.log = CaptureLog()

    check("a device that answers neither table gets one event naming both",
          poller.read_hardware(did)["sensors"] == [], "")
    line = poller.log.lines[0] if poller.log.lines else ""
    check("...and that event names the tables tried, so the operator is not "
          "left guessing which MIBs were asked for",
          "answered nothing" in line and "ENTITY-SENSOR-MIB" in line
          and "CISCO-ENTITY-SENSOR-MIB" in line, line)

    poller.read_hardware(did)
    check("a second read inside the minute does not write a second event -- "
          "an open dialog re-reads on a timer and must not flood the log",
          len(poller.log.lines) == 1, poller.log.lines)
    db.close()
finally:
    stub.kill()

stub, port = spawn_stub("stub_agent_ups_env.py", "cisco_dom")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    # --- read something, map nothing --------------------------------------
    db = new_nodes_db("diag_unmapped")
    did = device_against(db, "unmatched-ifdescr")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    poller.log = CaptureLog()

    check("with no alias rows and an ifDescr that matches no sensor name, "
          "read_hardware still lists all six sensors",
          len(poller.read_hardware(did)["sensors"]) == 6,
          poller.read_hardware(did)["sensors"])
    check("...while read_dom_all is empty, because nothing resolved to a port",
          poller.read_dom_all(did) == [], poller.read_dom_all(did))
    line = poller.log.lines[0] if poller.log.lines else ""
    check("the event says how many rows were read, out of which MIB, and "
          "that both mapping routes came up empty",
          "none mapped to an interface" in line
          and "CISCO-ENTITY-SENSOR-MIB" in line
          and "entAliasMappingIdentifier had 0 row(s)" in line
          and "entPhysicalName matched no stored ifDescr" in line, line)
    db.close()
finally:
    stub.kill()

# ==================================== § 6 the name canonicaliser itself

canonical = nodepoll_mod._canonical_if_name
check("an abbreviation expands to the long form the same box writes in "
      "ifDescr",
      canonical("Te1/1/1") == canonical("TenGigabitEthernet1/1/1"),
      (canonical("Te1/1/1"), canonical("TenGigabitEthernet1/1/1")))
check("the whole leading alpha run has to be the abbreviation: 'Ten...' is "
      "never re-read as 'Te' + 'n...'",
      canonical("TenGigabitEthernet1/1/1") == "tengigabitethernet1/1/1",
      canonical("TenGigabitEthernet1/1/1"))
check("whitespace and case are ignored",
      canonical(" Gi 0/1 ") == canonical("GigabitEthernet0/1"),
      (canonical(" Gi 0/1 "), canonical("GigabitEthernet0/1")))
check("a name with no abbreviation is left alone apart from the reduction",
      canonical("Vlan100") == "vlan100", canonical("Vlan100"))
check("two different ports never collide",
      canonical("Gi0/1") != canonical("Gi0/2"), "")

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

"""Per-port media from ENTITY-MIB, and the optic that is dark rather than
failing (5.2.0).

Covers: _poll_environment resolving interfaces.media to 'optic' (DOM rows
present), 'sfp' (a cage holding a transceiver that reports no DOM at all)
and 'sfp_empty' (a cage with nothing in it) from entPhysicalClass, and
leaving a copper port an agent happens to model as container+port unbadged;
a multi-lane optic whose dark lane must not win the worst-of away from its
healthy one; an optic dark on every lane still recording the floor so the
port's chart keeps its continuity; alertrules.breaches refusing to alert on
that floor for the two optic power rules and nothing else; and
evaluate_threshold closing an alert already open on a port that goes dark.
"""
import socket
import time

import _paths
from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath.alertrules import (DARK_OPTIC_DBM, breaches, evaluate_threshold,
                               is_dark_optic)
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

TMP = tmpdir("sfp_media_")

ENT_VENDOR_TYPE = "1.3.6.1.2.1.47.1.1.1.1.3"
ENT_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"

FAILS = []

PORTS = [{"if_index": 1, "descr": "GigabitEthernet1/0/1"},
         {"if_index": 2, "descr": "GigabitEthernet1/0/2"},
         {"if_index": 3, "descr": "GigabitEthernet1/0/3"},
         {"if_index": 4, "descr": "GigabitEthernet1/0/4"},
         {"if_index": 5, "descr": "GigabitEthernet1/0/5"},
         {"if_index": 6, "descr": "GigabitEthernet1/0/6"},
         {"if_index": 7, "descr": "GigabitEthernet1/0/7"},
         {"if_index": 8, "descr": "GigabitEthernet1/0/8"},
         {"if_index": 9, "descr": "GigabitEthernet1/0/9"},
         {"if_index": 10, "descr": "GigabitEthernet1/0/10"},
         {"if_index": 11, "descr": "GigabitEthernet1/0/11"},
         {"if_index": 12, "descr": "GigabitEthernet1/0/12"},
         {"if_index": 13, "descr": "GigabitEthernet1/0/13"},
         {"if_index": 14, "descr": "GigabitEthernet1/0/14"},
         {"if_index": 15, "descr": "GigabitEthernet1/0/15"},
         {"if_index": 16, "descr": "GigabitEthernet1/0/16"},
         {"if_index": 17, "descr": "GigabitEthernet1/0/17"},
         {"if_index": 18, "descr": "GigabitEthernet1/0/18"},
         {"if_index": 19, "descr": "GigabitEthernet1/0/19"}]

IF_MAU_TYPE = "1.3.6.1.2.1.26.2.1.1.3"


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def stub_control(port: int, command: bytes) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sock.sendto(command, ("127.0.0.1", port))
    try:
        return sock.recv(4096).decode("utf-8", "replace")
    finally:
        sock.close()


def stub_columns(port: int) -> set:
    """The entPhysicalEntry columns (and ifMauType) the stub was asked for,
    over its own control datagram -- the stub_agent_fdb.py convention every
    stub here follows. A column is a whole table walk of cost every cadence,
    so which ones are asked for is part of the contract, not an
    implementation detail."""
    return set(stub_control(port, b"COLUMNS").split())


def new_nodes_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, name: str) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid)


def mark_cisco(db: NodesDatabase, did: int) -> None:
    """Writes vendor_detected without a real identify walk -- the idiom
    tests/test_cisco_entity_sensor.py's own mark_cisco uses -- so
    _cisco_sensor_table_plausible's entPhysicalName fallback walk runs."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)


class CaptureLog:
    """Just enough of eventlog to read back what the poller wrote."""

    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append(message)


def rule(source_kind, threshold, clear_threshold, comparison):
    """The columns breaches() and evaluate_threshold() read off a rule row,
    as the plain dict alertrules' own contract says a caller may pass."""
    return {"source_kind": source_kind, "threshold": threshold,
            "clear_threshold": clear_threshold, "comparison": comparison,
            "for_polls": 1}


# ================================================ § 1 media from the walk

stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("media")
    did = device_against(db, "media-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}

    check("a port with DOM readings is 'optic' -- sensors outrank anything "
          "the entity table says about the cage they sit in",
          media.get(1) == "optic", media)
    check("a cage holding a transceiver that reports no DOM is 'sfp': the "
          "slot is identified even though nothing measurable is in it",
          media.get(2) == "sfp", media)
    check("a cage with nothing in it is 'sfp_empty' even with an ifMauType "
          "copper arc on it -- an empty cage is not a confirmed transceiver, "
          "so the entity-scan gate refuses the arc",
          media.get(3) == "sfp_empty", media)
    check("a copper port the agent also models as container+port names no "
          "transceiver anywhere and stays unbadged, and an ifMauType copper "
          "arc on it cannot confirm one either -- same gate",
          media.get(4) is None, media)
    check("a copper module named by text alone ('1000BaseT SFP' / GLC-T), "
          "no sensor at all, is 'copper'",
          media.get(8) == "copper", media)
    check("a copper module named by text, with a temperature-only sensor, "
          "is still 'copper' -- medium wins over 'has a DOM reading'",
          media.get(9) == "copper", media)
    check("module text alone ('Transceiver module') cannot tell copper from "
          "laser; ifMauType arc 30 (1000BASE-T) is what makes if 10 'copper'",
          media.get(10) == "copper", media)
    check("an optical module (real DOM Rx row) whose ifMauType answers a "
          "fiber arc (36, 10GBASE-SR) is not downgraded: fiber proof still "
          "leaves it 'optic'",
          media.get(11) == "optic", media)
    check("copper text (GLC-T) with no sensor at all is downgraded to 'sfp' "
          "by an ifMauType fiber arc -- the wire vetoes the text even with "
          "nothing else to go on",
          media.get(12) == "sfp", media)
    check("an 'unknown PMD' ifMauType arc (22, 1000BASE-XFD) is neither "
          "copper nor fiber: GLC-T text on if 8 stays 'copper' despite it",
          media.get(8) == "copper", media)
    check("a combo port's text ('1000BASE-T/SFP combo') is copper, but a "
          "real Rx dBm sensor on it wins: DOM beats copper text",
          media.get(13) == "optic", media)
    check("an ifMauType row whose value OID is not under the dot3MauType "
          "prefix is ignored outright -- ambiguous text alone leaves if 14 "
          "'sfp', not 'copper'",
          media.get(14) == "sfp", media)
    check("module text 'SFP-GE-T' alone (5.25.1's widened _COPPER_TEXT) is "
          "'copper'",
          media.get(15) == "copper", media)

    optic_mode = {r["if_index"]: r["optic_mode"] for r in db.interfaces(did)}
    check("if 2's module text (10Gbase-LR SFP+ / SFP-10G-LR) reads 'sm' "
          "through the cage/occupant scan",
          optic_mode.get(2) == "sm", optic_mode)
    check("an occupied cage naming a multimode module (GLC-SX-MMD), no "
          "DOM, reads 'mm' the same way",
          media.get(16) == "sfp" and optic_mode.get(16) == "mm", optic_mode)
    check("a DOM-lit port with no entPhysicalClass row at all still reads "
          "'mm' off its own module text (SFP-10G-SR) -- the optic_ports "
          "fallback scan, not the cage/occupant one",
          media.get(17) == "optic" and optic_mode.get(17) == "mm", optic_mode)
    check("copper ports never carry an optic_mode",
          optic_mode.get(8) is None and optic_mode.get(9) is None
          and optic_mode.get(10) is None, optic_mode)
    check("a DOM-lit port whose parent chain carries a chassis model name "
          "(N9K-C93180YC-EX) reads 'mm' off its transceiver child "
          "(SFP-10G-SR), not 'sm' off the chassis -- the fallback scan's "
          "transceiver gate (F1, 5.36.0)",
          media.get(18) == "optic" and optic_mode.get(18) == "mm", optic_mode)
    check("the same chassis ancestor with no transceiver text anywhere "
          "reads None, not the chassis model name (F1, 5.36.0)",
          media.get(19) == "optic" and optic_mode.get(19) is None, optic_mode)

    metrics = {m["key"]: m["last_value"] for m in db.metrics(did)}
    check("a copper module's temperature sensor is still recorded -- "
          "copper only changes the badge, not what gets measured",
          metrics.get("sfp_temp_c.9") == 35.0, metrics.get("sfp_temp_c.9"))

    # Every column here is a full walk of entPhysical, every
    # _SENSOR_REFRESH_S, for every port-mapped device, so which ones are
    # asked for is part of the contract.
    columns = stub_columns(port)
    check("the cage scan reads entPhysicalClass and entPhysicalModelName",
          {ENT_CLASS, ENT_MODEL_NAME} <= columns, sorted(columns))
    check("...and never entPhysicalVendorType: it is an OBJECT IDENTIFIER "
          "column, so what comes back is a dotted number, and no vendor's "
          "own name for a part reads as transceiver text either",
          ENT_VENDOR_TYPE not in columns, sorted(columns))
    check("...and now also ifMauType, the MAU-MIB copper/fiber proof",
          IF_MAU_TYPE in columns, sorted(columns))
    db.close()
finally:
    stub.kill()

# --- ifMauType's own probe-once-remember: noSuchObject is not re-walked --
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_mau")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("mau_reprobe")
    did = device_against(db, "no-mau-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    t0 = time.time()
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(), t0)
    check("a device that answers nothing under ifMauType is still walked "
          "once, to find that out",
          IF_MAU_TYPE in stub_columns(port), stub_columns(port))

    stub_control(port, b"RESET")
    # Past _SENSOR_REFRESH_S (300 s) so the outer sensor-cadence gate reopens
    # this poll, but well inside _SENSOR_REPROBE_S (3600 s) -- the window
    # that matters here is ifMauType's own.
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             t0 + 301)
    check("...and is not re-walked on the next poll inside the hourly "
          "reprobe window, once it is known unsupported",
          IF_MAU_TYPE not in stub_columns(port), stub_columns(port))
    db.close()
finally:
    stub.kill()

# --- a walk that answered nothing must never clear a badge ---------------
stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("media_keep")
    did = device_against(db, "quiet-sw")
    db.replace_interfaces(did, PORTS[:2])
    db.update_interface_media(did, [{"if_index": 1, "media": "sfp"},
                                    {"if_index": 2, "media": "sfp_empty"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("the new media kinds are kept through a walk that answered "
          "nothing, exactly as 'optic' already was",
          media == {1: "sfp", 2: "sfp_empty"}, media)
    db.close()
finally:
    stub.kill()

# --- nor must one the device answered only part of -----------------------
# The flaky case, and the one an empty walk does not cover: alias and
# containment answer, entPhysicalClass times out. The clear pass runs on the
# strength of the alias walk, and everything the cage scan never reached
# looks exactly like a cage that is gone.
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_class")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("media_partial")
    did = device_against(db, "flaky-sw")
    db.replace_interfaces(did, PORTS)
    db.update_interface_media(did, [
        {"if_index": 2, "media": "sfp", "optic_mode": "sm"},
        {"if_index": 3, "media": "sfp_empty"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    optic_mode = {r["if_index"]: r["optic_mode"] for r in db.interfaces(did)}
    check("a device whose entPhysicalClass walk times out keeps its SFP "
          "badges rather than flickering them off for one cadence",
          (media.get(2), media.get(3)) == ("sfp", "sfp_empty"), media)
    check("...and keeps the stored optic_mode exactly as it keeps media",
          optic_mode.get(2) == "sm", optic_mode)
    check("...while the ports this poll's sensors did answer for are badged "
          "from it as usual: a cut-short walk stops nothing else",
          media.get(1) == "optic", media)
    db.close()
finally:
    stub.kill()

# --- a timed-out DOM value walk must not strip a stored 'optic' badge ----
# (5.35.0 review fix, F2): entPhySensorValue refused outright, everything
# else (class/alias/containment) answers -- the case an empty walk (the
# 'media_keep' block above) does not cover.
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_sensor_values")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("media_sensor_timeout")
    did = device_against(db, "sensor-timeout-sw")
    db.replace_interfaces(did, PORTS)
    db.update_interface_media(did, [{"if_index": 2, "media": "optic"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("a device whose entPhySensorValue walk times out keeps a stored "
          "'optic' badge, not just 'sfp'/'copper' -- a stale cage scan must "
          "never rewrite a port this poll had no sensors to re-prove",
          media.get(2) == "optic", media)
    db.close()
finally:
    stub.kill()

# --- a timed-out module-text walk must not null a DOM-proven port's mode -
# (5.36.0 review fix, F2): entPhysicalDescr refused outright starves both
# the cage/occupant scan and the optic_ports fallback scan of text on the
# same cadence, while the DOM sensor itself still proves if 17 'optic'.
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_descr")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("media_mode_timeout")
    did = device_against(db, "mode-timeout-sw")
    db.replace_interfaces(did, PORTS)
    db.update_interface_media(did, [{"if_index": 17, "media": "optic",
                                     "optic_mode": "mm"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    optic_mode = {r["if_index"]: r["optic_mode"] for r in db.interfaces(did)}
    check("if 17 stays 'optic' off its own DOM sensor even with no module "
          "text to read this cycle",
          media.get(17) == "optic", media)
    check("...and keeps its stored optic_mode rather than going NULL until "
          "the next full walk",
          optic_mode.get(17) == "mm", optic_mode)
    db.close()
finally:
    stub.kill()

# ==================================== § 1b cage scan decoupled (5.35.0, F)

# --- a device with no DOM sensors at all still gets its cages badged -----
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_sensors")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("no_sensors")
    did = device_against(db, "no-sensors-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("a device answering no ENTITY-SENSOR-MIB rows at all still badges "
          "an occupied cage 'sfp' from entPhysicalClass/text alone -- the "
          "cage scan no longer waits on the sensor gate",
          media.get(2) == "sfp", media)
    check("...and no metric samples are invented for a device with nothing "
          "to measure (optic_ports/dbm_ports both empty)",
          db.metrics(did) == [], db.metrics(did))
    db.close()
finally:
    stub.kill()

# --- an incomplete entPhysicalName fallback walk keeps stored badges -----
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_names")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("names_cut")
    did = device_against(db, "names-cut-sw")
    mark_cisco(db, did)
    db.replace_interfaces(did, PORTS)
    db.update_interface_media(did, [{"if_index": 2, "media": "sfp"},
                                    {"if_index": 3, "media": "sfp_empty"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("a Cisco device whose entPhysicalName fallback walk times out "
          "keeps its stored SFP badges -- a half-mapped pass must not "
          "strip them",
          (media.get(2), media.get(3)) == ("sfp", "sfp_empty"), media)
    db.close()
finally:
    stub.kill()

# --- diagnostic: nothing mapped to a port at all --------------------------
stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media_no_port_map")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("no_port_map")
    did = device_against(db, "no-port-map-sw")
    db.replace_interfaces(did, PORTS[:1])
    poller = NodePoller(db)
    poller.log = CaptureLog()
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    check("the empty-port-map diagnostic names the alias row count and "
          "says entPhysicalName matched nothing",
          any("no entity mapped to a port" in line
              and "entAliasMappingIdentifier had 1 row(s)" in line
              and "entPhysicalName matched no stored ifDescr" in line
              for line in poller.log.lines),
          poller.log.lines)
    db.close()
finally:
    stub.kill()

# --- plain-host cage latch: a device answering nothing at all -------------
# (5.35.0 review fix, should-fix): a complete-empty ENTITY-MIB answer marks
# the device both sensor- and cage-incapable in one pass, so the next poll
# is gated out to the hourly reprobe window instead of re-walked every
# cadence. _walk_column_detail is stubbed directly, not via the SNMP stub
# agent, so no real session is needed for it.
db = new_nodes_db("plain_host")
did = device_against(db, "plain-host")
poller = NodePoller(db)
walked: list = []


def empty_complete_walk(device, config, oid, raise_on_timeout=False, deadline=None):
    walked.append(oid)
    return {}, True, ""


poller._walk_column_detail = empty_complete_walk
t0 = time.time()
device = db.device(did)
poller._poll_environment(did, device, db.effective_config(device), set(), t0)
check("first probe of a plain host walks the ENTITY-MIB columns",
      walked != [], walked)
check("plain host latches cage-incapable",
      poller._cage_capable.get(did) is False, poller._cage_capable)

walked.clear()
device = db.device(did)
poller._poll_environment(did, device, db.effective_config(device), set(), t0 + 60)
check("the next poll, 60s later, walks nothing -- the latch (cage) and "
      "sensor_capable=False (outer gate) together confirm a plain host "
      "once instead of re-probing it every cadence",
      walked == [], walked)
db.close()

# ============================================== § 2 the dark optic's value

stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_nodes_db("dark")
    did = device_against(db, "dark-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    metrics = {m["key"]: m["last_value"] for m in db.metrics(did)}

    check("a healthy single-lane optic is recorded as it reads",
          metrics.get("sfp_rx_dbm.1") == -5.5, sorted(metrics))
    check("the dark lane of a two-lane optic does not win the worst-of: the "
          "healthy lane at -6 is what the port reports, not the -40",
          metrics.get("sfp_rx_dbm.5") == -6.0, metrics.get("sfp_rx_dbm.5"))
    check("an optic dark on every lane still records the floor, so the "
          "port's chart keeps its continuity and its history stays true",
          metrics.get("sfp_rx_dbm.6") == DARK_OPTIC_DBM,
          metrics.get("sfp_rx_dbm.6"))
    check("a transmit reading of exactly 0.0 dBm is recorded as 0.0: 1 mW is "
          "a nominal ER/ZR level, and writing the -40 floor over it dropped "
          "the port's chart to the bottom of the scale for that poll",
          metrics.get("sfp_tx_dbm.7") == 0.0, metrics.get("sfp_tx_dbm.7"))
    db.close()
finally:
    stub.kill()

# ======================================= § 3 what the floor may not alert

rx_low = rule("sfp_rx_dbm", -22.0, -20.0, "below")
tx_low = rule("sfp_tx_dbm", -12.0, -10.0, "below")

check("-25 dBm is a genuinely failing optic and still breaches",
      breaches(rx_low, -25.0))
check("-40 dBm raises nothing: the port is powered down or has no fiber "
      "in it, which is not a fault to alert on",
      not breaches(rx_low, -40.0))
check("...and the transmit rule is guarded the same way",
      not breaches(tx_low, -40.0) and breaches(tx_low, -15.0))
check("a reading just above the floor is still refused -- vendors do not "
      "all clamp to exactly -40.00",
      not breaches(rx_low, -39.8))
# 0 dBm is 1 mW, which an ER/ZR/DWDM part really transmits at, and an agent
# quoting 0.1 dBm units rounds -0.04 to exactly it. An agent reporting watts
# with a zero raw value yields a non-finite dBm through the scale arithmetic
# instead, which is what the floor test's isfinite clause is for.
check("0 dBm is a reading like any other, not a sentinel for 'no light'",
      not is_dark_optic("sfp_rx_dbm", 0.0)
      and not is_dark_optic("sfp_tx_dbm", 0.0))
tx_high = rule("sfp_tx_dbm", -1.0, -3.0, "above")
check("an operator's own above-rule on transmit power fires at exactly "
      "0.0 dBm, where it used to be silenced as darkness",
      breaches(tx_high, 0.0))

# The guard is keyed off the rule's metric family, so nothing else can
# inherit it -- a 'below' rule on any other metric is untouched.
other_low = rule("ping_loss_pct", -22.0, -20.0, "below")
check("another 'below' rule reading -40 breaches as it always did: the "
      "guard is keyed to the two optic power families, not to the value",
      breaches(other_low, -40.0))
check("a rule row with no source_kind column at all (an older row, or a "
      "test's own dict) still evaluates rather than raising",
      breaches({"threshold": -22.0, "comparison": "below"}, -25.0))

check("is_dark_optic answers only for the optic power families",
      is_dark_optic("sfp_rx_dbm", -40.0) and is_dark_optic("sfp_tx_dbm", -40.0)
      and not is_dark_optic("sfp_temp_c", -40.0)
      and not is_dark_optic("sfp_volt", 0.0))
check("a non-finite reading is dark: an agent with no answer to give must "
      "not become an alert either",
      is_dark_optic("sfp_rx_dbm", float("-inf"))
      and is_dark_optic("sfp_rx_dbm", float("nan")))

# ==================================== § 4 what the floor has to close down

# breaches() refusing to open an alert says nothing about one already open:
# the sample is fresh every poll, so threshold_stale_s never expires it, and
# without a verdict of its own the row sits there for ever showing the -25
# that raised it.
check("-25 dBm opens the alert, as it did before",
      evaluate_threshold(rx_low, -25.0, 1) == "breach")
check("the optic going dark closes it: a port with no light is "
      "interface_down's business, not a low-light state",
      evaluate_threshold(rx_low, -40.0, 0) == "clear")
check("...and the transmit rule closes the same way",
      evaluate_threshold(tx_low, -40.0, 0) == "clear")
check("a reading just above the floor closes it too, on the same tolerance "
      "breaches() refuses to open on",
      evaluate_threshold(rx_low, -39.8, 0) == "clear")
check("a genuinely dim optic is untouched: -25 is still a breach, and the "
      "hysteresis gap still says nothing",
      evaluate_threshold(rx_low, -21.0, 3) == "")
check("another 'below' rule reading -40 is unaffected -- it breaches, and "
      "the dark verdict is keyed to the optic power families",
      evaluate_threshold(other_low, -40.0, 1) == "breach")

# ========================================= § 5 _COPPER_TEXT, regex-only

_COPPER_TEXT = nodepoll_mod._COPPER_TEXT
COPPER_POSITIVES = ["SFP-GE-T", "SFP-1G-T", "EX-SFP-1GE-T", "SFP-T",
                    "1000BaseT SFP", "GLC-T", "GLC-TE", "SFP-10G-T-S",
                    "SFP-10G-T-X", "RJ45", "copper", "Cat5e", "Cat6a"]
FIBER_NEGATIVES = ["SFP-10G-SR-S", "1000BASE-BX", "GLC-SX-MMD",
                   "GLC-LH-SMD", "GLC-BX-D", "SFP-10G-LRM", "1000BASE-X"]
for text in COPPER_POSITIVES:
    check(f"_COPPER_TEXT matches {text!r}", bool(_COPPER_TEXT.search(text)))
for text in FIBER_NEGATIVES:
    check(f"_COPPER_TEXT does not match laser part {text!r}",
          not _COPPER_TEXT.search(text))

# --------------------------------- § 6 _optic_mode, real Cisco part numbers
_optic_mode = nodepoll_mod._optic_mode
OPTIC_MODE_TABLE = [
    ("GLC-SX-MMD", "mm"), ("GLC-LH-SMD", "sm"), ("GLC-EX-SMD", "sm"),
    ("GLC-ZX-SMD", "sm"), ("GLC-BX-U", "sm"), ("SFP-10G-SR", "mm"),
    ("SFP-10G-LR", "sm"), ("SFP-10G-ER", "sm"), ("SFP-10G-LRM", "mm"),
    ("SFP-25G-SR-S", "mm"), ("QSFP-40G-SR4", "mm"), ("QSFP-100G-LR4", "sm"),
    ("SFP-10G-BX10-U", "sm"), ("SFP-10G-BX10-D", "sm"),
    ("SFP-10G-BX40-U", "sm"), ("SFP-10G-BX40-D", "sm"),
    ("SFP-10G-SRL", "mm"), ("SFP-LX10", "sm"), ("QSFP-100G-ER4L-S", "sm"),
    ("GLC-T", None), ("SFP-H10GB-CU1M", None),
]
for text, expected in OPTIC_MODE_TABLE:
    check(f"_optic_mode({text!r}) is {expected!r}",
          _optic_mode(text) == expected, _optic_mode(text))

# ------------------------- § 6b the media code itself, not the part number
# 5.38.0: the classifier reads the IEEE/MSA PMD suffix out of whatever text
# a device offers, so a module whose part number nobody has listed is still
# classified. FX was the gap that prompted this -- a 100Base-FX module read
# as a bare 'SFP' badge because no pattern named FX.
MEDIA_CODE_TABLE = [
    ("100BaseFX SFP", "mm"), ("100Base-FX", "mm"), ("GLC-FE-100FX", "mm"),
    ("1000Base-SX SFP", "mm"), ("1000Base-LX SFP", "sm"),
    ("100Base-BX10-U", "sm"), ("1000Base-BX-D", "sm"),
    # LRM reads like LR and is multimode; LX4 reads like LX and runs on MMF.
    ("10GBASE-LRM", "mm"), ("10GBASE-LX4", "mm"),
    ("QSFP-40G-CSR4", "mm"), ("QSFP-100G-PSM4", "sm"),
    ("CWDM SFP 1530", "sm"), ("DWDM-SFP10G-C", "sm"),
    # Wavelength is the fallback for a module that quotes its optics and
    # not its PMD at all.
    ("SFP module, 850nm", "mm"), ("SFP module, 1310nm", "sm"),
    ("SFP module, 1550 nm", "sm"),
    # A code too short to trust bare: "sw" names 10GBASE-SW, and also every
    # switch an operator ever abbreviated.
    ("sw-core-01 uplink", None), ("10GBASE-SW", "mm"),
]
for text, expected in MEDIA_CODE_TABLE:
    check(f"_optic_mode({text!r}) is {expected!r}",
          _optic_mode(text) == expected, _optic_mode(text))
check("a 100Base-FX cage counts as a transceiver on its text alone",
      bool(nodepoll_mod._TRANSCEIVER_TEXT.search("100Base-FX")))

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

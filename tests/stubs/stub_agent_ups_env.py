"""A mode-selected v2c stub for UPS-MIB (RFC 1628) and the device-level
ENTITY-SENSOR-MIB read (RFC 3433) — the same "MODE global, table_for()
picks the OID dict" shape stub_agent_l2.py and stub_agent_fdb.py already
established, kept as its own script rather than a new mode grafted onto
stub_agent_l2.py so this suite cannot perturb any existing one's table.

    stub_agent_ups_env.py <port> <mode>

Modes:
  ups        Full standard UPS-MIB: battery status batteryLow(3), 45s on
             battery, 12 minutes estimated remaining, 63% charge, a 24.3 V
             battery (243 decivolts, so the /10 scale is exercised),
             31 C battery temperature, output source battery(5), 2 active
             alarms, a two-line upsInputTable (118 V, 121 V -- column_first
             takes 118) and a two-line upsOutputTable (55%, 72% --
             column_max takes 72). A generic (non-APC) sysObjectID, so the
             APC runtime fallback is never reached from this mode.
  wild_scale The `hardware` sensor table with entPhySensorScale answered as
             2147483647 and entPhySensorPrecision as -2147483648 on every
             row: both are exponents, and an unclamped reader never
             returns from one such row.
  no_ups     Generic scalars only, no UPS-MIB object at all: proves the two
             UPS table walks are never attempted when the scalar batch
             answered nothing.
  apc_ups    UPS-MIB scalars WITHOUT upsEstimatedMinutesRemaining (the
             standard scalar this app prefers is simply absent, the way a
             real APC agent's answer varies by firmware), an APC sysObjectID
             (enterprise arc 318) and upsAdvBatteryRunTimeRemaining served
             in TimeTicks -- the fallback path.
  sensors    ENTITY-SENSOR-MIB, four entities: one (#1) mapped to ifIndex 1
             through entAliasMappingIdentifier, a fractional-precision
             temperature (45.1 C) -- the read_dom()-reachable case AND the
             temp_optic_c case, since it maps to a port; three (#2-#4)
             mapped to nothing, all invisible to read_dom() and all visible
             to the device-level scan: #2 a humidity reading with a
             NEGATIVE scale exponent (milli, scale=8) -- also the signal
             that promotes #4 to temp_ambient_c rather than temp_chassis_c,
             #3 a temperature marked nonoperational (status=3, must be
             excluded), #4 a plain-ok temperature hotter than #1 (must win
             the device's worst-of-kind reading).
  sensors_no_humidity
             The same entities 1/3/4 as `sensors`, with entity 2 (the
             humidity sensor) removed: #4 now has no positive evidence this
             is a dedicated environmental monitor, so it must land in
             temp_chassis_c, never temp_ambient_c -- the "cannot be
             determined must not silently become ambient" case.
  hardware   `sensors`' four entities plus a fifth (#5, a bias-current
             reading) reached only through entPhysicalContainedIn -- #5 has
             no entAliasMappingIdentifier row of its own, only a containment
             pointer to #1 (which does), the read_hardware/read_dom_all
             chain-resolution case _entity_port_map exists for. Entity #1
             also gets an entPhysicalName distinct from its
             entPhysicalDescr, so read_hardware's name preference (and
             read_dom's indifference to it) can both be checked from the
             same walk. Adds CISCO-ENVMON-MIB: one supply row (normal), one
             fan row (warning), one temperature row (critical, with a
             threshold) -- a Cisco sysObjectID, so the vendor gate in
             read_hardware would pass were it driven by sysObjectID alone
             (tests still set vendor_detected directly; a full identify
             walk is not this stub's job).
  cisco_dom  A Cisco switch as one really answers: no ENTITY-SENSOR-MIB
             (1.3.6.1.2.1.99) rows and no entAliasMappingIdentifier rows at
             all, with the readings in CISCO-ENTITY-SENSOR-MIB
             (1.3.6.1.4.1.9.9.91) instead -- five optic sensors under one
             port module (entity 1000, entPhysicalName
             "TenGigabitEthernet1/1/1") and one chassis inlet probe. Only
             the temperature sensor names its own port ("Te1/1/1 Module
             Temperature Sensor"); the rest reach it by climbing
             entPhysicalContainedIn to entity 1000. Two dBm rows in the two
             shapes real gear uses -- units/precision 1 (IOS) and
             milli/precision 0 (NX-OS) -- both decoding through the plain
             RFC 3433 arithmetic.
  cisco_dom_thresholds
             `cisco_dom` plus CISCO-ENTITY-SENSOR-MIB's
             entSensorThresholdTable -- the levels each transceiver
             publishes about itself, each quoted in ITS OWN entity's scale
             and precision, plus a partly-published band, two rows naming
             no band at all, a duplicated level and a chassis probe mapped
             to no port. See CISCO_DOM_THRESHOLD_TABLE.
  sfp_media  Fourteen ports covering every media verdict, the dark optic,
             copper (5.25.0) and the MAU gate/veto/prefix fixes (5.25.1):
             a working optic, an occupied cage with no DOM, an empty cage,
             a copper port an agent models as container+port too (which
             must stay unbadged), a two-lane optic with one lane dark, one
             dark on both lanes, one transmitting at exactly 0 dBm, a
             copper module named by text alone with no sensor, a copper
             module named by text with a temperature-only sensor, a
             module ifMauType alone proves copper, an optical module whose
             ifMauType fiber arc must not downgrade it, copper text vetoed
             by a fiber arc with no sensor, a combo port a real Rx dBm
             sensor wins over copper text, and a MAU row under the wrong
             OID prefix that must be ignored. See SFP_MEDIA_TABLE and
             SFP_MAU_TABLE.
  sfp_media_no_class
             `sfp_media`, except that every request into the
             entPhysicalClass column goes unanswered -- the flaky device
             that answers the alias and containment walks and then stops,
             so that walk times out rather than coming back empty. The
             difference matters to a caller that deletes rows its walk did
             not produce. See DEAD_COLUMNS.
  sfp_media_no_mau
             `sfp_media`'s SFP_MEDIA_TABLE with no SFP_MAU_TABLE merged in
             -- ifMauType answers nothing (a clean empty walk, not a
             timeout), the noSuchObject case the reprobe gate is for.
  sfp_media_no_sensors
             `sfp_media`'s SFP_MEDIA_TABLE with every ENTITY-SENSOR-MIB row
             (1.3.6.1.2.1.99.*) stripped out -- a switch that lists no DOM
             sensors at all, so _walk_sensor_columns comes back empty and
             the 5.35.0 cage-scan decoupling (F1) is what has to run for
             any badge to appear at all. The cage/alias/containment rows
             for if 2 (an occupied cage naming a transceiver, no sensor of
             any kind) survive the strip, so it still badges 'sfp'.
  sfp_media_no_names
             `sfp_media`'s SFP_MEDIA_TABLE plus SFP_MAU_TABLE, served under
             a CISCO sysObjectID so _poll_environment's Cisco-only
             entPhysicalName fallback walk actually runs, with that column
             (entPhysicalName) refused outright -- a timeout, not a clean
             empty answer. Proves an incomplete names walk keeps whatever
             badges were already stored rather than stripping them.
  sfp_media_no_port_map
             One lone entAliasMappingIdentifier row pointing at something
             that is NOT an ifIndex column -- alias_rows > 0 (there was
             ENTITY-MIB to map) but port_map ends up empty either way, the
             diagnostic-event case (F3).
  sfp_media_no_sensor_values
             `sfp_media`'s SFP_MEDIA_TABLE with no MAU table, and
             entPhySensorValue refused outright -- a timed-out DOM value
             walk on a device already latched sensor_capable, the 5.35.0
             review fix (F2) that must keep a stored 'optic' badge rather
             than let the empty-sensors cage scan overwrite it.

Three control datagrams, on the same socket as SNMP itself (see
stub_agent_fdb.py, which established this convention):
  STATS       -> the request count so far, as decimal text
  COLUMNS     -> the entPhysicalEntry columns (and ifMauType) asked for,
                 space-separated
  RESET       -> zeroes both
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int, enc_octets, enc_oid,
    enc_varbind,
)

GENERIC_SCALARS = {
    "1.3.6.1.2.1.1.1.0": ("str", "ups/env stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99998.1"),
    "1.3.6.1.2.1.1.3.0": ("int", 654321),
    "1.3.6.1.2.1.1.5.0": ("str", "ups-env-stub"),
}
APC_SCALARS = {**GENERIC_SCALARS,
               "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.318.1.1.1")}
# Enterprise arc 9 (Cisco) sysObjectID, for the "hardware" mode -- the tests
# against it set vendor_detected on the device row directly rather than
# running a full identify walk, so this is here only so the mode looks like
# a real Cisco agent's scalar batch, not because anything reads it back.
CISCO_SCALARS = {**GENERIC_SCALARS,
                 "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.9.1.1")}

# ----------------------------------------------------------------- UPS-MIB
UPS_TABLE = {
    "1.3.6.1.2.1.33.1.2.1.0": ("int", 3),          # upsBatteryStatus: batteryLow
    "1.3.6.1.2.1.33.1.2.2.0": ("int", 45),         # upsSecondsOnBattery
    "1.3.6.1.2.1.33.1.2.3.0": ("int", 12),         # upsEstimatedMinutesRemaining
    "1.3.6.1.2.1.33.1.2.4.0": ("int", 63),         # upsEstimatedChargeRemaining
    "1.3.6.1.2.1.33.1.2.5.0": ("int", 243),        # upsBatteryVoltage: 24.3 V
    "1.3.6.1.2.1.33.1.2.7.0": ("int", 31),         # upsBatteryTemperature
    "1.3.6.1.2.1.33.1.4.1.0": ("int", 5),          # upsOutputSource: battery
    "1.3.6.1.2.1.33.1.6.1.0": ("int", 2),          # upsAlarmsPresent
    "1.3.6.1.2.1.33.1.3.3.1.3.1": ("int", 118),    # upsInputVoltage, line 1
    "1.3.6.1.2.1.33.1.3.3.1.3.2": ("int", 121),    # upsInputVoltage, line 2
    "1.3.6.1.2.1.33.1.4.4.1.5.1": ("int", 55),     # upsOutputPercentLoad, line 1
    "1.3.6.1.2.1.33.1.4.4.1.5.2": ("int", 72),     # upsOutputPercentLoad, line 2
}
APC_UPS_TABLE = {k: v for k, v in UPS_TABLE.items()
                 if k != "1.3.6.1.2.1.33.1.2.3.0"}   # no upsEstimatedMinutesRemaining
APC_RUNTIME_TABLE = {
    "1.3.6.1.4.1.318.1.1.1.2.2.3.0": ("int", 900_000),   # TimeTicks: 9000 s = 150 min
}

# ---------------------------------------------------------- ENTITY-SENSOR
# entPhysicalDescr / entPhySensor{Type,Scale,Precision,Value,Status,Units},
# entity 1 mapped to ifIndex 1, entities 2-4 mapped to nothing.
SENSOR_TABLE = {
    "1.3.6.1.2.1.47.1.1.1.1.2.1": ("str", "Xcvr temp"),
    "1.3.6.1.2.1.47.1.1.1.1.2.2": ("str", "Chassis humidity"),
    "1.3.6.1.2.1.47.1.1.1.1.2.3": ("str", "Failed probe"),
    "1.3.6.1.2.1.47.1.1.1.1.2.4": ("str", "Hot spot"),

    "1.3.6.1.2.1.99.1.1.1.1.1": ("int", 8),    # #1 type: celsius
    "1.3.6.1.2.1.99.1.1.1.1.2": ("int", 9),    # #2 type: %RH
    "1.3.6.1.2.1.99.1.1.1.1.3": ("int", 8),    # #3 type: celsius
    "1.3.6.1.2.1.99.1.1.1.1.4": ("int", 8),    # #4 type: celsius

    "1.3.6.1.2.1.99.1.1.1.2.1": ("int", 9),    # #1 scale: units (10^0)
    "1.3.6.1.2.1.99.1.1.1.2.2": ("int", 8),    # #2 scale: milli (10^-3) -- negative exponent
    "1.3.6.1.2.1.99.1.1.1.2.3": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.2.4": ("int", 9),

    "1.3.6.1.2.1.99.1.1.1.3.1": ("int", 1),    # #1 precision: 1 decimal place
    "1.3.6.1.2.1.99.1.1.1.3.2": ("int", 0),
    "1.3.6.1.2.1.99.1.1.1.3.3": ("int", 0),
    "1.3.6.1.2.1.99.1.1.1.3.4": ("int", 0),

    "1.3.6.1.2.1.99.1.1.1.4.1": ("int", 451),    # #1 value: 451 * 10^0 / 10^1 = 45.1 C
    "1.3.6.1.2.1.99.1.1.1.4.2": ("int", 65000),  # #2 value: 65000 * 10^-3 / 10^0 = 65.0 %RH
    "1.3.6.1.2.1.99.1.1.1.4.3": ("int", 99),     # #3 value: would be 99 C if not excluded
    "1.3.6.1.2.1.99.1.1.1.4.4": ("int", 52),     # #4 value: 52 C -- the device's hottest OK reading

    "1.3.6.1.2.1.99.1.1.1.5.1": ("int", 1),    # #1 status: ok
    "1.3.6.1.2.1.99.1.1.1.5.2": ("int", 1),    # #2 status: ok
    "1.3.6.1.2.1.99.1.1.1.5.3": ("int", 3),    # #3 status: nonoperational
    "1.3.6.1.2.1.99.1.1.1.5.4": ("int", 1),    # #4 status: ok

    # entAliasMappingIdentifier: only entity 1 maps to an ifIndex.
    "1.3.6.1.2.1.47.1.3.2.1.2.1.1": ("str", "1.3.6.1.2.1.2.2.1.1.1"),
}

# The same entities 1/3/4 as SENSOR_TABLE (entity 1 port-mapped, entity 3
# excluded by status, entity 4 an unmapped ok reading) with entity 2 (the
# humidity sensor, and its descr) removed entirely -- a chassis with NO
# humidity sensor at all, so entity 4's reading has no positive "this is a
# room monitor" evidence and must default to temp_chassis_c, never
# temp_ambient_c. This is the "sensor kind cannot be determined" case
# nodepoll._poll_environment's docstring says must not silently become
# ambient. Entity 1's own alias-mapping row (base OID
# "1.3.6.1.2.1.47.1.3.2.1.2", entity 2's happens to share no arc with it)
# is kept.
_DROP_ENTITY_2 = (
    "1.3.6.1.2.1.47.1.1.1.1.2.2",     # descr
    "1.3.6.1.2.1.99.1.1.1.1.2",       # type
    "1.3.6.1.2.1.99.1.1.1.2.2",       # scale
    "1.3.6.1.2.1.99.1.1.1.3.2",       # precision
    "1.3.6.1.2.1.99.1.1.1.4.2",       # value
    "1.3.6.1.2.1.99.1.1.1.5.2",       # status
)
SENSOR_TABLE_NO_HUMIDITY = {oid: value for oid, value in SENSOR_TABLE.items()
                           if oid not in _DROP_ENTITY_2}

# ------------------------------------------- read_hardware / read_dom_all
# Entity 5: a bias-current reading with NO entAliasMappingIdentifier row of
# its own -- only entPhysicalContainedIn pointing at entity 1, which IS
# aliased to ifIndex 1. Proves the containment-chain resolution
# _entity_port_map does (read_dom's own inline walk-up, generalised) reaches
# a sensor mounted on a port-mapped entity rather than aliased directly.
# Entity 1 also gets an entPhysicalName distinct from its entPhysicalDescr,
# so read_hardware's name preference can be told apart from read_dom's
# indifference to this column (read_dom never walks it).
HARDWARE_TABLE = {
    **SENSOR_TABLE,
    "1.3.6.1.2.1.47.1.1.1.1.7.1": ("str", "Gi0/1 SFP module"),   # entPhysicalName, entity 1

    "1.3.6.1.2.1.47.1.1.1.1.2.5": ("str", "Xcvr bias current"),  # entPhysicalDescr
    "1.3.6.1.2.1.99.1.1.1.1.5": ("int", 5),     # #5 type: amperes
    "1.3.6.1.2.1.99.1.1.1.2.5": ("int", 9),     # #5 scale: units
    "1.3.6.1.2.1.99.1.1.1.3.5": ("int", 0),     # #5 precision: 0
    "1.3.6.1.2.1.99.1.1.1.4.5": ("int", 35),    # #5 value: 35 A
    "1.3.6.1.2.1.99.1.1.1.5.5": ("int", 1),     # #5 status: ok
    "1.3.6.1.2.1.47.1.1.1.1.4.5": ("int", 1),   # entPhysicalContainedIn: 5 -> 1
}

# HARDWARE_TABLE with every entPhySensorScale answered as the largest legal
# Integer32 and every entPhySensorPrecision as the smallest -- the shape a
# buggy or hostile agent produces, and the one that made
# _scaled_sensor_value build a multi-billion-digit integer and never
# return. Every other column is untouched, so a reader that clamps the two
# exponents gets the raw values back at scale 9 / precision 0.
_SENSOR_SCALE_COLUMN = "1.3.6.1.2.1.99.1.1.1.2."
_SENSOR_PRECISION_COLUMN = "1.3.6.1.2.1.99.1.1.1.3."
WILD_SCALE_TABLE = {
    oid: (("int", 2147483647) if oid.startswith(_SENSOR_SCALE_COLUMN) else
          ("int", -2147483648) if oid.startswith(_SENSOR_PRECISION_COLUMN)
          else value)
    for oid, value in HARDWARE_TABLE.items()
}

# CISCO-ENVMON-MIB (1.3.6.1.4.1.9.9.13): one row each of supply/fan/
# temperature status, the three enum-driven tables read_hardware's
# _read_cisco_envmon walks. State enum: 1 normal, 2 warning, 3 critical,
# 4 shutdown, 5 notPresent, 6 notFunctioning.
CISCO_ENVMON_TABLE = {
    "1.3.6.1.4.1.9.9.13.1.5.1.2.1": ("str", "PSU 1"),
    "1.3.6.1.4.1.9.9.13.1.5.1.3.1": ("int", 1),        # normal
    "1.3.6.1.4.1.9.9.13.1.4.1.2.1": ("str", "Fan tray 1"),
    "1.3.6.1.4.1.9.9.13.1.4.1.3.1": ("int", 2),        # warning
    "1.3.6.1.4.1.9.9.13.1.3.1.2.1": ("str", "Hot spot"),
    "1.3.6.1.4.1.9.9.13.1.3.1.3.1": ("int", 55),       # value: 55 C
    "1.3.6.1.4.1.9.9.13.1.3.1.4.1": ("int", 70),       # threshold: 70 C
    "1.3.6.1.4.1.9.9.13.1.3.1.6.1": ("int", 3),        # critical
}

# ------------------------------------------- CISCO-ENTITY-SENSOR-MIB
# A Cisco switch as it actually answers: NOTHING under 1.3.6.1.2.1.99 and
# NOT ONE entAliasMappingIdentifier row, so both the standard sensor table
# and the standard entity->ifIndex mapping come back empty and the only way
# to reach these sensors is the Cisco table plus the entPhysicalName match.
#
# Entity 1000 is the port module, named the long way ifDescr names it.
# Sensors 1010-1014 hang off it by entPhysicalContainedIn; only 1010 carries
# the port in its own name, so the other four can only resolve by climbing
# to 1000. Entity 2000 is a chassis inlet probe belonging to no port.
CISCO_DOM_TABLE = {
    "1.3.6.1.2.1.47.1.1.1.1.2.1000": ("str", "TenGigabitEthernet1/1/1"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1000": ("str", "TenGigabitEthernet1/1/1"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1000": ("int", 1),

    "1.3.6.1.2.1.47.1.1.1.1.2.1010": ("str", "Te1/1/1 Module Temperature Sensor"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1010": ("str", "Te1/1/1 Module Temperature Sensor"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1010": ("int", 1000),
    "1.3.6.1.2.1.47.1.1.1.1.2.1011": ("str", "Supply Voltage"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1011": ("str", "Supply Voltage"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1011": ("int", 1000),
    "1.3.6.1.2.1.47.1.1.1.1.2.1012": ("str", "Bias Current"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1012": ("str", "Bias Current"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1012": ("int", 1000),
    "1.3.6.1.2.1.47.1.1.1.1.2.1013": ("str", "Transmit Power"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1013": ("str", "Transmit Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1013": ("int", 1000),
    "1.3.6.1.2.1.47.1.1.1.1.2.1014": ("str", "Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.7.1014": ("str", "Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.1014": ("int", 1000),

    "1.3.6.1.2.1.47.1.1.1.1.2.2000": ("str", "Switch 1 - Inlet Temp Sensor"),
    "1.3.6.1.2.1.47.1.1.1.1.7.2000": ("str", "Switch 1 - Inlet Temp Sensor"),
    "1.3.6.1.2.1.47.1.1.1.1.4.2000": ("int", 1),

    # entSensorType: celsius(8), voltsDC(4), amperes(5), dBm(14) x2, celsius(8)
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.1010": ("int", 8),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.1011": ("int", 4),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.1012": ("int", 5),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.1013": ("int", 14),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.1014": ("int", 14),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.1.2000": ("int", 8),

    # entSensorScale: units(9) or milli(8)
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.1010": ("int", 9),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.1011": ("int", 8),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.1012": ("int", 8),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.1013": ("int", 9),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.1014": ("int", 8),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.2.2000": ("int", 9),

    # entSensorPrecision
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.1010": ("int", 0),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.1011": ("int", 0),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.1012": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.1013": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.1014": ("int", 0),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.3.2000": ("int", 0),

    # entSensorValue. The two dBm rows are the two shapes real Cisco gear
    # reports optical power in, and BOTH decode through the ordinary RFC
    # 3433 arithmetic with no dBm special case: IOS writes units(9)/
    # precision 1/-24 for -2.4 dBm, NX-OS writes milli(8)/precision 0/
    # -5500 for -5.5 dBm.
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.1010": ("int", 33),      # 33 C
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.1011": ("int", 3299),    # 3.299 V DC
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.1012": ("int", 62),      # 0.0062 A
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.1013": ("int", -24),     # -2.4 dBm
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.1014": ("int", -5500),   # -5.5 dBm
    "1.3.6.1.4.1.9.9.91.1.1.1.1.4.2000": ("int", 41),      # 41 C

    # entSensorStatus: ok(1) throughout
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.1010": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.1011": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.1012": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.1013": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.1014": ("int", 1),
    "1.3.6.1.4.1.9.9.91.1.1.1.1.5.2000": ("int", 1),
}

# --------------------------------- entSensorThresholdTable (CISCO, 5.3.0)
# The levels a transceiver publishes about itself, indexed
# <entPhysicalIndex>.<threshold index>. Its own dict, merged only into the
# `cisco_dom_thresholds` mode, so `cisco_dom` stays byte-identical for the
# suites that assert request counts against it.
#
# The whole point of this fixture is that each entity quotes its thresholds
# in ITS OWN scale and precision -- the same two that CISCO_DOM_TABLE gives
# its reading:
#
#   1013 Tx, scale units(9)/precision 1: -82 -> -8.2 dBm
#   1014 Rx, scale milli(8)/precision 0: -14400 -> -14.4 dBm
#
# A threshold decoded against the wrong entity's scale is out by a factor of
# a thousand and still looks like a plausible dBm figure, so only a fixture
# with two different scales can catch it.
#
# Deliberately also here: 1010 publishes ONE level (partial publication);
# 1011 publishes an equalTo(5) relation and an other(1) severity, both of
# which name no band and must be dropped; 1012 quotes low_warn twice, and
# the tighter (earlier-alerting) one must win; 2000, the chassis inlet, is
# mapped to no port and must produce no row at all.
CISCO_DOM_THRESHOLD_TABLE = {
    # --- 1010 optic temperature: a major/greaterOrEqual level and nothing else
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1010.1": ("int", 20),      # major
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1010.1": ("int", 4),       # greaterOrEqual
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1010.1": ("int", 75),      # 75 C

    # --- 1011 supply voltage: an equalTo relation and an other severity
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1011.1": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1011.1": ("int", 5),       # equalTo
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1011.1": ("int", 3000),
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1011.2": ("int", 1),       # other
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1011.2": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1011.2": ("int", 2900),

    # --- 1012 bias current: low_warn quoted twice, tighter must win
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1012.1": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1012.1": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1012.1": ("int", 20),      # 0.002 A
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1012.2": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1012.2": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1012.2": ("int", 30),      # 0.003 A

    # --- 1013 Tx power, scale units(9) / precision 1
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1013.1": ("int", 30),      # critical
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1013.1": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1013.1": ("int", -82),     # -8.2 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1013.2": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1013.2": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1013.2": ("int", -73),     # -7.3 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1013.3": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1013.3": ("int", 3),       # greaterThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1013.3": ("int", 15),      # 1.5 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1013.4": ("int", 30),      # critical
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1013.4": ("int", 3),       # greaterThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1013.4": ("int", 20),      # 2.0 dBm

    # --- 1014 Rx power, scale milli(8) / precision 0
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1014.1": ("int", 30),      # critical
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1014.1": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1014.1": ("int", -14400),  # -14.4 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1014.2": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1014.2": ("int", 1),       # lessThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1014.2": ("int", -11400),  # -11.4 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1014.3": ("int", 10),      # minor
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1014.3": ("int", 3),       # greaterThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1014.3": ("int", 500),     # 0.5 dBm
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.1014.4": ("int", 30),      # critical
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.1014.4": ("int", 3),       # greaterThan
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.1014.4": ("int", 1000),    # 1.0 dBm

    # --- 2000 the chassis inlet: mapped to no port, so no row may result
    "1.3.6.1.4.1.9.9.91.1.2.1.1.2.2000.1": ("int", 20),
    "1.3.6.1.4.1.9.9.91.1.2.1.1.3.2000.1": ("int", 3),
    "1.3.6.1.4.1.9.9.91.1.2.1.1.4.2000.1": ("int", 55),
}
# ------------------------------------------- SFP media and the dark optic
# Eleven ports, one row of ENTITY-MIB reality each. Ports 1/5/6/7 carry
# standard ENTITY-SENSOR-MIB optical-power rows (dBm(14), scale units(9),
# precision 1) and are aliased to their ifIndex; ports 2/3/4 have no sensor
# of any kind, which is exactly why entPhysicalClass has to answer for them:
#
#   if 1  a working optic, -5.5 dBm                     -> media 'optic'
#   if 2  a cage holding a transceiver that reports no DOM  -> media 'sfp'
#   if 3  a cage with nothing in it                     -> media 'sfp_empty'
#   if 4  a copper port an agent ALSO models as container+port, naming no
#         transceiver anywhere -> media NULL, never a badge
#   if 5  a two-lane optic, one lane dark at -40 and one healthy at -6
#   if 6  a two-lane optic dark on both lanes
#   if 7  a single-lane optic transmitting at exactly 0.0 dBm -- 1 mW, a
#         nominal level for an ER/ZR part, and what an agent quoting 0.1 dBm
#         units rounds -0.04 to
#
# Copper (5.25.0), added without renumbering the seven ports above:
#   if 8  module text "1000BaseT SFP" / model "GLC-T", no sensor at all
#         -> media 'copper' from text alone
#   if 9  module text "SFP-10G-T-S", one temperature-only sensor (no
#         optical-power row) -> media 'copper': medium wins over "has a
#         DOM reading", and sfp_temp_c.9 is still recorded
#   if 10 module names a transceiver but nothing telling ("Transceiver
#         module"), no sensor -> text alone leaves it 'sfp'; ifMauType
#         arc 30 (1000BASE-T) is what makes it 'copper' -- see SFP_MAU_TABLE
#   if 11 module text "SFP-10G-SR" (optical, not copper) plus a real DOM
#         Rx row, AND an ifMauType arc 36 (10GBASE-SR) row on the same
#         port -- proves fiber wins a MAU/text disagreement, and that a
#         MAU fiber verdict never turns off a genuine optic
#
# Gate/veto edge cases (5.25.1 review):
#   if 12 copper text (GLC-T), fiber ifMauType (arc 36), no sensor -> 'sfp'
#   if 13 combo port text, real Rx dBm sensor -> 'optic' beats copper text
#   if 14 ambiguous transceiver text, a MAU row under the wrong OID prefix
#         -> ignored, stays 'sfp'
SFP_MEDIA_TABLE = {
    # --- if 1: an ordinary DOM optic
    "1.3.6.1.2.1.47.1.1.1.1.2.101": ("str", "GigabitEthernet1/0/1"),
    "1.3.6.1.2.1.47.1.1.1.1.5.101": ("int", 10),               # port
    "1.3.6.1.2.1.47.1.3.2.1.2.101.1": ("str", "1.3.6.1.2.1.2.2.1.1.1"),
    "1.3.6.1.2.1.47.1.1.1.1.2.111": ("str", "Gi1/0/1 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.111": ("int", 101),
    "1.3.6.1.2.1.99.1.1.1.1.111": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.111": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.111": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.111": ("int", -55),                # -5.5 dBm
    "1.3.6.1.2.1.99.1.1.1.5.111": ("int", 1),

    # --- if 2: an occupied cage, no sensors at all
    "1.3.6.1.2.1.47.1.1.1.1.2.202": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.202": ("int", 5),                # container
    "1.3.6.1.2.1.47.1.1.1.1.2.252": ("str", "GigabitEthernet1/0/2"),
    "1.3.6.1.2.1.47.1.1.1.1.5.252": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.252": ("int", 202),
    "1.3.6.1.2.1.47.1.3.2.1.2.252.1": ("str", "1.3.6.1.2.1.2.2.1.1.2"),
    "1.3.6.1.2.1.47.1.1.1.1.2.302": ("str", "10Gbase-LR SFP+"),
    "1.3.6.1.2.1.47.1.1.1.1.5.302": ("int", 9),                # module
    "1.3.6.1.2.1.47.1.1.1.1.4.302": ("int", 202),
    "1.3.6.1.2.1.47.1.1.1.1.13.302": ("str", "SFP-10G-LR"),

    # --- if 3: the same cage with nothing in it
    "1.3.6.1.2.1.47.1.1.1.1.2.203": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.203": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.253": ("str", "GigabitEthernet1/0/3"),
    "1.3.6.1.2.1.47.1.1.1.1.5.253": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.253": ("int", 203),
    "1.3.6.1.2.1.47.1.3.2.1.2.253.1": ("str", "1.3.6.1.2.1.2.2.1.1.3"),

    # --- if 4: a copper port modelled the same way, naming no transceiver
    "1.3.6.1.2.1.47.1.1.1.1.2.204": ("str", "GigabitEthernet1/0/4 Container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.204": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.254": ("str", "GigabitEthernet1/0/4"),
    "1.3.6.1.2.1.47.1.1.1.1.5.254": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.254": ("int", 204),
    "1.3.6.1.2.1.47.1.3.2.1.2.254.1": ("str", "1.3.6.1.2.1.2.2.1.1.4"),

    # --- if 5: one dark lane, one healthy lane
    "1.3.6.1.2.1.47.1.1.1.1.2.105": ("str", "GigabitEthernet1/0/5"),
    "1.3.6.1.2.1.47.1.1.1.1.5.105": ("int", 10),
    "1.3.6.1.2.1.47.1.3.2.1.2.105.1": ("str", "1.3.6.1.2.1.2.2.1.1.5"),
    "1.3.6.1.2.1.47.1.1.1.1.2.151": ("str", "Gi1/0/5 Lane 1 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.151": ("int", 105),
    "1.3.6.1.2.1.99.1.1.1.1.151": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.151": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.151": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.151": ("int", -400),               # -40.0 dBm
    "1.3.6.1.2.1.99.1.1.1.5.151": ("int", 1),                  # and ok(1)
    "1.3.6.1.2.1.47.1.1.1.1.2.152": ("str", "Gi1/0/5 Lane 2 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.152": ("int", 105),
    "1.3.6.1.2.1.99.1.1.1.1.152": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.152": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.152": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.152": ("int", -60),                # -6.0 dBm
    "1.3.6.1.2.1.99.1.1.1.5.152": ("int", 1),

    # --- if 6: dark on both lanes
    "1.3.6.1.2.1.47.1.1.1.1.2.106": ("str", "GigabitEthernet1/0/6"),
    "1.3.6.1.2.1.47.1.1.1.1.5.106": ("int", 10),
    "1.3.6.1.2.1.47.1.3.2.1.2.106.1": ("str", "1.3.6.1.2.1.2.2.1.1.6"),
    "1.3.6.1.2.1.47.1.1.1.1.2.161": ("str", "Gi1/0/6 Lane 1 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.161": ("int", 106),
    "1.3.6.1.2.1.99.1.1.1.1.161": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.161": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.161": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.161": ("int", -400),
    "1.3.6.1.2.1.99.1.1.1.5.161": ("int", 1),
    "1.3.6.1.2.1.47.1.1.1.1.2.162": ("str", "Gi1/0/6 Lane 2 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.162": ("int", 106),
    "1.3.6.1.2.1.99.1.1.1.1.162": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.162": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.162": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.162": ("int", -400),
    "1.3.6.1.2.1.99.1.1.1.5.162": ("int", 1),

    # --- if 7: transmitting at exactly 0.0 dBm
    "1.3.6.1.2.1.47.1.1.1.1.2.107": ("str", "GigabitEthernet1/0/7"),
    "1.3.6.1.2.1.47.1.1.1.1.5.107": ("int", 10),
    "1.3.6.1.2.1.47.1.3.2.1.2.107.1": ("str", "1.3.6.1.2.1.2.2.1.1.7"),
    "1.3.6.1.2.1.47.1.1.1.1.2.171": ("str", "Gi1/0/7 Transmit Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.171": ("int", 107),
    "1.3.6.1.2.1.99.1.1.1.1.171": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.171": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.171": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.171": ("int", 0),                  # 0.0 dBm
    "1.3.6.1.2.1.99.1.1.1.5.171": ("int", 1),

    # --- if 8: copper module text, no sensor at all
    "1.3.6.1.2.1.47.1.1.1.1.2.208": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.208": ("int", 5),                # container
    "1.3.6.1.2.1.47.1.1.1.1.2.258": ("str", "GigabitEthernet1/0/8"),
    "1.3.6.1.2.1.47.1.1.1.1.5.258": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.258": ("int", 208),
    "1.3.6.1.2.1.47.1.3.2.1.2.258.1": ("str", "1.3.6.1.2.1.2.2.1.1.8"),
    "1.3.6.1.2.1.47.1.1.1.1.2.308": ("str", "1000BaseT SFP"),
    "1.3.6.1.2.1.47.1.1.1.1.5.308": ("int", 9),                # module
    "1.3.6.1.2.1.47.1.1.1.1.4.308": ("int", 208),
    "1.3.6.1.2.1.47.1.1.1.1.13.308": ("str", "GLC-T"),

    # --- if 9: copper module text, one temperature-only sensor
    "1.3.6.1.2.1.47.1.1.1.1.2.209": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.209": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.259": ("str", "GigabitEthernet1/0/9"),
    "1.3.6.1.2.1.47.1.1.1.1.5.259": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.259": ("int", 209),
    "1.3.6.1.2.1.47.1.3.2.1.2.259.1": ("str", "1.3.6.1.2.1.2.2.1.1.9"),
    "1.3.6.1.2.1.47.1.1.1.1.2.309": ("str", "SFP-10G-T-S"),
    "1.3.6.1.2.1.47.1.1.1.1.5.309": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.309": ("int", 209),
    "1.3.6.1.2.1.47.1.1.1.1.2.359": ("str", "Gi1/0/9 Temperature Sensor"),
    "1.3.6.1.2.1.47.1.1.1.1.4.359": ("int", 259),
    "1.3.6.1.2.1.99.1.1.1.1.359": ("int", 8),                  # temperature
    "1.3.6.1.2.1.99.1.1.1.2.359": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.359": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.359": ("int", 350),                # 35.0 C
    "1.3.6.1.2.1.99.1.1.1.5.359": ("int", 1),

    # --- if 10: module text names a transceiver but nothing telling; only
    # ifMauType (SFP_MAU_TABLE, arc 30) proves it copper
    "1.3.6.1.2.1.47.1.1.1.1.2.210": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.210": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.260": ("str", "GigabitEthernet1/0/10"),
    "1.3.6.1.2.1.47.1.1.1.1.5.260": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.260": ("int", 210),
    "1.3.6.1.2.1.47.1.3.2.1.2.260.1": ("str", "1.3.6.1.2.1.2.2.1.1.10"),
    "1.3.6.1.2.1.47.1.1.1.1.2.310": ("str", "Transceiver module"),
    "1.3.6.1.2.1.47.1.1.1.1.5.310": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.310": ("int", 210),

    # --- if 11: an optical module (real DOM Rx row) that also answers an
    # ifMauType fiber arc (SFP_MAU_TABLE, arc 36) -- fiber must not be
    # downgraded, and must stay 'optic'
    "1.3.6.1.2.1.47.1.1.1.1.2.211": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.211": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.261": ("str", "GigabitEthernet1/0/11"),
    "1.3.6.1.2.1.47.1.1.1.1.5.261": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.261": ("int", 211),
    "1.3.6.1.2.1.47.1.3.2.1.2.261.1": ("str", "1.3.6.1.2.1.2.2.1.1.11"),
    "1.3.6.1.2.1.47.1.1.1.1.2.311": ("str", "SFP-10G-SR"),
    "1.3.6.1.2.1.47.1.1.1.1.5.311": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.311": ("int", 211),
    "1.3.6.1.2.1.47.1.1.1.1.2.371": ("str", "Gi1/0/11 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.371": ("int", 261),
    "1.3.6.1.2.1.99.1.1.1.1.371": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.371": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.371": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.371": ("int", -60),                # -6.0 dBm
    "1.3.6.1.2.1.99.1.1.1.5.371": ("int", 1),

    # --- if 12: copper text (GLC-T), no sensor -- ifMauType fiber arc
    # (SFP_MAU_TABLE) must veto the text down to 'sfp'
    "1.3.6.1.2.1.47.1.1.1.1.2.212": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.212": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.262": ("str", "GigabitEthernet1/0/12"),
    "1.3.6.1.2.1.47.1.1.1.1.5.262": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.262": ("int", 212),
    "1.3.6.1.2.1.47.1.3.2.1.2.262.1": ("str", "1.3.6.1.2.1.2.2.1.1.12"),
    "1.3.6.1.2.1.47.1.1.1.1.2.312": ("str", "1000BaseT SFP"),
    "1.3.6.1.2.1.47.1.1.1.1.5.312": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.312": ("int", 212),
    "1.3.6.1.2.1.47.1.1.1.1.13.312": ("str", "GLC-T"),

    # --- if 13: combo port text with a real Rx dBm sensor -- DOM must beat
    # copper text (5.25.0's dbm_ports subtraction)
    "1.3.6.1.2.1.47.1.1.1.1.2.213": ("str", "1000BASE-T/SFP combo"),
    "1.3.6.1.2.1.47.1.1.1.1.5.213": ("int", 10),
    "1.3.6.1.2.1.47.1.3.2.1.2.213.1": ("str", "1.3.6.1.2.1.2.2.1.1.13"),
    "1.3.6.1.2.1.47.1.1.1.1.2.413": ("str", "Gi1/0/13 Receive Power"),
    "1.3.6.1.2.1.47.1.1.1.1.4.413": ("int", 213),
    "1.3.6.1.2.1.99.1.1.1.1.413": ("int", 14),
    "1.3.6.1.2.1.99.1.1.1.2.413": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.3.413": ("int", 1),
    "1.3.6.1.2.1.99.1.1.1.4.413": ("int", -50),                # -5.0 dBm
    "1.3.6.1.2.1.99.1.1.1.5.413": ("int", 1),

    # --- if 14: ambiguous transceiver text, no sensor, a MAU row whose
    # value OID is NOT under dot3MauType -- must be ignored, leaving 'sfp'
    "1.3.6.1.2.1.47.1.1.1.1.2.214": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.214": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.264": ("str", "GigabitEthernet1/0/14"),
    "1.3.6.1.2.1.47.1.1.1.1.5.264": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.264": ("int", 214),
    "1.3.6.1.2.1.47.1.3.2.1.2.264.1": ("str", "1.3.6.1.2.1.2.2.1.1.14"),
    "1.3.6.1.2.1.47.1.1.1.1.2.314": ("str", "Transceiver module"),
    "1.3.6.1.2.1.47.1.1.1.1.5.314": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.314": ("int", 214),

    # --- if 15: module text "SFP-GE-T", no sensor -- 5.25.1's widened
    # _COPPER_TEXT alternative, from text alone
    "1.3.6.1.2.1.47.1.1.1.1.2.215": ("str", "SFP+ container"),
    "1.3.6.1.2.1.47.1.1.1.1.5.215": ("int", 5),
    "1.3.6.1.2.1.47.1.1.1.1.2.265": ("str", "GigabitEthernet1/0/15"),
    "1.3.6.1.2.1.47.1.1.1.1.5.265": ("int", 10),
    "1.3.6.1.2.1.47.1.1.1.1.4.265": ("int", 215),
    "1.3.6.1.2.1.47.1.3.2.1.2.265.1": ("str", "1.3.6.1.2.1.2.2.1.1.15"),
    "1.3.6.1.2.1.47.1.1.1.1.2.315": ("str", "SFP-GE-T"),
    "1.3.6.1.2.1.47.1.1.1.1.5.315": ("int", 9),
    "1.3.6.1.2.1.47.1.1.1.1.4.315": ("int", 215),
}

# MAU-MIB ifMauType rows (ifIndex.mauIndex -> an OID whose last arc is a
# dot3MauType, or a bogus prefix for if 14's negative case). if 10/11 prove
# copper/fiber from the wire; 3/4 pin the entity-scan gate (an empty cage
# and a bare copper port must not be confirmed copper by the arc alone);
# 12 is the fiber-veto-with-no-sensor case; 14 is the wrong-OID-prefix
# case. Merged into 'sfp_media' only, never into 'sfp_media_no_class' or
# 'sfp_media_no_mau', so those two keep exercising the no-MAU-answered path.
IF_MAU_TYPE = "1.3.6.1.2.1.26.2.1.1.3"
SFP_MAU_TABLE = {
    f"{IF_MAU_TYPE}.3.1": ("oid", "1.3.6.1.2.1.26.4.30"),
    f"{IF_MAU_TYPE}.8.1": ("oid", "1.3.6.1.2.1.26.4.22"),    # 1000BASE-X: no vote
    f"{IF_MAU_TYPE}.4.1": ("oid", "1.3.6.1.2.1.26.4.30"),
    f"{IF_MAU_TYPE}.10.1": ("oid", "1.3.6.1.2.1.26.4.30"),
    f"{IF_MAU_TYPE}.11.1": ("oid", "1.3.6.1.2.1.26.4.36"),
    f"{IF_MAU_TYPE}.12.1": ("oid", "1.3.6.1.2.1.26.4.36"),
    f"{IF_MAU_TYPE}.14.1": ("oid", "1.3.6.1.4.1.9.9.99.30"),
}

# sfp_media_no_sensors (5.35.0, F1): the cage/alias/containment rows, with
# every ENTITY-SENSOR-MIB reading (1.3.6.1.2.1.99.*) removed.
SFP_MEDIA_NO_SENSORS_TABLE = {oid: value for oid, value in SFP_MEDIA_TABLE.items()
                              if not oid.startswith("1.3.6.1.2.1.99.")}

# sfp_media_no_port_map (5.35.0, F3): one alias row that answers something,
# just not an ifIndex -- so port_map ends up empty while alias_rows is not
# zero, the "no entity mapped to a port" diagnostic's own trigger.
PORT_MAP_EMPTY_TABLE = {
    "1.3.6.1.2.1.47.1.3.2.1.2.900.1": ("str", "1.3.6.1.2.1.99.1.1.1.1.900"),
}

# A mode may refuse a whole column outright, which is not the same as
# answering it empty: a real agent that goes quiet part-way through a big
# entPhysical walk leaves its caller with a timeout, and a caller that
# deletes rows its walk did not produce has to be able to tell the two
# apart. Keyed by mode, the column's base OID.
_ENT_PHYSICAL_NAME_COL = "1.3.6.1.2.1.47.1.1.1.1.7"
DEAD_COLUMNS = {
    "sfp_media_no_class": ("1.3.6.1.2.1.47.1.1.1.1.5",),
    "sfp_media_no_names": (_ENT_PHYSICAL_NAME_COL,),
    "sfp_media_no_sensor_values": ("1.3.6.1.2.1.99.1.1.1.4",),
}

# Which entPhysicalEntry columns (and ifMauType) a run was asked for at
# all. A walk asks for its column's base OID and then resumes from the last
# row it accepted, so every request it makes carries that column -- which is
# what makes "was this column ever walked?" a question a test can put, and
# each column is a whole table walk of cost.
ENT_PHYSICAL_ENTRY = "1.3.6.1.2.1.47.1.1.1.1."
COLUMNS_SEEN: set = set()

MODE = "ups"


def refuses(oid):
    return any(oid == base or oid.startswith(base + ".")
               for base in DEAD_COLUMNS.get(MODE, ()))


def table_for():
    if MODE == "ups":
        return {**GENERIC_SCALARS, **UPS_TABLE}
    if MODE == "no_ups":
        return dict(GENERIC_SCALARS)
    if MODE == "apc_ups":
        return {**APC_SCALARS, **APC_UPS_TABLE, **APC_RUNTIME_TABLE}
    if MODE == "sensors":
        return {**GENERIC_SCALARS, **SENSOR_TABLE}
    if MODE == "sensors_no_humidity":
        return {**GENERIC_SCALARS, **SENSOR_TABLE_NO_HUMIDITY}
    if MODE == "hardware":
        return {**CISCO_SCALARS, **HARDWARE_TABLE, **CISCO_ENVMON_TABLE}
    if MODE == "wild_scale":
        return {**CISCO_SCALARS, **WILD_SCALE_TABLE}
    if MODE == "cisco_dom":
        return {**CISCO_SCALARS, **CISCO_DOM_TABLE}
    if MODE == "cisco_dom_thresholds":
        return {**CISCO_SCALARS, **CISCO_DOM_TABLE,
                **CISCO_DOM_THRESHOLD_TABLE}
    if MODE == "sfp_media":
        return {**GENERIC_SCALARS, **SFP_MEDIA_TABLE, **SFP_MAU_TABLE}
    if MODE in ("sfp_media_no_class", "sfp_media_no_mau"):
        return {**GENERIC_SCALARS, **SFP_MEDIA_TABLE}
    if MODE == "sfp_media_no_sensors":
        return {**GENERIC_SCALARS, **SFP_MEDIA_NO_SENSORS_TABLE}
    if MODE == "sfp_media_no_names":
        return {**CISCO_SCALARS, **SFP_MEDIA_TABLE, **SFP_MAU_TABLE}
    if MODE == "sfp_media_no_port_map":
        return {**GENERIC_SCALARS, **PORT_MAP_EMPTY_TABLE}
    if MODE == "sfp_media_no_sensor_values":
        return {**GENERIC_SCALARS, **SFP_MEDIA_TABLE}
    return dict(GENERIC_SCALARS)


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    if kind in ("str", "bytes"):
        return enc_octets(value)
    if kind == "oid":
        return enc_oid(value)
    return enc_int(value)


def reply(request_id, body):
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets("public") + pdu)


def main():
    global MODE
    port = int(sys.argv[1])
    MODE = sys.argv[2] if len(sys.argv) > 2 else "ups"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"UPS/env stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
    count = 0
    while True:
        data, addr = sock.recvfrom(65535)
        if data == b"STATS":
            sock.sendto(str(count).encode(), addr)
            continue
        if data == b"COLUMNS":
            sock.sendto(" ".join(sorted(COLUMNS_SEEN)).encode(), addr)
            continue
        if data == b"RESET":
            count = 0
            COLUMNS_SEEN.clear()
            sock.sendto(b"0", addr)
            continue
        try:
            request = decode_response(data)
        except Exception:
            continue
        if not request.varbinds:
            continue
        count += 1
        table = table_for()
        keys = sorted(table, key=oid_key)
        oids = [vb["oid"] for vb in request.varbinds]
        if oids[0].startswith(ENT_PHYSICAL_ENTRY):
            COLUMNS_SEEN.add(".".join(oids[0].split(".")[:12]))
        elif oids[0].startswith(IF_MAU_TYPE):
            COLUMNS_SEEN.add(IF_MAU_TYPE)
        if refuses(oids[0]):
            continue
        if request.pdu_tag == PDU_GET:
            body = b""
            for oid in oids:
                entry = table.get(oid)
                body += enc_varbind(oid, _tlv(T_NO_SUCH_OBJECT, b"")
                                    if entry is None else encode_value(*entry))
        elif request.pdu_tag == PDU_GETNEXT:
            rk = oid_key(oids[0])
            nxt = next((k for k in keys if oid_key(k) > rk), None)
            body = (enc_varbind(oids[0], _tlv(T_END_OF_MIB_VIEW, b""))
                    if nxt is None else enc_varbind(nxt, encode_value(*table[nxt])))
        elif request.pdu_tag == PDU_GETBULK:
            max_repetitions = max(1, request.error_index or 1)
            cursor = oids[0]
            body = b""
            for _ in range(max_repetitions):
                rk = oid_key(cursor)
                nxt = next((k for k in keys if oid_key(k) > rk), None)
                if nxt is None:
                    body += enc_varbind(cursor, _tlv(T_END_OF_MIB_VIEW, b""))
                    break
                body += enc_varbind(nxt, encode_value(*table[nxt]))
                cursor = nxt
        else:
            continue
        sock.sendto(reply(request.request_id, body), addr)


if __name__ == "__main__":
    main()

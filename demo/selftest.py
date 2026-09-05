"""Offline proof that the demo fleet speaks the app's own SNMP.

Runs entirely against demo/fleet.py's `handle_packet()` — request bytes in,
reply bytes out, no sockets on port 161 — using the app's OWN builders
(netpath.snmppoll.build_request / build_v3_request) and its OWN decoder
(netpath.snmppoll.decode_response). If the fleet and the poller ever
disagree about the wire format, it fails here rather than as an
unexplained timeout during a demo.

    python3 demo/selftest.py            # exit 0 = every persona is pollable

Checks, per persona:
  1. every nodeoids.SYSTEM_SCALARS OID answers, with the right SNMP type
  2. a GETBULK walk of ifTable (and ifXTable) yields exactly the persona's
     port count and terminates on endOfMibView
  3. v3 engine discovery decodes through snmppoll's own v3 decoder and
     yields a non-empty engineID
  4. a v3 authNoPriv reply verifies with find_auth_span + HMAC
  5. the tooBig and authorizationError knobs really produce error_status
     1 and 16
and then, once, a real socket on 127.0.0.250:161 polled with
nodepoll._Session to prove the wire path end to end.
"""

from __future__ import annotations

import os
import random
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import fleet as fleetmod                          # noqa: E402
from demo import personas                                   # noqa: E402
from netpath import nodeoids                                # noqa: E402
from netpath.nodepoll import NodePoller, _Session            # noqa: E402
from netpath.nodesdb import NodesDatabase                   # noqa: E402
from netpath.snmppoll import (                              # noqa: E402
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT, build_request,
    build_v3_request, decode_response, discovery_probe, find_auth_span,
)
from netpath.trapdecode import (                            # noqa: E402
    AUTH_PROTOCOLS, V1, V2C, Decoder, Trap, localized_key,
)

IF_INDEX = nodeoids.IF_TABLE["if_index"]
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

FAILURES: list[str] = []
CHECKS = [0]


def check(condition, message: str) -> bool:
    CHECKS[0] += 1
    if not condition:
        FAILURES.append(message)
        print(f"  FAIL {message}")
        return False
    return True


def make_device(persona_key: str, index: int = 900, **knobs) -> personas.DeviceState:
    profile = knobs.pop("profile", "v2c-public")
    settings = personas.PROFILES[profile]
    if settings["snmp_version"] == 3:
        knobs.setdefault("v3", "sha" if profile == "v3-sha" else "noauth")
        knobs["v3_user"] = settings["v3_user"]
        knobs["v3_password"] = settings.get("v3_auth_password", "")
    entry = {"index": index, "ip": personas.ip_for(index),
             "name": f"selftest-{persona_key}", "persona": persona_key,
             "site": "Site-A", "snmp_version": settings["snmp_version"],
             "community": "public", "profile": profile, "knobs": knobs}
    return personas.build_device(entry)


def ask(dev, packet: bytes):
    reply = fleetmod.handle_packet(dev, packet)
    return None if reply is None else decode_response(reply)


# --------------------------------------------------------------- 1. scalars

EXPECTED_TYPES = {
    "sys_descr": "STRING", "sys_object_id": "OID", "sys_uptime": "TimeTicks",
    "sys_contact": "STRING", "sys_name": "STRING", "sys_location": "STRING",
}


def test_scalars(key: str, dev) -> None:
    for name, oid in nodeoids.SYSTEM_SCALARS.items():
        packet = build_request(V2C, "public", PDU_GET, random.randint(1, 65535), [oid])
        response = ask(dev, packet)
        if not check(response is not None, f"{key}: no reply to GET {name}"):
            continue
        if not check(len(response.varbinds) == 1,
                     f"{key}: {name} answered {len(response.varbinds)} varbinds"):
            continue
        vb = response.varbinds[0]
        check(vb["oid"] == oid, f"{key}: {name} answered a different OID ({vb['oid']})")
        check(vb["type"] == EXPECTED_TYPES[name],
              f"{key}: {name} is {vb['type']}, expected {EXPECTED_TYPES[name]}")
        check(vb["value"] not in (None, ""), f"{key}: {name} answered empty")


# ------------------------------------------------------------- 2. bulk walk

def bulk_walk(dev, base: str, max_repetitions: int = 40,
              version: int = V2C, community: str = "public"):
    """The same loop nodepoll._walk_column runs: GETBULK, take varbinds in
    order until one leaves the subtree or reports end-of-MIB, resume from
    the last accepted OID. Returns (values, stop_reason, requests)."""
    values: dict[str, object] = {}
    current = base
    requests = 0
    reason = "cap"
    while requests < 400:
        packet = build_request(version, community,
                               PDU_GETBULK if version != V1 else PDU_GETNEXT,
                               random.randint(1, 65535), [current],
                               max_repetitions=max_repetitions)
        response = ask(dev, packet)
        requests += 1
        if response is None:
            return values, "no reply", requests
        if response.error_status == 1:
            return values, "tooBig", requests
        if response.error_status:
            return values, f"error {response.error_status}", requests
        if not response.varbinds:
            return values, "empty", requests
        stop = ""
        for vb in response.varbinds:
            oid = vb["oid"]
            if not (oid == base or oid.startswith(base + ".")):
                stop = "left subtree"
                break
            if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                stop = "endOfMibView"
                break
            if nodeoids.oid_key(oid) <= nodeoids.oid_key(current):
                stop = "non-increasing"
                break
            values[oid[len(base) + 1:]] = vb["value"]
            current = oid
        if stop:
            reason = stop
            break
    return values, reason, requests


def port_count(dev) -> int:
    table = dev.table(None)
    prefix = IF_INDEX + "."
    return sum(1 for oid in table.oids if oid.startswith(prefix))


def test_if_walk(key: str, dev) -> None:
    expected = port_count(dev)
    values, reason, requests = bulk_walk(dev, IF_INDEX)
    check(len(values) == expected,
          f"{key}: ifIndex walk found {len(values)} rows, expected {expected}")
    check(reason in ("endOfMibView", "left subtree"),
          f"{key}: ifIndex walk stopped with {reason!r}")
    check(requests < 400, f"{key}: ifIndex walk did not terminate")

    if dev.table(None).has(f"{IF_NAME}.1"):
        values, reason, _ = bulk_walk(dev, IF_NAME)
        check(len(values) == expected,
              f"{key}: ifName walk found {len(values)} rows, expected {expected}")
        check(reason in ("endOfMibView", "left subtree"),
              f"{key}: ifName walk stopped with {reason!r}")

    # A walk that starts past the end of the table must report end-of-MIB
    # rather than looping or answering the request back.
    last = dev.table(None).oids[-1]
    packet = build_request(V2C, "public", PDU_GETNEXT, 1, [last])
    response = ask(dev, packet)
    check(response is not None and response.varbinds and
          response.varbinds[0]["type"] == "endOfMibView",
          f"{key}: GETNEXT past the last OID did not answer endOfMibView")


# -------------------------------------------------------------- 3/4. SNMPv3

def test_v3_discovery(key: str) -> None:
    dev = make_device(key, index=901, profile="v3-noauth")
    response = ask(dev, discovery_probe(msg_id=7))
    if not check(response is not None, f"{key}: no reply to the v3 discovery probe"):
        return
    check(response.pdu_tag == PDU_REPORT,
          f"{key}: discovery answered pdu 0x{response.pdu_tag:02X}, expected a Report")
    check(bool(response.engine_id),
          f"{key}: discovery reply carried no engineID")
    check(response.engine_id == dev.engine_id,
          f"{key}: discovery reply carried the wrong engineID")
    check(response.engine_boots >= 1, f"{key}: engineBoots was {response.engine_boots}")

    # ... and then a real noAuthNoPriv GET against the discovered engine.
    packet = build_v3_request(
        8, 4242, PDU_GET, [nodeoids.SYSTEM_SCALARS["sys_descr"]],
        engine_id=response.engine_id, engine_boots=response.engine_boots,
        engine_time=response.engine_time, user="poller")
    answer = ask(dev, packet)
    if not check(answer is not None, f"{key}: no reply to a noAuthNoPriv GET"):
        return
    check(answer.pdu_tag != PDU_REPORT,
          f"{key}: noAuthNoPriv GET was answered with a Report, not a Response")
    check(answer.varbinds and answer.varbinds[0]["type"] == "STRING",
          f"{key}: noAuthNoPriv GET did not return sysDescr")


def test_v3_sha(key: str) -> None:
    dev = make_device(key, index=902, profile="v3-sha")
    password = personas.PROFILES["v3-sha"]["v3_auth_password"]
    report = ask(dev, discovery_probe(msg_id=11))
    if not check(report is not None and report.engine_id,
                 f"{key}: SHA device did not answer engine discovery"):
        return
    auth_key = localized_key("SHA", password, report.engine_id)
    packet = build_v3_request(
        12, 777, PDU_GET, [nodeoids.SYSTEM_SCALARS["sys_descr"]],
        engine_id=report.engine_id, engine_boots=report.engine_boots,
        engine_time=report.engine_time, user="poller",
        auth_proto="SHA", auth_key=auth_key)
    raw = fleetmod.handle_packet(dev, packet)
    if not check(raw is not None, f"{key}: SHA device dropped a correctly signed GET"):
        return
    answer = decode_response(raw)
    check(answer.pdu_tag != PDU_REPORT,
          f"{key}: a correctly signed GET was answered with a Report")
    check(answer.varbinds and answer.varbinds[0]["type"] == "STRING",
          f"{key}: signed GET did not return sysDescr")

    # The reply's own digest, verified exactly the way the trap decoder
    # verifies an inbound v3 trap. NOTE: nodepoll does NOT do this — see
    # nodepoll.py:1125-1160, which never checks a response's digest — so
    # this is the strictest verifier the app actually contains.
    start, end = find_auth_span(raw)
    check(end - start == AUTH_PROTOCOLS["SHA"][1],
          f"{key}: reply auth field is {end - start} bytes, expected 12")
    check(raw[start:end] != b"\x00" * 12, f"{key}: reply was not signed")
    decoder = Decoder()
    decoder.configure({"v3_users": f"poller / SHA / {password}"})
    trap = Trap(community="poller", engine_id=dev.engine_id.hex())
    check(decoder._verify_v3(raw, trap, start, end) == "ok",
          f"{key}: the reply's HMAC-SHA1-96 did not verify")

    tampered = bytearray(raw)
    tampered[-1] ^= 0xFF
    check(decoder._verify_v3(bytes(tampered), trap, start, end) == "failed",
          f"{key}: a tampered reply still verified")

    # A wrongly signed request must be refused with a Report, not answered.
    bad_key = localized_key("SHA", "the wrong password", report.engine_id)
    bad = build_v3_request(
        13, 778, PDU_GET, [nodeoids.SYSTEM_SCALARS["sys_descr"]],
        engine_id=report.engine_id, engine_boots=report.engine_boots,
        engine_time=report.engine_time, user="poller",
        auth_proto="SHA", auth_key=bad_key)
    refused = ask(dev, bad)
    check(refused is not None and refused.pdu_tag == PDU_REPORT,
          f"{key}: a badly signed request was not refused with a Report")


# ------------------------------------------------------ 5. knobs and faults

def test_knobs() -> None:
    toobig = make_device("cisco_access", index=903, toobig=True)
    packet = build_request(V2C, "public", PDU_GETBULK, 1, [IF_INDEX],
                           max_repetitions=40)
    response = ask(toobig, packet)
    check(response is not None and response.error_status == 1,
          "toobig: GETBULK(40) did not answer error_status 1")
    packet = build_request(V2C, "public", PDU_GETBULK, 1, [IF_INDEX],
                           max_repetitions=8)
    response = ask(toobig, packet)
    check(response is not None and response.error_status == 0 and response.varbinds,
          "toobig: GETBULK(8) should have been answered normally")
    values, reason, _ = bulk_walk(toobig, IF_INDEX, max_repetitions=8)
    check(len(values) == port_count(toobig),
          "toobig: the halved walk did not return every row")

    auth = make_device("cisco_access", index=904, auth_fail=True)
    response = ask(auth, build_request(V2C, "public", PDU_GET, 1,
                                       [nodeoids.SYSTEM_SCALARS["sys_descr"]]))
    check(response is not None and response.error_status == 16,
          "auth_fail: GET did not answer error_status 16 (authorizationError)")

    dead = make_device("cisco_access", index=905, alive=False)
    check(fleetmod.handle_packet(dead, build_request(
        V2C, "public", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])) is None,
        "alive=False: a dead device answered")

    wrong = make_device("cisco_access", index=906)
    wrong.community = "secret42"
    check(fleetmod.handle_packet(wrong, build_request(
        V2C, "public", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])) is None,
        "wrong community: the device answered anyway")
    check(fleetmod.handle_packet(wrong, build_request(
        V2C, "secret42", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])) is not None,
        "right community: the device stayed silent")

    v1 = make_device("cisco_access", index=907, v1_only=True, profile="v1-public")
    response = ask(v1, build_request(V1, "public", PDU_GET, 1,
                                     [nodeoids.SYSTEM_SCALARS["sys_descr"]]))
    check(response is not None and response.varbinds and
          response.varbinds[0]["type"] == "STRING",
          "v1_only: a v1 GET was not answered")
    check(fleetmod.handle_packet(v1, build_request(
        V2C, "public", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])) is None,
        "v1_only: a v2c request was answered")
    response = ask(v1, build_request(V1, "public", PDU_GETBULK, 1, [IF_INDEX],
                                     max_repetitions=40))
    check(response is not None and response.error_status != 0,
          "v1_only: GETBULK did not produce a v1 error")
    values, reason, _ = bulk_walk(v1, IF_INDEX, version=V1)
    check(len(values) == port_count(v1),
          f"v1_only: the GETNEXT walk found {len(values)} rows, "
          f"expected {port_count(v1)}")

    wrap = make_device("cisco_access", index=908, wrap32=True)
    table = wrap.table(None)
    check(not table.has("1.3.6.1.2.1.31.1.1.1.6.1"),
          "wrap32: ifHCInOctets is still present")
    check(table.has("1.3.6.1.2.1.2.2.1.10.1"),
          "wrap32: the 32-bit ifInOctets column is missing")
    now = time.time()
    counter = table.entries["1.3.6.1.2.1.2.2.1.10.1"][1]
    samples = [counter(wrap, now + t) for t in (0, 15, 30, 45, 60)]
    check(len(set(samples)) > 1, "wrap32: the octet counter is not moving")
    check(all(0 <= s < 2 ** 32 for s in samples),
          "wrap32: the counter left the 32-bit range")
    # It must lap 2**32 within ~60 s — that is the whole point of the
    # device, and what makes nodepoll.counter_rate's wrap branch fire.
    check(any(b < a for a, b in zip(samples, samples[1:])),
          "wrap32: the 32-bit counter never wrapped inside 60 s")

    chassis = make_device("cisco_core", index=909, chassis_ports=500)
    check(port_count(chassis) == 500,
          f"chassis: {port_count(chassis)} ports, expected 500")

    flap = make_device("cisco_access", index=910, flapping=[7])
    states = {flap.oper_status(t, 7) for t in range(0, 400, 5)}
    check(states == {1, 2}, f"flapping: ifOperStatus never toggled ({states})")

    rebooter = make_device("cisco_access", index=911, reboot_every_s=240)
    before = rebooter.uptime_ticks(rebooter.start_ts + 239)
    after = rebooter.uptime_ticks(rebooter.start_ts + 241)
    check(after < before, "reboot_every_s: sysUpTime did not reset")

    dark = make_device("cisco_access", index=912, dark_after_s=120,
                       dark_for_s=180, dark_every_s=300)
    check(dark.is_alive(dark.start_ts + 60), "dark: down before its time")
    check(not dark.is_alive(dark.start_ts + 200), "dark: still answering while dark")
    check(dark.is_alive(dark.start_ts + 320), "dark: never came back")


def test_cisco_vlan_context() -> None:
    """The classic-IOS per-VLAN forwarding table: nothing in the global
    context, rows inside `public@10` — the reason
    nodepoll._cisco_vlan_device_fdb exists."""
    dev = make_device("cisco_core", index=913)
    fdb = "1.3.6.1.2.1.17.4.3.1.2"
    values, _reason, _ = bulk_walk(dev, fdb)
    check(not values, "cisco vlan: the global context served a bridge table")
    values, _reason, _ = bulk_walk(dev, fdb, community="public@10")
    check(bool(values), "cisco vlan: public@10 served no bridge table")
    vtp, _reason, _ = bulk_walk(dev, "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1")
    check(len(vtp) >= 5, "cisco vlan: vtpVlanState is missing")
    check(fleetmod.handle_packet(dev, build_request(
        V2C, "public@999", PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])) is None,
        "cisco vlan: an unknown VLAN context was answered")


def test_dom_and_fdb() -> None:
    """The tables behind the interface dialog's two on-demand reads."""
    dev = make_device("cisco_access", index=914)
    alias, _r, _ = bulk_walk(dev, "1.3.6.1.2.1.47.1.3.2.1.2")
    check(bool(alias), "dom: entAliasMappingIdentifier is empty")
    check(any(str(v).startswith("1.3.6.1.2.1.2.2.1.1.") for v in alias.values()),
          "dom: no alias mapping points at an ifIndex")
    sensors, _r, _ = bulk_walk(dev, "1.3.6.1.2.1.99.1.1.1.4")
    check(len(sensors) >= 10, f"dom: only {len(sensors)} sensor values")
    fdb, _r, _ = bulk_walk(dev, "1.3.6.1.2.1.17.7.1.2.2.1.2")
    check(len(fdb) == 48 * 4, f"fdb: {len(fdb)} dot1q rows, expected 192")
    ports, _r, _ = bulk_walk(dev, "1.3.6.1.2.1.17.1.4.1.2")
    check(len(ports) == 48, f"fdb: {len(ports)} bridge ports, expected 48")

    wlc = make_device("fortigate_wlc", index=915)
    aps, _r, _ = bulk_walk(wlc, "1.3.6.1.4.1.12356.101.14.4.4.1.7")
    check(len(aps) == len(personas.AP_NAMES),
          f"wlc: {len(aps)} AP session rows, expected {len(personas.AP_NAMES)}")
    check(sorted(aps.values()).count(1) == 2, "wlc: expected exactly 2 offline APs")


def test_vendor_identity() -> None:
    """Every persona must be nameable by the app's own identification —
    that is the whole point of the sysObjectID/sysDescr choices."""
    for key in personas.PERSONAS:
        dev = make_device(key, index=916)
        table = dev.table(None)
        descr = table.entries["1.3.6.1.2.1.1.1.0"][1]
        oid = table.entries["1.3.6.1.2.1.1.2.0"][1]
        vendor, how = nodeoids.identify_vendor(oid, descr)
        check(bool(vendor), f"{key}: sysObjectID {oid} identifies no vendor")
        if key in ("rockwell_plc",):
            check(how == "sysDescr",
                  f"{key}: expected identification from sysDescr, got {how}")
        elif key not in ("linux_host",):
            check(how == "sysObjectID",
                  f"{key}: expected identification from sysObjectID, got {how}")


# ------------------------------------------------------ 6. estate personas

def _decode_entity_sensor(dev, entity: int) -> float:
    """nodepoll.read_dom()'s own RFC 3433 arithmetic (nodepoll.py:2897-2899):
    value x 10^(3*(scale-9)) / 10^precision. Applied directly to a
    persona's table rather than through read_dom() itself, which needs a
    live device-DB row this offline harness has no use for — the formula is
    the part actually worth proving, and it is copied here verbatim."""
    entries = dev.table(None).entries
    scale = entries[f"{personas.ENT_SENSOR}.2.{entity}"][1]
    precision = entries[f"{personas.ENT_SENSOR}.3.{entity}"][1]
    raw_field = entries[f"{personas.ENT_SENSOR}.4.{entity}"][1]
    raw = raw_field(dev, time.time()) if callable(raw_field) else raw_field
    return raw * (10 ** (3 * (scale - 9))) / (10 ** precision)


def test_room_alert_dom() -> None:
    """nodepoll._poll_environment (nodepoll.py:3081) is a whole-device
    ENTITY-SENSOR-MIB walk that deliberately does NOT require
    entAliasMappingIdentifier — added specifically because an environmental
    monitor's sensors belong to no port. This persona proves both halves:
    no port mapping exists at all (so nodepoll.read_dom(), which still
    gates on that mapping, correctly finds nothing here), while the raw
    ENTITY-SENSOR values decode to a sensible °C/%RH on a plain device, and
    the temp_hot SPECIALS variant (index 15) clears alertsdb's temp_high
    threshold (35°C)."""
    normal = make_device("room_alert", index=930)
    alias, _reason, _ = bulk_walk(normal, "1.3.6.1.2.1.47.1.3.2.1.2")
    check(not alias, "room_alert: entAliasMappingIdentifier should be empty "
                      "— its sensors belong to no port")
    temp = _decode_entity_sensor(normal, 10011)   # if_index 1, slot 1
    humidity = _decode_entity_sensor(normal, 10012)               # slot 2
    check(15.0 <= temp <= 30.0,
          f"room_alert: decoded temperature {temp}°C looks wrong")
    check(30.0 <= humidity <= 60.0,
          f"room_alert: decoded humidity {humidity}%RH looks wrong")

    hot = make_device("room_alert", index=931, temp_hot=True)
    hot_temp = _decode_entity_sensor(hot, 10011)
    check(hot_temp > 35.0,
          f"room_alert: temp_hot did not clear alertsdb's temp_high "
          f"threshold (35°C), got {hot_temp}°C")


def test_apc_ups() -> None:
    """RFC 1628 scalars matching nodeoids.UPS_HEALTH answer, typed as
    INTEGER; on_battery (SPECIALS index 14) flips upsOutputSource from
    normal(3) to battery(5) and, given a few minutes, drains
    upsBatteryStatus through batteryLow(3) to batteryDepleted(4) — the
    three-alert arc (ups_on_battery, ups_battery_low, ups_battery_replace)
    alertsdb.py:493-501 defines. upsEstimatedMinutesRemaining (.1.2.3.0) is
    deliberately absent, so nodepoll._apc_runtime_fallback's PowerNet-arc
    read is what actually answers ups_runtime_min for this persona."""
    dev = make_device("apc_ups", index=932)
    packet = build_request(V2C, "public", PDU_GET, 1,
                           [f"{personas.UPS_MIB}.1.2.3.0",    # minutes remaining
                            f"{personas.UPS_MIB}.1.2.4.0",    # charge remaining
                            f"{personas.UPS_MIB}.1.4.1.0",    # output source
                            "1.3.6.1.4.1.318.1.1.1.2.2.3.0"]) # PowerNet runtime
    response = ask(dev, packet)
    if not check(response is not None and len(response.varbinds) == 4,
                 "apc_ups: RFC 1628 scalars did not answer"):
        return
    minutes, charge, source, powernet_runtime = response.varbinds
    check(minutes["type"] in ("noSuchObject", "noSuchInstance"),
          f"apc_ups: upsEstimatedMinutesRemaining should be absent, "
          f"got {minutes}")
    check(charge["type"] == "INTEGER" and 0 <= int(charge["value"]) <= 100,
          f"apc_ups: upsEstimatedChargeRemaining decoded as {charge}")
    check(source["type"] == "INTEGER" and int(source["value"]) == 3,
          f"apc_ups: upsOutputSource should read normal(3) on mains, got {source}")
    check(powernet_runtime["type"] == "TimeTicks",
          f"apc_ups: PowerNet upsAdvBatteryRunTimeRemaining is "
          f"{powernet_runtime['type']}, expected TimeTicks")

    battery = make_device("apc_ups", index=933, on_battery=True)
    response = ask(battery, build_request(
        V2C, "public", PDU_GET, 1, [f"{personas.UPS_MIB}.1.4.1.0"]))
    check(response is not None and int(response.varbinds[0]["value"]) == 5,
          "apc_ups: on_battery did not flip upsOutputSource to battery(5)")
    # Fast-forward the same knob far enough on battery to watch
    # upsBatteryStatus drain through batteryLow to batteryDepleted.
    status_field = battery.table(None).entries[f"{personas.UPS_MIB}.1.2.1.0"][1]
    now = battery.start_ts
    early = status_field(battery, now + 10)
    low = status_field(battery, now + 250)
    depleted = status_field(battery, now + 300)
    check(early == 2, f"apc_ups: battery status should start normal(2), got {early}")
    check(low == 3, f"apc_ups: battery status should read batteryLow(3) "
                    f"partway through the drain, got {low}")
    check(depleted == 4, f"apc_ups: battery status should reach "
                         f"batteryDepleted(4) once fully drained, got {depleted}")


def test_eaton_ups() -> None:
    """A second UPS vendor answering only the standard scalars (including
    upsEstimatedMinutesRemaining, unlike apc_ups) — proves
    nodepoll._poll_ups_health's per-device design is not APC-specific, and
    that Eaton's arc (534) identifies the device on its own."""
    dev = make_device("eaton_ups", index=938)
    table = dev.table(None)
    descr = table.entries["1.3.6.1.2.1.1.1.0"][1]
    oid = table.entries["1.3.6.1.2.1.1.2.0"][1]
    vendor, how = nodeoids.identify_vendor(oid, descr)
    check(vendor == "eaton", f"eaton_ups: expected vendor 'eaton', got {vendor!r}")
    check(how == "sysObjectID", f"eaton_ups: expected sysObjectID identification, got {how}")
    packet = build_request(V2C, "public", PDU_GET, 1,
                           [f"{personas.UPS_MIB}.1.2.3.0",    # minutes remaining
                            f"{personas.UPS_MIB}.1.2.4.0"])   # charge remaining
    response = ask(dev, packet)
    if not check(response is not None and len(response.varbinds) == 2,
                 "eaton_ups: RFC 1628 scalars did not answer"):
        return
    minutes, charge = response.varbinds
    check(minutes["type"] == "INTEGER" and int(minutes["value"]) > 0,
          f"eaton_ups: upsEstimatedMinutesRemaining decoded as {minutes}")
    check(charge["type"] == "INTEGER" and int(charge["value"]) == 100,
          f"eaton_ups: upsEstimatedChargeRemaining decoded as {charge}")
    check(not table.has("1.3.6.1.4.1.318.1.1.1.2.2.1.0"),
          "eaton_ups: should answer nothing under APC's PowerNet arc")


def test_printer_mfp() -> None:
    """A supply level and its max capacity both read, and the level never
    exceeds the capacity it is a fraction of."""
    dev = make_device("printer_mfp", index=934)
    packet = build_request(V2C, "public", PDU_GET, 1,
                           [f"{personas.PRT_MARKER_SUPPLIES}.8.1.1",  # max capacity
                            f"{personas.PRT_MARKER_SUPPLIES}.9.1.1"])  # level
    response = ask(dev, packet)
    if not check(response is not None and len(response.varbinds) == 2,
                 "printer_mfp: prtMarkerSuppliesMaxCapacity/Level did not answer"):
        return
    cap, level = response.varbinds
    check(cap["type"] == "INTEGER" and int(cap["value"]) > 0,
          f"printer_mfp: max capacity read as {cap}")
    check(level["type"] == "INTEGER" and 0 <= int(level["value"]) <= int(cap["value"]),
          f"printer_mfp: supply level read as {level}")


_NO_MEM_PCT_OIDS = (
    # Every OID any nodepoll.py code path reads on the way to a mem_pct
    # metric: UCD-SNMP-MIB (the generic fallback everything else beats),
    # the Cisco memory-pool pair (arc 9 only, via _cisco_memory_pct), and
    # Fortinet's VENDOR_HEALTH mem scalar (nodeoids.py:97-102) — the only
    # vendor arc besides Cisco's that names one at all; Juniper's entry in
    # that same table is cpu_pct/temp_c only, no memory. None of these
    # should be present on a Windows persona — that absence is
    # _host_resources_no_memory's whole point.
    personas.UCD_MEM_TOTAL, personas.UCD_MEM_AVAIL,
    "1.3.6.1.4.1.9.9.48.1.1.1.5.1", "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    "1.3.6.1.4.1.12356.101.4.1.4.0",
)


def _host_resources_no_memory(key: str, dev) -> None:
    """CPU and disk populate for a Windows persona (GENERIC_HEALTH's
    hrProcessorLoad column_avg, _host_resources_disk_pct's
    hrStorageFixedDisk filter — both confirmed by reading nodepoll.py, not
    guessed), but no path in nodepoll.py produces mem_pct for one — also
    confirmed by reading nodepoll.py rather than inferred. Shared by
    test_windows_server and test_windows_endpoint."""
    table = dev.table(None)
    check(table.has("1.3.6.1.2.1.25.3.3.1.2.1"),
          f"{key}: hrProcessorLoad is missing — cpu_pct would not populate")
    for oid in _NO_MEM_PCT_OIDS:
        check(not table.has(oid),
              f"{key}: answers {oid}, which would give it a memory metric "
              f"nodepoll.py has no path to produce for a Windows host")


def test_windows_server() -> None:
    """hrStorageTable types matter: exactly two rows read as
    hrStorageFixedDisk and exactly one as hrStorageRam (nothing else),
    hrSystemUptime/hrSWRunTable both answer, and the CPU/disk-but-no-memory
    asymmetry (SPECIALS index 17) holds."""
    dev = make_device("windows_server", index=935)
    table = dev.table(None)
    types, sizes, used = {}, {}, {}
    for oid, (_tag, value) in table.entries.items():
        if oid.startswith("1.3.6.1.2.1.25.2.3.1.2."):
            types[oid.rsplit(".", 1)[-1]] = value
        elif oid.startswith("1.3.6.1.2.1.25.2.3.1.5."):
            sizes[oid.rsplit(".", 1)[-1]] = value
        elif oid.startswith("1.3.6.1.2.1.25.2.3.1.6."):
            used[oid.rsplit(".", 1)[-1]] = value(dev, time.time())
    fixed = [i for i, t in types.items() if t == personas.HR_STORAGE_FIXED_DISK]
    ram = [i for i, t in types.items() if t == personas.HR_STORAGE_RAM]
    check(len(fixed) == 2,
          f"windows_server: expected exactly two hrStorageFixedDisk rows, "
          f"found {len(fixed)}")
    check(len(ram) == 1,
          f"windows_server: expected exactly one hrStorageRam row, "
          f"found {len(ram)}")
    for i in fixed:
        pct = 100.0 * used[i] / sizes[i]
        check(0 < pct < 100, f"windows_server: disk-used percentage is {pct}")
    check(table.has(f"{personas.HR_SW_RUN}.2.1"),
          "windows_server: hrSWRunTable is empty")
    check(table.has(personas.HR_SYSTEM_UPTIME),
          "windows_server: hrSystemUptime is missing")
    _host_resources_no_memory("windows_server", dev)


def test_windows_endpoint() -> None:
    """The cheap, single-interface shape: one wireless-looking adapter,
    still two hrStorageFixedDisk rows and one hrStorageRam row, and the
    same CPU/disk-but-no-memory asymmetry as windows_server (SPECIALS
    index 18)."""
    dev = make_device("windows_endpoint", index=936)
    table = dev.table(None)
    check(port_count(dev) == 1,
          f"windows_endpoint: {port_count(dev)} interfaces, expected 1")
    descr = table.entries["1.3.6.1.2.1.2.2.1.2.1"][1]
    kind = table.entries["1.3.6.1.2.1.2.2.1.3.1"][1]
    check(kind == 71, f"windows_endpoint: ifType is {kind}, expected 71 (ieee80211)")
    check("wi-fi" in descr.lower() or "wireless" in descr.lower(),
          f"windows_endpoint: ifDescr {descr!r} does not look wireless")
    fixed = [oid for oid, (_tag, v) in table.entries.items()
             if oid.startswith("1.3.6.1.2.1.25.2.3.1.2.")
             and v == personas.HR_STORAGE_FIXED_DISK]
    check(len(fixed) == 2,
          f"windows_endpoint: expected exactly two fixed-disk storage rows, "
          f"found {len(fixed)}")
    _host_resources_no_memory("windows_endpoint", dev)


def test_tablet_ouis() -> None:
    """A tablet/phone has no SNMP agent of its own — the only honest way
    this fleet represents one is as a leaf MAC in an access switch's
    forwarding table, under a real phone/tablet vendor's OUI, so a report
    can point at it in the FDB the way a real switch would show it."""
    dev = make_device("cisco_access", index=937)
    fdb, _reason, _ = bulk_walk(dev, "1.3.6.1.2.1.17.7.1.2.2.1.2")
    ouis = {tuple(int(a) for a in suffix.split(".")[1:4]) for suffix in fdb}
    check(personas.APPLE_OUI in ouis,
          "cisco_access: no Apple-OUI MAC in the FDB")
    check(personas.SAMSUNG_OUI in ouis,
          "cisco_access: no Samsung-OUI MAC in the FDB")


# ----------------------------------------------------------- the wire path

def wire_test() -> None:
    """One real socket, one real poll, with the app's own _Session."""
    ip = "127.0.0.250"
    dev = make_device("cisco_access", index=248)
    dev.ip = ip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, 161))
    except OSError as exc:
        check(False, f"wire: could not bind {ip}:161 ({exc}) — root is needed")
        sock.close()
        return
    stop = threading.Event()

    def serve():
        sock.settimeout(0.25)
        deadline = time.time() + 2.0
        while not stop.is_set() and time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            reply = fleetmod.handle_packet(dev, data)
            if reply:
                try:
                    sock.sendto(reply, addr)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        session = _Session(ip, 161, 2.0, 1)
        try:
            packet = build_request(V2C, "public", PDU_GET, 31337,
                                   [nodeoids.SYSTEM_SCALARS["sys_descr"],
                                    nodeoids.SYSTEM_SCALARS["sys_uptime"]])
            response = session.request(packet)
            check(response.request_id == 31337, "wire: request id did not round trip")
            check(len(response.varbinds) == 2,
                  f"wire: {len(response.varbinds)} varbinds, expected 2")
            check("Cisco IOS" in str(response.varbinds[0]["value"]),
                  f"wire: sysDescr came back as {response.varbinds[0]['value']!r}")
            check(response.varbinds[1]["type"] == "TimeTicks",
                  "wire: sysUpTime was not TimeTicks")
            print(f"  wire: {ip}:161 answered "
                  f"{str(response.varbinds[0]['value'])[:48]}...")
        finally:
            session.close()
    finally:
        stop.set()
        thread.join(timeout=3)
        sock.close()


def test_live_lldp_poll() -> None:
    """The end-to-end proof static table inspection cannot give: a REAL
    netpath.nodepoll.NodePoller, against a REAL netpath.nodesdb.
    NodesDatabase, running the actual scheduled-poll methods
    (_poll_device then _run_lldp_table) over real sockets against
    core-sw-01 and acc-sw-001 — not hand-inserted rows, which cannot make
    NodePoller.counters['lldp_walks'] believe it walked anything, and not
    a synthetic neighbours row, which cannot exercise nodesdb.
    upstream_suggestions()'s own confidence-tier scoring.

    Two different loopback addresses from wire_test()'s (127.0.0.250), so
    a bind failure there does not also take this out."""
    core_ip, acc_ip = "127.0.0.252", "127.0.0.253"
    tmp_db = os.path.join(tempfile.mkdtemp(prefix="selftest_nodesdb_"), "nodes.db")
    nodes_db = NodesDatabase(tmp_db)
    group_id = nodes_db.ensure_default_group()
    sockets: list[socket.socket] = []
    stop = threading.Event()
    threads: list[threading.Thread] = []

    def serve_one(ip: str, dev) -> socket.socket | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((ip, 161))
        except OSError as exc:
            check(False, f"live LLDP poll: could not bind {ip}:161 ({exc}) — root is needed")
            sock.close()
            return None
        sockets.append(sock)

        def serve():
            sock.settimeout(0.25)
            deadline = time.time() + 10.0
            while not stop.is_set() and time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                except (socket.timeout, OSError):
                    continue
                reply = fleetmod.handle_packet(dev, data)
                if reply:
                    try:
                        sock.sendto(reply, addr)
                    except OSError:
                        pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        threads.append(thread)
        return sock

    def register(name: str, persona_key: str, ip: str):
        device_id = nodes_db.add_device(ip, name=name, group_id=group_id)
        entry = {"index": device_id, "ip": ip, "name": name, "persona": persona_key,
                 "site": "Site-A", "snmp_version": 1, "community": "public",
                 "profile": "v2c-public", "knobs": {}}
        dev = personas.build_device(entry)
        return device_id, dev

    core_id, core_dev = register("core-sw-01", "cisco_core", core_ip)
    acc_id, acc_dev = register("acc-sw-001", "cisco_access", acc_ip)
    if serve_one(core_ip, core_dev) is None or serve_one(acc_ip, acc_dev) is None:
        stop.set()
        for t in threads:
            t.join(timeout=2)
        for s in sockets:
            s.close()
        return

    poller = NodePoller(nodes_db)
    try:
        before = poller.counters["lldp_walks"]
        # _poll_device first: the chassis-MAC join needs interfaces.
        # phys_addr, which only a real interface-table poll populates —
        # the LLDP walk alone never touches that table.
        for device_id in (core_id, acc_id):
            device = nodes_db.device(device_id)
            config = poller.working_config(device)
            poller._poll_device(device, config)
        poller._run_lldp_table(core_id)
        poller._run_lldp_table(acc_id)
        check(poller.counters["lldp_walks"] == before + 2,
              f"live LLDP poll: lldp_walks should have incremented by 2, "
              f"went from {before} to {poller.counters['lldp_walks']}")

        suggestions = {s["device_id"]: s for s in nodes_db.upstream_suggestions()}
        core_suggestion = suggestions.get(core_id)
        acc_suggestion = suggestions.get(acc_id)
        check(core_suggestion is not None and not core_suggestion["ambiguous"]
              and len(core_suggestion["candidates"]) == 1,
              f"live LLDP poll: core-sw-01 should have exactly one, "
              f"unambiguous upstream candidate: {core_suggestion}")
        check(acc_suggestion is not None and not acc_suggestion["ambiguous"]
              and len(acc_suggestion["candidates"]) == 1,
              f"live LLDP poll: acc-sw-001 should have exactly one, "
              f"unambiguous upstream candidate: {acc_suggestion}")
        if core_suggestion and acc_suggestion:
            core_candidate = core_suggestion["candidates"][0]
            acc_candidate = acc_suggestion["candidates"][0]
            check(core_candidate["matched_device_name"] == "acc-sw-001"
                  and acc_candidate["matched_device_name"] == "core-sw-01",
                  f"live LLDP poll: each device's candidate names the "
                  f"other: {core_candidate['matched_device_name']!r} / "
                  f"{acc_candidate['matched_device_name']!r}")
            # The one this whole check exists for: a real chassis-MAC
            # agreement, freshly walked, must score 'high' — not merely
            # resolvable by sysName at 'medium'.
            check(core_candidate["match_kind"] == "chassis_mac"
                  and core_candidate["confidence"] == "high",
                  f"live LLDP poll: core-sw-01's candidate should be "
                  f"chassis_mac/high, got {core_candidate['match_kind']}/"
                  f"{core_candidate['confidence']}")
            check(acc_candidate["match_kind"] == "chassis_mac"
                  and acc_candidate["confidence"] == "high",
                  f"live LLDP poll: acc-sw-001's candidate should be "
                  f"chassis_mac/high, got {acc_candidate['match_kind']}/"
                  f"{acc_candidate['confidence']}")
            print(f"  live LLDP poll: core-sw-01 <-> acc-sw-001, "
                  f"match_kind={core_candidate['match_kind']}, "
                  f"confidence={core_candidate['confidence']}")
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=3)
        for s in sockets:
            s.close()
        nodes_db.close()


# ------------------------------------------------------- L2 topology (4.49.0)
#
# LLDP/CDP neighbours, PoE and STP were three of 4.47.0's Tier 1 features
# that no persona had ever answered — the Topology tab, the device pane's
# Neighbours/Bridge&RF subtabs and the upstream-suggestion feature all had
# nothing to draw against this fleet. personas.py now answers all four on
# a deliberate, named subset of switches shaped like the fleet's own site
# plan (see personas.py's own "L2 topology" section comment) rather than
# wired so every device claims to neighbour every other one.

LLDP_PERSONAS = {"cisco_access", "cisco_core", "aruba_switch",
                 "siemens_scalance", "moxa", "juniper"}
CDP_PERSONAS = {"cisco_access", "cisco_core"}
POE_PERSONAS = {"cisco_access", "aruba_switch"}
STP_PERSONAS = {"cisco_access", "cisco_core", "aruba_switch",
                "siemens_scalance", "moxa", "juniper"}

LLDP_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
POE_PORT_ADMIN = "1.3.6.1.2.1.105.1.1.1.1.3"
POE_PSE_POWER = "1.3.6.1.2.1.105.1.3.1.1.2.1"
STP_PROTOCOL_SPEC = "1.3.6.1.2.1.17.2.1.0"
STP_SCALARS = ("1.3.6.1.2.1.17.2.1.0", "1.3.6.1.2.1.17.2.2.0",
              "1.3.6.1.2.1.17.2.5.0", "1.3.6.1.2.1.17.2.6.0",
              "1.3.6.1.2.1.17.2.7.0")


def test_l2_topology(key: str, dev) -> None:
    """Per persona: LLDP/CDP/PoE/STP each walk and terminate correctly for
    the personas that should answer them — and, just as important, a
    persona that should NOT answer one of these genuinely does not, the
    same "probed once, capability remembered" contract nodepoll.py's own
    _poll_poe/_poll_stp docstrings describe: a device that never answers
    the first probe must never be asked again, so it had better actually
    stay silent rather than answer a stray row that would relabel it
    capable by accident."""
    table = dev.table(None)

    values, reason, _ = bulk_walk(dev, LLDP_SYS_NAME)
    if key in LLDP_PERSONAS:
        check(bool(values), f"{key}: expected LLDP neighbours, found none")
        check(reason in ("endOfMibView", "left subtree"),
              f"{key}: LLDP walk stopped with {reason!r}")
    else:
        check(not values, f"{key}: should not answer LLDP at all, got {values}")

    values, _reason, _ = bulk_walk(dev, CDP_DEVICE_ID)
    if key in CDP_PERSONAS:
        check(bool(values), f"{key}: expected CDP neighbours, found none")
    else:
        check(not values, f"{key}: should not answer CDP at all, got {values}")

    values, reason, _ = bulk_walk(dev, POE_PORT_ADMIN)
    if key in POE_PERSONAS:
        check(bool(values), f"{key}: expected a PoE port table, found none")
        check(reason in ("endOfMibView", "left subtree"),
              f"{key}: PoE port walk stopped with {reason!r}")
        check(table.has(POE_PSE_POWER), f"{key}: PSE power-budget scalar missing")
    else:
        check(not values, f"{key}: should not answer any PoE port row, got {values}")
        check(not table.has(POE_PSE_POWER),
              f"{key}: should not answer the PSE power-budget scalar at all")

    if key in STP_PERSONAS:
        for oid in STP_SCALARS:
            check(table.has(oid), f"{key}: dot1dStp scalar {oid} is missing")
    else:
        check(not table.has(STP_PROTOCOL_SPEC),
              f"{key}: should not answer dot1dStpProtocolSpecification at all")


def test_topology_consistency() -> None:
    """The neighbour graph the fleet reports has to be internally
    consistent, not merely present: every neighbour a device claims (by
    LLDP sysName or CDP device id) resolves to a device that genuinely
    exists in this SAME fleet_plan(), and the ten deliberately-paired
    core<->access links (personas.py's own L2-topology comment) agree
    from both ends — by name, and by the chassis MAC nodesdb's own join
    checks (see personas.py._mac_for), not merely "some string matches"."""
    count = 250
    plan = personas.fleet_plan(count)
    names = {row["name"] for row in plan}
    topology_rows = [row for row in plan
                    if row["persona"] in (LLDP_PERSONAS | CDP_PERSONAS)]
    now = time.time()

    claimed: dict[str, set[str]] = {}
    chassis_claim: dict[tuple[str, str], bytes] = {}   # (device, neighbor) -> mac claimed
    real_mac: dict[str, dict[int, bytes]] = {}          # device -> {if_index: real mac}

    for row in topology_rows:
        dev = personas.build_device(row)
        table = dev.table(None)
        name = row["name"]
        for oid, (_tag, value) in table.entries.items():
            if oid.startswith(f"{LLDP_SYS_NAME}."):
                claimed.setdefault(name, set()).add(str(value))
            elif oid.startswith(f"{CDP_DEVICE_ID}."):
                claimed.setdefault(name, set()).add(str(value))
            elif oid.startswith("1.0.8802.1.1.2.1.4.1.1.5."):   # chassis id
                chassis_claim[(name, oid)] = value
        real_mac[name] = {}
        for oid, (_tag, value) in table.entries.items():
            if oid.startswith("1.3.6.1.2.1.2.2.1.6."):          # ifPhysAddress
                if_index = int(oid.rsplit(".", 1)[-1])
                real_mac[name][if_index] = value(dev, now) if callable(value) else value

    unresolved = [(name, neighbor) for name, neighbors in claimed.items()
                 for neighbor in neighbors if neighbor not in names]
    check(not unresolved,
          f"every claimed neighbour resolves to a real device in a "
          f"{count}-device plan: unresolved={unresolved[:10]}")

    core = claimed.get("core-sw-01", set())
    expected_access = {f"acc-sw-{n:03d}" for n in range(1, 11)}
    check(expected_access <= core,
          "core-sw-01 claims all ten of its deliberately-paired access "
          f"switches as LLDP/CDP neighbours: has {core}")
    for acc_name in expected_access:
        check("core-sw-01" in claimed.get(acc_name, set()),
              f"{acc_name} reciprocally claims core-sw-01 as its neighbour: "
              f"has {claimed.get(acc_name)}")

    # Chassis-MAC join, both directions, for the first pair — the same
    # cross-reference personas._mac_for exists to make correct (see
    # nodesdb._NEIGHBOR_MATCH_SQL's chassis_id_subtype=4 join). Looked up
    # by the exact suffix personas.lldp_neighbor's own indexing produces:
    # timeMark 0, local port (1 on the core, 49 on the access switch — its
    # uplink), remIndex 1.
    core_claim_re_acc1 = chassis_claim.get(
        ("core-sw-01", "1.0.8802.1.1.2.1.4.1.1.5.0.1.1"))
    check(core_claim_re_acc1 is not None
          and core_claim_re_acc1 == real_mac.get("acc-sw-001", {}).get(49),
          "core-sw-01's chassis-MAC claim about acc-sw-001 matches "
          f"acc-sw-001's own real ifPhysAddress on its uplink port: "
          f"{core_claim_re_acc1!r} vs {real_mac.get('acc-sw-001', {}).get(49)!r}")
    acc1_claim_re_core = chassis_claim.get(
        ("acc-sw-001", "1.0.8802.1.1.2.1.4.1.1.5.0.49.1"))
    check(acc1_claim_re_core is not None
          and acc1_claim_re_core == real_mac.get("core-sw-01", {}).get(1),
          "acc-sw-001's chassis-MAC claim about core-sw-01 matches "
          f"core-sw-01's own real ifPhysAddress on port 1: "
          f"{acc1_claim_re_core!r} vs {real_mac.get('core-sw-01', {}).get(1)!r}")


# ------------------------------------------------------------------- main

def main() -> int:
    started = time.time()
    print(f"demo/selftest.py — {len(personas.PERSONAS)} personas")
    for key in personas.PERSONAS:
        dev = make_device(key)
        test_scalars(key, dev)
        test_if_walk(key, dev)
        test_l2_topology(key, dev)
        print(f"  {key:<20} {len(dev.table(None)):>5} OIDs, "
              f"{port_count(dev):>3} ports  ok")

    print("v3 discovery and noAuthNoPriv ...")
    test_v3_discovery("cisco_access")
    print("v3 authNoPriv HMAC-SHA1-96 ...")
    test_v3_sha("cisco_access")
    print("behaviour knobs ...")
    test_knobs()
    print("cisco per-VLAN contexts ...")
    test_cisco_vlan_context()
    print("DOM sensors, forwarding tables and the fgWc AP table ...")
    test_dom_and_fdb()
    print("vendor identification ...")
    test_vendor_identity()
    print("estate device personas (UPS, Room Alert, printer, Windows) ...")
    test_room_alert_dom()
    test_apc_ups()
    test_eaton_ups()
    test_printer_mfp()
    test_windows_server()
    test_windows_endpoint()
    test_tablet_ouis()
    print("L2 topology: neighbour graph consistency across a 250-device plan ...")
    test_topology_consistency()
    print("wire path on 127.0.0.250:161 ...")
    wire_test()
    print("live LLDP poll on 127.0.0.252/127.0.0.253 (real NodePoller + NodesDatabase) ...")
    test_live_lldp_poll()

    elapsed = time.time() - started
    if FAILURES:
        print(f"\n{len(FAILURES)} of {CHECKS[0]} checks FAILED in {elapsed:.1f}s")
        for message in FAILURES[:25]:
            print(f"  - {message}")
        return 1
    print(f"\nall {CHECKS[0]} checks passed in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

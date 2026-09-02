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
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import fleet as fleetmod                          # noqa: E402
from demo import personas                                   # noqa: E402
from netpath import nodeoids                                # noqa: E402
from netpath.nodepoll import _Session                       # noqa: E402
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


# ------------------------------------------------------------------- main

def main() -> int:
    started = time.time()
    print(f"demo/selftest.py — {len(personas.PERSONAS)} personas")
    for key in personas.PERSONAS:
        dev = make_device(key)
        test_scalars(key, dev)
        test_if_walk(key, dev)
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
    print("wire path on 127.0.0.250:161 ...")
    wire_test()

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

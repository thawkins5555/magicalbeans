"""Per-port VLAN membership: the bitmap decoders in isolation, the live walk
against stub_agent_vlan (Q-BRIDGE standards path, CISCO-VTP-MIB, the
"Cisco supersedes standards" rule, the mac_entries fallback), present-flag
ageing (mirroring neighbors/mac_entries), and vlan_interval_s scheduling/
inheritance (0 = off, mirroring lldp_interval_s)."""
import time

from _paths import spawn_stub, tmpdir, free_udp_port

TMP = tmpdir("port_vlans_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller, _decode_port_list, _decode_vlan_bitmap
from netpath.trapdecode import _octets_text

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, port: int, *, vendor: str = "",
                   name: str = "sw") -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    did = db.add_device("127.0.0.1", name=name, group_id=gid)
    db.seed_identity(did, sys_descr="", sys_name=name,
                     sys_object_id="1.3.6.1.4.1.9.1.1208", vendor=vendor)
    return did


# ---------------------------------------------- 1. _decode_port_list, in isolation
check("empty string decodes to no ports", _decode_port_list("") == [])
check("empty bytes decodes to no ports", _decode_port_list(b"") == [])
check("a single full byte (0xFF) decodes to ports 1-8",
      _decode_port_list(bytes([0xFF])) == [1, 2, 3, 4, 5, 6, 7, 8],
      _decode_port_list(bytes([0xFF])))
check("a byte-boundary bitmap: last bit of byte 0 + first bit of byte 1",
      _decode_port_list(bytes([0x01, 0x80])) == [8, 9],
      _decode_port_list(bytes([0x01, 0x80])))
check("space-separated hex text decodes the same as the raw bytes",
      _decode_port_list("01 80") == [8, 9], _decode_port_list("01 80"))
check("colon-separated six-byte hex text (the MAC-style special case) "
     "decodes the same way",
      _decode_port_list("00:00:00:00:00:80") == [41],
      _decode_port_list("00:00:00:00:00:80"))

# ------------------- 1b. _decode_port_list through the real OCTET_STRING
# pipeline (Finding 5, 4.54.0 review): trapdecode._octets_text is not
# losslessly reversible, so these feed it the exact bytes a live walk would
# and check what comes back out the other end, not bytes handed in directly.
check("a literal space byte (0x20) decodes to port 3, not an empty list "
     "(the old code's own .strip() used to throw this away)",
      _decode_port_list(_octets_text(bytes([0x20]))) == [3],
      _decode_port_list(_octets_text(bytes([0x20]))))
check("a literal 'A' byte (0x41) decodes as itself (ports 2, 8), not as "
     "the single hex digit 0x0A (ports 5, 7)",
      _decode_port_list(_octets_text(bytes([0x41]))) == [2, 8],
      _decode_port_list(_octets_text(bytes([0x41]))))
check("a single non-printable byte (0xFF) still round-trips through the "
     "hex path -- the common single-octet case this fix must not regress",
      _decode_port_list(_octets_text(bytes([0xFF]))) == [1, 2, 3, 4, 5, 6, 7, 8],
      _decode_port_list(_octets_text(bytes([0xFF]))))
check("a bare LF byte (0x0A) decodes the same way a literal space would, "
     "not silently to an empty list -- _octets_text itself collapses 0x0A/"
     "0x0D/0x20 to the identical character, an ambiguity this file cannot "
     "resolve without the raw bytes (see _octets_from_value's docstring), "
     "but it must no longer be a silent empty result",
      _decode_port_list(_octets_text(bytes([0x0A]))) == [3],
      _decode_port_list(_octets_text(bytes([0x0A]))))
# Two literal printable bytes ('1', '2') and one non-printable byte (0x12)
# both render as the text "12" -- _octets_text destroys the distinction
# (there is no separator for a single hex group either way), so this exact
# case is a genuine, irreducible ambiguity, not a bug this file can fix
# without the raw bytes. Documented, not asserted as "fixed": the single-
# non-printable-byte reading (a real, common case -- any 8-port switch with
# one bit set outside the printable range) is kept, unchanged from before.
check("two literal-looking hex characters with no separating space keep "
     "the single-non-printable-byte reading (documented, not fixed: see "
     "_octets_from_value)",
      _decode_port_list(_octets_text(bytes([0x31, 0x32]))) == [4, 7],
      _decode_port_list(_octets_text(bytes([0x31, 0x32]))))

# --------------------------------------- 2. _decode_vlan_bitmap, all four bases
# CISCO-VTP-MIB's own bitmap is 0-based (octet 0's MSB is VLAN 0), NOT a
# PortList's 1-based convention (octet 0's MSB is bridge port 1) -- Finding 2,
# 4.54.0 review.
check("base 0: byte 0 bit 0 (MSB) -> VLAN 0, not VLAN 1",
      _decode_vlan_bitmap(bytes([0x80]), 0) == [0], _decode_vlan_bitmap(bytes([0x80]), 0))
check("base 0: byte 0 bit 1 -> VLAN 1, not VLAN 2",
      _decode_vlan_bitmap(bytes([0x40]), 0) == [1], _decode_vlan_bitmap(bytes([0x40]), 0))
check("base 1024: byte 0 bit 6 -> VLAN 1030 (above 1023, the 2k column's "
     "extended range)",
      _decode_vlan_bitmap(bytes([0x02]), 1024) == [1030],
      _decode_vlan_bitmap(bytes([0x02]), 1024))
check("base 2048: a byte-boundary bitmap (last bit of byte 0 + first bit "
     "of byte 1) -> VLANs 2055, 2056",
      _decode_vlan_bitmap(bytes([0x01, 0x80]), 2048) == [2055, 2056],
      _decode_vlan_bitmap(bytes([0x01, 0x80]), 2048))
check("base 3072: byte 0 bit 1 -> VLAN 3073, not VLAN 3074",
      _decode_vlan_bitmap(bytes([0x40]), 3072) == [3073],
      _decode_vlan_bitmap(bytes([0x40]), 3072))

# ------------------------------------------------------- 3. dot1q standards path
stub, port = spawn_stub("stub_agent_vlan.py", "dot1q")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("dot1q")
    did = device_against(db, port, vendor="", name="dot1q-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a dot1q walk returns a result", result is not None, result)
    if result:
        vlans = {v["vlan"]: v["name"] for v in result["vlans"]}
        check("...VLAN names carried through, including one with no membership",
              vlans == {10: "data", 20: "voice", 30: "guest"}, vlans)
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        check("...bridge port 1 (-> ifIndex 1) carries VLAN 10 untagged",
              memberships.get((1, 10)) is False, memberships)
        check("...bridge port 2 (-> ifIndex 2) carries VLAN 10 tagged, "
             "VLAN 20 untagged",
              memberships.get((2, 10)) is True and memberships.get((2, 20)) is False,
              memberships)
        ports = {p["if_index"]: p for p in result["ports"]}
        check("...dot1qPvid becomes each port's native_vlan",
              ports[1]["native_vlan"] == 10 and ports[2]["native_vlan"] == 20, ports)
    db.close()
finally:
    stub.kill()

# --------------------------------- 4. dot1dBasePortIfIndex absent -> fallback
stub, port = spawn_stub("stub_agent_vlan.py", "dot1q_no_baseport")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("dot1q_no_baseport")
    did = device_against(db, port, vendor="", name="nomap-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a dot1q walk with no dot1dBasePortIfIndex still returns a result",
          result is not None, result)
    if result:
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        check("...the bridge port number is used as the ifIndex directly",
              memberships.get((1, 10)) is False and memberships.get((2, 10)) is True
              and memberships.get((2, 20)) is False, memberships)
    db.close()
finally:
    stub.kill()

# ------------------------------ 5. cisco_vtp: gated off a non-Cisco device
stub, port = spawn_stub("stub_agent_vlan.py", "cisco_vtp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cisco_noncisco")
    did = device_against(db, port, vendor="", name="noncisco-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a non-Cisco device against a CISCO-VTP-only agent gets nothing "
         "(the Cisco tables are never consulted)",
          result is None, result)
    db.close()
finally:
    stub.kill()

# ---------------------- 5b. the same agent DOES answer once marked Cisco
stub, port = spawn_stub("stub_agent_vlan.py", "cisco_vtp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cisco_yescisco")
    did = device_against(db, port, vendor="cisco", name="cisco-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("...but the identical answers ARE used once the device is Cisco",
          result is not None, result)
    if result:
        vlans = {v["vlan"]: v["name"] for v in result["vlans"]}
        check("...vtpVlanName carried through, including the extended-range "
             "VLAN the 2k column has to answer for",
              vlans.get(10) == "data" and vlans.get(1030) == "voice-ext", vlans)
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        check("...native VLAN untagged, extended VLAN tagged",
              memberships.get((1, 10)) is False and memberships.get((1, 1030)) is True,
              memberships)
        ports = {p["if_index"]: p for p in result["ports"]}
        check("...mode 'trunk' and the native VLAN recorded",
              ports[1]["mode"] == "trunk" and ports[1]["native_vlan"] == 10, ports)
    db.close()
finally:
    stub.kill()

# ------------------------------------------ 6. Cisco supersedes standards
stub, port = spawn_stub("stub_agent_vlan.py", "both")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("both")
    did = device_against(db, port, vendor="cisco", name="both-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a device answering both tables returns a result", result is not None, result)
    if result:
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        check("...Cisco's answer wins for the port both describe: VLAN 10 "
             "tagged (not dot1q's untagged), VLAN 20 native/untagged",
              memberships.get((5, 10)) is True and memberships.get((5, 20)) is False,
              memberships)
        ports = {p["if_index"]: p for p in result["ports"]}
        check("...native_vlan is Cisco's (20), not dot1q's pvid (10)",
              ports[5]["native_vlan"] == 20 and ports[5]["mode"] == "trunk", ports)
    db.close()
finally:
    stub.kill()

# ------------------ 6b. Cisco trunk allow-list gated off access ports
# (Finding 3, 4.54.0 review): vlanTrunkPortDynamicStatus carries a row for
# EVERY switchport on real IOS, access included, and an access port still
# answers vlanTrunkPortVlansEnabled/vlanTrunkPortNativeVlan -- neither is
# meaningful for a port that is not trunking, so it must be ignored there,
# leaving the standards-path answer (dot1qPvid, the egress/untagged
# bitmaps) in place.
stub, port = spawn_stub("stub_agent_vlan.py", "cisco_mixed")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cisco_mixed")
    did = device_against(db, port, vendor="cisco", name="mixed-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a Cisco switch with both a trunk and an access port returns a result",
          result is not None, result)
    if result:
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        ports = {p["if_index"]: p for p in result["ports"]}
        check("...the trunking port (ifIndex 1) gets the Cisco allow-list: "
             "native VLAN 10 untagged, VLAN 20 tagged",
              memberships.get((1, 10)) is False and memberships.get((1, 20)) is True,
              memberships)
        check("...and is recorded as mode 'trunk' with native_vlan 10",
              ports[1]["mode"] == "trunk" and ports[1]["native_vlan"] == 10, ports)
        check("...the access port (ifIndex 2) keeps dot1qPvid's real access "
             "VLAN (30), not IOS's default native VLAN (1) from VTP",
              ports[2]["native_vlan"] == 30, ports)
        check("...and is recorded as mode 'access', not 'trunk'",
              ports[2]["mode"] == "access", ports)
        check("...its only membership is VLAN 30 untagged, from the "
             "standards path -- the Cisco allow-list's VLAN 1 must not "
             "appear at all",
              memberships.get((2, 30)) is False and (2, 1) not in memberships,
              memberships)
    db.close()
finally:
    stub.kill()

# --------------------------------------------------- 7. neither table -> None
stub, port = spawn_stub("stub_agent_vlan.py", "no_vlan")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("no_vlan")
    did = device_against(db, port, vendor="cisco", name="none-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a device answering no VLAN table returns None, not empty lists",
          result is None, result)

    seed_ts = time.time() - 100.0
    db.replace_vlans(did, [{"vlan": 99, "name": "pre-existing"}], now=seed_ts)
    before = {r["vlan"]: dict(r) for r in db.vlans_for(did)}
    poller._run_vlan_table(did)
    after = {r["vlan"]: dict(r) for r in db.vlans_for(did)}
    check("...and _run_vlan_table leaves existing VLAN rows completely untouched",
          before == after, (before, after))
    db.close()
finally:
    stub.kill()

# ------------------------------ 7b. dot1dBasePortIfIndex alone is not
# evidence of a VLAN-capable device (the "Also" fix, 4.54.0 review): a
# switch that speaks plain BRIDGE-MIB but nothing VLAN-related at all must
# still return None, not a genuine-but-empty dict that ages every stored
# row to present=0 and logs a 0-row walk on every scheduled poll.
stub, port = spawn_stub("stub_agent_vlan.py", "baseport_only")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("baseport_only")
    did = device_against(db, port, vendor="", name="baseport-only-sw")
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a device answering only dot1dBasePortIfIndex (no VLAN table at "
         "all) returns None, not an empty-but-real dict",
          result is None, result)
    db.close()
finally:
    stub.kill()

# --------------------------------------------------- 8. mac_entries fallback
stub, port = spawn_stub("stub_agent_vlan.py", "dot1q")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("fallback")
    did = device_against(db, port, vendor="", name="fallback-sw")
    db.replace_mac_entries(did, [
        {"if_index": 42, "mac": "aa:bb:cc:dd:ee:01", "vlan": "77"},
    ])
    poller = NodePoller(db)
    result = poller.read_device_vlans(did)
    check("a dot1q walk plus an unrelated port's mac_entries returns a result",
          result is not None, result)
    if result:
        memberships = {(m["if_index"], m["vlan"]): m["tagged"]
                       for m in result["memberships"]}
        check("...a port neither VLAN table described picks up its "
             "mac_entries VLAN, tagged",
              memberships.get((42, 77)) is True, memberships)
        ports = {p["if_index"]: p for p in result["ports"]}
        check("...with an empty mode: evidence, not configuration",
              ports.get(42, {}).get("mode") == "", ports)
    db.close()
finally:
    stub.kill()

# --------------------------------------------- 9. present-flag ageing / prune
db = new_db("ageing")
did = db.add_device("10.0.0.95", name="age-sw", group_id=db.ensure_default_group())
walk1_ts = time.time() - 3700.0
db.replace_port_vlans(did, [
    {"if_index": 1, "vlan": 10, "tagged": False},
    {"if_index": 1, "vlan": 20, "tagged": True},
], now=walk1_ts)
first_pass = {(r["if_index"], r["vlan"]): dict(r) for r in db.port_vlans_for(did)}
check("first walk stores both memberships, all present",
      len(first_pass) == 2 and all(r["present"] for r in first_pass.values()),
      first_pass)

walk2_ts = walk1_ts + 60.0
# The second walk only still sees VLAN 10 -- VLAN 20 dropped off the port.
db.replace_port_vlans(did, [
    {"if_index": 1, "vlan": 10, "tagged": False},
], now=walk2_ts)
rows = {(r["if_index"], r["vlan"]): dict(r) for r in db.port_vlans_for(did)}
check("the row count is unchanged -- nothing deleted, just marked",
      len(rows) == len(first_pass), (len(rows), len(first_pass)))
vanished_key = (1, 20)
still_key = (1, 10)
check("the vanished membership is present=0 with its old seen_ts kept",
      not rows[vanished_key]["present"]
      and rows[vanished_key]["seen_ts"] == first_pass[vanished_key]["seen_ts"], rows)
check("the still-seen membership got a fresh seen_ts and stays present",
      rows[still_key]["present"] and rows[still_key]["seen_ts"] == walk2_ts, rows)

removed = db.prune_port_vlans(60.0)   # both rows are well past a 1-minute window
check("prune_port_vlans drops rows past the retention window",
      removed == len(rows), (removed, len(rows)))
db.close()

# --------------------------------------------- 10. scheduling / inheritance
db = new_db("schedule")
gid = db.ensure_default_group()
db.update_group(gid, vlan_interval_s=0)     # shipped default overridden off
did_off = db.add_device("10.0.0.100", name="off-sw", group_id=gid)
did_on = db.add_device("10.0.0.101", name="on-sw", group_id=gid, vlan_interval_s=900)
poller = NodePoller(db)
device_off = db.device(did_off)
config_off = db.effective_config(device_off)
check("a group set to 0 disables VLAN scheduling (inherited)",
      config_off.get("vlan_interval_s") == 0, config_off)
poller._maybe_walk_vlans(device_off, config_off, time.time())
check("...and _maybe_walk_vlans never schedules a due time for it",
      did_off not in poller._next_vlan_walk, poller._next_vlan_walk)

device_on = db.device(did_on)
config_on = db.effective_config(device_on)
check("a device override beats the group's 0",
      config_on.get("vlan_interval_s") == 900, config_on)
now = time.time()
poller._maybe_walk_vlans(device_on, config_on, now)
check("...and _maybe_walk_vlans schedules a first walk within one interval",
      did_on in poller._next_vlan_walk
      and now <= poller._next_vlan_walk[did_on] <= now + 900,
      poller._next_vlan_walk)

db2 = new_db("default_interval")
did_default = db2.add_device("10.0.0.102", name="default-sw",
                             group_id=db2.ensure_default_group())
config_default = db2.effective_config(db2.device(did_default))
check("the shipped default is 3600s, mirroring lldp_interval_s",
      config_default.get("vlan_interval_s") == 3600, config_default)
db2.close()
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

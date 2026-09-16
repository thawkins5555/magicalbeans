"""configrx_stanza.interface_stanza: pulling one interface's own block out
of a whole-device stored configuration, and the short-name/long-name
matching (Gi/GigabitEthernet, Po/Port-channel, ...) it reads Nodes'
ifName/ifDescr candidates against."""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import configrx_stanza

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------- IOS, '!' separators
ios_text = (
    "hostname sw1\n"
    "!\n"
    "interface GigabitEthernet1/0/1\n"
    " description uplink\n"
    " switchport mode trunk\n"
    "!\n"
    "interface GigabitEthernet1/0/2\n"
    " description edge\n"
    "!\n"
    "end\n"
)
stanza = configrx_stanza.interface_stanza(ios_text, ["Gi1/0/1", "GigabitEthernet1/0/1"])
check("IOS: the short ifName (Gi1/0/1) finds the long-form header",
      stanza == "interface GigabitEthernet1/0/1\n description uplink\n"
      " switchport mode trunk", stanza)
check("IOS: the trailing '!' separator is not part of the returned stanza",
      stanza is not None and not stanza.rstrip("\n").endswith("!"), stanza)

stanza2 = configrx_stanza.interface_stanza(ios_text, ["Gi1/0/2"])
check("IOS: a second interface in the same file is found on its own",
      stanza2 == "interface GigabitEthernet1/0/2\n description edge", stanza2)

# --------------------------------------------------- NX-OS, no '!' separator
nxos_text = (
    "interface Ethernet1/1\n"
    "  description core\n"
    "  no shutdown\n"
    "interface Ethernet1/2\n"
    "  shutdown\n"
)
stanza3 = configrx_stanza.interface_stanza(nxos_text, ["Eth1/1"])
check("NX-OS: a block with no '!' separator stops at the next interface header",
      stanza3 == "interface Ethernet1/1\n  description core\n  no shutdown", stanza3)

# ------------------------------------------------------ short/long name table
pairs_text_tpl = "interface {long}\n description x\n!\n"
for short, long in (
    ("Gi1/0/1", "GigabitEthernet1/0/1"),
    ("Te1/1/1", "TenGigabitEthernet1/1/1"),
    ("Po1", "Port-channel1"),
    ("Eth1/1", "Ethernet1/1"),
    ("Vl10", "Vlan10"),
    ("Fa0/1", "FastEthernet0/1"),
    ("Lo0", "Loopback0"),
    ("Tu0", "Tunnel0"),
    ("Hu1/1", "HundredGigE1/1"),
    ("Fo1/1", "FortyGigabitEthernet1/1"),
    ("Twe1/1", "TwentyFiveGigE1/1"),
):
    text = pairs_text_tpl.format(long=long)
    result = configrx_stanza.interface_stanza(text, [short])
    check(f"short/long match: {short} finds {long}",
          result is not None and result.startswith(f"interface {long}"), result)

# ------------------------------------------------------------------ no match
check("an interface not present in the config returns None",
      configrx_stanza.interface_stanza(ios_text, ["Gi2/0/1"]) is None)

check("empty text returns None",
      configrx_stanza.interface_stanza("", ["Gi1/0/1"]) is None)

check("no candidate names returns None",
      configrx_stanza.interface_stanza(ios_text, []) is None)

# ---------------------------------------- numeric part must match exactly
check("Gi1/0/1 does not match a config's Gi1/0/10 (same prefix, longer rest)",
      configrx_stanza.interface_stanza(
          "interface GigabitEthernet1/0/10\n shutdown\n!\n", ["Gi1/0/1"]) is None)

# --------------------------------------------------- exact equality, no prefix
check("ProCurve-style names with no alphabetic prefix match only exactly",
      configrx_stanza.interface_stanza(
          "interface 1/A1\n untagged vlan 10\n!\n", ["1/A1"]) is not None
      and configrx_stanza.interface_stanza(
          "interface 1/A1\n untagged vlan 10\n!\n", ["1/A2"]) is None)

# --------------------------------------------------------------- Juniper
juniper_text = (
    "interfaces {\n"
    "    ge-0/0/0 {\n"
    "        unit 0 {\n"
    "            family inet {\n"
    "                address 10.0.0.1/24;\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    ge-0/0/1 {\n"
    "        disable;\n"
    "    }\n"
    "}\n"
)
jstanza = configrx_stanza.interface_stanza(juniper_text, ["ge-0/0/0"])
check("Juniper: brace-matched block for the named interface",
      jstanza is not None and jstanza.startswith("    ge-0/0/0 {")
      and jstanza.rstrip().endswith("}") and "ge-0/0/1" not in jstanza
      and "address 10.0.0.1/24" in jstanza,
      jstanza)
check("Juniper: a name not present returns None",
      configrx_stanza.interface_stanza(juniper_text, ["ge-0/0/2"]) is None)

# ------------------------------- exact match wins over an earlier prefix hit
tw_text = (
    "interface TwentyFiveGigE1/0/1\n shutdown\n!\n"
    "interface TwoGigabitEthernet1/0/1\n description access\n!\n"
)
tw_result = configrx_stanza.interface_stanza(
    tw_text, ["Tw1/0/1", "TwoGigabitEthernet1/0/1"])
check("Tw1/0/1 finds the exact TwoGigabitEthernet1/0/1 header, not the "
      "earlier TwentyFiveGigE1/0/1 prefix match",
      tw_result is not None and tw_result.startswith("interface TwoGigabitEthernet1/0/1"),
      tw_result)

fo_text = (
    "interface FourHundredGigE1/0/1\n shutdown\n!\n"
    "interface FortyGigabitEthernet1/0/1\n description core\n!\n"
)
fo_result = configrx_stanza.interface_stanza(
    fo_text, ["Fo1/0/1", "FortyGigabitEthernet1/0/1"])
check("Fo1/0/1 finds the exact FortyGigabitEthernet1/0/1 header, not the "
      "earlier FourHundredGigE1/0/1 prefix match",
      fo_result is not None and fo_result.startswith("interface FortyGigabitEthernet1/0/1"),
      fo_result)

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

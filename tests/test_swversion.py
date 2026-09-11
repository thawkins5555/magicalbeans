"""netpath/swversion.py: the pure split of a device's software version and
image out of sysDescr plus whatever the one best-effort vendor GET answered.

Every sysDescr below is a real string off real gear (or the vendor's own
documented example), not an invented one — the point of the module is that
it never invents a version, so a table of made-up inputs would prove
nothing. A device nothing matches stores NULLs: the last case is a plain
net-snmp Linux box and it must come back empty on all three fields.
"""
import sys

import _paths  # noqa: F401  (repo root on sys.path)

from netpath import nodeoids, swversion

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


ENT = nodeoids.ENT_PHYSICAL_SOFTWARE_REV + ".1"
CISCO_CONFIG = nodeoids.CISCO_SYS_CONFIG_NAME


def sw(arc, sys_descr, scalars=None):
    return swversion.extract(arc, sys_descr, scalars or {})


# (name, arc, sysDescr, scalars, expected version, expected image)
CASES = [
    ("IOS 12 classic (Catalyst 2950)", 9,
     "Cisco Internetwork Operating System Software \r\nIOS (tm) C2950 Software "
     "(C2950-I6Q4L2-M), Version 12.1(22)EA14, RELEASE SOFTWARE (fc1)",
     {}, "12.1(22)EA14", "C2950-I6Q4L2-M"),
    ("IOS 15 (Catalyst 2960X)", 9,
     "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version "
     "15.2(7)E4, RELEASE SOFTWARE (fc2)",
     {}, "15.2(7)E4", "C2960X-UNIVERSALK9-M"),
    ("IOS-XE 16 bundle mode (Catalyst 3850)", 9,
     "Cisco IOS Software [Everest], Catalyst L3 Switch Software "
     "(CAT3K_CAA-UNIVERSALK9-M), Version 16.6.5, RELEASE SOFTWARE (fc3)",
     {}, "16.6.5", "CAT3K_CAA-UNIVERSALK9-M"),
    ("IOS-XE 17 install mode (Catalyst 9300)", 9,
     "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
     "(CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc4)",
     {}, "17.9.4a", "CAT9K_IOSXE"),
    ("NX-OS (Nexus 9000)", 9,
     "Cisco NX-OS(tm) n9000, Software (NXOS 64-bit), Version 9.3(8), RELEASE "
     "SOFTWARE Copyright (c) 2002-2021 by Cisco Systems, Inc.",
     {}, "9.3(8)", "NXOS 64-bit"),
    ("ASA (no image token at all)", 9,
     "Cisco Adaptive Security Appliance Version 9.12(4)35", {}, "9.12(4)35", ""),
    ("FortiGate fgSysVersion scalar", 12356,
     "FortiGate-100F",
     {nodeoids.SW_VERSION_OIDS[12356][0]: "v7.2.8,build1639,240416 (GA.M)"},
     "7.2.8", "build1639 (GA.M)"),
    ("FortiGate with no answer to the vendor GET: the same string is in "
     "sysDescr", 12356,
     "FortiGate-100F v7.2.8,build1639,240110 (GA.M) wireless-controller",
     {}, "7.2.8", "build1639 (GA.M)"),
    ("Aruba 2930F on Aruba's own arc, still ProCurve's sysDescr shape", 14823,
     "Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16.10.0021, "
     "ROM WC.16.01.0006 (/ws/swbuildm/rel_ukiah_qaoff)",
     {}, "WC.16.10.0021", "ROM WC.16.01.0006"),
    ("Junos EX, kernel JUNOS in sysDescr", 2636,
     "Juniper Networks, Inc. ex2200-24t-4g Ethernet Switch, kernel JUNOS "
     "12.3R12.4, Build date: 2016-01-20 05:31:35 UTC",
     {}, "12.3R12.4", ""),
    ("Junos SRX, hrSWInstalledName package", 2636,
     "Juniper Networks, Inc. srx300 internet router",
     {nodeoids.HR_SW_INSTALLED_NAME_FIRST: "JUNOS Software Release [20.4R3.8]"},
     "20.4R3.8", "JUNOS Software Release"),
    ("HP ProCurve, revision + ROM in sysDescr", 11,
     "ProCurve J9085A Switch 2610-24, revision R.11.122, ROM R.10.06 "
     "(/sw/code/build/cod)",
     {}, "R.11.122", "ROM R.10.06"),
    ("HP ProCurve, hpSwitchOsVersion scalar wins", 11,
     "ProCurve J9085A Switch 2610-24, revision R.11.122, ROM R.10.06",
     {nodeoids.SW_VERSION_OIDS[11][0]: "R.11.130"}, "R.11.130", "ROM R.10.06"),
    ("Aruba CX, entPhysicalSoftwareRev on the chassis row", 47196,
     "Aruba JL663A 6300M 48SR5 CL6 PoE 4SFP56 Swch",
     {ENT: "PL.10.09.0010"}, "PL.10.09.0010", ""),
    ("HPE Comware, Software Version + Release", 25506,
     "HPE Comware Platform Software, Software Version 7.1.070, Release 3208P03 "
     "HPE 5130 48G PoE+ 4SFP+ (370W) EI Switch",
     {}, "7.1.070", "Release 3208P03"),
    ("Arista EOS", 30065,
     "Arista Networks EOS version 4.27.3M running on an Arista Networks "
     "DCS-7050SX-64",
     {}, "4.27.3M", ""),
    ("ExtremeXOS, image in parentheses", 1916,
     "ExtremeXOS (X440G2-48t-10G4) version 31.7.1.4 v3171b4-patch1-5 by "
     "release-manager on Wed Apr 6 2022",
     {}, "31.7.1.4", "X440G2-48t-10G4"),
    ("MikroTik, RouterBOOT as the image", 14988,
     "RouterOS CCR1009-7G-1C-1S+",
     {nodeoids.SW_VERSION_OIDS[14988][0]: "6.49.7",
      nodeoids.SW_VERSION_OIDS[14988][1]: "6.48.6"},
     "6.49.7", "RouterBOOT 6.48.6"),
    ("Ubiquiti airOS, firmware in sysDescr", 41112,
     "Linux 2.6.32 #1 SMP NanoStation M5 firmware XM.v6.3.11",
     {}, "XM.v6.3.11", ""),
    ("Ubiquiti UniFi AP scalar", 41112,
     "UAP-AC-PRO", {nodeoids.SW_VERSION_OIDS[41112][0]: "6.5.28.15047"},
     "6.5.28.15047", ""),
    ("Palo Alto panSysSwVersion", 25461,
     "Palo Alto Networks PA-3220 series firewall",
     {nodeoids.SW_VERSION_OIDS[25461][0]: "10.1.9"}, "10.1.9", ""),
    ("Dell N-series productIdentificationVersion", 674,
     "Dell Networking N3048P, 6.6.0.19, Linux 3.6.5-8dd4c48f",
     {nodeoids.SW_VERSION_OIDS[674][0]: "6.6.0.19"}, "6.6.0.19", ""),
    ("Brocade/Ruckus ICX snAgImgVer", 1991,
     "Brocade Communications Systems, Inc. ICX7250-48P, IronWare Version "
     "08.0.30tT213 Compiled on Sep 13 2016",
     {nodeoids.SW_VERSION_OIDS[1991][0]: "08.0.30tT213"}, "08.0.30tT213", ""),
    ("Brocade ICX with no scalar falls back to the sysDescr text", 1991,
     "Brocade Communications Systems, Inc. ICX7250-48P, IronWare Version "
     "08.0.30tT213 Compiled on Sep 13 2016",
     {}, "08.0.30tT213", ""),
    ("net-snmp Linux: nothing is invented", 8072,
     "Linux nms-01 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC "
     "2023 x86_64",
     {}, "", ""),
]

for name, arc, descr, scalars, want_version, want_image in CASES:
    info = sw(arc, descr, scalars)
    check(f"{name}: version {want_version!r}",
          info.version == want_version, repr(info))
    check(f"{name}: image {want_image!r}", info.image == want_image, repr(info))

# ------------------------------------------------------- the standard fallback

check("a rule that fell back to sysDescr says so in `source`, so the "
      "vendor GET's own answer stays distinguishable from the text guess",
      sw(12356, "FortiGate-60F v7.2.5,build1517,230606 (GA.M)", {}).source
      == "sysDescr"
      and sw(12356, "", {nodeoids.SW_VERSION_OIDS[12356][0]: "v7.2.8,build1639"}
             ).source == "vendor_oid",
      (sw(12356, "FortiGate-60F v7.2.5,build1517,230606 (GA.M)", {}),))

info = sw(2011, "Some switch nobody wrote a rule for", {ENT: "V200R019C00SPC500"})
check("entPhysicalSoftwareRev answers for a vendor with no rule of its own",
      info.version == "V200R019C00SPC500" and info.source == "entPhysicalSoftwareRev",
      repr(info))

info = sw(None, "Widget controller, firmware v2.14b", {})
check("the generic sysDescr regex answers where nothing else does",
      info.version == "2.14b" and info.source == "sysDescr", repr(info))

info = sw(None, "Linux nms-01 5.15.0-76-generic #83-Ubuntu SMP x86_64", {})
check("...and matches nothing on a string with no version word in it",
      info.version == "" and info.image == "" and info.source == "", repr(info))

# ------------------------------------------------- Cisco's boot image file

CONFIG_NAME = "flash:/c2960x-universalk9-mz.152-7.E4/c2960x-universalk9-mz.152-7.E4.bin"
info = sw(9, "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
             "Version 15.2(7)E4, RELEASE SOFTWARE (fc2)",
          {CISCO_CONFIG: CONFIG_NAME})
check("sysConfigName is kept as the boot image FILE, beside the image name",
      info.image == "C2960X-UNIVERSALK9-M" and info.image_file == CONFIG_NAME,
      repr(info))

info = sw(9, "Cisco IOS-XE running in install mode",
          {CISCO_CONFIG: "bootflash:packages.conf", ENT: "17.6.5"})
check("...and its basename stands in as the image when sysDescr has no "
      "parenthesised one",
      info.image == "packages.conf" and info.version == "17.6.5", repr(info))

# --------------------------------------------------------------- robustness

check("no sysDescr, no scalars, no arc is empty rather than an exception",
      swversion.extract(None, "", {}) == swversion.SwInfo(),
      repr(swversion.extract(None, "", {})))
check("a non-text scalar answer (an agent returning an integer) is ignored, "
      "not stringified into a version",
      sw(11, "", {nodeoids.SW_VERSION_OIDS[11][0]: b"\x00\x01"}).version == "",
      repr(sw(11, "", {nodeoids.SW_VERSION_OIDS[11][0]: b"\x00\x01"})))

# ------------------------------------------------------- the OIDs to request

oids = swversion.oids_for(9)
check("a Cisco poll asks for the chassis entPhysicalSoftwareRev and "
      "sysConfigName",
      ENT in oids and CISCO_CONFIG in oids, oids)
check("...and asks for each OID exactly once", len(oids) == len(set(oids)), oids)
check("an unknown arc still asks for the standard entPhysicalSoftwareRev",
      swversion.oids_for(None) == (ENT,), swversion.oids_for(None))
check("a vendor with a scalar of its own asks for it too",
      nodeoids.SW_VERSION_OIDS[12356][0] in swversion.oids_for(12356),
      swversion.oids_for(12356))
check("no vendor asks for more than four objects (one GET, not a walk)",
      all(len(swversion.oids_for(arc)) <= 4 for arc in nodeoids.SW_VERSION_OIDS),
      {arc: swversion.oids_for(arc) for arc in nodeoids.SW_VERSION_OIDS})

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

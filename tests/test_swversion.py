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
    ("Cisco wireless (Catalyst 9800) agentInventoryProductVersion", 14179,
     "Cisco Controller", {nodeoids.SW_VERSION_OIDS[14179][0]: "8.10.185.0"},
     "8.10.185.0", ""),
    ("Netgear agentInventorySoftwareVersion", 4526,
     "NETGEAR GS724Tv4", {nodeoids.SW_VERSION_OIDS[4526][0]: "6.0.9.0"},
     "6.0.9.0", ""),
    ("SonicWall snwlSysFirmwareVersion", 8741,
     "SonicWALL", {nodeoids.SW_VERSION_OIDS[8741][0]: "7.0.1-5119"},
     "7.0.1-5119", ""),
    ("Synology version scalar", 6574,
     "Synology RackStation", {nodeoids.SW_VERSION_OIDS[6574][0]: "7.2-64570"},
     "7.2-64570", ""),
    ("VMware vmwProdVersion", 6876,
     "VMware ESXi", {nodeoids.SW_VERSION_OIDS[6876][0]: "7.0.3"},
     "7.0.3", ""),
    ("Sophos sfosDeviceFWVersion", 2604,
     "Sophos XG Firewall", {nodeoids.SW_VERSION_OIDS[2604][0]: "19.5.3"},
     "19.5.3", ""),
    ("F5 sysProductVersion", 3375,
     "BIG-IP", {nodeoids.SW_VERSION_OIDS[3375][0]: "16.1.3.2"},
     "16.1.3.2", ""),
    ("F5's other module root (12276), same sysProductVersion object", 12276,
     "BIG-IP", {nodeoids.SW_VERSION_OIDS[12276][0]: "15.1.5"},
     "15.1.5", ""),
    ("Citrix sysBuildVersion", 5951,
     "NetScaler", {nodeoids.SW_VERSION_OIDS[5951][0]: "13.1-49.15"},
     "13.1-49.15", ""),
    ("Zyxel sysSwVersionString", 890,
     "Zyxel GS1900-24", {nodeoids.SW_VERSION_OIDS[890][0]: "V2.70(AAHH.0)"},
     "V2.70(AAHH.0)", ""),
    ("Cambium swVersion", 161,
     "Cambium ePMP 1000", {nodeoids.SW_VERSION_OIDS[161][0]: "4.7.1"},
     "4.7.1", ""),
    ("Cambium's other arc (17713), same swVersion object", 17713,
     "Cambium PTP", {nodeoids.SW_VERSION_OIDS[17713][0]: "5.5.2"},
     "5.5.2", ""),
    ("Aerohive ahFirmwareVersion", 26928,
     "Aerohive AP330", {nodeoids.SW_VERSION_OIDS[26928][0]: "10.0r8"},
     "10.0r8", ""),
    ("TP-Link tpSysInfoSwVersion", 11863,
     "TP-Link T1600G-28TS", {nodeoids.SW_VERSION_OIDS[11863][0]: "1.0.0 Build 20210101"},
     "1.0.0 Build 20210101", ""),
    ("Moxa siStatProductInfoFirmwareVersion", 8691,
     "Moxa NPort 5110", {nodeoids.SW_VERSION_OIDS[8691][0]: "2.5"},
     "2.5", ""),
    ("Check Point svnProdVerMajor/Minor composed", 2620,
     "Check Point Gateway",
     {nodeoids.SW_VERSION_OIDS[2620][0]: 81, nodeoids.SW_VERSION_OIDS[2620][1]: 20},
     "81.20", ""),
    ("NETGEAR smart-switch line answers under ng700smartswitch", 4526,
     "GS308T", {nodeoids.SW_VERSION_OIDS[4526][1]: "1.0.0.10"},
     "1.0.0.10", ""),
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
ENT_FW = nodeoids.ENT_PHYSICAL_FIRMWARE_REV + ".1"
check("an unknown arc still asks for the standard entPhysicalSoftwareRev "
      "and entPhysicalFirmwareRev",
      swversion.oids_for(None) == (ENT, ENT_FW), swversion.oids_for(None))
check("a vendor with a scalar of its own asks for it too",
      nodeoids.SW_VERSION_OIDS[12356][0] in swversion.oids_for(12356),
      swversion.oids_for(12356))
check("no vendor asks for more than four objects (one GET, not a walk)",
      all(len(swversion.oids_for(arc)) <= 4 for arc in nodeoids.SW_VERSION_OIDS),
      {arc: swversion.oids_for(arc) for arc in nodeoids.SW_VERSION_OIDS})

oids = swversion.oids_for(8741)
check("a vendor with a software scalar, a separate firmware scalar and both "
      "ENTITY-MIB fallbacks asks for all four, once each",
      len(oids) == 4 and len(oids) == len(set(oids)), oids)

# ------------------------------------------------------- firmware scalars

for name, arc, descr, version, firmware in (
        ("SonicWall: snwlSysFirmwareVersion + snwlSysROMVersion", 8741,
         "SonicWALL TZ 370", "7.0.1-5145", "6.4.0.0"),
        ("Eaton 534: xupsIdentSoftwareVersion lands as firmware", 534,
         "Eaton 5PX", "", "02.10.0012"),
        ("Eaton 705 shares the XUPS-MIB object", 705,
         "Eaton 9PX", "", "03.02.0001"),
        ("Vertiv: the agent card's scalar when no managed device answered", 476,
         "Liebert GXT4", "", "2.500.0")):
    scalars = {nodeoids.FW_VERSION_OIDS[arc]: firmware}
    if version:
        scalars[nodeoids.SW_VERSION_OIDS[arc][0]] = version
    info = swversion.extract(arc, descr, scalars)
    check(name, info.version == version and info.firmware == firmware and
          info.fw_source == "vendor_oid", repr(info))

VERTIV_FW = nodeoids.SW_VERSION_COLUMNS[476][0][1]
info = swversion.extract(476, "Liebert GXT4",
                         {nodeoids.FW_VERSION_OIDS[476]: "2.500.0"},
                         columns={VERTIV_FW: {"1": "UPS 4.1.2"}})
check("...and the managed device's own firmware column beats the card's scalar",
      info.firmware == "UPS 4.1.2", repr(info))

# ------------------------------------------------------------- ArubaOS 14823

info = swversion.extract(14823, "ArubaOS (MODEL: Aruba7210)",
                         {nodeoids.WLSX_SYS_EXT_SW_VERSION: "8.10.0.4"})
check("Aruba's controller arc uses wlsxSysExtSwVersion when sysDescr says "
      "ArubaOS, not the ProCurve _hp shape",
      info.version == "8.10.0.4" and info.source == "vendor_oid", repr(info))

# ------------------------------------------------------- firmware, dropped

info = swversion.extract(47196, "Aruba JL663A 6300M",
                         {ENT: "PL.10.09.0010", ENT_FW: "PL.10.09.0010"})
check("firmware that just repeats the version is dropped rather than shown "
      "twice",
      info.version == "PL.10.09.0010" and info.firmware == "" and
      info.fw_source == "", repr(info))

info = swversion.extract(9, "Cisco IOS-XE running in install mode",
                         {CISCO_CONFIG: "bootflash:packages.conf", ENT: "17.6.5",
                          ENT_FW: "17.6.6"})
check("...but a genuinely different firmware value is kept, sourced from "
      "entPhysicalFirmwareRev",
      info.version == "17.6.5" and info.firmware == "17.6.6" and
      info.fw_source == "entPhysicalFirmwareRev", repr(info))

# ----------------------------------------------------------- column vendors

DELL_SW = nodeoids.SW_VERSION_COLUMNS[6027][0][0]
info = swversion.extract(6027, "Dell Networking S4048", {},
                         columns={DELL_SW: {"1": "10.5.1.6"}})
check("Dell dellNetSwModuleRuntimeImgVersion, first row",
      info.version == "10.5.1.6" and info.source == "vendor_oid", repr(info))

RUCKUS_SW, RUCKUS_STATUS = nodeoids.SW_VERSION_COLUMNS[25053][0][0], \
    nodeoids.SW_VERSION_COLUMNS[25053][1]
info = swversion.extract(25053, "Ruckus ZoneFlex R510", {}, columns={
    RUCKUS_SW: {"1": "112.0.0.0build158", "2": "112.0.0.10build162"},
    RUCKUS_STATUS: {"1": 1, "2": 2},
})
check("Ruckus: the row whose ruckusSwRevStatus is active(2) wins over an "
      "inactive row",
      info.version == "112.0.0.10build162" and info.source == "vendor_oid",
      repr(info))

ARUBA_CX_SW, ARUBA_CX_FW = nodeoids.SW_VERSION_COLUMNS[47196][0]
info = swversion.extract(47196, "Aruba JL658A 6300M", {}, columns={
    ARUBA_CX_SW: {"1": "FL.10.09.0010"}, ARUBA_CX_FW: {"1": "1.0.0.6"},
})
check("Aruba CX: software column and firmware (ServiceOS) column both read",
      info.version == "FL.10.09.0010" and info.firmware == "1.0.0.6" and
      info.fw_source == "vendor_oid", repr(info))

VERTIV_FW = nodeoids.SW_VERSION_COLUMNS[476][0][1]
info = swversion.extract(476, "Liebert GXT5", {},
                         columns={VERTIV_FW: {"1": "4.2.1"}})
check("Vertiv: firmware-only column, no software column to answer `version`",
      info.version == "" and info.firmware == "4.2.1" and
      info.fw_source == "vendor_oid", repr(info))

RARITAN_FW = nodeoids.SW_VERSION_COLUMNS[13742][0][1]
info = swversion.extract(13742, "Raritan PX3-5000 PDU", {}, columns={
    RARITAN_FW: {"1.2.1": "2.1.0", "1.1.1": "3.5.2"},
})
check("Raritan: the row whose boardType (index component 2) is 1 wins over "
      "a boardType-2 row, regardless of walk order",
      info.firmware == "3.5.2", repr(info))

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

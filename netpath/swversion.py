"""Which software version and image a device is running, split out of what
the poller already has: its sysDescr, and one best-effort GET of the vendor
objects nodeoids.SW_VERSION_OIDS names for its enterprise arc.

Pure — no I/O, no database, no SNMP. `extract()` takes the arc, the sysDescr
string and a {oid: value} dict of whatever that GET answered, and returns the
three fields stored on the device row. It never invents one: a device nothing
matches comes back empty on all three, which is stored as NULL and shown as
nothing at all.

The per-vendor rules are the ones the vendors' own strings actually carry —
Cisco writes `(IMAGE), Version X` in sysDescr on every IOS train there has
ever been, Fortinet writes `v7.2.8,build1639,240416 (GA.M)` into fgSysVersion,
Junos writes `kernel JUNOS X` — with ENTITY-MIB's entPhysicalSoftwareRev as
the standard fallback for everything else and a deliberately narrow generic
sysDescr regex behind that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import nodeoids

VENDOR_SW_OIDS = nodeoids.SW_VERSION_OIDS
ENT_SOFTWARE_REV = nodeoids.ENT_PHYSICAL_SOFTWARE_REV_FIRST


@dataclass(frozen=True)
class SwInfo:
    version: str = ""
    image: str = ""
    # Cisco's sysConfigName: the boot image's file path, not a version.
    image_file: str = ""
    # Which of the four rules answered: "vendor_oid", "sysDescr",
    # "entPhysicalSoftwareRev" or "" for a device that matched nothing.
    source: str = ""


def oids_for(arc) -> tuple[str, ...]:
    """The objects one identity poll asks this device for, deduplicated: its
    vendor's own version/image scalars where nodeoids names any, plus the
    standard chassis entPhysicalSoftwareRev. Small enough to be one GET on
    every vendor — never a walk."""
    oids = []
    for oid in VENDOR_SW_OIDS.get(arc, (None, None)):
        if oid and oid not in oids:
            oids.append(oid)
    if ENT_SOFTWARE_REV not in oids:
        oids.append(ENT_SOFTWARE_REV)
    return tuple(oids)


def _text(value) -> str:
    """A scalar answer as a printable string, or "" for anything that is not
    one. An agent answering an integer or raw octets where a DisplayString
    was expected has not told us a version."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return ""
        return decoded.strip() if decoded.isprintable() else ""
    return ""


def _scalar(scalars: dict, arc, which: int) -> str:
    oid = VENDOR_SW_OIDS.get(arc, (None, None))[which]
    return _text(scalars.get(oid)) if oid else ""


def _search(pattern: str, text: str, group: int = 1) -> str:
    match = re.search(pattern, text or "", re.IGNORECASE)
    return (match.group(group) or "").strip() if match else ""


# ------------------------------------------------------------- per vendor

# `(IMAGE), Version X` — the one shape every Cisco train writes, from
# IOS 12's "IOS (tm) C2950 Software (C2950-I6Q4L2-M), Version 12.1(22)EA14"
# through IOS-XE's "(CAT9K_IOSXE), Version 17.9.4a" to NX-OS's
# "Software (NXOS 64-bit), Version 9.3(8)". Anchored on the parenthesis
# IMMEDIATELY followed by ", Version", which is what keeps "(tm)" out of it.
_CISCO_IMAGE_VERSION = re.compile(r"\(([^()]{1,64})\)\s*,\s*Version\s+([^,\s]+)",
                                  re.IGNORECASE)
_CISCO_ASA = r"Adaptive Security Appliance Version\s+([^,\s]+)"


def _cisco(sys_descr: str, scalars: dict) -> SwInfo:
    image_file = _text(scalars.get(nodeoids.CISCO_SYS_CONFIG_NAME))
    match = _CISCO_IMAGE_VERSION.search(sys_descr or "")
    if match:
        return SwInfo(version=match.group(2).strip(),
                      image=match.group(1).strip(), image_file=image_file,
                      source="sysDescr")
    version = _search(_CISCO_ASA, sys_descr) or _search(r"\bVersion\s+([^,\s]+)", sys_descr)
    # An install-mode IOS-XE box says nothing useful in sysDescr; its boot
    # file's basename is the closest thing to an image name it has.
    image = image_file.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if image_file else ""
    return SwInfo(version=version, image=image, image_file=image_file,
                  source="sysDescr" if version else "")


def _fortinet(sys_descr: str, scalars: dict) -> SwInfo:
    raw = _scalar(scalars, 12356, 0)
    source = "vendor_oid"
    if not raw:
        # FortiOS writes fgSysVersion's own string into sysDescr as well:
        # "FortiGate-60F v7.2.5,build1517,230606 (GA.M)". Same split, so a
        # device whose vendor GET went unanswered is not left blank.
        raw = _search(r"(\bv[0-9][\w.]*,build.*)$", sys_descr)
        source = "sysDescr"
    version = _search(r"^v?([0-9][\w.]*)", raw)
    build = _search(r"build(\w+)", raw)
    tag = _search(r"\(([^)]+)\)", raw)
    image = f"build{build}" + (f" ({tag})" if build and tag else "") if build else ""
    return SwInfo(version=version, image=image, source=source if version else "")


def _juniper(sys_descr: str, scalars: dict) -> SwInfo:
    version = _search(r"kernel JUNOS ([^\s,]+)", sys_descr)
    if version:
        return SwInfo(version=version, source="sysDescr")
    package = _scalar(scalars, 2636, 1)
    version = _search(r"\[([^\]]+)\]", package)
    image = package.split("[", 1)[0].strip() if version else ""
    return SwInfo(version=version, image=image,
                  source="vendor_oid" if version else "")


def _hp(sys_descr: str, scalars: dict) -> SwInfo:
    # hpSwitchRomVersion is a second object for the same fact sysDescr's
    # "ROM X" already carries, so only the version scalar is requested.
    rom = _search(r"\bROM ([^\s,)]+)", sys_descr)
    image = f"ROM {rom}" if rom else ""
    version = _scalar(scalars, 11, 0)
    if version:
        return SwInfo(version=version, image=image, source="vendor_oid")
    version = _search(r"revision ([^\s,]+)", sys_descr)
    return SwInfo(version=version, image=image,
                  source="sysDescr" if version else "")


def _comware(sys_descr: str, scalars: dict) -> SwInfo:
    version = _search(r"Software Version ([^\s,]+)", sys_descr)
    release = _search(r"\bRelease (\w+)", sys_descr)
    return SwInfo(version=version, image=f"Release {release}" if release else "",
                  source="sysDescr" if version else "")


def _arista(sys_descr: str, scalars: dict) -> SwInfo:
    version = _search(r"EOS version ([^\s,]+)", sys_descr)
    return SwInfo(version=version, source="sysDescr" if version else "")


def _extreme(sys_descr: str, scalars: dict) -> SwInfo:
    image = _search(r"ExtremeXOS \(([^)]+)\)", sys_descr)
    version = _scalar(scalars, 1916, 0)
    if version:
        return SwInfo(version=version, image=image, source="vendor_oid")
    version = _search(r"\bversion ([^\s,]+)", sys_descr)
    return SwInfo(version=version, image=image,
                  source="sysDescr" if version else "")


def _mikrotik(sys_descr: str, scalars: dict) -> SwInfo:
    version = _scalar(scalars, 14988, 0)
    boot = _scalar(scalars, 14988, 1)
    return SwInfo(version=version, image=f"RouterBOOT {boot}" if boot else "",
                  source="vendor_oid" if version else "")


def _ubiquiti(arc):
    def rule(sys_descr: str, scalars: dict) -> SwInfo:
        version = _scalar(scalars, arc, 0)
        if version:
            return SwInfo(version=version, source="vendor_oid")
        version = _search(r"firmware ([^\s,]+)", sys_descr)
        return SwInfo(version=version, source="sysDescr" if version else "")
    return rule


def _plain_scalar(arc, descr_pattern: str = ""):
    """A vendor whose whole answer is one DisplayString scalar, with an
    optional sysDescr regex behind it (Dell and Brocade both write the same
    version into sysDescr as well, and plenty of them answer only one)."""
    def rule(sys_descr: str, scalars: dict) -> SwInfo:
        version = _scalar(scalars, arc, 0)
        if version:
            return SwInfo(version=version, source="vendor_oid")
        version = _search(descr_pattern, sys_descr) if descr_pattern else ""
        return SwInfo(version=version, source="sysDescr" if version else "")
    return rule


_RULES = {
    9: _cisco,
    12356: _fortinet,
    2636: _juniper,
    11: _hp,
    # Aruba's own arc, for the ProCurve-lineage switches (2930F and kin)
    # that answer it while still writing HP's "revision X, ROM Y" sysDescr.
    # Aruba CX (47196) writes neither and falls through to
    # entPhysicalSoftwareRev, which is what it does answer.
    14823: _hp,
    25506: _comware,
    30065: _arista,
    1916: _extreme,
    14988: _mikrotik,
    41112: _ubiquiti(41112),
    10002: _ubiquiti(10002),
    25461: _plain_scalar(25461),
    674: _plain_scalar(674),
    1991: _plain_scalar(1991, r"IronWare Version ([^\s,]+)"),
}

# Last resort, on a device no rule above claimed and with no
# entPhysicalSoftwareRev: a version-looking token after a version-ish word.
# Deliberately narrow — it must start with a digit, so "Linux 5.15.0-76-generic
# #83-Ubuntu SMP" (no keyword at all) and a model number in a product name
# both fall through to nothing rather than to a fiction.
_GENERIC = r"(?:firmware|version|revision|release)[:\s]+v?([0-9][\w.()-]*)"


def extract(arc, sys_descr: str, scalars: dict) -> SwInfo:
    """(version, image, image_file, source) for one device.

    Rules in order: the vendor's own rule (its scalar, then its sysDescr
    shape), then ENTITY-MIB's entPhysicalSoftwareRev, then the generic
    sysDescr regex. Anything unmatched stays empty."""
    scalars = scalars or {}
    sys_descr = sys_descr or ""
    rule = _RULES.get(arc)
    info = rule(sys_descr, scalars) if rule else SwInfo()
    if info.version:
        return info
    ent = _text(scalars.get(ENT_SOFTWARE_REV))
    if ent:
        return SwInfo(version=ent, image=info.image, image_file=info.image_file,
                      source="entPhysicalSoftwareRev")
    generic = _search(_GENERIC, sys_descr)
    if generic:
        return SwInfo(version=generic, image=info.image,
                      image_file=info.image_file, source="sysDescr")
    return info

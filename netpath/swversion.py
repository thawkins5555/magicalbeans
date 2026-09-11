"""Which software version and image a device is running, from its sysDescr
and one best-effort GET of the vendor objects nodeoids.SW_VERSION_OIDS names."""

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
    image_file: str = ""  # Cisco's sysConfigName: boot image file path, not a version.
    source: str = ""


def oids_for(arc) -> tuple[str, ...]:
    """The objects one identity poll asks this device for, deduplicated."""
    oids = []
    for oid in VENDOR_SW_OIDS.get(arc, (None, None)):
        if oid and oid not in oids:
            oids.append(oid)
    if ENT_SOFTWARE_REV not in oids:
        oids.append(ENT_SOFTWARE_REV)
    return tuple(oids)


def _text(value) -> str:
    """A scalar answer as a printable string, or "" for anything that is not one."""
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

# `(IMAGE), Version X` — the shape every Cisco train writes into sysDescr.
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
    # Install-mode IOS-XE: fall back to the boot file's basename as the image name.
    image = image_file.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if image_file else ""
    return SwInfo(version=version, image=image, image_file=image_file,
                  source="sysDescr" if version else "")


def _fortinet(sys_descr: str, scalars: dict) -> SwInfo:
    raw = _scalar(scalars, 12356, 0)
    source = "vendor_oid"
    if not raw:
        # FortiOS writes fgSysVersion's own string into sysDescr as well.
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
    """A vendor whose whole answer is one DisplayString scalar."""
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
    14823: _hp,  # Aruba's own arc, for ProCurve-lineage switches sharing HP's sysDescr shape.
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

# Last resort: a version-looking token after a version-ish word, deliberately
# narrow (must start with a digit) so an unrelated string doesn't match.
_GENERIC = r"(?:firmware|version|revision|release)[:\s]+v?([0-9][\w.()-]*)"


def extract(arc, sys_descr: str, scalars: dict) -> SwInfo:
    """(version, image, image_file, source) for one device."""
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

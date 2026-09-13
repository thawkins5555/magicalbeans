"""Which software version and image a device is running, from its sysDescr
and one best-effort GET of the vendor objects nodeoids.SW_VERSION_OIDS names."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from . import nodeoids

VENDOR_SW_OIDS = nodeoids.SW_VERSION_OIDS
VENDOR_FW_OIDS = nodeoids.FW_VERSION_OIDS
ENT_SOFTWARE_REV = nodeoids.ENT_PHYSICAL_SOFTWARE_REV_FIRST
ENT_FIRMWARE_REV = nodeoids.ENT_PHYSICAL_FIRMWARE_REV_FIRST


@dataclass(frozen=True)
class SwInfo:
    version: str = ""
    image: str = ""
    image_file: str = ""  # Cisco's sysConfigName: boot image file path, not a version.
    source: str = ""
    firmware: str = ""
    fw_source: str = ""


def oids_for(arc) -> tuple[str, ...]:
    """The objects one identity poll asks this device for, deduplicated."""
    oids = []
    for oid in VENDOR_SW_OIDS.get(arc, (None, None)):
        if oid and oid not in oids:
            oids.append(oid)
    fw_oid = VENDOR_FW_OIDS.get(arc)
    if fw_oid and fw_oid not in oids:
        oids.append(fw_oid)
    if ENT_SOFTWARE_REV not in oids:
        oids.append(ENT_SOFTWARE_REV)
    if ENT_FIRMWARE_REV not in oids:
        oids.append(ENT_FIRMWARE_REV)
    if arc == 14823 and nodeoids.WLSX_SYS_EXT_SW_VERSION not in oids:
        oids.append(nodeoids.WLSX_SYS_EXT_SW_VERSION)
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


def _num_text(value) -> str:
    """An integer scalar (Gauge32/Integer32) as a printable string. Excludes
    bool, which is an int subclass but never a version component."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return _text(value)


def _num_scalar(scalars: dict, arc, which: int) -> str:
    oid = VENDOR_SW_OIDS.get(arc, (None, None))[which]
    return _num_text(scalars.get(oid)) if oid else ""


def _index_key(index: str):
    """Sort key for a walk's index suffixes, numeric when every component is."""
    try:
        return tuple(int(part) for part in index.split("."))
    except ValueError:
        return (index,)


def _first_nonempty(rows: dict) -> str:
    for index in sorted(rows, key=_index_key):
        value = _text(rows[index])
        if value:
            return value
    return ""


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


def _checkpoint(sys_descr: str, scalars: dict) -> SwInfo:
    """svnProdVerMajor/Minor, two Gauge32 composed into one "major.minor"."""
    major = _num_scalar(scalars, 2620, 0)
    minor = _num_scalar(scalars, 2620, 1)
    version = f"{major}.{minor}" if major and minor else ""
    return SwInfo(version=version, source="vendor_oid" if version else "")


def _either_scalar(arc):
    """A vendor with the same object under two product-line arcs; whichever answered."""
    def rule(sys_descr: str, scalars: dict) -> SwInfo:
        version = _scalar(scalars, arc, 0) or _scalar(scalars, arc, 1)
        return SwInfo(version=version, source="vendor_oid" if version else "")
    return rule


def _aruba_or_hp(sys_descr: str, scalars: dict) -> SwInfo:
    if "ArubaOS" in (sys_descr or ""):
        version = _text(scalars.get(nodeoids.WLSX_SYS_EXT_SW_VERSION))
        return SwInfo(version=version, source="vendor_oid" if version else "")
    return _hp(sys_descr, scalars)


# --------------------------------------------------------- column vendors

def _raritan_row(rows: dict) -> str:
    """The row whose compound index names boardType 1 (the main controller),
    else the first non-empty row."""
    for index in sorted(rows, key=_index_key):
        parts = index.split(".")
        if len(parts) > 1 and parts[1] == "1":
            value = _text(rows[index])
            if value:
                return value
    return _first_nonempty(rows)


def _ruckus_row(sw_rows: dict, status_rows: dict) -> str:
    """The row whose ruckusSwRevStatus is active(2), else the first non-empty row."""
    for index in sorted(sw_rows, key=_index_key):
        if _num_text(status_rows.get(index)) == "2":
            value = _text(sw_rows[index])
            if value:
                return value
    return _first_nonempty(sw_rows)


def _column_first(arc):
    """A rule reading nodeoids.SW_VERSION_COLUMNS's sw column out of a walk."""
    (sw_column, _fw_column), status_column = nodeoids.SW_VERSION_COLUMNS[arc]
    def rule(columns: dict) -> SwInfo:
        rows = columns.get(sw_column) or {} if sw_column else {}
        if not rows:
            return SwInfo()
        if arc == 25053:
            version = _ruckus_row(rows, columns.get(status_column) or {})
        elif arc == 13742:
            version = _raritan_row(rows)
        else:
            version = _first_nonempty(rows)
        return SwInfo(version=version, source="vendor_oid" if version else "")
    return rule


def _column_firmware(arc, columns: dict) -> str:
    (_sw_column, fw_column), _status_column = nodeoids.SW_VERSION_COLUMNS[arc]
    if not fw_column:
        return ""
    rows = columns.get(fw_column) or {}
    if not rows:
        return ""
    return _raritan_row(rows) if arc == 13742 else _first_nonempty(rows)


_RULES = {
    9: _cisco,
    12356: _fortinet,
    2636: _juniper,
    11: _hp,
    14823: _aruba_or_hp,
    25506: _comware,
    30065: _arista,
    1916: _extreme,
    14988: _mikrotik,
    41112: _ubiquiti(41112),
    10002: _ubiquiti(10002),
    25461: _plain_scalar(25461),
    674: _plain_scalar(674),
    1991: _plain_scalar(1991, r"IronWare Version ([^\s,]+)"),
    14179: _plain_scalar(14179),
    4526: _either_scalar(4526),
    8741: _plain_scalar(8741),
    6574: _plain_scalar(6574),
    6876: _plain_scalar(6876),
    2604: _plain_scalar(2604),
    3375: _plain_scalar(3375),
    12276: _plain_scalar(12276),
    5951: _plain_scalar(5951),
    890: _plain_scalar(890),
    161: _plain_scalar(161),
    17713: _plain_scalar(17713),
    26928: _plain_scalar(26928),
    11863: _plain_scalar(11863),
    8691: _plain_scalar(8691),
    2620: _checkpoint,
    318: _plain_scalar(318),
}

# Last resort: a version-looking token after a version-ish word, deliberately
# narrow (must start with a digit) so an unrelated string doesn't match.
_GENERIC = r"(?:firmware|version|revision|release)[:\s]+v?([0-9][\w.()-]*)"


def _fill_firmware(arc, info: SwInfo, scalars: dict, columns: dict) -> SwInfo:
    """firmware/fw_source: vendor column (the equipment) > vendor scalar >
    entPhysicalFirmwareRev, dropped when it just repeats `version`."""
    firmware = ""
    fw_source = ""
    if arc in nodeoids.SW_VERSION_COLUMNS:
        firmware = _column_firmware(arc, columns)
        fw_source = "vendor_oid" if firmware else ""
    fw_oid = VENDOR_FW_OIDS.get(arc)
    if not firmware and fw_oid:
        firmware = _text(scalars.get(fw_oid))
        fw_source = "vendor_oid" if firmware else ""
    if not firmware:
        firmware = _text(scalars.get(ENT_FIRMWARE_REV))
        fw_source = "entPhysicalFirmwareRev" if firmware else ""
    if firmware and firmware == info.version:
        firmware, fw_source = "", ""
    return replace(info, firmware=firmware, fw_source=fw_source)


def extract(arc, sys_descr: str, scalars: dict, columns: dict = None) -> SwInfo:
    """(version, image, image_file, source, firmware, fw_source) for one device."""
    scalars = scalars or {}
    sys_descr = sys_descr or ""
    columns = columns or {}
    rule = _RULES.get(arc)
    info = rule(sys_descr, scalars) if rule else SwInfo()
    if not info.version and arc in nodeoids.SW_VERSION_COLUMNS:
        info = _column_first(arc)(columns)
    if not info.version:
        ent = _text(scalars.get(ENT_SOFTWARE_REV))
        if ent:
            info = SwInfo(version=ent, image=info.image, image_file=info.image_file,
                          source="entPhysicalSoftwareRev")
    if not info.version:
        generic = _search(_GENERIC, sys_descr)
        if generic:
            info = SwInfo(version=generic, image=info.image,
                          image_file=info.image_file, source="sysDescr")
    return _fill_firmware(arc, info, scalars, columns)

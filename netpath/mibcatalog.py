"""A curated catalog of vendor MIB bundles that can be fetched on demand.

Why a catalog and not "ship every MIB there is": the obvious answer to "can
you include all of cisco/cisco-mibs?" is no, and for reasons worth writing
down. That repository is 2,921 MIB files and roughly 350 MB of text, with no
license file of its own; `mib_files` stores each file's full text in SQLite
and `all_known_oids()` loads every resolved object into a dict on each
resolve, so bundling it would multiply this app's database size by two orders
of magnitude to give an operator ten MIBs they actually poll. Worse, it would
do so silently at install time, on a box that may have no internet access and
no say in the matter.

So: the standard IETF MIBs every device answers are *bundled* (netpath/mibs/,
seeded on first start), and everything vendor-specific lives here as a named
bundle an admin picks and installs deliberately. The catalog is static data —
no network access to read it, so the list below is the "list to choose from"
even on an air-gapped install; only pressing Install reaches out.

Each bundle names its upstream explicitly. Nothing is mirrored or
redistributed by this project: the files are fetched at install time from the
vendor's or the distribution's own public repository, and an operator who
would rather not fetch anything can download the same files by hand and use
the ordinary MIB upload (which accepts a zip).
"""

from __future__ import annotations

import io
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field

# Cisco publishes its own MIBs; everything else comes from LibreNMS's
# aggregated vendor tree, which is where these files are practically
# obtainable in one consistent layout.
_CISCO = "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/"
_LIBRE = "https://raw.githubusercontent.com/librenms/librenms/master/mibs/"

# A browser pretending to be a browser gets rate-limited less predictably than
# one that says what it is; raw.githubusercontent serves either.
USER_AGENT = "SappiWhere-MIB-catalog/1.0 (+https://github.com/)"


@dataclass
class Bundle:
    key: str
    vendor: str
    name: str
    description: str
    source: str                       # human-readable upstream, shown in the UI
    files: list[tuple[str, str]] = field(default_factory=list)   # (filename, url)

    @property
    def file_count(self) -> int:
        return len(self.files)


def _cisco(*names: str) -> list[tuple[str, str]]:
    return [(f"{n}.my", f"{_CISCO}{n}.my") for n in names]


def _libre(vendor_dir: str, *names: str) -> list[tuple[str, str]]:
    # LibreNMS stores MIBs without an extension; ".mib" is added locally so the
    # stored filename looks like every other MIB in the list.
    return [(f"{n}.mib", f"{_LIBRE}{vendor_dir}/{n}") for n in names]


CATALOG: list[Bundle] = [
    Bundle(
        key="cisco-core",
        vendor="Cisco",
        name="Cisco IOS / IOS-XE core",
        description="CPU, memory, environment sensors, FRU/entity, CDP, VTP, "
                    "VLAN membership, stack, PoE and interface extensions — "
                    "the objects an IOS or IOS-XE switch or router actually "
                    "answers day to day.",
        source="cisco/cisco-mibs (v2)",
        files=_cisco(
            "CISCO-SMI", "CISCO-TC", "CISCO-PRODUCTS-MIB",
            "CISCO-PROCESS-MIB", "CISCO-MEMORY-POOL-MIB",
            "CISCO-ENHANCED-MEMPOOL-MIB", "CISCO-ENVMON-MIB",
            "CISCO-ENTITY-SENSOR-MIB", "CISCO-ENTITY-FRU-CONTROL-MIB",
            "CISCO-ENTITY-VENDORTYPE-OID-MIB", "CISCO-CDP-MIB",
            "CISCO-VTP-MIB", "CISCO-VLAN-MEMBERSHIP-MIB", "CISCO-STACK-MIB",
            "CISCO-IF-EXTENSION-MIB", "CISCO-POWER-ETHERNET-EXT-MIB",
            "CISCO-LAG-MIB", "CISCO-CONFIG-MAN-MIB", "CISCO-FLASH-MIB",
            "CISCO-IMAGE-MIB", "CISCO-SYSLOG-MIB", "OLD-CISCO-CHASSIS-MIB",
        ),
    ),
    Bundle(
        key="cisco-wireless",
        vendor="Cisco",
        name="Cisco wireless (LWAPP / AireOS)",
        description="Access points, radios, WLANs and mobility on a Cisco "
                    "wireless LAN controller, plus the AireOS objects an "
                    "older WLC answers.",
        source="cisco/cisco-mibs (v2) and librenms/librenms",
        files=_cisco(
            "CISCO-LWAPP-TC-MIB", "CISCO-LWAPP-AP-MIB", "CISCO-LWAPP-DOT11-MIB",
            "CISCO-LWAPP-WLAN-MIB", "CISCO-LWAPP-MOBILITY-MIB",
            "CISCO-LWAPP-SYS-MIB",
        ) + _libre("cisco", "AIRESPACE-REF-MIB", "AIRESPACE-WIRELESS-MIB",
                   "AIRESPACE-SWITCHING-MIB"),
    ),
    Bundle(
        key="fortinet",
        vendor="Fortinet",
        name="Fortinet FortiGate / FortiAP / FortiSwitch",
        description="The full FORTINET-FORTIGATE-MIB the Wireless module "
                    "already polls by numeric OID, so AP, radio and session "
                    "objects show their real names and enumerations — plus "
                    "FortiSwitch, FortiManager and FortiAuthenticator.",
        source="librenms/librenms (mibs/fortinet)",
        files=_libre(
            "fortinet", "FORTINET-CORE-MIB", "FORTINET-FORTIGATE-MIB",
            "FORTINET-FORTIAP-MIB", "FORTINET-FORTISWITCH-MIB",
            "FORTINET-FORTIMANAGER-FORTIANALYZER-MIB",
            "FORTINET-FORTIAUTHENTICATOR-MIB",
        ),
    ),
    Bundle(
        key="juniper",
        vendor="Juniper",
        name="Juniper JUNOS",
        description="The Juniper enterprise tree, chassis and routing "
                    "objects for JUNOS devices.",
        source="librenms/librenms (mibs/juniper)",
        files=_libre(
            "juniper", "JUNIPER-SMI", "Juniper-TC", "Juniper-MIBs",
            "JUNIPER-MIB", "Juniper-ROUTER-MIB", "Juniper-UNI-SMI",
            "Juniper-IP-POLICY-MIB",
        ),
    ),
    Bundle(
        key="aruba-wireless",
        vendor="Aruba / HPE",
        name="Aruba ArubaOS wireless",
        description="ArubaOS controllers and access points: WLANs, radios, "
                    "associated users, monitored stations and switch health.",
        source="librenms/librenms (mibs/arubaos)",
        files=_libre(
            "arubaos", "ARUBA-TC", "ARUBA-MIB", "ARUBA-MGMT-MIB", "AI-AP-MIB",
            "WLSX-SWITCH-MIB", "WLSX-SYSTEMEXT-MIB", "WLSX-WLAN-MIB",
            "WLSX-USER-MIB", "WLSX-MON-MIB", "WLSX-STATS-MIB", "WLSX-IFEXT-MIB",
            "WLSR-AP-MIB", "WLSX-TRAP-MIB",
        ),
    ),
    Bundle(
        key="aruba-cx",
        vendor="Aruba / HPE",
        name="Aruba CX switches",
        description="AOS-CX chassis, modules, fans, power supplies, "
                    "temperature sensors, PoE and VSF/VSX stacking.",
        source="librenms/librenms (mibs/arubaos-cx)",
        files=_libre(
            "arubaos-cx", "ARUBAWIRED-NETWORKING-OID", "ARUBAWIRED-CHASSIS-MIB",
            "ARUBAWIRED-MODULE-MIB", "ARUBAWIRED-FAN-MIB",
            "ARUBAWIRED-FANTRAY-MIB", "ARUBAWIRED-POWERSUPPLY-MIB",
            "ARUBAWIRED-TEMPSENSOR-MIB", "ARUBAWIRED-POE-MIB",
            "ARUBAWIRED-INTERFACE-MIB", "ARUBAWIRED-SYSTEMINFO-MIB",
            "ARUBAWIRED-VSF-MIB", "ARUBAWIRED-VSX-MIB",
        ),
    ),
    Bundle(
        key="hp-procurve",
        vendor="HP / HPE",
        name="HP ProCurve / Aruba switches (ICF)",
        description="The HP ICF tree used by ProCurve and older Aruba wired "
                    "switches: chassis, PoE, transceivers, CPU and memory.",
        source="librenms/librenms (mibs/hp)",
        files=_libre(
            "hp", "HP-ICF-OID", "HP-ICF-TC", "HP-ICF-BASIC", "HP-ICF-CHASSIS",
            "HP-ICF-BRIDGE", "HP-ICF-POE-MIB", "HP-ICF-TRANSCEIVER-MIB",
            "HP-ENTITY-MIB", "HP-MEMPROC-MIB", "NETSWITCH-MIB", "STATISTICS-MIB",
            "CONFIG-MIB", "FAN-MIB", "SEMI-MIB",
        ),
    ),
    Bundle(
        key="arista",
        vendor="Arista",
        name="Arista EOS",
        description="Arista's enterprise tree, entity sensors and interface "
                    "extensions for EOS switches.",
        source="librenms/librenms (mibs/arista)",
        files=_libre(
            "arista", "ARISTA-SMI-MIB", "ARISTA-GENERAL-MIB",
            "ARISTA-ENTITY-SENSOR-MIB", "ARISTA-IF-MIB", "ARISTA-VRF-MIB",
        ),
    ),
    Bundle(
        key="mikrotik",
        vendor="MikroTik",
        name="MikroTik RouterOS",
        description="RouterOS health, wireless and storage objects.",
        source="librenms/librenms (mibs/mikrotik)",
        files=_libre("mikrotik", "MIKROTIK-MIB"),
    ),
    Bundle(
        key="ubiquiti",
        vendor="Ubiquiti",
        name="Ubiquiti UniFi / EdgeMAX / airMAX",
        description="UniFi access points, EdgeRouter/EdgeSwitch and airMAX "
                    "and airFiber radios.",
        source="librenms/librenms (mibs/ubnt)",
        files=_libre(
            "ubnt", "UBNT-MIB", "UBNT-UniFi-MIB", "UBNT-EdgeMAX-MIB",
            "UBNT-AirMAX-MIB", "UBNT-AirFIBER-MIB", "UBNT-UFIBER-MIB",
            "UBNT-AFLTU-MIB", "UI-AF60-MIB",
        ),
    ),
    Bundle(
        key="extreme",
        vendor="Extreme Networks",
        name="Extreme EXOS",
        description="EXOS system health, ports, FDB, VLANs, PoE and stacking.",
        source="librenms/librenms (mibs/extreme)",
        files=_libre(
            "extreme", "EXTREME-BASE-MIB", "EXTREME-SYSTEM-MIB",
            "EXTREME-PORT-MIB", "EXTREME-FDB-MIB", "EXTREME-VLAN-MIB",
            "EXTREME-POE-MIB", "EXTREME-SOFTWARE-MONITOR-MIB",
            "EXTREME-STACKING-MIB", "EXTREME-ENTITY-MIB",
        ),
    ),
    Bundle(
        key="dell-networking",
        vendor="Dell",
        name="Dell Networking / OS10",
        description="Dell Networking (Force10) chassis, system components and "
                    "interface extensions.",
        source="librenms/librenms (mibs/dell)",
        files=_libre(
            "dell", "DELL-NETWORKING-SMI", "DELL-NETWORKING-TC",
            "DELL-NETWORKING-PRODUCTS-MIB", "DELL-NETWORKING-CHASSIS-MIB",
            "DELL-NETWORKING-SYSTEM-COMPONENT-MIB",
            "DELL-NETWORKING-IF-EXTENSION-MIB",
            "DELL-NETWORKING-LINK-AGGREGATION-MIB",
        ),
    ),
    Bundle(
        key="netgear",
        vendor="NETGEAR",
        name="NETGEAR smart switches",
        description="NETGEAR's smart-switching tree, including box services "
                    "(fans, temperature, power).",
        source="librenms/librenms (mibs/netgear)",
        files=_libre(
            "netgear", "NETGEAR-REF-MIB", "NETGEAR-SMART-SWITCHING-MIB",
            "NETGEAR-SWITCHING-MIB", "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        ),
    ),
    Bundle(
        key="sonicwall",
        vendor="SonicWall",
        name="SonicWall firewalls",
        description="SonicOS firewall statistics and SSL-VPN objects.",
        source="librenms/librenms (mibs/sonicwall)",
        files=_libre(
            "sonicwall", "SONICWALL-SMI", "SNWL-COMMON-MIB",
            "SONICWALL-FIREWALL-IP-STATISTICS-MIB", "SNWL-SSLVPN-MIB",
        ),
    ),
    Bundle(
        key="apc-ups",
        vendor="APC / Schneider",
        name="APC PowerNet (UPS and rack PDU)",
        description="APC's PowerNet MIB: UPS battery, load, runtime and rack "
                    "PDU outlets.",
        source="librenms/librenms (mibs/apc)",
        files=_libre("apc", "PowerNet-MIB"),
    ),
    Bundle(
        key="synology",
        vendor="Synology",
        name="Synology NAS",
        description="Synology system health, disks and RAID volumes.",
        source="librenms/librenms (mibs/synology)",
        files=_libre(
            "synology", "SYNOLOGY-SYSTEM-MIB", "SYNOLOGY-DISK-MIB",
            "SYNOLOGY-RAID-MIB",
        ),
    ),
    Bundle(
        key="vmware",
        vendor="VMware",
        name="VMware ESXi",
        description="ESXi host resources, environment sensors and guest "
                    "inventory.",
        source="librenms/librenms (mibs/vmware)",
        files=_libre(
            "vmware", "VMWARE-ROOT-MIB", "VMWARE-TC-MIB", "VMWARE-PRODUCTS-MIB",
            "VMWARE-SYSTEM-MIB", "VMWARE-RESOURCES-MIB", "VMWARE-ENV-MIB",
            "VMWARE-VMINFO-MIB",
        ),
    ),
    Bundle(
        key="paloalto",
        vendor="Palo Alto Networks",
        name="Palo Alto PAN-OS",
        description="PAN-OS firewalls and Panorama: system state, sessions, "
                    "chassis entities and the trap definitions.",
        source="librenms/librenms (mibs/paloaltonetworks)",
        files=_libre(
            "paloaltonetworks", "PAN-GLOBAL-REG", "PAN-GLOBAL-TC",
            "PAN-COMMON-MIB", "PAN-PRODUCTS-MIB", "PAN-ENTITY-EXT-MIB",
            "PAN-LC-MIB", "PAN-TRAPS",
        ),
    ),
    Bundle(
        key="checkpoint",
        vendor="Check Point",
        name="Check Point firewalls",
        description="Check Point's enterprise tree: firewall, VPN, cluster "
                    "and appliance health objects.",
        source="librenms/librenms (mibs/checkpoint)",
        files=_libre("checkpoint", "CHECKPOINT-MIB"),
    ),
    Bundle(
        key="watchguard",
        vendor="WatchGuard",
        name="WatchGuard Firebox",
        description="Firebox system statistics, policies, high availability "
                    "and IPsec tunnels.",
        source="librenms/librenms (mibs/watchguard)",
        files=_libre(
            "watchguard", "WATCHGUARD-SMI", "WATCHGUARD-MIB",
            "WATCHGUARD-PRODUCTS-MIB", "WATCHGUARD-INFO-SYSTEM-MIB",
            "WATCHGUARD-SYSTEM-CONFIG-MIB", "WATCHGUARD-SYSTEM-STATISTICS-MIB",
            "WATCHGUARD-POLICY-MIB", "WATCHGUARD-HA-MIB",
            "WATCHGUARD-IPSEC-TUNNEL-MIB", "WATCHGUARD-CLIENT-MIB",
        ),
    ),
    Bundle(
        key="sophos",
        vendor="Sophos",
        name="Sophos XG / SFOS firewalls",
        description="SFOS firewall system health, licensing and service "
                    "status.",
        source="librenms/librenms (mibs/sophos)",
        files=_libre("sophos", "SFOS-FIREWALL-MIB"),
    ),
    Bundle(
        key="f5",
        vendor="F5",
        name="F5 BIG-IP",
        description="BIG-IP system, local traffic (virtual servers, pools, "
                    "nodes), platform statistics and APM.",
        source="librenms/librenms (mibs/f5)",
        files=_libre(
            "f5", "F5-COMMON-SMI-MIB", "F5-BIGIP-COMMON-MIB",
            "F5-BIGIP-SYSTEM-MIB", "F5-BIGIP-LOCAL-MIB",
            "F5-BIGIP-GLOBAL-MIB", "F5-PLATFORM-STATS-MIB",
            "F5-BIGIP-APM-MIB",
        ),
    ),
    Bundle(
        key="citrix",
        vendor="Citrix",
        name="Citrix NetScaler / ADC",
        description="NetScaler ADC virtual servers, services and system "
                    "counters, plus SD-WAN.",
        source="librenms/librenms (mibs/citrix)",
        files=_libre(
            "citrix", "NS-ROOT-MIB", "CITRIX-NetScaler-SD-WAN-MIB",
        ),
    ),
    Bundle(
        key="ruckus",
        vendor="Ruckus / CommScope",
        name="Ruckus wireless (ZoneDirector, SmartZone, Unleashed)",
        description="Ruckus controllers and access points across all three "
                    "platforms: APs, WLANs, system health and events.",
        source="librenms/librenms (mibs/ruckus)",
        files=_libre(
            "ruckus", "RUCKUS-ROOT-MIB", "RUCKUS-TC-MIB", "RUCKUS-PRODUCTS-MIB",
            "RUCKUS-SYSTEM-MIB", "RUCKUS-DEVICE-MIB", "RUCKUS-HWINFO-MIB",
            "RUCKUS-SWINFO-MIB", "RUCKUS-ZD-SYSTEM-MIB", "RUCKUS-ZD-AP-MIB",
            "RUCKUS-ZD-WLAN-MIB", "RUCKUS-SZ-SYSTEM-MIB", "RUCKUS-SZ-WLAN-MIB",
            "RUCKUS-UNLEASHED-SYSTEM-MIB", "RUCKUS-UNLEASHED-WLAN-MIB",
        ),
    ),
    Bundle(
        key="cambium",
        vendor="Cambium Networks",
        name="Cambium PMP / PTP / cnPilot",
        description="Point-to-multipoint access points and subscriber "
                    "modules, PTP backhaul links and cnMatrix switches.",
        source="librenms/librenms (mibs/cambium)",
        files=_libre(
            "cambium", "WHISP-GLOBAL-REG-MIB", "WHISP-TCV2-MIB",
            "WHISP-BOX-MIBV2-MIB", "WHISP-APS-MIB", "WHISP-SM-MIB",
            "CAMBIUM-PTP650-MIB", "CAMBIUM-PTP670-MIB",
            "CAMBIUM-PMP80211-MIB",
        ),
    ),
    Bundle(
        key="aerohive",
        vendor="Aerohive / Extreme",
        name="Aerohive HiveOS access points",
        description="HiveOS access point system, interface and mesh "
                    "objects.",
        source="librenms/librenms (mibs/aerohive)",
        files=_libre(
            "aerohive", "AH-SMI-MIB", "AH-SYSTEM-MIB", "AH-INTERFACE-MIB",
            "AH-MRP-MIB",
        ),
    ),
    Bundle(
        key="zyxel",
        vendor="Zyxel",
        name="Zyxel switches and firewalls",
        description="Zyxel managed switches (hardware monitor, stacking, "
                    "transceivers) and ZyWALL / USG firewalls.",
        source="librenms/librenms (mibs/zyxel)",
        files=_libre(
            "zyxel", "ZYXEL-MIB", "ZYXEL-ES-SMI", "ZYXEL-ES-COMMON",
            "ZYXEL-HW-MONITOR-MIB", "ZYXEL-STACKING-MIB",
            "ZYXEL-TRANSCEIVER-MIB", "ZYXEL-ZYWALL-MIB",
            "ZYXEL-ZYWALL-ZLD-COMMON-MIB",
        ),
    ),
    Bundle(
        key="tplink",
        vendor="TP-Link",
        name="TP-Link JetStream switches",
        description="System information and monitoring, PoE, VLANs, LLDP "
                    "and DDM transceiver diagnostics.",
        source="librenms/librenms (mibs/tplink)",
        files=_libre(
            "tplink", "TPLINK-MIB", "TPLINK-TC-MIB", "TPLINK-PRODUCTS-MIB",
            "TPLINK-SYSINFO-MIB", "TPLINK-SYSMONITOR-MIB",
            "TPLINK-POWER-OVER-ETHERNET-MIB", "TPLINK-DOT1Q-VLAN-MIB",
            "TPLINK-LLDP-MIB", "TPLINK-LLDPINFO-MIB", "TPLINK-DDMSTATUS-MIB",
            "TPLINK-DDMMANAGE-MIB",
        ),
    ),
    Bundle(
        key="eaton",
        vendor="Eaton",
        name="Eaton UPS and rack PDU",
        description="Eaton and MGE UPS battery, load and alarm objects, "
                    "managed ePDU outlets and environmental sensors.",
        source="librenms/librenms (mibs/eaton)",
        files=_libre(
            "eaton", "EATON-OIDS", "XUPS-MIB", "MG-SNMP-UPS-MIB",
            "EATON-EPDU-MIB", "EATON-EMP-MIB", "EATON-SENSOR-MIB",
            "EATON-ATS2-MIB",
        ),
    ),
    Bundle(
        key="liebert",
        vendor="Vertiv / Liebert",
        name="Vertiv Liebert UPS and cooling",
        description="Liebert GP agent objects: UPS power, PDU, environmental "
                    "(CRAC/cooling) readings and condition alarms.",
        source="librenms/librenms (mibs/liebert)",
        files=_libre(
            "liebert", "LIEBERT-GP-REGISTRATION-MIB", "LIEBERT-GP-AGENT-MIB",
            "LIEBERT-GP-SYSTEM-MIB", "LIEBERT-GP-POWER-MIB",
            "LIEBERT-GP-PDU-MIB", "LIEBERT-GP-ENVIRONMENTAL-MIB",
            "LIEBERT-GP-CONDITIONS-MIB", "LIEBERT-GP-NOTIFICATIONS-MIB",
        ),
    ),
    Bundle(
        key="raritan",
        vendor="Raritan / Legrand",
        name="Raritan PX rack PDU",
        description="Raritan PDU inlets, outlets, sensors and the KVM "
                    "device MIB.",
        source="librenms/librenms (mibs/raritan)",
        files=_libre(
            "raritan", "PDU-MIB", "PDU2-MIB", "RemoteKVMDevice-MIB",
        ),
    ),
    Bundle(
        key="rittal",
        vendor="Rittal",
        name="Rittal CMC III",
        description="CMC III rack monitoring: temperature, humidity, access "
                    "and power sensors.",
        source="librenms/librenms (mibs/rittal)",
        files=_libre(
            "rittal", "RITTAL-SMI-MIB", "RITTAL-CMC-III-MIB",
            "RITTAL-CMC-III-PRODUCTS-MIB", "RITTAL-CMC-TC-MIB",
        ),
    ),
]

BUNDLES = {bundle.key: bundle for bundle in CATALOG}


def bundle(key: str) -> Bundle | None:
    return BUNDLES.get(key)


# --------------------------------------------------------------- downloading

class DownloadError(RuntimeError):
    """A fetch failed for a reason worth showing an operator verbatim."""


def fetch_file(url: str, timeout_s: float, max_bytes: int) -> str:
    """One MIB over HTTPS, capped and decoded.

    Reads one byte past the cap so an oversized file is refused rather than
    silently truncated into a MIB that parses to nonsense.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        raise DownloadError(f"{url} returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise DownloadError(
            f"Could not reach {url}: {error.reason}. This server needs "
            f"outbound HTTPS to install a MIB bundle — on a closed network, "
            f"download the files by hand and use Upload MIB instead."
        ) from error
    except OSError as error:
        raise DownloadError(f"Could not reach {url}: {error}") from error
    if len(raw) > max_bytes:
        raise DownloadError(f"{url} exceeds the {max_bytes:,} byte per-file limit")
    if not raw.strip():
        raise DownloadError(f"{url} returned an empty file")
    return raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


# ------------------------------------------------------------- zip unpacking

MIB_SUFFIXES = (".mib", ".my", ".txt", ".smi")


def looks_like_zip(raw: bytes) -> bool:
    return raw[:2] == b"PK"


def unpack_zip(raw: bytes, max_files: int, max_file_bytes: int,
               max_total_bytes: int) -> list[tuple[str, str]]:
    """Every MIB-looking member of a zip, as (filename, text).

    Directory entries, nested paths and anything that is not a MIB extension
    are skipped rather than refused: vendors ship their MIBs inside a folder
    with a readme and a couple of PDFs, and rejecting the whole archive over
    those would be useless. The caps are enforced against the *declared*
    uncompressed size before anything is read, so a zip bomb is refused
    without being expanded.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as error:
        raise ValueError(f"Not a readable zip file: {error}") from error

    members = [info for info in archive.infolist()
               if not info.is_dir()
               and info.filename.lower().endswith(MIB_SUFFIXES)]
    if not members:
        raise ValueError("The zip contains no .mib/.my/.txt/.smi files")
    if len(members) > max_files:
        raise ValueError(f"The zip contains {len(members)} MIB files; "
                         f"the limit is {max_files}")
    declared = sum(info.file_size for info in members)
    if declared > max_total_bytes:
        raise ValueError(f"The zip expands to {declared:,} bytes; "
                         f"the limit is {max_total_bytes:,}")

    out: list[tuple[str, str]] = []
    for info in members:
        if info.file_size > max_file_bytes:
            raise ValueError(f"{info.filename} is {info.file_size:,} bytes; "
                             f"the per-file limit is {max_file_bytes:,}")
        with archive.open(info) as handle:
            data = handle.read(max_file_bytes + 1)
        if len(data) > max_file_bytes:
            raise ValueError(f"{info.filename} is larger than it declared")
        # Flatten: a MIB's identity is its module name, not its folder.
        name = info.filename.rsplit("/", 1)[-1]
        out.append((name, data.decode("utf-8", "replace")
                    .replace("\r\n", "\n").replace("\r", "\n")))
    return out


# ----------------------------------------------------------------- install job

class InstallJob:
    """One bundle install, run on a thread so the browser can poll it.

    Shaped like the discovery jobs in nodediscover.py — a plain object the API
    reads fields off, with no locking beyond the GIL, because every field is a
    single assignment and the UI only ever reads.
    """

    def __init__(self, key: str, total: int):
        self.key = key
        self.state = "running"          # running | done | error
        self.total = total
        self.completed = 0
        self.current = ""
        self.error = ""
        self.installed: list[str] = []
        self.skipped: list[str] = []
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.resolved_count = 0
        self.object_count = 0

    def json(self) -> dict:
        return {"key": self.key, "state": self.state, "total": self.total,
                "completed": self.completed, "current": self.current,
                "error": self.error, "installed": self.installed,
                "skipped": self.skipped, "started_ts": self.started_ts,
                "finished_ts": self.finished_ts,
                "resolved_count": self.resolved_count,
                "object_count": self.object_count}

"""Port and protocol names, so charts read as applications rather than numbers.

Three sources, in order: names the site has declared, a small curated table for
the ones worth presenting nicely, and the operating system's own services file
for everything else registered with IANA.
"""

from __future__ import annotations

import socket

PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
    132: "SCTP",
}

PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 502: "Modbus", 514: "Syslog", 515: "LPD",
    520: "RIP", 546: "DHCPv6", 547: "DHCPv6", 587: "SMTP-sub", 623: "IPMI",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1645: "RADIUS", 1646: "RADIUS", 1701: "L2TP", 1723: "PPTP",
    1812: "RADIUS", 1813: "RADIUS", 1883: "MQTT", 2049: "NFS", 2055: "NetFlow",
    2222: "EtherNet/IP", 3128: "Squid", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 4500: "IPsec-NAT", 5060: "SIP",
    5061: "SIPS", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-S", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt", 9100: "JetDirect", 9200: "Elasticsearch",
    27017: "MongoDB", 44818: "EtherNet/IP",

    # Infrastructure and management
    49: "TACACS+", 102: "ISO-TSAP", 113: "ident", 177: "XDMCP", 264: "BGMP",
    323: "PTP", 464: "kpasswd", 496: "PIM-RP-DISC", 512: "exec", 513: "login",
    543: "klogin", 544: "kshell", 548: "AFP", 554: "RTSP", 631: "IPP",
    646: "LDP", 830: "NETCONF", 831: "NETCONF-ssh", 873: "rsync",
    902: "VMware", 989: "FTPS-data", 990: "FTPS", 992: "Telnets",
    1080: "SOCKS", 1099: "Java-RMI", 1352: "Lotus", 1414: "MQ-Series",
    1521: "Oracle", 1547: "Laplink", 1604: "Citrix-ICA", 1701: "L2TP",
    1720: "H.323", 1755: "MMS", 1812: "RADIUS", 1985: "HSRP",
    2000: "SCCP", 2002: "Cisco-globe", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
    2404: "IEC-104", 2598: "Citrix-CGP", 3128: "Squid", 3260: "iSCSI",
    3269: "LDAPS-GC", 3299: "SAP-router", 3478: "STUN", 3479: "STUN",
    3690: "Subversion", 3784: "BFD", 3785: "BFD-echo", 4369: "EPMD",
    4500: "IPsec-NAT", 4505: "Salt", 4506: "Salt", 4840: "OPC-UA",
    4949: "Munin", 5000: "UPnP", 5001: "commplex-link", 5007: "WSM-Server-SSL",
    5222: "XMPP", 5269: "XMPP-server", 5353: "mDNS", 5355: "LLMNR",
    5357: "WSDAPI", 5432: "PostgreSQL", 5555: "Freeciv", 5601: "Kibana",
    5672: "AMQP", 5671: "AMQPS", 5666: "NRPE", 5671: "AMQPS",
    5701: "Hazelcast", 5800: "VNC-http", 5901: "VNC-1", 5902: "VNC-2",
    5903: "VNC-3", 5938: "TeamViewer", 5984: "CouchDB", 6000: "X11",
    6001: "X11-1", 6081: "Geneve", 6443: "Kubernetes", 6514: "Syslog-TLS",
    6667: "IRC", 6697: "IRC-TLS", 8006: "Proxmox", 8009: "AJP",
    8086: "InfluxDB", 8140: "Puppet", 8161: "ActiveMQ", 8200: "Vault",
    8291: "MikroTik", 8333: "Bitcoin", 8500: "Consul", 8883: "MQTT-TLS",
    8888: "HTTP-alt", 9090: "Prometheus", 9092: "Kafka", 9300: "Elastic-node",
    9418: "Git", 9999: "abyss", 10000: "Webmin", 10050: "Zabbix-agent",
    10051: "Zabbix-server", 11211: "Memcached", 15672: "RabbitMQ-mgmt",
    16992: "Intel-AMT", 16993: "Intel-AMT-TLS", 20000: "DNP3",
    25565: "Minecraft", 26000: "Quake", 32768: "filenet-tms",
    34962: "PROFINET-RT", 34963: "PROFINET-RTM", 34964: "PROFINET-CM",
    47808: "BACnet", 51820: "WireGuard", 4789: "VXLAN", 1935: "RTMP",
    1194: "OpenVPN", 1723: "PPTP", 3391: "RDP-censor", 5061: "SIPS",
}


# Site-specific names, set from the NetFlow settings. Unregistered ports are
# unknowable from here — 22609 belongs to whatever the site runs on it — so
# they are declared rather than guessed at.
_CUSTOM_PORTS: dict[int, str] = {}

# Answers from the operating system's services file, which is the IANA registry
# shipped with the OS. Cached because it is consulted for every flow row.
_SYSTEM_PORTS: dict[int, str | None] = {}


def set_custom_ports(mapping: dict) -> None:
    global _CUSTOM_PORTS
    _CUSTOM_PORTS = {int(k): str(v) for k, v in mapping.items()}


def parse_custom_ports(text: str) -> dict[int, str]:
    """Read `22609 = NVR` lines, one per line, ignoring anything malformed."""
    mapping: dict[int, str] = {}
    for line in str(text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        left, name = line.split("=", 1)
        left = left.strip().split("/", 1)[0]      # tolerate "443/tcp"
        try:
            mapping[int(left)] = name.strip()
        except ValueError:
            continue
    return mapping


def _system_port_name(port: int) -> str | None:
    """Ask the OS services file, the same source `getent services` reads.

    On Windows that is %SystemRoot%\\System32\\drivers\\etc\\services, which
    carries the registered names well beyond the handful worth curating here.
    """
    if port in _SYSTEM_PORTS:
        return _SYSTEM_PORTS[port]
    name = None
    for proto in ("tcp", "udp"):
        try:
            name = socket.getservbyport(port, proto)
            break
        except (OSError, OverflowError, ValueError):
            continue
    if name:
        # The services file is lower case and terse; make it read like a name.
        name = name.replace("_", "-")
        if name.isalpha() and len(name) <= 5:
            name = name.upper()
    _SYSTEM_PORTS[port] = name
    return name


def protocol_name(number: int) -> str:
    return PROTOCOLS.get(int(number or 0), f"proto {int(number or 0)}")


def port_name(port: int, resolve: bool = True) -> str:
    port = int(port or 0)
    if not resolve:
        return str(port)
    name = _CUSTOM_PORTS.get(port) or PORTS.get(port) or _system_port_name(port)
    return f"{name} ({port})" if name else str(port)


def format_bytes(value: float) -> str:
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value:.0f} B"
        value /= 1024
    return f"{value:.1f} TB"


def format_rate(bytes_total: float, seconds: float) -> str:
    if seconds <= 0:
        return "0 bps"
    bits = float(bytes_total or 0) * 8 / seconds
    for unit in ("bps", "Kbps", "Mbps", "Gbps", "Tbps"):
        if bits < 1000 or unit == "Tbps":
            return f"{bits:.1f} {unit}"
        bits /= 1000
    return f"{bits:.1f} Tbps"


def format_packets(value: float) -> str:
    value = float(value or 0)
    for suffix in ("", "K", "M", "G"):
        if value < 1000 or suffix == "G":
            return f"{value:.0f}{suffix}"
        value /= 1000
    return f"{value:.0f}G"

"""Subnet discovery: a ping sweep, then a look at the local ARP table.

Two separate facts come out of a scan. Whether an address answers ICMP says
whether something is there at all — routed reachability, works across a
router hop like anything else NetPath probes. Whether the ARP table has a MAC
for that address says who is actually holding it right now — and ARP is
strictly a same-broadcast-domain protocol, so this half only sees addresses
on the same Ethernet segment as whichever machine is running SappiWhere.
Sweeping a remote subnet still tells you which addresses are alive; it will
not tell you their MACs, and so it cannot catch a conflict on that subnet.
That is a property of ARP, not a limitation of this code, and there is no way
around it short of asking a router for its own ARP table over SNMP, which is
future work rather than something this module does.

The sweep pings every address first and reads the table after, rather than
interleaving the two: a burst of ICMP populates the local ARP cache for
whatever answers, and reading once at the end is one command instead of one
per address.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from .procs import hidden

IS_WINDOWS = os.name == "nt"

_WIN_ARP_LINE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+\S+")
_LINUX_NEIGH_LINE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\blladdr\s+([0-9A-Fa-f:]{17})")
_BSD_ARP_LINE = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:]{1,2}(?::[0-9A-Fa-f]{1,2}){5})")


class SubnetTooLarge(ValueError):
    """Refused rather than swept, to protect against a fat-fingered range."""


def subnet_size(cidr: str) -> int:
    """Usable host addresses in the subnet, without materializing the list —
    for anything that only needs the count, such as a utilization figure.

    Matches usable_addresses() exactly, including its /31 and /32 handling:
    both return a single address rather than the two a strict RFC 3021
    reading of a /31 would give, since that is what a real sweep actually
    probes. A count that disagreed with the list it is meant to describe
    would make the pie chart's total wrong for exactly the subnets small
    enough that being off by one is most visible.
    """
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    if net.version != 4:
        raise ValueError("only IPv4 subnets are supported")
    count = net.num_addresses
    return 1 if count <= 2 else count - 2


def usable_addresses(cidr: str, max_addresses: int) -> list[str]:
    """Every host address in the subnet, smallest network first.

    Raises SubnetTooLarge before anything is sent, rather than truncating the
    list quietly — a truncated sweep would report a subnet as clean when most
    of it was never actually probed.
    """
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    if net.version != 4:
        raise ValueError("only IPv4 subnets are supported")
    count = subnet_size(cidr)
    if count > max_addresses:
        raise SubnetTooLarge(
            f"{cidr} has {count} usable addresses, over the {max_addresses}"
            f" limit. Narrow the subnet, or raise the limit in IPAM settings"
            f" if you mean to sweep something this size.")
    if net.num_addresses <= 2:
        return [str(net.network_address)]           # /31 or /32
    return [str(ip) for ip in net.hosts()]


def normalize_mac(text: str | None) -> str | None:
    """Lower-case, colon-separated, zero-padded, or None.

    Windows prints dashes with each octet zero-padded (00-11-22-...); Linux
    and Windows print colons the same way; BSD's arp does not zero-pad a
    leading digit (0:11:22:... rather than 00:11:22:...), so each part has to
    be padded individually rather than just concatenating the digits.
    """
    if not text:
        return None
    parts = re.split(r"[:\-]", text.strip())
    if len(parts) == 1:
        # Cisco's dotted form, aabb.ccdd.eeff — three groups of four hex
        # digits with no octet boundaries to pad.
        parts = text.strip().split(".")
        if len(parts) != 3 or not all(re.fullmatch(r"[0-9A-Fa-f]{4}", p) for p in parts):
            return None
        digits = "".join(parts)
    else:
        if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
            return None
        digits = "".join(p.zfill(2) for p in parts)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def _ping_command(ip: str, timeout_ms: int) -> list[str]:
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]


def ping_once(ip: str, timeout_ms: int = 800) -> bool:
    try:
        completed = subprocess.run(
            _ping_command(ip, timeout_ms), capture_output=True, text=True,
            timeout=(timeout_ms / 1000) + 2, **hidden())
    except (subprocess.TimeoutExpired, OSError):
        return False
    return completed.returncode == 0


def ping_many(ip: str, count: int = 3,
              timeout_ms: int = 1000) -> tuple[int, int, float | None]:
    """(sent, received, average RTT in ms) for `count` echo probes.

    Sent one at a time rather than as a single `ping -c N`: Windows and the
    BSDs disagree on how to ask for a burst and on how they summarise it,
    and one probe per subprocess is the only form already known to work
    everywhere here. It costs a process per probe, which at a default of
    three probes per poll interval is not worth trading correctness for.

    The RTT comes from the ping output's own "time=" figure, parsed with
    tracer.py's existing regexes, not from wall-clock timing around the
    subprocess — that measured process spawn as latency and reported a
    sub-millisecond LAN device at 20 ms or worse. Returns None for the RTT
    when nothing came back.
    """
    from .tracer import _UNIX_PING_TIME, _WIN_PING_TIME

    pattern = _WIN_PING_TIME if IS_WINDOWS else _UNIX_PING_TIME
    count = max(1, int(count))
    received = 0
    rtts: list[float] = []
    for _ in range(count):
        try:
            completed = subprocess.run(
                _ping_command(ip, timeout_ms), capture_output=True, text=True,
                timeout=(timeout_ms / 1000) + 2, **hidden())
        except (subprocess.TimeoutExpired, OSError):
            continue
        if completed.returncode != 0:
            continue
        received += 1
        match = pattern.search((completed.stdout or "") + "\n" +
                               (completed.stderr or ""))
        if match:
            rtts.append(float(match.group(1)))
    return count, received, (sum(rtts) / len(rtts)) if rtts else None


def read_arp_table() -> dict[str, str]:
    """The local ARP/neighbor cache as {ip: mac}, best-effort.

    Only ever reflects addresses this host has itself recently exchanged
    frames with on its own segment — see the module docstring.
    """
    if IS_WINDOWS:
        command, parser = ["arp", "-a"], _parse_windows_arp
    elif shutil.which("ip"):
        command, parser = ["ip", "neigh"], _parse_linux_neigh
    elif shutil.which("arp"):
        command, parser = ["arp", "-an"], _parse_bsd_arp
    else:
        return {}
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=10, **hidden())
    except OSError:
        return {}
    return parser(completed.stdout or "")


def _parse_windows_arp(output: str) -> dict[str, str]:
    table = {}
    for line in output.splitlines():
        match = _WIN_ARP_LINE.match(line)
        if match:
            mac = normalize_mac(match.group(2))
            if mac:
                table[match.group(1)] = mac
    return table


def _parse_linux_neigh(output: str) -> dict[str, str]:
    table = {}
    for line in output.splitlines():
        if " FAILED" in line or " INCOMPLETE" in line:
            continue                    # no MAC learned, not a sighting
        match = _LINUX_NEIGH_LINE.match(line)
        if match:
            mac = normalize_mac(match.group(2))
            if mac:
                table[match.group(1)] = mac
    return table


def _parse_bsd_arp(output: str) -> dict[str, str]:
    table = {}
    for line in output.splitlines():
        if "incomplete" in line:
            continue
        match = _BSD_ARP_LINE.search(line)
        if match:
            mac = normalize_mac(match.group(2))
            if mac:
                table[match.group(1)] = mac
    return table


# Probes per second a sweep may put on the wire. 64 workers each launching
# a `ping` as fast as it finishes was, on a /24, a burst of hundreds of ICMP
# echo requests in well under a second — the traffic pattern that has
# knocked over legacy PLC and RTU stacks. 200/s still finishes a /24 in
# about a second and a quarter; the point is that it is a rate rather than
# "as fast as this machine can fork".
DEFAULT_PROBES_PER_SECOND = 200


def parse_never_scan(text) -> list:
    """The "never scan these" list, as networks. Accepts a comma- or
    whitespace-separated string (what a settings field holds) or a list.
    Anything unparseable is dropped rather than raised on: a typo in a
    safety list must not stop the application starting, and an entry that
    does not parse simply protects nothing."""
    if not text:
        return []
    parts = text if isinstance(text, (list, tuple)) else re.split(r"[,\s]+", str(text))
    networks = []
    for part in parts:
        part = str(part).strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return networks


def is_never_scanned(ip: str, networks) -> bool:
    if not networks:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def sweep(addresses: list[str], timeout_ms: int = 800, workers: int = 64,
          probes_per_second: float = DEFAULT_PROBES_PER_SECOND,
          never_scan=()) -> dict[str, bool]:
    """Ping every address, at most `probes_per_second` of them. Returns
    {ip: answered}.

    Addresses inside `never_scan` are never probed at all and come back
    False — "did not answer" is exactly what they are to every caller, and
    the alternative (omitting them) would make a bounded sweep silently
    report fewer addresses than it was asked about.

    Pacing is applied where the probe is *submitted*, not where it
    completes, so the rate is a rate on the wire rather than on the
    results. The pool still runs `workers` probes concurrently: a probe
    takes up to `timeout_ms`, so a single-threaded 200/s is not reachable
    at all with a 800 ms timeout.
    """
    results: dict[str, bool] = {}
    if not addresses:
        return results
    blocked = parse_never_scan(never_scan)
    interval = 1.0 / probes_per_second if probes_per_second and probes_per_second > 0 else 0.0

    to_probe = []
    for ip in addresses:
        if is_never_scanned(ip, blocked):
            results[ip] = False
        else:
            to_probe.append(ip)
    if not to_probe:
        return results

    def paced(index_ip):
        index, ip = index_ip
        if interval:
            # Absolute rather than a sleep per probe: a sleep between
            # submissions would add the probe's own latency to the gap and
            # halve the effective rate.
            due = started + index * interval
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        return ping_once(ip, timeout_ms)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for ip, alive in zip(to_probe, pool.map(paced, enumerate(to_probe))):
            results[ip] = alive
    return results


def scan_subnet(cidr: str, max_addresses: int, timeout_ms: int = 800,
                workers: int = 64,
                probes_per_second: float = DEFAULT_PROBES_PER_SECOND,
                never_scan=()) -> tuple[dict[str, bool], dict[str, str]]:
    """One full pass: ping every address, then read the ARP table once.

    Returns (alive, arp) — alive is every address probed, arp is whatever the
    local table now holds for addresses in this subnet (a superset of what
    just answered is fine; the caller only looks up addresses it asked about).
    """
    addresses = usable_addresses(cidr, max_addresses)
    alive = sweep(addresses, timeout_ms=timeout_ms, workers=workers,
                  probes_per_second=probes_per_second, never_scan=never_scan)
    arp = read_arp_table()
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    in_subnet = {ip: mac for ip, mac in arp.items()
                if ipaddress.ip_address(ip) in net}
    return alive, in_subnet

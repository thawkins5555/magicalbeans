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
import selectors
import shutil
import socket
import struct
import subprocess
import threading
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
    count = net.num_addresses
    if net.version == 6:
        # No network or broadcast address to subtract in IPv6 — every
        # address in the prefix is a host address (RFC 4291 §2.6.1's
        # subnet-router anycast is still a usable address to probe).
        return count
    return 1 if count <= 2 else count - 2


def usable_addresses(cidr: str, max_addresses: int) -> list[str]:
    """Every host address in the subnet, smallest network first.

    Raises SubnetTooLarge before anything is sent, rather than truncating the
    list quietly — a truncated sweep would report a subnet as clean when most
    of it was never actually probed.
    """
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    count = subnet_size(cidr)
    if count > max_addresses:
        # An IPv6 prefix reaches this long before an IPv4 one does — a /64
        # is 18 quintillion addresses — and the message is the right
        # answer for both: name a prefix small enough to actually sweep.
        raise SubnetTooLarge(
            f"{cidr} has {count} usable addresses, over the {max_addresses}"
            f" limit. Narrow the subnet, or raise the limit in IPAM settings"
            f" if you mean to sweep something this size.")
    if net.version == 6:
        return [str(ip) for ip in net]
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
    # Resolved through PATH rather than left as a bare "ping" for
    # subprocess.run to find on its own: on Windows, CreateProcess appends
    # only ".exe" to an extensionless name and never consults PATHEXT, so a
    # bare "ping" always lands on C:\WINDOWS\system32\ping.EXE regardless of
    # what sits earlier on PATH. tracer.py:436's _ping_command already does
    # this same shutil.which("ping") for the same reason; this one did not,
    # so the two callers of the same binary resolved it two different ways -
    # on Windows only one of them honoured PATH. That is not cosmetic: it is
    # what let ping_once()/ping_many() below (which is what nodepoll's
    # reachability check actually calls) reach C:\WINDOWS\system32\ping.EXE
    # instead of a PATH override such as the demo harness's ICMP substitute,
    # so a device the harness had taken "down" kept reading as "up" here.
    exe = shutil.which("ping") or "ping"
    if IS_WINDOWS:
        return [exe, "-n", "1", "-w", str(timeout_ms), ip]
    return [exe, "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]


# ---------------------------------------------------------- socket ICMP
#
# ping_once/ping_many used to be one `subprocess.run(["ping", ...])` per
# probe. At three probes per device per poll that is 3,000 fork/execs a
# poll cycle across 1,000 devices — measured at 88-134 process creations a
# second and a load average of 15 on four cores, almost none of it actual
# network work. A raw or unprivileged-datagram ICMP socket does the same
# probe without spawning anything: build the echo request by hand (the
# checksum is the one part the kernel will not do for you), send it, and
# wait for the matching reply with select() against a deadline — the same
# shape as the subprocess path had, minus the process.
#
# NETPATH_PING_MODE picks the implementation:
#   unset / "auto"  — use a socket if one can be opened here, else the old
#                     subprocess path. Detected once per process, not once
#                     per probe (see _icmp_socket_kind).
#   "socket"        — demand the fast path; raise instead of silently
#                     falling back, so a deployment can confirm it landed.
#   "subprocess"    — always fork/exec `ping`, exactly as before. This is
#                     the demo harness's override: demo/bin/ping is a
#                     scripted stand-in on PATH that makes a simulated
#                     device (a plain loopback address — 127.0.0.x) look
#                     "down" by refusing to answer, per its own docstring.
#                     A real ICMP socket does not go through PATH at all;
#                     it would reach that loopback address directly, and
#                     the kernel always answers a loopback echo whether or
#                     not the fleet has taken the simulated device down,
#                     silently defeating the demo's failure scenarios.
#                     demo/ is off limits to this change, so this is the
#                     one place that can say it: demo/scenario.py's
#                     start_app() needs one more line —
#                     env["NETPATH_PING_MODE"] = "subprocess" — beside
#                     where it already sets PATH to demo/bin, to keep that
#                     guarantee on every host the demo runs on.
_PING_MODE_ENV = "NETPATH_PING_MODE"

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0

_icmp_kind_lock = threading.Lock()
_icmp_kind_cache = "unchecked"          # -> "dgram", "raw", or None


def _icmp_checksum(data: bytes) -> int:
    """The RFC 1071 Internet checksum — the same algorithm ping(8) itself
    computes over the ICMP header and payload. Nothing on this host
    validates an outgoing packet's checksum, so a wrong one here would not
    raise; it would just make every probe fail as 100% loss on the wire,
    the same as talking to a dead host."""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_echo_request(identifier: int, sequence: int, token: bytes) -> bytes:
    """One ICMP echo request, header checksum included. `token` rides
    along in the payload and is expected back verbatim in the reply — a
    second, cheap check alongside id/sequence that a reply actually
    answers this probe rather than being a stale or unrelated packet (a
    raw socket sees every ICMP packet the host receives, not just replies
    to its own probes)."""
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    checksum = _icmp_checksum(header + token)
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, checksum, identifier, sequence)
    return header + token


def _parse_icmp_reply(packet: bytes, has_ip_header: bool):
    """(type, code, identifier, sequence, payload) off the wire, or None
    if `packet` is too short to be a real one. A SOCK_RAW socket hands
    back the IP header along with the ICMP payload; SOCK_DGRAM's
    unprivileged ping socket has already stripped it, the same as any
    other UDP-shaped read."""
    if has_ip_header:
        if len(packet) < 20:
            return None
        packet = packet[(packet[0] & 0x0F) * 4:]
    if len(packet) < 8:
        return None
    icmp_type, code, _checksum, identifier, sequence = struct.unpack("!BBHHH", packet[:8])
    return icmp_type, code, identifier, sequence, packet[8:]


def _is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def _detect_icmp_socket_kind() -> str | None:
    """"dgram", "raw", or None — probed once, not once per call.

    SOCK_DGRAM + IPPROTO_ICMP is Linux's unprivileged "ping socket": the
    kernel only opens it for a uid inside
    /proc/sys/net/ipv4/ping_group_range, which nothing sets by default, so
    it only exists where an administrator deliberately granted it. It is
    tried first because a deliberate grant like that is exactly the signal
    that sending real ICMP from this process is wanted here.

    SOCK_RAW works unconditionally for a process with CAP_NET_RAW — root,
    ordinarily — which is a much weaker signal (plenty of things run as
    root without anyone having decided this process in particular should
    be pinging the network), but it is still the documented fallback:
    a locked-down host with neither gets None and the subprocess path,
    unchanged.
    """
    if IS_WINDOWS:
        return None
    for sock_type, name in ((socket.SOCK_DGRAM, "dgram"), (socket.SOCK_RAW, "raw")):
        try:
            probe = socket.socket(socket.AF_INET, sock_type, socket.IPPROTO_ICMP)
        except OSError:
            continue
        probe.close()
        return name
    return None


def _icmp_socket_kind() -> str | None:
    """The cached capability, honouring NETPATH_PING_MODE. See the module
    comment above for what each mode does and why the override exists."""
    global _icmp_kind_cache
    mode = os.environ.get(_PING_MODE_ENV, "").strip().lower()
    if mode == "subprocess":
        return None
    with _icmp_kind_lock:
        if _icmp_kind_cache == "unchecked":
            _icmp_kind_cache = _detect_icmp_socket_kind()
        kind = _icmp_kind_cache
    if kind is None and mode == "socket":
        raise OSError(
            "NETPATH_PING_MODE=socket but no ICMP socket could be opened here "
            "(see /proc/sys/net/ipv4/ping_group_range, or run with CAP_NET_RAW)")
    return kind


def _ping_many_socket(ip: str, count: int, timeout_ms: int,
                      kind: str) -> tuple[int, int, float | None]:
    """(sent, received, average RTT in ms) for `count` echo probes to `ip`,
    all sent over one socket rather than one subprocess per probe.

    A fresh socket per call rather than one shared across every in-flight
    probe: Linux's unprivileged ping socket (SOCK_DGRAM) demultiplexes
    replies straight to the socket that sent the matching request, by a
    local id the kernel assigns it, and a raw socket (SOCK_RAW) gets its
    own fan-out copy of every ICMP packet the host sees regardless of who
    else is listening. Either way a call's own socket only ever needs to
    care about its own replies, so concurrent polls of other devices —
    each on its own thread, each opening its own socket here — cannot
    steal each other's packets or block on one another. Socket setup costs
    nothing like a fork/exec, so one per call is not the bottleneck the
    subprocess it replaces was.

    Raises OSError only if the socket itself cannot be opened (capability
    looked fine at process start but is not right now); a probe that sends
    but gets no reply — including a genuine "network unreachable" on
    send — is just counted as not received, the same as it was for a
    failed subprocess ping.
    """
    sock_type = socket.SOCK_DGRAM if kind == "dgram" else socket.SOCK_RAW
    sock = socket.socket(socket.AF_INET, sock_type, socket.IPPROTO_ICMP)
    identifier = os.getpid() & 0xFFFF
    sent = 0
    received = 0
    rtts: list[float] = []
    # selectors.DefaultSelector rather than select.select() directly: on
    # Linux it picks epoll, which has no ceiling on the file descriptor
    # number, where select.select() raises ValueError (not OSError) for any
    # fd >= 1024. A 1,000-device fleet with a poll worker per device and
    # several sockets/handles apiece gets there easily, and that ValueError
    # is not what either caller below is watching for — see ping_once's and
    # ping_many's own except clauses, which now catch it precisely because
    # of this.
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    try:
        for sequence in range(1, count + 1):
            token = os.urandom(8)
            try:
                sock.sendto(_build_echo_request(identifier, sequence, token), (ip, 0))
            except OSError:
                sent += 1
                continue
            sent += 1
            sent_at = time.monotonic()
            deadline = sent_at + timeout_ms / 1000
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not selector.select(remaining):
                    break
                try:
                    packet, _addr = sock.recvfrom(1024)
                except OSError:
                    break
                parsed = _parse_icmp_reply(packet, has_ip_header=(sock_type == socket.SOCK_RAW))
                if not parsed:
                    continue
                reply_type, _code, reply_id, reply_seq, reply_payload = parsed
                if reply_type != _ICMP_ECHO_REPLY or reply_seq != sequence:
                    continue                       # not this probe's reply
                if sock_type == socket.SOCK_RAW and reply_id != identifier:
                    continue                       # someone else's raw-socket traffic
                if reply_payload[:len(token)] != token:
                    continue
                received += 1
                rtts.append((time.monotonic() - sent_at) * 1000)
                break
    finally:
        selector.close()
        sock.close()
    return sent, received, (sum(rtts) / len(rtts)) if rtts else None


def ping_once(ip: str, timeout_ms: int = 800) -> bool:
    if _is_ipv4(ip):
        kind = _icmp_socket_kind()
        if kind is not None:
            try:
                _sent, received, _rtt = _ping_many_socket(ip, 1, timeout_ms, kind)
                return received > 0
            except (OSError, ValueError):
                # ValueError alongside OSError: selectors.DefaultSelector
                # normally sidesteps select.select()'s fd>=1024 ceiling
                # (see _ping_many_socket's own comment), but a poll worker
                # is still handed whatever the platform's selector backend
                # throws, and this path exists precisely so a probe
                # degrades to the subprocess fallback rather than crashing
                # the worker on anything unexpected from the socket path.
                pass                    # socket path unavailable; fall through below
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

    Prefers one ICMP socket over `count` subprocess spawns wherever the
    platform permits it (see _icmp_socket_kind) — that used to cost a
    process per probe, three per device per poll, which is what turned
    into hundreds of fork/execs a second across a real-sized fleet. The
    RTT there is real wall-clock time around each send/receive, which is
    finally trustworthy: the old subprocess path measured `ping`'s own
    "time=" figure instead of timing the subprocess itself, specifically
    because process spawn overhead of a few milliseconds would otherwise
    have been reported as network latency. A socket has no such overhead
    to hide.

    Falls back to one `ping -c 1` subprocess per probe — Windows, IPv6 (not
    handled by the ICMPv4 socket path above), or any host where neither an
    unprivileged nor a raw ICMP socket could be opened. Sent one at a time
    rather than as a single `ping -c N` there too: Windows and the BSDs
    disagree on how to ask for a burst and on how they summarise it, and
    one probe per subprocess is the only form already known to work
    everywhere here.
    """
    count = max(1, int(count))
    if _is_ipv4(ip):
        kind = _icmp_socket_kind()
        if kind is not None:
            try:
                return _ping_many_socket(ip, count, timeout_ms, kind)
            except (OSError, ValueError):
                # See ping_once's matching except clause just above.
                pass                    # socket path unavailable; fall through below

    from .tracer import _UNIX_PING_TIME, _WIN_PING_TIME

    pattern = _WIN_PING_TIME if IS_WINDOWS else _UNIX_PING_TIME
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
    except (subprocess.TimeoutExpired, OSError):
        # TimeoutExpired is a SubprocessError, not an OSError, so the one
        # failure this call arranges for itself was the one it did not
        # catch: a slow `ip neigh` turned a good sweep into "scan finished
        # with an error".
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

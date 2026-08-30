"""Reverse-name lookup with fallbacks.

`socket.gethostbyaddr` is the obvious way to turn an address into a name, but
it goes through the operating system's whole name-resolution stack and that
stack does not always ask the same question `nslookup` asks. On Windows it
consults the hosts file, then DNS, then NetBIOS, subject to the suffix search
list and the DNS Client service's negative cache — so an address whose PTR
record exists on an internal server can still come back empty, most often
because a negative answer was cached earlier or because the reverse zone is
served by a resolver that is not first in the adapter's list.

So there are three attempts, in order:

1. `socket.gethostbyaddr` — fast, and right most of the time.
2. A PTR query sent straight to a nominated server, if one is configured. This
   is what `nslookup 10.1.2.3 10.0.0.53` does, without the negative cache and
   without a subprocess.
3. `nslookup` itself, which is worth having because it is the tool people check
   with: if nslookup finds a name, this finds the same name.

Anything found is cached by the caller, so the expensive paths run once per
address per cache period.
"""

from __future__ import annotations

import ipaddress
import os
import random
import re
import socket
import struct
import subprocess

from .procs import hidden

PTR = 12
TXT = 16
IN = 1

# Team Cymru's DNS-based whois answers ordinary recursive queries against
# public domain names (origin.asn.cymru.com / asn.cymru.com) — it does not
# require talking to their servers directly, any recursive resolver will
# walk the normal delegation chain. There is no portable, dependency-free way
# to discover the system's configured resolver via raw sockets (unlike PTR
# lookups, which go through socket.gethostbyaddr and so use it implicitly),
# so a public resolver is the default here unless one is configured.
DEFAULT_ASN_SERVER = "8.8.8.8"


def ptr_name(ip: str) -> str:
    """The in-addr.arpa or ip6.arpa name a PTR query asks about."""
    address = ipaddress.ip_address(ip)
    return address.reverse_pointer


def _encode(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii", "ignore")[:63]
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed domain name, returning it and the offset."""
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0

    while True:
        if offset >= len(message) or hops > 40:
            break
        length = message[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:               # pointer to earlier in the packet
            if offset + 1 >= len(message):
                break
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            continue
        offset += 1
        labels.append(message[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def query_ptr(ip: str, server: str, timeout_s: float = 3.0,
              port: int = 53) -> str | None:
    """Ask one server directly for the PTR record. None if it has no answer."""
    try:
        question = _encode(ptr_name(ip)) + struct.pack("!HH", PTR, IN)
    except ValueError:
        return None

    request_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
    packet = header + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        sock.sendto(packet, (server, port))
        while True:
            reply, _ = sock.recvfrom(4096)
            if len(reply) >= 12 and struct.unpack("!H", reply[:2])[0] == request_id:
                break
    except OSError:
        return None
    finally:
        sock.close()

    _, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", reply[:12])
    if flags & 0x000F or not answers:            # RCODE set, or nothing to say
        return None

    offset = 12
    for _ in range(questions):
        _, offset = _read_name(reply, offset)
        offset += 4
    for _ in range(answers):
        _, offset = _read_name(reply, offset)
        if offset + 10 > len(reply):
            return None
        rtype, _, _, rdlength = struct.unpack("!HHIH", reply[offset:offset + 10])
        offset += 10
        if rtype == PTR:
            name, _ = _read_name(reply, offset)
            return name.rstrip(".") or None
        offset += rdlength
    return None


def query_txt(name: str, server: str, timeout_s: float = 3.0,
              port: int = 53) -> str | None:
    """One TXT record's text for `name`, via the same raw-UDP path
    query_ptr() uses. None if there is no answer."""
    question = _encode(name) + struct.pack("!HH", TXT, IN)
    request_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
    packet = header + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        sock.sendto(packet, (server, port))
        while True:
            reply, _ = sock.recvfrom(4096)
            if len(reply) >= 12 and struct.unpack("!H", reply[:2])[0] == request_id:
                break
    except OSError:
        return None
    finally:
        sock.close()

    _, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", reply[:12])
    if flags & 0x000F or not answers:
        return None

    offset = 12
    for _ in range(questions):
        _, offset = _read_name(reply, offset)
        offset += 4
    for _ in range(answers):
        _, offset = _read_name(reply, offset)
        if offset + 10 > len(reply):
            return None
        rtype, _, _, rdlength = struct.unpack("!HHIH", reply[offset:offset + 10])
        offset += 10
        if rtype == TXT and rdlength:
            # A TXT record is one or more length-prefixed character strings;
            # concatenating them is what every resolver's own TXT output does.
            end = offset + rdlength
            parts = []
            pos = offset
            while pos < end:
                length = reply[pos]
                pos += 1
                parts.append(reply[pos:pos + length].decode("ascii", "replace"))
                pos += length
            return "".join(parts)
        offset += rdlength
    return None


def _reverse_origin_name(ip: str) -> str | None:
    """'d.c.b.a.origin.asn.cymru.com' for an IPv4 address a.b.c.d.

    IPv6 uses a different Cymru zone (origin6) with a different label
    format; only IPv4 is implemented, since that's what every traceroute
    hop in this app resolves to today.
    """
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        return None
    octets = ip.split(".")[::-1]
    return ".".join(octets) + ".origin.asn.cymru.com"


def asn_lookup(ip: str, server: str = "",
              timeout_s: float = 3.0) -> tuple[int | None, str | None]:
    """(ASN, short org name) for a public address, via Team Cymru's
    DNS-based whois. (None, None) for private/reserved addresses — those are
    never looked up at all, so no query naming an internal IP ever leaves
    this host — and for anything Cymru has no answer for.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    # is_global is the stdlib's single source of truth for "not private" —
    # it also correctly excludes loopback, link-local, CGNAT (100.64.0.0/10)
    # and the other IANA special-purpose ranges (RFC 6890) in one check,
    # so a range nobody thought to special-case by hand still can't reach
    # the network. No socket is ever opened for an address that fails this.
    if not address.is_global:
        return None, None

    origin_name = _reverse_origin_name(ip)
    if origin_name is None:
        return None, None
    resolver = server or DEFAULT_ASN_SERVER
    origin = query_txt(origin_name, resolver, timeout_s=timeout_s)
    if not origin:
        return None, None
    # "15169 | 8.8.8.0/24 | US | arin | 2000-03-30" — first field may itself
    # be several space-separated ASNs when more than one originates the
    # prefix; only the first is used, same as most whois clients.
    try:
        asn = int(origin.split("|")[0].strip().split()[0])
    except (ValueError, IndexError):
        return None, None

    org = None
    name_txt = query_txt(f"AS{asn}.asn.cymru.com", resolver, timeout_s=timeout_s)
    if name_txt:
        # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        parts = [p.strip() for p in name_txt.split("|")]
        if len(parts) >= 5:
            org = parts[4]
    return asn, org


_NSLOOKUP_NAME = re.compile(r"name\s*=\s*([^\s]+)", re.IGNORECASE)


def nslookup(ip: str, server: str | None = None,
             timeout_s: float = 5.0) -> str | None:
    """Shell out to nslookup, so that whatever it finds, this finds too."""
    command = ["nslookup", ip]
    if server:
        command.append(server)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout_s,
            **hidden(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    match = _NSLOOKUP_NAME.search(completed.stdout or "")
    if match:
        return match.group(1).rstrip(".")
    return None


def reverse(ip: str, timeout_s: float = 3.0, server: str | None = None,
            use_nslookup: bool = True) -> tuple[str | None, str]:
    """Best available name for an address, and which method produced it."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_s)
        name = socket.gethostbyaddr(ip)[0]
        if name:
            return name, "system"
    except (OSError, IndexError):
        pass
    finally:
        socket.setdefaulttimeout(previous)

    if server:
        name = query_ptr(ip, server, timeout_s)
        if name:
            return name, f"ptr@{server}"

    if use_nslookup:
        name = nslookup(ip, server, max(timeout_s * 2, 5.0))
        if name:
            return name, "nslookup"

    return None, "none"

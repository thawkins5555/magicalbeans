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
import re
import socket
import struct
import subprocess
import time

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


# One DNS label: 1-63 of letter/digit/hyphen, not starting or ending with a
# hyphen. Used to decide whether a configured resolver is a name this code is
# willing to hand to a subprocess -- see nslookup().
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\.?\Z")


def is_ip_literal(text: str) -> bool:
    try:
        ipaddress.ip_address((text or "").strip())
    except ValueError:
        return False
    return True


def is_resolver_address(text: str) -> bool:
    """True for an address or hostname a resolver may be nominated by.

    Everything else -- an empty string, a shell metacharacter, and above all
    anything starting with `-` -- is refused. `nslookup` reads a leading-`-`
    argument as an option (`-port=`, `-type=`, `-debug`, `-timeout=`) and has
    no `--` separator to stop it, so refusing the shape is the only defence
    there is.
    """
    text = (text or "").strip()
    if not text or len(text) > 255:
        return False
    return is_ip_literal(text) or bool(_HOSTNAME_RE.fullmatch(text))


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


def _question_echoes(reply: bytes, question: bytes) -> bool:
    """True when the reply carries back exactly the question that was asked.

    A resolver echoes the question section verbatim, so an answer that does
    not is not an answer to this query. Compared case-insensitively because
    only the letters of a label can legally differ, and every other byte in
    the encoded question (label lengths, which are at most 63, the qtype and
    the qclass) is below 'A' and so unaffected by .lower()."""
    if len(reply) < 12 + len(question):
        return False
    questions = struct.unpack("!H", reply[4:6])[0]
    return questions == 1 and reply[12:12 + len(question)].lower() == question.lower()


def _exchange(name: str, rtype: int, server: str, timeout_s: float,
              port: int) -> bytes | None:
    """One UDP query, and the verified reply to it -- or None.

    Three things this does that sending with `sendto` and matching on the
    16-bit ID alone did not:

    * `connect()` before sending, so the kernel drops any datagram that did
      not come from the server this query went to. Without it the only check
      on an injected PTR or TXT answer was guessing 16 bits, and the name
      that came back was stored and shown as the identity of a device or a
      traceroute hop.
    * The query ID comes from `os.urandom`, not from the Mersenne Twister,
      which is seeded once per process and whose next outputs can be
      predicted from a few observed ones.
    * `timeout_s` bounds the whole exchange rather than each `recv`. A peer
      that sent one junk datagram every two seconds used to restart the
      clock every time and could hold a resolver worker indefinitely; eight
      such streams took out all eight workers and reverse DNS stopped.
    """
    try:
        question = _encode(name) + struct.pack("!HH", rtype, IN)
    except (ValueError, UnicodeError):
        return None

    request_id = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0) + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    deadline = time.monotonic() + timeout_s
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        sock.connect((server, port))
        sock.send(packet)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            reply = sock.recv(4096)
            if len(reply) < 12:
                continue
            if struct.unpack("!H", reply[:2])[0] != request_id:
                continue
            if not _question_echoes(reply, question):
                continue
            return reply
    except OSError:
        return None
    finally:
        sock.close()


def query_ptr(ip: str, server: str, timeout_s: float = 3.0,
              port: int = 53) -> str | None:
    """Ask one server directly for the PTR record. None if it has no answer."""
    try:
        name = ptr_name(ip)
    except ValueError:
        return None
    reply = _exchange(name, PTR, server, timeout_s, port)
    if reply is None:
        return None

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
    reply = _exchange(name, TXT, server, timeout_s, port)
    if reply is None:
        return None

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


# BIND prints "name = host."; Windows prints "Name:    host". Both forms.
_NSLOOKUP_NAME = re.compile(r"name\s*[:=]\s*(\S+)", re.IGNORECASE)


def nslookup(ip: str, server: str | None = None,
             timeout_s: float = 5.0) -> str | None:
    """Shell out to nslookup, so that whatever it finds, this finds too.

    Both arguments are validated here rather than trusted from the caller.
    No shell is involved, so there was never a shell-injection path; what
    there was is that `nslookup` reads a leading-`-` argument as an option
    and offers no `--` to stop it, and that the safety of the two live
    callers rested on a property of those callers rather than on anything
    this public helper checked."""
    if not is_ip_literal(ip):
        return None
    command = ["nslookup", ip.strip()]
    if server:
        if not is_resolver_address(server):
            return None
        command.append(server.strip())
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
    """Best available name for an address, and which method produced it.

    `timeout_s` bounds attempts 2 and 3. It does not bound
    `socket.gethostbyaddr`, and never did: that call goes through the C
    library resolver and honours resolv.conf, not any Python setting. The
    code that used to bracket it in
    `socket.setdefaulttimeout(timeout_s)` / `setdefaulttimeout(previous)`
    therefore bought nothing and cost two things. `setdefaulttimeout` is
    process-wide, not thread-local, and it is applied to every socket
    created anywhere in the process while it is set -- the poller's UDP
    sockets, IPAM's sweep, an SSH transport, an alert mail, every
    connection the web server accepts -- and, with eight resolver workers
    running by default, the save/restore pairs interleaved and left the
    global permanently set to the resolver's timeout. Concurrency here is
    bounded by the caller's own thread pool instead.
    """
    if not is_ip_literal(ip):
        return None, "none"
    ip = ip.strip()
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name:
            return name, "system"
    except (OSError, IndexError):
        pass

    if server and is_resolver_address(server):
        name = query_ptr(ip, server, timeout_s)
        if name:
            return name, f"ptr@{server}"

    if use_nslookup:
        name = nslookup(ip, server, max(timeout_s * 2, 5.0))
        if name:
            return name, "nslookup"

    return None, "none"

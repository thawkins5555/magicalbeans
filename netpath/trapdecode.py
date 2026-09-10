"""Pure BER/ASN.1 + SNMP trap message decoder and encoder.

No sockets, no database. Mirrors nfdecode.py's shape: a `Decoder` with a
`.stats` counter dict, and `decode()` never raises past its own boundary —
one try/except around the whole body that counts the failure and returns
None. Feed it bytes, get a Trap.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

# Universal tags
T_INTEGER      = 0x02
T_OCTET_STRING = 0x04
T_NULL         = 0x05
T_OID          = 0x06
T_SEQUENCE     = 0x30

# Application tags (context = APPLICATION, primitive)
T_IPADDRESS    = 0x40
T_COUNTER32    = 0x41
T_GAUGE32      = 0x42          # also Unsigned32
T_TIMETICKS    = 0x43
T_OPAQUE       = 0x44
T_NSAPADDRESS  = 0x45
T_COUNTER64    = 0x46
T_UINTEGER32   = 0x47

# SNMPv2 exception markers (context-specific, primitive)
T_NO_SUCH_OBJECT   = 0x80
T_NO_SUCH_INSTANCE = 0x81
T_END_OF_MIB_VIEW  = 0x82

# PDU tags (context-specific, constructed)
PDU_GET      = 0xA0
PDU_GETNEXT  = 0xA1
PDU_RESPONSE = 0xA2
PDU_SET      = 0xA3
PDU_TRAP_V1  = 0xA4      # SNMPv1 Trap-PDU — a different shape entirely
PDU_GETBULK  = 0xA5
PDU_INFORM   = 0xA6      # InformRequest-PDU — same shape as SNMPv2-Trap-PDU
PDU_TRAP_V2  = 0xA7      # SNMPv2-Trap-PDU
PDU_REPORT   = 0xA8

V1, V2C, V3 = 0, 1, 3
VERSION_NAMES = {0: "v1", 1: "v2c", 3: "v3"}

GENERIC_NAMES = ["coldStart", "warmStart", "linkDown", "linkUp",
                 "authenticationFailure", "egpNeighborLoss",
                 "enterpriseSpecific"]

SYS_UPTIME_0 = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID_0 = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ENTERPRISE_0 = "1.3.6.1.6.3.1.1.4.3.0"

MAX_DATAGRAM = 65535

# SNMP's wire types bound these fields far tighter than BER does. RFC 2578
# 7.1: SNMP's "INTEGER" (the v1 generic/specific trap fields, the v2/v3
# request-id) is Integer32; TimeTicks (7.1.8, agent uptime) is unsigned
# 32-bit. Unclamped, a crafted 20-byte BER INTEGER produces a Python int
# SQLite's int64 bind cannot hold, and the OverflowError takes a whole
# in-flight batch of traps with it -- see snmptrapd._insert_batch.
_INT32_MIN, _INT32_MAX = -2147483648, 2147483647
_UINT32_MAX = 4294967295


def _clamp_int32(n: int) -> int:
    return max(_INT32_MIN, min(_INT32_MAX, n))


def _clamp_uint32(n: int) -> int:
    return max(0, min(_UINT32_MAX, n))


class BerError(Exception):
    pass


class Reader:
    """Walks a byte range and yields TLVs, tracking absolute offsets into the
    original datagram — never slices — so SNMPv3 authentication can hash the
    original buffer with one field blanked in place."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, start: int = 0, end: int | None = None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def at_end(self) -> bool:
        return self.pos >= self.end

    def read_tlv(self) -> tuple[int, int, int]:
        """Return (tag, value_start, value_end). Advances past the value."""
        if self.pos >= self.end:
            raise BerError("truncated")
        tag = self.data[self.pos]
        self.pos += 1
        if tag & 0x1F == 0x1F:
            # High-tag-number form. SNMP never uses tags above 30.
            raise BerError("high tag number")

        if self.pos >= self.end:
            raise BerError("truncated length")
        first = self.data[self.pos]
        self.pos += 1

        if first < 0x80:
            length = first
        elif first == 0x80:
            # Indefinite length. No conforming SNMP agent emits this;
            # accepting it means scanning attacker-controlled bytes for a
            # terminator for zero real-world benefit.
            raise BerError("indefinite length")
        elif first == 0xFF:
            raise BerError("reserved length")
        else:
            n = first & 0x7F
            if n > 4:                       # >4 GiB length is nonsense here
                raise BerError("length too long")
            if self.pos + n > self.end:
                raise BerError("truncated length")
            length = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n

        value_start = self.pos
        value_end = value_start + length
        if value_end > self.end or value_end < value_start:
            raise BerError("value overruns")
        self.pos = value_end
        return tag, value_start, value_end

    def expect(self, want_tag: int) -> tuple[int, int]:
        tag, s, e = self.read_tlv()
        if tag != want_tag:
            raise BerError(f"expected 0x{want_tag:02X}, got 0x{tag:02X}")
        return s, e

    def sub(self, s: int, e: int) -> "Reader":
        return Reader(self.data, s, e)


# ------------------------------------------------------ never-raising helpers

def _signed(data: bytes, s: int, e: int) -> int:
    if e <= s:
        return 0
    return int.from_bytes(data[s:e], "big", signed=True)


def _unsigned(data: bytes, s: int, e: int) -> int:
    if e <= s:
        return 0
    return int.from_bytes(data[s:e], "big", signed=False)


def _ipv4(data: bytes, s: int, e: int) -> str:
    if e - s != 4:
        return ""
    try:
        return socket.inet_ntop(socket.AF_INET, data[s:e])
    except OSError:
        return ""


def _oid(data: bytes, s: int, e: int) -> str:
    """BER OBJECT IDENTIFIER -> dotted-decimal text. Never raises."""
    if e <= s:
        return ""
    arcs: list[int] = []
    value = 0
    shifts = 0
    first = True
    i = s
    while i < e:
        byte = data[i]
        i += 1
        value = (value << 7) | (byte & 0x7F)
        shifts += 1
        if shifts > 10:                       # >70 bits: malformed, stop
            return ".".join(str(a) for a in arcs) if arcs else ""
        if byte & 0x80:
            continue
        if first:
            # X.690 8.19.4: the first sub-identifier is 40*arc1 + arc2.
            # arc1 is 0, 1 or 2; when it is 2, arc2 is unbounded, so this
            # cannot be written as a simple divmod by 40.
            if value < 40:
                arcs.extend((0, value))
            elif value < 80:
                arcs.extend((1, value - 40))
            else:
                arcs.extend((2, value - 80))
            first = False
        else:
            arcs.append(value)
        value = 0
        shifts = 0
    return ".".join(str(a) for a in arcs)


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _octets_text(raw: bytes) -> str:
    """Text if it reads as text, otherwise colon-separated hex.

    A six-byte non-printable string is almost always a MAC address
    (ifPhysAddress turns up in linkUp/linkDown varbinds constantly), so it
    is rendered as one.
    """
    if not raw:
        return ""
    if all(b in _PRINTABLE for b in raw):
        try:
            return raw.decode("utf-8").replace("\r", " ").replace("\n", " ")
        except UnicodeDecodeError:
            pass
    if len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    return " ".join(f"{b:02X}" for b in raw)


def format_ticks(ticks: int) -> str:
    """TimeTicks are hundredths of a second since the agent booted."""
    seconds, hundredths = divmod(int(ticks), 100)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{hundredths:02d}"


def _decode_value(data: bytes, tag: int, s: int, e: int,
                  max_chars: int) -> tuple[str, str, object]:
    """Returns (type_name, display_text, native_value)."""
    if tag == T_INTEGER:
        n = _signed(data, s, e)
        return "INTEGER", str(n), n
    if tag == T_OCTET_STRING:
        text = _octets_text(data[s:e])
        return "STRING", _truncate(text, max_chars), text
    if tag == T_NULL:
        return "NULL", "", None
    if tag == T_OID:
        oid = _oid(data, s, e)
        return "OID", oid, oid
    if tag == T_SEQUENCE:
        return "SEQUENCE", f"<{e - s} bytes>", None
    if tag == T_IPADDRESS:
        ip = _ipv4(data, s, e)
        return "IpAddress", ip, ip
    if tag == T_COUNTER32:
        n = _unsigned(data, s, e)
        return "Counter32", str(n), n
    if tag == T_GAUGE32:
        n = _unsigned(data, s, e)
        return "Gauge32", str(n), n
    if tag == T_TIMETICKS:
        n = _unsigned(data, s, e)
        return "TimeTicks", format_ticks(n), n
    if tag == T_OPAQUE:
        return "Opaque", data[s:e].hex(), data[s:e].hex()
    if tag == T_NSAPADDRESS:
        return "NsapAddress", data[s:e].hex(), data[s:e].hex()
    if tag == T_COUNTER64:
        n = _unsigned(data, s, e)
        return "Counter64", str(n), n
    if tag == T_UINTEGER32:
        n = _unsigned(data, s, e)
        return "Unsigned32", str(n), n
    if tag == T_NO_SUCH_OBJECT:
        return "noSuchObject", "noSuchObject", None
    if tag == T_NO_SUCH_INSTANCE:
        return "noSuchInstance", "noSuchInstance", None
    if tag == T_END_OF_MIB_VIEW:
        return "endOfMibView", "endOfMibView", None
    hexed = data[s:e].hex()
    return f"tag-0x{tag:02X}", hexed, hexed


def _truncate(text: str, max_chars: int) -> str:
    if len(text) > max_chars:
        return text[:max_chars] + "…"
    return text


@dataclass
class Trap:
    ts: float = 0.0
    source: str = ""
    version: int = 1
    community: str = ""        # v1/v2c community, or v3 msgUserName
    engine_id: str = ""        # v3 msgAuthoritativeEngineID, lowercase hex
    security: str = ""         # "", "noAuthNoPriv", "authNoPriv", "authPriv"
    auth_state: str = ""       # "", "ok", "failed", "unverified", "encrypted"
    trap_oid: str = ""         # canonical trap identity OID
    trap_name: str = ""        # resolved display name
    trap_kind: str = ""        # short label used for filters/detail
    severity: int = 5          # 0..7, same scale as syslog
    generic: int | None = None     # v1 only
    specific: int | None = None    # v1 only
    enterprise: str = ""           # v1 only
    agent_addr: str = ""           # v1 only
    uptime: int = 0                # TimeTicks
    is_inform: bool = False
    request_id: int = 0            # needed to acknowledge an inform
    varbinds: list = field(default_factory=list)   # [{oid,name,type,value,text}]
    varbind_text: str = ""
    raw: bytes = b""
    # Full TLV span (tag byte included) of the varbind-list inside `raw`, so
    # an inform can be acknowledged by splicing bytes rather than re-encoding.
    varbinds_tlv_span: tuple[int, int] | None = None


AUTH_PROTOCOLS = {                     # name -> (hashlib ctor, digest bytes)
    "MD5":    (hashlib.md5,    12),    # usmHMACMD5AuthProtocol
    "SHA":    (hashlib.sha1,   12),    # usmHMACSHAAuthProtocol
    "SHA1":   (hashlib.sha1,   12),
    "SHA224": (hashlib.sha224, 16),    # RFC 7860 usmHMAC128SHA224
    "SHA256": (hashlib.sha256, 24),    # RFC 7860 usmHMAC192SHA256
    "SHA384": (hashlib.sha384, 32),    # RFC 7860 usmHMAC256SHA384
    "SHA512": (hashlib.sha512, 48),    # RFC 7860 usmHMAC384SHA512
}

# The engine id in the key comes straight off the wire, so a stream of forged
# v3 traps with a fresh engine id each time grew this dict without bound (and
# paid a 1 MiB hash per entry). Bounded, least-recently-used.
#
# Mutated from every poll worker and from the trap receiver at once. The key
# is per (protocol, password, engine), so a race can never hand one device
# another's key — but OrderedDict.move_to_end on a key another thread's
# popitem has just evicted raises KeyError, which escaped localized_key into
# whichever poll was signing at the time. The lock covers get + move_to_end
# and set + evict; the 1 MiB hash is computed outside it, because serialising
# every worker's key derivation behind one lock would be its own regression.
_KEY_CACHE_MAX = 256
_KEY_CACHE: collections.OrderedDict = collections.OrderedDict()
_KEY_CACHE_LOCK = threading.Lock()


def localized_key(proto: str, password: str, engine_id: bytes) -> bytes | None:
    """RFC 3414 A.2.1/A.2.2 password-to-key, then localisation to one engine.

    Module level and shared, because snmppoll.py needs exactly the same
    derivation the trap verifier does and the 1 MiB hash is expensive
    enough that two caches would be two costs. Keyed on (protocol,
    password, engine), so a password change or a re-keyed agent simply
    misses.
    """
    entry = AUTH_PROTOCOLS.get(proto)
    if entry is None or not password:
        return None
    ctor, _ = entry
    key = (proto, password, engine_id)
    with _KEY_CACHE_LOCK:
        cached = _KEY_CACHE.get(key)
        if cached is not None:
            _KEY_CACHE.move_to_end(key)
            return cached
    raw = password.encode("utf-8")
    repeated = raw * (1048576 // len(raw) + 1)
    ku = ctor(repeated[:1048576]).digest()
    localized = ctor(ku + engine_id + ku).digest()
    # Two threads missing on the same key both hash and both store the
    # same bytes; that is one wasted hash, not a wrong key.
    with _KEY_CACHE_LOCK:
        _KEY_CACHE[key] = localized
        while len(_KEY_CACHE) > _KEY_CACHE_MAX:
            _KEY_CACHE.popitem(last=False)
    return localized


PRIV_KEY_LEN = 16     # AES-128 (usmAesCfb128Protocol, RFC 3826) — the only cipher spoken


def privacy_key(auth_proto: str, priv_password: str, engine_id: bytes) -> bytes | None:
    """The AES-128 privacy key for one user on one engine: RFC 3826 s1.2.

    USM has no privacy hash of its own — the privacy password goes through
    the AUTHENTICATION protocol's password-to-key and localisation (RFC
    3414 A.2), which is why this takes `auth_proto` and not a privacy
    protocol name. That yields a key of the digest's length: MD5 gives
    exactly the 16 bytes AES-128 needs, SHA-1 gives 20, SHA-224/256/384/512
    give 28/32/48/64 — and the cipher key is always the FIRST 16 of them
    (RFC 3826 s1.2, RFC 3414 s2.6 for DES before it): never the last, never
    a fold. The remainder is simply unused. AES-192/256 would need the
    Reeder/Blumenthal key extension instead, which is exactly why they are
    not offered (see snmpcrypt's docstring).

    Reuses localized_key and its cache rather than deriving again, so the
    1 MiB password hash is paid once per (protocol, password, engine)
    rather than once per message. That cache is bounded and lives for the
    process lifetime, and a Python bytes object cannot be wiped — both are
    documented in CREDENTIAL-SECURITY.md rather than pretended otherwise.
    """
    full = localized_key(auth_proto, priv_password, engine_id)
    if full is None:
        return None
    return full[:PRIV_KEY_LEN]


class Decoder:
    def __init__(self, log=None):
        self.log = log
        self.stats = {
            "packets": 0, "traps": 0, "errors": 0,
            "unsupported_version": 0, "not_a_trap": 0,
            "indefinite_length": 0, "too_many_varbinds": 0,
            "v3": 0, "v3_encrypted": 0, "v3_auth_ok": 0,
            "v3_auth_failed": 0, "v3_unverified": 0, "v3_no_user": 0,
        }
        self.oid_names: dict[str, str] = dict(WELL_KNOWN)
        self.severity_rules: list[tuple[str, int]] = list(DEFAULT_SEVERITY_RULES)
        self.users: dict[str, tuple[str, str]] = {}   # user -> (auth_proto, auth_pass)
        self.max_varbinds = 64
        self.max_value_chars = 512

    # --------------------------------------------------------------- config

    def configure(self, settings: dict) -> None:
        self.max_varbinds = max(1, int(settings.get("max_varbinds", 64)))
        self.max_value_chars = max(32, int(settings.get("max_value_chars", 512)))

        names = dict(WELL_KNOWN)
        for line in str(settings.get("oid_names", "") or "").splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            oid, name = line.split("=", 1)
            oid, name = oid.strip().strip("."), name.strip()
            if oid and name and all(part.isdigit() for part in oid.split(".")):
                names[oid] = name              # a user entry overrides a built-in
        self.oid_names = names

        rules = list(DEFAULT_SEVERITY_RULES)
        for line in str(settings.get("severity_rules", "") or "").splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            oid, level = line.split("=", 1)
            try:
                rules.append((oid.strip().strip("."), max(0, min(7, int(level.strip())))))
            except ValueError:
                continue
        # Longest prefix wins, so a specific rule beats a vendor-wide one.
        self.severity_rules = sorted(rules, key=lambda r: -len(r[0]))

        users = {}
        for line in str(settings.get("v3_users", "") or "").splitlines():
            parts = [p.strip() for p in line.split("/")]
            if len(parts) >= 3 and parts[0]:
                users[parts[0]] = (parts[1].upper().replace("-", ""), parts[2])
        self.users = users
        # Not cleared here: the module-level key cache (localized_key's
        # _KEY_CACHE) is shared with snmppoll.py's outbound signing and is
        # keyed on (protocol, password, engine) — a changed password simply
        # misses under its new key, so a stale entry is never returned.

    def resolve_oid(self, oid: str) -> str:
        """A readable name for an OID: exact hit, else the longest known prefix
        with the remaining arcs appended (1.3.6.1.2.1.2.2.1.2.7 -> ifDescr.7)."""
        if not oid:
            return ""
        name = self.oid_names.get(oid)
        if name:
            return name
        parts = oid.split(".")
        for cut in range(len(parts) - 1, 2, -1):
            name = self.oid_names.get(".".join(parts[:cut]))
            if name:
                return name + "." + ".".join(parts[cut:])
        return oid

    def severity_for(self, trap_oid: str) -> int:
        for prefix, level in self.severity_rules:      # already longest-first
            if trap_oid == prefix or trap_oid.startswith(prefix + "."):
                return level
        return 5                                       # notice

    # --------------------------------------------------------------- decode

    def decode(self, data: bytes, source: str, now: float | None = None) -> Trap | None:
        self.stats["packets"] += 1
        try:
            return self._decode(data, source, now if now is not None else time.time())
        except BerError as exc:
            if "indefinite" in str(exc):
                self.stats["indefinite_length"] += 1
            self.stats["errors"] += 1
            return None
        except (struct.error, IndexError, ValueError, UnicodeError, OSError):
            self.stats["errors"] += 1
            return None

    def _decode(self, data, source, now):
        top = Reader(data)
        body_s, body_e = top.expect(T_SEQUENCE)        # the whole Message
        msg = Reader(data, body_s, body_e)

        tag, s, e = msg.read_tlv()
        if tag != T_INTEGER:
            raise BerError("no version")
        version = _signed(data, s, e)

        if version in (V1, V2C):
            return self._decode_v1_v2c(data, msg, version, source, now)
        if version == V3:
            self.stats["v3"] += 1
            return self._decode_v3(data, msg, source, now)
        self.stats["unsupported_version"] += 1
        return None

    # ---------------------------------------------------------- v1 / v2c

    def _decode_v1_v2c(self, data, msg, version, source, now):
        cs, ce = msg.expect(T_OCTET_STRING)            # community
        community = data[cs:ce].decode("utf-8", "replace")

        tag, ps, pe = msg.read_tlv()                   # the PDU
        trap = Trap(ts=now, source=source, version=version,
                   community=community, raw=data)

        if tag == PDU_TRAP_V1:
            self._read_trap_v1(data, ps, pe, trap)
        elif tag in (PDU_TRAP_V2, PDU_INFORM):
            trap.is_inform = (tag == PDU_INFORM)
            self._read_trap_v2(data, ps, pe, trap)
        else:
            self.stats["not_a_trap"] += 1              # a GET aimed at port 162
            return None

        self._finish(trap)
        self.stats["traps"] += 1
        return trap

    def _read_trap_v1(self, data, ps, pe, trap):
        pdu = Reader(data, ps, pe)
        s, e = pdu.expect(T_OID);          trap.enterprise = _oid(data, s, e)
        tag, s, e = pdu.read_tlv();        trap.agent_addr = _ipv4(data, s, e)
        s, e = pdu.expect(T_INTEGER);      trap.generic = _clamp_int32(_signed(data, s, e))
        s, e = pdu.expect(T_INTEGER);      trap.specific = _clamp_int32(_signed(data, s, e))
        tag, s, e = pdu.read_tlv();        trap.uptime = _clamp_uint32(_unsigned(data, s, e))
        vtag_start = pdu.pos
        vs, ve = pdu.expect(T_SEQUENCE)
        trap.varbinds_tlv_span = (vtag_start, ve)
        trap.varbinds = self._read_varbinds(data, vs, ve)

        # RFC 3584 3.1: map the v1 identity onto the v2 snmpTrapOID space, so
        # the two versions are one searchable, alertable axis rather than two.
        generic = trap.generic if trap.generic is not None else 6
        if 0 <= generic <= 5:
            trap.trap_oid = f"1.3.6.1.6.3.1.1.5.{generic + 1}"
            trap.trap_kind = GENERIC_NAMES[generic]
        else:
            base = trap.enterprise or "1.3.6.1.4.1"
            if not base.endswith(".0"):
                base += ".0"
            trap.trap_oid = f"{base}.{trap.specific or 0}"
            trap.trap_kind = "enterpriseSpecific"

    def _read_trap_v2(self, data, ps, pe, trap):
        pdu = Reader(data, ps, pe)
        s, e = pdu.expect(T_INTEGER);  trap.request_id = _clamp_int32(_signed(data, s, e))
        pdu.expect(T_INTEGER)          # error-status, always 0 in a trap
        pdu.expect(T_INTEGER)          # error-index,  always 0 in a trap
        vtag_start = pdu.pos
        vs, ve = pdu.expect(T_SEQUENCE)
        trap.varbinds_tlv_span = (vtag_start, ve)
        trap.varbinds = self._read_varbinds(data, vs, ve)

        for vb in trap.varbinds:
            if vb["oid"] == SYS_UPTIME_0 and not trap.uptime:
                try:
                    trap.uptime = _clamp_uint32(int(vb["value"]))
                except (TypeError, ValueError):
                    pass
            elif vb["oid"] == SNMP_TRAP_OID_0 and not trap.trap_oid:
                trap.trap_oid = str(vb["value"] or "")
            elif vb["oid"] == SNMP_TRAP_ENTERPRISE_0 and not trap.enterprise:
                trap.enterprise = str(vb["value"] or "")

        # Some agents omit the mandatory pair, or send them out of order. Fall
        # back to positional reading rather than storing a trap with no identity.
        if not trap.trap_oid and len(trap.varbinds) >= 2:
            second = trap.varbinds[1]
            if second["type"] == "OID":
                trap.trap_oid = str(second["value"] or "")
        trap.trap_kind = KIND_BY_OID.get(trap.trap_oid, "enterpriseSpecific")

    def _read_varbinds(self, data, start, end) -> list[dict]:
        out = []
        walker = Reader(data, start, end)
        while not walker.at_end():
            try:
                bs, be = walker.expect(T_SEQUENCE)
            except BerError:
                break                       # trailing junk: keep what we have
            if len(out) >= self.max_varbinds:
                self.stats["too_many_varbinds"] += 1
                break
            pair = Reader(data, bs, be)
            try:
                os_, oe = pair.expect(T_OID)
                oid = _oid(data, os_, oe)
                if pair.at_end():
                    kind, text, value = "NULL", "", None
                else:
                    tag, vs, ve = pair.read_tlv()
                    kind, text, value = _decode_value(data, tag, vs, ve, self.max_value_chars)
            except BerError:
                continue                    # one bad varbind must not lose the trap
            out.append({"oid": oid, "name": self.resolve_oid(oid),
                       "type": kind, "value": value,
                       "text": enum_text(oid, kind, value, text)})
        return out

    def _finish(self, trap: Trap) -> None:
        trap.trap_name = self.resolve_oid(trap.trap_oid)
        if not trap.trap_kind:
            trap.trap_kind = KIND_BY_OID.get(trap.trap_oid, "enterpriseSpecific")
        trap.severity = self.severity_for(trap.trap_oid)
        parts = [f"{vb['name']}={vb['text']}" for vb in trap.varbinds]
        trap.varbind_text = " ".join(parts)[:4000]

    # -------------------------------------------------------------- v3

    def _decode_v3(self, data, msg, source, now):
        hs, he = msg.expect(T_SEQUENCE)                # msgGlobalData
        header = Reader(data, hs, he)
        header.expect(T_INTEGER)                       # msgID
        header.expect(T_INTEGER)                       # msgMaxSize
        fs, fe = header.expect(T_OCTET_STRING)         # msgFlags
        flags = data[fs] if fe > fs else 0
        header.expect(T_INTEGER)                       # msgSecurityModel

        auth = bool(flags & 0x01)
        priv = bool(flags & 0x02)

        ss, se = msg.expect(T_OCTET_STRING)            # msgSecurityParameters
        usm = Reader(data, ss, se)
        us, ue = usm.expect(T_SEQUENCE)
        params = Reader(data, us, ue)
        es, ee = params.expect(T_OCTET_STRING)         # engine id
        params.expect(T_INTEGER)                       # engine boots
        params.expect(T_INTEGER)                       # engine time
        ns, ne = params.expect(T_OCTET_STRING)         # user name
        as_, ae = params.expect(T_OCTET_STRING)        # auth params (offsets kept!)
        params.expect(T_OCTET_STRING)                  # privacy params

        trap = Trap(ts=now, source=source, version=V3, raw=data,
                   engine_id=data[es:ee].hex(),
                   community=data[ns:ne].decode("utf-8", "replace"),
                   security=("authPriv" if priv else
                             "authNoPriv" if auth else "noAuthNoPriv"))

        if auth:
            trap.auth_state = self._verify_v3(data, trap, as_, ae)
        else:
            trap.auth_state = "unverified"
            self.stats["v3_unverified"] += 1

        if priv:
            # The scoped PDU is encrypted. Everything above is in the clear
            # and is worth storing: who sent it, from which engine, as which
            # user.
            #
            # Not decrypted here — yet. The poller speaks AES-128-CFB (RFC
            # 3826) since 5.8.0 through netpath/snmpcrypt.py, and that
            # module was written as a leaf precisely so this decoder can
            # use it without a cycle; wiring it in — a privacy password per
            # v3 trap user, the key localised to the SENDER's engine id off
            # the wire, and decryptionErrors accounting — is a deliberate
            # follow-up. Until then an authPriv trap is stored with
            # everything the header carries in the clear and flagged in
            # the UI, as it always was.
            self.stats["v3_encrypted"] += 1
            trap.auth_state = "encrypted"
            trap.trap_oid = ""
            trap.trap_kind = "encrypted"
            trap.trap_name = "encrypted (authPriv) — not decoded"
            trap.severity = 5
            trap.varbind_text = ""
            return trap

        ds, de = msg.expect(T_SEQUENCE)                # ScopedPDU
        scoped = Reader(data, ds, de)
        scoped.expect(T_OCTET_STRING)                  # contextEngineID
        scoped.expect(T_OCTET_STRING)                  # contextName
        tag, ps, pe = scoped.read_tlv()
        if tag in (PDU_TRAP_V2, PDU_INFORM):
            trap.is_inform = (tag == PDU_INFORM)
            self._read_trap_v2(data, ps, pe, trap)
        elif tag == PDU_TRAP_V1:
            self._read_trap_v1(data, ps, pe, trap)
        elif tag == PDU_REPORT:
            # Engine discovery from a manager. Nothing to store.
            self.stats["not_a_trap"] += 1
            return None
        else:
            self.stats["not_a_trap"] += 1
            return None

        self._finish(trap)
        self.stats["traps"] += 1
        return trap

    def _localized_key(self, proto: str, password: str, engine_id: bytes) -> bytes | None:
        return localized_key(proto, password, engine_id)

    def _verify_v3(self, data, trap, auth_start, auth_end) -> str:
        entry = self.users.get(trap.community)
        if entry is None:
            self.stats["v3_no_user"] += 1
            return "unverified"
        proto, password = entry
        spec = AUTH_PROTOCOLS.get(proto)
        if spec is None:
            return "unverified"
        ctor, digest_len = spec
        engine = bytes.fromhex(trap.engine_id) if trap.engine_id else b""
        key = self._localized_key(proto, password, engine)
        if key is None:
            return "unverified"
        sent = data[auth_start:auth_end]
        if len(sent) != digest_len:
            self.stats["v3_auth_failed"] += 1
            return "failed"
        blanked = bytearray(data)
        blanked[auth_start:auth_end] = b"\x00" * digest_len
        computed = hmac.new(key, bytes(blanked), ctor).digest()[:digest_len]
        if hmac.compare_digest(computed, sent):
            self.stats["v3_auth_ok"] += 1
            return "ok"
        self.stats["v3_auth_failed"] += 1
        return "failed"


# --------------------------------------------------------------------- encode

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def enc_int(n: int) -> bytes:
    n = int(n)
    size = max(1, (n.bit_length() + 8) // 8) if n >= 0 else \
           max(1, ((~n).bit_length() + 8) // 8)
    return _tlv(T_INTEGER, n.to_bytes(size, "big", signed=True))


def enc_unsigned(tag: int, n: int) -> bytes:
    n = max(0, int(n))
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body           # keep it unambiguously non-negative
    return _tlv(tag, body)


def enc_octets(value) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(T_OCTET_STRING, value)


def enc_oid(oid: str) -> bytes:
    arcs = [int(a) for a in str(oid).strip(".").split(".") if a != ""]
    if len(arcs) < 2:
        arcs = [1, 3]
    body = bytearray()
    first = arcs[0] * 40 + arcs[1]
    for value in [first, *arcs[2:]]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        body.extend(reversed(chunk))
    return _tlv(T_OID, bytes(body))


def enc_varbind(oid: str, value_bytes: bytes) -> bytes:
    return _tlv(T_SEQUENCE, enc_oid(oid) + value_bytes)


def build_v2c_trap(community: str, trap_oid: str, uptime_ticks: int,
                   varbinds=None, request_id: int = 1) -> bytes:
    """A minimal but wholly valid SNMPv2c Trap-PDU: the mandatory
    sysUpTime.0 / snmpTrapOID.0 pair followed by anything extra."""
    body = enc_varbind(SYS_UPTIME_0, enc_unsigned(T_TIMETICKS, uptime_ticks))
    body += enc_varbind(SNMP_TRAP_OID_0, enc_oid(trap_oid))
    for oid, value_bytes in (varbinds or []):
        body += enc_varbind(oid, value_bytes)
    pdu = _tlv(PDU_TRAP_V2,
               enc_int(request_id) + enc_int(0) + enc_int(0) +
               _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(community) + pdu)


def build_v1_trap(community: str, enterprise: str, agent_addr: str,
                  generic: int, specific: int, uptime_ticks: int,
                  varbinds=None) -> bytes:
    try:
        addr = socket.inet_pton(socket.AF_INET, agent_addr or "127.0.0.1")
    except OSError:
        addr = b"\x7f\x00\x00\x01"
    body = b"".join(enc_varbind(o, v) for o, v in (varbinds or []))
    pdu = _tlv(PDU_TRAP_V1,
               enc_oid(enterprise) + _tlv(T_IPADDRESS, addr) +
               enc_int(generic) + enc_int(specific) +
               enc_unsigned(T_TIMETICKS, uptime_ticks) +
               _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V1) + enc_octets(community) + pdu)


def build_inform_response(version: int, community: str, request_id: int,
                          varbind_list_raw: bytes) -> bytes:
    """RFC 3416: acknowledge an InformRequest with a Response-PDU carrying
    the same request-id and the same varbinds. The varbind bytes are spliced
    back verbatim from the request (its full TLV, tag byte included), so
    nothing can be lost re-encoding them."""
    pdu = _tlv(PDU_RESPONSE,
               enc_int(request_id) + enc_int(0) + enc_int(0) + varbind_list_raw)
    return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(community) + pdu)


# ---------------------------------------------------------------------------
# SNMP OID names, enum tables, and default severity rules.
#
# A name table, not a MIB compiler: parsing SMIv1/SMIv2 ASN.1 modules is a
# parser project of its own and out of scope for a stdlib-only app. This
# table plus the admin-editable `oid_names` setting (see Decoder.configure)
# covers the traps a site actually cares about.
# ---------------------------------------------------------------------------

WELL_KNOWN = {
    # -------------------------------------------------- SNMPv2-MIB (system)
    "1.3.6.1.2.1.1":           "system",
    "1.3.6.1.2.1.1.1":         "sysDescr",
    "1.3.6.1.2.1.1.2":         "sysObjectID",
    "1.3.6.1.2.1.1.3":         "sysUpTime",
    "1.3.6.1.2.1.1.4":         "sysContact",
    "1.3.6.1.2.1.1.5":         "sysName",
    "1.3.6.1.2.1.1.6":         "sysLocation",
    "1.3.6.1.2.1.1.7":         "sysServices",
    # --------------------------------------------- SNMPv2-MIB (trap group)
    "1.3.6.1.6.3.1.1.4.1":     "snmpTrapOID",
    "1.3.6.1.6.3.1.1.4.3":     "snmpTrapEnterprise",
    "1.3.6.1.6.3.1.1.5.1":     "coldStart",
    "1.3.6.1.6.3.1.1.5.2":     "warmStart",
    "1.3.6.1.6.3.1.1.5.3":     "linkDown",
    "1.3.6.1.6.3.1.1.5.4":     "linkUp",
    "1.3.6.1.6.3.1.1.5.5":     "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6":     "egpNeighborLoss",
    "1.3.6.1.6.3.18.1.3":      "snmpTrapAddress",
    "1.3.6.1.6.3.18.1.4":      "snmpTrapCommunity",
    # ------------------------------------------------------------- IF-MIB
    "1.3.6.1.2.1.2.2.1.1":     "ifIndex",
    "1.3.6.1.2.1.2.2.1.2":     "ifDescr",
    "1.3.6.1.2.1.2.2.1.3":     "ifType",
    "1.3.6.1.2.1.2.2.1.4":     "ifMtu",
    "1.3.6.1.2.1.2.2.1.5":     "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6":     "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7":     "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8":     "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1":  "ifName",
    "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
    # ------------------------------------------------- BRIDGE-MIB / RSTP
    "1.3.6.1.2.1.17.0.1":      "newRoot",
    "1.3.6.1.2.1.17.0.2":      "topologyChange",
    # ---------------------------------------------------------- BGP4-MIB
    "1.3.6.1.2.1.15.7.1":      "bgpEstablished",
    "1.3.6.1.2.1.15.7.2":      "bgpBackwardTransition",
    # bgpPeerRemoteAddr is .1.7 and bgpPeerState is .1.2, not the other way
    # round: a real bgpBackwardTransition rendered as
    # "bgpPeerState.198.51.100.75=198.51.100.75", which reads as a peer stuck
    # in a state that does not exist and hides the state that does.
    "1.3.6.1.2.1.15.3.1.2":    "bgpPeerState",
    "1.3.6.1.2.1.15.3.1.7":    "bgpPeerRemoteAddr",
    "1.3.6.1.2.1.15.3.1.14":   "bgpPeerLastError",
    # ----------------------------------------------------------- UPS-MIB
    "1.3.6.1.2.1.33.2.1":      "upsTrapOnBattery",
    "1.3.6.1.2.1.33.2.2":      "upsTrapTestCompleted",
    "1.3.6.1.2.1.33.2.3":      "upsTrapAlarmEntryAdded",
    "1.3.6.1.2.1.33.2.4":      "upsTrapAlarmEntryRemoved",
    # -------------------------------------------------------- ENTITY-MIB
    "1.3.6.1.2.1.47.1.1.1.1.2": "entPhysicalDescr",
    "1.3.6.1.2.1.47.1.1.1.1.7": "entPhysicalName",
    # ------------------------------------------- vendor roots (prefixes)
    "1.3.6.1.4.1.9":           "cisco",
    "1.3.6.1.4.1.9.9.41.2.0.1": "clogMessageGenerated",
    "1.3.6.1.4.1.9.9.43.2.0.1": "ciscoConfigManEvent",
    "1.3.6.1.4.1.9.9.187.0.1": "cbgpFsmStateChange",
    "1.3.6.1.4.1.232":         "hpCompaq",
    "1.3.6.1.4.1.311":         "microsoft",
    "1.3.6.1.4.1.318":         "apc",
    "1.3.6.1.4.1.674":         "dell",
    "1.3.6.1.4.1.789":         "netApp",
    "1.3.6.1.4.1.1916":        "extremeNetworks",
    "1.3.6.1.4.1.1991":        "brocade",
    "1.3.6.1.4.1.2011":        "huawei",
    "1.3.6.1.4.1.2021":        "ucdavis",
    "1.3.6.1.4.1.2636":        "juniper",
    "1.3.6.1.4.1.3375":        "f5",
    "1.3.6.1.4.1.4526":        "netgear",
    "1.3.6.1.4.1.6876":        "vmware",
    "1.3.6.1.4.1.8072":        "netSnmp",
    "1.3.6.1.4.1.12356":       "fortinet",
    "1.3.6.1.4.1.14988":       "mikrotik",
    "1.3.6.1.4.1.25461":       "paloAlto",
    "1.3.6.1.4.1.25506":       "h3c",
    "1.3.6.1.4.1.30065":       "arista",
    # --- added 4.28.0. Every arc below was read out of that vendor's own MIB
    # text (the "::= { enterprises N }" line), not from memory: a wrong arc
    # silently mislabels every device under it, which is worse than a blank
    # Vendor column. The MIB catalog shipped bundles for vendors this table
    # could not even name, so a device could have its MIB installed and still
    # show no vendor at all.
    "1.3.6.1.4.1.11":          "hp",             # HP-ICF-OID
    "1.3.6.1.4.1.161":         "motorola",       # Cambium's Canopy/PMP line
                                                 # still registers under
                                                 # Motorola's arc, so this is
                                                 # named for the arc's owner
                                                 # rather than for Cambium.
    "1.3.6.1.4.1.171":         "dlink",
    "1.3.6.1.4.1.248":         "hirschmann",
    "1.3.6.1.4.1.476":         "vertiv",         # Liebert / Emerson
    "1.3.6.1.4.1.534":         "eaton",
    "1.3.6.1.4.1.664":         "adtran",
    "1.3.6.1.4.1.890":         "zyxel",
    "1.3.6.1.4.1.2604":        "sophos",
    "1.3.6.1.4.1.2606":        "rittal",
    "1.3.6.1.4.1.2620":        "checkPoint",
    "1.3.6.1.4.1.3097":        "watchguard",
    "1.3.6.1.4.1.4413":        "broadcom",       # NETGEAR's managed switches
                                                 # run OEM'd Broadcom FASTPATH
                                                 # and report here; so do other
                                                 # FASTPATH OEMs, hence the
                                                 # arc's real owner, not
                                                 # "netgear".
    "1.3.6.1.4.1.5951":        "citrix",         # NetScaler
    "1.3.6.1.4.1.6027":        "dellNetworking", # Force10 line; 674 is the
                                                 # separate Dell/OpenManage arc
    "1.3.6.1.4.1.6574":        "synology",
    "1.3.6.1.4.1.8691":        "moxa",           # MOXA-GENERAL-MIB
    "1.3.6.1.4.1.8741":        "sonicwall",
    "1.3.6.1.4.1.11863":       "tpLink",
    "1.3.6.1.4.1.12276":       "f5Networks",     # 3375 is F5's other arc
    "1.3.6.1.4.1.13742":       "raritan",
    "1.3.6.1.4.1.14823":       "aruba",
    "1.3.6.1.4.1.25053":       "ruckus",
    "1.3.6.1.4.1.26928":       "aerohive",
    "1.3.6.1.4.1.41112":       "ubiquiti",
    "1.3.6.1.4.1.47196":       "arubaCx",        # HPE's ArubaOS-CX line
}

# The short label the table column and the kind filter show.
KIND_BY_OID = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.2.1.17.0.1":  "newRoot",
    "1.3.6.1.2.1.17.0.2":  "topologyChange",
    "1.3.6.1.2.1.15.7.1":  "bgpEstablished",
    "1.3.6.1.2.1.15.7.2":  "bgpBackwardTransition",
    "1.3.6.1.2.1.33.2.1":  "upsOnBattery",
}

# Every kind the filter dropdown offers, in the order it offers them.
KINDS = ["coldStart", "warmStart", "linkDown", "linkUp",
         "authenticationFailure", "egpNeighborLoss", "newRoot",
         "topologyChange", "bgpEstablished", "bgpBackwardTransition",
         "upsOnBattery", "enterpriseSpecific", "encrypted"]

# Longest prefix wins; the decoder re-sorts after appending user rules.
# The scale is syslog's, deliberately: 0 emergency … 7 debug. A future
# alerting engine can then treat a trap and a syslog line as the same kind of
# thing without translating between two severity vocabularies.
DEFAULT_SEVERITY_RULES = [
    ("1.3.6.1.6.3.1.1.5.1", 4),   # coldStart            -> warning
    ("1.3.6.1.6.3.1.1.5.2", 4),   # warmStart            -> warning
    ("1.3.6.1.6.3.1.1.5.3", 3),   # linkDown             -> error
    ("1.3.6.1.6.3.1.1.5.4", 5),   # linkUp               -> notice
    ("1.3.6.1.6.3.1.1.5.5", 4),   # authenticationFailure-> warning
    ("1.3.6.1.6.3.1.1.5.6", 3),   # egpNeighborLoss      -> error
    ("1.3.6.1.2.1.15.7.1",  5),   # bgpEstablished       -> notice
    ("1.3.6.1.2.1.15.7.2",  3),   # bgpBackwardTransition-> error
    ("1.3.6.1.2.1.17.0.1",  4),   # newRoot              -> warning
    ("1.3.6.1.2.1.17.0.2",  5),   # topologyChange       -> notice
    ("1.3.6.1.2.1.33.2.1",  2),   # upsTrapOnBattery     -> critical
]

# The shortest OID that can be a table column here (1.3.6.1.2.1.x.y.1.z is
# seven arcs), so walking back through a varbind's instance index can never
# reach so far up the tree that it matches an unrelated table.
MIN_COLUMN_ARCS = 7

# Enum-valued objects worth showing by name rather than as a bare number.
ENUMS = {
    "1.3.6.1.2.1.2.2.1.7": {1: "up", 2: "down", 3: "testing"},          # ifAdminStatus
    "1.3.6.1.2.1.2.2.1.8": {1: "up", 2: "down", 3: "testing",
                            4: "unknown", 5: "dormant", 6: "notPresent",
                            7: "lowerLayerDown"},                        # ifOperStatus
    "1.3.6.1.2.1.15.3.1.2": {1: "idle", 2: "connect", 3: "active",
                             4: "opensent", 5: "openconfirm",
                             6: "established"},                          # bgpPeerState
}


def enum_text(oid: str, kind: str, value, fallback: str) -> str:
    """Name a numeric enum where one is known: 'down (2)' rather than '2'.

    A varbind names a column plus its instance index, and the index is not
    always one arc: ifOperStatus.7 has one, but bgpPeerState is indexed by the
    peer's IP address, so the instance is four. Stripping a single arc found
    the column for the first and never for the second, which is why the BGP
    state was rendered as a bare number even once its OID was right. Walk the
    prefixes instead, shortest index first, stopping well before the arcs that
    make up the column itself.
    """
    if kind != "INTEGER":
        return fallback
    table = ENUMS.get(oid)
    arcs = oid.split(".")
    # An instance index of more than eight arcs is not something any of these
    # tables uses, and MIN_COLUMN_ARCS keeps the walk from reaching up into
    # the OID tree far enough to hit an unrelated table.
    for depth in range(1, 9):
        if table or len(arcs) - depth < MIN_COLUMN_ARCS:
            break
        table = ENUMS.get(".".join(arcs[:len(arcs) - depth]))
    if not table:
        return fallback
    try:
        name = table.get(int(value) if value is not None else None)
    except (TypeError, ValueError):
        return fallback
    return f"{name} ({value})" if name else fallback


if __name__ == "__main__":
    # Round-trip self-test: encode a trap, decode it back, confirm the fields
    # survive. Validates both halves of the BER code against each other with
    # no network/socket involved.
    d = Decoder()

    v2c_packet = build_v2c_trap(
        "public", "1.3.6.1.6.3.1.1.5.3", 12345,
        [("1.3.6.1.2.1.2.2.1.1", enc_int(7)),
         ("1.3.6.1.2.1.2.2.1.2", enc_octets("eth0"))])
    trap = d.decode(v2c_packet, "127.0.0.1")
    assert trap is not None, "v2c decode failed"
    assert trap.version == V2C
    assert trap.trap_oid == "1.3.6.1.6.3.1.1.5.3"
    assert trap.trap_name == "linkDown"
    assert trap.uptime == 12345
    # sysUpTime.0 and snmpTrapOID.0 are always present as varbinds[0:2] per
    # the wire format, followed by the two extra varbinds this test added.
    assert len(trap.varbinds) == 4
    assert trap.varbinds[2]["oid"] == "1.3.6.1.2.1.2.2.1.1"
    assert trap.varbinds[2]["value"] == 7
    assert trap.varbinds[3]["value"] == "eth0"
    print("v2c round trip OK:", trap.trap_name, trap.varbind_text)

    v1_packet = build_v1_trap(
        "public", "1.3.6.1.4.1.9", "10.0.0.1", generic=0, specific=0,
        uptime_ticks=99)
    trap = d.decode(v1_packet, "127.0.0.1")
    assert trap is not None, "v1 decode failed"
    assert trap.version == V1
    assert trap.trap_oid == "1.3.6.1.6.3.1.1.5.1"
    assert trap.trap_name == "coldStart"
    assert trap.agent_addr == "10.0.0.1"
    assert trap.enterprise == "1.3.6.1.4.1.9"
    print("v1 round trip OK:", trap.trap_name, trap.agent_addr)

    print("all self-tests passed")

"""The parts of SNMPv3 privacy that are ours and need no cipher at all —
so this suite never skips, whatever `cryptography` is installed here.

  1. RFC 3414 A.3.1/A.3.2 known answers for localized_key (password
     `maplesyrup`, engine 000000000000000000000002) — the derivation every
     signed request has depended on since 4.x, and its first ever test;
  2. the privacy key is the FIRST 16 bytes of the auth protocol's
     localised key, for MD5, SHA and every SHA-2 (RFC 3826 s1.2) — never
     the last, never a fold;
  3. THE PINNED BYTES: build_v3_request with no privacy arguments produces
     exactly the bytes 5.7.2 produced, hex computed from that commit and
     pasted here. This is what proves the 5.8.0 upgrade changes no request
     an existing install sends;
  4. the RFC 3826 IV is boots || time || salt — with inputs wide enough
     that a mask narrower than 32 bits gives a different answer — salts
     never repeat, not even across threads racing for them, and are never
     all-zero, and the salt generator is not the `random` module;
  5. a privacy key without an auth key is refused, not downgraded;
  6. the availability guard reports "unavailable" against a backend that
     panics — a BaseException, not an ImportError — rather than crashing,
     and recovers on recheck; and against a backend that round-trips
     cleanly but is not AES-128-CFB (the known answer, not a bare round
     trip, is the probe);
  7. security_level and Credential.security_level derive the level the
     same way, and the label names it;
  8. the digest length a reply is checked against comes from the
     configured protocol, never from the reply itself, and
     SnmpDowngrade is not an SnmpAuthError.
"""
import hmac
import os
import sys
import threading

import _paths  # noqa: F401  (puts the repo root on sys.path)

from netpath import snmpcrypt
from netpath.nodepoll import (
    Credential, _credential_label, access_denied_advice, security_level)
from netpath.snmppoll import (
    FLAG_AUTH, SnmpAuthError, SnmpDowngrade, SnmpError, _v3_message,
    build_v3_request, decode_response, discovery_probe, find_auth_span,
    scoped_pdu)
from netpath.trapdecode import (
    AUTH_PROTOCOLS, PDU_GET, PDU_GETBULK, localized_key, privacy_key)

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ===================================== § 1 RFC 3414 A.3 known answers

print("\n-- RFC 3414 A.3.1 / A.3.2: password 'maplesyrup', engine ...0002")
ENGINE_A3 = bytes.fromhex("000000000000000000000002")
check("A.3.1 MD5: localized key 526f5eed9fcce26f8964c2930787d82b",
      localized_key("MD5", "maplesyrup", ENGINE_A3).hex()
      == "526f5eed9fcce26f8964c2930787d82b",
      localized_key("MD5", "maplesyrup", ENGINE_A3).hex())
check("A.3.2 SHA: localized key 6695febc9288e36282235fc7151f128497b38f3f",
      localized_key("SHA", "maplesyrup", ENGINE_A3).hex()
      == "6695febc9288e36282235fc7151f128497b38f3f",
      localized_key("SHA", "maplesyrup", ENGINE_A3).hex())
check("SHA1 is the same protocol as SHA",
      localized_key("SHA1", "maplesyrup", ENGINE_A3)
      == localized_key("SHA", "maplesyrup", ENGINE_A3))
check("a different engine gives a different key (localisation is real)",
      localized_key("SHA", "maplesyrup", ENGINE_A3 + b"\x01")
      != localized_key("SHA", "maplesyrup", ENGINE_A3))
check("an unknown protocol or an empty password yields None, never a key",
      localized_key("DES", "maplesyrup", ENGINE_A3) is None
      and localized_key("SHA", "", ENGINE_A3) is None)


# ===================================== § 2 the privacy key

print("\n-- privacy key == localized_key(auth proto, priv password)[:16]")
ENGINE = bytes.fromhex("80001f8880abcdef0123")
for proto, digest_bytes in (("MD5", 16), ("SHA", 20), ("SHA224", 28),
                            ("SHA256", 32), ("SHA384", 48), ("SHA512", 64)):
    full = localized_key(proto, "privpassword", ENGINE)
    key = privacy_key(proto, "privpassword", ENGINE)
    check(f"{proto}: the localised key is {digest_bytes} bytes and the privacy "
          f"key is its FIRST 16",
          len(full) == digest_bytes and key == full[:16] and len(key) == 16,
          (len(full), key.hex() if key else None))
    if digest_bytes > 16:
        check(f"{proto}: ...not the last 16, and not a fold",
              key != full[-16:] and
              key != bytes(a ^ b for a, b in zip(full[:16], full[16:32].ljust(16, b"\0"))))
check("the privacy key is derived with the AUTH protocol's hash — a different "
      "auth protocol on the same privacy password gives a different key",
      privacy_key("MD5", "privpassword", ENGINE) != privacy_key("SHA", "privpassword", ENGINE))
check("privacy_key reuses the localized_key cache (same object back)",
      privacy_key("SHA", "privpassword", ENGINE)
      == localized_key("SHA", "privpassword", ENGINE)[:16])
check("no password, no key", privacy_key("SHA", "", ENGINE) is None)


# ===================================== § 3 the pinned bytes

print("\n-- build_v3_request without privacy is byte-identical to 5.7.2")
# Every hex below was printed by netpath.snmppoll at commit 38e679c (5.7.2)
# before any of this change existed. If one of these ever differs, an
# upgrade changed a request that every existing install sends.
PINNED = {
    "SHA GET, boots 7, time 1234, msg 1, req 1": (
        "306d020103300e020101020300ffe3040101020103042d302b040a80001f8880abcdef01230201"
        "07020204d20406706f6c6c6572040c81013e687048570dd2d548ab04003029040a80001f8880ab"
        "cdef01230400a019020101020100020100300e300c06082b060102010103000500"),
    "MD5 GETBULK x25, two OIDs, msg 0x1234, req 0x5678": (
        "307e020103300f02021234020300ffe3040101020103042c302a040a80001f8880abcdef0123"
        "0201030201630406706f6c6c6572040c961b44c2860478ec2a6572e80400303a040a80001f88"
        "80abcdef01230400a52a02025678020100020119301e300d06092b06010201020201020500300d"
        "06092b060102010202010a0500"),
    "noAuthNoPriv GET, user 'ro'": (
        "305c020103300e020105020300ffe3040100020103041c301a040a80001f8880abcdef012302"
        "01010201020402726f040004003029040a80001f8880abcdef01230400a019020106020100020100"
        "300e300c06082b060102010101000500"),
    "discovery probe": (
        "3038020103300e020101020300ffe30401040201030410300e0400020100020100040004000400"
        "301104000400a00b0201000201000201003000"),
}
built = {
    "SHA GET, boots 7, time 1234, msg 1, req 1": build_v3_request(
        1, 1, PDU_GET, ["1.3.6.1.2.1.1.3.0"], engine_id=ENGINE, engine_boots=7,
        engine_time=1234, user="poller", auth_proto="SHA",
        auth_key=localized_key("SHA", "authpassword", ENGINE)),
    "MD5 GETBULK x25, two OIDs, msg 0x1234, req 0x5678": build_v3_request(
        0x1234, 0x5678, PDU_GETBULK, ["1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.10"],
        engine_id=ENGINE, engine_boots=3, engine_time=99, user="poller",
        auth_proto="MD5", auth_key=localized_key("MD5", "authpassword", ENGINE),
        non_repeaters=0, max_repetitions=25),
    "noAuthNoPriv GET, user 'ro'": build_v3_request(
        5, 6, PDU_GET, ["1.3.6.1.2.1.1.1.0"], engine_id=ENGINE, engine_boots=1,
        engine_time=2, user="ro"),
    "discovery probe": discovery_probe(),
}
for name, expected in PINNED.items():
    check(f"pinned: {name}", built[name].hex() == expected, built[name].hex())
check("find_auth_span is unchanged: the digest field of the pinned SHA message "
      "is 12 bytes and non-zero",
      (lambda s, e: e - s == 12 and built["SHA GET, boots 7, time 1234, msg 1, req 1"][s:e] != bytes(12))(
          *find_auth_span(built["SHA GET, boots 7, time 1234, msg 1, req 1"])))
reply = decode_response(built["noAuthNoPriv GET, user 'ro'"])
check("decode_response on a no-priv message still works with no keys given "
      "(flags 0, nothing verified, nothing to verify)",
      reply.flags == 0 and reply.auth_verified is False and reply.priv_params == b""
      and reply.user == "ro", reply)


# ===================================== § 4 the IV and the salt

print("\n-- RFC 3826 s3.1.2.1: IV = boots(4) || time(4) || salt(8)")
salt = bytes.fromhex("0102030405060708")
iv = snmpcrypt.iv_for(7, 1234, salt)
check("boots 7, time 1234 → 00000007 000004d2, then the salt",
      iv == bytes.fromhex("00000007" "000004d2") + salt and len(iv) == 16, iv.hex())
check("boots and time are masked to 32 bits like the wire field",
      snmpcrypt.iv_for(2 ** 32 + 7, 2 ** 33 + 1234, salt) == iv)
# Inputs that need all 32 bits: boots 7 and time 1234 fit in 16, so a
# mask narrowed to 16 bits would pass the check above and break every
# device with over ~18 h of uptime (65536 s) in production.
wide = snmpcrypt.iv_for(0x00010007, 0x000204D2, salt)
check("boots 0x00010007, time 0x000204d2 keep their high halves: the mask "
      "is 32 bits, not 16",
      wide == bytes.fromhex("00010007" "000204d2") + salt, wide.hex())
check("...and the full 32-bit range survives too (0xffffffff twice)",
      snmpcrypt.iv_for(0xFFFFFFFF, 0xFFFFFFFF, salt)
      == bytes.fromhex("ffffffff" "ffffffff") + salt)
try:
    snmpcrypt.iv_for(1, 1, b"short")
    check("a salt of the wrong length is a PrivError", False)
except snmpcrypt.PrivError:
    check("a salt of the wrong length is a PrivError", True)

salts = {snmpcrypt.next_salt() for _ in range(10_000)}
check("10,000 next_salt() calls give 10,000 distinct salts",
      len(salts) == 10_000, len(salts))
check("...none all-zero, all 8 bytes",
      all(len(s) == 8 and s != bytes(8) for s in salts))

# The salt counter's read-modify-write is guarded by a lock, and that lock
# is the one thing in this module that must not be wrong: two poll workers
# drawing the same salt under one key is the IV reuse the whole design
# exists to rule out. A single-threaded loop cannot tell whether the lock
# is there, so this one races eight threads for the counter with the
# interpreter switching as often as it can, and asks for every salt to be
# distinct. Without the lock, dozens repeat.
THREADS, PER_THREAD = 8, 20_000
drawn: list[list[bytes]] = [[] for _ in range(THREADS)]
start = threading.Barrier(THREADS)


def draw(bucket: list) -> None:
    start.wait()
    bucket.extend(snmpcrypt.next_salt() for _ in range(PER_THREAD))


previous_interval = sys.getswitchinterval()
sys.setswitchinterval(1e-6)
try:
    workers = [threading.Thread(target=draw, args=(bucket,)) for bucket in drawn]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
finally:
    sys.setswitchinterval(previous_interval)
raced = [s for bucket in drawn for s in bucket]
check(f"{THREADS} threads x {PER_THREAD} next_salt() calls, racing, give "
      f"{THREADS * PER_THREAD} distinct salts (the _salt_lock is load-bearing)",
      len(set(raced)) == len(raced) == THREADS * PER_THREAD,
      f"{len(raced) - len(set(raced))} repeated")
src = open(os.path.join(_paths.REPO_ROOT, "netpath", "snmpcrypt.py"), encoding="utf-8").read()
check("snmpcrypt does not import `random` (that seeds request ids; wrong for an IV)",
      "import random" not in src and "os.urandom" in src)
import ast  # noqa: E402  — the real imports, not the docstring's prose about them
imported = set()
for node in ast.walk(ast.parse(src)):
    if isinstance(node, ast.Import):
        imported.update(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom):
        imported.add(("." * node.level) + (node.module or ""))
check("snmpcrypt imports nothing from netpath — a leaf module",
      not any(name.startswith((".", "netpath")) for name in imported), sorted(imported))
check("...only cryptography and the standard library",
      imported <= {"__future__", "os", "struct", "threading", "warnings",
                   "cryptography.hazmat.primitives.ciphers",
                   "cryptography.hazmat.decrepit.ciphers.modes",
                   "cryptography.hazmat.primitives.ciphers.modes",
                   # the deprecation-warning category the CFB fallback
                   # silences; still cryptography, still not ours
                   "cryptography.utils"}, sorted(imported))
check("...and says what it is not: not a crypto library, no key generation, "
      "one construction",
      "not a cryptographic library" in src and "derives no keys" in src
      and "exactly one construction" in src)


# ===================================== § 5 privacy requires authentication

print("\n-- USM has no privNoAuth")
try:
    build_v3_request(1, 1, PDU_GET, ["1.3.6.1.2.1.1.3.0"], engine_id=ENGINE,
                     engine_boots=1, engine_time=1, user="u",
                     priv_proto="AES", priv_key=b"k" * 16)
    check("a privacy key without an auth key raises rather than building authNoPriv", False)
except SnmpError as exc:
    check("a privacy key without an auth key raises rather than building authNoPriv",
          "authentication password" in str(exc) and "privacy" in str(exc), str(exc))


# ===================================== § 6 the availability guard

print("\n-- available() against a backend that panics")


class Panic(BaseException):
    """What pyo3 raises from a broken Rust backend: not an Exception."""


real_loader = snmpcrypt._load_backend
was = snmpcrypt.available()


def broken():
    raise Panic("Python API call failed")


snmpcrypt._load_backend = broken
try:
    verdict = snmpcrypt.available(recheck=True)
    check("a BaseException from the backend makes available() False, not a crash",
          verdict is False)
    check("...and the reason is kept for the operator's message",
          "Panic" in snmpcrypt.unavailable_reason(), snmpcrypt.unavailable_reason())
    check("...and cached: a second call without recheck does not re-import",
          snmpcrypt.available() is False)
    try:
        snmpcrypt.encrypt(b"k" * 16, 1, 1, b"x")
        check("encrypt() on an unusable backend is a PrivError", False)
    except snmpcrypt.PrivError as exc:
        check("encrypt() on an unusable backend is a PrivError naming the package",
              "cryptography" in str(exc) and "restart the worker" in str(exc), str(exc))
finally:
    snmpcrypt._load_backend = real_loader
check("recheck=True after the fix restores whatever this machine really has "
      "('install it, then restart the worker' without an app restart)",
      snmpcrypt.available(recheck=True) is was)


class _StreamCipher:
    """A backend that round-trips perfectly and is not AES-CFB: a keystream
    from key and IV, XORed in. Length-preserving, decrypt(encrypt(x)) == x,
    so a probe that only asked for a round trip would bless it — and would
    bless a real backend in CFB8 mode, or with a swapped byte order, just
    the same. The known answer is what tells THIS cipher from those."""

    def __init__(self, algorithm, mode):
        self._stream = bytes((k + i + n) & 0xFF for n, (k, i) in enumerate(
            zip(algorithm.key * 16, mode.iv * 16)))

    def encryptor(self):
        return self

    decryptor = encryptor

    def update(self, data):
        return bytes(b ^ s for b, s in zip(data, self._stream))

    @staticmethod
    def finalize():
        return b""


class _Key:
    def __init__(self, key):
        self.key = key


class _IV:
    def __init__(self, iv):
        self.iv = iv


snmpcrypt._load_backend = lambda: (_StreamCipher, _Key, _IV)
try:
    check("a backend that round-trips but is not AES-128-CFB fails the known-"
          "answer probe: available() is False...",
          snmpcrypt.available(recheck=True) is False)
    check("...and the reason names the known-answer test",
          "known-answer" in snmpcrypt.unavailable_reason(), snmpcrypt.unavailable_reason())
finally:
    snmpcrypt._load_backend = real_loader
snmpcrypt.available(recheck=True)


# ===================================== § 8 the digest length, and the types

print("\n-- the digest length is the protocol's, not the reply's")
# A reply whose auth field is shorter than the protocol's digest. If the
# receiver took the length from the field it was handed, an EMPTY field
# would verify — HMAC(...)[:0] == b"" — and a one-byte one would fall to a
# 1-in-256 guess. The message is assembled by hand with the short
# placeholder and signed over that, so the only thing wrong with it is
# the length; neither may verify.
for short_len in (0, 1):
    message = _v3_message(1, flags=FLAG_AUTH, engine_id=ENGINE, engine_boots=1,
                          engine_time=1, user="poller", auth_placeholder_len=short_len,
                          priv_params=b"",
                          scoped=scoped_pdu(PDU_GET, 1, ["1.3.6.1.2.1.1.3.0"],
                                            context_engine_id=ENGINE))
    if short_len:
        s, e = find_auth_span(message)
        digest = hmac.new(localized_key("SHA", "authpassword", ENGINE),
                          message, AUTH_PROTOCOLS["SHA"][0]).digest()[:short_len]
        message = message[:s] + digest + message[e:]
    try:
        decode_response(message, auth_proto="SHA",
                        auth_key=localized_key("SHA", "authpassword", ENGINE))
        check(f"a {short_len}-byte auth field on a SHA reply is refused", False)
    except SnmpAuthError:
        check(f"a {short_len}-byte auth field on a SHA reply is refused (SHA "
              f"means 12, and the reply does not get to say otherwise)", True)
check("SnmpDowngrade is its own type: not an SnmpAuthError, and not the other "
      "way round either — the two have different remedies",
      not issubclass(SnmpDowngrade, SnmpAuthError)
      and not issubclass(SnmpAuthError, SnmpDowngrade)
      and issubclass(SnmpDowngrade, SnmpError))


# ===================================== § 7 the derived level

print("\n-- the level is derived, never stored")
base = {"snmp_version": 3, "v3_user": "poller"}
auth = dict(base, v3_auth_proto="SHA", v3_auth_pass_enc=b"blob")
priv = dict(auth, v3_priv_proto="AES", v3_priv_pass_enc=b"blob2")
check("no pair → noAuthNoPriv; auth pair → authNoPriv; both → authPriv",
      security_level(base) == "noAuthNoPriv" and security_level(auth) == "authNoPriv"
      and security_level(priv) == "authPriv")
check("a privacy pair with no auth pair is NOT a level: noAuthNoPriv from config...",
      security_level(dict(base, v3_priv_proto="AES", v3_priv_pass_enc=b"x")) == "noAuthNoPriv")
check("...a protocol without a blob, or a blob without a protocol, is no pair",
      security_level(dict(auth, v3_priv_proto="AES")) == "authNoPriv"
      and security_level(dict(auth, v3_priv_pass_enc=b"x")) == "authNoPriv")
check("the two new columns absent (a pre-5.8.0 row) derive what 5.7.2 derived",
      security_level({k: v for k, v in auth.items()}) == "authNoPriv")
cred = Credential("poller", "SHA", "pw", "AES", "pw2")
check("Credential.security_level agrees with security_level",
      cred.security_level == "authPriv"
      and Credential("poller", "SHA", "pw").security_level == "authNoPriv"
      and Credential("poller", None, None).security_level == "noAuthNoPriv"
      and Credential("poller", None, None, "AES", "pw2").security_level == "noAuthNoPriv")
check("Credential[0] is still the identity, and the old 3-name unpack fails loudly",
      cred[0] == "poller" and len(cred) == 5)
try:
    _a, _b, _c = cred
    check("three-name unpack of a Credential raises ValueError", False)
except ValueError:
    check("three-name unpack of a Credential raises ValueError", True)
check("_credential_label names the level, from config or as given",
      _credential_label(priv) == "SNMPv3 user 'poller' at authPriv"
      and _credential_label(auth) == "SNMPv3 user 'poller' at authNoPriv"
      and _credential_label(auth, "authPriv") == "SNMPv3 user 'poller' at authPriv",
      _credential_label(priv))
text = access_denied_advice(auth, "authNoPriv")
check("the authNoPriv advice now says to set the privacy protocol and password, "
      "and no longer says authPriv is unimplemented",
      "privacy protocol (AES)" in text and "authPriv" in text
      and "not implemented" not in text and "cannot yet" not in text, text)
text = access_denied_advice(priv, "authPriv")
check("the authPriv advice says neither password is the problem",
      "neither password" in text and "VACM" in text, text)

print()
if FAILS:
    print(f"{len(FAILS)} FAILED:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all SNMPv3 key/framing checks passed")

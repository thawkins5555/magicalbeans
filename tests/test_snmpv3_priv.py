"""SNMPv3 authPriv at the message level — the framing that is ours, tested
against the cipher that is OpenSSL's.

Skips (exit 77) when AES-CFB is not usable here: `import cryptography`
succeeding is not enough — a build with a broken Rust backend imports fine
and panics in the first cipher call — so the gate is snmpcrypt.available(),
which runs a real known-answer encrypt/decrypt. CI installs paramiko and
therefore a working cryptography, and runs this for real.

  1. ciphertext length equals plaintext length for every length 0..64 and
     1500 (CFB128: no padding), and the msgPrivacyParameters on the wire IS
     the salt the IV was built from;
  2. 10,000 encrypt() calls with one key give 10,000 distinct salts;
  3. build_v3_request at authPriv: the ScopedPDU is an OCTET STRING, the
     flags are AUTH|PRIV, the digest covers the ciphertext (encrypt first,
     then authenticate), and decode_response with the same keys gives the
     request back — verify first, then decrypt;
  4. a wrong privacy key is a SnmpPrivError that says "privacy password",
     never a silent wrong answer and never "malformed";
  5. a tampered message is SnmpAuthError before any decryption; an
     unsigned reply to a signed request is SnmpDowngrade, whose message
     says it is new in 5.8.0 and names the setting; verify=False accepts
     the unsigned reply — and STILL refuses the tampered one, because a
     digest that is present is always checked;
  6. Reports are exempt: an unauthenticated Report decodes with keys given;
  7. context_name is carried through;
  8. the decryption oracle is closed: a reply claiming privacy without
     authentication never reaches the cipher, and a wrong privacy key's
     message is a fixed sentence — the parser's "got 0x.." (the first
     decrypted byte) is not in it;
  9. the request-id check comes BEFORE the digest on an unencrypted reply
     (a stray is SnmpStray, never SnmpAuthError) and after it on an
     encrypted one, where the id is inside the ciphertext;
 10. SnmpDowngrade is not an SnmpAuthError, and the availability probe
     rejects a real `cryptography` backend in CFB8 mode.
"""
import sys

import _paths  # noqa: F401  (puts the repo root on sys.path)

from netpath import snmpcrypt

if not snmpcrypt.available():
    print(f"AES-CFB is not usable here ({snmpcrypt.unavailable_reason()}); "
          f"install 'cryptography' with a working backend to run this suite")
    raise SystemExit(77)

from netpath.snmppoll import (  # noqa: E402
    FLAG_AUTH, FLAG_PRIV, SnmpAuthError, SnmpDowngrade, SnmpError, SnmpPrivError,
    SnmpStray, SnmpUnsupported, build_v3_request, decode_response, find_auth_span,
    scoped_pdu, sign_v3)
from netpath.trapdecode import (  # noqa: E402
    PDU_GET, PDU_GETBULK, PDU_REPORT, Reader, T_OCTET_STRING, T_SEQUENCE,
    _tlv, enc_int, enc_octets, enc_unsigned, enc_varbind, localized_key,
    privacy_key, T_COUNTER32)

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


ENGINE = bytes.fromhex("80001f8880abcdef0123")
AUTH_KEY = localized_key("SHA", "authpassword", ENGINE)
PRIV_KEY = privacy_key("SHA", "privpassword", ENGINE)
WRONG_PRIV = privacy_key("SHA", "not-the-privacy-password", ENGINE)
OIDS = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]


# ===================================== § 1 length and salt

print("\n-- CFB128 pads nothing; msgPrivacyParameters is the salt")
lengths = list(range(0, 65)) + [1500]
ok_len = True
for n in lengths:
    ciphertext, salt = snmpcrypt.encrypt(PRIV_KEY, 3, 100, bytes(range(256)) * 6 + b"x" * n)
    plain_len = len(bytes(range(256)) * 6 + b"x" * n)
    if len(ciphertext) != plain_len or len(salt) != 8:
        ok_len = False
        check(f"length {plain_len} preserved", False, (len(ciphertext), len(salt)))
        break
check("ciphertext length == plaintext length for lengths 0..64 and 1500", ok_len)
fixed = bytes.fromhex("0011223344556677")
ciphertext, salt = snmpcrypt.encrypt(PRIV_KEY, 7, 1234, b"scoped-pdu-bytes", salt=fixed)
check("a caller-supplied salt (tests only) comes back as the priv params",
      salt == fixed)
check("...and decrypts with the same boots, time and salt",
      snmpcrypt.decrypt(PRIV_KEY, 7, 1234, salt, ciphertext) == b"scoped-pdu-bytes")
check("...but not with a different engineTime: the IV depends on it "
      "(a stale engine cache would not decrypt the device's reply)",
      snmpcrypt.decrypt(PRIV_KEY, 7, 1235, salt, ciphertext) != b"scoped-pdu-bytes")
check("...nor a different engineBoots",
      snmpcrypt.decrypt(PRIV_KEY, 8, 1234, salt, ciphertext) != b"scoped-pdu-bytes")
for bad_key in (b"k" * 15, b"k" * 20):
    try:
        snmpcrypt.encrypt(bad_key, 1, 1, b"x")
        check(f"a {len(bad_key)}-byte key is refused", False)
    except snmpcrypt.PrivError:
        check(f"a {len(bad_key)}-byte key is refused (AES-128 wants exactly 16)", True)
try:
    snmpcrypt.decrypt(PRIV_KEY, 1, 1, b"\x00" * 7, b"x")
    check("a 7-byte priv params is refused", False)
except snmpcrypt.PrivError:
    check("a 7-byte msgPrivacyParameters is refused", True)


# ===================================== § 2 salt uniqueness

print("\n-- 10,000 encryptions, one key")
salts = set()
for _ in range(10_000):
    _c, s = snmpcrypt.encrypt(PRIV_KEY, 1, 1, b"the same plaintext every time")
    salts.add(s)
check("10,000 encrypt() calls give 10,000 distinct salts", len(salts) == 10_000, len(salts))
check("...none all-zero", bytes(8) not in salts)


# ===================================== § 3 the message

print("\n-- build_v3_request at authPriv, decoded back")
message = build_v3_request(
    11, 22, PDU_GET, OIDS, engine_id=ENGINE, engine_boots=7, engine_time=1234,
    user="poller", auth_proto="SHA", auth_key=AUTH_KEY, priv_proto="AES",
    priv_key=PRIV_KEY)
top = Reader(message)
bs, be = top.expect(T_SEQUENCE)
body = Reader(message, bs, be)
body.read_tlv()                          # version
hs, he = body.expect(T_SEQUENCE)          # header
header = Reader(message, hs, he)
header.read_tlv(); header.read_tlv()
fs, fe = header.expect(T_OCTET_STRING)
flags = message[fs]
body.expect(T_OCTET_STRING)               # security params
tag, ds, de = body.read_tlv()
check("msgFlags carry AUTH|PRIV", flags == (FLAG_AUTH | FLAG_PRIV), hex(flags))
check("the scoped-PDU field is an OCTET STRING (encryptedPDU), not a SEQUENCE",
      tag == T_OCTET_STRING, hex(tag))
plain = scoped_pdu(PDU_GET, 22, OIDS, context_engine_id=ENGINE)
check("...as long as the plaintext ScopedPDU it wraps (no padding)",
      de - ds == len(plain), (de - ds, len(plain)))
check("the plaintext OIDs do not appear in the message",
      b"\x2b\x06\x01\x02\x01\x01\x01\x00" not in message)
reply = decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY,
                        priv_proto="AES", priv_key=PRIV_KEY)
check("decode with the same keys gives the request back: verified, then decrypted",
      reply.auth_verified is True and reply.request_id == 22
      and [vb["oid"] for vb in reply.varbinds] == OIDS and reply.flags == 3, reply)
check("...and Response.priv_params is the salt from the wire",
      len(reply.priv_params) == 8 and reply.priv_params != bytes(8))
# The digest covers the ciphertext: re-signing the message with the salt
# changed must produce a different digest.
s1, e1 = find_auth_span(message)
altered = bytearray(message)
# msgPrivacyParameters sits right after the auth field: <04 08 salt>
altered[e1 + 2] ^= 0xFF
blank = bytes(altered[:s1]) + bytes(e1 - s1) + bytes(altered[e1:])
resigned = sign_v3(blank, "SHA", AUTH_KEY)
check("the digest is over the assembled message INCLUDING the salt and the "
      "ciphertext (encrypt first, then authenticate)",
      resigned[s1:e1] != message[s1:e1])

message_bulk = build_v3_request(
    1, 2, PDU_GETBULK, ["1.3.6.1.2.1.2.2.1.2"], engine_id=ENGINE, engine_boots=1,
    engine_time=1, user="poller", auth_proto="MD5",
    auth_key=localized_key("MD5", "authpassword", ENGINE), priv_proto="AES",
    priv_key=privacy_key("MD5", "privpassword", ENGINE), max_repetitions=25)
reply = decode_response(message_bulk, auth_proto="MD5",
                        auth_key=localized_key("MD5", "authpassword", ENGINE),
                        priv_proto="AES", priv_key=privacy_key("MD5", "privpassword", ENGINE))
check("GETBULK's max-repetitions survives encryption (MD5 auth this time)",
      reply.pdu_tag == PDU_GETBULK and reply.error_index == 25, reply)
try:
    build_v3_request(1, 1, PDU_GET, OIDS, engine_id=ENGINE, engine_boots=1,
                     engine_time=1, user="u", auth_proto="SHA", auth_key=AUTH_KEY,
                     priv_proto="DES", priv_key=PRIV_KEY)
    check("DES is refused as unsupported", False)
except SnmpUnsupported as exc:
    check("DES is refused as SnmpUnsupported naming AES-128-CFB as the one offered",
          "AES-128-CFB" in str(exc), str(exc))


# ===================================== § 4 wrong privacy key

print("\n-- a wrong privacy key is named as such")
try:
    decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY,
                    priv_proto="AES", priv_key=WRONG_PRIV)
    check("wrong privacy key raises", False)
except SnmpPrivError as exc:
    check("a wrong privacy key is a SnmpPrivError, not a silent wrong answer",
          True)
    check("...whose message says 'privacy password' and that the signature "
          "verified, and never says 'malformed'",
          "privacy password" in str(exc) and "signature verified" in str(exc)
          and "malformed" not in str(exc), str(exc))
try:
    decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY)
    check("an encrypted reply with no privacy key raises", False)
except SnmpPrivError as exc:
    check("an encrypted reply with no privacy key given is a SnmpPrivError that "
          "says so", "no privacy password" in str(exc), str(exc))


# ===================================== § 5 verification and the downgrade

print("\n-- verify first: a tampered message never reaches the cipher")
tampered = message[:-1] + bytes([message[-1] ^ 0xFF])
try:
    decode_response(tampered, auth_proto="SHA", auth_key=AUTH_KEY,
                    priv_proto="AES", priv_key=PRIV_KEY)
    check("a tampered ciphertext is refused", False)
except SnmpAuthError as exc:
    check("a tampered ciphertext is SnmpAuthError (the digest failed) — not a "
          "SnmpPrivError, so decryption was never attempted",
          "signature does not verify" in str(exc), str(exc))
except SnmpPrivError as exc:
    check("a tampered ciphertext is refused BEFORE decryption", False, str(exc))
wrong_auth = localized_key("SHA", "wrong-auth", ENGINE)
try:
    decode_response(message, auth_proto="SHA", auth_key=wrong_auth,
                    priv_proto="AES", priv_key=PRIV_KEY)
    check("a wrong auth key is refused", False)
except SnmpAuthError as exc:
    check("a wrong AUTH key is SnmpAuthError naming the authentication password",
          "authentication password" in str(exc), str(exc))

# An unsigned "reply" to a signed request: the same PDU at noAuthNoPriv.
unsigned = build_v3_request(11, 22, PDU_GET, OIDS, engine_id=ENGINE,
                            engine_boots=7, engine_time=1234, user="poller")
try:
    decode_response(unsigned, auth_proto="SHA", auth_key=AUTH_KEY)
    check("an unsigned reply to a signed request is refused", False)
except SnmpDowngrade as exc:
    text = str(exc)
    check("an unsigned reply to a signed request is SnmpDowngrade — its own type, "
          "not SnmpAuthError", True)
    check("...and the message says: no signature at all, refused as a downgrade, "
          "NEW in 5.8.0, and which setting accepts such replies",
          "no signature" in text and "downgrade" in text and "new in 5.8.0" in text
          and "Verify the signature on every SNMPv3 reply" in text, text)
    check("...and does not blame the password",
          "password" not in text, text)
except SnmpAuthError as exc:
    check("an unsigned reply is SnmpDowngrade, not SnmpAuthError", False, str(exc))
signed_only = build_v3_request(11, 22, PDU_GET, OIDS, engine_id=ENGINE,
                               engine_boots=7, engine_time=1234, user="poller",
                               auth_proto="SHA", auth_key=AUTH_KEY)
try:
    decode_response(signed_only, auth_proto="SHA", auth_key=AUTH_KEY,
                    priv_proto="AES", priv_key=PRIV_KEY)
    check("an unencrypted reply to an encrypted request is refused", False)
except SnmpDowngrade as exc:
    check("an unencrypted reply to an encrypted request is SnmpDowngrade too",
          "unencrypted" in str(exc), str(exc))
accepted = decode_response(unsigned, auth_proto="SHA", auth_key=AUTH_KEY, verify=False)
check("verify=False (the v3_verify_replies setting off) accepts the unsigned "
      "reply — what every release before 5.8.0 did",
      accepted.request_id == 22 and accepted.auth_verified is False)
accepted = decode_response(signed_only, auth_proto="SHA", auth_key=AUTH_KEY,
                           priv_proto="AES", priv_key=PRIV_KEY, verify=False)
check("...and the unencrypted reply to an encrypted request, with its digest "
      "still verified", accepted.request_id == 22 and accepted.auth_verified is True)
try:
    decode_response(tampered, auth_proto="SHA", auth_key=AUTH_KEY,
                    priv_proto="AES", priv_key=PRIV_KEY, verify=False)
    check("...but a digest that IS present is still checked with verify=False", False,
          "the tampered message was accepted")
except SnmpAuthError:
    check("...but a digest that IS present is still checked with verify=False: "
          "the setting relaxes only the downgrade refusal, so the tampered "
          "authPriv message is refused before the cipher — an unverified "
          "ciphertext never reaches it on request", True)
except SnmpPrivError as exc:
    check("...but a digest that IS present is still checked with verify=False",
          False, f"decrypted instead: {exc}")

print("\n-- Reports are exempt")
report_pdu = _tlv(PDU_REPORT, enc_int(0) + enc_int(0) + enc_int(0) + _tlv(
    T_SEQUENCE, enc_varbind("1.3.6.1.6.3.15.1.1.4.0", enc_unsigned(T_COUNTER32, 1))))
from netpath.snmppoll import _v3_message  # noqa: E402
report = _v3_message(11, flags=0, engine_id=ENGINE, engine_boots=7, engine_time=1234,
                     user="", auth_placeholder_len=0, priv_params=b"",
                     scoped=_tlv(T_SEQUENCE, enc_octets(ENGINE) + enc_octets("") + report_pdu))
decoded = decode_response(report, auth_proto="SHA", auth_key=AUTH_KEY,
                          priv_proto="AES", priv_key=PRIV_KEY)
check("an unauthenticated, unencrypted Report decodes even with both keys given "
      "(engine discovery would break otherwise)",
      decoded.pdu_tag == PDU_REPORT and decoded.auth_verified is False)


# ===================================== § 7 context name

print("\n-- contextName passes through")
named = build_v3_request(1, 1, PDU_GET, OIDS, engine_id=ENGINE, engine_boots=1,
                         engine_time=1, user="u", auth_proto="SHA", auth_key=AUTH_KEY,
                         priv_proto="AES", priv_key=PRIV_KEY, context_name=b"vsys1")
plain = scoped_pdu(PDU_GET, 1, OIDS, context_engine_id=ENGINE, context_name=b"vsys1")
check("a named context is in the plaintext ScopedPDU", b"vsys1" in plain)
check("...and encrypted with it: not visible on the wire",
      b"vsys1" not in named)
check("default context_name is b'' — the pinned bytes in test_snmpv3_keys "
      "already prove the no-priv path is unchanged",
      b"vsys1" not in build_v3_request(1, 1, PDU_GET, OIDS, engine_id=ENGINE,
                                       engine_boots=1, engine_time=1, user="u"))


# ===================================== § 8 the decryption oracle

print("\n-- privacy without authentication never reaches the cipher")
# The authPriv message from § 3 with the AUTH bit cleared in msgFlags: an
# attacker's shape, since USM has no privNoAuth. Before the fix this fell
# through the digest check (only run under FLAG_AUTH) straight into the
# cipher, with an IV and ciphertext of the sender's choosing.
top = Reader(message)
bs, be = top.expect(T_SEQUENCE)
body = Reader(message, bs, be)
body.read_tlv()
hs, he = body.expect(T_SEQUENCE)
header = Reader(message, hs, he)
header.read_tlv(); header.read_tlv()
fs, fe = header.expect(T_OCTET_STRING)
priv_no_auth = bytearray(message)
priv_no_auth[fs] = FLAG_PRIV
priv_no_auth = bytes(priv_no_auth)
cipher_calls = []
real_decrypt = snmpcrypt.decrypt


def spying_decrypt(*args, **kwargs):
    cipher_calls.append(args)
    return real_decrypt(*args, **kwargs)


snmpcrypt.decrypt = spying_decrypt
try:
    try:
        decode_response(priv_no_auth, auth_proto="SHA", auth_key=AUTH_KEY,
                        priv_proto="AES", priv_key=PRIV_KEY)
        check("FLAG_PRIV without FLAG_AUTH is refused", False, "accepted")
    except (SnmpAuthError, SnmpPrivError, SnmpDowngrade) as exc:
        check("FLAG_PRIV without FLAG_AUTH is refused as plain garbage, not as a "
              "verdict", False, f"{type(exc).__name__}: {exc}")
    except SnmpError as exc:
        check("FLAG_PRIV without FLAG_AUTH is a plain SnmpError — garbage from the "
              "right address, which _Session drops and waits past (RFC 3412 s7.2)",
              "RFC 3412" in str(exc) and "discarded" in str(exc), str(exc))
    check("...and the cipher was never called with it", cipher_calls == [], cipher_calls)
    # The same with no keys at all, and with verify=False: the check is
    # structural and does not depend on what the caller holds.
    for kwargs in ({}, {"auth_proto": "SHA", "auth_key": AUTH_KEY, "priv_proto": "AES",
                        "priv_key": PRIV_KEY, "verify": False}):
        try:
            decode_response(priv_no_auth, **kwargs)
            refused = False
        except SnmpError:
            refused = True
    check("...whatever keys are given and with verify=False too", refused and cipher_calls == [])
finally:
    snmpcrypt.decrypt = real_decrypt

print("\n-- a wrong privacy key's message is a fixed sentence")
try:
    decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY,
                    priv_proto="AES", priv_key=WRONG_PRIV)
    check("wrong privacy key raises", False)
except SnmpPrivError as exc:
    text = str(exc)
    check("the message carries no parser detail: no 'expected', no 'got 0x', no "
          "hex byte — the first decrypted byte stays out of the device row, the "
          "API and the alert email",
          "expected" not in text and "got" not in text and "0x" not in text
          and text.endswith(")"), text)
# Many wrong keys, one message: were the plaintext leaking, the sentence
# would differ between keys (a different first byte each time).
messages = set()
for n in range(8):
    try:
        decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY, priv_proto="AES",
                        priv_key=privacy_key("SHA", f"wrong-{n}", ENGINE))
    except SnmpPrivError as exc:
        messages.add(str(exc))
check("eight wrong keys give one identical message", len(messages) == 1, messages)
# Decrypting with no auth key given (the stub's own inbound path) must not
# claim the signature verified.
try:
    decode_response(message, priv_proto="AES", priv_key=WRONG_PRIV)
except SnmpPrivError as exc:
    check("without an auth key the message says the signature was NOT checked, "
          "rather than asserting the authentication password is fine",
          "not checked" in str(exc) and "not the problem" not in str(exc), str(exc))


# ===================================== § 9 the request id and the digest

print("\n-- unencrypted: id first, then the digest; encrypted: digest first")
# signed_only carries request id 22 and a digest under AUTH_KEY.
try:
    decode_response(signed_only, auth_proto="SHA", auth_key=wrong_auth,
                    expect_request_id=424242)
    check("a stray raises", False)
except SnmpStray:
    check("an unencrypted reply with a wrong-key digest AND a foreign request id "
          "is SnmpStray — the id is in the clear and is checked first, so a "
          "spoofed datagram is a dropped stray, not an auth alert", True)
except SnmpAuthError as exc:
    check("an unencrypted stray is SnmpStray, not SnmpAuthError", False, str(exc))
try:
    decode_response(signed_only, auth_proto="SHA", auth_key=wrong_auth,
                    expect_request_id=22)
    check("the right id with a wrong key raises", False)
except SnmpAuthError:
    check("...the same reply with OUR request id is SnmpAuthError: the digest is "
          "still checked once the id matches", True)
try:
    decode_response(message, auth_proto="SHA", auth_key=wrong_auth, priv_proto="AES",
                    priv_key=PRIV_KEY, expect_request_id=424242)
    check("an encrypted stray with a bad digest raises", False)
except SnmpAuthError:
    check("an ENCRYPTED reply with a bad digest is SnmpAuthError whatever id it "
          "carries — the id is inside the ciphertext, so only the digest can come "
          "first there", True)
except SnmpStray:
    check("an encrypted reply's id cannot be read before the digest", False)
try:
    decode_response(message, auth_proto="SHA", auth_key=AUTH_KEY, priv_proto="AES",
                    priv_key=PRIV_KEY, expect_request_id=424242)
    check("an encrypted, verified stray raises", False)
except SnmpStray:
    check("...and once verified and decrypted, a foreign id is SnmpStray", True)
check("no expect_request_id means no id check (the stub decodes inbound "
      "requests this way)",
      decode_response(signed_only, auth_proto="SHA", auth_key=AUTH_KEY).request_id == 22)
check("a Report is exempt from the id check (it answers the msgID, not the "
      "request id)",
      decode_response(report, auth_proto="SHA", auth_key=AUTH_KEY,
                      expect_request_id=424242).pdu_tag == PDU_REPORT)


# ===================================== § 10 the types, and CFB8

print("\n-- SnmpDowngrade is its own type; CFB8 is not the cipher")
check("SnmpDowngrade is not an SnmpAuthError (test_snmpv3_priv catches it "
      "first, so the except order above could not tell)",
      not issubclass(SnmpDowngrade, SnmpAuthError))
real_loader = snmpcrypt._load_backend


def cfb8_backend():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB8
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB8
    return Cipher, algorithms.AES, CFB8


snmpcrypt._load_backend = cfb8_backend
try:
    check("the real cryptography backend in CFB8 mode — which round-trips "
          "perfectly and pads nothing — fails the known-answer probe",
          snmpcrypt.available(recheck=True) is False
          and "known-answer" in snmpcrypt.unavailable_reason(),
          snmpcrypt.unavailable_reason())
finally:
    snmpcrypt._load_backend = real_loader
check("...and the real backend is back", snmpcrypt.available(recheck=True) is True)

print()
if FAILS:
    print(f"{len(FAILS)} FAILED:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all SNMPv3 privacy framing checks passed")

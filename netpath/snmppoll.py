"""SNMP request/response wire format for the Nodes poller: GET/GETNEXT/
GETBULK/SET request builders, a Response-PDU decoder, and v1/v2c/v3
message assembly at every USM level — noAuthNoPriv, authNoPriv and, since
5.8.0, authPriv with AES-128-CFB (RFC 3826; the cipher itself lives in
snmpcrypt.py, the key derivation beside localized_key in trapdecode.py).

Every BER/ASN.1 primitive is imported from trapdecode.py rather than
duplicated — this file is purely the poller-specific half of the same wire
format the trap receiver already decodes.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from . import snmpcrypt
from .trapdecode import (
    AUTH_PROTOCOLS, BerError, PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT,
    PDU_RESPONSE, PDU_SET, Reader, T_INTEGER, T_NULL, T_OCTET_STRING, T_OID,
    T_SEQUENCE, V1, V2C, V3, _decode_value, _oid, _signed, _tlv, _unsigned,
    enc_int, enc_octets, enc_oid, enc_unsigned, enc_varbind, localized_key,
)

ERROR_STATUS = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
    4: "readOnly", 5: "genErr", 6: "noAccess", 7: "wrongType",
    8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue",
    11: "noCreation", 12: "inconsistentValue", 13: "resourceUnavailable",
    14: "commitFailed", 15: "undoFailed", 16: "authorizationError",
    17: "notWritable", 18: "inconsistentName",
}

FLAG_AUTH = 0x01
FLAG_PRIV = 0x02
FLAG_REPORTABLE = 0x04


@dataclass
class Response:
    version: int = 1
    pdu_tag: int = 0
    request_id: int = 0
    error_status: int = 0
    error_index: int = 0
    varbinds: list = field(default_factory=list)   # same shape trapdecode uses
    # v3 only
    engine_id: bytes = b""
    engine_boots: int = 0
    engine_time: int = 0
    user: str = ""
    # msgFlags as received, so a caller can tell an unsigned reply from a
    # signed one without re-parsing the header; and whether decode_response
    # was given a key and the digest checked out against it.
    flags: int = 0
    auth_verified: bool = False


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpAuthError(SnmpError):
    """A v3 reply this poller will not accept as an answer: its digest did
    not verify with the credential the request was signed with, or it
    arrived at a lower security level than the request went out at (an
    unsigned or unencrypted Response to a signed or encrypted request).
    Raised, never dropped as a stray datagram: dropping it would turn a
    wrong key — or a forgery — into a timeout, and a timeout is the one
    diagnosis that sends an operator to look at the network instead of at
    the credential. Reports are exempt (see _decode_v3)."""


class SnmpPrivError(SnmpError):
    """An encrypted v3 reply that could not be turned back into a ScopedPDU:
    no privacy key for it, the wrong one (CFB decrypts anything to
    something, so "not a BER SEQUENCE" IS the wrong-key test), or a
    privacy layer this process cannot run. Its own class rather than a
    plain SnmpError because the message must say "privacy password" and
    not "malformed SNMP response", which is what a wrong key looks like
    from the parser's side."""


class SnmpUnsupported(SnmpError):
    """The security level asked for cannot be built or was refused: a
    privacy protocol this poller does not speak (only AES-128-CFB is
    offered — see snmpcrypt), an authPriv credential on a host whose
    `cryptography` backend does not work, or an agent answering
    usmStatsUnsupportedSecLevels. The poll path files it as status
    'unsupported' — a verdict about this end, not the device."""


class SnmpAccessDenied(SnmpError):
    """The agent processed and accepted the request, then refused the object
    under its own access control (authorizationError(16)). The credential is
    proven good; the view, or the security level, is not.

    An SnmpError, deliberately, and not the poller's _AuthFailure: the
    credential loop rotates on SnmpError, and rotating is right here — a
    profile may hold an authPriv alternate after the authNoPriv one that
    genuinely will succeed — while filing this as an authentication failure
    is the misreport that sent an operator re-checking a password the device
    had just verified."""


# --------------------------------------------------------------------- build

def _pdu_bytes(pdu_tag: int, request_id: int, oids, non_repeaters: int,
               max_repetitions: int) -> bytes:
    body = b"".join(enc_varbind(oid, _tlv(T_NULL, b"")) for oid in oids)
    second = enc_int(non_repeaters if pdu_tag == PDU_GETBULK else 0)
    third = enc_int(max_repetitions if pdu_tag == PDU_GETBULK else 0)
    return _tlv(pdu_tag, enc_int(request_id) + second + third +
               _tlv(T_SEQUENCE, body))


def build_request(version: int, community: str, pdu_tag: int, request_id: int,
                  oids, non_repeaters: int = 0, max_repetitions: int = 10) -> bytes:
    """v1/v2c GET/GETNEXT/GETBULK/SET. For GET/GETNEXT/SET the second and
    third integers after request-id are error-status(0)/error-index(0);
    for GETBULK (RFC 3416 s3) they are non-repeaters/max-repetitions
    instead — same wire position, different meaning."""
    pdu = _pdu_bytes(pdu_tag, request_id, oids, non_repeaters, max_repetitions)
    return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(community) + pdu)


def scoped_pdu(pdu_tag: int, request_id: int, oids, *, context_engine_id: bytes,
               context_name: bytes = b"", non_repeaters: int = 0,
               max_repetitions: int = 0) -> bytes:
    """The plaintext ScopedPDU (RFC 3412 s6.8): contextEngineID,
    contextName, PDU, as one SEQUENCE. Extracted so the plain and the
    encrypted paths build the identical bytes — the encrypted path takes
    this SEQUENCE and encrypts it whole, the plain path sends it as is —
    and cannot drift into two constructions that agree on nothing but
    their name."""
    pdu = _pdu_bytes(pdu_tag, request_id, oids, non_repeaters, max_repetitions)
    return _tlv(T_SEQUENCE, enc_octets(context_engine_id) +
                enc_octets(context_name) + pdu)


def _v3_message(msg_id: int, *, flags: int, engine_id: bytes, engine_boots: int,
                engine_time: int, user: str, auth_placeholder_len: int,
                priv_params: bytes, scoped: bytes) -> bytes:
    """msgGlobalData + msgSecurityParameters (USM) + the scoped-PDU field —
    structurally the exact reverse of trapdecode.Decoder._decode_v3.
    `scoped` is either the plaintext SEQUENCE from scoped_pdu() or the
    OCTET STRING wrapping its ciphertext; this function does not care
    which, which is the point."""
    header = _tlv(T_SEQUENCE,
                  enc_int(msg_id) + enc_int(65507) +
                  _tlv(T_OCTET_STRING, bytes([flags])) + enc_int(3))
    usm_body = (enc_octets(engine_id) + enc_int(engine_boots) + enc_int(engine_time) +
               enc_octets(user) +
               _tlv(T_OCTET_STRING, bytes(auth_placeholder_len)) +
               _tlv(T_OCTET_STRING, priv_params))
    sec_params = _tlv(T_OCTET_STRING, _tlv(T_SEQUENCE, usm_body))
    return _tlv(T_SEQUENCE, enc_int(V3) + header + sec_params + scoped)


def sign_v3(message: bytes, auth_proto: str, auth_key: bytes) -> bytes:
    """`message` with its zero-filled msgAuthenticationParameters replaced
    by the HMAC of the whole message computed over that zero-filled field —
    Decoder._verify_v3's blank-then-hash exactly, in reverse. Shared by
    build_v3_request and the test stub's agent side, so a reply is signed
    the way a request is."""
    ctor, digest_len = AUTH_PROTOCOLS[auth_proto]
    start, end = find_auth_span(message)
    if end - start != digest_len:
        raise SnmpError("auth placeholder does not match the protocol's digest length")
    digest = hmac.new(auth_key, message, ctor).digest()[:digest_len]
    return message[:start] + digest + message[end:]


def encrypt_scoped(priv_proto: str, priv_key: bytes, engine_boots: int,
                   engine_time: int, scoped: bytes) -> tuple[bytes, bytes]:
    """(the OCTET STRING TLV wrapping the encrypted ScopedPDU, the
    msgPrivacyParameters salt) — RFC 3826 s3.1.3. Refuses a protocol this
    poller does not speak and turns snmpcrypt's own failure into the
    SnmpError subclass the poll path already classifies."""
    if priv_proto not in snmpcrypt.PRIV_PROTOCOLS:
        raise SnmpUnsupported(
            f"privacy protocol {priv_proto!r} is not supported: this poller "
            f"speaks AES-128-CFB only (choose 'AES' on the credential)")
    try:
        ciphertext, salt = snmpcrypt.encrypt(priv_key, engine_boots, engine_time, scoped)
    except snmpcrypt.PrivError as exc:
        raise SnmpUnsupported(str(exc)) from exc
    return _tlv(T_OCTET_STRING, ciphertext), salt


def build_v3_request(msg_id: int, request_id: int, pdu_tag: int, oids, *,
                     engine_id: bytes, engine_boots: int, engine_time: int,
                     user: str, auth_proto: str | None = None,
                     auth_key: bytes | None = None, non_repeaters: int = 0,
                     max_repetitions: int = 10, priv_proto: str | None = None,
                     priv_key: bytes | None = None,
                     context_name: bytes = b"") -> bytes:
    """One v3 request at whichever USM level the keys imply: noAuthNoPriv
    with neither, authNoPriv with an auth key, authPriv with both.

    Order matters and is RFC 3414 s3.1's: the ScopedPDU is encrypted
    FIRST, then the whole assembled message — which by then contains the
    ciphertext and the salt — is authenticated, with the auth-parameters
    field zero-filled, and the digest is spliced in last. The receiver
    does the exact reverse (verify the digest, then decrypt), and that
    ordering is what stops a chosen-ciphertext game: nothing is ever
    decrypted that was not first proven to come from the key holder.

    Privacy REQUIRES authentication — USM defines no privNoAuth level —
    and a privacy key without an auth key raises rather than quietly
    building an authNoPriv message, because a silent downgrade produces
    exactly the authorizationError(16) that having a privacy password is
    meant to fix. With no privacy arguments the bytes produced are
    identical to those of every release before 5.8.0 (pinned in
    tests/test_snmpv3_priv.py); that is what makes the upgrade a no-op.

    `context_name` is passed through rather than hardcoded empty: an
    agent whose user has a view only in a named context refuses the
    default one with the same authorizationError, and it costs nothing."""
    signing = bool(auth_proto and auth_key)
    encrypting = bool(priv_proto and priv_key)
    if encrypting and not signing:
        raise SnmpError(
            "a privacy password needs an authentication password: USM has "
            "no privacy-without-authentication level (RFC 3414 s2.4)")
    digest_len = AUTH_PROTOCOLS[auth_proto][1] if signing else 0
    flags = FLAG_AUTH if signing else 0
    scoped = scoped_pdu(pdu_tag, request_id, oids, context_engine_id=engine_id,
                        context_name=context_name, non_repeaters=non_repeaters,
                        max_repetitions=max_repetitions)
    priv_params = b""
    if encrypting:
        scoped, priv_params = encrypt_scoped(priv_proto, priv_key, engine_boots,
                                             engine_time, scoped)
        flags |= FLAG_PRIV
    message = _v3_message(
        msg_id, flags=flags, engine_id=engine_id, engine_boots=engine_boots,
        engine_time=engine_time, user=user, auth_placeholder_len=digest_len,
        priv_params=priv_params, scoped=scoped)
    if not signing:
        return message
    return sign_v3(message, auth_proto, auth_key)


def discovery_probe(msg_id: int = 1) -> bytes:
    """An empty, unauthenticated, reportable GET — RFC 3414 s4's engine
    discovery exchange. Sent once per (device, engine) to learn
    engineID/engineBoots/engineTime from the Report-PDU the agent replies
    with, before any authenticated request can be built."""
    return _v3_message(msg_id, flags=FLAG_REPORTABLE, engine_id=b"",
                       engine_boots=0, engine_time=0, user="",
                       auth_placeholder_len=0, priv_params=b"",
                       scoped=scoped_pdu(PDU_GET, 0, [], context_engine_id=b""))


def find_auth_span(message: bytes) -> tuple[int, int]:
    """Re-parses a just-built v3 message to locate the
    msgAuthenticationParameters OCTET STRING's value span, the same way
    trapdecode._decode_v3 does when verifying."""
    top = Reader(message)
    body_s, body_e = top.expect(T_SEQUENCE)
    msg = Reader(message, body_s, body_e)
    msg.expect(T_INTEGER)                          # version
    msg.expect(T_SEQUENCE)                         # msgGlobalData — skip contents
    ss, se = msg.expect(T_OCTET_STRING)             # msgSecurityParameters
    usm = Reader(message, ss, se)
    us, ue = usm.expect(T_SEQUENCE)
    params = Reader(message, us, ue)
    params.expect(T_OCTET_STRING)                   # engine id
    params.expect(T_INTEGER)                        # engine boots
    params.expect(T_INTEGER)                        # engine time
    params.expect(T_OCTET_STRING)                   # user name
    as_, ae = params.expect(T_OCTET_STRING)          # auth params
    return as_, ae


# ------------------------------------------------------------------- decode

def _read_varbinds(data: bytes, start: int, end: int) -> list[dict]:
    out = []
    walker = Reader(data, start, end)
    while not walker.at_end():
        try:
            bs, be = walker.expect(T_SEQUENCE)
        except BerError:
            break
        pair = Reader(data, bs, be)
        try:
            os_, oe = pair.expect(T_OID)
            oid = _oid(data, os_, oe)
            if pair.at_end():
                kind, text, value = "NULL", "", None
            else:
                tag, vs, ve = pair.read_tlv()
                kind, text, value = _decode_value(data, tag, vs, ve, 4096)
        except BerError:
            continue
        out.append({"oid": oid, "type": kind, "value": value, "text": text})
    return out


def _read_pdu(data: bytes, ps: int, pe: int, response: Response) -> None:
    pdu = Reader(data, ps, pe)
    s, e = pdu.expect(T_INTEGER)
    response.request_id = _signed(data, s, e)
    s, e = pdu.expect(T_INTEGER)
    response.error_status = _signed(data, s, e)
    s, e = pdu.expect(T_INTEGER)
    response.error_index = _signed(data, s, e)
    vs, ve = pdu.expect(T_SEQUENCE)
    response.varbinds = _read_varbinds(data, vs, ve)


def _verify_digest(data: bytes, auth_start: int, auth_end: int,
                   auth_proto: str, auth_key: bytes) -> bool:
    """Decoder._verify_v3's arithmetic for a reply: the auth field blanked
    in a copy, the whole datagram HMACed with the key we signed our request
    with, the leading digest-length bytes compared in constant time."""
    ctor, digest_len = AUTH_PROTOCOLS[auth_proto]
    sent = data[auth_start:auth_end]
    if len(sent) != digest_len:
        return False
    blanked = bytearray(data)
    blanked[auth_start:auth_end] = bytes(digest_len)
    computed = hmac.new(auth_key, bytes(blanked), ctor).digest()[:digest_len]
    return hmac.compare_digest(computed, sent)


def _read_scoped(buffer: bytes, ds: int, de: int, response: Response) -> None:
    scoped = Reader(buffer, ds, de)
    scoped.expect(T_OCTET_STRING)                    # contextEngineID
    scoped.expect(T_OCTET_STRING)                    # contextName
    tag, ps, pe = scoped.read_tlv()
    response.pdu_tag = tag
    _read_pdu(buffer, ps, pe, response)


def _decode_v3(data: bytes, msg: Reader, *, auth_proto: str | None = None,
               auth_key: bytes | None = None, priv_proto: str | None = None,
               priv_key: bytes | None = None) -> Response:
    """A v3 message at any level. With keys given, the digest is verified
    FIRST and only then is the ScopedPDU decrypted — RFC 3414 s3.2's
    order, the mirror of build_v3_request's encrypt-then-authenticate —
    so nothing reaches the cipher, let alone the parser, that was not
    proven to come from the key holder.

    The digest is checked only when the reply carries FLAG_AUTH. That is
    not laxity: an agent's Report-PDU for usmStatsUnknownEngineIDs or
    usmStatsUnknownUserNames is legitimately unauthenticated — it IS the
    discovery exchange, sent before the agent could possibly have a key
    to sign with — and verifying those would break engine discovery on
    every device. Whether a NON-Report reply is allowed to arrive unsigned
    or unencrypted is decode_response's decision, which knows what was
    sent."""
    hs, he = msg.expect(T_SEQUENCE)
    header = Reader(data, hs, he)
    header.expect(T_INTEGER)                       # msgID
    header.expect(T_INTEGER)                       # msgMaxSize
    fs, fe = header.expect(T_OCTET_STRING)
    flags = data[fs] if fe > fs else 0
    header.expect(T_INTEGER)                       # msgSecurityModel

    ss, se = msg.expect(T_OCTET_STRING)
    usm = Reader(data, ss, se)
    us, ue = usm.expect(T_SEQUENCE)
    params = Reader(data, us, ue)
    es, ee = params.expect(T_OCTET_STRING)
    bs, be = params.expect(T_INTEGER)
    ts_, te = params.expect(T_INTEGER)
    ns, ne = params.expect(T_OCTET_STRING)
    as_, ae = params.expect(T_OCTET_STRING)         # auth params (offsets kept)
    ps_, pe = params.expect(T_OCTET_STRING)         # priv params — the salt

    response = Response(version=V3, engine_id=data[es:ee],
                        engine_boots=_unsigned(data, bs, be),
                        engine_time=_unsigned(data, ts_, te),
                        user=data[ns:ne].decode("utf-8", "replace"),
                        flags=flags)

    if flags & FLAG_AUTH and auth_proto and auth_key:
        if not _verify_digest(data, as_, ae, auth_proto, auth_key):
            raise SnmpAuthError(
                "the reply's signature does not verify with this "
                "credential — the authentication password or protocol is "
                "wrong for this engine, or the reply was forged or altered "
                "in transit")
        response.auth_verified = True

    tag, ds, de = msg.read_tlv()
    if not flags & FLAG_PRIV:
        if tag != T_SEQUENCE:
            raise BerError("ScopedPDU is not a SEQUENCE")
        _read_scoped(data, ds, de, response)
        return response

    # encryptedPDU: an OCTET STRING whose value is the ScopedPDU under
    # AES-CFB with the IV built from THIS message's boots, time and salt.
    if tag != T_OCTET_STRING:
        raise BerError("encryptedPDU is not an OCTET STRING")
    if not (priv_proto and priv_key):
        raise SnmpPrivError(
            "the reply is encrypted (authPriv) and this credential has no "
            "privacy password to decrypt it with")
    if priv_proto not in snmpcrypt.PRIV_PROTOCOLS:
        raise SnmpUnsupported(
            f"privacy protocol {priv_proto!r} is not supported: this poller "
            f"speaks AES-128-CFB only")
    try:
        plain = snmpcrypt.decrypt(priv_key, response.engine_boots,
                                  response.engine_time, data[ps_:pe], data[ds:de])
    except snmpcrypt.PrivError as exc:
        raise SnmpPrivError(f"could not decrypt the reply: {exc}") from exc
    try:
        inner = Reader(plain)
        ds, de = inner.expect(T_SEQUENCE)
        _read_scoped(plain, ds, de, response)
    except (BerError, IndexError, ValueError) as exc:
        # CFB turns any ciphertext into some plaintext, so a wrong key does
        # not fail in the cipher — it fails here, as bytes that are not a
        # ScopedPDU. Name the cause, or a wrong privacy password reads as
        # "malformed SNMP response" and the device gets the blame.
        raise SnmpPrivError(
            "the reply decrypted to something that is not a ScopedPDU — the "
            "privacy password or protocol is wrong for this user (the "
            "signature verified, so the authentication password is not the "
            f"problem): {exc}") from exc
    return response


def _decode(data: bytes, **keys) -> Response:
    top = Reader(data)
    body_s, body_e = top.expect(T_SEQUENCE)
    msg = Reader(data, body_s, body_e)
    tag, s, e = msg.read_tlv()
    if tag != T_INTEGER:
        raise BerError("no version")
    version = _signed(data, s, e)

    if version in (V1, V2C):
        msg.expect(T_OCTET_STRING)                  # community
        tag, ps, pe = msg.read_tlv()
        response = Response(version=version, pdu_tag=tag)
        _read_pdu(data, ps, pe, response)
        return response

    if version == V3:
        return _decode_v3(data, msg, **keys)

    raise BerError(f"unsupported version {version}")


def decode_response(data: bytes, *, auth_proto: str | None = None,
                    auth_key: bytes | None = None, priv_proto: str | None = None,
                    priv_key: bytes | None = None) -> Response:
    """The mirror of trapdecode's trap decoder, but for a Response-PDU (or,
    given a just-built request, decodes it back — same code path, since a
    Response-PDU and a Get/GetNext/GetBulk-PDU share request-id/slot-2/
    slot-3/varbind-list per RFC 3416). Never lets a raw parse exception
    leak with a confusing type — always raises a clean SnmpError subclass,
    or a plain SnmpError for a malformed reply. A non-zero error_status is
    NOT raised on here — it's reported in the Response for the caller to
    interpret, since 'noSuchName' on one OID in a batch does not make the
    whole reply worthless.

    The keys are the ones the REQUEST was built with. Given an auth key, a
    v3 reply carrying FLAG_AUTH has its digest verified before anything
    else is read (verify first, then decrypt — RFC 3414 s3.2), and a
    non-Report reply that arrives unsigned — or, given a privacy key,
    unencrypted — is refused as SnmpAuthError: a reply at a lower level
    than its request is not an answer, it is a downgrade, and until 5.8.0
    nothing on this end checked either. Report-PDUs are exempt both ways,
    because the discovery exchange and a wrongDigests refusal are
    unauthenticated by design."""
    try:
        response = _decode(data, auth_proto=auth_proto, auth_key=auth_key,
                           priv_proto=priv_proto, priv_key=priv_key)
    except SnmpError:
        raise
    except (BerError, IndexError, ValueError, UnicodeError) as exc:
        raise SnmpError(f"malformed SNMP response: {exc}") from exc
    if response.version == V3 and response.pdu_tag != PDU_REPORT:
        if auth_key and auth_proto and not response.flags & FLAG_AUTH:
            raise SnmpAuthError(
                "the reply to a signed request is unsigned — refused as a "
                "downgrade (RFC 3414 s3.2); the device did not answer this")
        if priv_key and priv_proto and not response.flags & FLAG_PRIV:
            raise SnmpAuthError(
                "the reply to an encrypted request is not encrypted — "
                "refused as a downgrade (RFC 3414 s3.2)")
    return response


if __name__ == "__main__":
    # Round trips through the same BER code, with no socket. This is the
    # half of the protocol that can be proven without a device: if the
    # encoder and the decoder disagree, it fails here rather than as an
    # unexplained timeout against real hardware.

    # --- v2c GetRequest
    packet = build_request(V2C, "public", PDU_GET, 4242,
                           ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"])
    reply = decode_response(packet)
    assert reply.version == V2C and reply.request_id == 4242
    assert [vb["oid"] for vb in reply.varbinds] == \
           ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]
    assert all(vb["type"] == "NULL" for vb in reply.varbinds)
    print("v2c GetRequest round trip OK")

    # --- v1 GetNextRequest
    packet = build_request(V1, "public", PDU_GETNEXT, 7, ["1.3.6.1.2.1.2.2.1.2"])
    reply = decode_response(packet)
    assert reply.version == V1 and reply.pdu_tag == PDU_GETNEXT
    print("v1 GetNextRequest round trip OK")

    # --- GetBulk: the two slots after request-id are non-repeaters and
    #     max-repetitions, not error-status/error-index (RFC 3416 s3).
    packet = build_request(V2C, "public", PDU_GETBULK, 9,
                           ["1.3.6.1.2.1.2.2.1.10"],
                           non_repeaters=0, max_repetitions=25)
    reply = decode_response(packet)
    assert reply.error_status == 0 and reply.error_index == 25, \
        "GetBulk's max-repetitions must land in the third integer slot"
    print("v2c GetBulkRequest round trip OK")

    # --- a synthetic Response carrying real values, decoded back
    from .trapdecode import T_COUNTER32, T_TIMETICKS
    body = (enc_varbind("1.3.6.1.2.1.1.1.0", enc_octets("Test Device v1.0")) +
            enc_varbind("1.3.6.1.2.1.1.3.0", enc_unsigned(T_TIMETICKS, 987654)) +
            enc_varbind("1.3.6.1.2.1.2.2.1.10.3", enc_unsigned(T_COUNTER32, 2**31)))
    pdu = _tlv(PDU_RESPONSE, enc_int(4242) + enc_int(0) + enc_int(0) +
               _tlv(T_SEQUENCE, body))
    packet = _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets("public") + pdu)
    reply = decode_response(packet)
    assert reply.varbinds[0]["value"] == "Test Device v1.0"
    assert reply.varbinds[1]["value"] == 987654
    assert reply.varbinds[2]["value"] == 2**31
    print("Response-PDU decode OK")

    # --- a non-zero error-status must be reported, not swallowed
    from .trapdecode import T_NO_SUCH_OBJECT
    pdu = _tlv(PDU_RESPONSE, enc_int(1) + enc_int(2) + enc_int(1) +
               _tlv(T_SEQUENCE, enc_varbind("1.3.6.1.9.9.9", _tlv(T_NULL, b""))))
    packet = _tlv(T_SEQUENCE, enc_int(V1) + enc_octets("public") + pdu)
    reply = decode_response(packet)
    assert reply.error_status == 2 and ERROR_STATUS[2] == "noSuchName"
    print("error-status decode OK")

    # --- the SNMPv2 exception markers must survive as their own types
    pdu = _tlv(PDU_RESPONSE, enc_int(3) + enc_int(0) + enc_int(0) +
               _tlv(T_SEQUENCE,
                    enc_varbind("1.3.6.1.4.1.9.9.109.1.1.1.1.8",
                                _tlv(T_NO_SUCH_OBJECT, b""))))
    packet = _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets("public") + pdu)
    reply = decode_response(packet)
    assert reply.varbinds[0]["type"] == "noSuchObject"
    print("noSuchObject passthrough OK")

    # --- v3 authNoPriv: build, locate the digest field, sign, verify with
    #     trapdecode's own verifier.
    from .trapdecode import Decoder, Trap
    engine = bytes.fromhex("80001f8880" + "abcdef0123")
    key = localized_key("SHA", "authpassword", engine)
    message = build_v3_request(
        1, 1, PDU_GET, ["1.3.6.1.2.1.1.3.0"], engine_id=engine,
        engine_boots=7, engine_time=1234, user="poller",
        auth_proto="SHA", auth_key=key)
    start, end = find_auth_span(message)
    assert end - start == AUTH_PROTOCOLS["SHA"][1] == 12
    assert message[start:end] != b"\x00" * 12, "digest was not spliced in"

    decoder = Decoder()
    decoder.configure({"v3_users": "poller / SHA / authpassword"})
    trap = Trap(community="poller", engine_id=engine.hex())
    assert decoder._verify_v3(message, trap, start, end) == "ok", \
        "the digest this encoder produces must verify with the trap decoder's"
    print("v3 authNoPriv sign/verify OK")

    broken = bytearray(message)
    broken[-1] ^= 0xFF
    assert decoder._verify_v3(bytes(broken), trap, start, end) == "failed"
    print("v3 tamper detection OK")

    for proto in ("MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"):
        k = localized_key(proto, "authpassword", engine)
        m = build_v3_request(1, 1, PDU_GET, ["1.3.6.1.2.1.1.3.0"],
                             engine_id=engine, engine_boots=1, engine_time=1,
                             user="poller", auth_proto=proto, auth_key=k)
        s, e = find_auth_span(m)
        assert e - s == AUTH_PROTOCOLS[proto][1], proto
    print("all auth protocol digest lengths OK")

    probe = discovery_probe()
    reply = decode_response(probe)
    assert reply.version == V3 and reply.engine_id == b"" and reply.user == ""
    print("v3 discovery probe round trip OK")

    print("all self-tests passed")

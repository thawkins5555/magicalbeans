"""SNMP request/response wire format for the Nodes poller: GET/GETNEXT/
GETBULK/SET request builders, a Response-PDU decoder, and v1/v2c/v3
(noAuthNoPriv/authNoPriv only — see decision #2) message assembly.

Every BER/ASN.1 primitive is imported from trapdecode.py rather than
duplicated — this file is purely the poller-specific half of the same wire
format the trap receiver already decodes.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

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


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpAuthError(SnmpError):
    pass


class SnmpUnsupported(SnmpError):
    """authPriv requested; deferred per decision #2."""


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


def _v3_message(msg_id: int, request_id: int, pdu_tag: int, oids, *, flags: int,
                engine_id: bytes, engine_boots: int, engine_time: int, user: str,
                auth_placeholder_len: int, non_repeaters: int, max_repetitions: int,
                context_engine_id: bytes, context_name: bytes) -> bytes:
    """msgGlobalData + msgSecurityParameters (USM) + ScopedPDU — structurally
    the exact reverse of trapdecode.Decoder._decode_v3."""
    header = _tlv(T_SEQUENCE,
                  enc_int(msg_id) + enc_int(65507) +
                  _tlv(T_OCTET_STRING, bytes([flags])) + enc_int(3))
    usm_body = (enc_octets(engine_id) + enc_int(engine_boots) + enc_int(engine_time) +
               enc_octets(user) +
               _tlv(T_OCTET_STRING, bytes(auth_placeholder_len)) +
               _tlv(T_OCTET_STRING, b""))
    sec_params = _tlv(T_OCTET_STRING, _tlv(T_SEQUENCE, usm_body))
    pdu = _pdu_bytes(pdu_tag, request_id, oids, non_repeaters, max_repetitions)
    scoped = _tlv(T_SEQUENCE, enc_octets(context_engine_id) +
                  enc_octets(context_name) + pdu)
    return _tlv(T_SEQUENCE, enc_int(V3) + header + sec_params + scoped)


def build_v3_request(msg_id: int, request_id: int, pdu_tag: int, oids, *,
                     engine_id: bytes, engine_boots: int, engine_time: int,
                     user: str, auth_proto: str | None = None,
                     auth_key: bytes | None = None, non_repeaters: int = 0,
                     max_repetitions: int = 10) -> bytes:
    """authNoPriv or noAuthNoPriv only (decision #2). Builds the full
    message with the auth-parameters field zero-filled, then — if signing
    — computes the HMAC over the assembled bytes with that field zeroed and
    splices the real digest in, mirroring Decoder._verify_v3's
    blank-then-hash exactly so the two are provably the same operation in
    reverse."""
    signing = bool(auth_proto and auth_key)
    digest_len = AUTH_PROTOCOLS[auth_proto][1] if signing else 0
    flags = FLAG_AUTH if signing else 0
    message = _v3_message(
        msg_id, request_id, pdu_tag, oids, flags=flags, engine_id=engine_id,
        engine_boots=engine_boots, engine_time=engine_time, user=user,
        auth_placeholder_len=digest_len, non_repeaters=non_repeaters,
        max_repetitions=max_repetitions, context_engine_id=engine_id,
        context_name=b"")
    if not signing:
        return message
    start, end = find_auth_span(message)
    ctor = AUTH_PROTOCOLS[auth_proto][0]
    digest = hmac.new(auth_key, message, ctor).digest()[:digest_len]
    return message[:start] + digest + message[end:]


def discovery_probe(msg_id: int = 1) -> bytes:
    """An empty, unauthenticated, reportable GET — RFC 3414 s4's engine
    discovery exchange. Sent once per (device, engine) to learn
    engineID/engineBoots/engineTime from the Report-PDU the agent replies
    with, before any authenticated request can be built."""
    return _v3_message(msg_id, 0, PDU_GET, [], flags=FLAG_REPORTABLE,
                       engine_id=b"", engine_boots=0, engine_time=0, user="",
                       auth_placeholder_len=0, non_repeaters=0,
                       max_repetitions=0, context_engine_id=b"", context_name=b"")


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


def _decode_v3(data: bytes, msg: Reader) -> Response:
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
    params.expect(T_OCTET_STRING)                   # auth params — the caller
                                                      # verifies against its own
                                                      # stored key if it needs to
    params.expect(T_OCTET_STRING)                   # priv params

    response = Response(version=V3, engine_id=data[es:ee],
                        engine_boots=_unsigned(data, bs, be),
                        engine_time=_unsigned(data, ts_, te),
                        user=data[ns:ne].decode("utf-8", "replace"))

    if flags & FLAG_PRIV:
        raise SnmpUnsupported(
            "authPriv is not supported; this poller speaks noAuthNoPriv "
            "and authNoPriv only")

    ds, de = msg.expect(T_SEQUENCE)                 # ScopedPDU
    scoped = Reader(data, ds, de)
    scoped.expect(T_OCTET_STRING)                    # contextEngineID
    scoped.expect(T_OCTET_STRING)                    # contextName
    tag, ps, pe = scoped.read_tlv()
    response.pdu_tag = tag
    _read_pdu(data, ps, pe, response)
    return response


def _decode(data: bytes) -> Response:
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
        return _decode_v3(data, msg)

    raise BerError(f"unsupported version {version}")


def decode_response(data: bytes) -> Response:
    """The mirror of trapdecode's trap decoder, but for a Response-PDU (or,
    given a just-built request, decodes it back — same code path, since a
    Response-PDU and a Get/GetNext/GetBulk-PDU share request-id/slot-2/
    slot-3/varbind-list per RFC 3416). Never lets a raw parse exception
    leak with a confusing type — always raises a clean SnmpError subclass,
    or a plain SnmpError for a malformed reply. A non-zero error_status is
    NOT raised on here — it's reported in the Response for the caller to
    interpret, since 'noSuchName' on one OID in a batch does not make the
    whole reply worthless."""
    try:
        return _decode(data)
    except SnmpError:
        raise
    except (BerError, IndexError, ValueError, UnicodeError) as exc:
        raise SnmpError(f"malformed SNMP response: {exc}") from exc


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

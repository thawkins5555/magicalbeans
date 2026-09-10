"""A stub SNMP agent with a real ifTable, and the misbehaviours the poller
has to survive.

The existing stubs each answer one narrow thing; this one serves the whole
scalar + ifTable/ifXTable shape a device poll actually asks for, with a
configurable interface count, and can be told to misbehave in the specific
ways the review found the poller mishandled:

    python3 stub_agent_iftable.py <port> [mode] [--interfaces N]

Modes:
  ok               a well-behaved v2c agent (the default)
  v1_nosuchname    a real SNMPv1 agent: a GET naming any object it does not
                   implement (every ifXTable column) is answered with
                   error-status 2 (noSuchName), error-index pointing at the
                   first offender, and the request's varbind list echoed
                   back as nulls. This is what makes every interface on a
                   v1 device come back blank.
  dark_after_walk  answers the ifIndex walk and the first --dark-after
                   GETs, then stops replying — the device that holds a
                   poll worker for N x timeout x retries.
  nonnumeric       the ifIndex column carries one non-numeric index suffix
                   between two numeric ones.
  reboot           sysUpTime counts up for the first --reboot-after reads
                   and then drops to a few seconds, and every counter
                   restarts with it — a device that rebooted between two
                   polls.
  stale_id         answers every GET twice: first with request-id + 1 and
                   a wrong sysName, then correctly. A receiver that takes
                   the first datagram off the socket stores the wrong
                   answer — which is what a late reply to a previous
                   attempt does on a real network.
  palo_alto        answers as a PAN-OS box: a Palo Alto sysObjectID under
                   1.3.6.1.4.1.25461, several hundred interfaces, and the
                   three net-snmp behaviours a real firewall shows a
                   poller. --reply-delay SECONDS holds every reply back, so
                   a walk of that many interfaces runs out of the poll's
                   budget part way down the table. --bulk-cap N returns
                   FEWER varbinds than the GETBULK asked for once the
                   response would exceed N of them, which is what net-snmp
                   actually does: it truncates the reply rather than
                   answering tooBig, so a walker that only handles tooBig
                   never learns anything is wrong. --gen-err OID (repeatable,
                   or comma-separated) answers any request inside that
                   subtree with error-status genErr(5) and no varbinds;
                   --no-such-name OID does the same with noSuchName(2).
                   --refuse-bulk answers every GETBULK with tooBig whatever
                   the repetition count, the agent that forces a GETNEXT
                   fallback for good.
  fortigate        answers as a FortiGate: a Fortinet sysObjectID and the
                   FORTINET-FORTIGATE-MIB CPU, memory and session scalars,
                   plus an ipAddrTable naming a management address the
                   devices table has never seen.
  cisco            answers as a Cisco router: a Cisco sysObjectID,
                   cpmCPUTotal5minRev and a two-pool ciscoMemoryPool table.
  v3               speaks SNMPv3 noAuthNoPriv with an authoritative engine
                   id, engineBoots and a real engineTime clock, and applies
                   an RFC 3414 §3.2 time window of --window seconds:
                   a request whose msgAuthoritativeEngineTime is outside it
                   is answered with a Report-PDU naming
                   usmStatsNotInTimeWindows, exactly as an agent does to a
                   poller whose cached engineTime has stopped advancing.
                   --bump-boots-at SECONDS restarts the engine (boots + 1,
                   engineTime back to 0) on the first request that arrives
                   after an idle gap of at least that many seconds, so a
                   test can put the restart between two polls without
                   counting requests. It used to count from process start,
                   and a slow runner (Windows in CI) reached the deadline
                   while the FIRST poll was still in flight, restarting the
                   engine under the poll the test expected to succeed.
                   --auth-pass PASSWORD (with --auth-proto NAME, default
                   SHA) makes the stub a real authNoPriv agent: a signed
                   request is verified with the localized key, a wrong
                   digest is answered with a Report naming
                   usmStatsWrongDigests, and an unsigned one with
                   usmStatsUnsupportedSecLevels — what an agent says to a
                   wrong password, and to no password. --require-priv is
                   the PAN-OS symptom this stub could not reproduce before
                   it: the request is ACCEPTED (its signature verified, if
                   there is one) and then answered with an ordinary
                   Response-PDU carrying error-status 16
                   (authorizationError) and error-index 1, because the
                   user's only access entry is at authPriv and an
                   authNoPriv request matches no entry at all (RFC 3415).
                   --priv-pass PASSWORD (with --priv-proto AES) makes the
                   stub a real authPriv agent, the PAN-OS user as
                   provisioned: an inbound authPriv request has its digest
                   verified FIRST and is then decrypted (RFC 3414 s3.2's
                   order), one that will not decrypt to a ScopedPDU is
                   answered with a Report naming usmStatsDecryptionErrors
                   (a wrong privacy password, distinct from wrongDigests),
                   an unencrypted request to this user with
                   usmStatsUnsupportedSecLevels, and every reply goes back
                   encrypted under a fresh salt of the stub's own. The
                   salts it received and the salts it sent are both listed
                   in --stats, so a test can prove none repeated across a
                   real walk. Whenever the stub holds an auth key its
                   replies are SIGNED, as a real agent's are — the poller
                   verifies a reply's digest since 5.8.0 and refuses an
                   unsigned answer to a signed request as a downgrade.
                   --tamper-reply flips one byte of every Response after
                   it is signed, the forged-or-altered reply that
                   verification exists to catch. --unsigned-replies makes
                   the stub verify a signed request and then answer it
                   UNSIGNED — the agent, proxy or middlebox that has always
                   done this and that 5.8.0's downgrade refusal is the
                   first release to notice.
                   Every one of these is off by default.

Options: --host ADDRESS (bind elsewhere than 127.0.0.1 — "::1" opens an
AF_INET6 socket), --interfaces N, --reboot-after N, --dark-after N, --window SECONDS,
--bump-boots-at SECONDS, --stats PATH (a JSON counter file the test reads),
--reply-delay SECONDS, --bulk-cap N, --gen-err OID, --no-such-name OID,
--refuse-bulk, --dark-after-rows N (answer N ifIndex rows and then stop
answering walk requests at all, the mid-table timeout with rows already in
hand), --stale-id N (prepend a wrong-request-id copy to the
first N replies — the datagram _Session.dropped counts), and the v3
--auth-pass/--auth-proto/--require-priv/--priv-pass/--priv-proto/
--tamper-reply/--unsigned-replies described above. Answering from
the wrong SOURCE PORT deliberately has no flag: _Session._is_peer compares
the host only, because agents that reply from an ephemeral port are common
and not forgery, so a wrong port is not a dropped datagram here.

Prints one "listening" line after bind(), the banner tests/_paths.py's
spawn_stub waits for.
"""
import hmac
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/

from netpath import nodeoids, snmpcrypt
from netpath.snmppoll import (
    FLAG_AUTH, FLAG_PRIV, SnmpPrivError, decode_response, find_auth_span, sign_v3,
)
from netpath.trapdecode import (
    AUTH_PROTOCOLS, PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT, PDU_RESPONSE,
    T_COUNTER32, T_COUNTER64, T_END_OF_MIB_VIEW, T_GAUGE32, T_NO_SUCH_OBJECT,
    T_NULL, T_INTEGER, T_OCTET_STRING, T_SEQUENCE, T_TIMETICKS, V3, Reader,
    _signed, _tlv, enc_int, enc_octets, enc_unsigned, enc_varbind, localized_key,
    privacy_key,
)

COMMUNITY = "public"
UPTIME_TICKS = 987_654
ENGINE_ID = b"\x80\x00\x1f\x88\x80stub-engine"
USM_UNSUPPORTED_SEC_LEVELS = "1.3.6.1.6.3.15.1.1.1.0"
USM_NOT_IN_TIME_WINDOWS = "1.3.6.1.6.3.15.1.1.2.0"
USM_UNKNOWN_ENGINE_IDS = "1.3.6.1.6.3.15.1.1.4.0"
USM_WRONG_DIGESTS = "1.3.6.1.6.3.15.1.1.5.0"
USM_DECRYPTION_ERRORS = "1.3.6.1.6.3.15.1.1.6.0"
# RFC 3416's authorizationError: the agent accepted the message and
# refused the object under its own access control.
AUTHORIZATION_ERROR = 16


class Agent:
    def __init__(self, port: int, mode: str = "ok", interfaces: int = 2,
                 reboot_after: int = 2, window: float = 1.0,
                 bump_boots_at: float = 0.0, stats_path: str = "",
                 dark_after: int = 0, host: str = "127.0.0.1",
                 reply_delay: float = 0.0, bulk_cap: int = 0,
                 gen_err: tuple = (), no_such_name: tuple = (),
                 refuse_bulk: bool = False, stale_id: int = 0,
                 dark_after_rows: int = 0, require_priv: bool = False,
                 auth_pass: str = "", auth_proto: str = "SHA",
                 priv_pass: str = "", priv_proto: str = "AES",
                 tamper_reply: bool = False, unsigned_replies: bool = False):
        self.mode = mode
        self.n_interfaces = interfaces
        self.require_priv = require_priv
        self.auth_pass = auth_pass
        self.auth_proto = auth_proto
        self.priv_pass = priv_pass
        self.priv_proto = priv_proto
        self.tamper_reply = tamper_reply
        self.unsigned_replies = unsigned_replies
        # Every msgPrivacyParameters this agent received and every one it
        # sent, in order, as hex — the evidence for the non-reuse test.
        self.salts_seen: list[str] = []
        self.salts_sent: list[str] = []
        self.reply_delay = reply_delay
        self.bulk_cap = bulk_cap
        self.gen_err = tuple(gen_err)
        self.no_such_name = tuple(no_such_name)
        self.refuse_bulk = refuse_bulk
        self.stale_id = stale_id
        self.dark_after_rows = dark_after_rows
        self.rows_served = 0
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.host = host
        self.walked = False          # dark_after_walk: has the ifIndex walk run?
        self.in_octets = 1_000_000
        self.reboot_after = reboot_after
        self.uptime_reads = 0
        self.sys_name = "iftable-stub"
        # Extra instance OIDs this mode serves, beyond the scalars and the
        # ifTable: vendor health tables, ipAddrTable. Walked as well as
        # GET-able, so the poller's column walks find them.
        self.extra = self._vendor_objects()
        self.window = window
        self.dark_after = dark_after
        self.gets = 0
        self.bump_boots_at = bump_boots_at
        self.bumped = False
        self.last_request_at = None   # the idle gap --bump-boots-at measures
        self.stats_path = stats_path
        self.engine_boots = 3
        self.engine_epoch = time.monotonic()
        self.counts = {"requests": 0, "reports": 0, "discoveries": 0,
                       "responses": 0, "get": 0, "getnext": 0, "getbulk": 0,
                       "bulk_refused": 0, "stale": 0,
                       # v3 refusals, by kind: a wrong digest, and a
                       # request accepted and then denied the object.
                       "wrong_digests": 0, "denied": 0,
                       # authPriv: requests decrypted, ones that would not
                       # decrypt, and a received salt seen twice (never).
                       "decrypted": 0, "decrypt_errors": 0, "salt_reuse": 0}

    # ------------------------------------------------------------- SNMPv3

    @staticmethod
    def _msg_header(data: bytes) -> tuple[int, int]:
        """The request's (msgID, msgFlags). The id is echoed back the way
        a real agent does; the flags say whether the request was signed
        and whether it asked for privacy, which is what --auth-pass and
        --require-priv decide on. decode_response surfaces neither, so
        they are read here."""
        top = Reader(data)
        body_s, body_e = top.expect(T_SEQUENCE)
        msg = Reader(data, body_s, body_e)
        msg.expect(T_INTEGER)                      # version
        hs, he = msg.expect(T_SEQUENCE)            # msgGlobalData
        header = Reader(data, hs, he)
        s, e = header.expect(T_INTEGER)
        msg_id = _signed(data, s, e)
        header.expect(T_INTEGER)                   # msgMaxSize
        fs, fe = header.expect(T_OCTET_STRING)      # msgFlags
        return msg_id, (data[fs] if fe > fs else 0)

    def _digest_ok(self, data: bytes) -> bool:
        """Whether a signed request's digest is the one --auth-pass makes:
        RFC 3414 §6.3.2 in reverse of build_v3_request — the auth field
        blanked, the whole message HMACed with the key localized to THIS
        engine, the leading digest-length bytes compared."""
        ctor, length = AUTH_PROTOCOLS[self.auth_proto]
        key = localized_key(self.auth_proto, self.auth_pass, ENGINE_ID)
        start, end = find_auth_span(data)
        blank = data[:start] + bytes(end - start) + data[end:]
        expected = hmac.new(key, blank, ctor).digest()[:length]
        return hmac.compare_digest(expected, data[start:end])

    def _auth_key(self) -> bytes:
        return localized_key(self.auth_proto, self.auth_pass, ENGINE_ID)

    def _priv_key(self) -> bytes:
        return privacy_key(self.auth_proto, self.priv_pass, ENGINE_ID)

    @staticmethod
    def _priv_params(data: bytes) -> bytes:
        """The msgPrivacyParameters an inbound message carried — the field
        right after the one find_auth_span locates."""
        _start, end = find_auth_span(data)
        params = Reader(data, end)
        ps, pe = params.expect(T_OCTET_STRING)
        return data[ps:pe]

    def engine_time(self) -> int:
        return int(time.monotonic() - self.engine_epoch)

    def _bump_boots(self) -> None:
        """The agent restarted: engineBoots increments and engineTime goes
        back to zero, so every cached engine parameter a poller holds is
        now wrong and it must resync off our Report."""
        self.engine_boots += 1
        self.engine_epoch = time.monotonic()

    def _v3_message(self, msg_id: int, pdu: bytes, level: int = 0) -> bytes:
        """One reply at `level` (FLAG_AUTH and/or FLAG_PRIV), clipped to
        what this agent can actually produce: it signs only with an auth
        key and encrypts only with a privacy key. Encrypt first, sign
        last — the same order build_v3_request uses, because it is the
        order RFC 3414 s3.1 prescribes for everyone."""
        level &= ((FLAG_AUTH if self.auth_pass else 0) |
                  (FLAG_PRIV if self.priv_pass else 0))
        if self.unsigned_replies:
            level = 0
        boots, now = self.engine_boots, self.engine_time()
        scoped = _tlv(T_SEQUENCE, enc_octets(ENGINE_ID) + enc_octets("") + pdu)
        priv_params = b""
        if level & FLAG_PRIV:
            ciphertext, priv_params = snmpcrypt.encrypt(self._priv_key(), boots, now, scoped)
            scoped = _tlv(T_OCTET_STRING, ciphertext)
            self.salts_sent.append(priv_params.hex())
        digest_len = AUTH_PROTOCOLS[self.auth_proto][1] if level & FLAG_AUTH else 0
        header = _tlv(T_SEQUENCE, enc_int(msg_id) + enc_int(65507) +
                      _tlv(T_OCTET_STRING, bytes([level])) + enc_int(3))
        usm_body = (enc_octets(ENGINE_ID) + enc_int(boots) + enc_int(now) +
                    enc_octets("") + _tlv(T_OCTET_STRING, bytes(digest_len)) +
                    _tlv(T_OCTET_STRING, priv_params))
        sec = _tlv(T_OCTET_STRING, _tlv(T_SEQUENCE, usm_body))
        message = _tlv(T_SEQUENCE, enc_int(V3) + header + sec + scoped)
        if level & FLAG_AUTH:
            message = sign_v3(message, self.auth_proto, self._auth_key())
        return message

    def _tampered(self, message: bytes) -> bytes:
        """The last byte flipped AFTER signing — inside the ScopedPDU, or
        inside the ciphertext — so the digest no longer matches."""
        return message[:-1] + bytes([message[-1] ^ 0xFF])

    @staticmethod
    def _pdu(tag: int, request_id: int, varbinds: bytes,
             error_status: int = 0, error_index: int = 0) -> bytes:
        """error-status/error-index were hardcoded to 0 here, which is why
        a v3 agent that accepts the message and refuses the object could
        not be simulated, and why that fault shipped."""
        return _tlv(tag, enc_int(request_id) + enc_int(error_status) +
                    enc_int(error_index) + _tlv(T_SEQUENCE, varbinds))

    def _report(self, msg_id: int, request_id: int, oid: str, level: int = 0) -> bytes:
        """A Report-PDU. Unauthenticated by default, as an agent's are for
        everything it could not verify (unknown engine or user, a wrong
        digest, a level it does not serve, a message it could not
        decrypt); notInTimeWindows alone is sent signed (authNoPriv) when
        the request was, the way net-snmp does it, since by then the
        signature HAS verified and the manager is expected to check the
        Report's own."""
        self.counts["reports"] += 1
        body = enc_varbind(oid, enc_unsigned(T_COUNTER32, self.counts["reports"]))
        return self._v3_message(msg_id, self._pdu(PDU_REPORT, request_id, body),
                                level & FLAG_AUTH)

    def _v3_handle(self, req, msg_id: int, flags: int = 0,
                   data: bytes = b"", verified: bool = False) -> list:
        self.counts["requests"] += 1
        # Replies go back at the request's own level; the flags that
        # arrived are the flags that leave (clipped by what we can do).
        level = flags & (FLAG_AUTH | FLAG_PRIV)
        now = time.monotonic()
        # The requests of one poll arrive within milliseconds of each other;
        # the test's deliberate sleep between polls is the only gap that
        # reaches the deadline, so the restart lands exactly where the test
        # says it does whatever the runner's speed.
        if self.bump_boots_at and not self.bumped and \
                self.last_request_at is not None and \
                now - self.last_request_at >= self.bump_boots_at:
            self.bumped = True
            self._bump_boots()
        self.last_request_at = now
        if not req.engine_id:
            # Engine discovery: an unauthenticated, empty, reportable GET.
            self.counts["discoveries"] += 1
            return [self._report(msg_id, req.request_id,
                                 USM_UNKNOWN_ENGINE_IDS)]
        if req.engine_id != ENGINE_ID:
            return [self._report(msg_id, req.request_id,
                                 USM_NOT_IN_TIME_WINDOWS)]
        # RFC 3414 §3.2's order: the signature (step 6) is checked before
        # the time window (step 7), so a wrong password reads as
        # wrongDigests whatever the clock says. Off unless --auth-pass was
        # given, so every existing suite sees the agent it always did.
        if self.auth_pass:
            if not flags & FLAG_AUTH:
                return [self._report(msg_id, req.request_id,
                                     USM_UNSUPPORTED_SEC_LEVELS)]
            if not verified and not self._digest_ok(data):
                self.counts["wrong_digests"] += 1
                return [self._report(msg_id, req.request_id, USM_WRONG_DIGESTS)]
        if self.priv_pass and not flags & FLAG_PRIV:
            # An authPriv user sent an authNoPriv request: USM refuses it
            # before VACM ever sees it (RFC 3414 s3.2 step 5). This is the
            # OTHER thing a real agent may do with the PAN-OS case —
            # --require-priv is the VACM version of the same mismatch.
            return [self._report(msg_id, req.request_id,
                                 USM_UNSUPPORTED_SEC_LEVELS)]
        if req.engine_boots != self.engine_boots \
                or abs(req.engine_time - self.engine_time()) > self.window:
            return [self._report(msg_id, req.request_id,
                                 USM_NOT_IN_TIME_WINDOWS, level)]
        self.counts["responses"] += 1
        if self.require_priv and not flags & FLAG_PRIV and \
                req.pdu_tag in (PDU_GET, PDU_GETNEXT, PDU_GETBULK):
            # The message was accepted — USM is done with it — and VACM
            # finds no access entry for this user at this level. PAN-OS
            # provisions its user at authPriv; an authNoPriv request
            # matches nothing, and the answer is an ordinary Response-PDU
            # with error-status 16, error-index 1 and the request's own
            # varbinds echoed as nulls, the way net-snmp answers it.
            self.counts["denied"] += 1
            echo = b"".join(enc_varbind(vb["oid"], _tlv(T_NULL, b""))
                            for vb in req.varbinds)
            return [self._v3_message(
                msg_id, self._pdu(PDU_RESPONSE, req.request_id, echo,
                                  error_status=AUTHORIZATION_ERROR,
                                  error_index=1), level)]
        reply = None
        if req.pdu_tag == PDU_GET:
            body = b""
            for vb in req.varbinds:
                value = self.value_for(vb["oid"])
                body += enc_varbind(vb["oid"], value if value is not None
                                    else _tlv(T_NO_SUCH_OBJECT, b""))
            reply = self._v3_message(
                msg_id, self._pdu(PDU_RESPONSE, req.request_id, body), level)
        elif req.pdu_tag in (PDU_GETNEXT, PDU_GETBULK):
            oid, value = self._next_after(req.varbinds[0]["oid"])
            reply = self._v3_message(
                msg_id, self._pdu(PDU_RESPONSE, req.request_id,
                                  enc_varbind(oid, value)), level)
        if reply is None:
            return []
        return [self._tampered(reply) if self.tamper_reply else reply]

    def _v3_encrypted(self, msg_id: int, flags: int, data: bytes) -> list:
        """An inbound message with the privacy flag set. The digest is
        verified BEFORE anything is decrypted — RFC 3414 s3.2, and the
        same reason the poller does it in that order — and a message that
        decrypts to something other than a ScopedPDU draws
        usmStatsDecryptionErrors with request-id 0, since the id is inside
        the part that could not be read. A real agent does exactly this,
        which is what makes a wrong privacy password distinguishable from
        a wrong authentication one at the poller."""
        if not self.priv_pass:
            # This user is not provisioned for privacy: refused before any
            # attempt to read the PDU, as an agent must (RFC 3414 s3.2 5).
            self.counts["requests"] += 1
            return [self._report(msg_id, 0, USM_UNSUPPORTED_SEC_LEVELS)]
        if self.auth_pass and (not flags & FLAG_AUTH or not self._digest_ok(data)):
            self.counts["requests"] += 1
            self.counts["wrong_digests"] += 1
            return [self._report(msg_id, 0, USM_WRONG_DIGESTS)]
        salt = self._priv_params(data).hex()
        if salt in self.salts_seen:
            self.counts["salt_reuse"] += 1
        self.salts_seen.append(salt)
        try:
            req = decode_response(data, priv_proto=self.priv_proto,
                                  priv_key=self._priv_key())
        except SnmpPrivError:
            self.counts["requests"] += 1
            self.counts["decrypt_errors"] += 1
            return [self._report(msg_id, 0, USM_DECRYPTION_ERRORS)]
        self.counts["decrypted"] += 1
        return self._v3_handle(req, msg_id, flags, data, verified=True)

    def write_stats(self) -> None:
        """Rewritten atomically: the test reads this file while the stub is
        still serving, and a half-written one is not valid JSON."""
        if not self.stats_path:
            return
        temporary = self.stats_path + ".tmp"
        with open(temporary, "w") as handle:
            json.dump(dict(self.counts, engine_boots=self.engine_boots,
                           salts_seen=self.salts_seen, salts_sent=self.salts_sent),
                      handle)
        # On Windows the replace fails with EACCES while the test has the
        # destination open for its own read. Retry briefly; and never let a
        # stats hiccup escape, because this is called from serve() and a
        # dead stub turns every later poll into "connection forcibly closed".
        for attempt in range(20):
            try:
                os.replace(temporary, self.stats_path)
                return
            except PermissionError:
                time.sleep(0.01)
        try:
            os.replace(temporary, self.stats_path)
        except OSError as exc:
            print(f"stub stats not written: {exc}", flush=True)

    # ---------------------------------------------------------------- values

    def rebooted(self) -> bool:
        """True once this agent has 'restarted': sysUpTime drops and every
        counter restarts from a low value at the same moment, exactly as a
        real agent's do."""
        return self.mode == "reboot" and self.uptime_reads > self.reboot_after

    def indexes(self) -> list[str]:
        """The ifIndex column's own suffixes, as text. `nonnumeric` puts a
        garbled one in the middle: a real agent under a broken row can do
        this, and the poller used to abandon the walk at that point and
        then delete every interface it had not reached."""
        rows = [str(i) for i in range(1, self.n_interfaces + 1)]
        if self.mode == "nonnumeric" and len(rows) >= 2:
            rows.insert(1, "1.5")
        return rows

    _SYS_OBJECT_IDS = {
        "fortigate": "1.3.6.1.4.1.12356.101.1.1000",
        "cisco": "1.3.6.1.4.1.9.1.1208",
        # panPA5220 — the enterprise arc a Palo Alto firewall identifies by.
        "palo_alto": "1.3.6.1.4.1.25461.2.3.34",
    }

    def _vendor_objects(self) -> dict:
        """The vendor health and address objects for this mode, as
        instance OID -> encoded value."""
        if self.mode == "fortigate":
            return {
                # fgSysCpuUsage / fgSysMemUsage / fgSysSesCount
                "1.3.6.1.4.1.12356.101.4.1.3.0": enc_unsigned(T_GAUGE32, 95),
                "1.3.6.1.4.1.12356.101.4.1.4.0": enc_unsigned(T_GAUGE32, 61),
                "1.3.6.1.4.1.12356.101.4.1.8.0": enc_unsigned(T_GAUGE32, 1234),
                # ipAddrTable: the address the devices table knows, and a
                # loopback the device also answers on and sends traps from.
                "1.3.6.1.2.1.4.20.1.1.127.0.0.1": enc_octets("127.0.0.1"),
                "1.3.6.1.2.1.4.20.1.1.10.9.9.9": enc_octets("10.9.9.9"),
            }
        if self.mode == "cisco":
            return {
                # cpmCPUTotal5minRev, one CPU
                "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": enc_unsigned(T_GAUGE32, 42),
                # ciscoMemoryPoolUsed / Free, processor and I/O pools:
                # 300 MB used of 400 MB total = 75%.
                "1.3.6.1.4.1.9.9.48.1.1.1.5.1": enc_unsigned(T_GAUGE32, 200_000_000),
                "1.3.6.1.4.1.9.9.48.1.1.1.5.2": enc_unsigned(T_GAUGE32, 100_000_000),
                "1.3.6.1.4.1.9.9.48.1.1.1.6.1": enc_unsigned(T_GAUGE32, 60_000_000),
                "1.3.6.1.4.1.9.9.48.1.1.1.6.2": enc_unsigned(T_GAUGE32, 40_000_000),
            }
        return {}

    def _scalar(self, oid: str):
        S = nodeoids.SYSTEM_SCALARS
        if oid == S["sys_descr"]:
            if self.mode == "palo_alto":
                return enc_octets("Palo Alto Networks PA-5220 series firewall")
            return enc_octets("ifTable stub agent")
        if oid == S["sys_object_id"]:
            return enc_octets(self._SYS_OBJECT_IDS.get(
                self.mode, "1.3.6.1.4.1.99999.1"))
        if oid == S["sys_uptime"]:
            self.uptime_reads += 1
            if self.rebooted():
                return enc_unsigned(T_TIMETICKS, 800)   # 8 seconds up
            return enc_unsigned(T_TIMETICKS, UPTIME_TICKS + self.uptime_reads)
        if oid == S["sys_contact"]:
            return enc_octets("noc@example.com")
        if oid == S["sys_name"]:
            return enc_octets(self.sys_name)
        if oid == S["sys_location"]:
            return enc_octets("lab")
        if self.mode in self._SYS_OBJECT_IDS:
            # Real vendor gear does not implement UCD-SNMP-MIB; answering
            # it here would hide whether the vendor objects were read.
            return None
        U = nodeoids.UCD_SNMP
        if oid == U["cpu_raw_idle"]:
            return enc_unsigned(T_GAUGE32, 75)      # 25% busy
        if oid == U["mem_avail_kb"]:
            return enc_unsigned(T_GAUGE32, 4_000_000)
        if oid == U["mem_total_kb"]:
            return enc_unsigned(T_GAUGE32, 8_000_000)
        return None

    def counter_base(self) -> int:
        """Where this agent's counters currently sit. They advance once per
        poll (sysUpTime is read exactly once per poll) and restart from
        nearly zero after a 'reboot' — which is what makes a naive rate
        calculation report an enormous burst across the restart."""
        if self.rebooted():
            return 700 * (self.uptime_reads - self.reboot_after)
        return self.in_octets + 125_000 * self.uptime_reads

    def _if_value(self, key: str, index: int):
        if not 1 <= index <= self.n_interfaces:
            return None
        if key == "if_index":
            return enc_int(index)
        if key == "if_descr":
            return enc_octets(f"Gi0/{index}")
        if key == "if_type":
            return enc_int(6)                        # ethernetCsmacd
        if key == "if_admin_status":
            return enc_int(1)
        if key == "if_oper_status":
            return enc_int(1)
        if key == "if_phys_addr":
            return enc_octets(bytes([0x02, 0, 0, 0, 0, index & 0xFF]))
        if key == "if_speed":
            return enc_unsigned(T_GAUGE32, 1_000_000_000)
        base = self.counter_base()
        if key == "if_in_octets":
            return enc_unsigned(T_COUNTER32, (base + index) % (2 ** 32))
        if key == "if_out_octets":
            return enc_unsigned(T_COUNTER32, (base // 2 + index) % (2 ** 32))
        if key == "if_in_errors":
            return enc_unsigned(T_COUNTER32, base // 1000 + index)
        if key == "if_out_errors":
            return enc_unsigned(T_COUNTER32, 0)
        if key == "if_in_discards":
            return enc_unsigned(T_COUNTER32, base // 2000 + index)
        if key == "if_out_discards":
            return enc_unsigned(T_COUNTER32, 0)
        return None

    def _ifx_value(self, key: str, index: int):
        if not 1 <= index <= self.n_interfaces:
            return None
        if key == "if_alias":
            return enc_octets(f"link-{index}")
        if key == "if_high_speed":
            return enc_unsigned(T_GAUGE32, 1000)
        base = self.counter_base()
        if key == "if_hc_in_octets":
            return enc_unsigned(T_COUNTER64, base + index)
        if key == "if_hc_out_octets":
            return enc_unsigned(T_COUNTER64, base // 2 + index)
        return None

    @staticmethod
    def _split(oid: str, table: dict):
        for key, base in table.items():
            if oid.startswith(base + "."):
                suffix = oid[len(base) + 1:]
                try:
                    return key, int(suffix)
                except ValueError:
                    return key, None
        return None, None

    def value_for(self, oid: str):
        """The encoded value for one instance OID, or None when this agent
        does not implement it."""
        if oid in self.extra:
            return self.extra[oid]
        value = self._scalar(oid)
        if value is not None:
            return value
        key, index = self._split(oid, nodeoids.IF_TABLE)
        if key is not None and index is not None:
            return self._if_value(key, index)
        key, index = self._split(oid, nodeoids.IFX_TABLE)
        if key is not None and index is not None:
            return self._ifx_value(key, index)
        return None

    def implements_ifx(self) -> bool:
        return self.mode != "v1_nosuchname"

    # ----------------------------------------------------------------- wire

    def _response(self, version, request_id, varbinds: bytes,
                  error_status: int = 0, error_index: int = 0) -> bytes:
        pdu = _tlv(PDU_RESPONSE,
                   enc_int(request_id) + enc_int(error_status) +
                   enc_int(error_index) + _tlv(T_SEQUENCE, varbinds))
        return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(COMMUNITY) + pdu)

    def _get_reply(self, req, request_id: int | None = None):
        oids = [vb["oid"] for vb in req.varbinds]
        request_id = req.request_id if request_id is None else request_id
        if not self.implements_ifx():
            # A v1 agent answers the whole PDU with noSuchName as soon as
            # one named object is unimplemented, and echoes the varbind
            # list back as nulls.
            for position, oid in enumerate(oids, start=1):
                if self.value_for(oid) is None:
                    nulls = b"".join(enc_varbind(o, _tlv(T_NULL, b""))
                                     for o in oids)
                    return self._response(req.version, request_id, nulls,
                                          error_status=2, error_index=position)
        body = b""
        for oid in oids:
            value = self.value_for(oid)
            body += enc_varbind(
                oid, value if value is not None else _tlv(T_NO_SUCH_OBJECT, b""))
        return self._response(req.version, request_id, body)

    @staticmethod
    def _key(oid: str):
        return tuple((0, int(a)) if a.isdigit() else (1, a)
                     for a in oid.split("."))

    def _next_after(self, oid: str):
        """The lexicographic successor across everything this agent serves:
        the ifIndex column, and whatever vendor table the mode adds."""
        base = nodeoids.IF_TABLE["if_index"]
        self.walked = True
        self.rows_served += 1
        walkable = [(f"{base}.{suffix}", enc_int(position + 1))
                    for position, suffix in enumerate(self.indexes())]
        walkable += sorted(self.extra.items(), key=lambda item: self._key(item[0]))
        walkable.sort(key=lambda item: self._key(item[0]))
        wanted = self._key(oid)
        for candidate, value in walkable:
            if self._key(candidate) > wanted:
                return candidate, value
        # Past everything: an OID outside any subtree being walked, which
        # is how an agent says the table ended.
        return "9.9.9.9", enc_octets("past-the-end")

    def _refusal(self, req):
        """The error-status this agent answers the requested subtree with,
        or 0. A net-snmp agent (so PAN-OS) answers genErr for a subtree its
        own handler failed on, and noSuchName for one a v1 view hides;
        neither carries a usable varbind, which is exactly what a walker
        testing only for tooBig reads as the end of the table."""
        asked = req.varbinds[0]["oid"] if req.varbinds else ""
        for prefix in self.no_such_name:
            if asked == prefix or asked.startswith(prefix.rstrip(".") + "."):
                return 2
        for prefix in self.gen_err:
            if asked == prefix or asked.startswith(prefix.rstrip(".") + "."):
                return 5
        return 0

    def _stale_copy(self, reply_bytes, req):
        """A duplicate of this reply carrying request-id + 1, sent first.
        A receiver that takes the first datagram off the socket stores the
        wrong answer; _Session drops it and counts it."""
        if self.counts["stale"] >= self.stale_id:
            return None
        self.counts["stale"] += 1
        return reply_bytes

    def handle(self, data: bytes) -> list:
        """Every datagram this agent wants to send back, in order. A list
        because a misbehaving agent sends more than one."""
        if self.mode == "v3":
            msg_id, flags = self._msg_header(data)
            if flags & FLAG_PRIV:
                return self._v3_encrypted(msg_id, flags, data)
            return self._v3_handle(decode_response(data), msg_id, flags, data)
        req = decode_response(data)
        if req.pdu_tag == PDU_GET:
            self.gets += 1
            self.counts["get"] += 1
        elif req.pdu_tag == PDU_GETNEXT:
            self.counts["getnext"] += 1
        elif req.pdu_tag == PDU_GETBULK:
            self.counts["getbulk"] += 1
        refusal = self._refusal(req)
        if refusal:
            echo = b"".join(enc_varbind(vb["oid"], _tlv(T_NULL, b""))
                            for vb in req.varbinds)
            return [self._response(req.version, req.request_id, echo,
                                   error_status=refusal, error_index=1)]
        if self.refuse_bulk and req.pdu_tag == PDU_GETBULK:
            self.counts["bulk_refused"] += 1
            return [self._response(req.version, req.request_id, b"",
                                   error_status=1)]
        if self.mode == "dark_after_walk" and self.walked and \
                req.pdu_tag == PDU_GET and self.gets > self.dark_after:
            return []                        # answered its share, now silent
        if self.dark_after_rows and self.rows_served >= self.dark_after_rows \
                and req.pdu_tag in (PDU_GETNEXT, PDU_GETBULK):
            # Answered part of the table and then stopped: a mid-walk
            # timeout, with rows already in hand. GETs still answer, so
            # this is the agent that is slow/overloaded on the table
            # rather than the device that has gone away.
            return []
        if req.pdu_tag == PDU_GET:
            if self.mode == "stale_id":
                # The late answer to somebody else's attempt, first, with
                # a value a receiver that accepts it will visibly store.
                self.sys_name = "STALE-WRONG-ANSWER"
                stale = self._get_reply(req, request_id=req.request_id + 1)
                self.sys_name = "iftable-stub"
                return [stale, self._get_reply(req)]
            replies = [self._get_reply(req)]
        elif req.pdu_tag == PDU_GETNEXT:
            oid, value = self._next_after(req.varbinds[0]["oid"])
            replies = [self._response(req.version, req.request_id,
                                      enc_varbind(oid, value))]
        elif req.pdu_tag == PDU_GETBULK:
            cursor = req.varbinds[0]["oid"]
            body = b""
            wanted = max(1, req.error_index or 1)
            # net-snmp does not answer tooBig when the reply would not fit:
            # it sends the varbinds that DO fit and stops. A walker resumes
            # from the last one and never learns it asked for too much,
            # which is why the cap is silent truncation and not an error.
            if self.bulk_cap:
                wanted = min(wanted, self.bulk_cap)
            for _ in range(wanted):
                cursor, value = self._next_after(cursor)
                body += enc_varbind(cursor, value)
                if not cursor.startswith(nodeoids.IF_TABLE["if_index"] + "."):
                    break
            replies = [self._response(req.version, req.request_id, body)]
        else:
            return []
        if self.stale_id:
            stale = self._stale_copy(
                self._response(req.version, req.request_id + 1, b""), req)
            if stale is not None:
                replies.insert(0, stale)
        return replies

    def serve(self):
        print(f"listening on {self.host}:{self.port} ({self.mode})", flush=True)
        while True:
            data, addr = self.sock.recvfrom(65535)
            try:
                replies = self.handle(data)
            except Exception as exc:          # a stub must not die quietly
                print(f"stub error: {exc}", flush=True)
                continue
            if self.reply_delay:
                # After handle(), not before: the delay is the agent being
                # slow to answer, and every reply of this request pays it.
                time.sleep(self.reply_delay)
            for reply in replies or ():
                self.sock.sendto(reply, addr)
            self.write_stats()


def main(argv):
    port = int(argv[0])
    mode = "ok"
    interfaces = 2
    reboot_after = 2
    window = 1.0
    bump_boots_at = 0.0
    stats_path = ""
    dark_after = 0
    host = "127.0.0.1"
    reply_delay = 0.0
    bulk_cap = 0
    gen_err = []
    no_such_name = []
    refuse_bulk = False
    stale_id = 0
    dark_after_rows = 0
    require_priv = False
    auth_pass = ""
    auth_proto = "SHA"
    priv_pass = ""
    priv_proto = "AES"
    tamper_reply = False
    unsigned_replies = False
    rest = list(argv[1:])
    while rest:
        item = rest.pop(0)
        if item == "--require-priv":
            require_priv = True
        elif item == "--auth-pass":
            auth_pass = rest.pop(0)
        elif item == "--auth-proto":
            auth_proto = rest.pop(0)
        elif item == "--priv-pass":
            priv_pass = rest.pop(0)
        elif item == "--priv-proto":
            priv_proto = rest.pop(0)
        elif item == "--tamper-reply":
            tamper_reply = True
        elif item == "--unsigned-replies":
            unsigned_replies = True
        elif item == "--reply-delay":
            reply_delay = float(rest.pop(0))
        elif item == "--bulk-cap":
            bulk_cap = int(rest.pop(0))
        elif item == "--gen-err":
            gen_err += [o for o in rest.pop(0).split(",") if o]
        elif item == "--no-such-name":
            no_such_name += [o for o in rest.pop(0).split(",") if o]
        elif item == "--refuse-bulk":
            refuse_bulk = True
        elif item == "--stale-id":
            stale_id = int(rest.pop(0))
        elif item == "--dark-after-rows":
            dark_after_rows = int(rest.pop(0))
        elif item == "--interfaces":
            interfaces = int(rest.pop(0))
        elif item == "--reboot-after":
            reboot_after = int(rest.pop(0))
        elif item == "--window":
            window = float(rest.pop(0))
        elif item == "--bump-boots-at":
            bump_boots_at = float(rest.pop(0))
        elif item == "--stats":
            stats_path = rest.pop(0)
        elif item == "--dark-after":
            dark_after = int(rest.pop(0))
        elif item == "--host":
            host = rest.pop(0)
        else:
            mode = item
    Agent(port, mode, interfaces, reboot_after, window, bump_boots_at,
          stats_path, dark_after, host, reply_delay, bulk_cap, tuple(gen_err),
          tuple(no_such_name), refuse_bulk, stale_id, dark_after_rows,
          require_priv, auth_pass, auth_proto, priv_pass, priv_proto,
          tamper_reply, unsigned_replies).serve()


if __name__ == "__main__":
    main(sys.argv[1:])

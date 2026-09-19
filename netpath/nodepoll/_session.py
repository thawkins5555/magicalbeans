from __future__ import annotations

import random
import socket
import threading
import time
from typing import NamedTuple
from .. import snmpcrypt
from ..snmppoll import ERROR_STATUS, PDU_REPORT, Response, SnmpAccessDenied, SnmpAuthError, SnmpDowngrade, SnmpPrivError, SnmpError, SnmpStray, SnmpTimeout, SnmpUnsupported, build_v3_request, decode_response, discovery_probe
from ..trapdecode import localized_key, privacy_key
from ._consts import MAX_UDP
from ._decode import report_reason




class EngineCache:
    """One entry per device needing v3: device_id -> (engine_id, boots,
    time, learned_at). A v3 device's first poll after startup (or after
    this entry expires) sends discovery_probe() first, learns engine
    parameters from the Report-PDU, then proceeds with the real signed
    request. Entries are kept for the process lifetime — engine boots/time
    only need refreshing if the target actually reboots or its clock skews
    enough to be rejected, and that shows up either as an auth failure (a
    Report) or, from an agent that discards what it will not accept, as a
    timeout on a request built from this entry; either one drops it and
    the next poll rediscovers. Not a background expiry timer. Until 5.8.1
    only the auth failure did, on the assumption a stale entry always
    draws a Report — it does not, and a silently refused entry was then
    reused every poll until the process restarted."""

    def __init__(self):
        self._entries: dict[int, tuple[bytes, int, int, float]] = {}
        self._lock = threading.Lock()

    def get(self, device_id: int):
        with self._lock:
            return self._entries.get(device_id)

    def current(self, device_id: int):
        """(engine_id, boots, engine_time) with engineTime advanced to now.

        engineTime is the agent's own clock in seconds, and RFC 3414 §3.2
        rejects an authenticated message whose engineTime is more than 150
        seconds from the agent's. Sending back the value learned at
        discovery would make every v3 device start failing 150 seconds
        after its first poll, so the elapsed wall time since it was learned
        is added.
        """
        with self._lock:
            entry = self._entries.get(device_id)
        if entry is None:
            return None
        engine_id, boots, engine_time, learned_at = entry
        elapsed = max(0.0, time.time() - learned_at)
        return engine_id, boots, engine_time + int(elapsed)

    def set(self, device_id: int, engine_id: bytes, boots: int, engine_time: int) -> None:
        with self._lock:
            self._entries[device_id] = (engine_id, boots, engine_time, time.time())

    def invalidate(self, device_id: int) -> None:
        with self._lock:
            self._entries.pop(device_id, None)

    def forget(self, device_ids) -> None:
        """Drop entries for devices that no longer exist. The cache is
        keyed by device id and kept for the process lifetime, so without
        this a long-running install accumulates one entry per device ever
        deleted."""
        keep = set(device_ids)
        with self._lock:
            for device_id in [k for k in self._entries if k not in keep]:
                self._entries.pop(device_id, None)


class _Session:
    """One UDP socket for one poll: send/recv with retry, closed after."""

    def __init__(self, ip: str, port: int, timeout_s: float, retries: int):
        self.ip = ip
        self.port = port
        self.timeout_s = max(0.2, float(timeout_s))
        self.retries = max(0, int(retries))
        # A device on an IPv6 management plane needs an AF_INET6 socket;
        # AF_INET was hardcoded, so every such device timed out on every
        # poll. A literal address is unambiguous — a colon cannot appear in
        # a dotted-quad — and the port is separate, so there is nothing to
        # parse.
        self.family = socket.AF_INET6 if ":" in str(ip) else socket.AF_INET
        try:
            self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        except OSError as exc:
            # A bare OSError here escapes every SnmpError handler, and
            # record_poll never runs -- the device's status freezes.
            raise SnmpError(f"could not open a socket for {ip}: {exc}") from exc
        self.sock.settimeout(self.timeout_s)
        # Request ids for this session's own exchanges. A counter from a
        # random start rather than random.randint per request: two requests
        # in one walk drawing the same id by chance is exactly the
        # confusion the id exists to prevent.
        self._request_id = random.randint(1, 2 ** 24)
        self.dropped = 0        # datagrams discarded as not ours

    def next_request_id(self) -> int:
        self._request_id = (self._request_id + 1) % (2 ** 31 - 1) or 1
        return self._request_id

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _is_peer(self, addr) -> bool:
        """Whether a datagram came from the device we asked. `addr` is
        (host, port[, flow, scope]) — only the host is compared, because a
        few agents answer from an ephemeral port rather than 161, which is
        odd but not forgery. IPv6 literals are compared after normalising
        both sides, since 'fe80::1' and 'fe80:0:0:0:0:0:0:1' are the same
        address written two ways."""
        try:
            source = addr[0]
        except (TypeError, IndexError):
            return False
        if source == self.ip:
            return True
        if self.family != socket.AF_INET6:
            return False
        try:
            packed = socket.inet_pton(socket.AF_INET6, source.split("%")[0])
            mine = socket.inet_pton(socket.AF_INET6, self.ip.split("%")[0])
        except (OSError, AttributeError):
            return False
        return packed == mine

    def request(self, packet: bytes, expect_request_id: int | None = None, *,
                expect_msg_id: int | None = None,
                auth_proto: str | None = None, auth_key: bytes | None = None,
                priv_proto: str | None = None, priv_key: bytes | None = None,
                verify: bool = True) -> Response:
        """Send, wait for OUR reply, decode it.

        The keys are the ones `packet` was built with, handed to
        decode_response so a signed reply's digest is verified and an
        encrypted one decrypted; a reply that fails either is raised, not
        dropped — see the except arm below. `verify=False` is the
        v3_verify_replies setting turned off: a reply below the level
        asked is accepted (a digest that IS present is still checked).

        A UDP socket accepts whatever arrives, so taking the first datagram
        would let a late answer to attempt 1 be read as the answer to
        attempt 2, and let any other address answer at all. A datagram from
        the wrong peer, or carrying a different request id, is dropped and
        the wait continues. The id test lives in decode_response
        (expect_request_id) rather than after it, because where it falls
        relative to the digest check matters: on an unencrypted reply the
        id is in the clear and is checked first, so a spoofed datagram
        with a made-up id is a dropped stray and not an auth alert; on an
        encrypted reply the id is inside the ciphertext and only the digest
        can come first. A Report-PDU is exempt from the id test: an agent
        reports an engine mismatch against its own msgID, and dropping it
        would turn one v3 resync into a timeout — but its msgID is
        checked instead (expect_msg_id), which is the field RFC 3412 s7.2
        has the receiver match and the one a forger cannot guess.

        Retries on timeout up to self.retries times; raises SnmpTimeout if
        every attempt times out.
        """
        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            try:
                self.sock.sendto(packet, (self.ip, self.port))
            except OSError as exc:
                last_error = SnmpError(str(exc))
                continue
            deadline = time.monotonic() + self.timeout_s
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                    break
                try:
                    self.sock.settimeout(remaining)
                    data, addr = self.sock.recvfrom(MAX_UDP)
                except socket.timeout:
                    last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                    break
                except ConnectionResetError:
                    # Windows: an ICMP port-unreachable reads as a reset on
                    # the next recvfrom, same as udpsock.py treats it.
                    last_error = SnmpTimeout(f"no reply from {self.ip}:{self.port}")
                    break
                except OSError as exc:
                    last_error = SnmpError(str(exc))
                    break
                if not self._is_peer(addr):
                    self.dropped += 1
                    continue
                try:
                    response = decode_response(
                        data, auth_proto=auth_proto, auth_key=auth_key,
                        priv_proto=priv_proto, priv_key=priv_key, verify=verify,
                        expect_request_id=expect_request_id,
                        expect_msg_id=expect_msg_id)
                except SnmpStray:
                    # Somebody else's answer, or a late one: not ours.
                    self.dropped += 1
                    continue
                except (SnmpUnsupported, SnmpAuthError, SnmpDowngrade, SnmpPrivError):
                    # Not garbage: a datagram from the right peer, answering
                    # THIS request, whose signature does not verify, or
                    # that cannot be decrypted, or that arrived below the
                    # level asked for. Waiting on past it would report a
                    # wrong key as a timeout, which is the misdiagnosis
                    # this exists to prevent.
                    raise
                except SnmpError as exc:
                    # Garbage from the right address is not an answer: keep
                    # waiting for one within this attempt's budget rather
                    # than failing the whole request on it.
                    self.dropped += 1
                    last_error = exc
                    continue
                return response
        raise last_error or SnmpTimeout(f"no reply from {self.ip}:{self.port}")


class Credential(NamedTuple):
    """What credential_for hands back: the identity, the authentication
    pair and the privacy pair, decrypted just in time and never cached.
    A NamedTuple rather than the bare 3-tuple it was so that `[0]` and
    iteration keep working where only the identity is wanted, while the
    old three-name unpack fails loudly rather than silently reading the
    privacy protocol as a password."""
    identity: str | None
    auth_proto: str | None
    auth_password: str | None
    priv_proto: str | None = None
    priv_password: str | None = None

    @property
    def security_level(self) -> str:
        """The USM level a request built from this credential goes out at,
        derived and not stored: an authentication pair makes it authNoPriv,
        a privacy pair on top of that makes it authPriv, neither is
        noAuthNoPriv. A privacy pair WITHOUT an authentication pair is not
        a level USM has and is reported as noAuthNoPriv here — v3_exchange
        refuses to send it rather than dropping the privacy silently."""
        if self.auth_proto and self.auth_password:
            if self.priv_proto and self.priv_password:
                return "authPriv"
            return "authNoPriv"
        return "noAuthNoPriv"


def _decrypt_secret(blob) -> str | None:
    """One stored secret, decrypted immediately before use. Raises whatever
    the store raises; the caller decides whether that is loud or silent."""
    from .. import dpapi
    return dpapi.unprotect(bytes(blob)).decode("utf-8")


def credential_for(config: dict) -> Credential:
    """Decrypt-just-in-time, the same shape as ipam_worker.credential_for_server:
    returns a Credential — (community_or_user, auth_proto, auth_password,
    priv_proto, priv_password) — with each stored blob decrypted
    immediately before use and never cached. `config` is already the
    effective_config() merge of a device's own overrides over its group's
    defaults.

    The two secrets are treated identically at rest, in flight and on
    failure: a stored blob that will not decrypt on this machine RAISES,
    it does not quietly become "no password". Until 5.8.0 an undecryptable
    authentication blob polled the device unsigned, which is the silent
    downgrade this whole release refuses at the other end of the wire —
    and after a database move it did so to every authNoPriv device at
    once, with the advice telling the operator to set a password that IS
    stored. A privacy blob that will not decrypt polling at authNoPriv is
    the same fault one level down: a request at the wrong level answered
    with authorizationError(16) against a password that was never wrong,
    the exact thing 5.7.2 was written to explain. Both only for a v3
    credential — a profile switched back to v2c can carry a stale blob it
    never reads, and that must not stop the community working.

    The identity is stripped, and a v1/v2c community carrying a comma is
    refused rather than transmitted. Both because an agent that dislikes
    the community it was sent does not say so — net-snmp (so PAN-OS)
    drops the datagram — so a pasted trailing space, or the
    comma-separated list that only nodediscover.py ever split, arrives as
    a timeout indistinguishable from an unreachable device.
    nodesdb.clean_community refuses the same comma at save time; this is
    what a database written before it did still reads as."""
    v3 = snmp_version_of(config) == 3
    if v3:
        identity = config.get("v3_user")
    else:
        identity = config.get("community")
        if identity and "," in identity:
            # Named, never printed: this message reaches devices.snmp_error,
            # the device event log, the API and any alert mail, and a
            # community string is a secret (see _credential_label).
            raise SnmpError(
                "the community configured for this device contains a comma "
                "— one device is polled with one community; put the "
                "alternates in the polling profile's credentials instead")
    if isinstance(identity, str):
        identity = identity.strip()
    auth_proto = config.get("v3_auth_proto")
    blob = config.get("v3_auth_pass_enc")
    password = None
    if blob and v3:
        try:
            password = _decrypt_secret(blob)
        except Exception as exc:
            raise SnmpError(
                f"the stored SNMPv3 authentication password for {identity!r} "
                f"could not be decrypted on this machine ({type(exc).__name__}) "
                f"— refusing to poll unsigned instead; re-enter the credential "
                f"here, or see CREDENTIAL-SECURITY.md on moving a database "
                f"between machines") from exc
    priv_proto = config.get("v3_priv_proto")
    priv_blob = config.get("v3_priv_pass_enc")
    priv_password = None
    if priv_proto and priv_blob and v3:
        try:
            priv_password = _decrypt_secret(priv_blob)
        except Exception as exc:
            password = None
            raise SnmpError(
                f"the stored SNMPv3 privacy password for {identity!r} could "
                f"not be decrypted on this machine ({type(exc).__name__}) — "
                f"refusing to poll at authNoPriv instead; re-enter the "
                f"credential here, or see CREDENTIAL-SECURITY.md on moving a "
                f"database between machines") from exc
    return Credential(identity, auth_proto, password, priv_proto, priv_password)


def snmp_version_of(config: dict) -> int:
    """The SNMP version a merged config polls at: 0 for v1, 1 for v2c, 3
    for v3, v2c when the column is absent. A None is the v2c default too,
    NOT `int(None)`: a device override row lays `snmp_version: None` over
    its profile when the field is left at "(profile)", nodesdb merges that
    away, and a merge that ever misses it again would make the poll die
    of a TypeError — which no `except SnmpError` catches, so record_poll
    never runs and the device's status freezes at whatever it last was.
    `or 1` would be wrong here: 0 is v1."""
    value = config.get("snmp_version")
    return 1 if value is None else int(value)


def discover_engine(session: _Session, ip: str) -> tuple[bytes, int, int]:
    """RFC 3414 §4's engine discovery: the empty, unauthenticated probe, and
    the (engine_id, boots, time) the agent's Report-PDU answers with.

    The probe carries this session's own msgID rather than the fixed 1 the
    builder defaults to, so the Report that answers it can be matched
    against it — a Report is exempt from the request-id filter, and
    discovery is the one exchange whose whole answer is a Report."""
    msg_id = session.next_request_id()
    response = session.request(discovery_probe(msg_id), expect_msg_id=msg_id)
    if not response.engine_id:
        raise SnmpError(f"{ip}: no engine id in discovery reply")
    return response.engine_id, response.engine_boots, response.engine_time


def v3_exchange(session: _Session, pdu_tag: int, oids: list[str], *,
                identity: str | None, auth_proto: str | None,
                password: str | None, engine: tuple | None = None,
                max_repetitions: int = 0, ip: str = "",
                learned=None, priv_proto: str | None = None,
                priv_password: str | None = None,
                verify_replies: bool = True) -> Response:
    """One authenticated v3 round trip, with the engine resync RFC 3414
    §3.2 actually prescribes — the ONE copy of it.

    The poller had this loop and the Test button did not, so a device with
    a skewed clock failed the Test while the poll shrugged it off, and an
    operator was told two different things about one device. Both call
    this now. A Report is what it is: the agent telling us its current
    engine id, boots and time. Those are learned (and handed to `learned`,
    so a caller with a cache can keep them), the request is retried once
    with them, and only a second Report is an error — named after the
    usmStats counter the agent pointed at, so a wrong password reads
    differently from a wrong clock, and a wrong PRIVACY password
    (decryptionErrors) differently from either. A refused security level
    is raised as SnmpUnsupported, which the poll path classifies as status
    'unsupported' rather than as an auth failure.

    `engine` is (engine_id, boots, time) if the caller already knows it;
    None discovers first. A Report carrying no engine id (or discovery
    itself failing) leaves the caller's cache to be rebuilt on the next
    call, exactly as before this was shared.

    With `priv_proto`/`priv_password` the exchange is authPriv: the privacy
    key is localised to the engine the request is built for (so a resync
    that teaches a new engine id re-derives it), the ScopedPDU goes out
    encrypted, and the reply must come back signed and encrypted or it is
    refused. A privacy password with no authentication password is
    refused up front — USM has no such level, and building authNoPriv
    instead would be the silent downgrade that ends in
    authorizationError(16). A reply whose signature does not verify, or
    that cannot be decrypted, is an _AuthFailure: the credential is what
    is wrong, and the engine cache is what the poller drops on one. A
    reply that carries NO signature to a signed request is SnmpDowngrade,
    passed through untouched: the credential is not wrong, the device (or
    something between here and it) is answering below the level asked —
    the poll files that as its own finding, neither an auth failure nor
    an outage — and `verify_replies=False` (the v3_verify_replies
    setting) is the operator's way to accept such replies."""
    encrypting = bool(priv_proto and priv_password)
    if encrypting and not (auth_proto and password):
        raise SnmpError(
            f"{ip}: the credential for {identity!r} has a privacy password "
            f"but no authentication password — USM has no privacy-without-"
            f"authentication level, so the request was not sent")
    if encrypting and not snmpcrypt.available():
        raise SnmpUnsupported(
            f"{ip}: authPriv needs the 'cryptography' package with a working "
            f"AES backend on this machine ({snmpcrypt.unavailable_reason()}); "
            f"install it and restart the worker, or poll this user at "
            f"authNoPriv")
    last: Response | None = None
    for attempt in (0, 1):
        if engine is None:
            engine = discover_engine(session, ip)
            if learned is not None:
                learned(*engine)
        engine_id, boots, engine_time = engine
        auth_key = localized_key(auth_proto, password, engine_id) \
            if auth_proto and password else None
        priv_key = privacy_key(auth_proto, priv_password, engine_id) \
            if encrypting else None
        request_id = session.next_request_id()
        msg_id = session.next_request_id()
        packet = _assemble(
            build_v3_request,
            msg_id, request_id, pdu_tag, oids,
            engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
            user=identity or "", auth_proto=auth_proto, auth_key=auth_key,
            max_repetitions=max_repetitions,
            priv_proto=priv_proto if encrypting else None, priv_key=priv_key)
        try:
            response = session.request(
                packet, request_id, expect_msg_id=msg_id,
                auth_proto=auth_proto, auth_key=auth_key,
                priv_proto=priv_proto if encrypting else None, priv_key=priv_key,
                verify=verify_replies)
        except SnmpAuthError as exc:
            raise _AuthFailure(f"{ip}: SNMPv3 reply rejected — {exc}") from exc
        except SnmpPrivError as exc:
            raise _AuthFailure(f"{ip}: SNMPv3 reply rejected — {exc}",
                               usm_name="decryptionErrors") from exc
        if response.pdu_tag != PDU_REPORT:
            return response
        last = response
        name, explanation = report_reason(response)
        # A Report is unauthenticated and exempt from the request-id
        # filter, so one forged datagram could teach this poller an
        # engine id, boots and time of the forger's choosing — after which
        # the signed retry fails against the real agent — or, naming
        # unsupportedSecLevels, file the device as 'unsupported' for a
        # week. The one thing the forger cannot know is what we sent:
        # a Report about OUR request comes back with the engine id we put
        # in it (RFC 3414 s3.2 answers under the agent's own id, which is
        # that one whenever the request was addressed to it at all). The
        # single legitimate exception is unknownEngineIDs, the Report
        # whose whole purpose is to tell us an id we did not have. Any
        # other Report under a foreign id is not learned and not acted on;
        # the retry rediscovers instead. The second thing the forger
        # cannot know is the msgID we sent, which _check_report_msg_id
        # matches before this code sees the datagram at all. Not a proof —
        # discovery itself is unauthenticated, by RFC — but one datagram
        # no longer poisons a cache that a signed exchange had already
        # confirmed.
        trusted = (name == "unknownEngineIDs"
                   or (bool(response.engine_id) and response.engine_id == engine_id))
        if name == "unsupportedSecLevels" and trusted:
            raise SnmpUnsupported(f"{ip}: {explanation}")
        if attempt == 0:
            # The Report carries the agent's own authoritative engine id,
            # boots and time — which is exactly what the retry needs. Learn
            # them rather than throwing the answer away and rediscovering
            # on the next poll.
            engine = None
            if response.engine_id and trusted:
                engine = (response.engine_id, response.engine_boots,
                          response.engine_time)
                if learned is not None:
                    learned(*engine)
            continue
        raise _AuthFailure(
            f"{ip}: SNMPv3 request refused"
            + (f" ({explanation})" if explanation
               else " (the device answered with a Report-PDU)")
            + (f" [usmStats{name[0].upper()}{name[1:]}]" if name else ""),
            usm_name=name, report=response)
    raise _AuthFailure(f"{ip}: SNMPv3 request refused"
                       + (" (a Report-PDU, twice)" if last else ""),
                       report=last)


def _credential_label(config: dict, level: str | None = None) -> str:
    """How to name the credential in an operator-facing message, without
    ever printing the credential itself: a community string is a secret.

    The USM level is named too, because "I could not see what level I was
    sending at" is what an authorizationError comes down to. `level` is
    the level the request actually went out at when the caller knows it —
    the Test button signs with a password that was typed and never stored,
    so the config alone can be wrong about it — and is derived from the
    config otherwise."""
    version = snmp_version_of(config)
    if version == 3:
        user = config.get("v3_user")
        level = level or security_level(config)
        return (f"SNMPv3 user {user!r} at {level}" if user
                else f"SNMPv3 (no user set) at {level}")
    name = {0: "v1", 1: "v2c"}.get(version, f"v{version}")
    return (f"the SNMP{name} community" if config.get("community")
            else f"SNMP{name} with no community set")


def _error_status_reason(response: Response, base_oid: str) -> str:
    """Why a walk stopped when the agent answered with an error-status.

    The walk used to test only for tooBig(1); a genErr(5) or noSuchName(2)
    — what PAN-OS answers for a subtree its agent will not serve — carried
    no varbinds, so it fell through to the non-increasing-OID guard and
    ended the walk with nothing logged, nothing raised and nothing in the
    device's snmp_error. The status is named, not numbered, because
    'error-status 5' told an operator nothing."""
    name = ERROR_STATUS.get(response.error_status, "an unknown error")
    return (f"the device answered {name}({response.error_status}) for "
            f"{base_oid} — its SNMP agent refuses that subtree")


def security_level(config: dict) -> str:
    """The USM security level a request built from `config` goes out at:
    'authPriv' when credential_for will sign AND encrypt it, 'authNoPriv'
    when it will only sign, 'noAuthNoPriv' when it will do neither, '' for
    v1/v2c, which have no such thing. Mirrors Credential.security_level's
    rule — a protocol AND a stored password, for each pair — rather than
    decrypting the passwords a second time to find out.

    Derived, never stored. A level column would be a fourth state that can
    contradict the four fields it summarises; the implicit rule is what
    makes the 5.8.0 upgrade a provable no-op — two NULL columns cannot
    change the answer for any existing row."""
    if snmp_version_of(config) != 3:
        return ""
    if config.get("v3_auth_proto") and config.get("v3_auth_pass_enc"):
        if config.get("v3_priv_proto") and config.get("v3_priv_pass_enc"):
            return "authPriv"
        return "authNoPriv"
    return "noAuthNoPriv"


def refused_oid(response: Response, request_oids) -> str:
    """The object an error-index points at, or '' when the agent named none.

    error-index is 1-based into the request's varbind list (RFC 3416
    §4.2.1) and a Response echoes that list, so the response's own varbinds
    are read first and the request's OIDs are the fallback for an agent
    that answered an error with an empty list. Zero, or a value past the
    end of both lists, means the agent named nothing — and that is what is
    reported, rather than the first OID guessed at, because 'refuses
    sysDescr' when the agent said no such thing is exactly the kind of
    confident wrong answer this message exists to stop."""
    index = int(getattr(response, "error_index", 0) or 0)
    if index < 1:
        return ""
    for oids in (getattr(response, "varbinds", None) or (), request_oids or ()):
        if index <= len(oids):
            item = oids[index - 1]
            return str(item.get("oid") if isinstance(item, dict) else item or "")
    return ""


def access_denied_headline(response: Response, request_oids) -> str:
    """The one-line shape _error_status_reason already produces for a walk,
    which operators have learned to read, applied to a GET the agent
    refused under its own access control."""
    name = ERROR_STATUS.get(response.error_status, "an unknown error")
    oid = refused_oid(response, request_oids)
    if oid:
        return (f"the device answered {name}({response.error_status}) for "
                f"{oid} — its SNMP agent refuses that object")
    return (f"the device answered {name}({response.error_status}) without "
            f"naming the object it refused (error-index "
            f"{int(response.error_index or 0)}) — its SNMP agent refuses "
            f"something in this request")


def access_denied_advice(config: dict, level: str) -> str:
    """What an authorizationError(16) means for THIS credential, and what to
    do about it.

    An SNMPv3 request fails in two places that look alike from outside. USM
    checks the signature first; a message it will not accept is answered
    with a Report-PDU, and that is the wrong-password case. A message it
    accepts then goes to VACM, whose vacmAccessTable is keyed on (group,
    context, security model, security LEVEL) — so an entry created for a
    user at authPriv matches nothing that arrives at authNoPriv, and the
    agent answers an ordinary Response-PDU with error-status 16. PAN-OS
    provisions its v3 user as authPriv. Until 5.8.0 this poller could only
    send authNoPriv. The result was 'Authorization Error' against a
    username and password that were never wrong, and an operator who spent
    days re-checking them — which is why the authenticated case says, in
    so many words, that the password is not the problem, and now says what
    the fix is: the privacy password field this credential has since 5.8.0.

    `level` is the security level the request actually went out at ('' for
    v1/v2c); it is a parameter, not read from `config`, because the Test
    button signs with a password that was typed and never stored. Never
    prints a community, a password or a key: _credential_label is the rule."""
    who = _credential_label(config, level or None)
    if level == "authNoPriv":
        return (
            f"The message authenticated: the device verified the signature "
            f"for {who} and processed the request, so this is an "
            f"access-control (VACM) refusal, not a bad password. If that "
            f"user is configured on the device with a privacy password as "
            f"well (authPriv — the way PAN-OS creates its SNMPv3 user), an "
            f"authNoPriv request matches no access entry at all and is "
            f"refused exactly like this (RFC 3415). Either set the user's "
            f"privacy protocol (AES) and privacy password on this credential "
            f"so the request goes out at authPriv, or grant the user a view "
            f"at authNoPriv on the device.")
    if level == "noAuthNoPriv":
        return (
            f"The request was unsigned (noAuthNoPriv) and the device "
            f"processed it, so this is an access-control (VACM) refusal: "
            f"the view for {who} at noAuthNoPriv does not include that "
            f"object. A view granted to that user at authNoPriv or authPriv "
            f"does not match an unsigned request (RFC 3415); either grant "
            f"the view at noAuthNoPriv, or set an authentication protocol "
            f"and password on this credential so the request goes out at "
            f"authNoPriv.")
    if level == "authPriv":
        return (f"The message authenticated and decrypted (authPriv, the "
                f"highest level there is), so this is an access-control "
                f"(VACM) refusal and neither password is the problem: the "
                f"view for {who} does not include that object. Grant it on "
                f"the device.")
    return (f"The device accepted {who} and refused the object under its "
            f"access control: the community's view does not include it.")


def access_denied_reason(config: dict, response: Response, request_oids,
                         level: str) -> str:
    """The whole message for an authorizationError(16): the headline that
    names the refused object, then the advice for this credential. Module-
    level so netpath/web/api.py composes the Test button's answer from the
    same two pieces — the Test and the poll must never disagree about
    wording, and a second copy is how they would start to."""
    return (access_denied_headline(response, request_oids) + ". "
            + access_denied_advice(config, level))


def _with_dropped(reason: str, session: "_Session") -> str:
    """`reason` with the session's rejected-datagram count appended when
    there is one. A reply that arrived and was thrown away (wrong peer,
    undecodable, wrong request id) is a different fault from no reply at
    all — the first is a NAT/ACL or a duplicate responder, the second is a
    firewall or a wrong community — and the count was read by nothing."""
    if not session.dropped:
        return reason
    return (f"{reason}; {session.dropped} datagram(s) arrived and were "
            f"rejected (wrong peer, bad decode or mismatched request id)")


class SnmpBadOid(ValueError):
    """An OID this poller was asked to send cannot be encoded (enc_oid). Deliberately NOT an SnmpError, so it still travels past `except SnmpError` arms."""


def _assemble(build, *args, **kwargs) -> bytes:
    """One request built, an unencodable OID raising SnmpBadOid."""
    try:
        return build(*args, **kwargs)
    except ValueError as exc:
        raise SnmpBadOid(str(exc)) from exc


class _AuthFailure(SnmpError):
    """Internal: an authentication/engine-sync failure — the agent would not
    accept the message — reported as the auth_fail device event rather than
    a generic error or a timeout. NOT an authorizationError(16): that is a
    message the agent accepted and an object it then refused, which is
    SnmpAccessDenied. `usm_name` is the usmStats counter the final Report
    named ('' when it named none) and `report` that Report itself, so a
    reader such as the Test button can say which of the three v3 failures
    this was without matching a substring of the message."""

    def __init__(self, message: str = "", *, usm_name: str = "",
                 report: Response | None = None):
        super().__init__(message)
        self.usm_name = usm_name
        self.report = report


# The SnmpError verdicts about the credential or security level rather than
# about one absent object; _best_effort re-raises these and swallows the rest.
# SnmpAccessDenied is not here: a restricted v3 view answers authorizationError
# for exactly the optional subtrees these reads ask about.
_CREDENTIAL_VERDICTS = (_AuthFailure, SnmpAuthError, SnmpDowngrade,
                        SnmpPrivError, SnmpUnsupported)


def _credential_contradicted(exc: Exception) -> bool:
    """Whether a failure is THIS END refusing what the device sent back —
    a digest that did not verify, a reply that would not decrypt, an
    unsigned answer to a signed request — as opposed to the device
    refusing the request by name. The credential loops stop on the first
    kind and rotate on the second: see _poll_snmp_scalars_with_credential.
    An _AuthFailure with no Report attached is the first kind — v3_exchange
    raises it from SnmpAuthError/SnmpPrivError, and attaches the Report
    for every refusal the agent itself named."""
    if isinstance(exc, SnmpDowngrade):
        return True
    return isinstance(exc, _AuthFailure) and exc.report is None


def _error_specificity(exc: Exception) -> int:
    """How much a credential's failure says about the device: 0 for
    silence, 2 for a refusal that names the fault (a Report, an
    authorizationError, a level not served, a downgrade), 1 for the rest.
    _poll_snmp_scalars_with_credential keeps the highest across a sweep."""
    if isinstance(exc, SnmpTimeout):
        return 0
    if isinstance(exc, (_AuthFailure, SnmpAccessDenied, SnmpUnsupported, SnmpDowngrade)):
        return 2
    return 1

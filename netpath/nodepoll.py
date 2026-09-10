"""NodePoller: the per-device SNMP/ping scheduler.

Monitor-shaped, not IpamWorker-shaped — a hot-resizable ThreadPoolExecutor,
restart-safe per-device due-time seeding (from the device's own
last_poll_ts, so a service restart does not fire every device at once),
reschedule-before-run, overrun logging, and a wrap-everything/finally
worker discipline, all copied from netpath/monitor.py's Monitor class.
Nodes will typically manage far more devices than IPAM manages subnets, so
the finer-grained, restart-safe scheduling Monitor already has is the
right shape, not IpamWorker's coarser "unseen = immediately due" one.
"""

from __future__ import annotations

import ipaddress
import json
import math
import random
import re
import socket
import sqlite3
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple

from . import mibcatalog, nodeoids, nodesdb, vendorid
from .alertrules import DARK_OPTIC_DBM, is_dark_optic
from .eventlog import ERROR, NODES, NullLog
from .ipam_scan import ping_many
from .nodediscover import DiscoveryJob
from .nodeoids import DEFAULT_SNMP_PORT
from .nodesdb import NodesDatabase, detected_vendor
from . import snmpcrypt
from .snmppoll import (
    ERROR_STATUS, PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT, Response,
    SnmpAccessDenied, SnmpAuthError, SnmpDowngrade, SnmpPrivError, SnmpError, SnmpStray, SnmpTimeout, SnmpUnsupported, build_request,
    build_v3_request, decode_response, discovery_probe,
)
from .alertmail import duration_text
from .trapdecode import format_ticks, localized_key, privacy_key
from .worker import Worker, ago

MAX_UDP = 65535

# Bounds on read_device_vlans' walk (see its own docstring): the number of
# distinct VLAN ids one walk will keep and write, the lowest-numbered ones
# kept when a device reports more. A device with a garbled or enormous VLAN
# range (a bad agent, or a trunk allow-list read as if every bit meant a
# real VLAN) must not turn one scheduled walk into an unbounded number of
# stored rows — the same "cap rather than fail" idiom the class-level
# _MAX_VLAN_CONTEXTS/_VLAN_WALK_BUDGET_S use for _cisco_vlan_fdb's per-VLAN-
# community sweep. Deliberately MODULE-level rather than a same-named class
# attribute: this walk has no per-VLAN SNMP context to size against (it
# bounds the OUTPUT of a handful of column walks, not a loop that opens one
# SNMP session per VLAN), and giving it its own class attribute of the same
# name as the existing one would silently shadow it in the class namespace.
# What a poll is assumed to cost before one has been measured, in seconds.
# Only ever used for a device the poller has not polled yet, and only until
# it has: a cold start must not size the pool to zero.
_DEFAULT_POLL_COST = 1.0

# The weight one poll carries in its device's mean. 0.3 settles within a
# handful of polls, which at a 120 s interval is minutes -- fast enough to
# follow a device going down, slow enough that one slow answer does not
# resize the pool on its own.
_POLL_COST_ALPHA = 0.3

# A poll longer than this is not a measurement. The interface read alone is
# bounded to half a poll interval and gives up after three timeouts, so
# nothing legitimate approaches it.
_POLL_COST_CEILING_S = 600.0

_MAX_VLANS = 512
_VLAN_WALK_BUDGET_S = 20.0

# RFC 3414 §5's usmStats counters, the objects an agent names in the
# Report-PDU it answers a v3 request it would not process with. Reported by
# name, because "engine resync required" told an operator nothing about
# whether the password was wrong, the clock was out, or the security level
# was refused — three different problems with three different fixes.
USM_STATS = {
    "1.3.6.1.6.3.15.1.1.1": ("unsupportedSecLevels",
                             "the device refused this security level — its "
                             "user is provisioned at a different one (an "
                             "authPriv user needs a privacy password on this "
                             "credential; an authNoPriv user must not be "
                             "sent one)"),
    "1.3.6.1.6.3.15.1.1.2": ("notInTimeWindows",
                             "the device rejected the message's engine time"),
    "1.3.6.1.6.3.15.1.1.3": ("unknownUserNames",
                             "the device does not know this SNMPv3 user"),
    "1.3.6.1.6.3.15.1.1.4": ("unknownEngineIDs",
                             "the device did not recognise the engine id"),
    "1.3.6.1.6.3.15.1.1.5": ("wrongDigests",
                             "the authentication password or protocol is wrong"),
    "1.3.6.1.6.3.15.1.1.6": ("decryptionErrors",
                             "the device could not decrypt the message — the "
                             "privacy password or protocol is wrong (the "
                             "authentication password is not the problem: "
                             "the signature is checked first)"),
}


# The per-interface metric keys one poll emits, in the order they are
# recorded. `in_bps`/`out_bps` and the two `*_err` keys keep the names the
# charts and any stored history already use; the rest are new in 4.39.0.
def _INTERFACE_METRICS(in_bps, out_bps, in_err_rate, out_err_rate,
                       in_disc_rate, out_disc_rate, in_util, out_util):
    return (
        ("in_bps", "bps", in_bps),
        ("out_bps", "bps", out_bps),
        ("in_err", "err/s", in_err_rate),
        ("out_err", "err/s", out_err_rate),
        ("in_error_rate", "err/s", in_err_rate),
        ("out_error_rate", "err/s", out_err_rate),
        ("in_discard_rate", "disc/s", in_disc_rate),
        ("out_discard_rate", "disc/s", out_disc_rate),
        ("in_util_pct", "%", in_util),
        ("out_util_pct", "%", out_util),
    )


# suffix -> (unit, device-level label). A device-level key is the worst
# value across the device's interfaces this poll, which is what a rule
# written against a device rather than a port can usefully mean.
_DEVICE_MAX_KEYS = {
    "in_util_pct": ("%", "Interface inbound utilization (busiest port)"),
    "out_util_pct": ("%", "Interface outbound utilization (busiest port)"),
    "in_error_rate": ("err/s", "Interface inbound errors (worst port)"),
    "out_error_rate": ("err/s", "Interface outbound errors (worst port)"),
    "in_discard_rate": ("disc/s", "Interface inbound discards (worst port)"),
    "out_discard_rate": ("disc/s", "Interface outbound discards (worst port)"),
}


# root key -> (label suffix, unit); full key is "<root>.<ifIndex>", the
# shape the per-interface if_* keys already use.
_SFP_METRICS = {
    "sfp_rx_dbm": ("Rx power", "dBm"),
    "sfp_tx_dbm": ("Tx power", "dBm"),
    "sfp_bias_ma": ("bias current", "mA"),
    "sfp_volt": ("supply voltage", "V"),
    "sfp_temp_c": ("optic temperature", "°C"),
}

# A cage, and what is in it: entPhysicalDescr/ModelName/VendorType text that
# names a transceiver. Deliberately not "1000BaseT" and friends on their own
# -- a fixed copper port describes itself that way and is not an SFP slot --
# so only an optical media suffix or a form factor counts.
_TRANSCEIVER_TEXT = re.compile(
    r"\b(?:[cq]?sfp\d*|xfp|x2|gbic|xcvr|transceiver)\b|\bglc-|\bsfp-"
    r"|base-?(?:sx|lx|lh|zx|sr|lr|er|zr|bx)\b", re.I)

# dBm(14) says a sensor reads optical power but not which way the light is
# going, so the direction comes out of the sensor's own name.
_OPTIC_RX = re.compile(r"\b(rx|receive[d]?|input)\b", re.I)
_OPTIC_TX = re.compile(r"\b(tx|transmit(ted)?|output|laser)\b", re.I)


def _optical_direction(label: str, descr: str) -> str | None:
    """'rx', 'tx', or None for an optical-power reading whose name says
    neither. entPhysicalName is asked first (the column a Cisco agent puts
    "Te1/1/1 Receive Power" in); entPhysicalDescr is the fallback for agents
    that leave the name empty. Rx wins a name claiming both, since a
    receive-power alarm is the one that catches a dying link."""
    for text in (label, descr):
        text = str(text or "")
        if not text:
            continue
        rx = bool(_OPTIC_RX.search(text))
        tx = bool(_OPTIC_TX.search(text))
        if rx:
            return "rx"
        if tx:
            return "tx"
    return None


def report_reason(response) -> tuple[str, str]:
    """(usmStats name, plain explanation) for a Report-PDU, or ("", "")
    when it names nothing this table knows."""
    for vb in getattr(response, "varbinds", None) or ():
        oid = str(vb.get("oid") or "")
        # The instance is the counter's OID with .0 appended.
        known = USM_STATS.get(oid) or USM_STATS.get(oid.rsplit(".", 1)[0])
        if known:
            return known
    return "", ""


class EngineCache:
    """One entry per device needing v3: device_id -> (engine_id, boots,
    time, learned_at). A v3 device's first poll after startup (or after
    this entry expires) sends discovery_probe() first, learns engine
    parameters from the Report-PDU, then proceeds with the real signed
    request. Entries are kept for the process lifetime — engine boots/time
    only need refreshing if the target actually reboots or its clock skews
    enough to be rejected, which shows up as an auth failure and triggers
    a fresh discovery on the next poll, not a background expiry timer."""

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
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
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
        would turn one v3 resync into a timeout.

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
                        expect_request_id=expect_request_id)
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
    from . import dpapi
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
            raise SnmpError(
                f"the community {identity!r} contains a comma — one device "
                f"is polled with one community; put the alternates in the "
                f"polling profile's credentials instead")
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
    the (engine_id, boots, time) the agent's Report-PDU answers with."""
    response = session.request(discovery_probe())
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
        packet = build_v3_request(
            session.next_request_id(), request_id, pdu_tag, oids,
            engine_id=engine_id, engine_boots=boots, engine_time=engine_time,
            user=identity or "", auth_proto=auth_proto, auth_key=auth_key,
            max_repetitions=max_repetitions,
            priv_proto=priv_proto if encrypting else None, priv_key=priv_key)
        try:
            response = session.request(
                packet, request_id, auth_proto=auth_proto, auth_key=auth_key,
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
        # the retry rediscovers instead. Not a proof — discovery itself is
        # unauthenticated, by RFC — but one datagram no longer poisons a
        # cache that a signed exchange had already confirmed.
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


def counter_rate(previous: int | None, previous_ts: float, current: int | None,
                 current_ts: float, bit_width: int, *,
                 speed_bps: float | None = None) -> float | None:
    """Per-second rate (units of the counter, e.g. bytes/sec for an octet
    counter) from two counter samples, handling wraparound and rejecting
    nonsense. A 32-bit counter that decreased is assumed to have wrapped
    once; a 64-bit counter that decreased is assumed to have been reset
    (rebooted/reinitialized) since a real wrap would take centuries at any
    realistic speed. If speed_bps is given (bits/sec) and the implied rate
    would exceed ~1.3x it, the sample is treated as a reset rather than a
    multi-wrap and None is returned — this is why ifXTable's 64-bit
    counters (nodeoids.IFX_TABLE) are preferred whenever present."""
    if previous is None or current is None:
        return None
    dt = current_ts - previous_ts
    if dt <= 0:
        return None
    if current >= previous:
        rate = (current - previous) / dt
    elif bit_width >= 64:
        return None
    else:
        modulus = 2 ** bit_width
        rate = (modulus - previous + current) / dt
    if speed_bps and rate * 8 > speed_bps * 1.3:
        return None
    return rate


IF_SPEED_SENTINEL = 4_294_967_295
# 1.6 TbE, the next rate the standard defines: a full doubling above 800GbE,
# the fastest Ethernet port actually shipping, and still three orders below
# what a kbit/s-for-Mbit/s ifHighSpeed makes of a 10G port.
MAX_PLAUSIBLE_SPEED_BPS = 1.6e12
# ...but that ceiling describes a PHYSICAL PORT, and an aggregate's rate is
# the sum of its members: the bound for one of those is the largest bundle
# that can exist, 802.3ad's 16 members at 800GbE.
MAX_PLAUSIBLE_AGGREGATE_BPS = 16 * 800e9
# ieee8023adLag and propVirtual: what a modern and an older platform
# respectively call a Port-channel.
AGGREGATE_IF_TYPES = frozenset({53, 161})


def interface_speed_bps(speed, high_speed, if_type=None) -> float | None:
    """One interface's line rate in bits/sec from ifSpeed (bit/s, Gauge32,
    saturating at IF_SPEED_SENTINEL) and ifHighSpeed (Mbit/s), refusing an
    ifHighSpeed that cannot be what the MIB says it is — the same shape of
    refusal counter_rate makes when a derived rate outruns the link.

    ifHighSpeed is preferred as it always was; it is the only one of the two
    that can express a modern link. But agents exist (per-linecard, which is
    why only a few ports on a device are wrong) that answer it in kbit/s, and
    x 1e6 then reports a 10 Gb/s port as 10 Tb/s — the right digits, three
    orders out, and a utilization consequently near 0%. So: a value above the
    ceiling is not a link that exists, and a value 100x or more above a
    NON-saturated ifSpeed is contradicted by the device itself, since an
    unsaturated ifSpeed is exact. A rejected reading falls to ifSpeed where
    ifSpeed can answer; it cannot above ~4.29 Gb/s, which is exactly where the
    quirk shows, so there the reading is retried as kbit/s and kept only if
    THAT lands inside the ceiling. A genuine 400G or 800G port passes every
    check untouched and is never rescaled.

    Two readings that trip those rules legitimately, each exempted by
    something checkable. An 8x400G port-channel answers 3,200,000 against a
    saturated ifSpeed, and no arithmetic separates that from a quirky 3.2
    Gb/s port — a 3.2 Tb/s bundle exists, a 3.2 Tb/s port does not — so
    if_type decides, and only the ceiling moves. And an agent reporting
    ifSpeed as speed mod 2^32 rather than saturated gives a 400G port
    568,041,472 beside a correct ifHighSpeed: not a contradiction but the
    same number truncated, recognised exactly rather than guessed at. The
    1 Gb/s quirk cannot pass as one — 1e12 % 2**32 is 3,567,587,328, not the
    1e9 its ifSpeed reports."""
    high_bps = (float(high_speed) * 1_000_000
                if isinstance(high_speed, (int, float)) and high_speed else None)
    speed_bps = float(speed) if isinstance(speed, (int, float)) else None
    if high_bps is None:
        return speed_bps
    aggregate = (isinstance(if_type, (int, float))
                 and int(if_type) in AGGREGATE_IF_TYPES)
    ceiling = MAX_PLAUSIBLE_AGGREGATE_BPS if aggregate else MAX_PLAUSIBLE_SPEED_BPS
    wrapped = high_bps > IF_SPEED_SENTINEL and high_bps % 2 ** 32 == speed_bps
    contradicted = (speed_bps is not None and 0 < speed_bps < IF_SPEED_SENTINEL
                    and high_bps >= speed_bps * 100 and not wrapped)
    if high_bps <= ceiling and not contradicted:
        return high_bps
    if speed_bps is not None and 0 < speed_bps < IF_SPEED_SENTINEL:
        return speed_bps
    rescaled = high_bps / 1000
    if rescaled <= ceiling:
        return rescaled
    return speed_bps


def detect_reboot(uptime_ticks: int, uptime_ts: float, previous_ticks: int | None,
                  previous_ts: float) -> tuple[bool, str]:
    """sysUpTime is a TimeTicks (hundredths of a second) since the agent's
    own last (re)initialization, wrapping at ~497 days (2**32 hundredths).
    A reboot is detected when the current uptime is significantly smaller
    than the previous reading, ruling out two false-positive cases: a
    497-day wrap (only plausible when the previous reading was already
    enormous) and ordinary jitter (a 30-second grace band)."""
    if previous_ticks is None:
        return False, ""
    elapsed_s = uptime_ts - previous_ts
    if elapsed_s <= 0:
        return False, ""
    grace_ticks = 30 * 100
    if uptime_ticks + grace_ticks >= previous_ticks:
        return False, ""   # uptime kept increasing (or barely dipped): normal
    wrap_modulus = 2 ** 32
    near_wrap = previous_ticks > wrap_modulus - (elapsed_s * 100 + grace_ticks) * 2
    if near_wrap:
        return False, ""
    # duration_text refuses a sub-second gap, and "after  without a reading"
    # would be the result of pasting its "" in unguarded.
    gap = duration_text(elapsed_s)
    sentence = (f"uptime dropped from {format_ticks(previous_ticks)} to "
                f"{format_ticks(uptime_ticks)}")
    if gap:
        sentence += f" after {gap} without a reading"
    return True, sentence


# The inverse of the sentence above, kept beside it so the two cannot drift.
# Both groups are pinned to the two shapes trapdecode.format_ticks can emit,
# not to `(.+?)`: the pre-5.3 sentence ("uptime dropped from 1036800000 to
# 15000 hundredths of a second after 300s") is still readable out of a row the
# 5.2 poller wrote, and a loose group matched it and handed the raw tick counts
# to the reboot email as uptimes -- the very mistake 5.3 removed.
_UPTIME_TEXT = r"(\d+d \d\d:\d\d:\d\d|\d\d:\d\d:\d\d\.\d\d)"
_REBOOT_UPTIMES = re.compile(f"uptime dropped from {_UPTIME_TEXT} to {_UPTIME_TEXT}")


def reboot_uptimes(detail: str) -> tuple[str, str]:
    """The before/after uptimes out of a `rebooted` device_event's detail.

    Read back out of the event row rather than off the device, because the
    device row no longer has them: `devices.last_uptime_ticks` was overwritten
    with the post-reboot reading by the poll that detected the reboot, and the
    pre-reboot figure is gone for good by the time the alert engine drains the
    event. ("", "") for a detail this did not write.
    """
    match = _REBOOT_UPTIMES.search(detail or "")
    return (match.group(1), match.group(2)) if match else ("", "")


def _interface_reassigned(prior: "sqlite3.Row | dict", row: dict) -> bool:
    """True only on affirmative evidence that the physical port at this
    ifIndex changed between `prior` and `row` — a stack member reboot can
    move port 5 from ifIndex 10 to 14.

    ifPhysAddress first: the burned-in MAC is tied to the hardware, not to
    how the agent numbers the port, so it survives a renumbering that descr
    (which encodes the member number) would not. ifDescr is the fallback
    where phys_addr is blank, common on logical interfaces.

    A field empty on either side is never evidence — only a disagreement
    between two non-empty values counts. Otherwise a platform that does not
    populate either column would have every reboot read as a reassignment,
    suppressing every post-reboot oper_status comparison forever."""
    for field in ("phys_addr", "descr"):
        old = prior[field] if field in prior.keys() else None
        new = row.get(field)
        if old and new:
            return old != new
    return False


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


# Moved to nodeoids in 4.32 so vendorid can share it; kept under its old
# name here so the walk code and its tests read unchanged.
_oid_key = nodeoids.oid_key


def _format_cdp_address(raw) -> str:
    """cdpCacheAddress, as this app's OCTET_STRING decoder hands it back,
    is a space-separated run of hex bytes for anything non-printable (see
    trapdecode._octets_text) — a raw IPv4 address decodes as e.g.
    "0A 00 00 09". Reformatted to dotted-decimal when it is exactly four
    bytes; left as-is (and still informative) for anything else, since a
    real cdpCacheAddress can carry a different protocol's address entirely
    and this app does not attempt every one CISCO-CDP-MIB allows."""
    text = str(raw or "").strip()
    if not text:
        return ""
    parts = text.split()
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return text
    if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
        return ".".join(str(o) for o in octets)
    return text


def _int_keyed(column: dict) -> dict:
    """A `_walk_column` result with every index suffix parsed to int,
    dropping anything that is not one. Several VLAN-walk columns below are
    indexed by a bare bridge port or ifIndex (a single arc), and this is
    the one-line version of the `try: int(suffix) except...: continue` loop
    every other table walk in this file already repeats inline — worth
    naming once here because the VLAN walk needs it five separate times."""
    out = {}
    for suffix, value in column.items():
        try:
            out[int(suffix)] = value
        except (TypeError, ValueError):
            continue
    return out


# The short interface-name forms IOS/NX-OS write in entPhysicalName, mapped
# to the long form the same box writes in ifDescr — "Te1/1/1 Transmit Power"
# against "TenGigabitEthernet1/1/1". See _canonical_if_name, which is the
# only reason this table exists: a Cisco sensor is very often reachable only
# by this name match, because CISCO-ENTITY-SENSOR-MIB gear routinely leaves
# entAliasMappingIdentifier empty.
_IF_NAME_ABBREVIATIONS = {
    "fa": "fastethernet", "gi": "gigabitethernet",
    "te": "tengigabitethernet", "twe": "twentyfivegige",
    "fo": "fortygigabitethernet", "hu": "hundredgige",
    "eth": "ethernet", "tw": "twogigabitethernet",
    "fi": "fivegigabitethernet", "po": "port-channel",
}


def _canonical_if_name(name: str) -> str:
    """An interface name reduced to a form two spellings of the same port
    compare equal on: lowercased, whitespace removed, and a leading
    abbreviation expanded to its long form.

    The expansion applies only when the WHOLE leading run of letters is an
    abbreviation, so "TenGigabitEthernet1/1/1" is never re-read as "Te" +
    "nGigabitEthernet1/1/1" and mangled into something that matches
    nothing.
    """
    text = "".join(str(name or "").split()).lower()
    head = ""
    for char in text:
        if not char.isalpha():
            break
        head += char
    expanded = _IF_NAME_ABBREVIATIONS.get(head) if head else None
    return expanded + text[len(head):] if expanded else text


# trapdecode._octets_text's own two non-literal branches, and only those:
# its six-byte MAC-address special case always joins with ':' and always
# lowercase hex (`f"{b:02x}"`); its general fallback always joins with ' '
# and always UPPERCASE hex (`f"{b:02X}"`). A literal run that merely looks
# hex-ish (a single odd-length token, or one that mixes case, or one whose
# groups run together with no separating space) can never have come out of
# either branch, so it is deliberately NOT matched here — see
# _octets_from_value.
_HEX_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_HEX_OCTETS_RE = re.compile(r"^[0-9A-F]{2}(?: [0-9A-F]{2})*$")


def _octets_from_value(raw) -> bytes:
    """The bytes behind a PortList/VLAN-bitmap OCTET STRING, whether `raw`
    is already bytes (callers and tests that have them directly) or has
    been through this app's shared OCTET_STRING decoder for a live walk
    (trapdecode._octets_text — the same one _format_cdp_address documents):
    plain text when every byte happened to be printable, colon-separated
    lowercase hex when the string was exactly six bytes and not all
    printable (that decoder's MAC-address special case), or space-separated
    uppercase hex otherwise.

    That decode is NOT losslessly reversible, despite this file previously
    documenting it as such, and this function cannot make it so — the raw
    octets are gone before it is ever called. `trapdecode._decode_value`
    returns an OCTET STRING's printable rendering as the value itself, so
    the bytes are discarded at BER-parse time; recovering them would mean
    re-implementing v1/v2c/v3 parsing here. INTERNALS.md records this as a
    known limit of the whole SNMP path — the LLDP chassis-id decode has it
    too — rather than of this function alone.

    What this DOES do is narrow the guess to the shapes `_octets_text`
    provably produces — its six-group lowercase colon-hex MAC form, or a
    run of space-separated uppercase hex pairs — instead of the previous
    heuristic, which reinterpreted any printable one-or-two-character hex
    look-alike and so turned a literal "A" (0x41, ports 2 and 8) into 0x0A
    (ports 5 and 7).

    Two ambiguities are irreducible, and are resolved the way that is right
    more often on real hardware rather than pretended away:

      - 0x0A, 0x0D and 0x20 all render as the same single space, so all
        three read back as 0x20 (port 3). A PortList setting ports 5 and 7
        is indistinguishable from one setting port 3.
      - A run matching the uppercase-hex-pair shape is read AS hex, so the
        text "12" becomes the one byte 0x12 rather than the two literal
        characters "1" and "2". An agent's PortList reaches `_octets_text`
        as hex far more often than a switch answers with literal decimal
        text, so this is the better default — but it is a default, not a
        certainty.
    """
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    text = str(raw or "")
    if not text:
        return b""
    if _HEX_MAC_RE.match(text):
        return bytes(int(part, 16) for part in text.split(":"))
    if _HEX_OCTETS_RE.match(text):
        return bytes(int(part, 16) for part in text.split(" "))
    return text.encode("latin-1", "replace")


def _bit_positions(octets: bytes):
    """(octet index, bit index within it — 0 the most significant) for
    every set bit of a big-endian bitmap, the scan _decode_port_list and
    _decode_vlan_bitmap share; they differ only in how a position becomes
    a port or VLAN number (see _decode_vlan_bitmap's own docstring)."""
    for i, byte in enumerate(octets):
        for bit in range(8):
            if byte & (0x80 >> bit):
                yield i, bit


def _decode_port_list(raw) -> list[int]:
    """Bridge port numbers set in a Q-BRIDGE-MIB PortList OCTET STRING
    (dot1qVlanStatic/CurrentEgressPorts, …UntaggedPorts).

    A PortList (RFC 4363) is a big-endian bitmap: the most significant bit
    of byte 0 is bridge port 1, the next bit down is port 2, ... the least
    significant bit of byte 0 is port 8, the most significant bit of byte 1
    is port 9, and so on — 1-based, unlike CISCO-VTP-MIB's own bitmaps (see
    _decode_vlan_bitmap, which shares this function's octet-decoding and
    bit-scan but not its 1-based numbering).

    `raw` is either raw bytes, or text already through this app's shared
    OCTET_STRING decoder — see _octets_from_value for how that text is
    turned back into bytes, and why that is best-effort rather than
    lossless for a short run of bytes that all happen to be printable.
    """
    return [i * 8 + bit + 1 for i, bit in _bit_positions(_octets_from_value(raw))]


def _decode_vlan_bitmap(raw, base: int) -> list[int]:
    """VLAN ids set in one of CISCO-VTP-MIB's four vlanTrunkPortVlansEnabled*
    bitmaps (see nodeoids' VTP_TRUNK_VLANS_ENABLED* block for the four
    OIDs and their base offsets). Same big-endian, most-significant-bit-
    first octet scan _decode_port_list uses — but 0-based, NOT 1-based
    like that PortList convention: CISCO-VTP-MIB's own DESCRIPTION says
    the first octet specifies VLANs 0 through 7, its most significant bit
    the LOWEST-numbered of those, not "the lowest VLAN plus one" the way a
    PortList's octet 0 reserves its most significant bit for bridge port 1
    rather than port 0. Adding `base` (0, 1024, 2048 or 3072 — one per
    column) places the result in the right thousand."""
    return [base + i * 8 + bit
           for i, bit in _bit_positions(_octets_from_value(raw))]


class _OidWalkJob:
    """A whole-device SNMP walk, run on its own thread.

    Its own thread rather than the poll pool: a full walk of a core switch
    is tens of thousands of GETNEXTs and minutes of wall time, and parking
    one of four poll workers on it for that long would stall the devices
    behind it. Exactly one runs per device at a time — a second request
    while one is running is refused politely, the way backup_now does.
    """

    def __init__(self, poller, device_id: int, base: str, max_rows: int,
                 budget_s: float):
        self.poller = poller
        self.device_id = device_id
        self.base = base
        self.max_rows = max_rows
        self.budget_s = budget_s
        self.rows: list[dict] = []
        self.state = "starting"      # starting|running|done|failed
        self.stopped = ""
        self.error = ""
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.device_label = ""
        self._count = 0              # read without the lock by status()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "running")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"oid-walk-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self, with_rows: bool = False) -> dict:
        elapsed = (self.finished_ts or time.time()) - self.started_ts
        result = {"device_id": self.device_id, "state": self.state,
                  "rows": self._count, "elapsed": elapsed,
                  "stopped": self.stopped, "error": self.error,
                  "base": self.base, "started_ts": self.started_ts,
                  "complete": self.stopped == "end of subtree",
                  "device_label": self.device_label}
        if with_rows:
            result["walk"] = list(self.rows)
        return result

    def _run(self) -> None:
        try:
            device = self.poller.db.device(self.device_id)
            if device is None:
                raise ValueError("No such device")
            self.device_label = device["sys_name"] or device["name"] or device["ip"]
            config = self.poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")
            self.state = "running"

            # Progress only: _walk_from owns the list and hands it back
            # whole below, so a status() mid-walk reports a count without
            # racing a list another thread is appending to.
            def note(_row):
                self._count += 1

            rows, stopped = self.poller._walk_from(
                device, config, self.base, self.max_rows, self.budget_s,
                cancelled=self._cancel.is_set, on_row=note)
            self.rows = rows
            self._count = len(rows)
            self.stopped = stopped
            self.state = "done"
        except Exception as exc:                      # a job thread must not die quietly
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            self.poller.log.add(
                ERROR, f"OID walk failed for device #{self.device_id}: {self.error}",
                detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()


class _VendorIdJob:
    """One device's vendor identification, on its own thread.

    Off the poll pool for the same reason _OidWalkJob is: the bounded walk
    is up to a few hundred requests and ~20 s by budget, but a device that
    stops answering half way through pays its timeout per request on top,
    and on a 60 s profile that is an overrun parked on one of the pool's
    workers. Concurrency is capped by NodePoller._maybe_identify instead.
    """

    def __init__(self, poller, device_id: int, trigger: str):
        self.poller = poller
        self.device_id = device_id
        self.trigger = trigger
        self.state = "starting"          # starting|hopping|walking|done|failed
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.requests = 0
        self.objects = 0
        self.arcs: list[int] = []
        self.error = ""
        self.decision = None
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "hopping", "walking")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"vendor-id-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self) -> dict:
        return {"device_id": self.device_id, "state": self.state, "trigger": self.trigger,
                "elapsed": (self.finished_ts or time.time()) - self.started_ts,
                "requests": self.requests, "objects": self.objects,
                "arcs_found": list(self.arcs), "error": self.error,
                "decision": self.decision.json() if self.decision else None}

    def _run(self) -> None:
        poller = self.poller
        db = poller.db
        settings = db.settings()
        hop = None
        rows_by_arc: dict[int, list[str]] = {}
        capped: dict[int, bool] = {}
        candidates: list = []
        walk_info: dict = {}
        error = ""
        device = db.device(self.device_id)
        sys_object_id = (device["sys_object_id"] if device else "") or ""
        previous_attempts = 0
        try:
            if device is None:
                raise ValueError("No such device")
            evidence_before = vendorid._evidence_dict(device)
            if evidence_before.get("error"):
                previous_attempts = int(evidence_before.get("attempts") or 0)
            config = poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")

            # The hop keeps the device's own retries: a missed hop loses an
            # arc. The walk below goes without them.
            self.state = "hopping"

            def getnext(oid):
                if self._cancel.is_set():
                    raise SnmpError("cancelled")
                self.requests += 1
                return poller._getnext_one(device, config, oid)

            hop = vendorid.hop_enterprise_arcs(getnext)
            self.arcs = list(hop.arcs)
            if hop.stopped == "timeout" and not hop.arcs:
                # The hop swallows a timeout on purpose so a partial answer
                # survives — but no answer at all is not an identification,
                # it is a device that did not reply. Recorded as an error so
                # the bounded retries apply instead of this counting as done.
                raise SnmpTimeout(f"no reply from {device['ip']} during the "
                                  f"identification walk")

            self.state = "walking"
            max_objects = int(settings.get("vendor_walk_max_objects", 500) or 500)
            budget_s = float(settings.get("vendor_walk_budget_s", 20.0) or 20.0)
            walk_config = {**config, "snmp_retries": 0}
            deadline = time.time() + budget_s
            walk_started = time.time()
            walk_requests = 0
            stopped = "complete"
            for arc in hop.arcs:
                remaining = max_objects - self.objects
                remaining_s = deadline - time.time()
                if remaining <= 0 or remaining_s <= 0:
                    stopped = ("stopped at the %d-object limit" % max_objects
                               if remaining <= 0 else "stopped after %.0fs" % budget_s)
                    break
                if self._cancel.is_set():
                    stopped = "cancelled"
                    break
                generic = arc in vendorid.GENERIC_ARCS
                per_arc = 20 if generic else min(vendorid.PER_ARC_OBJECTS, remaining)
                per_arc_s = min(vendorid.PER_ARC_BUDGET_S, remaining_s)

                def note(_row):
                    self.objects += 1

                rows, why = poller._walk_from(
                    device, walk_config, f"{nodeoids.ENTERPRISES}.{arc}",
                    max_rows=per_arc, budget_s=per_arc_s,
                    cancelled=self._cancel.is_set, on_row=note)
                walk_requests += len(rows) + 1
                rows_by_arc[arc] = [row["oid"] for row in rows]
                capped[arc] = len(rows) >= per_arc or why.startswith("stopped")
            self.requests += walk_requests
            if self._cancel.is_set():
                # What was gathered is kept and shown, but a cancelled walk
                # is not a verdict: it is recorded as incomplete, so the
                # dialog says so and the bounded retries still apply.
                error = "cancelled"
            walk_info = {"objects": sum(len(v) for v in rows_by_arc.values()),
                         "requests": walk_requests,
                         "elapsed_s": round(time.time() - walk_started, 2),
                         "stopped": stopped}
            candidates = vendorid.fingerprint(rows_by_arc, poller._mib_index_cached())
        except Exception as exc:              # a job thread must not die quietly
            error = ("cancelled" if self._cancel.is_set()
                     else (str(exc) or exc.__class__.__name__))
            if not isinstance(exc, (SnmpError, ValueError)):
                poller.log.add(ERROR, f"Vendor identification failed for device "
                                      f"#{self.device_id}: {error}",
                               detail=traceback.format_exc())
        try:
            device = db.device(self.device_id)
            if device is None:
                self.state = "failed"
                return
            decision = vendorid.decide(
                sys_object_id, device["sys_descr"] or "", hop.arcs if hop else [],
                candidates, manual=device["vendor_override"] or "",
                learned=db.learned_vendor(sys_object_id),
                catalog_arcs=mibcatalog.ARC_KEYS)
            self.decision = decision
            evidence = vendorid.evidence(
                sys_object_id, self.trigger, hop, rows_by_arc, capped, candidates,
                decision, walk_info, catalog_arcs=mibcatalog.ARC_KEYS, error=error,
                attempts=previous_attempts + 1)
            db.record_identification(self.device_id, decision, evidence, sys_object_id)
            poller._apply_identification(self.device_id, decision, error)
            self.error = error
            self.state = "failed" if error else "done"
        except Exception as exc:
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            poller.log.add(ERROR, f"Vendor identification could not be recorded for "
                                  f"device #{self.device_id}: {self.error}",
                           detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()
            poller._bump("identifications")


class DiscoveryBusy(RuntimeError):
    """A sweep of this target is already on the wire. Raised by
    start_discovery(refuse_if_target_running=True) rather than answered as a
    return value, so a caller cannot mistake a refusal for a job id."""


class NodePoller(Worker):
    STOPPED_TEXT = "Poller stopped"
    THREAD_NAME = "node-poller"

    def __init__(self, db: NodesDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        # v3_verify_replies, read once per poll in _poll_device (settings()
        # is a query, and a walk is hundreds of exchanges) and carried here
        # for every v3 exchange that poll makes. True until a poll has read
        # the setting, because verified is the shipped default.
        self._verify_replies = True
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._queued: dict[int, float] = {}
        self._started: dict[int, float] = {}
        self._next_run: dict[int, float] = {}
        # device_id -> when it was last pinged, so ping_interval_s can
        # decouple ICMP probing from the SNMP poll cadence.
        self._last_ping: dict[int, float] = {}
        # device_id -> when its forwarding table was last walked, and which
        # walks are in flight. Its own cadence, well away from the poll
        # cycle: a switch's FDB is hundreds to thousands of rows and is
        # walked at most once per mac_table_interval_s, opt-in per profile.
        self._next_mac_walk: dict[int, float] = {}
        self._mac_running: set[int] = set()
        # device_id -> when its LLDP/CDP neighbour table was last walked, and
        # which walks are in flight. The topology walk's own cadence
        # (lldp_interval_s), mirroring _next_mac_walk/_mac_running exactly —
        # see _maybe_walk_lldp.
        self._next_lldp_walk: dict[int, float] = {}
        self._lldp_running: set[int] = set()
        # device_id -> when its per-port VLAN membership was last walked,
        # and which walks are in flight — _next_lldp_walk/_lldp_running's
        # own shape, its own cadence (vlan_interval_s), see _maybe_walk_vlans.
        self._next_vlan_walk: dict[int, float] = {}
        self._vlan_running: set[int] = set()
        # device_id -> when its ARP cache was last walked, and which walks
        # are in flight — _next_mac_walk/_mac_running's own shape, its own
        # cadence (arp_table_interval_s, shipped 0), see _maybe_walk_arp_table.
        self._next_arp_walk: dict[int, float] = {}
        self._arp_running: set[int] = set()
        # Devices whose last ARP walk stored nothing (answered neither
        # table, or was cut short), so that fact is logged once when it
        # becomes true and once when it stops being true — not on every
        # interval. The setting is opt-in, and an operator who turns it on
        # for a profile of L2-only switches would otherwise get one
        # "answers no ARP table" line per switch per cycle for as long as
        # it stayed on. See _run_arp_table.
        self._arp_unanswered: set[int] = set()
        self._engines = EngineCache()
        self._discovery_jobs: dict[int, DiscoveryJob] = {}
        # Held across a whole discovery start — the "is one already running"
        # question, the job row, and the thread — so two HTTP threads asking
        # it at once cannot both be told no one is scanning this target.
        # Reentrant because the answer is also read on its own below.
        self._discovery_lock = threading.RLock()
        # device_id -> the whole-device OID walk running or last finished for
        # it. In memory and one-at-a-time per device, the same shape as
        # _discovery_jobs above: a walk result is transient, downloaded once
        # and then dropped.
        self._oid_walks: dict[int, "_OidWalkJob"] = {}
        # device_id -> its running or last vendor identification job, and
        # the MIB corpus index the fingerprint scores against, rebuilt only
        # when nodesdb.mib_generation() says the corpus changed.
        self._vendor_ids: dict[int, "_VendorIdJob"] = {}
        self._mib_index: tuple | None = None       # (generation, MibIndex)
        self._last_completed: float = 0.0
        # The merged per-device configs the scheduling pass reads, and the
        # nodesdb config generation and wall time they were built at.
        self._configs: dict | None = None
        self._configs_generation: int = -1
        self._configs_loaded: float = 0.0
        # device_id -> when its ipAddrTable was last read. See
        # _refresh_addresses: once an hour, not once a poll.
        self._addresses_read: dict[int, float] = {}
        # device_id -> when its ENTITY-SENSOR-MIB table was last walked.
        # See _poll_environment/_SENSOR_REFRESH_S: a fixed cadence, in
        # memory only, the same shape _addresses_read already uses for a
        # walk that answers something that does not change between one
        # poll and the next.
        self._sensor_read: dict[int, float] = {}
        # device_id -> when its entSensorThresholdTable was last walked. A
        # separate stamp from _sensor_read above because it runs an order of
        # magnitude less often: a DOM reading moves every poll, but the
        # limits a transceiver publishes change only when somebody pulls the
        # optic out. See _SENSOR_THRESHOLD_REFRESH_S.
        self._sensor_threshold_read: dict[int, float] = {}
        # device_id -> when a sensor-diagnostic event was last written for
        # it. See _log_sensor_diag.
        self._sensor_diag_ts: dict[int, float] = {}
        # device_id -> the GETBULK repetition count that last worked for it.
        # A device that answers "tooBig" is retried at half as many rows, and
        # remembering that means the next walk starts where the last one
        # ended up rather than re-learning the same limit every time.
        self._bulk_repetitions: dict[int, int] = {}
        # Forwarding-table walks run here, not on the poll pool: one walk is
        # hundreds to thousands of rows, and parking poll workers on them is
        # what made the pool saturate.
        self._mac_executor: ThreadPoolExecutor | None = None
        # When the pool first looked saturated, and whether that has been
        # reported. See _note_saturation.
        self._saturated_since: float | None = None
        self._saturation_reported = False
        # device_id -> an EWMA of how long its polls actually take. _run_one
        # already had both ends of that; this keeps the difference.
        # device_id -> how many consecutive cycles have skipped this
        # device's SNMP phase while it is down. See _snmp_backoff_due.
        self._snmp_backoff: dict[int, int] = {}
        self._poll_cost: dict[int, float] = {}
        self._poll_cost_mean: float = _DEFAULT_POLL_COST
        # Cached at start()/reconfigure() rather than read per pass:
        # test_scheduler pins a steady pass at five SQL statements and
        # asserts it never reads the settings table.
        self._autoscale = {"auto": False, "min": 1, "max": 1, "headroom": 1.5}
        self._manual_workers = 16
        # None = no ceiling computed yet, which is what _note_saturation
        # reads to behave exactly as it did before autoscaling existed.
        self._autoscale_ceiling: int | None = None
        self._autoscale_at: float = 0.0
        self._autoscale_resized_at: float = 0.0
        self._autoscale_demand: float = 0.0        # rolling max this window
        self._autoscale_want: int = 0              # last target computed
        self._autoscale_shrink_votes: int = 0
        self._autoscale_sat_since: float | None = None
        # Set by the application once the alert engine exists, so the poller
        # can raise a system alert about itself. Left None (and every use
        # guarded) so the poller runs standalone in tests and scripts.
        self.alert_engine = None
        # device_id -> index into db.credential_candidates(device) that last
        # worked, so a multi-credential profile costs an extra request only
        # on a device's first poll or after its cached credential stops
        # working. In memory and process-lifetime only, like EngineCache.
        self._credentials: dict[int, int] = {}
        # device_id -> when an on-demand credential probe last failed for it,
        # so a device that is simply down does not re-sweep its profile's
        # candidates on every dialog a human opens. See working_config().
        self._credential_probe_failed: dict[int, float] = {}
        # device_id set: devices whose SNMP is currently failing on
        # AUTHENTICATION. auth_fail is recorded on entering the set and
        # auth_ok only on leaving it, which is what makes both transitions --
        # see _poll_device for why the device row cannot answer that. In
        # memory and process-lifetime only, like _credentials above.
        self._auth_failing: set[int] = set()
        # The same shape for a device whose agent accepted the credential
        # and refused the object (SnmpAccessDenied): entering records
        # access_denied, leaving on a successful poll records access_ok.
        # In memory for the same reason _auth_failing is — see the events
        # block in _poll_device.
        self._access_denied: set[int] = set()
        # And once more for a device whose replies are refused as a
        # downgrade (SnmpDowngrade: answering, but below the level asked):
        # entering records snmp_downgrade, leaving on a poll whose reply
        # verified records snmp_verified.
        self._downgraded: set[int] = set()
        # Devices whose per-method lane events have been confirmed to exist
        # (or seeded) since this process started — see the events block in
        # _poll_device and nodesdb.has_method_events. One query per device
        # per process, then never again.
        self._method_seeded: set[int] = set()
        # device_id -> consecutive qualifying SNMP-failing polls (ping OK,
        # not an auth failure, not unsupported), gating the `snmp_error`
        # device event behind `snmp_fail_alert_after` — see _poll_device.
        # In memory and process-lifetime only, like _auth_failing above.
        self._snmp_failing_count: dict[int, int] = {}
        # (device_id, expires_ts, interval_s): the device currently selected
        # in a browser polls at interval_s until expires_ts. Renewed by the
        # frontend every refresh tick while selected, so it self-expires
        # when the tab is left or the browser closes — no cleanup path.
        self._focus: tuple[int, float, float] | None = None
        self.counters = {"polls": 0, "ok": 0, "timeout": 0, "auth_fail": 0,
                         # denied: the agent accepted the credential and
                         # refused the object (authorizationError) — counted
                         # apart from auth_fail because it is the opposite
                         # finding about the password.
                         "unsupported": 0, "denied": 0,
                         # downgraded: the device answered, below the level
                         # it was asked at, and the reply was refused unread
                         # — its own count because it is neither an auth
                         # failure (nothing contradicted the password) nor
                         # an error (nothing failed on this end).
                         "downgraded": 0,
                         "errors": 0, "overruns": 0, "snmp_backoff": 0,
                         "mac_walks": 0, "identifications": 0,
                         # lldp_walks counts completed LLDP/CDP walks;
                         # poe_polls/stp_polls/rf_polls count poll-cycle
                         # reads that produced data (a device whose
                         # capability probe was negative never bumps them).
                         "lldp_walks": 0, "poe_polls": 0, "stp_polls": 0,
                         "rf_polls": 0,
                         # vlan_walks: completed per-port VLAN membership
                         # walks, lldp_walks' own counter.
                         "vlan_walks": 0,
                         # arp_walks: completed ARP-cache walks that stored
                         # something — a device answering neither table
                         # does not count, the same way mac_walks does not
                         # count a switch that answered no forwarding table.
                         "arp_walks": 0}

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        settings = settings if settings is not None else self.db.settings()
        self._read_pool_settings(settings)
        self._executor = ThreadPoolExecutor(max_workers=self._initial_pool_size())
        self._mac_executor = ThreadPoolExecutor(
            max_workers=self._mac_walk_workers(settings),
            thread_name_prefix="mac-walk")
        self._spawn()

    def _read_pool_settings(self, settings: dict) -> None:
        """Cache the pool settings on the poller.

        Read here and not in the scheduling pass on purpose:
        tests/test_scheduler.py pins a steady pass at five SQL statements
        regardless of fleet size and asserts it never reads the settings
        table. reconfigure() runs on every Nodes settings save, so this
        cache cannot go stale.
        """
        # Bounded here as well as in nodesdb.save_settings, because this is
        # the point of USE and it is handed a dict rather than reading the
        # file: a caller with an unclamped dict must not be able to size the
        # pool past the ceiling the store would have enforced.
        cap = NodesDatabase.MAX_POLL_WORKERS
        floor = max(1, min(cap, int(settings.get(
            "poll_workers_min", settings.get("poll_workers", 16)) or 1)))
        ceiling = max(floor, min(cap, int(settings.get("poll_workers_max", 128)
                                          or floor)))
        self._autoscale = {
            "auto": bool(settings.get("poll_workers_auto", True)),
            "min": floor,
            "max": ceiling,
            "headroom": max(1.0, float(settings.get("poll_pool_headroom", 1.5) or 1.5)),
        }
        self._autoscale_ceiling = ceiling if self._autoscale["auto"] else None
        self._manual_workers = max(1, min(cap, int(
            settings.get("poll_workers", 16) or 1)))

    def _mac_walk_workers(self, settings: dict) -> int:
        return max(1, min(32, int(settings.get("mac_walk_workers",
                                               self._MAC_WALK_WORKERS) or 1)))

    def _apply_mac_pool_size(self, settings: dict) -> None:
        """Resize the walk pool on a settings save as well as at start().

        Read only in start() before this, so the new mac_walk_workers control
        did nothing at all until the poller was disabled and re-enabled --
        a setting that silently ignores you is worse than no setting.
        """
        want = self._mac_walk_workers(settings)
        current = getattr(self._mac_executor, "_max_workers", None)
        if self._mac_executor is None or current == want:
            return
        previous, self._mac_executor = self._mac_executor, ThreadPoolExecutor(
            max_workers=want, thread_name_prefix="mac-walk")
        previous.shutdown(wait=False)

    def _initial_pool_size(self) -> int:
        """Where the pool starts. With auto off that is poll_workers, exactly
        as before. With auto on it is the floor -- which on an upgraded
        install IS the operator's existing poll_workers, seeded by nodesdb's
        migration, so no fleet ever starts with fewer threads than it had."""
        if not self._autoscale["auto"]:
            return self._manual_workers
        return max(self._autoscale["min"],
                   min(self._autoscale["max"], self._manual_workers))

    def reconfigure(self, settings: dict) -> None:
        """Hot pool resize, matching Monitor.set_workers: build a new
        executor, swap it in, let the old one drain in-flight work rather
        than cancelling it. Starts/stops the loop only if `enabled`
        actually changed."""
        if settings.get("enabled", True):
            if not self.running:
                self.start(settings)
                return
            self._read_pool_settings(settings)
            self._apply_mac_pool_size(settings)
            workers = self._initial_pool_size()
            if self._autoscale["auto"]:
                # Auto keeps whatever size it has arrived at, only pulled
                # back inside the operator's new bounds. Snapping to the
                # floor on every unrelated settings save would throw away
                # everything the controller had learned.
                current = getattr(self._executor, "_max_workers", workers)
                workers = max(self._autoscale["min"],
                              min(self._autoscale["max"], current))
            if self._executor is not None and self._executor._max_workers == workers:
                return
            self._apply_pool_size(workers)
        elif self.running:
            self.stop()

    _MAC_WALK_WORKERS = 4

    def stop(self) -> None:
        """Fast: cancels queued work and returns without waiting for a poll
        already running to finish. Used for a hot restart (start() calls
        this first) and for an operator disabling Nodes polling from
        Settings on an HTTP thread, neither of which should block on the
        network — shutdown() below is the version that waits."""
        self.begin_stop()
        self._join()

    def begin_stop(self) -> None:
        self._stop.set()
        for job in list(self._discovery_jobs.values()):
            job.cancel()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._mac_executor:
            self._mac_executor.shutdown(wait=False, cancel_futures=True)
            self._mac_executor = None

    def finish_stop(self, deadline: float) -> None:
        # min, not shutdown()'s max, for the reason Monitor.finish_stop gives:
        # the in-flight budget is a ceiling, and the shared teardown deadline
        # wins when it is the smaller of the two.
        self._join(timeout=max(0.0, deadline - time.monotonic()))
        self.drain(min(max(0.0, deadline - time.monotonic()),
                       self._inflight_budget_s()))

    def _inflight_ids(self) -> set[int]:
        with self._lock:
            return set(self._queued) | set(self._started)

    def _running_discovery_jobs(self) -> list:
        """stop() already calls job.cancel() on each of these; a running job
        stops submitting addresses and drains what's in flight in parallel,
        landing within about one address's worth of work (see
        _discovery_budget_s) rather than finishing its whole sweep, which
        can be a subnet's worth of addresses and far too long to wait out
        here."""
        return [job for job in list(self._discovery_jobs.values()) if job.running]

    def drain(self, timeout_s: float) -> bool:
        """Wait for in-flight polls and discovery jobs to finish. True if
        they all did. The same shape as Monitor.drain (netpath/monitor.py)
        for the trace scheduler this class was copied from."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self._inflight_ids() and not self._running_discovery_jobs():
                return True
            time.sleep(0.05)
        return not self._inflight_ids() and not self._running_discovery_jobs()

    def _discovery_budget_s(self, job) -> float:
        """One address's worst case for a running discovery job, from its
        own settings dict -- not a model of the whole sweep (see
        _running_discovery_jobs), and still per-address, not per-worker: the
        pool's drain waits for all of them together, so the slowest single
        address is what bounds it. Two SNMP versions tried, a handful of
        community guesses each, plus the vendor arc hop
        (hop_enterprise_arcs: "typically three to eight" GETNEXTs, no
        retry of its own) are approximated as ten SNMP round trips rather
        than counted exactly -- a generous approximation, the same shape
        as a per-device poll's own budget below; DiscoveryJob._run_safe's
        guard (netpath/nodediscover.py) is the backstop for whatever this
        misses."""
        settings = job.settings
        default_timeout = float(settings.get("default_snmp_timeout_s", 3.0))
        snmp_timeout_s = float(settings.get("discovery_snmp_timeout_s") or default_timeout)
        ping_timeout_s = float(settings.get("discovery_ping_timeout_s") or default_timeout)
        snmp_retries = max(0, int(settings.get("discovery_snmp_retries") or 0))
        ping_retries = max(0, int(settings.get("discovery_ping_retries") or 0))
        return (ping_timeout_s * (1 + ping_retries)
               + snmp_timeout_s * (1 + snmp_retries) * 10)

    # A full poll's fixed part: the ping sweep (if enabled) plus a handful
    # of SNMP round trips that always happen (scalars, ifTable, ifXTable) —
    # not a page-by-page model of a GETBULK walk against a very-high-port-
    # count chassis, which _inflight_budget_s cannot see coming. _run_one's
    # guard is the backstop for whatever this approximation misses, exactly
    # as expected_budget's own docstring in tracer.py says of a trace.
    _SNMP_ROUND_TRIPS = 4

    def _inflight_budget_s(self, ceiling_s: float = 30.0) -> float:
        """The longest a currently in-flight poll could still legitimately
        run, per its own device's configured ping/SNMP timeouts and
        retries — the drain window shutdown() should honour before giving
        up on it. Capped so one misconfigured device cannot hang shutdown
        indefinitely. Mirrors Monitor._inflight_budget_s for the trace
        scheduler this class was copied from."""
        worst = 0.0
        for device_id in self._inflight_ids():
            try:
                device = self.db.device(device_id)
                if device is None:
                    continue
                config = self.db.effective_config(device)
            except Exception:
                continue
            budget = 0.0
            if config.get("ping_enabled"):
                budget += (int(config.get("ping_count", 3) or 1)
                          * (int(config.get("ping_timeout_ms", 1000) or 1000) / 1000))
            timeout_s = float(config.get("snmp_timeout_s", 3.0))
            retries = int(config.get("snmp_retries", 2))
            budget += timeout_s * (retries + 1) * self._SNMP_ROUND_TRIPS
            try:
                if len(self.db.credential_candidates(device)) > 1:
                    budget += self._PROBE_BUDGET_S
            except Exception:
                pass
            worst = max(worst, budget)
        for job in self._running_discovery_jobs():
            try:
                worst = max(worst, self._discovery_budget_s(job))
            except Exception:
                continue
        return min(worst, ceiling_s)

    def shutdown(self, drain_s: float = 0.0) -> None:
        """Same as stop(), but waits for whatever was already running to
        finish (or to hit its own worst-case budget) before returning, so
        the databases Service.shutdown() closes right after this are not
        closed under a poll still writing its result. See _run_one's
        except clause for the backstop when a poll still overruns even
        this."""
        self.stop()
        self.drain(max(drain_s, self._inflight_budget_s()))

    def pool_state(self) -> dict:
        """How much of the poll pool is in use right now.

        Queued and running are counted separately: together against the
        pool size they produced gauges reading "48 of 32 busy".
        """
        with self._lock:
            busy = len(self._started)
            queued = len(self._queued)
        workers = getattr(self._executor, "_max_workers", 0) if self._executor else 0
        return {"busy": busy, "queued": queued, "workers": workers,
                "saturated": bool(workers and busy >= workers and queued),
                # Added beside the original four, never in place of them.
                "auto": bool(self._autoscale["auto"]),
                "floor": int(self._autoscale["min"]),
                "ceiling": int(self._autoscale["max"]),
                "demand": round(self._autoscale_want, 1)}

    # How many cycles in a row a down device may skip SNMP. Two skips then
    # one attempt is the ~3x cap: enough to take most of the cost out of a
    # site outage, short enough that a device whose SNMP recovers before its
    # ping does is still found within about three intervals.
    _SNMP_BACKOFF_SKIPS = 2

    def _snmp_backoff_due(self, device_id: int) -> bool:
        """Whether this cycle skips SNMP for a device that is down.

        Counts cycles rather than keeping a wall-clock next-run stamp, on
        purpose. _last_ping/ping_interval_s is a wall clock because it
        answers an operator's separate question ("ping less often than you
        poll"); reusing it here would let that setting silently change how
        SNMP backs off. A skip count is its own thing.
        """
        skipped = self._snmp_backoff.get(device_id, 0)
        if skipped >= self._SNMP_BACKOFF_SKIPS:
            self._snmp_backoff[device_id] = 0
            return False
        self._snmp_backoff[device_id] = skipped + 1
        return True

    def _record_poll_cost(self, device_id: int, elapsed: float) -> None:
        """Fold one poll's wall time into this device's mean, and the fleet's.

        Weighted rather than averaged because the pool has to be sized for
        what polls cost NOW: a device that just went down costs thirty times
        what it did an hour ago, and an average would take an hour to say so.
        """
        if elapsed < 0 or elapsed > _POLL_COST_CEILING_S:
            # A clock step, or a poll that outlived a shutdown drain. Either
            # way it describes the machine, not the device.
            return
        previous = self._poll_cost.get(device_id)
        cost = elapsed if previous is None else (
            _POLL_COST_ALPHA * elapsed + (1 - _POLL_COST_ALPHA) * previous)
        self._poll_cost[device_id] = cost
        self._poll_cost_mean = (
            _POLL_COST_ALPHA * cost + (1 - _POLL_COST_ALPHA) * self._poll_cost_mean)

    def _running_text(self) -> str:
        n = self.db.device_count()
        pool = self.pool_state()
        # The phrase "N busy and N queued of N worker(s)" is asserted
        # verbatim by tests/test_poll_write_path.py. Additions go after it.
        auto = (f" · auto {pool['floor']}-{pool['ceiling']}"
                if pool["auto"] else "")
        return (f"Polling {n} device(s) · {pool['busy']} busy and "
                f"{pool['queued']} queued of {pool['workers']} worker(s)"
                f"{auto} · last poll {ago(self._last_completed)}")

    def worker_state(self) -> dict:
        with self._lock:
            return {device_id: {"queued": self._queued.get(device_id),
                                "started": self._started.get(device_id)}
                    for device_id in set(self._queued) | set(self._started)}

    def next_runs(self) -> dict[int, float]:
        return dict(self._next_run)

    def poll_now(self, device_id: int) -> bool:
        """Submits this device to the worker pool now, ahead of its interval.
        True when it was queued, False when a poll for it was already queued
        or running — a click during an in-flight poll cannot start a second
        one, and reporting "Polled" off the first one's completion claimed
        credit for work the click did not cause."""
        # Also doubles as "try the sensor walk again": dropping the cadence
        # stamp skips both _SENSOR_REFRESH_S and the hourly reprobe window.
        self._sensor_read.pop(device_id, None)
        self._sensor_threshold_read.pop(device_id, None)
        return self._submit(device_id)

    def set_focus(self, device_id: int, ttl_s: float, interval_s: float) -> None:
        """The device a browser has selected polls at interval_s until the
        TTL lapses. interval_s <= 0 (the setting's off switch) clears any
        focus instead. Pulls the device's next run forward so the first
        fast poll lands promptly rather than after the profile interval."""
        if interval_s <= 0:
            self._focus = None
            return
        now = time.time()
        self._focus = (device_id, now + ttl_s, interval_s)
        due = self._next_run.get(device_id)
        if due is not None and due > now + interval_s:
            self._next_run[device_id] = now + interval_s

    # ------------------------------------------------------------ discovery

    def start_discovery(self, kind: str, target: str,
                        overrides: dict | None = None,
                        allow_ping_only: bool = False,
                        group_id: int | None = None,
                        scan_overrides: dict | None = None,
                        refuse_if_target_running: bool = False) -> int:
        """`overrides` is what THIS run's settings are built from; `group_id`
        and `scan_overrides` are what the row keeps so Re-discover can build
        the same settings again from the profile as it stands then.

        `refuse_if_target_running` raises DiscoveryBusy instead of putting a
        second sweep of one target on the wire. The check is here, under the
        lock the start holds, and not in the caller: asked first and acted on
        afterwards it is two steps with a window between them, and the web
        server is threaded, so a double-click on Re-discover fits two
        requests through it.
        """
        settings = dict(self.db.settings())
        if overrides:
            settings.update(overrides)
        with self._discovery_lock:
            if refuse_if_target_running and self._target_running(target):
                raise DiscoveryBusy(target)
            job_id = self.db.add_discovery_job(kind, target,
                                               allow_ping_only=allow_ping_only,
                                               group_id=group_id,
                                               scan_overrides=scan_overrides)
            job = DiscoveryJob(self.db, job_id, kind, target, settings,
                               log=self.log)
            self._discovery_jobs[job_id] = job
            job.start()
        return job_id

    def _target_running(self, target: str) -> bool:
        """Whether a sweep of this target is on the wire. Callers hold
        _discovery_lock, which is also what keeps a job whose row exists but
        whose thread has not been started yet from reading as stranded."""
        with self._discovery_lock:
            return any(job.target == target and job.running
                       for job in list(self._discovery_jobs.values()))

    def cancel_discovery(self, job_id: int) -> None:
        job = self._discovery_jobs.get(job_id)
        if job is not None:
            job.cancel()

    def discovery_running(self, job_id: int) -> bool:
        # Under the start's own lock: between the job row being written and
        # its thread being started there is nothing to read is_alive() on,
        # and a row read then would answer "stranded" for a sweep that is
        # about to run.
        with self._discovery_lock:
            job = self._discovery_jobs.get(job_id)
            return job is not None and job.running

    @staticmethod
    def _result_addresses(result) -> list[str]:
        """Every address the sweep reached this result on, the probed one
        first. Blank for a row written before 5.0 or by a sweep with
        discovery_addresses off."""
        addresses = [result["ip"]]
        keys = result.keys()
        if "ip_addresses" in keys and result["ip_addresses"]:
            try:
                walked = json.loads(result["ip_addresses"])
            except (TypeError, ValueError):
                walked = []
            for address in walked if isinstance(walked, list) else []:
                text = nodesdb.alias_candidate(address)
                if text and text not in addresses:
                    addresses.append(text)
        return addresses

    def promote(self, job_id: int, result_ids: list[int],
                force: bool = False) -> list[int]:
        """Creates a devices row per discovery result, carrying the
        discovered community/version as a per-device override only when it
        matches none of the target group's own credentials — its primary
        credential or any additional one — so a device that a profile's
        existing credential list already covers keeps trying that shared
        list (and benefits from any future credential added to the
        profile) instead of being pinned to one override. Already-promoted
        result ids are a no-op rather than a duplicate-IP error, so a
        second promote call with an overlapping selection is always safe
        to retry. A ping-only result (no SNMP answer) is skipped outright
        unless its job was started with the allow-ping-only option — the
        checkbox state in the browser is a convenience, this is the rule.

        A result folded into another (same box, second L3 address) is
        promoted as its primary, so ticking either row adds one device;
        a result whose walked addresses match a device already on file is
        recorded on that device rather than added beside it. `force` skips
        that fold for an operator who says they're genuinely two boxes.
        """
        job = self.db.discovery_job(job_id)
        allow_ping_only = bool(job and job["allow_ping_only"])
        family = self._folded_family(job_id)
        device_ids = []
        seen_results = set()
        for raw_id in result_ids:
            result = self.db.discovery_result(raw_id)
            if result is not None and result.keys().__contains__("folded_into_result_id") \
                    and result["folded_into_result_id"]:
                primary = self.db.discovery_result(result["folded_into_result_id"])
                if primary is not None:
                    result = primary
            if result is None or result["job_id"] != job_id:
                continue
            result_id = result["id"]
            if result_id in seen_results:
                continue
            seen_results.add(result_id)
            if not result["snmp_ok"] and not allow_ping_only:
                continue
            if result["promoted_device_id"]:
                device_ids.append(result["promoted_device_id"])
                continue
            addresses = self._result_addresses(result)
            existing = self.db.device_by_ip(result["ip"])
            if existing is None and not force:
                for address in addresses:
                    owner = self.db.device_id_for_address(address)
                    if owner is not None:
                        existing = self.db.device(owner)
                        break
            if existing is not None:
                self.db.record_device_addresses(
                    existing["id"], addresses, "discovery")
                self._mark_promoted_family(result_id, existing["id"], family)
                device_ids.append(existing["id"])
                continue
            group_id = result["suggested_group_id"]
            group_row = self.db.group(group_id) if group_id else None
            overrides = {}
            if result["snmp_ok"] and result["community_or_user"]:
                known = [group_row] + list(self.db.group_credentials(group_id)) \
                       if group_row is not None else []
                matches_known = any(
                    g["community"] == result["community_or_user"]
                    and g["snmp_version"] == result["snmp_version"] for g in known)
                if not matches_known:
                    overrides["community"] = result["community_or_user"]
                    overrides["snmp_version"] = result["snmp_version"]
            elif not result["snmp_ok"]:
                # A ping-only device would otherwise sit failing SNMP on
                # every poll; it can be switched back on in its Edit form
                # once real credentials are known.
                overrides["snmp_enabled"] = 0
                overrides["ping_enabled"] = 1
            # The manual name is left as the IP (add_device's default):
            # the displayed name prefers sys_name on its own, so copying
            # sysName into the manual field would only shadow later
            # renames on the device.
            device_id = self.db.add_device(
                result["ip"], group_id=group_id, **overrides)
            if result["snmp_ok"]:
                keys = result.keys()
                self.db.seed_identity(
                    device_id, sys_descr=result["sys_descr"] or "",
                    sys_name=result["sys_name"] or "",
                    sys_object_id=result["sys_object_id"] or "",
                    vendor=result["vendor"] or "",
                    vendor_source=(result["vendor_source"] if "vendor_source" in keys else "") or "",
                    vendor_confidence=(result["vendor_confidence"]
                                       if "vendor_confidence" in keys else "") or "",
                    vendor_evidence=(result["vendor_evidence"]
                                     if "vendor_evidence" in keys else None))
            self.db.record_device_addresses(device_id, addresses, "discovery")
            self._mark_promoted_family(result_id, device_id, family)
            device_ids.append(device_id)
        return device_ids

    def _folded_family(self, job_id: int) -> dict[int, list[int]]:
        """`{primary result id: [ids folded into it]}`, read once per
        promote() rather than once per row (promote-all on a large job)."""
        family: dict[int, list[int]] = {}
        for row in self.db.discovery_results(job_id):
            if "folded_into_result_id" not in row.keys():
                break
            primary = row["folded_into_result_id"]
            if primary and not row["promoted_device_id"]:
                family.setdefault(primary, []).append(row["id"])
        return family

    def _mark_promoted_family(self, result_id: int, device_id: int,
                              family: dict[int, list[int]]) -> None:
        """Mark the promoted row and every row folded into it, so all of
        that device's addresses show as added, not only the one ticked."""
        self.db.mark_promoted(result_id, device_id)
        for folded_id in family.get(result_id, ()):
            self.db.mark_promoted(folded_id, device_id)

    # ------------------------------------------------------------------ loop

    # A backstop behind the generation counter: a config change made
    # outside this process (a second copy of the app on the same file)
    # would not bump it, so the merged configs are rebuilt at least this
    # often regardless.
    _CONFIG_REFRESH_S = 60.0

    def _loop(self) -> None:
        """The scheduling thread. Every pass is guarded: this thread dying
        silently — which one transient database error was enough to do —
        stopped all polling with `poller.error` still None and the status
        strip still reading "Polling N devices". Now the failure is
        recorded, shown, and the thread keeps going."""
        while not self._stop.is_set():
            try:
                self._schedule_pass()
                if self.error:
                    self.log.add(NODES, "Polling scheduling recovered")
                    self.error = None
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                self.error = f"Poller scheduling failed: {message}"
                self._bump("errors")
                self.log.add(ERROR, self.error, detail=traceback.format_exc())
            self._stop.wait(1.0)

    def _schedule_pass(self) -> None:
        """One pass over the fleet: whose turn is it to be polled.

        Reads six columns per enabled device and nothing else. The merged
        per-device config — which used to be recomputed here once per
        device per second, four settings reads and a group read each — is
        held between passes and rebuilt only when nodesdb's config
        generation moves or the backstop expires.
        """
        now = time.time()
        generation = self.db.config_generation()
        if (self._configs is None or generation != self._configs_generation
                or now - self._configs_loaded > self._CONFIG_REFRESH_S):
            self._configs = self.db.effective_configs()
            self._configs_generation = generation
            self._configs_loaded = now
            self._forget_devices(set(self._configs))
        self._note_saturation(now)
        focus = self._focus
        # Little's Law, accumulated in the loop that is already running:
        # a device polled every `interval` seconds, each poll costing
        # `cost` seconds of a worker, occupies cost/interval of one worker
        # continuously. Summed over the fleet that is how many workers the
        # configured cadence actually requires. No extra query, no extra
        # iteration -- both terms are already in hand here.
        demand = 0.0
        for device in self.db.schedule_rows():
            device_id = device["id"]
            config = self._configs.get(device_id)
            if config is None:
                # Added since the last rebuild; it is picked up on the next
                # pass, because add_device bumped the generation.
                continue
            interval = config["poll_interval_s"]
            # The device selected in a browser polls faster (SNMP
            # devices only — a fast ping-only cadence shows nothing
            # new) until its focus TTL lapses.
            focused = (focus is not None and device_id == focus[0]
                       and now < focus[1] and config.get("snmp_enabled", True))
            if focused:
                interval = min(interval, focus[2])
            due = self._next_run.get(device_id)
            if due is None:
                due = (device["last_poll_ts"] + interval) if device["last_poll_ts"] else now
                self._next_run[device_id] = due
            if now >= due:
                self._next_run[device_id] = now + interval
                if device_id in self._started or device_id in self._queued:
                    # A poll slower than the fast focus cadence is
                    # expected, not an overrun worth logging — only
                    # blowing the device's own profile interval is.
                    if not (focused and interval < config["poll_interval_s"]):
                        self._record_overrun(device, now, config)
                else:
                    self._submit(device_id)
            demand += (self._poll_cost.get(device_id, self._poll_cost_mean)
                       / max(interval, 1.0))
            self._maybe_walk_mac_table(device, config, now)
            self._maybe_walk_lldp(device, config, now)
            self._maybe_walk_vlans(device, config, now)
            self._maybe_walk_arp_table(device, config, now)
        self._autoscale_pass(now, demand)

    # How long the pool has to look saturated before it is worth telling
    # somebody. A burst at the top of a poll cycle is normal; five minutes
    # of it means the pool is genuinely too small for the fleet.
    _SATURATION_S = 300.0

    # How often the pool's size is reconsidered, and how rarely it is
    # actually changed. The two are deliberately different numbers.
    #
    # Evaluating often is free -- it is arithmetic over dicts already in
    # hand -- and evaluating rarely would mean a site outage waited out the
    # interval before anyone noticed the fleet had got expensive.
    #
    # RESIZING often is not free. reconfigure() builds a whole new
    # ThreadPoolExecutor and calls shutdown(wait=False) on the old one,
    # which does not cancel running futures; the executor also keeps a
    # module-global entry per worker thread and an atexit handler. Once a
    # minute means at most one abandoned pool draining at a time. Seconds
    # apart would mean a heap of them.
    _AUTOSCALE_INTERVAL_S = 15.0
    _AUTOSCALE_COOLDOWN_S = 60.0
    # A target within this fraction of the current size is not worth a new
    # pool: 16 -> 17 is noise, not a decision.
    _AUTOSCALE_DEADBAND = 0.10
    _AUTOSCALE_DEADBAND_FLOOR = 2
    # Consecutive evaluations that must agree before shrinking. Growing
    # answers a fleet being polled late, which an operator can see; shrinking
    # answers nothing urgent at all, and every shrink abandons a pool.
    _AUTOSCALE_SHRINK_VOTES = 4
    # Saturation this long with the model still not asking for more means the
    # cost estimates are behind the truth -- the first seconds of an outage,
    # before any expensive poll has completed to move an EWMA. Push up anyway.
    _AUTOSCALE_RATCHET_S = 60.0

    def _autoscale_pass(self, now: float, demand: float) -> None:
        """Size the poll pool from what the fleet actually costs.

        Called once a second with this pass's demand figure; keeps the
        rolling maximum and acts on it at most every _AUTOSCALE_INTERVAL_S,
        resizing at most every _AUTOSCALE_COOLDOWN_S.

        The maximum rather than the latest sample: demand dips for a pass
        that happens to fall between due times, and sizing off a trough is
        how a pool ends up too small a second later.
        """
        settings = self._autoscale
        if not settings["auto"] or self._executor is None:
            # Nothing accumulates while auto is off, or the max since start
            # would be waiting for whoever switches it on later.
            self._autoscale_demand = 0.0
            self._autoscale_sat_since = None
            return
        if demand > self._autoscale_demand:
            self._autoscale_demand = demand

        # Saturation is sampled on EVERY pass, not at the evaluation instants
        # below, and any unsaturated pass resets the clock. The scheduler
        # submits every due device at once, so a fleet whose devices share a
        # due-time phase is saturated in bursts by design; sampling only
        # every 15 s can land inside burst after burst and read that as
        # continuous, ratcheting the pool up against a model that was right.
        # It would then shrink on the votes, re-lock, and ratchet again --
        # an abandoned executor every couple of minutes, for ever.
        pool = self.pool_state()
        if pool["saturated"]:
            if self._autoscale_sat_since is None:
                self._autoscale_sat_since = now
        else:
            self._autoscale_sat_since = None

        if now - self._autoscale_at < self._AUTOSCALE_INTERVAL_S:
            return
        self._autoscale_at = now

        floor, ceiling = int(settings["min"]), int(settings["max"])
        current = getattr(self._executor, "_max_workers", floor)
        want = math.ceil(self._autoscale_demand * float(settings["headroom"]))
        self._autoscale_demand = 0.0

        # The corrective term, and the only one. Overruns are not usable
        # here: _record_overrun returns early for a device that is down or
        # failing, so the overrun counter goes quiet during exactly the
        # outage that makes the fleet expensive. Measured on a 300-device
        # fleet at half the workers it needed, the counter read zero while
        # 182 devices sat queued and p95 lateness was already 8.95 s on a
        # 15 s interval. Saturation is the signal that moves when it should.
        if (self._autoscale_sat_since is not None
                and now - self._autoscale_sat_since >= self._AUTOSCALE_RATCHET_S
                and want <= current):
            # Saturated without a break for a full minute while the model
            # still asks for no more: the cost estimates are behind the
            # truth, which is the first seconds of an outage before any
            # expensive poll has completed to move an EWMA. Push up anyway.
            want = current + max(1, current // 4)

        want = max(floor, min(ceiling, want))
        self._autoscale_want = want
        self._autoscale_ceiling = ceiling
        if want == current:
            self._autoscale_shrink_votes = 0
            return

        deadband = max(self._AUTOSCALE_DEADBAND_FLOOR,
                       int(current * self._AUTOSCALE_DEADBAND))
        if abs(want - current) < deadband and want > floor and want < ceiling:
            self._autoscale_shrink_votes = 0
            return

        if want < current:
            # Shrinking buys nothing an operator can see and costs an
            # abandoned pool, so it has to be asked for repeatedly.
            self._autoscale_shrink_votes += 1
            if self._autoscale_shrink_votes < self._AUTOSCALE_SHRINK_VOTES:
                return
            want = max(want, current - max(1, current // 4))
        else:
            self._autoscale_shrink_votes = 0
            want = min(want, max(current * 2, current + 1))

        if now - self._autoscale_resized_at < self._AUTOSCALE_COOLDOWN_S:
            return
        self._autoscale_shrink_votes = 0
        self._autoscale_resized_at = now
        self._apply_pool_size(want)
        self.log.add(NODES, f"Poll pool resized from {current} to {want} worker(s) "
                            f"(floor {floor}, ceiling {ceiling})")

    def _apply_pool_size(self, workers: int) -> None:
        """Swap in a pool of this size and let the old one drain.

        shutdown(wait=False) rather than cancel: a poll in flight is talking
        to a device and holds no lock this cares about, so letting it finish
        costs nothing, where cancelling it would leave a device unpolled for
        an interval and its result unrecorded.
        """
        workers = max(1, int(workers))
        previous, self._executor = self._executor, ThreadPoolExecutor(
            max_workers=workers)
        if previous is not None:
            previous.shutdown(wait=False)

    def _note_saturation(self, now: float) -> None:
        """Raise (and clear) a system alert when every poll worker is busy
        and devices are still waiting.

        Without it, a fleet that had outgrown poll_workers looked like a
        fleet of slow devices. The alert names the number to raise.
        """
        pool = self.pool_state()
        engine = self.alert_engine
        # With the pool sizing itself, saturation below the ceiling is the
        # controller's job and not news: it corrects within fifteen seconds,
        # and an alert about something the application is already fixing is
        # the kind of noise that teaches operators to stop reading alerts.
        # Only the ceiling being reached means a human has to do something.
        #
        # _autoscale_ceiling is None until the autoscaler has run, which is
        # also the case for a poller whose start() never ran -- that is how
        # tests/test_poll_write_path.py drives this method, and None keeps
        # the pre-autoscaling behaviour exactly.
        ceiling = self._autoscale_ceiling
        below_ceiling = ceiling is not None and pool["workers"] < ceiling
        if not pool["saturated"] or below_ceiling:
            if self._saturation_reported:
                clear = getattr(engine, "clear_system_occurrence", None)
                if clear is not None:
                    clear("poll_pool_saturated", "poller")
            self._saturated_since = None
            self._saturation_reported = False
            return
        if self._saturated_since is None:
            self._saturated_since = now
            return
        if self._saturation_reported or now - self._saturated_since < self._SATURATION_S:
            return
        self._saturation_reported = True
        raise_it = getattr(engine, "system_occurrence", None)
        if raise_it is None:
            return
        minutes = (now - self._saturated_since) / 60.0
        raise_it(
            "poll_pool_saturated", "poller", "Polling pool", severity=3,
            extra={"busy": pool["busy"], "queued": pool["queued"],
                   "workers": pool["workers"],
                   "saturated_minutes": round(minutes, 1),
                   # The evidence behind the number, so the alert says why
                   # the ceiling is where it is as well as that it was hit.
                   "auto": pool["auto"], "floor": pool["floor"],
                   "ceiling": pool["ceiling"], "demand": pool["demand"]},
            message=(
                f"The poll pool has been at its ceiling of {pool['workers']} "
                f"workers with {pool['queued']} device(s) waiting for "
                f"{minutes:.0f} minutes. Devices are being polled later than "
                f"their interval. Raise Nodes → Settings → Most poll worker "
                f"threads, lengthen the polling interval, or split the fleet "
                f"across instances."
                if ceiling is not None else
                f"Every one of the {pool['workers']} poll workers has "
                f"been busy with {pool['queued']} device(s) waiting for "
                f"{minutes:.0f} minutes. Devices are being polled later "
                f"than their interval. Raise Nodes → Settings → Poll worker "
                f"threads, or lengthen the polling interval."))

    def _forget_devices(self, keep: set) -> None:
        """Drop the per-device state of devices that no longer exist.

        Every one of these is keyed by device id and kept for the process
        lifetime, so without this a long-running install accumulates an
        entry per device ever deleted.
        """
        # list(cache) first: workers insert into _poll_cost and _snmp_backoff
        # from _run_one and _poll_device while this runs, and iterating one
        # live would raise "dictionary changed size during iteration" and
        # cost a scheduling pass.
        for cache in (self._next_run, self._last_ping, self._next_mac_walk,
                      self._next_lldp_walk, self._next_vlan_walk,
                      self._next_arp_walk,
                      self._credentials, self._credential_probe_failed,
                      self._addresses_read, self._bulk_repetitions,
                      self._sensor_read, self._sensor_threshold_read,
                      self._sensor_diag_ts, self._snmp_backoff,
                      self._poll_cost):
            for device_id in [k for k in list(cache) if k not in keep]:
                cache.pop(device_id, None)
        # A set rather than a dict, so not in the loop above: the "logged
        # once" memory for a device that answers no ARP table.
        self._arp_unanswered.difference_update(
            [k for k in list(self._arp_unanswered) if k not in keep])
        with self._lock:
            for jobs in (self._oid_walks, self._vendor_ids):
                for device_id in [k for k in jobs if k not in keep]:
                    if not jobs[device_id].running:
                        jobs.pop(device_id, None)
        self._engines.forget(keep)

    def _maybe_walk_mac_table(self, device, config: dict, now: float) -> None:
        """Queue a forwarding-table walk when this device's own interval has
        come round. Off (0) unless a profile or a device asks for it, so an
        upgrade adds no SNMP load anywhere until somebody opts in.

        Not started while the device is failing or SNMP-disabled: a walk of
        hundreds of OIDs against a box that is not answering is the poll
        overrun problem all over again, at ten times the size.
        """
        interval = float(config.get("mac_table_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_mac_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every opted-in switch at once.
            self._next_mac_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._mac_running:
                return
            self._mac_running.add(device_id)
        self._next_mac_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_mac_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._mac_running.discard(device_id)

    def _maybe_walk_lldp(self, device, config: dict, now: float) -> None:
        """Queue an LLDP/CDP neighbour walk when this device's own interval
        has come round — _maybe_walk_mac_table's own scheduling, applied to
        lldp_interval_s instead of mac_table_interval_s, and sharing its
        executor: both are the same shape of thing (a whole-device table
        walk of hundreds of rows, off the poll pool), so there is no reason
        for a second thread pool to size separately."""
        interval = float(config.get("lldp_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_lldp_walk.get(device_id)
        if due is None:
            self._next_lldp_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._lldp_running:
                return
            self._lldp_running.add(device_id)
        self._next_lldp_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_lldp_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._lldp_running.discard(device_id)

    def _maybe_walk_vlans(self, device, config: dict, now: float) -> None:
        """Queue a per-port VLAN membership walk when this device's own
        interval has come round — _maybe_walk_lldp's own scheduling, applied
        to vlan_interval_s instead of lldp_interval_s, sharing the same
        executor for the same reason: another whole-device table walk of
        hundreds of rows, off the poll pool."""
        interval = float(config.get("vlan_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_vlan_walk.get(device_id)
        if due is None:
            self._next_vlan_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._vlan_running:
                return
            self._vlan_running.add(device_id)
        self._next_vlan_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_vlan_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._vlan_running.discard(device_id)

    def _maybe_walk_arp_table(self, device, config: dict, now: float) -> None:
        """Queue an ARP-cache walk when this device's own interval has come
        round — _maybe_walk_mac_table's own scheduling, applied to
        arp_table_interval_s, on the same executor for the same reason as
        the LLDP and VLAN walks: a whole-device table walk of hundreds to
        thousands of rows, off the poll pool, so a slow router's cache can
        never delay the sixty-second cycle. Off (0) unless a profile or a
        device asks for it — and here 0 really is the shipped value (see
        _merge_config), so an upgrade queues nothing anywhere.

        Not started while the device is failing or SNMP-disabled, for the
        reason _maybe_walk_mac_table gives, only more so: an ARP cache is
        the largest table this poller ever walks."""
        interval = float(config.get("arp_table_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_arp_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every opted-in router at once.
            self._next_arp_walk[device_id] = now + random.uniform(0, interval)
            return
        if now < due:
            return
        with self._lock:
            if device_id in self._arp_running:
                return
            self._arp_running.add(device_id)
        self._next_arp_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_arp_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._arp_running.discard(device_id)

    def _submit(self, device_id: int) -> bool:
        """True when this call put the device on the pool; False when it was
        already queued or running, or the pool has shut down."""
        with self._lock:
            if device_id in self._queued or device_id in self._started:
                return False
            self._queued[device_id] = time.time()
        try:
            self._executor.submit(self._run_one, device_id)
        except (RuntimeError, AttributeError):
            # The pool has shut down, or there is none (the scheduler being
            # exercised without one). Either way the device is not queued.
            with self._lock:
                self._queued.pop(device_id, None)
            return False
        return True

    def _record_overrun(self, device, now, config: dict | None = None) -> None:
        """Record that a poll was still running as the next one fell due.

        Not recorded while the device is not answering: a poll that spends
        its whole budget in timeouts and retries is the configured timeout
        doing exactly what it was told to, and the outage itself is already
        reported by device_down. status == "down" catches a formally down
        device; consecutive_fail > 0 catches the two or three polls before
        that, which is when the first overrun would otherwise fire — an
        overrun leads the outage, it does not follow it. Suppressed at
        source rather than filtered later, so no event row and no Debug
        line are written either (wirelessdb.out_of_service is the same
        shape).
        """
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        self._bump("overruns")
        running_for = now - self._started.get(device["id"], now)
        if config is None:
            config = self.db.effective_config(device)
        interval = config["poll_interval_s"]
        self.log.add(ERROR, f"Poll overrun for {device['name'] or device['ip']}: "
                            f"still running after {running_for:.0f}s, interval is "
                            f"{interval}s — lengthen the interval or shorten the "
                            f"timeout.", target=device["ip"])
        self.db.record_device_event(device["id"], "poll_overrun",
                                    f"running {running_for:.0f}s")

    def _run_one(self, device_id: int) -> None:
        """Wrapped entirely in except Exception (a scheduler thread must
        never die quietly); finally always clears _queued/_started for
        this id regardless of outcome."""
        with self._lock:
            self._queued.pop(device_id, None)
            self._started[device_id] = time.time()
        try:
            device = self.db.device(device_id)
            if device is None or not device["enabled"]:
                return
            config = self.db.effective_config(device)
            self._bump("polls")
            self._poll_device(device, config)
        except Exception as exc:
            self._bump("errors")
            # Two shapes that are not bugs and so get no traceback:
            # "Cannot operate on a closed database" while _stop is set (this
            # poll ran past shutdown()'s drain window), and a foreign key
            # failure with the device now gone (deleted mid-poll). The same
            # exceptions for any other reason still get the full treatment.
            device_gone = False
            if isinstance(exc, sqlite3.IntegrityError):
                try:
                    device_gone = self.db.device(device_id) is None
                except Exception:
                    pass  # can't tell any more; falls through to the loud path
            if isinstance(exc, sqlite3.ProgrammingError) and self._stop.is_set():
                self.log.add(NODES, f"Poll of device #{device_id} finished after "
                                    f"the poller stopped; its result was not saved")
            elif device_gone:
                self.log.add(NODES, f"Device #{device_id} was deleted while its "
                                    f"poll was running; the result was not saved")
            else:
                self.log.add(ERROR, f"Node poll worker error for device #{device_id}",
                             detail=traceback.format_exc())
                traceback.print_exc()
        finally:
            finished = time.time()
            with self._lock:
                started = self._started.pop(device_id, None)
                self._last_completed = finished
            if started is not None:
                self._record_poll_cost(device_id, finished - started)

    # ---------------------------------------------------------------- poll

    def _poll_device(self, device, config: dict) -> None:
        device_id = device["id"]
        ip = device["ip"]
        now = time.time()

        settings = self.db.settings()
        self._verify_replies = bool(settings.get("v3_verify_replies", True))
        ping_ok = None
        ping_rtt_ms = None
        ping_loss_pct = None
        if config.get("ping_enabled"):
            # Several probes, not one: a single probe can only ever report
            # 0% or 100% loss, which is no use for spotting a link that is
            # up but dropping a fifth of its traffic. The timeout is its own
            # setting rather than snmp_timeout_s borrowed — ICMP round trips
            # and SNMP round trips have nothing to do with each other, and
            # tying them meant raising an SNMP timeout silently slowed every
            # ping.
            interval = float(settings.get("ping_interval_s", 0) or 0)
            due = (interval <= 0
                   or (now - self._last_ping.get(device_id, 0.0)) >= interval)
            if due:
                self._last_ping[device_id] = now
                sent, received, rtt = ping_many(
                    ip, count=int(config.get("ping_count", 3) or 1),
                    timeout_ms=int(config.get("ping_timeout_ms", 1000) or 1000))
                ping_ok = received > 0
                ping_rtt_ms = rtt
                ping_loss_pct = 100.0 * (sent - received) / sent if sent else None
            else:
                # Not this device's turn to be pinged. The last known result
                # still stands: skipping a probe must not read as a failed
                # one, and record_poll overwrites both columns every time, so
                # the previous RTT has to be carried forward too or the device
                # row would blank it on every poll between pings.
                previous_ok = device["ping_ok"]
                ping_ok = None if previous_ok is None else bool(previous_ok)
                ping_rtt_ms = device["ping_rtt_ms"]

        if ping_ok:
            self._snmp_backoff.pop(device_id, None)

        snmp_ok = None
        snmp_error = ""
        # Whether SNMP failed because the device refuses something this
        # poller does not speak, rather than because it is unreachable.
        # Decided by exception type, never by a substring of the message:
        # no message this raises contains the word "unsupported".
        snmp_unsupported = False
        # Whether the agent verified the credential and then refused the
        # object under its own access control (authorizationError). Type-
        # decided like the two beside it: every message this raises
        # contains the word "auth", and so does every message that is NOT
        # this — see auth_failing below.
        snmp_denied = False
        # Whether the agent would not accept the message at all (a wrong
        # community or v3 password, an engine that will not resync).
        # Decided by exception type, never by a substring of the message:
        # the unsupportedSecLevels text contains "authPriv", and every
        # access-denied message above contains "authenticated", so "auth"
        # in the message was already raising auth_fail for faults that
        # proved the password GOOD.
        snmp_auth_failed = False
        # Whether the device answered every request, but below the level
        # it was asked at, and the reply was refused as a downgrade
        # (SnmpDowngrade). Type-decided like the three above. Not an
        # outage — the device is demonstrably answering — and not an auth
        # failure — nothing contradicted the password, there was no
        # signature to contradict it — which is why it is neither in the
        # down path nor in snmp_failing_now below. Before this flag it fell
        # into the generic arm, and with ping off a device that answered
        # every single request was marked down and mailed as one.
        snmp_downgraded = False
        identity = None
        uptime_ticks = None
        interfaces: list[dict] = []
        # Whether the interface read finished. A partial read must not
        # delete the interfaces it never reached (see replace_interfaces).
        interfaces_complete = True
        # None until an interface read actually happens, so a poll that
        # never got that far leaves the stored note alone rather than
        # blanking a truncation the stored rows still show.
        interfaces_note = None
        metrics: list[tuple] = []   # (key, label, unit, kind, value)

        # A device already down costs about thirty times one that is up, so
        # it skips the SNMP half of most cycles. Ping is NOT backed off,
        # which is what makes that safe: ping detects both the outage and the
        # recovery and _next_run is untouched, so the cadence, the timeline
        # and the up/down events are unchanged. Decided on THIS cycle's ping,
        # not device["status"], which _run_one read before the poll and so
        # describes the previous one. See INTERNALS.md.
        # ping_enabled and `is False` are both load-bearing: with ping off,
        # SNMP is the only evidence the device exists and skipping it means a
        # recovered device is never seen to recover; None is "no ping
        # evidence", and no evidence is not a failure.
        backed_off = (device["status"] == "down"
                      and config.get("ping_enabled")
                      and ping_ok is False
                      and config.get("snmp_enabled")
                      and self._snmp_backoff_due(device_id))
        if backed_off:
            # None, not False: None is this file's established "the poll did
            # not touch that method" (see the lane events below), and False
            # here would be read as a real SNMP failure by snmp_failing_now
            # once ping recovered, counting a phantom failure toward
            # snmp_fail_alert_after on every recovery. record_poll is handed
            # the previous values further down instead, so the device row
            # keeps saying what it last actually knew.
            self._bump("snmp_backoff")

        if config.get("snmp_enabled") and not backed_off:
            try:
                cred_config, identity, uptime_ticks, metrics = \
                    self._poll_snmp_scalars_with_credential(device, config)
                interfaces, interfaces_complete, interfaces_reason, interfaces_note = \
                    self._poll_interfaces(device, cred_config)
                # SNMP itself worked — the scalars answered — so snmp_ok
                # stays true and the interface read is what degraded. The
                # reason still has to reach the device row: an empty
                # interface table with no error beside it is the "healthy
                # device, zero interfaces" reading that sent operators
                # hunting the network instead of the agent.
                snmp_error = interfaces_reason
                if config.get("mib_file_id"):
                    metrics = metrics + self._poll_custom_mib(
                        device, cred_config, config["mib_file_id"])
                snmp_ok = True
            except SnmpUnsupported as exc:
                snmp_ok = False
                snmp_error = str(exc)
                snmp_unsupported = True
                self._bump("unsupported")
            except SnmpTimeout as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("timeout")
            except SnmpAccessDenied as exc:
                # Before SnmpError, which it is a subclass of: the credential
                # loop has already rotated on it (an authPriv alternate may
                # well have succeeded), so reaching here means every
                # candidate was refused this way or worse.
                snmp_ok = False
                snmp_error = str(exc)
                snmp_denied = True
                self._bump("denied")
            except _AuthFailure as exc:
                snmp_ok = False
                snmp_error = str(exc)
                snmp_auth_failed = True
                self._bump("auth_fail")
            except SnmpDowngrade as exc:
                # Before SnmpError, which it is a subclass of — the generic
                # arm is the outage path.
                snmp_ok = False
                snmp_error = str(exc)
                snmp_downgraded = True
                self._bump("downgraded")
            except SnmpError as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("errors")

        # -------------------------------------------------------- status

        down_after = int(settings.get("down_after_failures", 3))
        # SNMP's evidence that the device is up is wider than snmp_ok. An
        # authorizationError is the agent's own verified Response — it
        # accepted the message and refused the object — and a downgrade is
        # a reply to every request that merely lacked the signature asked
        # for. Neither is silence, and "down" means silence: a device that
        # answers is not having an outage, whatever else is wrong with it.
        # An auth failure is deliberately NOT here: a Report is the agent
        # declining to say anything about the request, and the existing
        # choice that it follows ping alone stands.
        snmp_answered = bool(snmp_ok) or snmp_denied or snmp_downgraded
        if not config.get("snmp_enabled"):
            # A ping-only device by design (SNMP off entirely) is reachable
            # by ping alone, regardless of the "degrade gracefully when
            # SNMP is failing" setting below — that setting is about a
            # device that normally has SNMP on, not one configured without
            # it. Ping-only is documented as a first-class configuration.
            reachable = bool(ping_ok)
        elif not config.get("ping_enabled"):
            # Nothing is pinging it, so SNMP is the only evidence there is.
            reachable = snmp_answered
        else:
            # Both probes run, so DOWN means both failed. A device answering
            # ICMP with a broken community string is reachable and
            # misconfigured; reporting it down hides the SNMP error behind
            # an outage that isn't happening. Per device and per profile,
            # because occasionally SNMP failing really is the outage.
            ping_only_ok = bool(config.get("unreachable_ping_only", True))
            reachable = snmp_answered or (ping_only_ok and bool(ping_ok))

        # snmp_denied deliberately has NO status of its own, and does not
        # reuse "unsupported" either. "unsupported" is a verdict about the
        # poller — it cannot speak what the device requires — and lives in
        # the status vocabulary of the devices table, the timeline segments,
        # the dashboard figures, the map and the availability report; a
        # fifth value there is a vocabulary change in six files for a
        # diagnostics fix. A refused object is a verdict about the
        # device's configuration, and the device itself is demonstrably
        # reachable (its agent verified the message and answered), so it
        # counts as answered above and the status is "up" — an outage is
        # the one thing it is not — and the access_denied event below
        # carries the finding. A downgrade is filed the same way, for the
        # same reason, with snmp_downgrade as its event.
        if snmp_unsupported:
            status = "unsupported"
        elif reachable:
            status = "up"
        elif device["consecutive_fail"] + 1 >= down_after:
            status = "down"
        else:
            status = device["status"] if device["status"] in ("up", "down") else "unknown"

        # Every sample this poll produced, written in ONE transaction at the
        # end (see the T4 block below) rather than one commit each. A device
        # that goes on to be marked down still leaves the loss sample that
        # explains why: the flush is unconditional, not part of the success
        # path.
        samples: list[tuple] = []   # (key, label, unit, kind, ts, value)
        if ping_loss_pct is not None:
            samples.append(("ping_loss_pct", "Packet loss", "%", "gauge",
                            now, ping_loss_pct))
        if ping_rtt_ms is not None:
            samples.append(("ping_rtt_ms", "Ping response time", "ms", "gauge",
                            now, ping_rtt_ms))

        # T1 — the device row.
        #
        # A backed-off cycle stores what SNMP last actually reported rather
        # than the None it reasoned with above. record_poll overwrites both
        # columns on every poll, so passing None would blank them: the
        # device pane would show a down device's SNMP as unknown, and
        # prev_snmp_ok would reset, so the next real failure would record a
        # second snmp_down event for an outage already being reported. The
        # skipped-ping branch carries its previous values forward for the
        # same reason -- see ping_interval_s above.
        stored_snmp_ok, stored_snmp_error = snmp_ok, snmp_error
        if backed_off:
            was = device["snmp_ok"]
            stored_snmp_ok = None if was is None else bool(was)
            stored_snmp_error = device["snmp_error"] or ""
        previous = self.db.record_poll(
            device_id, ping_ok=ping_ok, ping_rtt_ms=ping_rtt_ms,
            snmp_ok=stored_snmp_ok, snmp_error=stored_snmp_error,
            identity=identity, uptime_ticks=uptime_ticks,
            status=status, reachable=reachable, interfaces_note=interfaces_note)
        if previous is None:
            return

        if self.counters is not None and snmp_ok:
            self._bump("ok")

        # Once, when it starts and when it stops — not every poll. A device
        # over the interface cap stays over it, and a line repeated every
        # poll interval is noise the next real one hides behind. The note
        # itself lives on the device row for as long as it is true.
        if interfaces_note is not None:
            was = previous["interfaces_note"] if "interfaces_note" in previous.keys() else ""
            if bool(interfaces_note) != bool(was):
                self.log.add(
                    NODES,
                    (f"Interface table on {device['ip']}: {interfaces_note}."
                     if interfaces_note else
                     f"Interface table on {device['ip']} is no longer "
                     f"truncated: every interface it reports is read."),
                    target=device["ip"])

        # ---------------------------------------------------------- debug
        # A per-poll trace, the same shape monitor.py logs a trace with
        # (command + raw output in `detail`), so a device silently failing
        # to poll leaves a record beyond its own status/error fields.
        detail_lines = [
            f"ping       {'n/a' if ping_ok is None else ('ok' if ping_ok else 'no reply')}"
            + (f" ({ping_rtt_ms:.0f} ms)" if ping_rtt_ms is not None else ""),
            f"snmp       {'n/a' if snmp_ok is None else ('ok' if snmp_ok else 'failed')}",
        ]
        if snmp_ok:
            detail_lines.append(f"interfaces {len(interfaces)}"
                                + ("" if interfaces_complete else " (incomplete)"))
            if interfaces_note:
                detail_lines.append(f"truncated  {interfaces_note}")
            detail_lines.append(f"metrics    {len(metrics)}")
            if snmp_error:
                detail_lines.append(f"degraded   {snmp_error}")
        elif snmp_error:
            detail_lines.append(f"error      {snmp_error}")
        detail_lines.append(f"elapsed    {time.time() - now:.2f}s")
        self.log.add(NODES, f"Polled {device['ip']}: {status}", target=device["ip"],
                    detail="\n".join(detail_lines))

        # -------------------------------------------------------- events

        was_status = previous["status"]
        first_poll = previous["last_poll_ts"] is None
        if status == "up" and was_status not in ("up",) and not first_poll:
            self.db.record_device_event(device_id, "up", "responding again")
        elif status == "down" and was_status != "down":
            self.db.record_device_event(device_id, "down", snmp_error or "not responding")
        elif status == "unsupported" and was_status != "unsupported":
            self.db.record_device_event(device_id, "unsupported", snmp_error)

        # access_denied: the agent accepted the credential and refused the
        # object. Recorded beside `unsupported` because it is the same
        # kind of finding — a configuration verdict, not an outage — but on
        # a transition held in memory rather than in `status`, since it has
        # no status of its own (see the status block above). Entering the
        # set records access_denied with the full explanation; a successful
        # poll afterwards records access_ok, the pair alertrules.CLEARS
        # uses to close the alert, exactly as auth_fail/auth_ok do below.
        with self._lock:
            if snmp_denied and device_id not in self._access_denied:
                self._access_denied.add(device_id)
                access_event = ("access_denied", snmp_error)
            elif snmp_ok and device_id in self._access_denied:
                self._access_denied.discard(device_id)
                access_event = ("access_ok", "")
            else:
                access_event = None
        if access_event is not None:
            self.db.record_device_event(device_id, access_event[0], access_event[1])

        # snmp_downgrade: the same shape again, for a device answering below
        # the level asked. A transition, because the device that does this
        # does it on every poll until the operator either fixes the agent or
        # turns v3_verify_replies off — and then the next poll's verified
        # reply records snmp_verified, the pair alertrules.CLEARS uses to
        # close device_downgrade. Only a poll that succeeded leaves the set:
        # every other outcome — a timeout, a Report — says nothing about
        # whether replies verify now.
        with self._lock:
            if snmp_downgraded and device_id not in self._downgraded:
                self._downgraded.add(device_id)
                downgrade_event = ("snmp_downgrade", snmp_error)
            elif snmp_ok and device_id in self._downgraded:
                self._downgraded.discard(device_id)
                downgrade_event = ("snmp_verified", "")
            else:
                downgrade_event = None
        if downgrade_event is not None:
            self.db.record_device_event(device_id, downgrade_event[0], downgrade_event[1])

        # Per-method transitions (snmp_up/snmp_down, ping_up/ping_down): the
        # status timeline's split SNMP/ping lanes are built from these, not
        # from the up/down events above, which follow `status` — effectively
        # ping alone once unreachable_ping_only lets a dead SNMP agent hide
        # behind a healthy ping. Compared against `previous` (the device row
        # from before THIS poll's own record_poll update) rather than
        # recorded on every poll, so the event log grows on a real change,
        # not once per device per interval forever. A previous value of None
        # (never observed, or the method was off) seeds the first event too,
        # the same way the very first up/down does further down — a segment
        # needs a start. `snmp_ok`/`ping_ok` of None here means this poll
        # didn't touch that method (disabled, or not this poll's turn to
        # ping — see ping_interval_s above, which carries the old value
        # forward rather than going None), so it never manufactures an event
        # out of a probe that didn't run.
        prev_snmp_ok = previous["snmp_ok"]
        prev_snmp_ok = None if prev_snmp_ok is None else bool(prev_snmp_ok)
        prev_ping_ok = previous["ping_ok"]
        prev_ping_ok = None if prev_ping_ok is None else bool(prev_ping_ok)
        # An install upgraded from before the lanes existed has device rows
        # with snmp_ok/ping_ok already populated, so the comparison above
        # would never fire until the next flap — and then only for the
        # method that flapped, leaving the other lane empty. Once per device
        # per process: if no lane event was ever recorded, forget the
        # previous values so this poll seeds both methods it observed.
        with self._lock:
            unseeded = device_id not in self._method_seeded
        if unseeded:
            if not self.db.has_method_events(device_id):
                prev_snmp_ok = prev_ping_ok = None
            with self._lock:
                self._method_seeded.add(device_id)
        if snmp_ok is not None and snmp_ok != prev_snmp_ok:
            self.db.record_device_event(
                device_id, "snmp_up" if snmp_ok else "snmp_down",
                "" if snmp_ok else snmp_error)
        if ping_ok is not None and ping_ok != prev_ping_ok:
            self.db.record_device_event(
                device_id, "ping_up" if ping_ok else "ping_down", "")

        # TRANSITIONS, like the up/down events above: an alert an operator
        # resolved by hand must not re-open because the next poll repeated
        # what the last one said. The transition is held here, in
        # _auth_failing, rather than derived from the device row's previous
        # snmp_ok/snmp_error, which cannot answer it — a device that times
        # out one poll in ten would "recover" into an auth_ok every time, and
        # a multi-credential profile re-raises whichever candidate's error
        # came last, so the recorded text alternates while nothing changed.
        # Entering the set records auth_fail, leaving it records auth_ok,
        # everything else records nothing.
        #
        # Decided by exception type (snmp_auth_failed, set only in the
        # _AuthFailure arm), never by a substring of the message. This used
        # to test for "auth" in the text, and "auth" is in nearly every
        # SNMPv3 message there is: the unsupportedSecLevels explanation says
        # "authPriv", and an authorizationError explanation says "the
        # message authenticated" — so an alert named "SNMP authentication
        # failing" was raised for the one fault that proved the password
        # correct.
        auth_failing = bool(snmp_auth_failed and snmp_ok is False)
        # What ends it is any outcome proving the credential was ACCEPTED,
        # not only a successful poll. An authorizationError is one: the
        # agent verified the message and refused the object, so the
        # password is right by the device's own word. Leaving the set only
        # on snmp_ok kept "SNMP authentication failing" open beside an
        # access_denied whose text said the message authenticated — two
        # alerts contradicting each other about one password, one of them
        # stale. unsupportedSecLevels is NOT here: USM refuses the level
        # (RFC 3414 s3.2 step 5) before it checks the digest (step 6), so
        # that Report proves nothing about the password either way, and a
        # downgrade is unsigned, so it proves nothing at all.
        credential_accepted = bool(snmp_ok) or snmp_denied
        with self._lock:
            if auth_failing and device_id not in self._auth_failing:
                self._auth_failing.add(device_id)
                auth_event = ("auth_fail", snmp_error)
            elif credential_accepted and device_id in self._auth_failing:
                self._auth_failing.discard(device_id)
                auth_event = ("auth_ok", "")
            else:
                auth_event = None
        if auth_event is not None:
            self.db.record_device_event(device_id, auth_event[0], auth_event[1])

        # A switch whose SNMP agent has died but still answers ICMP is
        # reachable and broken; `unreachable_ping_only` keeps it out of
        # device_down, so this is the event `snmp_failing_ping_ok` watches.
        #
        # Gated on `snmp_fail_alert_after` CONSECUTIVE qualifying failures,
        # not the first one — a single missed poll is not "SNMP failing",
        # and alerting on it would open snmp_failing_ping_ok on any blip.
        # Counted in memory, per device, the same shape as _auth_failing
        # above, and reset the moment SNMP succeeds again. Once the
        # threshold is reached the event keeps recording on EVERY qualifying
        # poll after that, not just the one that crossed it — the rule
        # carries `auto_resolve_after_s`, measured from the alert's last
        # occurrence, so the repeats are what keep it open while the agent
        # stays dead and their stopping is what lets it clear. A transition
        # would freeze `last_ts` and announce a false all-clear an hour
        # later.
        # A refused object is excluded the way unsupported is: "SNMP is not
        # answering" is untrue of an agent that verified the message and
        # answered it, and the access_denied event above is its report. So
        # is a downgrade, for the same reason — the agent answered every
        # request — and the snmp_downgrade event above is its report.
        snmp_failing_now = (not auth_failing and snmp_ok is False and ping_ok
                            and not snmp_unsupported and not snmp_denied
                            and not snmp_downgraded)
        with self._lock:
            if snmp_failing_now:
                fail_count = self._snmp_failing_count.get(device_id, 0) + 1
                self._snmp_failing_count[device_id] = fail_count
            else:
                # Consecutive means consecutive: any poll that does not
                # qualify — SNMP answered, ping also down (that is a device
                # outage, not a dead agent), an auth failure — starts the
                # count over rather than pausing it.
                fail_count = 0
                self._snmp_failing_count.pop(device_id, None)
        snmp_fail_alert_after = max(
            1, int(settings.get("snmp_fail_alert_after", 3) or 1))
        if snmp_failing_now and fail_count >= snmp_fail_alert_after:
            self.db.record_device_event(
                device_id, "snmp_error",
                f"SNMP is not answering but the device replies to ping: "
                f"{snmp_error}")

        # Hoisted out of the branch below: the interface block needs it too.
        # A restarted device restarted its interface counters too, and
        # counter_rate cannot tell a reset from a 32-bit wrap. One poll's
        # rates are dropped; the counters are still stored, so the next poll
        # measures against the post-reboot baseline.
        rebooted = False
        if uptime_ticks is not None:
            rebooted, note = detect_reboot(
                uptime_ticks, now, previous["last_uptime_ticks"],
                previous["last_uptime_ts"] or now)
            if rebooted:
                self.db.record_device_event(device_id, "rebooted", note)

        walk_pending = bool(
            snmp_ok and identity and settings.get("vendor_walk_enabled", True)
            and config.get("snmp_enabled", True)
            and self._identification_due(previous, identity.get("sys_object_id") or "", now))
        self._check_vendor_mib(device_id, previous, identity, defer_assignment=walk_pending)
        if walk_pending:
            self._maybe_identify(device_id, identity, config, settings)

        # ----------------------------------------------------- interfaces

        if interfaces:
            # Captured before replace_interfaces() overwrites descr/alias/
            # admin_status/oper_status — comparing against a post-replace
            # read would always compare the new value to itself and never
            # detect a link_up/link_down transition.
            existing = {row["if_index"]: row for row in self.db.interfaces(device_id)}
            # T2 — the interface table. Its `ids` map replaces one
            # interface_id_for() SELECT per port below.
            result = self.db.replace_interfaces(
                device_id, interfaces, allow_delete=interfaces_complete)
            interface_ids = result["ids"]
            rate_rows: list[dict] = []
            # The device-level worst case of each per-interface rate. The
            # six shipped if_*_high threshold rules all read a metric with
            # no interface suffix, and "the worst port on this box" is what
            # a device-level rule can usefully mean.
            worst: dict[str, float] = {}
            for row in interfaces:
                if_index = row["if_index"]
                prior = existing.get(if_index)
                # This row's own GET timestamp, not the poll-start `now`:
                # the rate's dt has to match when the counters were actually
                # read (see the comment in _poll_interfaces). Metric samples
                # recorded below still use `now`, aligned with the rest of
                # this poll.
                sample_ts = row.get("_sample_ts") or now
                in_bps = out_bps = in_err_rate = out_err_rate = None
                in_disc_rate = out_disc_rate = None
                # ifCounterDiscontinuityTime: the agent saying this port's
                # counters restarted. A rate across that is fiction for
                # exactly the same reason a rate across a reboot is.
                discontinuity = row.get("discontinuity_ts")
                broke = (discontinuity is not None and prior is not None
                         and prior["discontinuity_ts"] is not None
                         and discontinuity != prior["discontinuity_ts"])
                if prior is not None and not rebooted and not broke:
                    since = prior["last_sample_ts"] or 0
                    # in_bits/out_bits track ifHCIn/OutOctets independently
                    # (see _poll_interfaces) because a device can answer
                    # one 64-bit ifXTable counter for a row without
                    # answering the other: applying one combined width to
                    # both counters would treat a genuinely 32-bit
                    # fallback as 64-bit and drop its wrapped sample.
                    in_bits = row.get("_in_octet_bits", 32)
                    out_bits = row.get("_out_octet_bits", 32)
                    in_bps = counter_rate(
                        prior["last_in_octets"], since, row.get("in_octets"),
                        sample_ts, in_bits, speed_bps=row.get("speed_bps"))
                    out_bps = counter_rate(
                        prior["last_out_octets"], since, row.get("out_octets"),
                        sample_ts, out_bits, speed_bps=row.get("speed_bps"))
                    # ifInErrors/ifOutErrors and ifInDiscards/ifOutDiscards
                    # are 32-bit counters; the rate is events per second
                    # between polls.
                    in_err_rate = counter_rate(
                        prior["last_in_errors"], since, row.get("in_errors"),
                        sample_ts, 32)
                    out_err_rate = counter_rate(
                        prior["last_out_errors"], since, row.get("out_errors"),
                        sample_ts, 32)
                    in_disc_rate = counter_rate(
                        prior["last_in_discards"], since, row.get("in_discards"),
                        sample_ts, 32)
                    out_disc_rate = counter_rate(
                        prior["last_out_discards"], since, row.get("out_discards"),
                        sample_ts, 32)
                speed_bps = row.get("speed_bps")
                # counter_rate already refuses any rate implying more than
                # 1.3x speed_bps (treating that as a reset rather than a
                # real burst), so a raw util here tops out around 130%,
                # not unbounded -- still above 100%, which is not a real
                # utilization. Clamped into [0, 100] for the same reason
                # the rate itself is bounded: a number a dashboard or
                # alert rule can trust.
                in_util = (max(0.0, min(100.0, 100.0 * in_bps * 8 / speed_bps))
                           if in_bps is not None and speed_bps else None)
                out_util = (max(0.0, min(100.0, 100.0 * out_bps * 8 / speed_bps))
                            if out_bps is not None and speed_bps else None)
                rate_rows.append({
                    "if_index": if_index, "in_octets": row.get("in_octets"),
                    "out_octets": row.get("out_octets"),
                    "in_errors": row.get("in_errors"),
                    "out_errors": row.get("out_errors"),
                    "in_discards": row.get("in_discards"),
                    "out_discards": row.get("out_discards"),
                    "in_bps": in_bps, "out_bps": out_bps,
                    "in_error_rate": in_err_rate, "out_error_rate": out_err_rate,
                    "in_discard_rate": in_disc_rate,
                    "out_discard_rate": out_disc_rate,
                    "discontinuity_ts": discontinuity,
                    "ts": sample_ts})
                interface_id = interface_ids.get(if_index)
                # Suppressed only when `rebooted` AND _interface_reassigned
                # says the port at this ifIndex really changed: some
                # platforms renumber ifIndex across a reload, and comparing
                # oper_status across a renumbering fabricates a link event.
                # A reboot alone is not evidence of renumbering, though, and
                # a missed link_down is far worse than an occasional
                # fabricated one -- so the comparison still runs whenever
                # the prior and current rows agree, or cannot be told apart.
                if (interface_id is not None and prior is not None
                        and not (rebooted and _interface_reassigned(prior, row))):
                    if prior["oper_status"] and prior["oper_status"] != row.get("oper_status"):
                        kind = "link_up" if row.get("oper_status") == "up" else "link_down"
                        if row.get("oper_status") in ("up", "down"):
                            self.db.record_interface_event(
                                interface_id, kind,
                                f"{row.get('descr') or if_index}: {prior['oper_status']} -> {row.get('oper_status')}")
                if interface_id is not None:
                    label = row.get("descr") or f"if{if_index}"
                    for suffix, unit, value in _INTERFACE_METRICS(
                            in_bps, out_bps, in_err_rate, out_err_rate,
                            in_disc_rate, out_disc_rate, in_util, out_util):
                        if value is None:
                            continue
                        samples.append((f"if_{suffix}.{if_index}",
                                        f"{label} {suffix}", unit, "gauge",
                                        now, value))
                        if suffix in _DEVICE_MAX_KEYS:
                            worst[suffix] = max(worst.get(suffix, value), value)
            for suffix, value in worst.items():
                unit, label = _DEVICE_MAX_KEYS[suffix]
                samples.append((f"if_{suffix}", label, unit, "gauge", now, value))
            # T3 — every interface's counters and rates.
            self.db.update_interface_rates(device_id, rate_rows)

        samples.extend((key, label, unit, kind, now, value)
                       for key, label, unit, kind, value in metrics)
        # T4 — every sample this poll produced, in one transaction.
        self.db.record_metric_samples(device_id, samples)

        # ---------------------------------------- PoE / STP / environment
        #
        # After the interface rows above are written, not before: PoE and
        # STP write per-port columns keyed by (device_id, if_index), and a
        # row that does not exist yet updates nothing. Each of the three
        # gets its own try, so a device that fails one keeps the others.
        if snmp_ok and config.get("snmp_enabled"):
            if config.get("poe_enabled", True):
                try:
                    self._poll_poe(device_id, device, cred_config)
                except SnmpError:
                    pass
                except Exception:
                    self._bump("errors")
                    self.log.add(ERROR, f"PoE read failed for device #{device_id}",
                                 detail=traceback.format_exc())
            if config.get("stp_enabled", True):
                try:
                    self._poll_stp(device_id, device, cred_config)
                except SnmpError:
                    pass
                except Exception:
                    self._bump("errors")
                    self.log.add(ERROR, f"STP read failed for device #{device_id}",
                                 detail=traceback.format_exc())
            try:
                self._poll_environment(device_id, device, cred_config,
                                       {m[0] for m in metrics}, now)
            except SnmpError:
                pass
            except Exception:
                self._bump("errors")
                self.log.add(ERROR, f"Environmental sensor read failed for "
                                    f"device #{device_id}",
                             detail=traceback.format_exc())

    def working_config(self, device) -> dict:
        """The config an *on-demand* read should use — effective_config()
        merged with the credential this device actually answers on.

        effective_config() resolves a device's overrides over its profile's
        PRIMARY credential and nothing else. A profile can carry alternates
        (group_credentials, for a mixed-vendor subnet) and the poller caches
        whichever one works in self._credentials, so an on-demand read built
        straight from effective_config() would query a device answering on
        an alternate with the wrong community: every read a timeout, on a
        device the poller shows as up.

        One candidate (the overwhelmingly common case, and any device with
        its own credential override) costs nothing extra: it *is*
        effective_config. With alternates, the poller's cached winner is
        trusted; only a device the poller has not resolved yet is probed
        here, one cheap GET per candidate, and the winner is cached the same
        way the poll path caches it.
        """
        config = self.db.effective_config(device)
        candidates = self.db.credential_candidates(device)
        if len(candidates) <= 1:
            return config
        cached = self._credentials.get(device["id"])
        if cached is not None and cached < len(candidates):
            return {**config, **candidates[cached]}
        # A probe that just failed is not worth repeating for every read: the
        # interface dialog alone fires two (MAC table and DOM sensors), and an
        # unreachable device would pay the whole candidate sweep for each.
        failed_at = self._credential_probe_failed.get(device["id"], 0.0)
        if time.time() - failed_at < self._PROBE_RETRY_S:
            return config
        # retries=0, and a budget across the whole sweep: the probe only asks
        # "does this credential answer at all", and the real read that follows
        # still gets the device's full configured timeout and retries. With
        # them, an unreachable device with a few alternates took
        # candidates x timeout x (retries+1) — half a minute of a request a
        # human is waiting on, for a device that is simply down.
        deadline = time.time() + self._PROBE_BUDGET_S
        for index, candidate in enumerate(candidates):
            if time.time() > deadline:
                break
            trial = {**config, **candidate, "snmp_retries": 0}
            try:
                self._snmp_get(device, trial,
                               [nodeoids.SYSTEM_SCALARS["sys_object_id"]])
            except SnmpError as exc:
                if _credential_contradicted(exc):
                    break        # see _poll_snmp_scalars_with_credential
                continue
            self._credentials[device["id"]] = index
            # The winning credential is returned with the device's own retry
            # setting restored — only the probe went without them.
            return {**config, **candidate}
        self._credential_probe_failed[device["id"]] = time.time()
        return config

    def _snmp_get(self, device, config: dict, oids: list[str]) -> Response:
        """One GET round trip against a device, handling v1/v2c/v3 (at
        whichever USM level the credential implies) transparently."""
        version = snmp_version_of(config)
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity = credential_for(config).identity
                request_id = session.next_request_id()
                packet = build_request(version, identity or "public", PDU_GET,
                                       request_id, oids)
                response = session.request(packet, request_id)
                self._check_error_status(response, config, oids)
                return response

            response = self._v3_exchange(session, device, config, PDU_GET, oids)
            self._check_error_status(response, config, oids)
            return response
        finally:
            session.close()

    def _v3_exchange(self, session: _Session, device, config: dict, pdu_tag: int,
                     oids: list[str], max_repetitions: int = 0) -> Response:
        """The poller's side of the module-level v3_exchange: the engine
        cache. Every v3 caller once went through its own copy of "build
        the message, send it, and if a Report comes back give up" — so a
        device whose engineBoots had incremented (a restart) failed every
        poll until something else invalidated the cache, and the operator
        was told only "engine resync required". The resync loop itself now
        lives in v3_exchange, shared with the Test button; what is left
        here is feeding it the cached engine parameters, keeping the ones
        a Report teaches, and dropping the entry when even the retry was
        refused, so the next poll rediscovers from nothing."""
        credential = credential_for(config)
        device_id = device["id"]

        def learned(engine_id: bytes, boots: int, engine_time: int) -> None:
            self._engines.set(device_id, engine_id, boots, engine_time)

        try:
            return v3_exchange(
                session, pdu_tag, oids, identity=credential.identity,
                auth_proto=credential.auth_proto, password=credential.auth_password,
                engine=self._engines.current(device_id),
                max_repetitions=max_repetitions, ip=device["ip"], learned=learned,
                priv_proto=credential.priv_proto,
                priv_password=credential.priv_password,
                verify_replies=self._verify_replies)
        except _AuthFailure:
            self._engines.invalidate(device_id)
            raise
        finally:
            credential = None

    def _check_error_status(self, response: Response, config: dict,
                            oids: list[str]) -> None:
        """authorizationError(16) on a GET, raised with the object named and
        the credential's own explanation (access_denied_reason). Every
        other error-status is left in the Response for the caller to
        interpret, as it always was — noSuchName on one OID in a batch does
        not make the whole reply worthless. An instance method rather than
        the staticmethod it was, because a useful message needs `config`
        (which credential, at what level) and the request's OID list (what
        error-index counts into), and both callers are in _snmp_get with
        both in hand."""
        if response.error_status == 16:   # authorizationError
            raise SnmpAccessDenied(access_denied_reason(
                config, response, oids, security_level(config)))

    def _poll_snmp_scalars_with_credential(self, device, config: dict):
        """Resolves which SNMP credential actually works for this device
        this poll, then fetches the system scalars with it — one function,
        so a working credential is never fetched twice. Tries the cached
        last-known-good candidate (from self._credentials) first; on a
        cache miss, or if that candidate no longer works, walks the full
        candidate list from db.credential_candidates() in order. Every
        failure mode is credential-specific in a mixed profile — a v3
        authPriv alternate raises SnmpUnsupported on a host whose
        `cryptography` backend does not work, while a v2c alternate right
        after it works — so every SnmpError subclass is caught and the
        sweep goes on, with two exceptions.

        A failure that CONTRADICTS the credential does not rotate. A digest
        that did not verify, a reply that would not decrypt, or an unsigned
        answer to a signed request is this end refusing what came back,
        not the device refusing the request — and it is exactly what one
        forged datagram looks like. Rotating on it would let that datagram
        walk the poller off a verified v3 credential and onto the cleartext
        v1/v2c community further down the list, which is a downgrade an
        attacker can ask for. Only a refusal the DEVICE named (a Report,
        an authorizationError, a level it does not serve, silence) is
        worth trying the next candidate on.

        And once every candidate has failed, the MOST SPECIFIC error is
        re-raised, not the last. A profile whose v3 primary is refused by
        name and whose v2c alternate the device simply ignores used to
        show whichever came last — the alternate's "no reply" — and hide
        the one message that named the fault; a sweep that ends in a
        timeout after a named refusal is still that refusal. Among equals
        the later one still wins, as before.
        Returns (winning_config, identity, uptime_ticks, metrics)."""
        device_id = device["id"]
        candidates = self.db.credential_candidates(device)
        cached_index = self._credentials.get(device_id)
        order = [cached_index] if cached_index is not None and cached_index < len(candidates) else []
        order += [i for i in range(len(candidates)) if i not in order]
        # A device that is simply down does not need its whole credential
        # list re-tried on every poll: four candidates at 3 s and two
        # retries is 36 s of a worker per poll, per down device. After a
        # sweep has failed, only the last-known-good candidate (or the
        # first, if there is none) is tried until the retry window passes —
        # the same negative caching the on-demand path in working_config
        # has always had.
        failed_at = self._credential_probe_failed.get(device_id, 0.0)
        if len(order) > 1 and time.time() - failed_at < self._PROBE_RETRY_S:
            order = order[:1]
        last_error: Exception | None = None
        for index in order:
            trial_config = {**config, **candidates[index]}
            try:
                identity, uptime_ticks, metrics = self._poll_snmp_scalars(device, trial_config)
            except SnmpError as exc:
                if _credential_contradicted(exc):
                    raise
                if last_error is None or \
                        _error_specificity(exc) >= _error_specificity(last_error):
                    last_error = exc
                continue
            self._credentials[device_id] = index
            self._credential_probe_failed.pop(device_id, None)
            return trial_config, identity, uptime_ticks, metrics
        if len(candidates) > 1:
            self._credential_probe_failed[device_id] = time.time()
        raise last_error or SnmpTimeout(f"no reply from {device['ip']}")

    def _identity_extras(self, device, config: dict, oids: list[str]) -> dict:
        """Answers to identity OIDs read in a GET of their own, best-effort.

        Separate from the scalar GET so that an object the device does not
        implement can cost nothing but this request — on SNMPv1 an
        unimplemented object in a request spoils every answer in it, and
        identity is the one thing that must not be lost that way. Failure is
        silent for the same reason the UCD-SNMP read below is: not answering
        is the normal case, not an error.
        """
        if not oids:
            return {}
        try:
            response = self._snmp_get(device, config, oids)
        except SnmpError:
            return {}
        return {vb["oid"]: vb["value"] for vb in response.varbinds
                if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                      "endOfMibView")}

    def _poll_snmp_scalars(self, device, config: dict):
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        # An operator-chosen OID for vendor and/or location. Both the bare and
        # the .0 instance form are asked for, because "1.3.6.1.4.1.x.y" and
        # "…y.0" are both reasonable things to type and only one of them
        # answers; whichever does is used. See nodeoids.identity_oid_variants.
        #
        # On v2c and v3 they ride in the SAME GET as the standard scalars,
        # for no extra round trip: an unimplemented object comes back as a
        # per-varbind noSuchObject and the rest of the response is unharmed.
        # SNMPv1 has no such thing — it answers noSuchName with the whole
        # varbind list echoed back as nulls, which would blank sysDescr,
        # sysObjectID, sysName and sysLocation on every v1 device with a
        # custom identity OID set. By construction at least one of the two
        # forms cannot answer, so on v1 they are read separately and
        # best-effort. Note the missing `or 1`: that fallback turns a
        # configured 0 (v1) into 1 (v2c) and would make this branch
        # unreachable for exactly the devices it protects.
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        custom = nodeoids.identity_oid_variants(config)
        if custom["all"] and not is_v1:
            oids += [oid for oid in custom["all"] if oid not in oids]
        response = self._snmp_get(device, config, oids)
        values = {vb["oid"]: vb["value"] for vb in response.varbinds
                  if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                        "endOfMibView")}
        if custom["all"] and is_v1:
            values.update(self._identity_extras(device, config, custom["all"]))
        identity = {
            "sys_descr": values.get(nodeoids.SYSTEM_SCALARS["sys_descr"]) or "",
            "sys_object_id": values.get(nodeoids.SYSTEM_SCALARS["sys_object_id"]) or "",
            "sys_name": values.get(nodeoids.SYSTEM_SCALARS["sys_name"]) or "",
            "sys_contact": values.get(nodeoids.SYSTEM_SCALARS["sys_contact"]) or "",
            "sys_location": values.get(nodeoids.SYSTEM_SCALARS["sys_location"]) or "",
        }
        # The zero-SNMP half of vendor identification, every poll: a manual
        # or learned vendor, a real vendor arc in sysObjectID, the walk this
        # device already had for this sysObjectID, then the sysDescr guess.
        # See vendorid.poll_decision for the order and why.
        detected, source, confidence, vendor_arc = vendorid.poll_decision(
            identity["sys_object_id"], identity["sys_descr"], device,
            self.db.learned_vendor(identity["sys_object_id"]))
        # Always stored, always what the behavioural readers use — a custom
        # vendor name replaces the display value only (see
        # nodesdb.detected_vendor).
        identity["vendor_detected"] = detected
        identity["vendor"], identity["vendor_source"] = detected, source
        identity["vendor_confidence"] = confidence
        identity["vendor_arc"] = vendor_arc

        custom_vendor = nodeoids.first_text(values, custom["vendor"])
        if custom_vendor:
            identity["vendor"] = custom_vendor
            identity["vendor_source"] = "oid"
        custom_location = nodeoids.first_text(values, custom["location"])
        if custom_location:
            identity["sys_location"] = custom_location

        uptime = values.get(nodeoids.SYSTEM_SCALARS["sys_uptime"])
        uptime_ticks = int(uptime) if isinstance(uptime, (int, float)) else None

        metrics = []
        try:
            extra_response = self._snmp_get(device, config, list(nodeoids.UCD_SNMP.values()))
            extra = {vb["oid"]: vb["value"] for vb in extra_response.varbinds
                     if vb["type"] not in ("noSuchObject", "noSuchInstance")}
            idle = extra.get(nodeoids.UCD_SNMP["cpu_raw_idle"])
            if isinstance(idle, (int, float)):
                metrics.append(("cpu_pct", "CPU", "%", "gauge", max(0.0, 100.0 - float(idle))))
            avail = extra.get(nodeoids.UCD_SNMP["mem_avail_kb"])
            total = extra.get(nodeoids.UCD_SNMP["mem_total_kb"])
            if isinstance(avail, (int, float)) and isinstance(total, (int, float)) and total:
                metrics.append(("mem_pct", "Memory", "%", "gauge",
                               max(0.0, 100.0 * (1 - float(avail) / float(total)))))
        except SnmpError:
            pass   # best-effort: UCD-SNMP-MIB not present on this device

        metrics.extend(self._poll_vendor_health(device, config, identity,
                                                already={m[0] for m in metrics}))
        # UPS-MIB: battery/output health for anything wired to a UPS that
        # answers SNMP. Not arc-gated the way _poll_vendor_health is — see
        # nodeoids.UPS_HEALTH's module comment for why — so it is read here,
        # best-effort, on every device exactly like the UCD-SNMP block
        # above rather than folded into _poll_vendor_health's per-arc loop.
        metrics.extend(self._poll_ups_health(device, config, identity,
                                             already={m[0] for m in metrics}))
        # RSSI/SNR/capacity for a PtP wireless bridge — the same
        # arc-gated, best-effort scalar shape _poll_vendor_health uses just
        # above, kept as its own method because RF is not "health" and has
        # its own OID table (nodeoids.RF_METRICS).
        metrics.extend(self._poll_rf_metrics(device, config, identity))
        return identity, uptime_ticks, metrics

    # How often a device's ipAddrTable is re-read. Its addresses change when
    # somebody reconfigures it, not between polls, and the walk exists to
    # correlate traps and syslog rather than to chart anything — so once an
    # hour, not on the poll cycle.
    _ADDRESS_REFRESH_S = 3600.0

    def _health_column(self, device, config: dict, oid: str, how: str):
        """One vendor table column, reduced to a single number.

        Best-effort throughout: a device that does not implement the column
        answers nothing and contributes nothing, exactly like the UCD-SNMP
        read above. Errors are swallowed for the same reason — not
        answering a vendor object is the normal case, not a poll failure.
        """
        try:
            values = self._walk_column(device, config, oid)
        except SnmpError:
            return None
        numbers = [float(value) for value in values.values()
                   if isinstance(value, (int, float))]
        if not numbers:
            return None
        if how == "column_max":
            return max(numbers)
        if how == "column_avg":
            return sum(numbers) / len(numbers)
        return numbers[0]

    def _cisco_memory_pct(self, device, config: dict):
        """Cisco reports memory as used and free bytes per pool rather than
        as a percentage. Pools are summed: a router with a processor pool
        and an I/O pool has one memory figure, not two."""
        try:
            used = self._walk_column(device, config, nodeoids.CISCO_MEMORY_USED)
            free = self._walk_column(device, config, nodeoids.CISCO_MEMORY_FREE)
        except SnmpError:
            return None
        used_total = sum(float(v) for v in used.values()
                         if isinstance(v, (int, float)))
        free_total = sum(float(v) for v in free.values()
                         if isinstance(v, (int, float)))
        total = used_total + free_total
        if total <= 0:
            return None
        return 100.0 * used_total / total

    def _host_resources_storage_rows(self, device, config: dict) -> tuple:
        """(types, sizes, used) — hrStorageType/Size/Used, walked ONCE and
        shared by every reader of hrStorageTable (today: disk_pct's worst
        fixed disk and mem_pct's HOST-RESOURCES fallback), so a device that
        needs both pays for this table exactly once per poll rather than
        once per kind of row somebody wants out of it. All three empty
        dicts on a device with no HOST-RESOURCES-MIB support at all, or on
        any SnmpError — best-effort, same as everything else this reads."""
        try:
            types = self._walk_column(device, config, nodeoids.HR_STORAGE_TYPE)
            if not types:
                return {}, {}, {}
            sizes = self._walk_column(device, config, nodeoids.HR_STORAGE_SIZE)
            used = self._walk_column(device, config, nodeoids.HR_STORAGE_USED)
        except SnmpError:
            return {}, {}, {}
        return types, sizes, used

    @staticmethod
    def _worst_storage_pct(types: dict, sizes: dict, used: dict,
                           wanted_type: str) -> float | None:
        """The fullest hrStorageTable row of one hrStorageType, as a
        percentage — disk_pct and mem_pct are the same computation over a
        different type. No allocation-unit scaling: a used/size ratio does
        not need it."""
        worst = None
        for index, kind in types.items():
            if str(kind).strip(".") != wanted_type:
                continue
            size = sizes.get(index)
            taken = used.get(index)
            if not isinstance(size, (int, float)) or not isinstance(taken, (int, float)):
                continue
            if size <= 0:
                continue
            pct = 100.0 * float(taken) / float(size)
            worst = pct if worst is None else max(worst, pct)
        return worst

    def _host_resources_disk_pct(self, types: dict, sizes: dict, used: dict):
        """The busiest fixed disk, as a percentage, from an already-walked
        hrStorageTable (see _host_resources_storage_rows).

        hrStorageTable also holds RAM and virtual memory rows; reporting
        those as disk would make a machine using its page cache look full.
        Only hrStorageFixedDisk rows count, and the fullest of them is what
        an operator means by "the disk is filling up"."""
        return self._worst_storage_pct(types, sizes, used,
                                       nodeoids.HR_STORAGE_FIXED_DISK)

    def _host_resources_mem_pct(self, types: dict, sizes: dict, used: dict):
        """Physical memory as a percentage, from the same already-walked
        hrStorageTable _host_resources_disk_pct reads — the HOST-RESOURCES
        fallback for mem_pct, tried only when UCD-SNMP, the Fortinet scalar
        and the Cisco memory pool all failed to answer.

        hrStorageRam only: hrStorageVirtualMemory (swap) sits under a
        different type and is never counted, because a machine with an
        ordinary swap file would otherwise read as critically low on RAM.
        """
        return self._worst_storage_pct(types, sizes, used, nodeoids.HR_STORAGE_RAM)

    def _refresh_addresses(self, device, config: dict) -> None:
        """Remember every address this device answers on.

        A switch sends its traps from a loopback and its syslog from a
        management VRF, and neither address is in the devices table, so the
        alert engine could not tell whose message it was. ipAddrTable says
        which addresses are the device's own. Walked at most once an hour
        per device — see _ADDRESS_REFRESH_S."""
        device_id = device["id"]
        now = time.time()
        if now - self._addresses_read.get(device_id, 0.0) < self._ADDRESS_REFRESH_S:
            return
        self._addresses_read[device_id] = now
        try:
            rows = self._walk_column(device, config, nodeoids.IP_ADDR_TABLE)
        except SnmpError:
            return
        # Joined on the index suffix (the address, for ipAddrTable); each
        # is its own best-effort walk so a partial answer still records.
        details = {}
        for oid, key in ((nodeoids.IP_ADDR_IFINDEX, "if_index"),
                         (nodeoids.IP_ADDR_NETMASK, "netmask")):
            try:
                extra = self._walk_column(device, config, oid)
            except SnmpError:
                continue
            for suffix, value in extra.items():
                if value is None or value == "":
                    continue
                # Must match record_device_addresses' folded lookup key.
                address = nodesdb.alias_candidate(rows.get(suffix) or suffix)
                if not address:
                    continue
                try:
                    entry = int(value) if key == "if_index" else str(value)
                except (TypeError, ValueError):
                    continue
                details.setdefault(address, {})[key] = entry
        addresses = [str(value) for value in rows.values() if value]
        if addresses:
            self.db.record_device_addresses(device_id, addresses, "ipAddrTable",
                                            details=details)

    def _poll_vendor_health(self, device, config: dict, identity: dict,
                            already=()) -> list[tuple]:
        """CPU, memory, disk, temperature and session count for real network
        gear, keyed on the vendor arc SNMP identification worked out.

        Everything here is best-effort and additive: the thresholds are
        unchanged, so a device that starts answering cpu_pct can now open
        `cpu_high` where it previously reported nothing at all. Only the
        objects the device's own maker defines are asked for; the
        HOST-RESOURCES fallback runs only when neither the vendor table nor
        UCD-SNMP produced a figure, so a net-snmp box costs nothing extra.
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc(
                (identity or {}).get("sys_object_id") or "")
        metrics: list[tuple] = []
        # `already` is what the UCD-SNMP read produced. A vendor's own
        # object beats it — a FortiGate that also answers UCD-SNMP is still
        # better described by fgSysCpuUsage — so the vendor probes below
        # ignore it and record_metric_samples keeps the last value per key.
        # Only the generic HOST-RESOURCES fallback respects it, so a
        # net-snmp box costs no extra requests at all.
        produced: set = set()

        def add(key, label, unit, value):
            if value is None or key in produced:
                return
            produced.add(key)
            metrics.append((key, label, unit, "gauge", float(value)))

        probes = nodeoids.VENDOR_HEALTH.get(arc, ())
        scalars = [probe for probe in probes if probe[4] == "scalar"]
        if scalars:
            try:
                response = self._snmp_get(device, config,
                                          [probe[3] for probe in scalars])
                values = {vb["oid"]: vb for vb in response.varbinds}
            except SnmpError:
                values = {}
            for key, label, unit, oid, _how in scalars:
                vb = values.get(oid)
                if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                             "endOfMibView", "null") \
                        and isinstance(vb["value"], (int, float)):
                    add(key, label, unit, vb["value"])
        for key, label, unit, oid, how in probes:
            if how == "scalar" or key in produced:
                continue
            add(key, label, unit, self._health_column(device, config, oid, how))
        if arc == 9:
            add("mem_pct", "Memory", "%",
                self._cisco_memory_pct(device, config))
        known = produced | set(already)
        if "cpu_pct" not in known:
            for key, label, unit, oid, how in nodeoids.GENERIC_HEALTH:
                add(key, label, unit,
                    self._health_column(device, config, oid, how))
        # hrStorageTable answers BOTH disk_pct's and mem_pct's HOST-RESOURCES
        # fallback, so it is walked once and only when at least one of the two
        # is still missing.
        if "disk_pct" not in known or "mem_pct" not in known:
            types, sizes, used = self._host_resources_storage_rows(device, config)
            if types:
                if "disk_pct" not in known:
                    add("disk_pct", "Storage", "%",
                        self._host_resources_disk_pct(types, sizes, used))
                if "mem_pct" not in known:
                    add("mem_pct", "Memory", "%",
                        self._host_resources_mem_pct(types, sizes, used))
        self._refresh_addresses(device, config)
        return metrics

    def _poll_rf_metrics(self, device, config: dict, identity: dict) -> list[tuple]:
        """RSSI/SNR/link-capacity for a point-to-point wireless bridge,
        gated on the vendor arc this poll's identity already worked out:
        RF_METRICS has no entry for anything that is not a radio, so the
        GET below never costs a packet against a device it does not apply
        to.
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
        probes = nodeoids.RF_METRICS.get(arc, ())
        if not probes:
            return []
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in probes])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            return []
        metrics = []
        for key, label, unit, oid, _how in probes:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                metrics.append((key, label, unit, "gauge", float(vb["value"])))
        if metrics:
            self._bump("rf_polls")
        return metrics

    def _poll_ups_health(self, device, config: dict, identity: dict,
                         already=()) -> list[tuple]:
        """UPS-MIB (RFC 1628) battery/output health.

        Tried on EVERY device, not gated by enterprise arc the way
        VENDOR_HEALTH is — see nodeoids.UPS_HEALTH's module comment for
        why keying this to a vendor list would not work for a UPS the way
        it does for a switch or router.

        Cost is bounded twice. Within a poll: one GET of every scalar in
        the table, and the two per-line table walks only once that GET
        shows a scalar answered. Across polls: devices.ups_capable is the
        probe-once-remember memory _poll_poe/_poll_stp use, so a confirmed
        not-a-UPS is skipped entirely rather than paying that GET forever.
        Recorded only on the FIRST probe (capable is None) — a UPS that
        times out one poll must not be relabelled incapable.
        """
        metrics: list[tuple] = []
        capable = device["ups_capable"]
        if capable == 0:
            return metrics
        scalars = [probe for probe in nodeoids.UPS_HEALTH if probe[4] == "scalar"]
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in scalars])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            # No answer at all, same as every scalar coming back
            # noSuchObject — folded into the `answered = False` path below
            # (same as _poll_poe/_poll_stp do for their own tables) so an
            # outright timeout on the first-ever probe still gets recorded
            # rather than silently retried forever.
            values = {}
        answered = False
        for key, label, unit, oid, _how, scale in scalars:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                answered = True
                if key not in already:
                    metrics.append((key, label, unit, "gauge",
                                    float(vb["value"]) * scale))
        if not answered:
            # Nothing in the scalar batch answered: not a UPS (or a UPS
            # that does not implement UPS-MIB at all), so the two column
            # walks below are skipped rather than sent to every non-UPS
            # device in the fleet on every poll.
            if capable is None:
                self.db.set_ups_capable(device["id"], False)
            return metrics
        if capable is None:
            self.db.set_ups_capable(device["id"], True)
        for key, label, unit, oid, how, scale in nodeoids.UPS_HEALTH:
            if how == "scalar" or key in already:
                continue
            value = self._health_column(device, config, oid, how)
            if value is not None:
                metrics.append((key, label, unit, "gauge", value * scale))
        if "ups_runtime_min" not in already and \
                not any(m[0] == "ups_runtime_min" for m in metrics):
            arc = identity.get("vendor_arc") if identity else None
            if arc is None:
                arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
            if arc == 318:   # APC / Schneider
                runtime = self._apc_runtime_fallback(device, config)
                if runtime is not None:
                    metrics.append(("ups_runtime_min", "Estimated runtime remaining",
                                    "min", "gauge", runtime))
        return metrics

    def _apc_runtime_fallback(self, device, config: dict) -> float | None:
        """APC PowerNet-MIB's upsAdvBatteryRunTimeRemaining, in TimeTicks
        (hundredths of a second), converted to minutes — read only when
        the standard upsEstimatedMinutesRemaining scalar did not answer.
        See nodeoids.APC_BATTERY_RUNTIME_TIMETICKS for why this one
        fallback, alone among everything else this module reads, is not
        cross-checked against a live unit."""
        try:
            response = self._snmp_get(
                device, config, [nodeoids.APC_BATTERY_RUNTIME_TIMETICKS])
        except SnmpError:
            return None
        for vb in response.varbinds:
            if vb["oid"] == nodeoids.APC_BATTERY_RUNTIME_TIMETICKS \
                    and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                           "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                return float(vb["value"]) / 100.0 / 60.0
        return None

    def _check_vendor_mib(self, device_id: int, previous, identity: dict | None,
                          defer_assignment: bool = False) -> None:
        """Says so when a device's vendor is identified but no uploaded MIB
        describes that vendor's objects, so an admin knows there is a MIB to
        add rather than wondering why the metrics never appear.

        Coverage is re-evaluated every poll and compared against the
        persisted verdict (devices.mib_covered), with events on transitions
        only — keying off sysObjectID changes instead would make the feature
        inert for every device whose identity was already stored, and could
        neither clear on a later upload nor re-fire on a deletion.
        mib_present pairs with mib_missing in alertrules.CLEARS, so the
        upload auto-resolves the alert."""
        if not identity:
            return
        sys_object_id = identity.get("sys_object_id") or ""
        # The vendor that was *detected* (never the display value a custom
        # OID may have replaced), and the arc it was decided from: the
        # sysObjectID's own for a real vendor arc, the walk's for a
        # generic-agent device. Coverage is asked about THAT arc — a
        # net-snmp box identified as Phoenix Contact by the walk needs the
        # Phoenix MIB, and asking about arc 8072 would never say so.
        vendor = identity.get("vendor_detected") or identity.get("vendor") or ""
        vendor_arc = identity.get("vendor_arc")
        if vendor_arc is None and "vendor_arc" not in identity:
            # An older-shaped identity (tests, replays): fall back to the
            # 4.31 rule, sysObjectID's arc only.
            vendor = vendor or nodeoids.identify_vendor(
                sys_object_id, identity.get("sys_descr") or "")[0]
            vendor_arc = nodeoids.enterprise_arc(sys_object_id)
        applicable = bool(vendor) and vendor_arc is not None
        was_covered = previous["mib_covered"]      # None / 0 / 1
        if not applicable:
            # The coverage question doesn't apply (no identity yet, a
            # standard-tree sysObjectID, or no recognizable vendor); make
            # sure no stale verdict lingers from a previous identity.
            if was_covered is not None:
                self.db.set_mib_covered(device_id, None)
            return
        coverage_oid = f"{nodeoids.ENTERPRISES}.{vendor_arc}"
        covered = self.db.has_mib_covering(coverage_oid)
        # While an identification walk is still due for this device, the
        # poll path leaves assignment to it: the walk's pick is the file that
        # actually named this device's objects, and an assignment made here
        # first — by "the file with the most objects under the arc" — would
        # stand, because assignment never overrides an existing choice.
        if covered and not defer_assignment:
            self._auto_assign_mib(device_id, coverage_oid, vendor,
                                  preferred=identity.get("preferred_mib_file_id"))
        if covered and not (was_covered is None or was_covered):
            # uncovered -> covered: the MIB arrived. CLEARS resolves the
            # standing mib_missing alert off this event.
            self.db.record_device_event(
                device_id, "mib_present",
                f"An uploaded MIB now describes {vendor} objects "
                f"(enterprise arc {vendor_arc}); vendor-specific data can be decoded.")
        elif not covered and (was_covered is None or was_covered):
            # first verdict, or covered -> uncovered (a MIB was deleted).
            bundle = mibcatalog.bundle_for_arc(vendor_arc)
            hint = (f"Install the {bundle.name} bundle from the MIB catalog"
                    if bundle else f"Upload the {vendor} MIB under Nodes → Profiles & MIBs")
            self.db.record_device_event(
                device_id, "mib_missing",
                f"No uploaded MIB describes {vendor} objects (enterprise arc "
                f"{vendor_arc}). {hint} to decode this device's vendor-specific data.")
        if was_covered is None or bool(was_covered) != covered:
            self.db.set_mib_covered(device_id, covered)

    def _auto_assign_mib(self, device_id: int, sys_object_id: str,
                         vendor: str, preferred: int | None = None) -> None:
        """Point a device at its own vendor's MIB once one is present.

        Assignment happens only where the operator has expressed no
        preference — and a preference can live on the polling profile as
        well as the device: mib_file_id is an _OVERRIDE_COLUMNS entry, so a
        device-level auto-assignment layered over a group whose MIB was
        chosen by hand would BEAT that choice. Hence the effective
        (device-or-group) value is what is checked, not the device column.
        It is an ordinary override afterwards.
        """
        device = self.db.device(device_id)
        if device is None:
            return
        if self.db.effective_config(device).get("mib_file_id") is not None:
            return
        # The fingerprint's pick — the file that actually named the most of
        # what this device answered — beats "the file with the most objects
        # under the arc", which is a guess about the device from the MIB
        # alone. Only when the preferred file still exists.
        mib_file_id = preferred if preferred and self.db.mib_file(preferred) else None
        by_evidence = mib_file_id is not None
        if mib_file_id is None:
            mib_file_id = self.db.mib_file_covering(sys_object_id)
        if mib_file_id is None:
            return
        self.db.update_device(device_id, mib_file_id=mib_file_id)
        mib = self.db.mib_file(mib_file_id)
        name = (mib["module"] if mib and mib["module"] else
                (mib["filename"] if mib else str(mib_file_id)))
        why = ("the identification walk matched its objects on this device"
               if by_evidence else
               f"it describes {vendor} objects (enterprise arc "
               f"{nodeoids.enterprise_arc(sys_object_id)})")
        # Recorded, not silent: this changes what gets polled every cycle, so
        # it belongs in the device's own event history where it can be seen
        # and undone rather than being discovered from new metric names.
        self.db.record_device_event(
            device_id, "mib_assigned",
            f"Assigned the {name} MIB to this device automatically: {why} "
            f"and no MIB had been chosen. Change or clear it under this "
            f"device's Custom MIB override.")

    # ------------------------------------------------ vendor identification

    _IDENTIFY_RETRY_S = 3600.0
    _IDENTIFY_MAX_ATTEMPTS = 3

    def _getnext_one(self, device, config: dict, oid: str):
        """One GETNEXT for the arc hop: (oid, type, value), or None when the
        agent signalled the end. _snmp_get_next does not check error_status
        — a v1 agent answers a probe past its last object with noSuchName
        and the request OID echoed back, which would read as a loop — so the
        end conditions live here, where vendorid.hop_enterprise_arcs expects
        them."""
        response = self._snmp_get_next(device, config, oid)
        if getattr(response, "error_status", 0):
            return None
        if not response.varbinds:
            return None
        vb = response.varbinds[0]
        if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
            return None
        return vb["oid"], vb["type"], vb["value"]

    def _mib_index_cached(self):
        """The MIB corpus as vendorid wants it, rebuilt only when the corpus
        changed. Identification is rare, so even a rebuild per run would do;
        the cache is for a bulk Re-identify of a few hundred devices."""
        generation = self.db.mib_generation()
        with self._lock:
            cached = self._mib_index
            if cached is not None and cached[0] == generation:
                return cached[1]
        index = vendorid.build_mib_index(self.db.enterprise_objects(), self.db.mib_files())
        with self._lock:
            self._mib_index = (generation, index)
        return index

    def _identification_due(self, device, sys_object_id: str, now: float) -> bool:
        """Whether this device needs (another) identification walk: never
        identified, identified for a different sysObjectID, or the last run
        failed and it is time for one of the bounded retries. A device
        identified for its current sysObjectID returns False before any I/O
        — that is the "zero steady-state traffic" rule."""
        if device["identified_ts"] is None:
            return True
        if (device["identified_sys_object_id"] or "") != (sys_object_id or ""):
            return True
        evidence = vendorid._evidence_dict(device)
        if evidence.get("error"):
            attempts = int(evidence.get("attempts") or 0)
            last = float(evidence.get("ts") or 0)
            return attempts < self._IDENTIFY_MAX_ATTEMPTS and \
                now - last >= self._IDENTIFY_RETRY_S
        return False

    def _maybe_identify(self, device_id: int, identity, config: dict, settings) -> None:
        """Start the bounded identification walk for a device whose poll just
        succeeded, when it is due and there is room. Called from the poll
        worker but starts a separate thread; see _VendorIdJob."""
        if not identity or not settings.get("vendor_walk_enabled", True):
            return
        if not config.get("snmp_enabled", True):
            return
        device = self.db.device(device_id)
        if device is None:
            return
        if not self._identification_due(device, identity.get("sys_object_id") or "",
                                        time.time()):
            return
        limit = int(settings.get("vendor_walk_parallel", 4) or 4)
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return
            running = sum(1 for j in self._vendor_ids.values() if j.running)
            if running >= limit:
                return           # the next poll tries again; identified_ts stays NULL
            trigger = ("sysobjectid_changed" if device["identified_ts"] is not None
                       and not vendorid._evidence_dict(device).get("error")
                       else "first_poll")
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        job.start()

    def start_identify(self, device_id: int, trigger: str = "manual") -> dict:
        """Re-identify on demand: forget the previous verdict so the next
        poll would walk anyway, and start the walk now. Refused politely
        while one is already running for this device."""
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        if not self.db.effective_config(device).get("snmp_enabled", True):
            raise ValueError("SNMP is disabled for this device")
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return job.status()
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        self.db.clear_identification(device_id)
        # Sensor plausibility depends on vendor (_cisco_sensor_table_plausible),
        # so a re-identification invalidates an old "no sensors" verdict.
        self.db.set_sensor_capable(device_id, None)
        self._sensor_read.pop(device_id, None)
        self._sensor_threshold_read.pop(device_id, None)
        job.start()
        return job.status()

    def identify_status(self, device_id: int) -> dict | None:
        job = self._vendor_ids.get(device_id)
        return job.status() if job else None

    def identifying(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        return job is not None and job.running

    def cancel_identify(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def _apply_identification(self, device_id: int, decision, error: str = "") -> None:
        """After a walk: coverage and MIB assignment against the decided arc,
        and one event saying what was decided and why."""
        device = self.db.device(device_id)
        if device is None:
            return
        identity = {"sys_object_id": device["sys_object_id"] or "",
                    "sys_descr": device["sys_descr"] or "",
                    "vendor_detected": decision.vendor, "vendor": decision.vendor,
                    "vendor_arc": decision.vendor_arc,
                    "preferred_mib_file_id": decision.mib_file_id}
        self._check_vendor_mib(device_id, device, identity)
        label = decision.vendor or "unidentified"
        text = (f"{label} via {decision.source} ({decision.confidence}): {decision.reason}"
                if decision.source else f"unidentified: {decision.reason}")
        if error:
            text += f" — walk incomplete: {error}"
        self.db.record_device_event(device_id, "identified", text)

    def _poll_custom_mib(self, device, config: dict, mib_file_id: int) -> list[tuple]:
        """A device or its polling profile can be assigned one uploaded
        MIB (nodesdb's mib_file_id override); this polls that MIB's own
        resolved *scalar* objects and reports them under its own names —
        the same best-effort shape as the UCD-SNMP-MIB block above (one
        failed GET never fails the whole poll; a device that doesn't
        answer any of this MIB's objects just contributes nothing).

        mibparse stores an OBJECT-TYPE's OID as its MIB clause names it, so
        the instance to GET is that OID plus the standard ".0" — the same
        convention nodeoids.SYSTEM_SCALARS' hand-written OIDs bake in. Table
        objects are out of scope: ".0" on a table column always misses, and
        so contributes nothing rather than raising."""
        objects = [o for o in self.db.mib_objects(mib_file_id, resolved_only=True)
                  if not o["is_notification"]]
        if not objects:
            return []
        instance_oids = [f"{o['oid']}.0" for o in objects]
        metrics = []
        try:
            response = self._snmp_get(device, config, instance_oids)
            values = {vb["oid"]: vb for vb in response.varbinds}
            for obj, instance_oid in zip(objects, instance_oids):
                vb = values.get(instance_oid)
                if not vb or vb["type"] in ("noSuchObject", "noSuchInstance"):
                    continue
                if not isinstance(vb["value"], (int, float)):
                    continue   # a string/OID-valued object isn't a chartable metric
                # Always "gauge": a Counter-typed object is charted at its
                # raw value, not a rate. A rate needs a per-metric baseline
                # (see counter_rate), which an arbitrary admin-picked MIB
                # object does not get.
                metrics.append((f"mib_{obj['name']}", obj["name"], "", "gauge", vb["value"]))
        except SnmpError:
            pass   # best-effort: this MIB's objects aren't answered by this device
        return metrics

    # Without a budget, a device the walk enumerated but whose
    # per-interface GETs stop answering costs N x timeout x (retries + 1) on
    # one poll worker — over an hour for a large chassis. Half the device's
    # own poll interval, with a floor so a 3-second focus poll still reads.
    _INTERFACE_BUDGET_FRACTION = 0.5
    _INTERFACE_BUDGET_FLOOR_S = 3.0
    _INTERFACE_GIVE_UP_TIMEOUTS = 3
    _MAX_INTERFACES = 512

    def _v1_get_dropping_unknown(self, device, config: dict, oids: list,
                                 max_drops: int = 3) -> dict:
        """A GET against an SNMPv1 agent, minus the objects it does not
        implement.

        v1 has no per-varbind noSuchObject: an agent asked for one object
        it does not have answers the WHOLE request with error-status 2
        (noSuchName), error-index naming the offender, and echoes every
        varbind back as a null. The offending varbind is dropped and the
        request re-sent, up to `max_drops` times — beyond that the device
        is answering nothing useful and the interface is skipped, rather
        than the poll spending one round trip per column.
        """
        remaining = list(oids)
        for _ in range(max_drops + 1):
            if not remaining:
                return {}
            response = self._snmp_get(device, config, remaining)
            if response.error_status != 2:            # noSuchName
                return {vb["oid"]: vb for vb in response.varbinds}
            index = response.error_index
            if not 1 <= index <= len(remaining):
                return {}      # the agent will not say which: nothing to drop
            remaining.pop(index - 1)
        return {}

    def _interface_varbinds(self, device, config: dict, if_index: int,
                            is_v1: bool, want_ifx: bool) -> tuple:
        """(oid -> varbind, whether ifXTable still answers) for one
        interface.

        On v2c and v3 the IF-MIB and ifXTable columns ride in one GET: an
        object the agent lacks comes back as a per-varbind noSuchObject and
        the rest of the reply is unharmed. On v1 they cannot — mixing one
        ifXTable OID into the request makes a v1 agent answer noSuchName
        for the whole PDU, and since only authorizationError was ever
        raised on, every interface on every v1 device came back blank: no
        counters, no speed, no link events. So on v1 the two tables are two
        requests, and an ifXTable that answers noSuchName is remembered as
        "this device has none" for the rest of the poll rather than
        re-asked once per port.
        """
        oids = [f"{oid}.{if_index}" for oid in nodeoids.IF_TABLE.values()]
        ifx_oids = [f"{oid}.{if_index}" for oid in nodeoids.IFX_TABLE.values()]
        if not is_v1:
            response = self._snmp_get(device, config, oids + ifx_oids)
            return {vb["oid"]: vb for vb in response.varbinds}, want_ifx
        values = self._v1_get_dropping_unknown(device, config, oids)
        if not want_ifx:
            return values, False
        try:
            response = self._snmp_get(device, config, ifx_oids)
        except SnmpTimeout:
            raise
        except SnmpError:
            return values, False
        if response.error_status == 2:                # no ifXTable at all
            return values, False
        values.update({vb["oid"]: vb for vb in response.varbinds})
        return values, True

    def _poll_interfaces(self, device, config: dict) -> tuple:
        """(rows, complete, reason, note) for a device's interfaces.

        `reason` is a fault the caller stores as snmp_error; `note` is the
        designed per-poll cap, which is not one — see _MAX_INTERFACES below.

        Walks the ifIndex column to discover interfaces, then reads the
        columns for each index.

        A walk that stops part way DEGRADES the interface data — complete
        is False, `reason` says what happened, and the device's own SNMP
        state is untouched. It used to fail the whole device: the ifIndex
        walk opted into raise_on_timeout, and the exception propagated out
        of _poll_device's one try to set snmp_ok = False even though the
        system scalars had already answered. On a chassis with several
        hundred interfaces behind a 3 s x 3 budget that is the whole
        reported fault — L3 confirmed, community confirmed, sysDescr
        populated, polling "failing".

        The boundary is progress, not cause: an ifIndex walk that got
        NOTHING at all still raises (see _walk_column_detail), because the
        scalars answering and then the very next request going unanswered
        is a device that has gone away mid-poll, and a device that has
        gone away must not read as healthy. One row is enough to say the
        agent is there and the credential is right.

        `complete` is what lets the caller decide whether an interface the
        walk did not produce is really gone: a walk cut short is not
        evidence of absence, and deleting on it takes the interfaces'
        link-event history with them.
        """
        interval = float(config.get("poll_interval_s") or 120)
        deadline = time.time() + max(self._INTERFACE_BUDGET_FLOOR_S,
                                     self._INTERFACE_BUDGET_FRACTION * interval)
        indexes, complete, reason = self._walk_indexes(
            device, config, nodeoids.IF_TABLE["if_index"], raise_on_timeout=True)
        if not indexes:
            return [], complete, reason, ""
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        want_ifx = True
        wanted = indexes[:self._MAX_INTERFACES]
        note = ""
        if len(indexes) > self._MAX_INTERFACES:
            complete = False
            # A NOTE, deliberately not the `reason` the caller stores as
            # snmp_error: this cap is a designed limit, the same on every
            # poll, and a core switch or a firewall with per-VLAN
            # subinterfaces sits over it permanently. Reported as an SNMP
            # error it painted a red line in the device pane and wrote a
            # NODES log line every poll interval for ever, which is how a
            # real error that arrives later gets missed. It still has to
            # reach the operator — a table that stops at 512 with nothing
            # saying why is the "healthy device, no interfaces" reading
            # again in miniature — so it travels to the device row and is
            # rendered under the interface table it describes.
            note = (f"the device reported {len(indexes)} interfaces; one poll "
                    f"reads the first {self._MAX_INTERFACES}")
        rows = []
        skipped = 0
        consecutive_timeouts = 0
        abandoned = ""
        for if_index in wanted:
            if time.time() > deadline:
                abandoned = "the poll's interface budget ran out"
                break
            if consecutive_timeouts >= self._INTERFACE_GIVE_UP_TIMEOUTS:
                abandoned = (f"{consecutive_timeouts} interfaces in a row did "
                             f"not answer")
                break
            try:
                values, want_ifx = self._interface_varbinds(
                    device, config, if_index, is_v1, want_ifx)
            except SnmpTimeout:
                # One interface's own GET timing out doesn't invalidate the
                # whole poll — the device answered enough to enumerate its
                # interfaces, so the rest are still worth collecting. Three
                # in a row does mean the device has gone quiet.
                skipped += 1
                consecutive_timeouts += 1
                continue
            except SnmpError:
                skipped += 1
                consecutive_timeouts = 0
                continue
            consecutive_timeouts = 0
            # Stamped right after this interface's own GET returns, not at
            # poll start: at a 3 s focus cadence that gap is a large
            # fraction of dt. This is the timestamp counter_rate and
            # update_interface_rates use for this row.
            sample_ts = time.time()

            def _val(table, key, _values=values, _index=if_index):
                vb = _values.get(f"{table[key]}.{_index}")
                if not vb or vb["type"] in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView", "null"):
                    return None
                return vb["value"]

            speed = _val(nodeoids.IF_TABLE, "if_speed")
            high_speed = _val(nodeoids.IFX_TABLE, "if_high_speed")
            if_type = _val(nodeoids.IF_TABLE, "if_type")
            # ifSpeed is a Gauge32 that RFC 2863 saturates at 4294967295 for
            # any link it cannot express in 32 bits of bits/sec, which is why
            # ifHighSpeed (Mbit/s) exists. The sentinel is left as a literal
            # denominator rather than treated as "unknown": in_util/out_util
            # are clamped to [0, 100], so a row stuck with it still reports a
            # bounded number instead of losing the metric.
            speed_bps = interface_speed_bps(speed, high_speed, if_type)
            hc_in = _val(nodeoids.IFX_TABLE, "if_hc_in_octets")
            hc_out = _val(nodeoids.IFX_TABLE, "if_hc_out_octets")
            in_octets = hc_in if isinstance(hc_in, (int, float)) else _val(nodeoids.IF_TABLE, "if_in_octets")
            out_octets = hc_out if isinstance(hc_out, (int, float)) else _val(nodeoids.IF_TABLE, "if_out_octets")
            # in_octets and out_octets fall back from the 64-bit ifXTable
            # counters to the 32-bit ifTable ones independently, so the wrap
            # width has to be tracked independently too: an agent answering
            # ifHCInOctets but not ifHCOutOctets would otherwise apply a
            # width of 64 to a genuinely 32-bit counter, and counter_rate
            # would drop the sample at every wrap.
            in_octet_bits = 64 if isinstance(hc_in, (int, float)) else 32
            out_octet_bits = 64 if isinstance(hc_out, (int, float)) else 32

            admin_raw = _val(nodeoids.IF_TABLE, "if_admin_status")
            oper_raw = _val(nodeoids.IF_TABLE, "if_oper_status")
            in_errors = _val(nodeoids.IF_TABLE, "if_in_errors")
            out_errors = _val(nodeoids.IF_TABLE, "if_out_errors")
            in_discards = _val(nodeoids.IF_TABLE, "if_in_discards")
            out_discards = _val(nodeoids.IF_TABLE, "if_out_discards")
            discontinuity = _val(nodeoids.IFX_TABLE, "if_discontinuity")
            rows.append({
                "if_index": if_index,
                "descr": _val(nodeoids.IF_TABLE, "if_descr") or "",
                "alias": _val(nodeoids.IFX_TABLE, "if_alias") or "",
                "phys_addr": (_val(nodeoids.IF_TABLE, "if_phys_addr") or ""),
                "speed_bps": speed_bps,
                "admin_status": {1: "up", 2: "down", 3: "testing"}.get(
                    int(admin_raw), "") if admin_raw is not None else "",
                "oper_status": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                               5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(
                    int(oper_raw), "") if oper_raw is not None else "",
                "in_octets": int(in_octets) if isinstance(in_octets, (int, float)) else None,
                "out_octets": int(out_octets) if isinstance(out_octets, (int, float)) else None,
                "in_errors": int(in_errors) if isinstance(in_errors, (int, float)) else None,
                "out_errors": int(out_errors) if isinstance(out_errors, (int, float)) else None,
                "in_discards": int(in_discards) if isinstance(in_discards, (int, float)) else None,
                "out_discards": int(out_discards) if isinstance(out_discards, (int, float)) else None,
                "discontinuity_ts": (float(discontinuity)
                                     if isinstance(discontinuity, (int, float)) else None),
                "_in_octet_bits": in_octet_bits,
                "_out_octet_bits": out_octet_bits,
                "_sample_ts": sample_ts,
            })
        if skipped or abandoned:
            complete = False
            per_interface = abandoned or f"{skipped} did not answer"
            self.log.add(NODES, f"Read {len(rows)} of {len(indexes)} interface(s) "
                                f"on {device['ip']}: {per_interface}. Interfaces "
                                f"that were not read keep their stored values.",
                        target=device["ip"])
            # Both halves, when both happened: the walk's own stop reason
            # names why the table is short, the per-interface one why the
            # rows it did enumerate are missing values.
            reason = f"{reason}; {per_interface}" if reason else per_interface
        if reason:
            self.log.add(NODES, f"Interface read on {device['ip']} is "
                                f"incomplete: {reason}", target=device["ip"])
        return rows, complete, reason, note

    def _walk_column(self, device, config: dict, base_oid: str,
                     raise_on_timeout: bool = False,
                     deadline: float | None = None) -> dict[str, object]:
        """One table column's values. See _walk_column_status, which this
        wraps for the callers that do not need to know whether the walk
        finished."""
        return self._walk_column_status(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout,
                                        deadline=deadline)[0]

    def _walk_column_status(self, device, config: dict, base_oid: str,
                            raise_on_timeout: bool = False,
                            deadline: float | None = None) -> tuple:
        """(index suffix -> value, whether the walk reached the end). See
        _walk_column_detail, which this wraps for the callers that do not
        need to know WHY a walk stopped."""
        return self._walk_column_detail(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout,
                                        deadline=deadline)[:2]

    def _walk_column_detail(self, device, config: dict, base_oid: str,
                            raise_on_timeout: bool = False,
                            deadline: float | None = None) -> tuple:
        """(index suffix -> value, whether the walk reached the end, why it
        stopped when it did not).

        `complete` is False whenever the walk stopped for a reason that is
        not "the table ended": a timeout, an SNMP error, the row cap, an
        agent that answered nothing, one that answered out of order, or
        the caller's own deadline. Callers that go on to delete rows the
        walk did not produce need to know the difference — a walk cut
        short is not evidence that anything is gone.

        v2c and v3 walk with GETBULK, up to
        `settings["snmp_bulk_max_repetitions"]` rows per request; v1 has no
        GETBULK PDU and uses GETNEXT. Either way the walk runs on one shared
        `_Session`. Per response, varbinds are taken in order until the first
        that leaves the subtree, answers noSuchObject/noSuchInstance/
        endOfMibView, or is not lexicographically after the request (an agent
        echoing itself or going backwards); the next request resumes from the
        last accepted OID. A GETBULK answered `error_status == 1` (tooBig) is
        retried at half the repetitions, then falls back to GETNEXT rather
        than looping, and the fallback itself is remembered. Any OTHER
        non-zero error-status — genErr(5) and noSuchName(2) are what a
        PAN-OS agent answers a subtree it will not serve — ends the walk
        with that status named in the reason. It used to fall through to
        the non-increasing-OID guard and end the walk with nothing said at
        all, which is a device reading healthy with zero interfaces. Stops
        at the subtree end or `settings["snmp_walk_max_rows"]` (logged
        once, not per row).

        A mid-walk SnmpTimeout means the device stopped answering, not that
        the table ended, so a caller whose result drives the device's own
        up/down status (_poll_interfaces, via _walk_indexes) passes
        raise_on_timeout=True rather than have it read as "no more rows".
        Best-effort callers leave it swallowed like any other SnmpError.
        Either way the reason names the session's `dropped` count when it
        is non-zero: replies that arrived and were rejected (wrong peer,
        undecodable, wrong request id) are a different fault from no reply
        at all, and only one of them is a firewall.
        """
        settings = self.db.settings()
        max_rows = int(settings.get("snmp_walk_max_rows", 16384) or 16384)
        # GETBULK does not exist in v1, so whether to use it is decided on
        # the configured version with 0 (v1) the only value that says no —
        # an absent version means v2c, the same default `_walk_request`,
        # `_snmp_get` and `_snmp_get_next` apply for framing. Framing
        # (build_request vs build_v3_request) is unaffected either way: v1
        # and v2c share the same community-based wire format. The
        # repetition count is the one this device last coped with.
        use_bulk, max_repetitions = self._bulk_settings(device, config)

        values: dict[str, object] = {}
        current = base_oid
        hit_cap = False
        complete = True
        reason = ""
        session = self._session_for(device, config)
        try:
            while True:
                if len(values) >= max_rows:
                    hit_cap = True
                    complete = False
                    reason = f"stopped at the {max_rows}-row cap"
                    break
                if deadline is not None and time.time() > deadline:
                    # The caller's own wall-clock budget. Checked inside
                    # the walk, not only between walks: a Cisco per-VLAN
                    # sweep that checked only between VLANs could run two
                    # unbounded walks past the budget it was given.
                    complete = False
                    reason = "the walk's own time budget ran out"
                    break
                try:
                    pdu_tag = PDU_GETBULK if use_bulk else PDU_GETNEXT
                    response = self._walk_request(
                        session, device, config, current, pdu_tag, max_repetitions)
                except SnmpTimeout as exc:
                    complete = False
                    reason = (f"{exc} (table walk cut short after "
                              f"{len(values)} row(s))")
                    if raise_on_timeout and not values:
                        # Nothing at all came back, so this is the device
                        # having stopped answering rather than a table too
                        # large to finish inside the budget. Only that
                        # reads as an SNMP failure; see _poll_interfaces.
                        raise SnmpTimeout(_with_dropped(reason, session)) from exc
                    break
                except SnmpError as exc:
                    complete = False
                    reason = f"SNMP error: {exc}"
                    break
                if use_bulk and response.error_status == 1:   # tooBig
                    if max_repetitions <= 1:
                        use_bulk = False
                        self._remember_repetitions(device, 0, use_bulk=False)
                    else:
                        max_repetitions = max(1, max_repetitions // 2)
                        self._remember_repetitions(device, max_repetitions)
                    continue
                if response.error_status:
                    complete = False
                    reason = _error_status_reason(response, base_oid)
                    break
                if not response.varbinds:
                    complete = False
                    reason = "the device returned nothing"
                    break
                stop = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base_oid or oid.startswith(base_oid + ".")):
                        stop = True
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                        stop = True
                        break
                    if _oid_key(oid) <= _oid_key(current):
                        complete = False
                        reason = (f"the device answered with a non-increasing "
                                  f"OID ({oid}) — its SNMP agent is misbehaving")
                        stop = True
                        break
                    values[oid[len(base_oid) + 1:]] = vb["value"]
                    current = oid
                    if len(values) >= max_rows:
                        hit_cap = True
                        complete = False
                        reason = f"stopped at the {max_rows}-row cap"
                        stop = True
                        break
                if stop:
                    break
            if reason:
                reason = _with_dropped(reason, session)
        finally:
            session.close()
        if hit_cap:
            self.log.add(NODES, f"Table walk of {base_oid} on {device['ip']} "
                                f"stopped at the {max_rows}-row cap",
                         target=device["ip"])
        return values, complete, reason

    def _walk_indexes(self, device, config: dict, base_oid: str,
                      raise_on_timeout: bool = False) -> tuple:
        """(the integer indexes the column reported, whether the walk
        finished, why it stopped when it did not).

        A suffix that is not an integer is skipped, not treated as the end
        of the table: one malformed row used to truncate the list, and
        because the caller then deleted every interface it had not seen,
        one bad row took the rest of the device's ports and their link
        history with it.
        """
        indexes: list[int] = []
        values, complete, reason = self._walk_column_detail(
            device, config, base_oid, raise_on_timeout=raise_on_timeout)
        for suffix in values:
            try:
                indexes.append(int(suffix))
            except ValueError:
                continue
        return indexes, complete, reason

    # ENTITY-MIB (RFC 6933) and ENTITY-SENSOR-MIB (RFC 3433) columns used
    # by read_dom() to find a port's transceiver sensors.
    _ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
    _ENT_PHYSICAL_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
    # entPhysicalClass/ModelName: what an entity IS, which is the only way
    # to see an SFP slot that reports no DOM at all -- a cage with nothing
    # in it has no sensor to be found by. entPhysicalVendorType would be the
    # obvious third, and is deliberately not walked: it is an OBJECT
    # IDENTIFIER, so a conforming agent answers a dotted number that no text
    # test can read, and the registered names behind those numbers
    # (`cevSFP10GLR` and its kin) run the words together, so they would not
    # match _TRANSCEIVER_TEXT even spelled out. Descr and model name carry
    # the whole job, for one fewer full walk of entPhysical per cadence.
    _ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
    _ENT_PHYSICAL_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"
    # entPhysicalName: RFC 6933 makes it optional, so read_dom's own decode
    # (shared with _poll_environment, both pre-dating this column's use
    # here) never depended on it -- but where an agent populates it, it is
    # a nicer name than entPhysicalDescr for a whole-device sensor list,
    # which is naming dozens of rows at once rather than the one a port
    # dialog already knows the context of. See _read_entity_sensors.
    _ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
    _ENT_ALIAS_MAPPING = "1.3.6.1.2.1.47.1.3.2.1.2"
    _ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
    _ENT_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
    _ENT_SENSOR_PRECISION = "1.3.6.1.2.1.99.1.1.1.3"
    _ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
    _ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
    _ENT_SENSOR_UNITS = "1.3.6.1.2.1.99.1.1.1.6"
    _IF_INDEX_COLUMN = "1.3.6.1.2.1.2.2.1.1"

    # CISCO-ENTITY-SENSOR-MIB entSensorValueTable — what Cisco switches
    # populate INSTEAD of RFC 3433's entPhySensorTable, which is why an
    # all-Cisco fleet saw both sensor sections empty. Same index and
    # type/scale/precision/status enums, extended with specialEnum(13) and
    # dBm(14); no units-display column, so unit text comes from the type enum.
    _CISCO_SENSOR_TYPE = "1.3.6.1.4.1.9.9.91.1.1.1.1.1"
    _CISCO_SENSOR_SCALE = "1.3.6.1.4.1.9.9.91.1.1.1.1.2"
    _CISCO_SENSOR_PRECISION = "1.3.6.1.4.1.9.9.91.1.1.1.1.3"
    _CISCO_SENSOR_VALUE = "1.3.6.1.4.1.9.9.91.1.1.1.1.4"
    _CISCO_SENSOR_STATUS = "1.3.6.1.4.1.9.9.91.1.1.1.1.5"
    _CISCO_ENTERPRISE_PREFIX = "1.3.6.1.4.1.9."

    # CISCO-ENTITY-SENSOR-MIB entSensorThresholdTable — the alarm and
    # warning levels a transceiver publishes about ITSELF, indexed
    # <entPhysicalIndex>.<threshold index>. This is what makes an optic
    # power alert mean anything: an SR part's floor is not a ZR part's.
    #
    # .5 entSensorThresholdEvaluation is deliberately NOT read. It is the
    # device's own instantaneous verdict, and taking it would bypass this
    # app's hysteresis, its breach streak and for_polls all at once — the
    # three things that stop a value hovering at its limit mailing somebody
    # every poll. .6 entSensorThresholdNotificationEnable is about the
    # device's own traps, not about us.
    _CISCO_THRESHOLD_SEVERITY = "1.3.6.1.4.1.9.9.91.1.2.1.1.2"
    _CISCO_THRESHOLD_RELATION = "1.3.6.1.4.1.9.9.91.1.2.1.1.3"
    _CISCO_THRESHOLD_VALUE = "1.3.6.1.4.1.9.9.91.1.2.1.1.4"

    # entSensorThresholdSeverity -> which of this app's two bands the level
    # belongs in. other(1) is dropped: it names no band, so there is no
    # column to put it in. major(20) and critical(30) both land in the alarm
    # band -- an optic that publishes both gets the tighter of the two by the
    # duplicate rule below, which is the one that alerts first.
    _CISCO_THRESHOLD_BAND = {10: "warn", 20: "alarm", 30: "alarm"}
    # entSensorThresholdRelation -> which SIDE of the reading the level is.
    # lessThan(1)/lessOrEqual(2) are a floor, greaterThan(3)/greaterOrEqual(4)
    # a ceiling; equalTo(5) and notEqualTo(6) describe neither and are
    # dropped, since this app's evaluator only ever asks "at or past".
    _CISCO_THRESHOLD_SIDE = {1: "low", 2: "low", 3: "high", 4: "high"}
    # Every real transceiver's published dBm levels sit well inside this
    # band, and nothing a scale misread produces does -- a threshold decoded
    # a factor of a thousand out lands at -14400 or -0.0144, both outside.
    # It is the only check that can catch that failure, which is otherwise
    # invisible: -14.4 and -14400 are both "a number".
    _DBM_LIMIT_RANGE = (-60.0, 30.0)

    _SENSOR_TYPE_UNITS = {3: "V AC", 4: "V DC", 5: "A", 6: "W", 7: "Hz",
                          8: "°C", 9: "%RH", 10: "RPM", 11: "m³/min",
                          12: "", 13: "", 14: "dBm"}
    _SENSOR_STATUS = {1: "ok", 2: "unavailable", 3: "nonoperational"}
    # entPhySensorType -> a human label, for read_hardware's whole-device
    # sensor list (a port dialog's DOM table already gives its rows
    # context; a device-wide list naming dozens of unrelated probes needs
    # to say what kind each one is).
    _SENSOR_TYPE_NAMES = {1: "other", 2: "unknown", 3: "voltage",
                          4: "voltage", 5: "current", 6: "power",
                          7: "frequency", 8: "temperature", 9: "humidity",
                          10: "fan speed", 11: "airflow", 12: "other",
                          13: "state", 14: "optical power"}

    # entPhySensorType values this app turns into a device-level metric —
    # see _poll_environment; the rest of _SENSOR_TYPE_UNITS' arcs are real
    # DOM readings a transceiver has, not something a device has one true
    # value for, so they aren't promoted to a device metric here.
    _SENSOR_TYPE_TEMPERATURE = 8
    _SENSOR_TYPE_HUMIDITY = 9

    # entPhySensorType -> the per-port optic metric root. Optical power (14)
    # is absent: its key depends on the sensor's name, not its type.
    _SFP_TYPE_ROOTS = {8: "sfp_temp_c", 3: "sfp_volt", 4: "sfp_volt",
                       5: "sfp_bias_ma"}
    _SENSOR_TYPE_OPTICAL = 14
    # The one entPhysicalClass value this app has to tell apart: a
    # transceiver cage is a container(5). What is IN one is a module(9) on
    # some agents and a port(10) on others, so the contents are identified
    # by their text rather than by a class enum — see _sfp_slot_media.
    _ENT_CLASS_CONTAINER = 5
    # ENTITY-SENSOR-MIB reports current in amperes; bias is quoted in
    # milliamps everywhere an operator would read it.
    _BIAS_A_TO_MA = 1000.0

    @staticmethod
    def _scaled_sensor_value(raw, scale, precision) -> float:
        """RFC 3433's arithmetic, alone: the reading is
        raw x 10^(3*(scale-9)) with `precision` decimal places already
        folded into the integer.

        Its own function because entSensorThresholdValue is quoted in the
        SAME scale and precision as the entity's reading, and a second copy
        of three lines of exponent arithmetic is how the two would drift a
        factor of a thousand apart without anything looking wrong.
        """
        scale = int(scale or 9)             # 9 = units (10^0)
        precision = int(precision or 0)
        return raw * (10 ** (3 * (scale - 9))) / (10 ** precision)

    def _decode_entity_sensor(self, suffix: str, raw, types: dict, scales: dict,
                              precisions: dict, statuses: dict, units: dict,
                              descrs: dict) -> dict | None:
        """One ENTITY-SENSOR-MIB row (RFC 3433) -> {"entity", "label",
        "value", "unit", "status"}, or None when `raw` is not the number
        entPhySensorValue is supposed to be (an unpopulated row, or an
        agent answering the wrong ASN.1 type for this instance).

        Shared by read_dom and _poll_environment so the scaling arithmetic
        lives in one place. Reached without entAliasMappingIdentifier, which
        maps a sensor to the port it rides on: an environmental monitor's
        probes belong to the chassis, map to nothing in that table, and
        would otherwise be invisible everywhere in this app.
        """
        if not isinstance(raw, (int, float)):
            return None
        try:
            entity = int(suffix)
        except ValueError:
            return None
        sensor_type = int(types.get(suffix) or 0)
        precision = int(precisions.get(suffix) or 0)
        value = self._scaled_sensor_value(
            raw, scales.get(suffix), precisions.get(suffix))
        unit = str(units.get(suffix) or "").strip() or \
            self._SENSOR_TYPE_UNITS.get(sensor_type, "")
        return {
            "entity": entity,
            "label": str(descrs.get(suffix) or f"sensor {entity}"),
            "value": round(value, max(precision, 4)),
            "unit": unit,
            "status": self._SENSOR_STATUS.get(
                int(statuses.get(suffix) or 0), "unknown"),
        }

    def _cisco_sensor_table_plausible(self, device) -> bool:
        """Whether CISCO-ENTITY-SENSOR-MIB could answer on this device.

        The fallback walk below is gated on this so nothing but Cisco gear
        ever pays for a second table walk that could only time out: on a
        fleet of a few hundred devices an ungated fallback would be one
        wasted walk per device per sensor read, forever.
        """
        if detected_vendor(device).lower() == "cisco":
            return True
        keys = device.keys() if hasattr(device, "keys") else device
        raw = (device["sys_object_id"] if "sys_object_id" in keys else "") or ""
        return str(raw).startswith(self._CISCO_ENTERPRISE_PREFIX)

    def _walk_sensor_columns(self, device, config: dict) -> tuple[str, dict, list]:
        """(source, columns, tables tried) — whichever sensor table this
        device actually populates, walked once for every caller.

        Falls back to CISCO-ENTITY-SENSOR-MIB only when ENTITY-SENSOR-MIB's
        value column comes back empty AND _cisco_sensor_table_plausible():
        the two are never merged, since gear that answers both would show
        every reading twice with no way to tell the duplicates apart.

        `columns` holds values/types/scales/precisions/statuses/units keyed
        by index suffix; `tried` names the tables, for the diagnostics
        event log.
        """
        tried = ["ENTITY-SENSOR-MIB"]
        source = "ENTITY-SENSOR-MIB"
        values = self._walk_column(device, config, self._ENT_SENSOR_VALUE)
        siblings = (self._ENT_SENSOR_TYPE, self._ENT_SENSOR_SCALE,
                    self._ENT_SENSOR_PRECISION, self._ENT_SENSOR_STATUS,
                    self._ENT_SENSOR_UNITS)
        if not values and self._cisco_sensor_table_plausible(device):
            tried.append("CISCO-ENTITY-SENSOR-MIB")
            source = "CISCO-ENTITY-SENSOR-MIB"
            values = self._walk_column(device, config, self._CISCO_SENSOR_VALUE)
            siblings = (self._CISCO_SENSOR_TYPE, self._CISCO_SENSOR_SCALE,
                        self._CISCO_SENSOR_PRECISION, self._CISCO_SENSOR_STATUS,
                        None)
        if not values:
            return "", {}, tried
        type_oid, scale_oid, precision_oid, status_oid, units_oid = siblings
        cols = {
            "values": values,
            "types": self._walk_column(device, config, type_oid),
            "scales": self._walk_column(device, config, scale_oid),
            "precisions": self._walk_column(device, config, precision_oid),
            "statuses": self._walk_column(device, config, status_oid),
            "units": self._walk_column(device, config, units_oid)
                     if units_oid else {},
        }
        return source, cols, tried

    def read_dom(self, device_id: int, if_index: int) -> list[dict]:
        """Live on-demand read of one interface's sensors — DOM/DDM data on
        an SFP port (light levels, bias current, supply voltage,
        temperature). Walked only while a human has the interface dialog
        open, never on the poll cycle: several table walks per call is fine
        once in a while and wasteful every interval.

        _read_entity_sensors filtered to one ifIndex, so this can never
        disagree with the whole-device list about which sensor rides on
        which port or which MIB it came from. `label` stays entPhysicalDescr
        here since a port dialog already supplies context a device-wide
        list has to spell out.

        Each row also carries `limits` — the four-band dict this port's own
        transceiver published for that reading, or None — and
        `limits_source`, the MIB it came out of. They are on the row rather
        than left to the caller because a reading and the level it is judged
        against are one fact: from 5.3.0 an optical power row with no limits
        raises no alert at all, and that is only honest if the dialog says
        so. One stored read per call, no extra walk.

        Returns [] when the device answers no sensor table or maps no
        entity to this ifIndex."""
        device = self.db.device(device_id)
        if device is None:
            return []
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return []
        limits = self.db.interface_thresholds(device_id)
        sensors = []
        for sensor in self._read_entity_sensors(device, config):
            if sensor.get("if_index") != if_index:
                continue
            sensors.append({
                "entity": sensor["entity"],
                "label": sensor.get("descr") or sensor["label"],
                "value": sensor["value"], "unit": sensor["unit"],
                "status": sensor["status"], "source": sensor.get("source", ""),
                **self._sensor_limits(limits, if_index, sensor)})
        sensors.sort(key=lambda s: s["entity"])
        return sensors

    @staticmethod
    def _sensor_limits(limits: dict, if_index, sensor: dict) -> dict:
        """{"limits": the four published bands or None, "limits_source": the
        MIB that published them} for one DOM row — the shape read_dom and
        read_dom_all both put on their rows."""
        row = limits.get((if_index, sensor.get("metric_root")))
        if row is None:
            return {"limits": None, "limits_source": ""}
        return {
            "limits": {band: row[band] for band in
                       ("low_alarm", "low_warn", "high_warn", "high_alarm")},
            "limits_source": row["source"],
        }

    def _entity_port_map(self, device, config: dict, names: dict | None = None,
                         if_by_name: dict | None = None,
                         contained_in: dict[int, int] | None = None
                         ) -> tuple[dict[int, int], int]:
        """(entPhysicalIndex -> ifIndex, how many entAliasMappingIdentifier
        rows the device answered) for every entity mapped to a port. The
        row count is only used to explain, in the Nodes event log, why
        sensors mapped to nothing.

        First pass: entAliasMappingIdentifier resolved through
        entPhysicalContainedIn — the standard, authoritative mapping.
        Second pass exists because Cisco gear often populates no alias rows
        at all: for an unmapped entity, climb its containment chain and
        match a hop's entPhysicalName (whole name or first word) against a
        stored ifDescr (`if_by_name`, canonicalised by _canonical_if_name)
        — e.g. "Te1/1/1 Transmit Power" against "TenGigabitEthernet1/1/1".
        Matched against ifDescr only, never ifAlias, since an operator-typed
        description proves nothing.

        `contained_in` is walked here when the caller has no use for it
        itself; _poll_environment passes its own so the SFP-slot scan and
        this share one walk of the column.
        """
        alias = self._walk_column(device, config, self._ENT_ALIAS_MAPPING)
        prefix = self._IF_INDEX_COLUMN + "."
        direct: dict[int, int] = {}
        for suffix, value in alias.items():
            target = str(value)
            if not target.startswith(prefix):
                continue
            try:
                entity = int(suffix.split(".")[0])
                if_index = int(target.rsplit(".", 1)[-1])
            except ValueError:
                continue
            direct[entity] = if_index
        if contained_in is None:
            contained_in = self._entity_contained_in(device, config)

        resolved: dict[int, int] = {}

        def resolve(entity: int):
            seen = 0
            chain = entity
            while chain and seen < 16:   # a real containment tree is shallow
                if chain in direct:
                    resolved[entity] = direct[chain]
                    return
                chain = contained_in.get(chain, 0)
                seen += 1

        for entity in set(direct) | set(contained_in):
            resolve(entity)
        if not names or not if_by_name:
            return resolved, len(alias)

        named = _int_keyed(names)
        for entity in sorted(set(named) | set(contained_in)):
            if entity in resolved:
                continue
            hop, seen = entity, 0
            while hop and seen < 16:
                if hop in resolved:
                    resolved[entity] = resolved[hop]
                    break
                hit = self._if_index_for_name(named.get(hop), if_by_name)
                if hit is not None:
                    resolved[entity] = hit
                    break
                hop = contained_in.get(hop, 0)
                seen += 1
        return resolved, len(alias)

    def _entity_contained_in(self, device, config: dict) -> dict[int, int]:
        """entPhysicalIndex -> the entity holding it, both ends parsed to
        int. Its own method because two passes over one device need the
        containment tree and neither may pay for a second walk of it."""
        parents: dict[int, int] = {}
        for suffix, value in _int_keyed(self._walk_column(
                device, config, self._ENT_PHYSICAL_CONTAINED_IN)).items():
            try:
                parents[suffix] = int(value)
            except (TypeError, ValueError):
                continue
        return parents

    def _sfp_slot_media(self, device, config: dict, port_map: dict[int, int],
                        contained_in: dict[int, int], descrs: dict) -> tuple:
        """({ifIndex: 'sfp' | 'sfp_empty'}, whether every walk it made
        finished) for the transceiver cages this device describes. The DOM
        scan cannot see these: a cage with nothing in it, or holding a
        transceiver that reports no sensors, has no sensor row to be found
        by, and until 5.2.0 an SFP slot like that was indistinguishable from
        a copper port.

        'sfp' is an entity whose own entPhysical text names a transceiver
        (the module plugged into a cage, or a port an agent puts that text
        on directly); 'sfp_empty' is a container(5) that says it is a
        transceiver cage and holds nothing that does. A container that names
        nothing is left alone rather than guessed at: some platforms give
        every copper port one too, and a copper port must never wear an SFP
        badge.

        The completeness flag is the caller's to act on, and it must: a walk
        cut short answers with what it had reached, which reads as a cage
        that is not there or a module that is not in one. See
        _poll_environment, which will not overwrite a stored badge on one.
        """
        raw_classes, complete = self._walk_column_status(
            device, config, self._ENT_PHYSICAL_CLASS)
        classes = _int_keyed(raw_classes)
        if not classes:
            return {}, complete
        models, models_done = self._walk_column_status(
            device, config, self._ENT_PHYSICAL_MODEL_NAME)
        complete = complete and models_done
        models = _int_keyed(models)
        by_descr = _int_keyed(descrs)
        children: dict[int, list[int]] = {}
        for entity, parent in contained_in.items():
            children.setdefault(parent, []).append(entity)

        def names_transceiver(entity: int) -> bool:
            return any(_TRANSCEIVER_TEXT.search(str(column.get(entity) or ""))
                       for column in (by_descr, models))

        def descendants(root: int) -> list[int]:
            found: list[int] = []
            queue, depth = list(children.get(root, ())), 0
            while queue and depth < 4:      # a cage's contents are shallow
                found.extend(queue)
                queue = [c for parent in queue for c in children.get(parent, ())]
                depth += 1
            return found

        media: dict[int, str] = {}
        for entity, klass in sorted(classes.items()):
            try:
                klass = int(klass)
            except (TypeError, ValueError):
                continue
            if klass != self._ENT_CLASS_CONTAINER:
                # The cage's own text names it either way, so only something
                # OTHER than the container proves one is occupied.
                if names_transceiver(entity) and entity in port_map:
                    media[port_map[entity]] = "sfp"
                continue
            if not names_transceiver(entity):
                continue
            # A cage rarely carries the alias row itself; the port sitting
            # in it does, which is the ifIndex the badge belongs to.
            if_index = next((port_map[e] for e in [entity] + children.get(entity, [])
                             if e in port_map), None)
            if if_index is None:
                continue
            if any(names_transceiver(child) for child in descendants(entity)):
                media[if_index] = "sfp"
            else:
                media.setdefault(if_index, "sfp_empty")
        return media, complete

    @staticmethod
    def _if_index_for_name(name, if_by_name: dict) -> int | None:
        """The ifIndex whose canonicalised ifDescr this entPhysicalName
        names, if any: the whole name first, then its first whitespace
        token, which is the part a Cisco sensor name puts the port in."""
        raw = str(name or "").strip()
        if not raw:
            return None
        for candidate in (raw, raw.split()[0]):
            hit = if_by_name.get(_canonical_if_name(candidate))
            if hit is not None:
                return hit
        return None

    def _read_entity_sensors(self, device, config: dict) -> list[dict]:
        """Every ENTITY-SENSOR-MIB row this device answers, whatever it
        does or does not map to -- the whole-device counterpart of
        read_dom()'s single-port filter, and read_hardware's "sensors"
        list. Shares _decode_entity_sensor with read_dom and
        _poll_environment, so the value/unit/status of a given reading can
        never disagree between them.

        Each row adds `type` (a human label for entPhySensorType),
        `if_index`/`if_name` (via _entity_port_map), `descr` (raw
        entPhysicalDescr, which read_dom labels its rows from) and `source`
        (the MIB the reading came from) on top of _decode_entity_sensor's
        own shape, and prefers entPhysicalName over entPhysicalDescr for
        `label` where an agent populates it -- see _ENT_PHYSICAL_NAME.
        """
        source, cols, tried = self._walk_sensor_columns(device, config)
        if not cols:
            self._log_sensor_diag(
                device, f"No sensor rows from {device['ip']}: "
                        f"{' and '.join(tried)} answered nothing")
            return []
        types = cols["types"]
        descrs = self._walk_column(device, config, self._ENT_PHYSICAL_DESCR)
        names = self._walk_column(device, config, self._ENT_PHYSICAL_NAME)
        interfaces = list(self.db.interfaces(device["id"]))
        if_names = {row["if_index"]: (row["descr"] or row["alias"] or "")
                   for row in interfaces}
        port_map, alias_rows = self._entity_port_map(
            device, config, names, self._if_index_by_name(interfaces))

        sensors = []
        for suffix, raw in cols["values"].items():
            reading = self._decode_entity_sensor(
                suffix, raw, types, cols["scales"], cols["precisions"],
                cols["statuses"], cols["units"], descrs)
            if reading is None:
                continue
            entity = reading["entity"]
            name = str(names.get(suffix) or "").strip()
            if_index = port_map.get(entity)
            if_name = if_names.get(if_index) if if_index is not None else None
            sensors.append({
                **reading,
                "label": name or reading["label"],
                "descr": str(descrs.get(suffix) or "").strip(),
                "source": source,
                "type": self._SENSOR_TYPE_NAMES.get(
                    int(types.get(suffix) or 0), "other"),
                # The per-port metric key this reading feeds, so the two DOM
                # reads can find the limits the port published for it without
                # re-deriving the direction from the sensor's name.
                "metric_root": self._sfp_root_for(
                    int(types.get(suffix) or 0), suffix, names, descrs),
                "if_index": if_index,
                "if_name": if_name or None,
            })
        sensors.sort(key=lambda s: s["entity"])
        # A UPS or a room monitor maps nothing to a port and is fine; an
        # unmapped optic, or any unmapped row on Cisco gear, is the case
        # this line was written for.
        suspicious = (self._cisco_sensor_table_plausible(device)
                      or any(s["type"] == "optical power" for s in sensors))
        if sensors and suspicious and not any(
                s["if_index"] is not None for s in sensors):
            self._log_sensor_diag(
                device, f"Read {len(sensors)} sensor row(s) from {device['ip']} "
                        f"via {source}, none mapped to an interface: "
                        f"entAliasMappingIdentifier had {alias_rows} row(s), "
                        f"entPhysicalName matched no stored ifDescr")
        return sensors

    @staticmethod
    def _if_index_by_name(interfaces) -> dict[str, int]:
        """Canonicalised ifDescr -> ifIndex, for _entity_port_map's name
        fallback. ifDescr only: ifAlias is whatever an operator typed."""
        by_name: dict[str, int] = {}
        for row in interfaces:
            key = _canonical_if_name(row["descr"] or "")
            if key:
                by_name.setdefault(key, row["if_index"])
        return by_name

    # One sensor-diagnostic event per device per minute. The device dialog
    # re-reads on every open, and a device that answers nothing must not
    # turn that into an event-log flood.
    _SENSOR_DIAG_INTERVAL_S = 60.0

    def _log_sensor_diag(self, device, message: str) -> None:
        now = time.time()
        device_id = device["id"]
        if now - self._sensor_diag_ts.get(device_id, 0.0) < \
                self._SENSOR_DIAG_INTERVAL_S:
            return
        self._sensor_diag_ts[device_id] = now
        self.log.add(NODES, message, target=device["ip"])

    # entPhySensorType -> device-metric keys and prefixes read_hardware's
    # "metrics" section shows: the polled figures _poll_vendor_health and
    # _poll_environment already keep current, not anything walked here.
    _HARDWARE_METRIC_KEYS = {"cpu_pct", "mem_pct", "humidity_pct"}
    _HARDWARE_METRIC_PREFIXES = ("temp_", "fan_", "psu_")

    def _hardware_metrics(self, device_id: int) -> list[dict]:
        """The stored metrics that are a hardware reading rather than a
        traffic counter, a ping figure or a UPS-MIB one -- cpu_pct,
        mem_pct, every temp_* key (optic/ambient/chassis), humidity_pct,
        and any fan_*/psu_* key a future vendor table adds.

        Read straight off metrics.last_value/last_ts: _poll_vendor_health
        and _poll_environment already keep these current on their own
        poll-cycle cadence, so read_hardware only needs to show the latest
        stored sample, never walk anything itself for this section.
        """
        rows = []
        for row in self.db.metrics(device_id):
            key = row["key"]
            if key not in self._HARDWARE_METRIC_KEYS and \
               not key.startswith(self._HARDWARE_METRIC_PREFIXES):
                continue
            if row["last_value"] is None:
                continue
            rows.append({"key": key, "label": row["label"],
                        "value": row["last_value"], "unit": row["unit"],
                        "status": "", "ts": row["last_ts"]})
        order = {"cpu_pct": 0, "mem_pct": 1}
        rows.sort(key=lambda r: (order.get(r["key"], 2), r["key"]))
        return rows

    # CISCO-ENVMON-MIB (the classic pre-ENTITY-SENSOR-MIB Cisco health
    # tables) columns used by _read_cisco_envmon. ciscoEnvMonSupplyState /
    # ciscoEnvMonFanState / ciscoEnvMonTemperatureState share one enum.
    _ENVMON_SUPPLY_DESCR = "1.3.6.1.4.1.9.9.13.1.5.1.2"
    _ENVMON_SUPPLY_STATE = "1.3.6.1.4.1.9.9.13.1.5.1.3"
    _ENVMON_FAN_DESCR = "1.3.6.1.4.1.9.9.13.1.4.1.2"
    _ENVMON_FAN_STATE = "1.3.6.1.4.1.9.9.13.1.4.1.3"
    _ENVMON_TEMP_DESCR = "1.3.6.1.4.1.9.9.13.1.3.1.2"
    _ENVMON_TEMP_VALUE = "1.3.6.1.4.1.9.9.13.1.3.1.3"
    _ENVMON_TEMP_THRESHOLD = "1.3.6.1.4.1.9.9.13.1.3.1.4"
    _ENVMON_TEMP_STATE = "1.3.6.1.4.1.9.9.13.1.3.1.6"
    _ENVMON_STATE = {1: "normal", 2: "warning", 3: "critical",
                     4: "shutdown", 5: "notPresent", 6: "notFunctioning"}

    def _read_cisco_envmon(self, device, config: dict) -> list[dict]:
        """CISCO-ENVMON-MIB power-supply, fan and temperature status --
        read_hardware's Cisco-only extra section, for gear old or simple
        enough to answer this rather than (or as well as) ENTITY-SENSOR-MIB.
        Only ever called once detected_vendor is "cisco": walking an OID
        subtree the agent has never heard of just times out, and every
        non-Cisco device in the fleet would otherwise pay for a wasted walk
        on every dialog open.
        """
        rows = []
        descrs = self._walk_column(device, config, self._ENVMON_SUPPLY_DESCR)
        states = self._walk_column(device, config, self._ENVMON_SUPPLY_STATE)
        for suffix, descr in descrs.items():
            rows.append({
                "kind": "supply", "label": str(descr) or f"supply {suffix}",
                "value": None, "unit": "",
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        descrs = self._walk_column(device, config, self._ENVMON_FAN_DESCR)
        states = self._walk_column(device, config, self._ENVMON_FAN_STATE)
        for suffix, descr in descrs.items():
            rows.append({
                "kind": "fan", "label": str(descr) or f"fan {suffix}",
                "value": None, "unit": "",
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        descrs = self._walk_column(device, config, self._ENVMON_TEMP_DESCR)
        values = self._walk_column(device, config, self._ENVMON_TEMP_VALUE)
        thresholds = self._walk_column(device, config, self._ENVMON_TEMP_THRESHOLD)
        states = self._walk_column(device, config, self._ENVMON_TEMP_STATE)
        for suffix, descr in descrs.items():
            value = values.get(suffix)
            numeric = isinstance(value, (int, float))
            rows.append({
                "kind": "temperature",
                "label": str(descr) or f"temperature {suffix}",
                "value": value if numeric else None,
                "unit": "°C" if numeric else "",
                "threshold": thresholds.get(suffix),
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        return rows

    def read_hardware(self, device_id: int) -> dict:
        """On-demand snapshot of a device's own hardware health for the
        device dialog's HARDWARE SENSORS section: the polled CPU/memory/
        temperature metrics already stored, every ENTITY-SENSOR-MIB row
        the device answers (not filtered to one port the way read_dom is),
        and CISCO-ENVMON-MIB's supply/fan/temperature status on Cisco gear.

        Walked only while a human has the device dialog open, never on the
        poll cycle -- the same reasoning read_dom's docstring gives. A
        device that answers nothing for a section leaves it an empty list
        rather than raising: this backs a dialog, and "no data" is a fact
        it can show, an exception is not.
        """
        device = self.db.device(device_id)
        if device is None:
            return {"metrics": [], "sensors": [], "envmon": []}
        metrics = self._hardware_metrics(device_id)
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return {"metrics": metrics, "sensors": [], "envmon": []}
        sensors = self._read_entity_sensors(device, config)
        envmon = self._read_cisco_envmon(device, config) \
            if detected_vendor(device).lower() == "cisco" else []
        return {"metrics": metrics, "sensors": sensors, "envmon": envmon}

    def read_dom_all(self, device_id: int) -> list[dict]:
        """Every port's DOM/SFP (ENTITY-SENSOR-MIB) reading across the
        whole device, in the one set of table walks _read_entity_sensors
        already does -- the device-wide counterpart of read_dom(), the
        same relationship read_device_mac_table already has to
        read_mac_table, so opening the device dialog costs one walk rather
        than one read_dom() per interface.

        Built from the exact same decode and the exact same containment
        resolution read_dom() uses, so the two can never disagree about
        which sensor belongs to which port -- only about how many ports
        they answer for in one call. Rows with no port mapping (a chassis
        or environmental-monitor probe, already visible in read_hardware's
        "sensors" list) are left out: this is the DOM/SFP table, one row
        per port, not the whole-device sensor list again.
        """
        device = self.db.device(device_id)
        if device is None:
            return []
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return []
        if_names = {row["if_index"]: (row["descr"] or row["alias"]
                                      or f"port {row['if_index']}")
                   for row in self.db.interfaces(device_id)}
        limits = self.db.interface_thresholds(device_id)
        rows = []
        for sensor in self._read_entity_sensors(device, config):
            if_index = sensor.get("if_index")
            if if_index is None:
                continue
            rows.append({
                "if_index": if_index,
                "if_name": if_names.get(if_index, f"port {if_index}"),
                "label": sensor["label"], "value": sensor["value"],
                "unit": sensor["unit"], "status": sensor["status"],
                **self._sensor_limits(limits, if_index, sensor)})
        rows.sort(key=lambda r: (r["if_index"], r["label"]))
        return rows

    # How often _poll_environment's whole-device ENTITY-SENSOR-MIB walk runs
    # per device. Six column walks cost what the LLDP/MAC walks do, so it
    # gets a cadence rather than the poll cycle; a temperature reading does
    # not change poll to poll the way an interface counter does. Fixed, not
    # a per-device column, and in memory only (see _sensor_read).
    #
    # Must stay well under alertengine's threshold_stale_s (900 s default):
    # a metric older than that reads as absent to a threshold rule, so a
    # slower cadence would flicker the temperature/humidity rules in and out
    # of "no data".
    _SENSOR_REFRESH_S = 300.0

    # How long a device that answered no sensor table waits before being
    # asked again. sensor_capable used to latch 0 forever, which was wrong
    # once a second table existed: a Cisco switch latched incapable before
    # ever being identified as Cisco would never get offered the Cisco
    # table at all. An hour bounds how long that mistake can last.
    _SENSOR_REPROBE_S = 3600.0

    # How often the published-threshold walk runs, against _SENSOR_REFRESH_S's
    # 300: a DOM reading changes every poll, but the levels a transceiver
    # publishes change only when somebody pulls the optic out of the cage.
    # Three extra column walks an hour on the switches that have optics is
    # the whole cost of per-port optic alerting.
    _SENSOR_THRESHOLD_REFRESH_S = 3600.0

    # The MIB these limits came out of, stored on every row so a second
    # vendor's walk one day replaces only its own. See
    # nodesdb.replace_interface_thresholds.
    _CISCO_THRESHOLD_SOURCE = "CISCO-ENTITY-SENSOR-MIB"

    def _sfp_root_for(self, sensor_type: int, suffix: str, names, descrs
                      ) -> str | None:
        """The per-port DOM metric root (_SFP_METRICS) this sensor writes,
        or None for a row that is not one.

        dBm(14) says a reading is optical power but not which way the light
        is going, so its root comes from the sensor's own name; every other
        type answers from its type alone (_SFP_TYPE_ROOTS). Its own function
        because the threshold walk has to reach the same verdict for a
        sensor the reading loop went on to discard.
        """
        if sensor_type == self._SENSOR_TYPE_OPTICAL:
            direction = _optical_direction(
                str(names.get(suffix) or "") if names else "",
                str(descrs.get(suffix) or ""))
            return f"sfp_{direction}_dbm" if direction else None
        return self._SFP_TYPE_ROOTS.get(sensor_type)

    def _poll_optic_thresholds(self, device_id: int, device, config: dict,
                               threshold_roots: dict, scales: dict,
                               precisions: dict, now: float) -> None:
        """The alarm/warning levels this device's own transceivers publish,
        into nodes.db's interface_thresholds — see that table's schema
        comment, and alertrules.PUBLISHED_THRESHOLD_RULES for what reads
        them.

        `threshold_roots` maps a sensor's index suffix to the
        (ifIndex, metric root) it belongs to; the caller builds it from the
        walk it has already done, so this costs three column walks and no
        re-walk of anything.

        Gated on _cisco_sensor_table_plausible rather than on which value
        table answered: a Nexus answers the STANDARD sensor table and
        publishes Cisco thresholds beside it, so gating on the value table's
        source would miss the whole NX-OS fleet. Gated again on this device
        having at least one port-mapped optic sensor this pass, so routers,
        PDUs and copper-only switches never pay three dead walks an hour for
        ever.
        """
        if not threshold_roots or not self._cisco_sensor_table_plausible(device):
            return
        if now - self._sensor_threshold_read.get(device_id, 0.0) < \
                self._SENSOR_THRESHOLD_REFRESH_S:
            return
        self._sensor_threshold_read[device_id] = now
        try:
            values, complete = self._walk_column_status(
                device, config, self._CISCO_THRESHOLD_VALUE)
            severities, sev_done = self._walk_column_status(
                device, config, self._CISCO_THRESHOLD_SEVERITY)
            relations, rel_done = self._walk_column_status(
                device, config, self._CISCO_THRESHOLD_RELATION)
        except SnmpError:
            return
        if not (complete and sev_done and rel_done):
            # Same doctrine as _sfp_slot_media's slots_complete, and it
            # matters more here: an empty answer means "this device publishes
            # nothing", which switches optic power alerting OFF for every
            # port on it. A slow device must not be able to say that. All
            # three columns, because a severity row the walk never reached
            # loses its band and drops a level just as silently.
            return

        # (ifIndex, root) -> {column: value}. Several entities can land on
        # one key -- a multi-lane optic reports a lane per entity -- and one
        # entity can quote the same band twice; both collapse the same way,
        # keeping whichever level alerts EARLIER.
        bands: dict[tuple, dict] = {}
        for suffix, raw in values.items():
            entity, _, _index = suffix.partition(".")
            target = threshold_roots.get(entity)
            if target is None or not isinstance(raw, (int, float)):
                continue
            side = self._CISCO_THRESHOLD_SIDE.get(
                int(relations.get(suffix) or 0) or 0)
            band = self._CISCO_THRESHOLD_BAND.get(
                int(severities.get(suffix) or 0) or 0)
            if side is None or band is None:
                continue
            # The threshold is quoted in the scale and precision of ITS OWN
            # entity's reading, never the threshold row's index -- decoding
            # one against another entity's scale is wrong by a factor of a
            # thousand and still looks like a plausible dBm figure.
            value = self._scaled_sensor_value(
                raw, scales.get(entity), precisions.get(entity))
            if target[1] == "sfp_bias_ma":
                # The reading loop above quotes bias in milliamps; a limit
                # left in the MIB's amperes would be a thousand times the
                # metric it governs.
                value *= self._BIAS_A_TO_MA
            column = f"{side}_{band}"
            existing = bands.setdefault(target, {}).get(column)
            if existing is not None:
                value = max(existing, value) if side == "low" \
                    else min(existing, value)
            bands[target][column] = value

        rows = []
        for (if_index, root), columns in sorted(bands.items()):
            if not self._optic_band_sane(root, columns):
                self._log_sensor_diag(
                    device, f"{device['ip']} publishes optic limits for "
                            f"{root} on ifIndex {if_index} that do not make "
                            f"sense together; they are ignored, so that port "
                            f"raises no optical power alerts")
                continue
            rows.append({"if_index": if_index, "metric_root": root,
                         "low_alarm": columns.get("low_alarm"),
                         "low_warn": columns.get("low_warn"),
                         "high_warn": columns.get("high_warn"),
                         "high_alarm": columns.get("high_alarm"),
                         "updated_ts": now})
        self.db.replace_interface_thresholds(
            device_id, self._CISCO_THRESHOLD_SOURCE, rows)

    def _optic_band_sane(self, root: str, columns: dict) -> bool:
        """Whether a published band is coherent enough to alert on.

        A partly-published band is fine and common (older IOS quotes an
        alarm and no warning); a band that contradicts itself is not, and
        the only honest thing to do with it is to alert on none of it. The
        dBm range check is the one gate that can catch a scale misread,
        which is otherwise invisible: -14.4 and -14400 are both numbers.
        """
        lows = [columns[c] for c in ("low_alarm", "low_warn") if c in columns]
        highs = [columns[c] for c in ("high_warn", "high_alarm") if c in columns]
        if root.endswith("_dbm"):
            floor, ceiling = self._DBM_LIMIT_RANGE
            if any(not floor <= v <= ceiling for v in lows + highs):
                return False
        if "low_alarm" in columns and "low_warn" in columns \
                and columns["low_alarm"] > columns["low_warn"]:
            return False
        if "high_alarm" in columns and "high_warn" in columns \
                and columns["high_alarm"] < columns["high_warn"]:
            return False
        return not any(low >= high for low in lows for high in highs)

    def _poll_environment(self, device_id: int, device, config: dict,
                          already: set, now: float) -> None:
        """Device-level temperature/humidity and per-port optic (DOM)
        readings from ENTITY-SENSOR-MIB (RFC 3433) — an environmental
        monitor, a switch's transceivers, or any device exposing its own
        chassis sensors through the standard MIB.

        A sensor is read whether or not it maps to a port; the mapping only
        decides WHICH key a temperature becomes, because 45 C is healthy on
        a chassis, ordinary on an SFP, and a warning in a comms closet. One
        "temp_c" key under one threshold rule alerts on all three:

        - temp_optic_c: the sensor maps to a port (_entity_port_map, the
          same resolution the two dialog reads use).
        - temp_ambient_c: unmapped, AND this device also answers a humidity
          sensor. A chassis essentially never does and a room monitor always
          does, on any vendor's arc — so this generalises past one vendor.
        - temp_chassis_c: everything else unmapped, and the deliberate
          default: a device that cannot be positively identified as an
          environmental monitor must not have its own warmth read as a room
          getting hot. Same key jnxOperatingTable uses, so a device
          answering both never reports two disagreeing temperatures.

        A port-mapped reading additionally becomes a per-port metric —
        `sfp_rx_dbm.<ifIndex>` and its four siblings (_SFP_METRICS) — so an
        alert rule can fire on the failing port rather than a device-wide
        worst-of; there is deliberately no device-level `sfp_*` key, since a
        chassis has no one true Rx power. The same mapping writes
        interfaces.media, rewritten only when the walk answered, so a
        timeout never strips the badge.

        Best-effort, gated twice: nothing runs inside the cadence window
        (_SENSOR_REFRESH_S normally, _SENSOR_REPROBE_S — a cheap hourly
        recheck — for a device that answered nothing), and
        devices.sensor_capable is the probe-once-remember memory
        _poll_poe/_poll_stp/_poll_ups_health also use. Capability is
        recorded only on a probe that learned something new: a device
        already confirmed capable that times out once must not be
        relabelled incapable.
        """
        capable = device["sensor_capable"]
        window = self._SENSOR_REPROBE_S if capable == 0 else self._SENSOR_REFRESH_S
        if now - self._sensor_read.get(device_id, 0.0) < window:
            return
        self._sensor_read[device_id] = now
        try:
            _source, cols, _tried = self._walk_sensor_columns(device, config)
        except SnmpError:
            cols = {}
        if not cols:
            # No answer at all and an outright SnmpError are folded
            # together on purpose here, same as _poll_poe/_poll_stp do for
            # their own tables: either way this poll learned nothing from
            # the device, and "empty" is the only verdict there is to
            # record.
            if capable is None:
                self.db.set_sensor_capable(device_id, False)
            return
        if not capable:
            # None (never probed) and 0 (probed, answered nothing) both
            # flip to 1 here — the latch has to be able to open again now
            # that a second table can be the one that answers.
            self.db.set_sensor_capable(device_id, True)
        sensor_values = cols["values"]
        types = cols["types"]
        scales = cols["scales"]
        precisions = cols["precisions"]
        statuses = cols["statuses"]
        units = cols["units"]
        descrs, descrs_done = self._walk_column_status(
            device, config, self._ENT_PHYSICAL_DESCR)
        interfaces = list(self.db.interfaces(device_id))
        # The name fallback exists for Cisco gear with no alias rows; nothing
        # else should pay a whole entPhysicalName walk every cadence for it.
        names = if_by_name = None
        if self._cisco_sensor_table_plausible(device):
            names = self._walk_column(device, config, self._ENT_PHYSICAL_NAME)
            if_by_name = self._if_index_by_name(interfaces)
        contained_in = self._entity_contained_in(device, config)
        port_map, _alias_rows = self._entity_port_map(
            device, config, names, if_by_name, contained_in)
        # Nothing mapped to a port means a walk that answered nothing useful;
        # the two ENTITY-MIB columns the cage scan needs would be two more
        # dead walks.
        sfp_slots, slots_complete = (
            self._sfp_slot_media(device, config, port_map, contained_in, descrs)
            if port_map else ({}, True))
        slots_complete = slots_complete and descrs_done

        has_humidity = any(int(types.get(suffix) or 0) == self._SENSOR_TYPE_HUMIDITY
                           for suffix in sensor_values)

        optic_temps: list[float] = []
        ambient_temps: list[float] = []
        chassis_temps: list[float] = []
        humidities: list[float] = []
        # (ifIndex, metric root) -> readings seen. A multi-lane optic reports
        # one row per lane, so a port can have several of the same root.
        per_port: dict[tuple[int, str], list[float]] = {}
        optic_ports: set[int] = set()
        # Sensor index suffix -> the (ifIndex, root) its published limits
        # belong to. See _poll_optic_thresholds.
        threshold_roots: dict[str, tuple] = {}
        for suffix, raw in sensor_values.items():
            sensor_type = int(types.get(suffix) or 0)
            try:
                entity = int(suffix)
            except ValueError:
                continue
            if_index = port_map.get(entity)
            if if_index is not None:
                # A failed optic is still an optic: any sensor resolving to
                # a port is proof one is there, whatever it reads.
                optic_ports.add(if_index)
            root = self._sfp_root_for(sensor_type, suffix, names, descrs)
            if if_index is not None and root is not None:
                # Recorded BEFORE the status filter below: a transceiver
                # reading nonoperational for one cadence still publishes the
                # same limits, and dropping them would switch that port's
                # optic alerting off and on again with it.
                threshold_roots[suffix] = (if_index, root)
            if sensor_type not in (self._SENSOR_TYPE_TEMPERATURE,
                                   self._SENSOR_TYPE_HUMIDITY,
                                   self._SENSOR_TYPE_OPTICAL) and root is None:
                continue
            reading = self._decode_entity_sensor(
                suffix, raw, types, scales, precisions, statuses, units, descrs)
            # A sensor reporting anything other than "ok" (unplugged,
            # failed, out of range) contributes nothing rather than a
            # bogus reading — an alert on a physical quantity is worth
            # nothing if it can silently be sourced from a dead probe.
            if reading is None or reading["status"] != "ok":
                continue
            value = reading["value"]
            if sensor_type == self._SENSOR_TYPE_HUMIDITY:
                humidities.append(value)
                continue
            if sensor_type == self._SENSOR_TYPE_TEMPERATURE:
                if if_index is not None:
                    optic_temps.append(value)
                elif has_humidity:
                    ambient_temps.append(value)
                else:
                    chassis_temps.append(value)
            if if_index is None or root is None:
                continue
            if root == "sfp_bias_ma":
                value *= self._BIAS_A_TO_MA
            per_port.setdefault((if_index, root), []).append(value)

        self._poll_optic_thresholds(device_id, device, config, threshold_roots,
                                    scales, precisions, now)

        # Worst (hottest/most humid) sensor of each kind wins — "the hot
        # spot is what matters", the same reasoning VENDOR_HEALTH's
        # column_max probes already use, applied per kind so an SFP
        # running warm never masks a genuinely hot chassis sensor or vice
        # versa.
        samples = []
        if optic_temps:
            samples.append(("temp_optic_c", "Optic temperature", "°C",
                            "gauge", now, max(optic_temps)))
        if ambient_temps:
            samples.append(("temp_ambient_c", "Ambient temperature", "°C",
                            "gauge", now, max(ambient_temps)))
        if chassis_temps and "temp_chassis_c" not in already:
            # `already` is what this poll's vendor-health pass produced —
            # a device with a better vendor-specific chassis reading
            # (Juniper's jnxOperatingTable) keeps it, and this only fills
            # in for one that has none, same as the pre-split code did.
            samples.append(("temp_chassis_c", "Chassis temperature", "°C",
                            "gauge", now, max(chassis_temps)))
        if humidities:
            samples.append(("humidity_pct", "Humidity", "%RH", "gauge", now,
                            max(humidities)))
        # Light levels take the LOWEST lane (the failing one on a multi-lane
        # optic is the dim one); everything else takes the highest, the same
        # "hot spot wins" rule the device keys above use.
        if_descrs = {row["if_index"]: row["descr"] for row in interfaces}
        for (if_index, root), values in sorted(per_port.items()):
            reading_name, unit = _SFP_METRICS[root]
            if root.endswith("_dbm"):
                # A dark lane is one with the light off, not a dim one, so it
                # must not win min() away from three healthy lanes on the same
                # optic. An optic dark on every lane still records the floor:
                # the port's chart stays continuous and its history stays
                # true. What that reading means for an ALERT is alertrules'
                # job, not this one's -- breaches() will not open one on it
                # and evaluate_threshold closes one already open.
                lit = [v for v in values if not is_dark_optic(root, v)]
                worst = min(lit) if lit else DARK_OPTIC_DBM
            else:
                worst = max(values)
            port = if_descrs.get(if_index) or f"if{if_index}"
            samples.append((f"{root}.{if_index}", f"{port} {reading_name}",
                            unit, "gauge", now, worst))
        if samples:
            self.db.record_metric_samples(device_id, samples)
        # DOM sensors win over anything the entity table says about the cage:
        # a port with readings is an optic whatever it is plugged into.
        media_by_if = dict(sfp_slots)
        media_by_if.update({if_index: "optic" for if_index in optic_ports})
        if not slots_complete:
            # A walk cut short is not evidence of anything: a cage it never
            # reached reads as absent, and a module it never reached reads
            # as an empty cage, so the pass would strip or downgrade every
            # SFP badge on a device that is merely slow -- and restore them
            # next cadence, flickering the list every five minutes. Only a
            # port this poll's own sensors proved is an optic may overwrite
            # what is stored.
            for row in interfaces:
                stored = row["media"] if "media" in row.keys() else None
                if (stored in ("sfp", "sfp_empty")
                        and media_by_if.get(row["if_index"]) != "optic"):
                    media_by_if[row["if_index"]] = stored
        media_rows = [{"if_index": if_index, "media": media}
                      for if_index, media in sorted(media_by_if.items())]
        media_rows += [{"if_index": row["if_index"], "media": None}
                       for row in interfaces
                       if row["if_index"] not in media_by_if
                       and ("media" in row.keys() and row["media"])]
        # An empty port map is a timed-out ENTITY-MIB walk, not a chassis
        # with no ports; keep the badges until a walk answers.
        if port_map:
            self.db.update_interface_media(device_id, media_rows)

    # BRIDGE-MIB (RFC 4188) columns used by read_mac_table() to map the
    # forwarding-database entries learned on a switch port back to the
    # ifIndex the rest of the app already keys interfaces by.
    _DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
    _DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
    # Q-BRIDGE-MIB (RFC 4363) dot1qTpFdbPort. The table a VLAN-aware switch
    # actually populates, and the one most modern gear answers instead of
    # dot1dTpFdbTable. Its index is <dot1qFdbId>.<6 MAC bytes> rather than
    # the MAC alone, which is why a six-arc-only parser sees nothing here.
    _DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    # CISCO-VTP-MIB vtpVlanState: the VLAN list for the per-VLAN community
    # trick below. 1 == operational.
    _VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
    # Bounds on the Cisco per-VLAN path: a trunk-heavy switch can carry
    # hundreds of VLANs and this runs while a human waits on a dialog.
    _MAX_VLAN_CONTEXTS = 48
    _VLAN_WALK_BUDGET_S = 15.0

    @staticmethod
    def _fdb_entries(fdb_port: dict, target_ports: set, vlan: str | None,
                     vlan_indexed: bool, port_map: dict | None = None) -> list[dict]:
        """Rows of a forwarding-database column.

        Filtered to `target_ports` — one port for the interface dialog, or
        every bridge port for the whole-device walk, which also passes
        `port_map` (bridge port -> ifIndex) so each entry says which
        interface learned the address.

        Both FDB tables carry the learned MAC in the row's own OID suffix,
        so no second GET is needed for the address column. dot1dTpFdbTable
        is indexed by the MAC alone (six arcs); dot1qTpFdbTable prefixes it
        with the filtering-database id, so the MAC is always the **last
        six** arcs and anything before it is the VLAN.
        """
        entries = []
        for suffix, port in fdb_port.items():
            try:
                if int(port) not in target_ports:
                    continue
            except (TypeError, ValueError):
                continue
            parts = suffix.split(".")
            if len(parts) < 6:
                continue
            if vlan_indexed and len(parts) < 7:
                continue
            try:
                mac = ":".join(f"{int(p):02x}" for p in parts[-6:])
            except ValueError:
                continue
            entry = {
                "mac": mac,
                "vlan": (parts[0] if vlan_indexed else vlan) or "",
            }
            if port_map is not None:
                # Whole-device form: carry which interface learned it. A
                # bridge port with no ifIndex mapping is dropped rather than
                # stored against a guess.
                if_index = port_map.get(int(port))
                if if_index is None:
                    continue
                entry["if_index"] = if_index
            entries.append(entry)
        return entries

    def _bridge_ports_for(self, device, config: dict, if_index: int,
                          deadline: float | None = None):
        """(bridge ports mapping to this ifIndex, whether the device answered).

        A switch that does not answer dot1dBasePortIfIndex at all is a
        different fact from one that answers and simply has no bridge port
        for this interface, and the caller reports them differently.
        """
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
        if not base_port_if_index:
            return set(), False
        ports = set()
        for suffix, value in base_port_if_index.items():
            try:
                if int(value) == if_index:
                    ports.add(int(suffix))
            except (TypeError, ValueError):
                continue
        return ports, True

    def _cisco_vlan_fdb(self, device, config: dict, if_index: int,
                        target_ports: set):
        """Classic Cisco IOS exposes its forwarding database only inside
        per-VLAN SNMP contexts, reached by suffixing the community with
        `@<vlan>`. There is no community to suffix under v3, so that is
        skipped rather than pretended at; and the walk is bounded in both
        VLAN count and wall-clock, because this runs while a human waits on
        an interface dialog and a trunk switch can carry hundreds of VLANs.

        Returns (entries, answered). `answered` reports whether any VLAN
        context produced a bridge-port table, which is how the caller tells
        "this switch cannot tell us" from "it can, and this port has learned
        nothing" on a device whose global context answers neither.
        """
        if snmp_version_of(config) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:          # operational only
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            # VLAN 1002-1005 are the legacy FDDI/token-ring defaults every
            # IOS switch reports and none of them ever learn anything.
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        # The budget is passed INTO each walk, not only checked between
        # VLANs: checking between them let the last VLAN start two
        # unbounded walks (bridge ports, then the forwarding table) after
        # the budget was already spent, which is how a dialog a human is
        # waiting on ran for minutes.
        deadline = time.time() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.time() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            ports = target_ports
            if not ports:
                # On these switches dot1dBasePortIfIndex lives in the same
                # per-VLAN context as the forwarding table, so the global
                # read the caller tried first comes back empty on exactly
                # the devices this path exists for.
                ports, port_answered = self._bridge_ports_for(
                    device, scoped, if_index, deadline=deadline)
                answered = answered or port_answered
                if not ports:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
            entries.extend(self._fdb_entries(fdb_port, ports, vlan, False))
        return entries, answered

    def read_mac_table(self, device_id: int, if_index: int) -> list[dict] | None:
        """Live on-demand read of the MAC addresses learned on one switch
        port — same on-demand-while-the-dialog-is-open shape as read_dom()
        above: walked only when a human asks, never on the poll cycle.

        Three sources, because no single one covers the field: Q-BRIDGE's
        dot1qTpFdbTable first, the original BRIDGE-MIB dot1dTpFdbTable as
        fallback, and classic Cisco IOS per VLAN through the community@vlan
        convention. The first that yields anything wins — they describe the
        same port, so merging them would double-count.

        Returns None (not []) when the device answers none of them, so the
        dialog can say "no data" instead of "zero MACs learned on this
        port" — those are different facts."""
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        target_ports, answered = self._bridge_ports_for(device, config, if_index)
        # detected_vendor, not device["vendor"]: a custom vendor_oid may have
        # replaced the displayed name with whatever the device calls itself,
        # and this gate needs the identified vendor key.
        is_cisco = detected_vendor(device).lower() == "cisco"

        entries = []
        if target_ports:
            entries = self._fdb_entries(
                self._walk_column(device, config, self._DOT1Q_FDB_PORT),
                target_ports, None, True)
            if not entries:
                entries = self._fdb_entries(
                    self._walk_column(device, config, self._DOT1D_FDB_PORT),
                    target_ports, None, False)
        # Deliberately also reached when the global context answered nothing
        # at all: a classic IOS switch hides dot1dBasePortIfIndex in the same
        # per-VLAN contexts as the forwarding table, so bailing out on an
        # empty global read would skip this path on the very devices it is
        # here for.
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_fdb(
                device, config, if_index, target_ports)
            answered = answered or cisco_answered
        if not answered:
            return None

        # One MAC can legitimately appear in several VLANs; dedupe on the
        # pair rather than the address so that stays visible.
        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["mac"], e["vlan"])):
            key = (entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def read_device_mac_table(self, device_id: int) -> list[dict] | None:
        """Every MAC this switch has learned, and on which interface.

        The whole-device counterpart of read_mac_table above, and the same
        three sources in the same order — a forwarding table is a forwarding
        table whether you want one port of it or all of it. What differs is
        that this is not filtered to one port, so the bridge-port map is
        needed in full, and that this runs on the mac_table_interval_s
        schedule rather than while somebody watches a dialog.

        Returns None when the device answers no forwarding table at all,
        which the caller must not confuse with an empty one: "this switch
        cannot tell us" and "this switch has learned nothing" are different
        facts, and only the second should overwrite what we already stored.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        port_map = self._bridge_port_map(device, config)
        is_cisco = detected_vendor(device).lower() == "cisco"
        answered = bool(port_map)

        entries = []
        if port_map:
            ports = set(port_map)
            entries = self._fdb_entries(
                self._walk_column(device, config, self._DOT1Q_FDB_PORT),
                ports, None, True, port_map)
            if not entries:
                entries = self._fdb_entries(
                    self._walk_column(device, config, self._DOT1D_FDB_PORT),
                    ports, None, False, port_map)
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_device_fdb(
                device, config, port_map)
            answered = answered or cisco_answered
        if not answered:
            return None

        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["if_index"], e["mac"],
                                                    e["vlan"])):
            key = (entry["if_index"], entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def _bridge_port_map(self, device, config: dict,
                         deadline: float | None = None) -> dict:
        """bridge port -> ifIndex, for every port the device reports."""
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
        mapping = {}
        for suffix, value in base_port_if_index.items():
            try:
                mapping[int(suffix)] = int(value)
            except (TypeError, ValueError):
                continue
        return mapping

    def _cisco_vlan_device_fdb(self, device, config: dict, port_map: dict):
        """The whole device's forwarding table out of classic IOS per-VLAN
        contexts — the community@vlan path read_mac_table already needs,
        without the per-port filter. Bounded in VLAN count and wall clock
        for the same reason: a trunk switch can carry hundreds of VLANs."""
        if snmp_version_of(config) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        # See _cisco_vlan_fdb: the budget goes into the walks themselves.
        deadline = time.time() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.time() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            mapping = port_map
            if not mapping:
                mapping = self._bridge_port_map(device, scoped, deadline=deadline)
                answered = answered or bool(mapping)
                if not mapping:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
            entries.extend(self._fdb_entries(
                fdb_port, set(mapping), vlan, False, mapping))
        return entries, answered

    # ------------------------------------------------------------- PoE / STP

    @staticmethod
    def _last_index_component(suffix: str) -> int | None:
        """The trailing arc of a table-column suffix, as an int — PoE's
        pethPsePortIndex (see nodeoids' PoE block for why this is treated
        as an ifIndex directly)."""
        parts = suffix.split(".")
        if not parts:
            return None
        try:
            return int(parts[-1])
        except ValueError:
            return None

    def _poll_poe(self, device_id: int, device, config: dict) -> None:
        """POWER-ETHERNET-MIB: PSE budget/consumption and
        per-port admin/detection state, read every poll once the device is
        known to answer it.

        Probed at most once per device: devices.poe_capable is None until
        the first attempt, then True or False, so a device that does not
        implement PoE (the overwhelming majority of a fleet) pays for this
        walk exactly once, ever — not once per poll, and not once per
        process restart either, since the verdict is persisted rather than
        held in memory the way _bulk_repetitions/_credentials are. A device
        already known capable=False is skipped before sending anything.
        """
        capable = device["poe_capable"]
        if capable == 0:
            return
        try:
            pse_power = self._walk_column(device, config, nodeoids.PETH_MAIN_PSE_POWER)
        except SnmpError:
            pse_power = {}
        if not pse_power:
            # Nothing answered even the budget scalar: not a PSE. Recorded
            # only on the FIRST probe (capable is None) — a device that has
            # already been confirmed capable and simply timed out this poll
            # must not be relabeled incapable off one missed walk, the same
            # "a miss is not a verdict" rule read_device_mac_table's None
            # return already follows.
            if capable is None:
                self.db.set_poe_capable(device_id, False)
            return
        if capable is None:
            self.db.set_poe_capable(device_id, True)

        try:
            pse_consumption = self._walk_column(
                device, config, nodeoids.PETH_MAIN_PSE_CONSUMPTION)
        except SnmpError:
            pse_consumption = {}
        budget_w = sum(float(v) for v in pse_power.values()
                       if isinstance(v, (int, float)))
        now = time.time()
        samples = [("poe_budget_w", "PoE power budget", "W", "gauge", now, budget_w)]
        if pse_consumption:
            consumption_w = sum(float(v) for v in pse_consumption.values()
                                if isinstance(v, (int, float)))
            samples.append(("poe_consumption_w", "PoE power in use", "W",
                            "gauge", now, consumption_w))
        self.db.record_metric_samples(device_id, samples)
        self._bump("poe_polls")

        try:
            port_admin = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_ADMIN)
        except SnmpError:
            port_admin = {}
        try:
            port_detect = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_DETECTION)
        except SnmpError:
            port_detect = {}
        try:
            port_power_mw = self._walk_column(device, config, nodeoids.CISCO_POE_PORT_POWER_MW)
        except SnmpError:
            port_power_mw = {}   # not a Cisco PSE, or the extension MIB isn't there

        rows: dict[int, dict] = {}
        for suffix, value in port_admin.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_admin"] = \
                nodeoids.PETH_PORT_ADMIN_ENUM.get(int(value))
        for suffix, value in port_detect.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_detect_status"] = \
                nodeoids.PETH_PORT_DETECTION_ENUM.get(int(value))
        for suffix, value in port_power_mw.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_power_mw"] = int(value)
        if rows:
            self.db.update_interface_poe(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

    def _poll_stp(self, device_id: int, device, config: dict) -> None:
        """BRIDGE-MIB dot1dStp: bridge-wide spanning-tree state
        every poll once the device is known to be a bridge, plus per-port
        state joined onto the SAME bridge-port -> ifIndex map the MAC table
        walk already resolves (_bridge_port_map) — dot1dStpPort IS
        dot1dBasePort, so there is no separate index guess to make here the
        way PoE's port-index assumption is. Probed once, same capability
        memory as PoE — see devices.stp_capable and _poll_poe's docstring.
        """
        capable = device["stp_capable"]
        if capable == 0:
            return
        try:
            response = self._snmp_get(device, config, [
                nodeoids.DOT1D_STP_PROTOCOL_SPEC, nodeoids.DOT1D_STP_PRIORITY,
                nodeoids.DOT1D_STP_TIME_SINCE_CHANGE, nodeoids.DOT1D_STP_TOP_CHANGES,
                nodeoids.DOT1D_STP_DESIGNATED_ROOT, nodeoids.DOT1D_STP_ROOT_COST,
                nodeoids.DOT1D_STP_ROOT_PORT])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            values = {}

        def num(oid):
            vb = values.get(oid)
            if vb is None or vb["type"] in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView", "null"):
                return None
            return vb["value"] if isinstance(vb["value"], (int, float)) else None

        protocol_spec_n = num(nodeoids.DOT1D_STP_PROTOCOL_SPEC)
        if protocol_spec_n is None:
            # Same "a miss on the first probe is a verdict, a miss later is
            # just a miss" rule _poll_poe follows.
            if capable is None:
                self.db.set_stp_capable(device_id, False)
            return
        if capable is None:
            self.db.set_stp_capable(device_id, True)

        priority = num(nodeoids.DOT1D_STP_PRIORITY)
        time_since_change = num(nodeoids.DOT1D_STP_TIME_SINCE_CHANGE)
        top_changes = num(nodeoids.DOT1D_STP_TOP_CHANGES)
        root_cost = num(nodeoids.DOT1D_STP_ROOT_COST)
        root_port = num(nodeoids.DOT1D_STP_ROOT_PORT)
        root_vb = values.get(nodeoids.DOT1D_STP_DESIGNATED_ROOT)
        root_id = (str(root_vb["value"])
                  if root_vb and root_vb["type"] not in
                  ("noSuchObject", "noSuchInstance", "endOfMibView", "null")
                  else None)

        self.db.update_stp_bridge(
            device_id,
            protocol_spec=nodeoids.DOT1D_STP_PROTOCOL_SPEC_ENUM.get(
                int(protocol_spec_n), str(int(protocol_spec_n))),
            priority=int(priority) if priority is not None else None,
            root_id=root_id,
            root_cost=int(root_cost) if root_cost is not None else None,
            root_port=int(root_port) if root_port is not None else None,
            time_since_change_s=(time_since_change / 100.0
                                 if time_since_change is not None else None))
        self._bump("stp_polls")
        if top_changes is not None:
            # A cumulative counter, stored as a gauge sample the same way
            # dot1dStpTopChanges' RFC-defined semantics are — the future
            # alerting wave rules on it *increasing* between samples
            # (series()), not on any single reading, so no rate math
            # belongs here.
            self.db.record_metric_samples(device_id, [
                ("stp_topology_changes", "STP topology changes", "count",
                 "gauge", time.time(), float(top_changes))])

        try:
            port_state = self._walk_column(device, config, nodeoids.DOT1D_STP_PORT_STATE)
        except SnmpError:
            port_state = {}
        if not port_state:
            return
        port_map = self._bridge_port_map(device, config)
        rows: dict[int, dict] = {}
        for suffix, value in port_state.items():
            try:
                bridge_port = int(suffix)
            except ValueError:
                continue
            if_index = port_map.get(bridge_port)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            state = nodeoids.DOT1D_STP_PORT_STATE_ENUM.get(int(value))
            if state is not None:
                rows[if_index] = {"stp_state": state}
        if rows:
            self.db.update_interface_stp(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

    def _run_mac_table(self, device_id: int) -> None:
        """One scheduled forwarding-table walk, on the poll pool.

        Wrapped in except Exception for the same reason _run_one is: a
        worker thread must never die quietly. A device that answers no
        forwarding table leaves what is stored alone rather than deleting
        it — a switch that failed to answer once has not forgotten every
        MAC it knows.
        """
        try:
            entries = self.read_device_mac_table(device_id)
            if entries is None:
                return
            stored = self.db.replace_mac_entries(device_id, entries)
            self._bump("mac_walks")
            self.log.add(NODES, f"Learned {stored} MAC address(es) on device "
                                f"#{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"MAC table walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._mac_running.discard(device_id)

    # ------------------------------------------------------------ ARP tables

    def read_device_arp_table(self, device_id: int) -> list[dict] | None:
        """Every IP-to-MAC mapping this device's ARP cache holds, and on
        which interface. The ARP counterpart of read_device_mac_table,
        with the same None-vs-empty-list contract: None means "nothing
        trustworthy came back" and storage must be left alone, an empty
        list is a genuine "the cache is empty right now" and ages every
        stored row. Each entry is {if_index, ip, mac, entry_type}, the
        MAC in the colon-hex form _fdb_entries produces (nodesdb
        normalises it on the way in).

        Two tables, walked as a FALLBACK and never merged: ipNetToMediaTable
        first, because it is what nearly every agent in the field actually
        populates, then ipNetToPhysicalTable — its IPv6-capable successor,
        and on newer gear sometimes the only one — when the first produced
        no rows at all. Not merged, because a modern agent answers both
        with the same IPv4 mappings and a merge would double-count every
        one of them; so the legacy table wins outright whenever it has
        anything to say, and a device that keeps its IPv6 neighbours only
        in the successor table loses them while it still answers the
        legacy one. That is the documented cost of never double-counting.

        The gate between the two is "produced no rows", NOT "the walk
        failed": an agent with no ipNetToMedia subtree at all answers the
        first GETNEXT with whatever object follows it, which _walk_column
        reads as a clean, complete, empty walk — exactly the case the
        fallback exists for. A walk that stopped for any OTHER reason
        (timeout, an SNMP error, the snmp_walk_max_rows cap, a
        misbehaving agent) returns None from either table rather than
        falling through, because a partial table is worse than none here:
        handing it to replace_arp_entries would mark the un-walked tail
        present=0 and quietly age out thousands of live entries every
        cycle. ARP caches are the one table this poller reads that
        actually meets the row cap on a core router, so this walker is
        deliberately MORE conservative than the MAC walker, which can
        derive "answered" from the bridge-port map and has no equivalent
        of this failure.
        """
        entries, _status, _detail = self._read_arp_table_detail(device_id)
        return entries

    # What _read_arp_table_detail's status word can be: stored/ageable
    # rows came back, the device answers neither table (a fact about the
    # box, logged once), a walk was cut short (a fact about this attempt,
    # storage left alone), or the device is not pollable at all.
    _ARP_OK, _ARP_UNANSWERED, _ARP_INCOMPLETE, _ARP_SKIPPED = (
        "ok", "unanswered", "incomplete", "skipped")

    def _read_arp_table_detail(self, device_id: int) -> tuple:
        """(entries or None, status, detail) — read_device_arp_table's
        answer plus WHY it is None when it is, so _run_arp_table can tell
        "this device does not answer" (say so once) from "this walk was cut
        short" (say why) without re-walking anything."""
        device = self.db.device(device_id)
        if device is None:
            return None, self._ARP_SKIPPED, "no such device"
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None, self._ARP_SKIPPED, "SNMP is disabled"

        entries, answered, legacy_reason = self._walk_arp_table(
            device, config, nodeoids.IP_NET_TO_MEDIA_PHYS_ADDRESS,
            nodeoids.IP_NET_TO_MEDIA_TYPE, self._arp_index_media)
        if entries is None:
            return None, self._ARP_INCOMPLETE, f"ipNetToMediaTable: {legacy_reason}"
        if answered:
            return entries, self._ARP_OK, ""
        entries, answered, modern_reason = self._walk_arp_table(
            device, config, nodeoids.IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
            nodeoids.IP_NET_TO_PHYSICAL_TYPE, self._arp_index_physical)
        if entries is None:
            return None, self._ARP_INCOMPLETE, f"ipNetToPhysicalTable: {modern_reason}"
        if answered:
            return entries, self._ARP_OK, ""
        # Neither produced a row. Each walk's own stop reason rides along
        # (empty when the subtree simply is not there), so a device that
        # timed out with nothing reads differently in the log from one that
        # cleanly has no such table — even though storage is left alone
        # either way.
        why = "; ".join(r for r in (legacy_reason, modern_reason) if r)
        return None, self._ARP_UNANSWERED, (
            "answers neither ipNetToMediaTable nor ipNetToPhysicalTable"
            + (f" ({why})" if why else ""))

    def _walk_arp_table(self, device, config: dict, phys_oid: str,
                        type_oid: str, parse_index) -> tuple:
        """One ARP table: (entries or None, whether the phys-address column
        produced any row at all, why the walk stopped when it did not
        finish).

        `entries` is None whenever the phys-address walk did not reach the
        end of its subtree — see read_device_arp_table for why a partial
        table must never be stored. "Produced any row" is judged on the
        raw walk, before invalid(2) rows and undecodable MACs are dropped,
        so a table whose every row is being deleted still counts as
        answered (an empty cache) rather than sending the caller to the
        fallback table for the same device.

        The type column is best effort: it is the same row count as the
        phys column, so a walk that finished the first will nearly always
        finish the second, and a row whose type never arrived is kept with
        entry_type '' rather than the whole table being thrown away over
        the one column that only ever removes rows.
        """
        try:
            phys, complete, reason = self._walk_column_detail(device, config, phys_oid)
        except SnmpError as exc:
            return None, False, f"SNMP error: {exc}"
        # Complete first, then empty: a timeout or an error on the very
        # first GETBULK is an empty `phys` too, and read as "this table
        # produced no rows" it sent the caller on to the successor table —
        # so a modern agent answering both would alternate sources across
        # cycles whenever the legacy walk transiently timed out, flapping
        # `present` on every IPv6-only row, and a device that merely timed
        # out twice was logged as answering neither table. Only a walk that
        # genuinely reached the end of its subtree and found nothing there
        # is the fallback's case; every other way of stopping is None, as
        # read_device_arp_table promises.
        if not complete:
            return None, bool(phys), reason
        if not phys:
            return [], False, reason
        try:
            types = self._walk_column(device, config, type_oid)
        except SnmpError:
            types = {}

        entries = []
        for suffix, raw in phys.items():
            parsed = parse_index(suffix)
            if parsed is None:
                continue
            if_index, ip = parsed
            octets = _octets_from_value(raw)
            if len(octets) != 6:
                # An incomplete entry, a DLCI, a tunnel endpoint: PhysAddress
                # is whatever the medium uses, and only six octets is a MAC
                # this app can join on. Not stored as a guess.
                continue
            type_n = types.get(suffix)
            try:
                type_n = int(type_n) if type_n is not None else None
            except (TypeError, ValueError):
                type_n = None
            if type_n == 2:
                # invalid(2): the MIB's own "this row is going away" marker,
                # and an agent may leave such rows visible for a while.
                continue
            entries.append({
                "if_index": if_index,
                "ip": ip,
                "mac": ":".join(f"{b:02x}" for b in octets),
                "entry_type": nodeoids.IP_NET_TO_MEDIA_TYPE_ENUM.get(type_n, "")
                              if type_n is not None else "",
            })
        return entries, True, ""

    @staticmethod
    def _arp_index_media(suffix: str) -> tuple[int, str] | None:
        """(ifIndex, dotted IPv4) out of an ipNetToMediaTable row suffix,
        which is ifIndex.a.b.c.d — both facts are in the index, which is
        why the net-address column is never walked."""
        parts = suffix.split(".")
        if len(parts) != 5:
            return None
        try:
            if_index = int(parts[0])
            address = ipaddress.ip_address(bytes(int(p) for p in parts[1:]))
        except ValueError:
            return None
        return if_index, str(address)

    @staticmethod
    def _arp_index_physical(suffix: str) -> tuple[int, str] | None:
        """(ifIndex, address text) out of an ipNetToPhysicalTable row
        suffix: ifIndex.addrType.addrLen.<addrLen arcs>, InetAddressType
        1 = ipv4 (4 arcs), 2 = ipv6 (16), and the zoned forms 3 = ipv4z
        (4 + a 4-arc zone) and 4 = ipv6z (16 + 4), whose zone is dropped
        because the interface the row is on already says which link it
        is. Any other type (DNS names are legal here) is skipped. An IPv6
        address is stored in its compressed lowercase form, the one form
        every later search or join can spell the same way."""
        parts = suffix.split(".")
        if len(parts) < 3:
            return None
        try:
            if_index, addr_type, addr_len = (int(parts[0]), int(parts[1]),
                                             int(parts[2]))
            arcs = [int(p) for p in parts[3:]]
        except ValueError:
            return None
        if addr_len != len(arcs):
            return None
        width = {1: 4, 2: 16, 3: 4, 4: 16}.get(addr_type)
        if width is None or addr_len < width:
            return None
        if addr_type in (1, 2) and addr_len != width:
            return None
        try:
            address = ipaddress.ip_address(bytes(arcs[:width]))
        except ValueError:
            return None
        return if_index, str(address)

    def _run_arp_table(self, device_id: int) -> None:
        """One scheduled ARP-cache walk, mirroring _run_mac_table: a worker
        thread must never die quietly, and a device whose walk stored
        nothing leaves its stored rows alone — a router that failed to
        answer once has not forgotten every host it talks to.

        What differs is that the two ways of storing nothing are told
        apart and said out loud, ONCE per transition rather than per
        interval: "answers neither table" is a fact about the box an
        operator who opted a whole profile in needs to see exactly once
        per device, and "cut short" names the reason (the row cap, most
        likely) so the fix — raise snmp_walk_max_rows, or take the device
        off the schedule — is in the same line. Recovery is logged too, so
        the log reads as a state change and not a stream."""
        try:
            entries, status, detail = self._read_arp_table_detail(device_id)
            if entries is None:
                if status == self._ARP_SKIPPED:
                    return
                if device_id not in self._arp_unanswered:
                    self._arp_unanswered.add(device_id)
                    if status == self._ARP_UNANSWERED:
                        self.log.add(NODES, f"Device #{device_id} {detail}; "
                                            f"its ARP cache is not being stored. "
                                            f"Set its ARP table interval to 0 to "
                                            f"stop asking.")
                    else:
                        self.log.add(NODES, f"ARP walk of device #{device_id} was "
                                            f"cut short and its stored table left "
                                            f"alone ({detail})")
                return
            stored = self.db.replace_arp_entries(device_id, entries)
            self._bump("arp_walks")
            if device_id in self._arp_unanswered:
                self._arp_unanswered.discard(device_id)
                self.log.add(NODES, f"Device #{device_id} answers its ARP table "
                                    f"again")
            self.log.add(NODES, f"Learned {stored} ARP entr"
                                f"{'y' if stored == 1 else 'ies'} on device "
                                f"#{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"ARP table walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._arp_running.discard(device_id)

    # ------------------------------------------------- LLDP/CDP neighbours

    # LLDP-MIB columns walked for one device's remote-systems table. Each
    # entry is walked as its own column (the same one-GETBULK-walk-per-
    # column shape _fdb_entries' callers already use for the FDB), then
    # joined back together on the shared lldpRemTimeMark.lldpRemLocalPortNum.
    # lldpRemIndex suffix in _walk_lldp — a device answering some columns
    # and timing out on others still contributes a row with whatever did
    # answer, rather than the whole walk failing on the slowest column.
    _LLDP_COLUMNS = {
        "chassis_id_subtype": nodeoids.LLDP_REM_CHASSIS_ID_SUBTYPE,
        "chassis_id":         nodeoids.LLDP_REM_CHASSIS_ID,
        "port_id_subtype":    nodeoids.LLDP_REM_PORT_ID_SUBTYPE,
        "port_id":            nodeoids.LLDP_REM_PORT_ID,
        "port_descr":         nodeoids.LLDP_REM_PORT_DESC,
        "sys_name":           nodeoids.LLDP_REM_SYS_NAME,
        "sys_descr":          nodeoids.LLDP_REM_SYS_DESC,
    }
    _CDP_COLUMNS = {
        "device_id":   nodeoids.CDP_CACHE_DEVICE_ID,
        "device_port": nodeoids.CDP_CACHE_DEVICE_PORT,
        "platform":    nodeoids.CDP_CACHE_PLATFORM,
        "address":     nodeoids.CDP_CACHE_ADDRESS,
    }

    def read_device_neighbors(self, device_id: int) -> list[dict] | None:
        """Every LLDP neighbour this device reports, plus CDP as a
        fallback/supplement on Cisco gear (classic IOS in particular often
        speaks CDP only). The whole-device counterpart of
        read_device_mac_table, with the same None-vs-empty-list contract:
        None means neither protocol answered anything at all — storage
        must be left alone — while an empty list is a genuine "this device
        has no neighbours right now" and ages every stored row.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        entries, lldp_answered = self._walk_lldp(device, config)
        answered = lldp_answered
        if detected_vendor(device).lower() == "cisco":
            cdp_entries, cdp_answered = self._walk_cdp(device, config)
            entries.extend(cdp_entries)
            answered = answered or cdp_answered
        if not answered:
            return None
        return entries

    def _walk_lldp(self, device, config: dict) -> tuple[list[dict], bool]:
        """(neighbour rows, whether the device answered anything). See
        nodeoids' LLDP block for why lldpRemLocalPortNum is used directly
        as the local ifIndex rather than resolved through lldpLocPortTable.
        """
        values: dict[str, dict] = {}
        answered = False
        for key, oid in self._LLDP_COLUMNS.items():
            try:
                column = self._walk_column(device, config, oid)
            except SnmpError:
                column = {}
            if column:
                answered = True
            values[key] = column
        if not answered:
            return [], False
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 3:
                continue                          # not a real 3-arc index
            try:
                local_port = int(parts[-2])
            except ValueError:
                continue
            chassis_subtype = values["chassis_id_subtype"].get(suffix)
            entries.append({
                "if_index": local_port,
                "protocol": "lldp",
                "rem_index": suffix,
                "chassis_id": str(values["chassis_id"].get(suffix) or ""),
                "chassis_id_subtype": (int(chassis_subtype)
                                       if isinstance(chassis_subtype, (int, float))
                                       else None),
                "port_id": str(values["port_id"].get(suffix) or ""),
                "port_id_subtype": (int(values["port_id_subtype"].get(suffix))
                                    if isinstance(values["port_id_subtype"].get(suffix),
                                                 (int, float)) else None),
                "port_descr": str(values["port_descr"].get(suffix) or ""),
                "sys_name": str(values["sys_name"].get(suffix) or ""),
                "sys_descr": str(values["sys_descr"].get(suffix) or ""),
            })
        return entries, True

    def _walk_cdp(self, device, config: dict) -> tuple[list[dict], bool]:
        """(neighbour rows, whether the device answered anything) from
        CISCO-CDP-MIB's cdpCacheTable. Indexed by cdpCacheIfIndex directly,
        so — unlike LLDP above — no local-port assumption is needed."""
        values: dict[str, dict] = {}
        answered = False
        for key, oid in self._CDP_COLUMNS.items():
            try:
                column = self._walk_column(device, config, oid)
            except SnmpError:
                column = {}
            if column:
                answered = True
            values[key] = column
        if not answered:
            return [], False
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            try:
                if_index = int(parts[0])
            except ValueError:
                continue
            device_id_text = str(values["device_id"].get(suffix) or "")
            entries.append({
                "if_index": if_index,
                "protocol": "cdp",
                "rem_index": suffix,
                "chassis_id": device_id_text,
                "sys_name": device_id_text,
                "port_id": str(values["device_port"].get(suffix) or ""),
                "platform": str(values["platform"].get(suffix) or ""),
                "remote_address": _format_cdp_address(values["address"].get(suffix)),
            })
        return entries, True

    def _run_lldp_table(self, device_id: int) -> None:
        """One scheduled LLDP/CDP walk, mirroring _run_mac_table exactly:
        a worker thread must never die quietly, and a device that answers
        neither protocol leaves its stored neighbours alone rather than
        deleting them — see read_device_neighbors' None contract."""
        try:
            entries = self.read_device_neighbors(device_id)
            if entries is None:
                return
            stored = self.db.replace_neighbors(device_id, entries)
            self._bump("lldp_walks")
            self.log.add(NODES, f"Learned {stored} LLDP/CDP neighbour(s) on "
                                f"device #{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"LLDP/CDP walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._lldp_running.discard(device_id)

    # ------------------------------------------------- VLAN membership

    def read_device_vlans(self, device_id: int) -> dict | None:
        """Every VLAN this device names, which of its ports are trunk/
        access (and a trunk's native VLAN), and which VLANs actually cross
        which port — the whole-device counterpart of read_device_neighbors,
        with the same None-vs-dict contract: None means nothing answered at
        all (storage untouched by _run_vlan_table); a dict — even one whose
        lists are all empty — is a genuine "walked, and this is what came
        back", which is what lets a membership that has truly gone away age
        its stored rows out instead of sitting present forever.

        Four sources, applied in authority order:
          (a) dot1dBasePortIfIndex resolves a BRIDGE-MIB bridge port number
              to the ifIndex the rest of the app keys interfaces by (the
              same table the FDB walk resolves through _bridge_port_map).
              Absent entirely on some small switches, which is not the same
              fact as "this device has no ports": see `resolve` below for
              why the bridge port number is used as the ifIndex directly
              rather than dropping every membership the device reports.
          (b) Q-BRIDGE-MIB dot1qVlanStatic*/dot1qVlanCurrent* — the
              standards path. The current-table columns are consulted only
              where their static counterpart came back empty: a VTP/GVRP
              client legitimately carries no static configuration of its
              own.
          (c) CISCO-VTP-MIB, Cisco only (detected_vendor gate, same one
              _walk_cdp uses) — and a Cisco answer for a port SUPERSEDES
              whatever the standards path said about that same port.
              vlanTrunkPortVlansEnabled is the trunk's configured allow
              list; dot1q's own egress bitmap on classic IOS often reflects
              only VLANs with a currently active member, which is a
              narrower and more volatile fact than what is actually
              configured to cross the trunk.
          (d) mac_entries' own vlan column, for a port neither (b) nor (c)
              described at all: a VLAN whose traffic this device has
              learned on a port is evidence that VLAN crosses it, even
              though no VLAN table said so. Evidence, not configuration —
              reached only for a port with no authoritative answer, and
              never allowed to override one.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        # The budget goes INTO each walk (see _cisco_vlan_fdb's own
        # comment on why): checking only between walks would let the last
        # one of eight start after the budget was already spent.
        deadline = time.time() + _VLAN_WALK_BUDGET_S
        answered = False

        def walk(oid: str, *, evidence: bool = True) -> dict:
            nonlocal answered
            column = self._walk_column(device, config, oid, deadline=deadline)
            if column and evidence:
                answered = True
            return column

        # (a) bridge port -> ifIndex. BRIDGE-MIB, not a VLAN table: it only
        # helps interpret a bridge port number the VLAN columns below might
        # report, and answering it is not itself evidence this device has
        # ANY VLAN-related MIB at all — a switch with nothing but plain
        # bridging support would otherwise flip `answered` true here and
        # get a genuine "walked, found nothing" dict below (aging every
        # stored row to present=0 and logging a 0-row walk every hour)
        # instead of the None this docstring promises for "nothing VLAN-
        # related answered". evidence=False keeps this call out of that
        # decision entirely.
        port_map = _int_keyed(walk(nodeoids.DOT1D_BASE_PORT_IFINDEX,
                                   evidence=False))

        def resolve(bridge_port: int):
            if port_map:
                return port_map.get(bridge_port)
            # dot1dBasePortIfIndex did not answer at all. Plenty of small
            # switches number their bridge ports 1:1 with ifIndex and never
            # populate this table, so treating the bridge port number as
            # the ifIndex directly recovers real data on exactly those
            # devices — a wrong guess on a device numbered differently only
            # misattributes which port a VLAN belongs to, a smaller loss
            # than dropping every membership this device reports.
            return bridge_port

        described_ports: set = set()
        port_mode: dict = {}
        port_native: dict = {}
        memberships: dict = {}   # (if_index, vlan) -> tagged
        vlan_names: dict = {}

        # (b) standards path
        static_names = walk(nodeoids.DOT1Q_VLAN_STATIC_NAME)
        egress = walk(nodeoids.DOT1Q_VLAN_STATIC_EGRESS)
        if not egress:
            egress = walk(nodeoids.DOT1Q_VLAN_CURRENT_EGRESS)
        untagged = walk(nodeoids.DOT1Q_VLAN_STATIC_UNTAGGED)
        if not untagged:
            untagged = walk(nodeoids.DOT1Q_VLAN_CURRENT_UNTAGGED)

        if static_names:
            for suffix, value in static_names.items():
                try:
                    vlan_names[int(suffix)] = str(value or "")
                except (TypeError, ValueError):
                    continue
        else:
            # No static VLAN table at all — the current-table bitmaps' own
            # suffixes are the only standards-path evidence a VLAN id
            # exists, and dot1qVlanCurrentTable has no name column to go
            # with them.
            for suffix in set(egress) | set(untagged):
                try:
                    vlan_names.setdefault(int(suffix), "")
                except (TypeError, ValueError):
                    continue

        def port_sets(column: dict) -> dict:
            out = {}
            for suffix, raw in column.items():
                try:
                    vlan = int(suffix)
                except (TypeError, ValueError):
                    continue
                ports = set()
                for bridge_port in _decode_port_list(raw):
                    if_index = resolve(bridge_port)
                    if if_index is not None:
                        ports.add(if_index)
                out[vlan] = ports
            return out

        egress_ports = port_sets(egress)
        untagged_ports = port_sets(untagged)
        # A port present in egress but not untagged is tagged; present in
        # both is untagged (dot1qPvid below is which VLAN that untagged
        # membership actually means for the port, i.e. its native VLAN).
        for vlan in set(egress_ports) | set(untagged_ports):
            eg = egress_ports.get(vlan, set())
            un = untagged_ports.get(vlan, set())
            for if_index in eg | un:
                described_ports.add(if_index)
                memberships[(if_index, vlan)] = if_index not in un

        for suffix, value in walk(nodeoids.DOT1Q_PVID).items():
            try:
                bridge_port = int(suffix)
                native = int(value)
            except (TypeError, ValueError):
                continue
            if_index = resolve(bridge_port)
            if if_index is None:
                continue
            port_native[if_index] = native
            described_ports.add(if_index)

        # (c) Cisco path — supersedes (b) per port
        if detected_vendor(device).lower() == "cisco":
            # vtpVlanEntry is indexed {managementDomainIndex, vtpVlanIndex},
            # not vtpVlanIndex alone -- a real agent answers a suffix like
            # "1.10", and int() on that raises. Same fix as _cisco_vlan_fdb's
            # suffix.split(".")[-1] below, applied to the name column that
            # copy of the logic doesn't touch.
            for suffix, value in walk(nodeoids.VTP_VLAN_NAME).items():
                vlan_id = suffix.split(".")[-1]
                if not vlan_id.isdigit():
                    continue
                vlan = int(vlan_id)
                # VLAN 1002-1005 are the legacy FDDI/token-ring defaults
                # every IOS switch names whether or not anything is
                # actually configured on them (see _cisco_vlan_fdb's
                # identical exclusion for the FDB walk). Leaving them out
                # of vlan_names keeps them out of existing_vlans below too,
                # so a default trunk doesn't grow four boilerplate VLANs on
                # top of whatever the operator actually configured.
                if 1002 <= vlan <= 1005:
                    continue
                vlan_names[vlan] = str(value or "")

            trunk_status = _int_keyed(walk(nodeoids.VTP_TRUNK_DYNAMIC_STATUS))
            trunk_native = _int_keyed(walk(nodeoids.VTP_TRUNK_NATIVE_VLAN))

            # vlanTrunkPortVlansEnabled* is the trunk's configured ALLOW
            # LIST, not the VLANs actually crossing it -- a trunk left at
            # IOS's default `switchport trunk allowed vlan all` answers all
            # four bitmaps fully set (every VLAN 0-4094 "allowed"), which is
            # not evidence any of those VLANs exist. The invariant this
            # walk must hold: a VLAN never appears on a link unless the
            # device itself says that VLAN exists -- vlan_names (vtpVlanName
            # above, dot1qVlanStaticName from the standards path) plus the
            # Q-BRIDGE egress/untagged bitmaps' own suffixes are that
            # evidence, so the allow-list is intersected against them below
            # rather than materialised as membership directly.
            existing_vlans = set(vlan_names) | set(egress_ports) | set(untagged_ports)

            cisco_vlans_by_port: dict = {}
            for oid, base in (
                (nodeoids.VTP_TRUNK_VLANS_ENABLED, 0),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_2K, 1024),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_3K, 2048),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_4K, 3072),
            ):
                for suffix, raw in walk(oid).items():
                    try:
                        if_index = int(suffix)
                    except (TypeError, ValueError):
                        continue
                    cisco_vlans_by_port.setdefault(if_index, set()).update(
                        _decode_vlan_bitmap(raw, base))

            cisco_ports = (set(trunk_status) | set(trunk_native)
                          | set(cisco_vlans_by_port))
            for if_index in cisco_ports:
                status = trunk_status.get(if_index)
                # The trunk allow-list is only meaningful for a port that is
                # actually trunking. On classic IOS, vlanTrunkPortDynamicStatus
                # carries a row for EVERY switchport -- access ports included,
                # reporting notTrunking(2) -- and such a port still answers
                # vlanTrunkPortVlansEnabled with its configured allow list
                # (default: all VLANs) and vlanTrunkPortNativeVlan (default:
                # 1). Applying those unconditionally, as this used to, threw
                # away a correctly-read access VLAN (dot1qPvid, via the
                # standards path) in favour of a fabricated ~4094-VLAN trunk
                # on every access port. So: only status == trunking(1) gets
                # the Cisco override below; anything else (notTrunking, or a
                # port this column simply never covers) keeps whatever the
                # standards path already recorded for it, and is merely
                # labelled here when IOS says outright that it is an access
                # port.
                if status != 1:
                    if status == 2:
                        port_mode[if_index] = "access"
                    continue

                # Supersede: drop whatever the standards path recorded for
                # this port before writing the Cisco answer over it.
                for key in [k for k in memberships if k[0] == if_index]:
                    del memberships[key]
                described_ports.add(if_index)
                port_mode[if_index] = "trunk"
                native = trunk_native.get(if_index)
                if native is not None:
                    port_native[if_index] = native
                # Allow-list ∩ VLANs that exist -- see existing_vlans above.
                # A default `allowed vlan all` trunk's ~4094-bit allow-list
                # collapses down to the handful the device actually has.
                vlans = cisco_vlans_by_port.get(if_index, set()) & existing_vlans
                if vlans:
                    for vlan in vlans:
                        memberships[(if_index, vlan)] = not (
                            native is not None and vlan == native)
                elif native is not None and native in existing_vlans:
                    memberships[(if_index, native)] = False

        if not answered:
            return None

        # (d) mac_entries fallback — evidence, not configuration, only for
        # a port neither (b) nor (c) described at all.
        for row in self.db.mac_entries_for(device_id):
            if_index = row["if_index"]
            if if_index in described_ports:
                continue
            vlan_text = str(row["vlan"] or "").strip()
            if not vlan_text.isdigit():
                continue
            memberships.setdefault((if_index, int(vlan_text)), True)

        # Bound the write: the same "cap rather than fail" idiom
        # _cisco_vlan_fdb's _MAX_VLAN_CONTEXTS slice uses. Now that a Cisco
        # trunk's allow-list is intersected against VLANs the device says
        # exist (above) rather than materialised wholesale, a real device's
        # VLAN count is bounded by what it actually has configured -- a few
        # hundred at most -- so this should not bind in practice. If it
        # ever does, keep VLANs with a real port membership (actual
        # configuration/traffic) ahead of merely-named-but-unused ones, and
        # break remaining ties by id rather than truncating to the lowest
        # ids: a deployment's important VLANs are exactly as likely to be
        # numbered 1000+ as under 512, and silently dropping the
        # highest-numbered ones is the same bug this fix exists for.
        all_vlan_ids = set(vlan_names) | {vlan for _, vlan in memberships}
        vlans_with_membership = {vlan for _, vlan in memberships}
        kept_vlans = set(sorted(
            all_vlan_ids,
            key=lambda vlan: (0 if vlan in vlans_with_membership else 1, vlan),
        )[:_MAX_VLANS])

        vlans_out = [{"vlan": vlan, "name": vlan_names.get(vlan, "")}
                    for vlan in sorted(kept_vlans)]
        port_ifindexes = (set(port_mode) | set(port_native)
                         | {if_index for if_index, _ in memberships})
        ports_out = [
            {"if_index": if_index, "mode": port_mode.get(if_index, ""),
             "native_vlan": port_native.get(if_index)}
            for if_index in sorted(port_ifindexes)]
        memberships_out = [
            {"if_index": if_index, "vlan": vlan, "tagged": tagged}
            for (if_index, vlan), tagged in memberships.items()
            if vlan in kept_vlans]

        return {"vlans": vlans_out, "ports": ports_out,
                "memberships": memberships_out}

    def _run_vlan_table(self, device_id: int) -> None:
        """One scheduled per-port VLAN membership walk, mirroring
        _run_lldp_table exactly: a worker thread must never die quietly,
        and a device that answers no VLAN table at all leaves its stored
        rows alone rather than deleting them — see read_device_vlans'
        None contract."""
        try:
            result = self.read_device_vlans(device_id)
            if result is None:
                return
            self.db.replace_vlans(device_id, result["vlans"])
            self.db.replace_vlan_ports(device_id, result["ports"])
            stored = self.db.replace_port_vlans(device_id, result["memberships"])
            self._bump("vlan_walks")
            self.log.add(NODES, f"Learned {stored} VLAN membership row(s) on "
                                f"device #{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"VLAN walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._vlan_running.discard(device_id)

    # Bounds for the OID browser. Generous enough to be useful on a switch,
    # small enough that a dialog someone is sitting in front of cannot hang:
    # a full walk of a large device is tens of thousands of objects and
    # minutes of GETNEXTs, which is why this browses subtrees rather than
    # offering "walk everything".
    # Bounds on the on-demand credential probe in working_config().
    _PROBE_BUDGET_S = 8.0
    _PROBE_RETRY_S = 60.0

    _BROWSE_MAX_ROWS = 600
    _BROWSE_BUDGET_S = 20.0

    def walk_subtree(self, device_id: int, base_oid: str,
                     max_rows: int | None = None,
                     budget_s: float | None = None) -> dict | None:
        """Live on-demand GETNEXT walk of one subtree, for the OID browser.

        Same on-demand shape as read_dom()/read_mac_table(): run only while a
        human is looking at the dialog, never on the poll cycle.

        Deliberately not _walk_column(): that returns index-suffix -> value
        for one table column and caps at 512 rows, which is right for its
        callers and wrong here. A browser needs the whole OID, the SNMP type
        and the raw value of every object it passed, and it needs to say why
        it stopped — silently truncating at a cap would make a partial walk
        look like the device's complete answer.

        Returns None when the device is unknown or has SNMP disabled.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None
        base = (base_oid or "").strip().strip(".")
        if not base or not all(part.isdigit() for part in base.split(".")):
            raise ValueError("An OID must be numeric, like 1.3.6.1.2.1.1")

        max_rows = int(max_rows or self._BROWSE_MAX_ROWS)
        budget = float(budget_s or self._BROWSE_BUDGET_S)
        rows, stopped = self._walk_from(device, config, base, max_rows, budget)
        return {"base": base, "rows": rows, "stopped": stopped,
                "complete": stopped == "end of subtree"}

    def _bulk_settings(self, device, config: dict) -> tuple:
        """(use GETBULK, repetitions) for a walk of this device.

        The repetition count is remembered per device: an agent that
        answered "tooBig" once will answer it again, and re-learning the
        same limit at the start of every walk costs a wasted round trip
        each time.

        The GETNEXT FALLBACK is remembered the same way, as a learned count
        of 0. It was not: an agent that refuses GETBULK at any repetition
        count was recorded as "1 repetition" and so re-asked with GETBULK
        on the next column of the next poll, for ever, paying a wasted
        round trip per walk against exactly the devices least able to
        afford one.
        """
        settings = self.db.settings()
        configured = int(settings.get("snmp_bulk_max_repetitions", 40) or 0)
        raw_version = config.get("snmp_version")
        is_v1 = raw_version is not None and int(raw_version) == 0
        if is_v1 or configured <= 0:
            return False, 0
        learned = self._bulk_repetitions.get(device["id"])
        if learned == 0:
            return False, 0
        return True, min(configured, learned) if learned else configured

    def _remember_repetitions(self, device, repetitions: int, *,
                              use_bulk: bool = True) -> None:
        self._bulk_repetitions[device["id"]] = (
            max(1, int(repetitions)) if use_bulk else 0)

    def _walk_from(self, device, config, base: str, max_rows: int,
                   budget_s: float, cancelled=None,
                   on_row=None) -> tuple[list[dict], str]:
        """The subtree walk itself: rows collected, and why it stopped.

        Shared by walk_subtree (one subtree, in front of a waiting human)
        and the background whole-device walk, which differ only in their
        bounds and in having a cancel — not in what a walk is. `cancelled`
        is polled between requests; `on_row` sees each row as it arrives so
        a job can report progress without exposing its list.

        GETBULK on v2c and v3, over one shared socket, the same way
        _walk_column already walks a table column — a GETNEXT and a fresh
        socket per row put a fleet-wide first identification in the hours.
        """
        deadline = time.time() + budget_s
        rows: list[dict] = []
        stopped = "end of subtree"
        current = base
        use_bulk, repetitions = self._bulk_settings(device, config)
        session = self._session_for(device, config)
        try:
            while True:
                if cancelled is not None and cancelled():
                    stopped = f"cancelled after {len(rows)} row(s)"
                    break
                if len(rows) >= max_rows:
                    stopped = f"stopped at the {max_rows}-row limit"
                    break
                if time.time() > deadline:
                    stopped = f"stopped after {budget_s:.0f}s"
                    break
                try:
                    response = self._walk_request(
                        session, device, config, current,
                        PDU_GETBULK if use_bulk else PDU_GETNEXT, repetitions)
                except SnmpTimeout:
                    # Name what was actually tried. "The device stopped
                    # answering" alone sent an operator hunting the device
                    # when the answer was on this end — which credential we
                    # used, and against which address and port.
                    stopped = (
                        f"no reply from {device['ip']}:{DEFAULT_SNMP_PORT} "
                        f"using {_credential_label(config)}"
                        + (f" — stopped after {len(rows)} row(s)" if rows else ""))
                    break
                except SnmpError as exc:
                    stopped = f"SNMP error: {exc}"
                    break
                if use_bulk and response.error_status == 1:      # tooBig
                    if repetitions <= 1:
                        use_bulk = False
                        self._remember_repetitions(device, 0, use_bulk=False)
                    else:
                        repetitions = max(1, repetitions // 2)
                        self._remember_repetitions(device, repetitions)
                    continue
                if response.error_status:
                    stopped = _error_status_reason(response, base)
                    break
                if not response.varbinds:
                    stopped = "the device returned nothing"
                    break
                done = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base or oid.startswith(base + ".")):
                        done = True          # walked out of the subtree
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance",
                                      "endOfMibView"):
                        done = True
                        break
                    # An answer must lexicographically follow the request; a
                    # broken agent that echoes the request OID (or goes
                    # backwards) would otherwise fill the dialog with the
                    # same row until the cap or the clock stopped it,
                    # presented as the device's answer.
                    if _oid_key(oid) <= _oid_key(current):
                        stopped = ("the device answered with a non-increasing "
                                   f"OID ({oid}) — its SNMP agent is "
                                   f"misbehaving")
                        done = True
                        break
                    row = {"oid": oid, "type": vb["type"],
                           "value": vb["value"], "text": vb.get("text")}
                    rows.append(row)
                    if on_row is not None:
                        on_row(row)
                    current = oid
                    if len(rows) >= max_rows:
                        stopped = f"stopped at the {max_rows}-row limit"
                        done = True
                        break
                if done:
                    break
        finally:
            session.close()
        return rows, stopped

    # The whole-device walk starts here rather than at .1: 1.3.6.1 is
    # internet(1), which is every MIB an agent can sensibly hold. Starting
    # above it would miss nothing real and starting below it invites an
    # agent to walk its own private branches forever.
    _FULL_WALK_BASE = "1.3.6.1"

    def start_oid_walk(self, device_id: int) -> dict:
        """Begin a whole-device walk in the background, or report the one
        already running for this device.

        Held in memory rather than in a table: a walk result is transient —
        it exists to be downloaded once and then thrown away — and a row
        surviving a restart would describe a job whose thread is gone.
        """
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and job.running:
                return job.status()
            settings = self.db.settings()
            job = _OidWalkJob(
                self, device_id,
                base=self._FULL_WALK_BASE,
                max_rows=int(settings.get("oid_walk_max_rows", 100_000)),
                budget_s=float(settings.get("oid_walk_budget_s", 600.0)))
            self._oid_walks[device_id] = job
        job.start()
        return job.status()

    def oid_walk_status(self, device_id: int, with_rows: bool = False) -> dict | None:
        job = self._oid_walks.get(device_id)
        return None if job is None else job.status(with_rows=with_rows)

    def cancel_oid_walk(self, device_id: int) -> bool:
        job = self._oid_walks.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def forget_oid_walk(self, device_id: int) -> None:
        """Drop a finished walk's rows. Called once the file has been handed
        over, so a 100k-row walk does not sit in memory for the life of the
        process."""
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and not job.running:
                self._oid_walks.pop(device_id, None)

    def browse_bases(self, device_id: int) -> list[dict]:
        """The subtrees the browser opens on: the two every SNMP agent
        answers, plus this device's own vendor arc where its sysObjectID
        names one. Enough to be immediately useful without walking a whole
        switch."""
        bases = [
            {"oid": nodeoids.SYSTEM_BASE, "label": "system"},
            {"oid": nodeoids.INTERFACES_BASE, "label": "interfaces"},
        ]
        device = self.db.device(device_id)
        if device is not None:
            root = nodeoids.enterprise_root(device["sys_object_id"] or "")
            if root:
                vendor = device["vendor"] or "vendor"
                bases.append({"oid": root, "label": f"{vendor} ({root})"})
        return bases

    def _snmp_get_next(self, device, config: dict, oid: str) -> Response:
        version = snmp_version_of(config)
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity = credential_for(config).identity
                request_id = session.next_request_id()
                packet = build_request(version, identity or "public", PDU_GETNEXT,
                                       request_id, [oid])
                return session.request(packet, request_id)
            return self._v3_exchange(session, device, config, PDU_GETNEXT, [oid])
        finally:
            session.close()

    def _session_for(self, device, config: dict) -> _Session:
        """One `_Session` (one UDP socket) for a caller that makes several
        round trips of its own — `_walk_column`'s whole walk, rather than a
        fresh socket per row the way `_snmp_get_next`/`_snmp_get` do for
        their single-request callers."""
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        return _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)

    def _walk_request(self, session: _Session, device, config: dict, oid: str,
                      pdu_tag: int, max_repetitions: int = 0) -> Response:
        """One GETNEXT/GETBULK round trip over an already-open session —
        the same v1/v2c/v3 request assembly `_snmp_get_next` uses, minus
        opening and closing a socket per call. `non_repeaters` is always 0:
        every walk here is over a single column, so there is nothing to
        exempt from repetition. Ignored by `build_request`/`build_v3_request`
        for a non-GETBULK `pdu_tag`, so a v1 caller can pass it unused."""
        version = snmp_version_of(config)
        if version in (0, 1):
            identity = credential_for(config).identity
            request_id = session.next_request_id()
            packet = build_request(version, identity or "public", pdu_tag,
                                   request_id, [oid],
                                   max_repetitions=max_repetitions)
            return session.request(packet, request_id)
        return self._v3_exchange(session, device, config, pdu_tag, [oid],
                                 max_repetitions=max_repetitions)


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


if __name__ == "__main__":
    # counter_rate / detect_reboot are pure functions and provable without
    # any network at all.
    assert counter_rate(100, 0.0, 200, 10.0, 32) == 10.0
    assert counter_rate(2**32 - 50, 0.0, 50, 10.0, 32) == 10.0        # one 32-bit wrap
    assert counter_rate(2**63, 0.0, 5, 10.0, 64) is None              # 64-bit: reset, not a wrap
    assert counter_rate(0, 0.0, 10**12, 1.0, 32, speed_bps=1e9) is None  # implausible vs. link speed
    assert counter_rate(100, 5.0, 200, 5.0, 32) is None               # dt == 0
    assert counter_rate(None, 0.0, 200, 10.0, 32) is None             # first poll
    print("counter_rate OK")

    assert interface_speed_bps(1_000_000_000, 1000) == 1e9             # ordinary 1G port
    assert interface_speed_bps(IF_SPEED_SENTINEL, 400_000) == 4e11     # a real 400G port
    assert interface_speed_bps(IF_SPEED_SENTINEL, 10_000_000) == 1e10  # kbit/s quirk, 10G port
    assert interface_speed_bps(1_000_000_000, 1_000_000) == 1e9        # ifSpeed contradicts it
    assert interface_speed_bps(IF_SPEED_SENTINEL, None) == float(IF_SPEED_SENTINEL)
    assert interface_speed_bps(None, None) is None
    print("interface_speed_bps OK")

    ok, note = detect_reboot(100, 1010.0, 500_000, 1000.0)
    assert ok, "a real restart must be detected"
    ok, _ = detect_reboot(29_000, 300.0, 2**32 - 1000, 0.0)
    assert not ok, "a 497-day TimeTicks wrap is not a reboot"
    ok, _ = detect_reboot(130_000, 300.0, 100_000, 0.0)
    assert not ok, "uptime going forwards is not a reboot"
    print("detect_reboot OK")

    print("all self-tests passed")

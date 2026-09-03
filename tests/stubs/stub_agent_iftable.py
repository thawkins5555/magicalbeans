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
  dark_after_walk  answers the ifIndex walk, then stops replying to
                   anything — the device that holds a poll worker for
                   N x timeout x retries.
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
  v3               speaks SNMPv3 noAuthNoPriv with an authoritative engine
                   id, engineBoots and a real engineTime clock, and applies
                   an RFC 3414 §3.2 time window of --window seconds:
                   a request whose msgAuthoritativeEngineTime is outside it
                   is answered with a Report-PDU naming
                   usmStatsNotInTimeWindows, exactly as an agent does to a
                   poller whose cached engineTime has stopped advancing.
                   --bump-boots-at SECONDS restarts the engine (boots + 1,
                   engineTime back to 0) that many seconds after the stub
                   started, so a test can put the restart between two
                   polls without counting requests.

Options: --interfaces N, --reboot-after N, --window SECONDS,
--bump-boots-at SECONDS, --stats PATH (a JSON counter file the test reads).

Prints one "listening" line after bind(), the banner tests/_paths.py's
spawn_stub waits for.
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/

from netpath import nodeoids
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT, PDU_RESPONSE, T_COUNTER32,
    T_COUNTER64, T_END_OF_MIB_VIEW, T_GAUGE32, T_NO_SUCH_OBJECT, T_NULL,
    T_INTEGER, T_OCTET_STRING, T_SEQUENCE, T_TIMETICKS, V3, Reader, _signed,
    _tlv, enc_int, enc_octets, enc_unsigned, enc_varbind,
)

COMMUNITY = "public"
UPTIME_TICKS = 987_654
ENGINE_ID = b"\x80\x00\x1f\x88\x80stub-engine"
USM_NOT_IN_TIME_WINDOWS = "1.3.6.1.6.3.15.1.1.2.0"
USM_UNKNOWN_ENGINE_IDS = "1.3.6.1.6.3.15.1.1.4.0"


class Agent:
    def __init__(self, port: int, mode: str = "ok", interfaces: int = 2,
                 reboot_after: int = 2, window: float = 1.0,
                 bump_boots_at: float = 0.0, stats_path: str = ""):
        self.mode = mode
        self.n_interfaces = interfaces
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.port = self.sock.getsockname()[1]
        self.walked = False          # dark_after_walk: has the ifIndex walk run?
        self.in_octets = 1_000_000
        self.reboot_after = reboot_after
        self.uptime_reads = 0
        self.sys_name = "iftable-stub"
        self.window = window
        self.bump_boots_at = bump_boots_at
        self.bumped = False
        self.started_at = time.monotonic()
        self.stats_path = stats_path
        self.engine_boots = 3
        self.engine_epoch = time.monotonic()
        self.counts = {"requests": 0, "reports": 0, "discoveries": 0,
                       "responses": 0}

    # ------------------------------------------------------------- SNMPv3

    @staticmethod
    def _msg_id(data: bytes) -> int:
        """The request's msgID, echoed back the way a real agent does.
        decode_response does not surface it, so it is read here."""
        top = Reader(data)
        body_s, body_e = top.expect(T_SEQUENCE)
        msg = Reader(data, body_s, body_e)
        msg.expect(T_INTEGER)                      # version
        hs, he = msg.expect(T_SEQUENCE)            # msgGlobalData
        header = Reader(data, hs, he)
        s, e = header.expect(T_INTEGER)
        return _signed(data, s, e)

    def engine_time(self) -> int:
        return int(time.monotonic() - self.engine_epoch)

    def _bump_boots(self) -> None:
        """The agent restarted: engineBoots increments and engineTime goes
        back to zero, so every cached engine parameter a poller holds is
        now wrong and it must resync off our Report."""
        self.engine_boots += 1
        self.engine_epoch = time.monotonic()

    def _v3_message(self, msg_id: int, pdu: bytes) -> bytes:
        header = _tlv(T_SEQUENCE, enc_int(msg_id) + enc_int(65507) +
                      _tlv(T_OCTET_STRING, bytes([0])) + enc_int(3))
        usm_body = (enc_octets(ENGINE_ID) + enc_int(self.engine_boots) +
                    enc_int(self.engine_time()) + enc_octets("") +
                    _tlv(T_OCTET_STRING, b"") + _tlv(T_OCTET_STRING, b""))
        sec = _tlv(T_OCTET_STRING, _tlv(T_SEQUENCE, usm_body))
        scoped = _tlv(T_SEQUENCE, enc_octets(ENGINE_ID) + enc_octets("") + pdu)
        return _tlv(T_SEQUENCE, enc_int(V3) + header + sec + scoped)

    @staticmethod
    def _pdu(tag: int, request_id: int, varbinds: bytes) -> bytes:
        return _tlv(tag, enc_int(request_id) + enc_int(0) + enc_int(0) +
                    _tlv(T_SEQUENCE, varbinds))

    def _report(self, msg_id: int, request_id: int, oid: str) -> bytes:
        self.counts["reports"] += 1
        body = enc_varbind(oid, enc_unsigned(T_COUNTER32, self.counts["reports"]))
        return self._v3_message(msg_id, self._pdu(PDU_REPORT, request_id, body))

    def _v3_handle(self, req, msg_id: int) -> list:
        self.counts["requests"] += 1
        if self.bump_boots_at and not self.bumped and \
                time.monotonic() - self.started_at >= self.bump_boots_at:
            self.bumped = True
            self._bump_boots()
        if not req.engine_id:
            # Engine discovery: an unauthenticated, empty, reportable GET.
            self.counts["discoveries"] += 1
            return [self._report(msg_id, req.request_id,
                                 USM_UNKNOWN_ENGINE_IDS)]
        if req.engine_id != ENGINE_ID or req.engine_boots != self.engine_boots \
                or abs(req.engine_time - self.engine_time()) > self.window:
            return [self._report(msg_id, req.request_id,
                                 USM_NOT_IN_TIME_WINDOWS)]
        self.counts["responses"] += 1
        if req.pdu_tag == PDU_GET:
            body = b""
            for vb in req.varbinds:
                value = self.value_for(vb["oid"])
                body += enc_varbind(vb["oid"], value if value is not None
                                    else _tlv(T_NO_SUCH_OBJECT, b""))
            return [self._v3_message(
                msg_id, self._pdu(PDU_RESPONSE, req.request_id, body))]
        if req.pdu_tag in (PDU_GETNEXT, PDU_GETBULK):
            oid, value = self._next_after(req.varbinds[0]["oid"])
            return [self._v3_message(
                msg_id, self._pdu(PDU_RESPONSE, req.request_id,
                                  enc_varbind(oid, value)))]
        return []

    def write_stats(self) -> None:
        if not self.stats_path:
            return
        with open(self.stats_path, "w") as handle:
            json.dump(dict(self.counts, engine_boots=self.engine_boots), handle)

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

    def _scalar(self, oid: str):
        S = nodeoids.SYSTEM_SCALARS
        if oid == S["sys_descr"]:
            return enc_octets("ifTable stub agent")
        if oid == S["sys_object_id"]:
            return enc_octets("1.3.6.1.4.1.99999.1")
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

    def _next_after(self, oid: str):
        """The lexicographic successor inside the ifIndex column only —
        every walk this stub serves is of that one column."""
        base = nodeoids.IF_TABLE["if_index"]
        suffixes = self.indexes()
        if oid == base:
            self.walked = True
            return f"{base}.{suffixes[0]}", enc_int(1)
        if oid.startswith(base + "."):
            current = oid[len(base) + 1:]
            if current in suffixes:
                position = suffixes.index(current) + 1
                if position < len(suffixes):
                    nxt = suffixes[position]
                    self.walked = True
                    return f"{base}.{nxt}", enc_int(position + 1)
        # Out of the subtree: the walk is over.
        self.walked = True
        return "1.3.6.1.2.1.2.2.1.2.1", enc_octets("past-the-column")

    def handle(self, data: bytes) -> list:
        """Every datagram this agent wants to send back, in order. A list
        because a misbehaving agent sends more than one."""
        req = decode_response(data)
        if self.mode == "v3":
            return self._v3_handle(req, self._msg_id(data))
        if self.mode == "dark_after_walk" and self.walked and \
                req.pdu_tag == PDU_GET:
            return []                        # answered the walk, now silent
        if req.pdu_tag == PDU_GET:
            if self.mode == "stale_id":
                # The late answer to somebody else's attempt, first, with
                # a value a receiver that accepts it will visibly store.
                self.sys_name = "STALE-WRONG-ANSWER"
                stale = self._get_reply(req, request_id=req.request_id + 1)
                self.sys_name = "iftable-stub"
                return [stale, self._get_reply(req)]
            return [self._get_reply(req)]
        if req.pdu_tag == PDU_GETNEXT:
            oid, value = self._next_after(req.varbinds[0]["oid"])
            return [self._response(req.version, req.request_id,
                                   enc_varbind(oid, value))]
        if req.pdu_tag == PDU_GETBULK:
            cursor = req.varbinds[0]["oid"]
            body = b""
            for _ in range(max(1, req.error_index or 1)):
                cursor, value = self._next_after(cursor)
                body += enc_varbind(cursor, value)
                if not cursor.startswith(nodeoids.IF_TABLE["if_index"] + "."):
                    break
            return [self._response(req.version, req.request_id, body)]
        return []

    def serve(self):
        print(f"listening on 127.0.0.1:{self.port} ({self.mode})", flush=True)
        while True:
            data, addr = self.sock.recvfrom(65535)
            try:
                replies = self.handle(data)
            except Exception as exc:          # a stub must not die quietly
                print(f"stub error: {exc}", flush=True)
                continue
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
    rest = list(argv[1:])
    while rest:
        item = rest.pop(0)
        if item == "--interfaces":
            interfaces = int(rest.pop(0))
        elif item == "--reboot-after":
            reboot_after = int(rest.pop(0))
        elif item == "--window":
            window = float(rest.pop(0))
        elif item == "--bump-boots-at":
            bump_boots_at = float(rest.pop(0))
        elif item == "--stats":
            stats_path = rest.pop(0)
        else:
            mode = item
    Agent(port, mode, interfaces, reboot_after, window, bump_boots_at,
          stats_path).serve()


if __name__ == "__main__":
    main(sys.argv[1:])

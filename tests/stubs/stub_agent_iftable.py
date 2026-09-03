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

Prints one "listening" line after bind(), the banner tests/_paths.py's
spawn_stub waits for.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/

from netpath import nodeoids
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_COUNTER32, T_COUNTER64,
    T_END_OF_MIB_VIEW, T_GAUGE32, T_NO_SUCH_OBJECT, T_NULL, T_SEQUENCE,
    T_TIMETICKS, _tlv, enc_int, enc_octets, enc_unsigned, enc_varbind,
)

COMMUNITY = "public"
UPTIME_TICKS = 987_654


class Agent:
    def __init__(self, port: int, mode: str = "ok", interfaces: int = 2):
        self.mode = mode
        self.n_interfaces = interfaces
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.port = self.sock.getsockname()[1]
        self.walked = False          # dark_after_walk: has the ifIndex walk run?
        self.in_octets = 1_000_000

    # ---------------------------------------------------------------- values

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
            return enc_unsigned(T_TIMETICKS, UPTIME_TICKS)
        if oid == S["sys_contact"]:
            return enc_octets("noc@example.com")
        if oid == S["sys_name"]:
            return enc_octets("iftable-stub")
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
        if key == "if_in_octets":
            return enc_unsigned(T_COUNTER32, (self.in_octets + index) % (2 ** 32))
        if key == "if_out_octets":
            return enc_unsigned(T_COUNTER32, 500 + index)
        if key == "if_in_errors":
            return enc_unsigned(T_COUNTER32, index)
        if key == "if_out_errors":
            return enc_unsigned(T_COUNTER32, 0)
        if key == "if_in_discards":
            return enc_unsigned(T_COUNTER32, 2 * index)
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
        if key == "if_hc_in_octets":
            return enc_unsigned(T_COUNTER64, self.in_octets + index)
        if key == "if_hc_out_octets":
            return enc_unsigned(T_COUNTER64, 500 + index)
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

    def _get_reply(self, req):
        oids = [vb["oid"] for vb in req.varbinds]
        if not self.implements_ifx():
            # A v1 agent answers the whole PDU with noSuchName as soon as
            # one named object is unimplemented, and echoes the varbind
            # list back as nulls.
            for position, oid in enumerate(oids, start=1):
                if self.value_for(oid) is None:
                    nulls = b"".join(enc_varbind(o, _tlv(T_NULL, b""))
                                     for o in oids)
                    return self._response(req.version, req.request_id, nulls,
                                          error_status=2, error_index=position)
        body = b""
        for oid in oids:
            value = self.value_for(oid)
            body += enc_varbind(
                oid, value if value is not None else _tlv(T_NO_SUCH_OBJECT, b""))
        return self._response(req.version, req.request_id, body)

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

    def handle(self, data: bytes):
        req = decode_response(data)
        if self.mode == "dark_after_walk" and self.walked and \
                req.pdu_tag == PDU_GET:
            return None                      # answered the walk, now silent
        if req.pdu_tag == PDU_GET:
            return self._get_reply(req)
        if req.pdu_tag == PDU_GETNEXT:
            oid, value = self._next_after(req.varbinds[0]["oid"])
            return self._response(req.version, req.request_id,
                                  enc_varbind(oid, value))
        if req.pdu_tag == PDU_GETBULK:
            cursor = req.varbinds[0]["oid"]
            body = b""
            for _ in range(max(1, req.error_index or 1)):
                cursor, value = self._next_after(cursor)
                body += enc_varbind(cursor, value)
                if not cursor.startswith(nodeoids.IF_TABLE["if_index"] + "."):
                    break
            return self._response(req.version, req.request_id, body)
        return None

    def serve(self):
        print(f"listening on 127.0.0.1:{self.port} ({self.mode})", flush=True)
        while True:
            data, addr = self.sock.recvfrom(65535)
            try:
                reply = self.handle(data)
            except Exception as exc:          # a stub must not die quietly
                print(f"stub error: {exc}", flush=True)
                continue
            if reply is not None:
                self.sock.sendto(reply, addr)


def main(argv):
    port = int(argv[0])
    mode = "ok"
    interfaces = 2
    rest = list(argv[1:])
    while rest:
        item = rest.pop(0)
        if item == "--interfaces":
            interfaces = int(rest.pop(0))
        else:
            mode = item
    Agent(port, mode, interfaces).serve()


if __name__ == "__main__":
    main(sys.argv[1:])

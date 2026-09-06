"""The SNMP trap listener.

Same two-thread split as syslogd.py: a receive thread reads and decodes, a
separate writer drains a batching queue. UDP only — SNMP has no TCP transport
in practice.
"""

from __future__ import annotations

import collections
import queue
import socket
import time
import traceback

from . import udpsock
from .eventlog import ERROR, SNMP
from .snmptrapdb import SnmpTrapDatabase
from .trapdecode import Decoder, VERSION_NAMES, build_inform_response
from .worker import ago

BATCH = 200
FLUSH_S = 1.0


class TrapCollector(udpsock.UdpReceiver):
    NOUN = "Receiver"
    DROPS_PORT_NOUN = "trap"
    LOG_CATEGORY = SNMP
    QUEUE_SIZE = 50_000
    COUNTERS = {"packets": 0, "traps": 0, "stored": 0, "dropped": 0,
                "rejected": 0, "bad_community": 0, "undecodable": 0,
                "filtered": 0, "informs_acked": 0, "errors": 0,
                "bad_auth": 0, "unverified": 0, "too_many_varbinds": 0,
                "last_trap": 0.0}

    def __init__(self, db: SnmpTrapDatabase, log=None, on_batch=None,
                 nodes_db=None):
        super().__init__(log)
        self.db = db
        # Optional: when the Nodes database is available, a v1 trap's
        # agent-address is recorded as another address of the sending device,
        # so the next message from that address correlates by name.
        self.nodes_db = nodes_db
        self.on_batch = on_batch
        self.decoder = Decoder()
        self._allowed: set[str] = set()
        self._auto_accept = True
        self._communities: set[str] = set()
        self._auto_community = True
        self._versions: set[int] = {0, 1, 3}
        self._ack_informs = True
        self._reject_failed_auth = True
        self._min_severity = 7
        # (source, agent address) pairs already written to the alias table, so
        # a steady stream of v1 traps costs one database write, not one per
        # trap. Keyed on spoofable data, so bounded and LRU.
        self._learned: collections.OrderedDict = collections.OrderedDict()

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self._reset_for_start()

        allow = str(settings.get("allowed_sources", "") or "")
        self._allowed = {i.strip() for i in allow.replace(",", "\n").split("\n") if i.strip()}
        self._auto_accept = bool(settings.get("auto_accept_sources", True))

        comms = str(settings.get("accepted_communities", "") or "")
        self._communities = {i.strip() for i in comms.replace(",", "\n").split("\n") if i.strip()}
        self._auto_community = bool(settings.get("auto_accept_communities", True))

        self._versions = set()
        if settings.get("accept_v1", True):
            self._versions.add(0)
        if settings.get("accept_v2c", True):
            self._versions.add(1)
        if settings.get("accept_v3", True):
            self._versions.add(3)

        self._ack_informs = bool(settings.get("acknowledge_informs", True))
        self._reject_failed_auth = bool(settings.get("reject_failed_auth", True))
        self._min_severity = int(settings.get("min_severity", 7))
        self.db.store_raw = bool(settings.get("store_raw", False))
        self.decoder.configure(settings)

        address = settings.get("bind_address", "0.0.0.0")
        port = int(settings.get("port", 162))
        buffer_bytes = int(settings.get("socket_buffer_kb", 2048)) * 1024
        self.ports = {}
        try:
            self._udp = self._bind(socket.SOCK_DGRAM, address, port, buffer_bytes)
            self.ports["UDP"] = port
        except OSError as exc:
            hint = ""
            code = getattr(exc, "errno", None)
            if code in (13, 1):
                hint = (" — ports below 1024 need administrator or root "
                        "rights. Use 1162 and point devices at it instead.")
            elif code in (48, 98, 10048):
                hint = (" — another process already holds it. On Windows: "
                        "Get-NetUDPEndpoint -LocalPort " + str(port) +
                        " | Select OwningProcess. The Windows SNMP Trap service "
                        "is the usual answer; stop it, or change the port in "
                        "Settings.")
            self.error = f"Could not bind {address}:{port}: {exc}{hint}"
            self.log.add(ERROR, self.error)
            self.stop()
            return False

        self._arm_kernel_drops(port)
        self.bound = (address, port)
        self._spawn(self._receive_udp, "snmp-udp")
        self._spawn(self._write, "snmp-write")
        self.log.add(SNMP, f"SNMP trap receiver listening on {address} (UDP {port})")
        return True

    # ------------------------------------------------------------------ errors

    def _note_error(self, exc: Exception) -> None:
        # The counters survive a restart, so errors are accumulated in the
        # counter itself rather than republished from a per-run total.
        self.counters["errors"] += 1
        self._log_throttled("receive", f"Receive error: {exc}",
                            detail=traceback.format_exc)

    # ------------------------------------------------------------------ access

    def _accepted_source(self, source: str) -> bool:
        if self._allowed:
            return source in self._allowed
        return self._auto_accept

    def _accepted_community(self, community: str, version: int) -> bool:
        # SNMPv3 has no community; its user name is checked against the
        # configured users by the decoder's authentication step instead.
        if version == 3:
            return True
        if self._communities:
            return community in self._communities
        return self._auto_community

    # ----------------------------------------------------------------- threads

    def _handle_datagram(self, data: bytes, address) -> None:
        source = udpsock.normalise_source(address[0])
        self.counters["packets"] += 1
        # The source check happens before decoding — a rejected packet is
        # never parsed, exactly as syslog does it.
        if not self._accepted_source(source):
            self.counters["rejected"] += 1
            return

        trap = self.decoder.decode(data, source)
        if trap is None:
            self.counters["undecodable"] += 1
            return
        if trap.version not in self._versions:
            self.counters["rejected"] += 1
            return
        if not self._accepted_community(trap.community, trap.version):
            self.counters["bad_community"] += 1
            return
        if not self._accepted_auth(trap):
            return

        self.counters["traps"] += 1
        self.counters["last_trap"] = time.time()
        # The decoder counts traps it had to truncate; without surfacing the
        # figure a 10,000-varbind trap arrives as 64 varbinds with nothing to
        # say the rest was thrown away.
        self.counters["too_many_varbinds"] = self.decoder.stats["too_many_varbinds"]
        self._learn_agent_address(trap)
        if self._first_from(source):
            self.log.add(SNMP, f"First SNMP trap from {source} "
                               f"({VERSION_NAMES.get(trap.version, '?')}, "
                               f"{trap.trap_name or trap.trap_oid})", target=source)

        if trap.is_inform and self._ack_informs:
            self._acknowledge(trap, address)

        if trap.severity > self._min_severity:
            self.counters["filtered"] += 1
            return
        try:
            self._queue.put_nowait(trap)
        except queue.Full:
            self.counters["dropped"] += 1

    def _learn_agent_address(self, trap) -> None:
        """Record a v1 trap's agent-address as another address of the sender.

        RFC 1157 traps carry the agent's own idea of its address, which on a
        device with a management VRF or a loopback trap-source is not the
        address the datagram came from. Writing it into the Nodes alias table
        means the operator sees the device's name against those traps.
        """
        if trap.version != 0 or not trap.agent_addr:
            return
        if trap.agent_addr == trap.source or trap.agent_addr == "0.0.0.0":
            return
        if not udpsock.lru_add(self._learned, (trap.source, trap.agent_addr)):
            return

        record = getattr(self.nodes_db, "record_device_addresses", None)
        if record is None:
            return
        try:
            device = self.nodes_db.device_by_ip(trap.source)
            if device is None:
                return
            record(device["id"], [trap.agent_addr], "trap_agent_addr")
        except Exception as exc:
            # Correlation is a convenience; never let it cost a trap.
            self._note_error(exc)

    def _accepted_auth(self, trap) -> bool:
        """Enforce the SNMPv3 digest the decoder already computed.

        v3 has no community, so _accepted_community cannot check it: without
        this a forged authNoPriv trap with a wrong digest was stored and
        alerted on like a genuine one. "failed" means a configured user's
        digest did not verify; "unverified" means no user is configured for
        that name, so nothing could be checked — those are counted and kept,
        because that is what a site with no v3 users has always had.
        """
        if trap.auth_state == "failed":
            self.counters["bad_auth"] += 1
            if not self._reject_failed_auth:
                return True
            self._log_throttled(
                "bad_auth",
                f"Discarded an SNMPv3 trap from {trap.source} whose "
                f"authentication failed (user {trap.community!r})",
                target=trap.source,
                detail="The digest did not verify against the "
                       "configured password for that user. Either "
                       "the device's password differs, or the trap "
                       "was forged. Turn off \"reject failed "
                       "authentication\" in Settings to store them "
                       "anyway.")
            return False
        if trap.version == 3 and trap.auth_state in ("unverified", "encrypted"):
            self.counters["unverified"] += 1
        return True

    def _acknowledge(self, trap, address) -> None:
        """An InformRequest is retransmitted until acknowledged. Answering it
        is still receive-only work: it is a reply on the socket the trap
        arrived on, not an outbound query."""
        # v3 informs are not acknowledged: doing so correctly means acting as
        # the authoritative engine, answering discovery Reports and tracking
        # engine boots and time, which is USM's other half and out of scope
        # here.
        if trap.version == 3 or not trap.varbinds_tlv_span:
            return
        try:
            a, b = trap.varbinds_tlv_span
            reply = build_inform_response(trap.version, trap.community,
                                          trap.request_id, trap.raw[a:b])
            self._udp.sendto(reply, address)
            self.counters["informs_acked"] += 1
        except (OSError, IndexError, ValueError):
            pass

    def _write(self) -> None:
        pending: list = []
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                pending.append(self._queue.get(timeout=0.3))
            except queue.Empty:
                pass
            self._poll_kernel_drops()
            due = time.time() - last_flush >= FLUSH_S
            if pending and (due or len(pending) >= BATCH):
                self.counters["stored"] += self._insert_batch(pending)
                pending.clear()
                last_flush = time.time()
                if self.on_batch:
                    self.on_batch()
        if pending:
            self.counters["stored"] += self._insert_batch(pending)

    def _insert_batch(self, traps: list) -> int:
        """Insert one flush's worth of traps.

        One poisoned row must not cost the other 199, so a batch that fails is
        retried a row at a time: the common case pays a single executemany.

        The rollback matters as much as the retry: sqlite3 does not
        auto-commit each row of an executemany, so rows that bound
        successfully before the poisoned one are left in an open transaction
        on the shared connection, and the first per-row retry's commit would
        store them a second time.
        """
        try:
            return self.db.insert(traps)
        except Exception as exc:
            # Under the database's own lock, not beside it. This connection is
            # shared (check_same_thread=False) with the retention thread, whose
            # chunked deletes commit under that same lock -- rolling back from
            # outside it could discard a delete that had bound its rows and not
            # yet committed. The lock is an RLock and this thread holds nothing
            # else, so taking it here cannot deadlock.
            try:
                with self.db._lock:
                    self.db._conn.rollback()
            except Exception:
                pass
            stored = 0
            lost = 0
            for trap in traps:
                try:
                    stored += self.db.insert([trap])
                except Exception:
                    lost += 1
            self._log_throttled(
                "batch",
                f"A batch of {len(traps)} traps failed to insert "
                f"together ({exc}); {lost} could not be stored "
                f"even retried one at a time and were discarded, "
                f"{stored} were saved",
                detail=traceback.format_exc())
            self.counters["errors"] += 1
            return stored

    # ------------------------------------------------------------------ status

    def _listening_text(self) -> str:
        address, port = self.bound or ("?", 0)
        base = f"Listening on {address} (UDP {port})"
        last = self.counters["last_trap"]
        return (f"{base} · last trap {ago(last)}" if last
                else f"{base} · waiting for traps")

    def _status_parts(self) -> list[str]:
        parts = []
        if self.counters["bad_auth"]:
            parts.append(f"{self.counters['bad_auth']} failed authentication")
        if self.counters["too_many_varbinds"]:
            parts.append(f"{self.counters['too_many_varbinds']} truncated")
        return parts

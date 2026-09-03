"""The SNMP trap listener.

Same two-thread split as syslogd.py: a receive thread reads and decodes, a
separate writer drains a batching queue. UDP only — SNMP has no TCP transport
in practice.
"""

from __future__ import annotations

import collections
import queue
import socket
import threading
import time
import traceback

from . import udpsock
from .eventlog import ERROR, NullLog, SNMP
from .snmptrapdb import SnmpTrapDatabase
from .trapdecode import Decoder, VERSION_NAMES, build_inform_response

BATCH = 200
FLUSH_S = 1.0
# Cap on the "first trap from ..." memory: the key is a spoofable source
# address, so it is an LRU rather than an unbounded set.
MAX_SEEN_SOURCES = 4096


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return f"{age / 3600:.1f}h ago"


class TrapCollector:
    def __init__(self, db: SnmpTrapDatabase, log=None, on_batch=None,
                 nodes_db=None):
        self.db = db
        # Optional: when the Nodes database is available, a v1 trap's
        # agent-address is recorded as another address of the sending device,
        # so the next message from that address correlates by name.
        self.nodes_db = nodes_db
        self.log = log or NullLog()
        self.on_batch = on_batch
        self.decoder = Decoder()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._queue: queue.Queue = queue.Queue(maxsize=50_000)
        self.error: str | None = None
        self.bound: tuple[str, int] | None = None
        self.family = socket.AF_INET
        self.counters = {"packets": 0, "traps": 0, "stored": 0, "dropped": 0,
                         "rejected": 0, "bad_community": 0, "undecodable": 0,
                         "filtered": 0, "informs_acked": 0, "errors": 0,
                         "bad_auth": 0, "unverified": 0, "last_trap": 0.0}
        # A receive thread must never die on packet content; failures are
        # counted here and _crash records a thread that ended anyway so the
        # status strip does not read like a deliberate stop.
        self._last_error_log = 0.0
        self._crash: str | None = None
        self._drops: udpsock.KernelDrops | None = None
        self._drops_logged = False
        self.ports: dict[str, int] = {}
        self._allowed: set[str] = set()
        self._auto_accept = True
        self._communities: set[str] = set()
        self._auto_community = True
        self._versions: set[int] = {0, 1, 3}
        self._ack_informs = True
        self._reject_failed_auth = True
        self._last_bad_auth_log = 0.0
        self._min_severity = 7
        self._seen: collections.OrderedDict = collections.OrderedDict()
        # (source, agent address) pairs already written to the alias table, so
        # a steady stream of v1 traps costs one database write, not one per
        # trap. Keyed on spoofable data, so bounded and LRU.
        self._learned: collections.OrderedDict = collections.OrderedDict()

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self.error = None
        self._crash = None
        self._stop.clear()
        self._seen.clear()

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
            self._udp = self._bind(address, port, buffer_bytes)
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

        self._drops = udpsock.KernelDrops(port) if udpsock.supported() else None
        self._drops_logged = False
        if self._drops is not None:
            self.counters["kernel_dropped"] = 0
        else:
            self.counters.pop("kernel_dropped", None)

        self.bound = (address, port)
        self._spawn(self._receive, "snmp-udp")
        self._spawn(self._write, "snmp-write")
        self.log.add(SNMP, f"SNMP trap receiver listening on {address} (UDP {port})")
        return True

    def _bind(self, address, port, buffer_bytes):
        sock, self.family = udpsock.bind(socket.SOCK_DGRAM, address, port,
                                         buffer_bytes)
        try:
            granted = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if granted < buffer_bytes:
                # Linux reports back twice what it granted, so a readback
                # below the request means net.core.rmem_max clamped it — the
                # commonest reason for kernel drops under load.
                self.log.add(ERROR,
                             f"The receive buffer was clamped to {granted} bytes "
                             f"(asked for {buffer_bytes})",
                             detail="Raise net.core.rmem_max on this host, or "
                                    "lower the buffer size in Settings so the "
                                    "two agree.")
        except OSError:
            pass
        return sock

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=lambda: self._guard(target, name),
                                  name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _guard(self, target, name: str) -> None:
        """Run a receiver thread and remember how it ended, so a crash reads
        as "stopped unexpectedly" rather than as an operator stop."""
        try:
            target()
        except Exception as exc:
            self._crash = f"{name}: {exc}"
            self.log.add(ERROR, f"The {name} thread stopped unexpectedly: {exc}",
                         detail=traceback.format_exc())
        else:
            if not self._stop.is_set():
                self._crash = f"{name} ended unexpectedly"


    def _poll_kernel_drops(self) -> None:
        """Read back the kernel's own loss counter for the bound port.

        counters["dropped"] only counts a message the writer queue could not
        take, which is loss the application caused; datagrams the socket
        buffer discarded before anyone read them were invisible. The key is
        absent on platforms that do not publish the figure.
        """
        if self._drops is None:
            return
        value = self._drops.poll()
        if value is None:
            return
        previous = self.counters.get("kernel_dropped", 0)
        self.counters["kernel_dropped"] = value
        if value > previous and not self._drops_logged:
            self._drops_logged = True
            self.log.add(ERROR,
                         f"The kernel is dropping datagrams on trap port "
                         f"{self._drops.port}: {value} lost before they could "
                         f"be read",
                         detail="The socket receive buffer is full: the sender "
                                "is faster than this host can drain it. Raise "
                                "the buffer size in Settings, and on Linux "
                                "raise net.core.rmem_max to at least that "
                                "value.")

    def _note_error(self, exc: Exception) -> None:
        """Count a datagram the receive path could not process; log at most
        one traceback a minute so a flood cannot fill the event log."""
        self.counters["errors"] += 1
        now = time.time()
        if now - self._last_error_log >= 60:
            self._last_error_log = now
            self.log.add(ERROR, f"Receive error: {exc}",
                         detail=traceback.format_exc())

    def stop(self) -> None:
        self._stop.set()
        if self._udp is not None:
            try:
                self._udp.close()
            except OSError:
                pass
        self._udp = None
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self._threads = []
        self.bound = None

    # ----------------------------------------------------------------- access


    def _first_from(self, source: str) -> bool:
        """True the first time a source is seen since the last start.

        The set is keyed on the datagram's source address, which anyone with
        network reach can vary, so it is bounded and least-recently-used
        rather than growing for the life of the process.
        """
        if source in self._seen:
            self._seen.move_to_end(source)
            return False
        self._seen[source] = None
        while len(self._seen) > MAX_SEEN_SOURCES:
            self._seen.popitem(last=False)
        return True

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

    def _receive(self) -> None:
        sock = self._udp
        while not self._stop.is_set() and sock is not None:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._enqueue(data, address)
            except Exception as exc:
                self._note_error(exc)

    def _enqueue(self, data: bytes, address) -> None:
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
        address the datagram came from. The decoder has always parsed it and
        the database has always stored it; nothing used it for correlation.
        Writing it into the Nodes alias table means the operator sees the
        device's name against those traps from then on.
        """
        if trap.version != 0 or not trap.agent_addr:
            return
        if trap.agent_addr == trap.source or trap.agent_addr == "0.0.0.0":
            return
        key = (trap.source, trap.agent_addr)
        if key in self._learned:
            self._learned.move_to_end(key)
            return
        self._learned[key] = None
        while len(self._learned) > MAX_SEEN_SOURCES:
            self._learned.popitem(last=False)

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

        _accepted_community returns True unconditionally for v3 because v3
        has no community, and nothing downstream looked at auth_state — so a
        forged authNoPriv trap with a wrong digest was counted as a failure
        and then stored and alerted on exactly like a genuine one. "failed"
        means a configured user's digest did not verify, which is either an
        attack or a password mismatch; "unverified" means no user is
        configured for that name, so nothing could be checked. The second is
        counted and kept, because that is what a site with no v3 users
        configured has always had.
        """
        if trap.auth_state == "failed":
            self.counters["bad_auth"] += 1
            if not self._reject_failed_auth:
                return True
            now = time.time()
            if now - self._last_bad_auth_log >= 60:
                self._last_bad_auth_log = now
                self.log.add(ERROR,
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
                try:
                    self.counters["stored"] += self.db.insert(pending)
                except Exception:
                    import traceback
                    traceback.print_exc()
                pending.clear()
                last_flush = time.time()
                if self.on_batch:
                    self.on_batch()
        if pending:
            try:
                self.db.insert(pending)
            except Exception:
                pass

    # ------------------------------------------------------------------ status

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            if self._crash:
                return f"Receiver stopped unexpectedly: {self._crash}"
            return "Receiver stopped"
        address, port = self.bound or ("?", 0)
        base = f"Listening on {address} (UDP {port})"
        last = self.counters["last_trap"]
        text = (f"{base} · last trap {_ago(last)}" if last
                else f"{base} · waiting for traps")
        lost = self.counters.get("kernel_dropped", 0)
        return f"{text} · {lost} dropped by the kernel" if lost else text

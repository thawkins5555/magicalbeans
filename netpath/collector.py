"""The NetFlow/IPFIX UDP listener.

One thread reads the socket and decodes; a second drains a queue and writes in
batches. Splitting them matters: a SQLite commit takes milliseconds, and doing
it on the receive path would leave the socket buffer unserviced long enough to
drop packets under load. NetFlow is UDP, so a dropped packet is lost data with
no retransmission.
"""

from __future__ import annotations

import queue
import socket
import time
import traceback

from . import udpsock
from .eventlog import ERROR, NETFLOW
from .flowdb import FlowDatabase
from .nfdecode import IPFIX, V5, V9, Decoder
from .worker import ago

# How far back a sampling rate announced after the fact rewrites the flows it
# applies to. Unbounded, that UPDATE has no index it can use and grows into a
# scan of the whole retention window -- run on the writer thread, under the
# write lock, after every flush. Whatever this is set to, the rewrite marks
# every rollup tier dirty from where it reached, so the buckets already built
# from those rows are rebuilt rather than left disagreeing with them.
RESAMPLE_MAX_AGE_S = 900

# Rows buffered before a flush goes early rather than waiting out the second.
FLUSH_ROWS = 5000

# Sampling-rate rewrites applied per flush. Each one is a retention-window
# UPDATE on the writer thread under the flow lock (tens of milliseconds on a
# busy store), and a sender cycling flowSamplerID can announce thousands in a
# second. The remainder waits for the next flush, so a legitimately announced
# rate still rewrites its own window, one flush later at worst.
MAX_RESAMPLE_PER_FLUSH = 64


class Collector(udpsock.UdpReceiver):
    NOUN = "Collector"
    DROPS_PORT_NOUN = "NetFlow"
    LOG_CATEGORY = NETFLOW
    STOP_LOG = True
    # Datagrams, not flows: one v9 packet carries up to about thirty, so this
    # is a ceiling of roughly 600,000 buffered flows.
    QUEUE_SIZE = 20000
    COUNTERS = {"packets": 0, "flows": 0, "dropped": 0, "rejected": 0,
                "errors": 0, "resampled": 0, "truncated_flows": 0,
                "first_seen_suppressed": 0,
                "last_packet": 0.0, "last_template": 0.0}

    def __init__(self, db: FlowDatabase, on_batch=None, log=None):
        super().__init__(log)
        self.db = db
        self.on_batch = on_batch
        self.decoder = Decoder()
        self.started_at = 0.0
        self._settings: dict = {}
        self._allowed: set[str] = set()
        self._versions: set[int] = {V5, V9, IPFIX}
        # Counted since each throttle's last line, for that line to report.
        self._templates_pending = 0
        self._first_seen_pending = 0

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self._settings = dict(settings)
        self._reset_for_start()
        self._templates_pending = 0
        self._first_seen_pending = 0

        self._versions = set()
        if settings.get("accept_v5", True):
            self._versions.add(V5)
        if settings.get("accept_v9", True):
            self._versions.add(V9)
        if settings.get("accept_ipfix", True):
            self._versions.add(IPFIX)

        allow = str(settings.get("allowed_exporters", "") or "")
        self._allowed = {item.strip() for item in allow.replace(",", "\n").split("\n")
                         if item.strip()}

        self.decoder = Decoder(
            default_sampling=int(settings.get("default_sampling", 1)),
            trust_exporter_sampling=bool(settings.get("trust_exporter_sampling", True)),
        )

        address = settings.get("bind_address", "0.0.0.0")
        port = int(settings.get("port", 2055))
        wanted = int(settings.get("socket_buffer_kb", 4096)) * 1024
        try:
            self._udp = self._bind(socket.SOCK_DGRAM, address, port, wanted)
        except OSError as exc:
            hint = ""
            if getattr(exc, "errno", None) in (48, 98, 10048):
                hint = (" — another process already holds this port. "
                        "Check it with: Get-NetUDPEndpoint -LocalPort "
                        f"{port} | Select LocalAddress,OwningProcess")
            self.error = f"Could not bind {address}:{port}: {exc}{hint}"
            self.log.add(ERROR, self.error)
            return False

        self._arm_kernel_drops(port)
        self.bound = (address, port)
        self.started_at = time.time()
        self._spawn(self._receive_udp, "netflow-rx")
        self._spawn(self._write, "netflow-wr")
        versions = ", ".join(f"v{v}" for v in sorted(self._versions))
        self.log.add(NETFLOW, f"Collector listening on {address}:{port}/udp",
                     detail=f"versions   {versions}\n"
                            f"rcvbuf     {self.rcvbuf} bytes\n"
                            f"allow list {sorted(self._allowed) or 'any exporter'}")
        return True

    # ------------------------------------------------------------------ errors

    def _sync_error_counter(self) -> None:
        self.counters["errors"] = self.decoder.stats["errors"] + self._loop_errors

    def _note_write_error(self, exc: Exception) -> None:
        """Count a batch the writer thread could not store. Unguarded, a bad
        row would end netflow-wr for good while netflow-rx kept accepting
        packets -- which is what `running` checking both threads is for."""
        self._loop_errors += 1
        self._sync_error_counter()
        self._log_throttled("write", f"A batch of flows failed to write: {exc}",
                            detail=traceback.format_exc)

    # ----------------------------------------------------------------- threads

    def _handle_datagram(self, data: bytes, address) -> None:
        exporter = udpsock.normalise_source(address[0])
        if self._allowed and exporter not in self._allowed:
            self.counters["rejected"] += 1
            return
        if not self._settings.get("auto_accept_exporters", True) and not self._allowed:
            self.counters["rejected"] += 1
            return
        if len(data) >= 2:
            version = int.from_bytes(data[:2], "big")
            if version not in self._versions:
                self.counters["rejected"] += 1
                return

        self.counters["packets"] += 1
        self.counters["last_packet"] = time.time()
        templates_before = self.decoder.stats["templates"]
        errors_before = self.decoder.stats["errors"]
        flows = self.decoder.decode(data, exporter)

        if self._first_from(exporter):
            self._log_first_seen(exporter, data)
        gained = self.decoder.stats["templates"] - templates_before
        if gained:
            # Outside the throttle: last_template must move on every re-send.
            self.counters["last_template"] = time.time()
            self._templates_pending += gained
            if self._log_netflow_throttled(
                    "templates",
                    f"Received {self._templates_pending} template(s) from "
                    f"{exporter}", target=exporter):
                self._templates_pending = 0
        if self.decoder.stats["errors"] > errors_before:
            # One line a minute, not one per datagram: the event log is a
            # 3,000-entry ring, and a flood of runts emptied it of everything
            # an operator would want at exactly the moment they looked. The
            # counters below still show the full volume.
            self._log_throttled("undecodable",
                                f"Undecodable packet from {exporter}",
                                target=exporter,
                                detail=lambda: f"{len(data)} bytes, first 32: "
                                               f"{data[:32].hex(' ')}")
        self._sync_error_counter()
        self.counters["truncated_flows"] = self.decoder.stats["truncated_flows"]
        if not flows:
            return
        try:
            self._queue.put_nowait((exporter, flows))
        except queue.Full:
            self.counters["dropped"] += len(flows)

    def _log_netflow_throttled(self, key: str, message: str, detail="",
                               target: str = "", interval_s: float = 60.0) -> bool:
        """Like _log_throttled but files NETFLOW instead of ERROR."""
        now = time.time()
        if now - self._log_times.get(key, 0.0) < interval_s:
            return False
        self._log_times[key] = now
        if callable(detail):
            detail = detail()
        self.log.add(NETFLOW, message, target=target, detail=detail)
        return True

    def _log_first_seen(self, exporter: str, data: bytes) -> None:
        """One "first packet from" line a minute, plus a count suppressed."""
        pending = self._first_seen_pending
        extra = (f" (and {pending} other new exporter(s) since the last such "
                 f"line)" if pending else "")
        if self._log_netflow_throttled(
                "first", f"First packet from exporter {exporter}{extra}",
                target=exporter,
                detail=lambda: (f"version  {int.from_bytes(data[:2], 'big')}\n"
                                f"bytes    {len(data)}\n"
                                f"sampling {self.decoder.sampling_for(exporter)}")):
            self._first_seen_pending = 0
            return
        self._first_seen_pending = pending + 1
        self.counters["first_seen_suppressed"] += 1

    def _write(self) -> None:
        pending: list = []
        # exporter -> [packets, flows, sampling, version]
        per_exporter: dict[str, list[int]] = {}
        last_flush = time.time()

        def take(exporter: str, flows: list) -> None:
            pending.extend(flows)
            entry = per_exporter.setdefault(exporter, [0, 0, 1, 0])
            entry[0] += 1
            entry[1] += len(flows)
            entry[2] = flows[0].sampling
            # Each exporter's own version, not whichever flow happened to
            # be first in the whole batch: with v5 and v9 exporters in one
            # flush window the Exporters table named the wrong protocol
            # for every one of them.
            entry[3] = flows[0].version

        while not self._stop.is_set():
            try:
                take(*self._queue.get(timeout=0.4))
            except queue.Empty:
                pass
            # Drain what else is already waiting rather than taking one
            # datagram per loop: a burst then costs one commit instead of
            # hundreds, and the queue stays shallow, so the point at which
            # queue.Full starts dropping flows comes far later.
            while len(pending) < FLUSH_ROWS:
                try:
                    take(*self._queue.get_nowait())
                except queue.Empty:
                    break

            self._poll_kernel_drops()
            due = time.time() - last_flush >= 1.0
            if pending and (due or len(pending) >= FLUSH_ROWS):
                # A batch that fails to write must not end this thread: one
                # crafted options record can push Flow.sampling past SQLite's
                # int64 bind range (see nfdecode._set_sampling's clamp).
                try:
                    written = self.db.insert_flows(pending)
                    self.counters["flows"] += written
                    self.db.touch_exporters(
                        [(exporter, entry[3], entry[0], entry[1], entry[2])
                         for exporter, entry in per_exporter.items()])
                except Exception as exc:
                    self._note_write_error(exc)
                pending.clear()
                per_exporter.clear()
                last_flush = time.time()
                self._apply_learned_rates()
                if self.on_batch:
                    self.on_batch()

        if pending:
            try:
                self.counters["flows"] += self.db.insert_flows(pending)
            except Exception as exc:
                self._note_write_error(exc)
        self._apply_learned_rates()

    def _apply_learned_rates(self) -> None:
        """Store any sampling rate announced since the last flush, and correct
        the flows that arrived before the announcement. At most
        MAX_RESAMPLE_PER_FLUSH of them per flush; the rest wait."""
        rates = self.decoder.drain_learned_rates(MAX_RESAMPLE_PER_FLUSH)
        if not rates:
            return
        try:
            corrected = self.db.record_sampling_rates(
                rates, max(self.started_at, time.time() - RESAMPLE_MAX_AGE_S))
        except Exception as exc:
            self._note_error(exc)
            return
        if corrected:
            self.counters["resampled"] += corrected

    # ------------------------------------------------------------------ status

    def _status_parts(self) -> list[str]:
        parts = []
        if self.counters["truncated_flows"]:
            parts.append(f"{self.counters['truncated_flows']} truncated")
        return parts

    def _listening_text(self) -> str:
        address, port = self.bound or ("?", 0)
        base = f"Listening on {address}:{port} ({self.PORT_LABEL})"
        last = self.counters["last_packet"]
        if last:
            template = self.counters["last_template"]
            # v9 and IPFIX are undecodable until a template arrives, and
            # exporters resend them only every few minutes, so how long ago
            # the last one came is worth as much as the packet time.
            tail = (f"last template {ago(template)}" if template
                    else "no template yet")
            return f"{base} · last packet {ago(last)} · {tail}"
        waiting = time.time() - self.started_at if self.started_at else 0
        if waiting > 60:
            return f"{base} · no packets yet ({waiting / 60:.0f} min)"
        return f"{base} · waiting for packets"

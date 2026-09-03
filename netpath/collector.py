"""The UDP listener.

One thread reads the socket and decodes; a second drains a queue and writes in
batches. Splitting them matters: a SQLite commit takes milliseconds, and doing
it on the receive path would leave the socket buffer unserviced long enough to
drop packets under load. NetFlow is UDP, so a dropped packet is lost data with
no retransmission.
"""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
import traceback

from .eventlog import ERROR, NETFLOW, NullLog
from .flowdb import FlowDatabase
from .nfdecode import IPFIX, V5, V9, Decoder


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


class Collector:
    def __init__(self, db: FlowDatabase, on_batch=None, log=None):
        self.db = db
        self.on_batch = on_batch
        self.log = log or NullLog()
        self._seen_exporters: set[str] = set()
        self._stop = threading.Event()
        self._rx_thread: threading.Thread | None = None
        self._wr_thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._queue: queue.Queue = queue.Queue(maxsize=20000)
        self.decoder = Decoder()
        self.error: str | None = None
        self.bound: tuple[str, int] | None = None
        self.rcvbuf = 0
        self.started_at = 0.0
        self.counters = {"packets": 0, "flows": 0, "dropped": 0, "rejected": 0,
                         "errors": 0, "last_packet": 0.0, "last_template": 0.0}
        # A receive thread must never be able to die on packet content, so its
        # per-datagram work is guarded and the failures counted here; _crash
        # records a thread that ended anyway, so the status strip can say
        # "stopped unexpectedly" instead of looking like an operator stop.
        self._loop_errors = 0
        self._last_error_log = 0.0
        self._crash: str | None = None
        self._settings: dict = {}
        self._allowed: set[str] = set()
        self._versions: set[int] = {V5, V9, IPFIX}

    # --------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return self._rx_thread is not None and self._rx_thread.is_alive()

    def start(self, settings: dict) -> bool:
        self.stop()
        self._settings = dict(settings)
        self.error = None
        self._crash = None
        self._loop_errors = 0
        self._stop.clear()

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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if os.name == "nt":
                # SO_REUSEADDR on Windows lets a second process bind the same
                # UDP port and quietly take delivery of the datagrams, so a
                # leftover instance silently steals every packet while this one
                # looks healthy. SO_EXCLUSIVEADDRUSE makes the second bind fail
                # loudly instead, which is the error we want to show.
                try:
                    sock.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_EXCLUSIVEADDRUSE, 1)
                except (AttributeError, OSError):
                    pass
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            wanted = int(settings.get("socket_buffer_kb", 4096)) * 1024
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, wanted)
                self.rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            except OSError:
                self.rcvbuf = 0
            sock.bind((address, port))
            sock.settimeout(0.5)
        except OSError as exc:
            hint = ""
            if getattr(exc, "errno", None) in (48, 98, 10048):
                hint = (" — another process already holds this port. "
                        "Check it with: Get-NetUDPEndpoint -LocalPort "
                        f"{port} | Select LocalAddress,OwningProcess")
            self.error = f"Could not bind {address}:{port}: {exc}{hint}"
            self.log.add(ERROR, self.error)
            return False

        self._sock = sock
        self.bound = (address, port)
        self._rx_thread = threading.Thread(
            target=lambda: self._guard(self._receive, "netflow-rx"),
            name="netflow-rx", daemon=True)
        self._wr_thread = threading.Thread(
            target=lambda: self._guard(self._write, "netflow-wr"),
            name="netflow-wr", daemon=True)
        self.started_at = time.time()
        self._seen_exporters.clear()
        self._rx_thread.start()
        self._wr_thread.start()
        versions = ", ".join(f"v{v}" for v in sorted(self._versions))
        self.log.add(NETFLOW, f"Collector listening on {address}:{port}/udp",
                     detail=f"versions   {versions}\n"
                            f"rcvbuf     {self.rcvbuf} bytes\n"
                            f"allow list {sorted(self._allowed) or 'any exporter'}")
        return True

    def stop(self) -> None:
        if self.running:
            self.log.add(NETFLOW, "Collector stopped")
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        for thread in (self._rx_thread, self._wr_thread):
            if thread and thread.is_alive():
                thread.join(timeout=2)
        self._rx_thread = self._wr_thread = None
        self.bound = None

    # ---------------------------------------------------------------- threads

    def _guard(self, target, name: str) -> None:
        """Run a collector thread and remember how it ended.

        Without this an exception simply printed itself to stderr and the
        listener was gone with `status_text` still reading "Collector
        stopped", which is what an operator sees after a deliberate stop.
        """
        try:
            target()
        except Exception as exc:
            self._crash = f"{name}: {exc}"
            self.log.add(ERROR, f"The {name} thread stopped unexpectedly: {exc}",
                         detail=traceback.format_exc())
        else:
            if not self._stop.is_set():
                self._crash = f"{name} ended unexpectedly"

    def _note_error(self, exc: Exception) -> None:
        """Count a datagram the receive path could not process, and log at
        most one traceback a minute so a flood cannot fill the event log."""
        self._loop_errors += 1
        self.counters["errors"] = self.decoder.stats["errors"] + self._loop_errors
        now = time.time()
        if now - self._last_error_log >= 60:
            self._last_error_log = now
            self.log.add(ERROR, f"Receive error: {exc}",
                         detail=traceback.format_exc())

    def _receive(self) -> None:
        sock = self._sock
        while not self._stop.is_set() and sock is not None:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(data, address)
            except Exception as exc:
                self._note_error(exc)

    def _handle(self, data: bytes, address) -> None:
        exporter = address[0]
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

        if exporter not in self._seen_exporters:
            self._seen_exporters.add(exporter)
            self.log.add(NETFLOW, f"First packet from exporter {exporter}",
                         target=exporter,
                         detail=f"version  {int.from_bytes(data[:2], 'big')}\n"
                                f"bytes    {len(data)}\n"
                                f"sampling {self.decoder.sampling_for(exporter)}")
        gained = self.decoder.stats["templates"] - templates_before
        if gained:
            self.counters["last_template"] = time.time()
            self.log.add(NETFLOW, f"Received {gained} template(s) from {exporter}",
                         target=exporter)
        if self.decoder.stats["errors"] > errors_before:
            self.log.add(ERROR, f"Undecodable packet from {exporter}",
                         target=exporter,
                         detail=f"{len(data)} bytes, first 32: {data[:32].hex(' ')}")
        self.counters["errors"] = self.decoder.stats["errors"] + self._loop_errors
        if not flows:
            return
        try:
            self._queue.put_nowait((exporter, flows))
        except queue.Full:
            self.counters["dropped"] += len(flows)

    def _write(self) -> None:
        pending: list = []
        per_exporter: dict[str, list[int]] = {}
        last_flush = time.time()

        while not self._stop.is_set():
            try:
                exporter, flows = self._queue.get(timeout=0.4)
                pending.extend(flows)
                entry = per_exporter.setdefault(exporter, [0, 0, 1])
                entry[0] += 1
                entry[1] += len(flows)
                entry[2] = flows[0].sampling
            except queue.Empty:
                pass

            due = time.time() - last_flush >= 1.0
            if pending and (due or len(pending) >= 500):
                written = self.db.insert_flows(pending)
                self.counters["flows"] += written
                for exporter, (packets, flows_n, sampling) in per_exporter.items():
                    version = pending[0].version if pending else 0
                    self.db.touch_exporter(exporter, version, packets, flows_n, sampling)
                pending.clear()
                per_exporter.clear()
                last_flush = time.time()
                if self.on_batch:
                    self.on_batch()

        if pending:
            self.db.insert_flows(pending)

    # ----------------------------------------------------------------- status

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            if self._crash:
                return f"Collector stopped unexpectedly: {self._crash}"
            return "Collector stopped"
        address, port = self.bound or ("?", 0)
        base = f"Listening on {address}:{port} (UDP)"

        last = self.counters["last_packet"]
        if last:
            parts = [base, f"last packet {_ago(last)}"]
            template = self.counters["last_template"]
            # v9 and IPFIX are undecodable until a template arrives, and
            # exporters resend them only every few minutes, so how long ago the
            # last one came is worth as much as the packet time.
            parts.append(f"last template {_ago(template)}" if template
                         else "no template yet")
            return " \u00b7 ".join(parts)
        waiting = time.time() - self.started_at if self.started_at else 0
        if waiting > 60:
            return f"{base} \u00b7 no packets yet ({waiting / 60:.0f} min)"
        return f"{base} \u00b7 waiting for packets"

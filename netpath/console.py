"""The service console.

What used to be the whole desktop application is now a small window that runs
the server and shows what it is doing. The interface itself moved to the
browser, so this exists to answer three questions without a browser: is the
server up, who is connected, and how do I change the port or restart it.

Closing this window stops the service, so anywhere it should keep running
unattended wants the headless mode instead — see `--headless`.
"""

from __future__ import annotations

import ctypes
import heapq
import os
import sys
import threading
import time
import webbrowser
from collections import deque
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .eventlog import SYSTEM


class OutputCapture:
    """Tee stdout and stderr into the console window.

    Under pythonw.exe there is no terminal at all and both streams are None,
    so anything printed — a traceback from a worker, say — would otherwise be
    lost entirely. This keeps it where someone can read it.
    """

    def __init__(self, capacity: int = 2000):
        self.lines: deque = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._partial = ""
        self._originals: dict = {}

    def install(self) -> None:
        for name in ("stdout", "stderr"):
            self._originals[name] = getattr(sys, name)
            setattr(sys, name, _Tee(self._originals[name], self, name))

    def restore(self) -> None:
        for name, stream in self._originals.items():
            setattr(sys, name, stream)

    def add(self, text: str, source: str) -> None:
        with self._lock:
            self._partial += text
            while "\n" in self._partial:
                line, self._partial = self._partial.split("\n", 1)
                stamp = datetime.now().strftime("%H:%M:%S")
                self.lines.append((stamp, source, line.rstrip()))

    def drain_text(self) -> str:
        with self._lock:
            return "\n".join(f"{stamp}  {line}" for stamp, _, line in self.lines)

    def count(self) -> int:
        with self._lock:
            return len(self.lines)

    def clear(self) -> None:
        with self._lock:
            self.lines.clear()


class _Tee:
    def __init__(self, original, capture: OutputCapture, name: str):
        self._original = original
        self._capture = capture
        self._name = name

    def write(self, text):
        if self._original is not None:
            try:
                self._original.write(text)
            except Exception:
                pass
        self._capture.add(text, self._name)
        return len(text)

    def flush(self):
        if self._original is not None:
            try:
                self._original.flush()
            except Exception:
                pass

    def isatty(self):
        return False

CLIENT_COLUMNS = ["Client", "Requests", "Errors", "First seen", "Last seen", "Agent"]

# How many client rows the table draws. AccessLog.clients is described in its
# own docstring as "a live view, not an audit trail" and keeps one entry per
# source address for the life of the process -- every port-scanner source,
# every health-check probe, every DHCP-reassigned laptop. This table redrew
# all of them once a second on the GUI thread: at 20,000 remembered clients
# that is a 20,000-element sort plus 120,000 QTableWidgetItem allocations
# per tick, and the window becomes unusable long before the memory matters.
# The most recent 200 is what anyone reads; the header says how many there
# are in total.
CLIENT_ROWS = 200
REQUEST_COLUMNS = ["Time", "Client", "Method", "Path", "Status", "Took"]


def section(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("sectionTitle")
    return label


def _ago(ts: float) -> str:
    if not ts:
        return "—"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def client_rows(clients: dict, limit: int = CLIENT_ROWS) -> tuple[int, list[tuple]]:
    """(clients seen in total, the `limit` most recently seen as table rows).

    nlargest rather than sorting the whole dict: the caller runs once a
    second on the GUI thread and the dict holds one entry per source address
    the process has ever answered."""
    newest = heapq.nlargest(limit, clients.items(),
                            key=lambda item: item[1]["last_seen"])
    return len(clients), [
        (address, str(info["requests"]), str(info["errors"]),
         _ago(info["first_seen"]), _ago(info["last_seen"]),
         info["agent"] or "—", bool(info["errors"]))
        for address, info in newest]


def _size(total: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if total < 1024 or unit == "TB":
            return f"{total:.0f} B" if unit == "B" else f"{total:.1f} {unit}"
        total /= 1024
    return f"{total:.1f} TB"


def _duration(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


class ConsoleWindow(QMainWindow):
    def __init__(self, service, server, capture=None):
        super().__init__()
        self.service = service
        self.server = server
        self.capture = capture
        self._output_seen = -1
        self._clients_seen: tuple = ()

        from . import __version__

        self.setWindowTitle(f"SappiWhere {__version__} — service console")
        self.resize(1020, 720)
        self._build_ui()
        self._load_fields()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh)
        self.timer.start(1000)
        self._refresh()

    # ------------------------------------------------------------------- ui

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        layout.addWidget(self._status_card())
        layout.addWidget(self._listener_card())
        layout.addWidget(self._collectors_card())
        layout.addWidget(self._storage_card())

        splitter = QSplitter(Qt.Orientation.Vertical)

        clients = QWidget()
        clients_layout = QVBoxLayout(clients)
        clients_layout.setContentsMargins(0, 0, 0, 0)
        self.clients_heading = section("Connected clients")
        clients_layout.addWidget(self.clients_heading)
        self.client_table = self._table(CLIENT_COLUMNS)
        clients_layout.addWidget(self.client_table)
        splitter.addWidget(clients)

        requests = QWidget()
        requests_layout = QVBoxLayout(requests)
        requests_layout.setContentsMargins(0, 0, 0, 0)
        header = QHBoxLayout()
        header.addWidget(section("Recent requests"))
        hint = QLabel("static files are counted but not listed")
        hint.setObjectName("hint")
        header.addWidget(hint)
        header.addStretch(1)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear_access)
        header.addWidget(clear)
        requests_layout.addLayout(header)
        self.request_table = self._table(REQUEST_COLUMNS)
        requests_layout.addWidget(self.request_table)
        splitter.addWidget(requests)

        output = QWidget()
        output_layout = QVBoxLayout(output)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_header = QHBoxLayout()
        output_header.addWidget(section("Console output"))
        self.output_hint = QLabel("")
        self.output_hint.setObjectName("hint")
        output_header.addWidget(self.output_hint)
        output_header.addStretch(1)

        self.terminal_check = QCheckBox("Show terminal window")
        self.terminal_check.setToolTip(
            "The black window this was launched from. Hiding it does not stop "
            "the service; anything it would have printed appears below.")
        self.terminal_check.toggled.connect(self._toggle_terminal)
        if self._console_handle():
            self.terminal_check.setChecked(True)
            output_header.addWidget(self.terminal_check)

        clear_output = QPushButton("Clear")
        clear_output.clicked.connect(self._clear_output)
        output_header.addWidget(clear_output)
        output_layout.addLayout(output_header)

        self.output_view = QPlainTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setFont(theme.mono(9))
        self.output_view.setPlaceholderText(
            "Nothing printed yet. Errors from the collectors and the web "
            "server appear here.")
        output_layout.addWidget(self.output_view)
        splitter.addWidget(output)

        splitter.setSizes([220, 260, 180])
        layout.addWidget(splitter, 1)

        note = QLabel(
            "The interface itself is in the browser. Closing this window stops "
            "the service; to keep it running unattended, start it with "
            "<b>--headless</b> under a service manager instead.")
        note.setObjectName("hint")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.setCentralWidget(central)
        self.statusBar().showMessage("Starting…")

    def _table(self, columns) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setFont(theme.mono(9))
        return table

    def _status_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        row = QHBoxLayout(card)
        row.setContentsMargins(14, 10, 14, 10)

        self.dot = QLabel("\u25cf")
        self.dot.setStyleSheet(f"color: {theme.TEXT_FAINT.name()}; font-size: 16px;")
        row.addWidget(self.dot)

        column = QVBoxLayout()
        self.state_label = QLabel("Server stopped")
        self.state_label.setObjectName("stat")
        self.url_label = QLabel("")
        self.url_label.setObjectName("hint")
        self.url_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        column.addWidget(self.state_label)
        column.addWidget(self.url_label)
        row.addLayout(column)
        row.addStretch(1)

        self.open_button = QPushButton("Open in browser")
        self.open_button.setObjectName("primary")
        self.open_button.clicked.connect(self._open_browser)
        row.addWidget(self.open_button)

        self.toggle_button = QPushButton("Stop server")
        self.toggle_button.clicked.connect(self._toggle)
        row.addWidget(self.toggle_button)
        return card

    def _listener_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.addWidget(section("Listener"))

        row = QHBoxLayout()
        row.addWidget(QLabel("Bind address"))
        self.host_edit = QLineEdit()
        self.host_edit.setMaximumWidth(150)
        row.addWidget(self.host_edit)

        row.addWidget(QLabel("Port"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setMaximumWidth(100)
        row.addWidget(self.port_spin)

        row.addWidget(QLabel("Certificate"))
        self.cert_edit = QLineEdit()
        self.cert_edit.setPlaceholderText("blank = plain HTTP")
        row.addWidget(self.cert_edit, 1)
        browse_cert = QPushButton("…")
        browse_cert.setMaximumWidth(30)
        browse_cert.clicked.connect(lambda: self._browse(self.cert_edit, "certificate"))
        row.addWidget(browse_cert)

        row.addWidget(QLabel("Key"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("defaults to the certificate")
        row.addWidget(self.key_edit, 1)
        browse_key = QPushButton("…")
        browse_key.setMaximumWidth(30)
        browse_key.clicked.connect(lambda: self._browse(self.key_edit, "private key"))
        row.addWidget(browse_key)

        apply_button = QPushButton("Apply and restart")
        apply_button.setObjectName("primary")
        apply_button.clicked.connect(self._apply_listener)
        row.addWidget(apply_button)
        outer.addLayout(row)

        self.listener_hint = QLabel("")
        self.listener_hint.setObjectName("hint")
        self.listener_hint.setWordWrap(True)
        outer.addWidget(self.listener_hint)
        return card

    def _collectors_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.addWidget(section("Collectors"))
        self.collectors_label = QLabel("")
        self.collectors_label.setObjectName("stat")
        self.collectors_label.setWordWrap(True)
        outer.addWidget(self.collectors_label)
        return card

    # -------------------------------------------------------------- actions

    def _storage_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.addWidget(section("Databases"))
        self.storage_label = QLabel("")
        self.storage_label.setObjectName("stat")
        outer.addWidget(self.storage_label)
        hint = QLabel("Sizes include each file's write-ahead log. Caps are set "
                      "on the Settings tab in the browser.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        outer.addWidget(hint)
        return card

    def _refresh_storage(self) -> None:
        settings = self.service.settings
        rows = [
            ("App", self.service.app_db, 0),
            ("Traces", self.service.db, settings.get("max_trace_db_mb", 0)),
            ("Flows", self.service.flow_db, settings.get("max_flow_db_mb", 0)),
            ("SNMP traps", self.service.snmp_db, settings.get("max_snmp_db_mb", 0)),
            ("Syslog", self.service.syslog_db, settings.get("max_syslog_db_mb", 0)),
            ("IPAM", self.service.ipam_db, 0),
            ("Nodes", self.service.nodes_db, settings.get("max_nodes_db_mb", 0)),
            ("Alerts", self.service.alerts_db, settings.get("max_alerts_db_mb", 0)),
        ]
        lines = []
        for label, database, cap_mb in rows:
            used = database.size_bytes()
            cap = int(cap_mb) * 1024 * 1024
            share = f"{used / cap * 100:5.1f}% of {int(cap_mb)} MB" if cap else "no cap"
            lines.append(f"{label:8s} {_size(used):>10s}   {share:>22s}   "
                         f"{database.path}")
        self.storage_label.setText("\n".join(lines))

    def _load_fields(self) -> None:
        """Read from the server, not the saved settings.

        They are normally the same, but if the two ever disagree the fields
        should say where the server actually is rather than where it was asked
        to be.
        """
        self.host_edit.setText(self.server.host)
        self.port_spin.setValue(int(self.server.port))
        self.cert_edit.setText(self.server.certfile or "")
        self.key_edit.setText(self.server.keyfile or "")

    def _browse(self, field: QLineEdit, what: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, f"Choose a {what}", "",
                                              "PEM files (*.pem *.crt *.key);;All files (*)")
        if path:
            field.setText(path)

    def _apply_listener(self) -> None:
        host = self.host_edit.text().strip() or "0.0.0.0"
        port = self.port_spin.value()
        cert = self.cert_edit.text().strip()
        key = self.key_edit.text().strip()

        if cert and not os.path.isfile(cert):
            QMessageBox.warning(self, "Certificate", f"No such file:\n{cert}")
            return

        self.service.save_listener_settings(
            {"web_host": host, "web_port": port,
             "web_cert": cert, "web_key": key})

        ok = self.server.restart(host=host, port=port, certfile=cert, keyfile=key)
        if ok:
            self.service.log.add(SYSTEM, f"Web server restarted on {self.server.url}")
            self.statusBar().showMessage(f"Listening on {self.server.url}", 6000)
        else:
            QMessageBox.warning(self, "Could not start the server",
                                self.server.error or "Unknown error")
        self._refresh()

    def _toggle(self) -> None:
        if self.server.running:
            self.server.stop()
            self.service.log.add(SYSTEM, "Web server stopped from the console")
        else:
            if not self.server.start(block=False):
                QMessageBox.warning(self, "Could not start the server",
                                    self.server.error or "Unknown error")
        self._refresh()

    def _open_browser(self) -> None:
        if not self.server.running:
            return
        try:
            webbrowser.open(self.server.url)
        except Exception:
            QDesktopServices.openUrl(self.server.url)

    def _clear_access(self) -> None:
        self.server.access.clear()
        self._refresh()

    @staticmethod
    def _console_handle() -> int:
        """The terminal this was launched from, if there is one.

        Zero under pythonw.exe, which is the point of launching that way.
        """
        if os.name != "nt":
            return 0
        try:
            return int(ctypes.windll.kernel32.GetConsoleWindow())
        except Exception:
            return 0

    def _toggle_terminal(self, visible: bool) -> None:
        handle = self._console_handle()
        if not handle:
            return
        try:
            ctypes.windll.user32.ShowWindow(handle, 5 if visible else 0)
        except Exception:
            pass

    def _clear_output(self) -> None:
        if self.capture:
            self.capture.clear()
        self.output_view.clear()
        self._output_seen = -1

    # -------------------------------------------------------------- refresh

    def _refresh(self) -> None:
        running = self.server.running
        colour = theme.OK if running else (theme.FAIL if self.server.error
                                           else theme.TEXT_FAINT)
        self.dot.setStyleSheet(f"color: {QColor(colour).name()}; font-size: 16px;")
        self.toggle_button.setText("Stop server" if running else "Start server")
        self.open_button.setEnabled(running)

        snapshot = self.server.access.snapshot()
        if running:
            uptime = _duration(time.time() - self.server.access.started_at)
            self.state_label.setText(
                f"Server running   {snapshot['total']} requests   "
                f"{snapshot['active']} open   uptime {uptime}")
            self.url_label.setText(f"{self.server.url}   "
                                   f"({'TLS' if self.server.certfile else 'plain HTTP'})")
        else:
            self.state_label.setText("Server stopped")
            self.url_label.setText(self.server.error or "")

        # What is actually true and worth knowing at a glance: whether the
        # traffic is encrypted, and how far the listener reaches. Until
        # 4.37.0 this card told the operator, once a second, that the product
        # had no sign-in -- text left over from before auth.py, the login
        # page, the per-module read/write permissions, the forced first-run
        # password change and the sign-in throttling existed. Someone who
        # believes it either fronts the appliance with a reverse proxy it does
        # not need, or reads it after deploying and concludes that the login
        # page they have been using is decorative.
        reach = ("reachable from every interface on this host"
                 if str(self.server.host) in ("", "0.0.0.0", "::")
                 else f"reachable on {self.server.host} only")
        self.listener_hint.setText(
            ("Encrypted with TLS." if self.server.certfile else
             "Plain HTTP: no certificate is configured, so sign-ins and "
             "session cookies cross the network in the clear.")
            + f" The listener is {reach}. Sign-in is required for every page "
              "except the login page itself."
            + (f"  Last error: {self.server.error}" if self.server.error else ""))

        self._refresh_collectors()
        self._refresh_storage()
        self._fill_clients(snapshot)
        self._fill_requests(snapshot)
        self._refresh_output()

    def _refresh_output(self) -> None:
        if not self.capture:
            return
        count = self.capture.count()
        if count == self._output_seen:
            return
        self._output_seen = count
        # Only repaint when something new arrived; the scroll position is
        # kept unless the view was already at the bottom.
        bar = self.output_view.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        self.output_view.setPlainText(self.capture.drain_text())
        if at_bottom:
            self.output_view.verticalScrollBar().setValue(
                self.output_view.verticalScrollBar().maximum())
        self.output_hint.setText(f"{count} line(s)")

    def _refresh_collectors(self) -> None:
        service = self.service
        names = service.hostname_stats()
        parts = [
            f"NetPath   {'running' if service.monitor.running else 'stopped'} \u00b7 "
            f"{len(service.db.targets())} destinations \u00b7 "
            f"{service.monitor.workers} workers",
            f"NetFlow   {service.collector.status_text()}",
            f"SNMP      {service.snmp.status_text()}",
            f"Syslog    {service.syslog.status_text()}",
            f"Nodes     {service.node_poller.status_text()}",
            f"Alerts    {service.alert_engine.status_text()}",
            f"DNS       {names['named']}/{names['cached']} named"
            + (f", {names['pending']} pending" if names["pending"] else ""),
        ]
        self.collectors_label.setText("\n".join(parts))

    def _fill_clients(self, snapshot: dict) -> None:
        """The CLIENT_ROWS most recently seen clients, redrawn only when
        something about them changed -- the same guard _refresh_output()
        already uses for the log view, because this runs once a second on
        the GUI thread."""
        total, rows = client_rows(snapshot["clients"])
        if (total, rows) == self._clients_seen:
            return
        self._clients_seen = (total, rows)

        self.clients_heading.setText(
            "Connected clients" if total <= CLIENT_ROWS else
            f"Connected clients — {total:,} seen, showing the "
            f"{CLIENT_ROWS} most recent")
        self.client_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            for column, value in enumerate(entry[:6]):
                item = QTableWidgetItem(value)
                if column == 2 and entry[6]:
                    item.setForeground(QColor(theme.WARN))
                self.client_table.setItem(row, column, item)

    def _fill_requests(self, snapshot: dict) -> None:
        recent = snapshot["recent"][:200]
        self.request_table.setRowCount(len(recent))
        for row, entry in enumerate(recent):
            values = [
                datetime.fromtimestamp(entry["ts"]).strftime("%H:%M:%S"),
                entry["client"], entry["method"], entry["path"],
                str(entry["status"]), f"{entry['ms']:.1f} ms",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 4 and entry["status"] >= 400:
                    item.setForeground(QColor(theme.FAIL))
                self.request_table.setItem(row, column, item)

    def closeEvent(self, event) -> None:
        self.timer.stop()
        if self.capture:
            self.capture.restore()
        self.server.stop()
        self.service.shutdown()
        super().closeEvent(event)

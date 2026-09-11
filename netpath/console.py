"""The service console: a small window that runs the server and answers,
without a browser, whether it's up, who's connected, and how to change the
port or restart it. Closing this window stops the service — use
`--headless` anywhere it should keep running unattended.
"""

from __future__ import annotations

import ctypes
import heapq
import os
import sys
import threading
import time
import traceback
import webbrowser
from datetime import datetime

from PySide6.QtCore import Qt, QTimer, Signal
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
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import procstats, theme
from .eventlog import SYSTEM
from .web.service import STORES, db_for


class OutputCapture:
    """Tee stdout and stderr so `print()` cannot raise under pythonw.exe.

    Under pythonw.exe both streams are None; without this, the first
    `print()` anywhere would raise `AttributeError` instead of being lost.
    """

    def __init__(self):
        self._originals: dict = {}

    def install(self) -> None:
        for name in ("stdout", "stderr"):
            self._originals[name] = getattr(sys, name)
            setattr(sys, name, _Tee(self._originals[name]))

    def restore(self) -> None:
        for name, stream in self._originals.items():
            setattr(sys, name, stream)


class _Tee:
    def __init__(self, original):
        self._original = original

    def write(self, text):
        if self._original is not None:
            try:
                self._original.write(text)
            except Exception:
                pass
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


# How long the window waits for the teardown before ending the process
# anyway. Service.shutdown() is bounded by its own SHUTDOWN_DEADLINE_S plus
# the database grace, so this is that with room to spare rather than a guess.
FORCE_QUIT_MS = 20_000

# How long a teardown waits for a self-update already installing. Longer than
# the shutdown budget on purpose: the install owns the teardown at that point
# and the process is going to be replaced anyway.
UPDATE_WAIT_S = 120.0


def run_teardown(server, service, on_status, *, wait_for_job=None,
                 job_wait_s: float = UPDATE_WAIT_S) -> str:
    """Stop the server and the service. Returns what happened.

    Qt-free and module-level so it can be driven straight from a test: it is
    the policy, and closeEvent below is only the plumbing that runs it off the
    GUI thread.

    "update-owns-it" means a self-update is installing and has not finished.
    Nothing is torn down in that case: the install runs the same stop/shutdown
    sequence itself from its own thread and then restarts the process, so
    closing app.db underneath it here would break the install this is trying
    to get out of the way of.
    """
    if wait_for_job is None:
        from . import selfupdate
        wait_for_job = selfupdate.wait_for_job
    if not wait_for_job(0.0):
        # Only said when there is actually one to wait for.
        on_status("An update is installing — waiting for it to finish…")
        if not wait_for_job(job_wait_s):
            return "update-owns-it"
    on_status("Stopping the web server…")
    server.stop()
    # Strictly after the listener is down, the same order __main__.py uses on
    # both paths: a request in flight against a closing store is the one thing
    # this ordering exists to prevent.
    on_status("Stopping collectors and closing databases…")
    service.shutdown()
    return "stopped"


class _ShutdownNotice(QWidget):
    """What replaces the console while the teardown runs. The window itself
    is already closed by then; without this there is nothing on screen and
    the process merely looks hung, which is the complaint this whole change
    is about."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SappiWhere — shutting down")
        self.setFixedWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)
        heading = QLabel("Shutting down…")
        heading.setObjectName("stat")
        layout.addWidget(heading)
        self.detail = QLabel("Stopping collectors and closing databases.")
        self.detail.setObjectName("hint")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)
        bar = QProgressBar()
        bar.setRange(0, 0)          # indeterminate: there is no honest per-cent
        bar.setTextVisible(False)
        layout.addWidget(bar)

    def say(self, message: str) -> None:
        self.detail.setText(message)


class ConsoleWindow(QMainWindow):
    # Emitted from the teardown thread; Qt delivers a cross-thread signal as
    # a queued connection, so both handlers run on the GUI thread. Nothing on
    # that thread may be touched from the teardown thread directly.
    teardown_status = Signal(str)
    teardown_done = Signal(str)
    # Same contract for the storage card's figures, which are read off the
    # GUI thread so a database lock cannot freeze the window.
    storage_ready = Signal(str)

    def __init__(self, service, server, capture=None):
        super().__init__()
        self.service = service
        self.server = server
        self.capture = capture
        self._clients_seen: tuple = ()
        self._proc_sample: dict = {}
        self._teardown_started = False
        self._notice = None
        self._force_timer = None
        self._storage_thread: threading.Thread | None = None

        from . import __version__

        self.setWindowTitle(f"SappiWhere {__version__} — service console")
        self.resize(1020, 720)
        self._build_ui()
        self._load_fields()

        self.storage_ready.connect(self.storage_label.setText)
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
        layout.addWidget(self._storage_card())

        clients = QWidget()
        clients_layout = QVBoxLayout(clients)
        clients_layout.setContentsMargins(0, 0, 0, 0)
        self.clients_heading = section("Connected clients")
        clients_layout.addWidget(self.clients_heading)
        self.client_table = self._table(CLIENT_COLUMNS)
        clients_layout.addWidget(self.client_table)
        layout.addWidget(clients, 1)

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
        self.dot.setStyleSheet(f"color: {theme.LINE.name()}; font-size: 16px;")
        row.addWidget(self.dot)

        column = QVBoxLayout()
        self.state_label = QLabel("Server stopped")
        self.state_label.setObjectName("stat")
        self.url_label = QLabel("")
        self.url_label.setObjectName("hint")
        self.url_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.process_label = QLabel("")
        self.process_label.setObjectName("hint")
        self.process_label.setFont(theme.mono(9))
        column.addWidget(self.state_label)
        column.addWidget(self.url_label)
        column.addWidget(self.process_label)

        self.terminal_check = QCheckBox("Show terminal window")
        self.terminal_check.setToolTip(
            "The black window this was launched from. Hiding it does not "
            "stop the service.")
        self.terminal_check.toggled.connect(self._toggle_terminal)
        if self._console_handle():
            self.terminal_check.setChecked(True)
            column.addWidget(self.terminal_check)

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
        hint = QLabel("Sizes include each file's write-ahead log, and each "
                      "line says how far back that file still reaches. Caps "
                      "are set on the Settings tab in the browser.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        outer.addWidget(hint)
        return card

    def _refresh_storage(self) -> None:
        """Ask a worker thread for the figures; the last ones stay on screen
        meanwhile.

        Every line here is a database read — size_bytes() stats three files
        and oldest_ts() is a MIN() over an index — and each takes that
        store's lock, which a poll, a prune or a device purge can be
        holding. Run on the GUI thread at 1 Hz, as this was, that is the
        window not repainting while a background delete runs.
        """
        if self._storage_thread is not None and self._storage_thread.is_alive():
            return
        self._storage_thread = threading.Thread(
            target=self._read_storage, name="console-storage", daemon=True)
        self._storage_thread.start()

    def _read_storage(self) -> None:
        # Off the GUI thread. Driven from service.STORES rather than a list
        # of its own: this card used to name ten of the thirteen stores and
        # read IPAM's cap as 0, so the console called a capped file uncapped.
        settings = self.service.settings
        rows = []
        for store in STORES:
            database = db_for(self.service, store)
            if database is None:
                continue
            cap_mb = settings.get(store.cap_key, 0) if store.cap_key else 0
            rows.append((store.label, database, cap_mb))
        lines = []
        try:
            for label, database, cap_mb in rows:
                used = database.size_bytes()
                cap = int(cap_mb) * 1024 * 1024
                share = (f"{used / cap * 100:5.1f}% of {int(cap_mb)} MB"
                         if cap else "no cap")
                oldest = database.oldest_ts()
                # What the cap beside it has actually cost, in history, not bytes.
                age = (f"oldest {_duration(time.time() - oldest)}" if oldest
                       else "no history")
                lines.append(f"{label:13s} {_size(used):>10s}   {share:>22s}   "
                             f"{age:>16s}   {database.path}")
        except Exception:                                     # noqa: BLE001
            # A store closing under a shutdown, most likely. The card keeps
            # the previous figures rather than the traceback.
            return
        self.storage_ready.emit("\n".join(lines))

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

    # -------------------------------------------------------------- refresh

    def _refresh(self) -> None:
        running = self.server.running
        colour = theme.OK if running else (theme.FAIL if self.server.error
                                           else theme.LINE)
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
        # traffic is encrypted, and how far the listener reaches.
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

        self._refresh_storage()
        self._refresh_process()
        self._fill_clients(snapshot)

    def _refresh_process(self) -> None:
        sample = procstats.read_self()
        pct = procstats.cpu_percent(self._proc_sample, sample)
        self._proc_sample = sample
        ram = _size(sample["rss_bytes"]) if "rss_bytes" in sample else "—"
        cpu = f"{pct:.1f}%" if pct is not None else "—"
        self.process_label.setText(f"RAM {ram} · CPU {cpu}")

    def _fill_clients(self, snapshot: dict) -> None:
        """The CLIENT_ROWS most recently seen clients, redrawn only when
        something about them changed, because this runs once a second on
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

    def closeEvent(self, event) -> None:
        """Accept the close at once and tear down on a thread of its own.

        This used to run server.stop() and service.shutdown() inline. That is
        the GUI thread, so for the whole teardown the window was frozen,
        Windows ghosted it as "Not Responding", and operators ended the task —
        which aborted the teardown partway through. The work is the same; only
        the thread it happens on, and the fact that the click is honoured
        immediately, have changed.
        """
        event.accept()
        if self._teardown_started:
            return
        self._teardown_started = True

        # Before anything closes: this fires once a second and reads the
        # stores the teardown is about to close.
        self.timer.stop()
        # sys.stdout is process-wide state; swap it back here, on the GUI
        # thread, rather than from the teardown thread.
        if self.capture:
            self.capture.restore()

        self._notice = _ShutdownNotice()
        self._notice.show()
        self.teardown_status.connect(self._notice.say)
        self.teardown_done.connect(self._on_teardown_done)

        self._force_timer = QTimer(self)
        self._force_timer.setSingleShot(True)
        self._force_timer.timeout.connect(self._force_quit)
        self._force_timer.start(FORCE_QUIT_MS)

        threading.Thread(target=self._run_teardown,
                         name="sappiwhere-console-shutdown",
                         daemon=True).start()

    def _run_teardown(self) -> None:
        """The teardown thread. Touches no widget — it reports through the
        signals only."""
        outcome = "stopped"
        try:
            outcome = run_teardown(self.server, self.service,
                                   self.teardown_status.emit)
        except Exception:
            traceback.print_exc()
            outcome = "failed"
        self.teardown_done.emit(outcome)

    def _on_teardown_done(self, outcome: str) -> None:
        self._force_timer.stop()
        if outcome == "update-owns-it":
            # The install is running the same teardown from its own thread and
            # ends in spawning the replacement process; exiting here would
            # leave the machine with nothing running. The notice stays up
            # saying so — closing it would leave an empty desktop for however
            # long the install takes, which is the impression this whole
            # change exists to remove — and the timer is re-armed so that an
            # install which somehow never finishes still ends up closing this
            # process rather than leaving it forever.
            if self._notice is not None:
                self._notice.say("An update is installing. SappiWhere will "
                                 "restart itself when it finishes.")
            self._force_timer.start(FORCE_QUIT_MS)
            return
        if self._notice is not None:
            self._notice.close()
        self._exit()

    def _force_quit(self) -> None:
        """The teardown overran its budget. End the process rather than leave
        an operator with nothing on screen and a live PID."""
        from . import selfupdate

        # Never out from under an install: it is about to spawn the
        # replacement, and killing this process first leaves nothing running.
        # A zero wait, because this runs on the GUI thread.
        if not selfupdate.wait_for_job(0.0):
            selfupdate._log_restart(
                "console teardown overran, but an update is still installing; "
                "waiting for it rather than ending its replacement")
            self._force_timer.start(FORCE_QUIT_MS)
            return
        selfupdate._log_restart(
            f"console teardown did not finish within "
            f"{FORCE_QUIT_MS / 1000:.0f}s; ending the process")
        self._exit()

    @staticmethod
    def _exit() -> None:
        """os._exit, not app.quit().

        app.exec() returning drops into interpreter shutdown, and two things
        there are unbounded: concurrent.futures joins every ThreadPoolExecutor
        thread with no timeout (they are not daemons, and cancel_futures only
        drops work that had not started), and the self-updater's own threads
        are deliberately not daemons either. That is the window-is-gone,
        process-still-running state that has operators reaching for Task
        Manager. Every store is closed by the time this runs, so there is
        nothing left to flush but the streams.

        Both callers have already established that no update is in flight.
        """
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

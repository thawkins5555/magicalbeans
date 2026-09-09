"""Closing the service console must not freeze the window, and must actually
end the process.

The complaint this suite exists for: closing the desktop application took an
extremely long time and often had to be ended from Task Manager.
ConsoleWindow.closeEvent ran server.stop() and service.shutdown() inline --
on the Qt GUI thread -- and that teardown was measured at 37-63s against a
real fleet (see netpath/selfupdate.py's module comment). For all of it the
window was frozen, so Windows ghosted it as "Not Responding" and operators
ended the task, which aborted the teardown partway through.

Two things are asserted here and nowhere else, because both need a real
QApplication and a real ConsoleWindow:

  1. closeEvent returns immediately -- with a deliberately slow teardown
     underneath it -- and the GUI thread keeps processing events while that
     teardown runs. That is the difference between a window that closes and
     one Windows paints over as hung.
  2. the teardown still runs to completion afterwards, and the process is
     ended rather than left to unwind through an interpreter shutdown that
     joins ThreadPoolExecutor threads with no timeout.

Offscreen, so it needs no display. Skipped where PySide6 is absent -- CI's
suite job installs only paramiko, so this reports SKIP there and runs on a
developer machine, which is where the console is used anyway.
"""
import os
import shutil
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
except ImportError as exc:                # run_all.py reports this as SKIP
    print(f"SKIP: PySide6 is not importable, so there is no console to close ({exc})")
    raise SystemExit(77)

from netpath import theme                                    # noqa: E402
from netpath.console import ConsoleWindow, OutputCapture      # noqa: E402
from netpath.web import Service, WebServer                    # noqa: E402

TMPDIR = _paths.tmpdir("console_shutdown_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")

data_dir = os.path.join(TMPDIR, "console")
os.makedirs(data_dir, exist_ok=True)
service = Service(*[os.path.join(data_dir, n + ".db") for n in DB_NAMES])
# Port 0: a real listener on whatever the OS hands out, so nothing here can
# collide with another suite or with a developer's own instance.
server = WebServer(service, host="127.0.0.1", port=0)
server.start(block=False)

# A teardown that takes long enough to be unmistakable. The real one is
# bounded now (Service.SHUTDOWN_DEADLINE_S), but the point of this suite is
# that however long it takes, the window does not wait for it.
TEARDOWN_S = 2.0
torn_down = threading.Event()
real_shutdown = service.shutdown


def slow_shutdown(*args, **kwargs):
    time.sleep(TEARDOWN_S)
    real_shutdown(*args, **kwargs)
    torn_down.set()


service.shutdown = slow_shutdown

# The real _exit calls os._exit, which would take this test process with it.
exits = []
ConsoleWindow._exit = staticmethod(lambda: exits.append(time.monotonic()))

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
app.setStyleSheet(theme.STYLESHEET)
window = ConsoleWindow(service, server, capture=OutputCapture())
window.show()

measured = {}
heartbeats = []


def close_it():
    started = time.monotonic()
    window.close()                     # exactly what the X button does
    measured["started"] = started
    measured["close_s"] = time.monotonic() - started


# Heartbeats spanning the teardown: each one only runs if the GUI thread is
# free to process events, which is the whole question.
for _ms in (400, 700, 1000, 1400, 1800):
    QTimer.singleShot(_ms, lambda: heartbeats.append(time.monotonic()))
QTimer.singleShot(200, close_it)
QTimer.singleShot(int((TEARDOWN_S + 3) * 1000), app.quit)
app.exec()

check("closeEvent returns at once instead of running the teardown inline",
      measured.get("close_s", 99) < 0.5, f"{measured.get('close_s', -1):.3f}s")
# Ran *during* the teardown, not merely at some point afterwards: with the
# teardown inline every heartbeat still fires eventually, so counting them is
# not the test -- the question is whether the GUI thread was free while the
# teardown was in flight.
_during = [t for t in heartbeats
           if measured.get("started", 0) < t
           < measured.get("started", 0) + TEARDOWN_S]
check("...and the GUI thread keeps processing events WHILE the teardown runs, "
      "so Windows never paints the window as Not Responding",
      len(_during) >= 2,
      f"{len(_during)} of {len(heartbeats)} heartbeats landed inside the "
      f"{TEARDOWN_S:.0f}s teardown window")
check("the teardown still ran to completion on its own thread",
      torn_down.wait(TEARDOWN_S + 10))
check("...and the process is ended once it finishes, rather than left to "
      "unwind through an interpreter shutdown that joins pool threads untimed",
      len(exits) == 1, f"{len(exits)} exit call(s)")

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

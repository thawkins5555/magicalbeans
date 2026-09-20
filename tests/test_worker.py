"""netpath/worker.py: the pieces every background worker shares, exercised
incidentally elsewhere but pinned nowhere on their own. ago()'s four bands
and their boundaries, _join leaving an unfinished thread attached so
running() stays honest, _finish_stop_draining bounding the drain by the
in-flight budget rather than the whole remaining deadline (min, not max),
_bump's locked read-modify-write under concurrent callers, and hidden()
off Windows.
"""
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import worker as worker_mod
from netpath.worker import Worker, ago, hidden

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------------------ ago

BASE = 1_700_000_000.0
real_time = worker_mod.time.time
worker_mod.time.time = lambda: BASE
try:
    check("ago(0) means never polled", ago(0) == "never")
    check("just under 5s old reads as just now",
          ago(BASE - 4.9) == "just now", ago(BASE - 4.9))
    check("exactly 5s old is the seconds band, not just now",
          ago(BASE - 5.0) == "5s ago", ago(BASE - 5.0))
    check("89s old is still the seconds band",
          ago(BASE - 89.0) == "89s ago", ago(BASE - 89.0))
    check("exactly 90s old moves to the minutes band",
          ago(BASE - 90.0).endswith("m ago"), ago(BASE - 90.0))
    check("5399s old is still the minutes band",
          ago(BASE - 5399.0).endswith("m ago"), ago(BASE - 5399.0))
    check("exactly 5400s old moves to the hours band",
          ago(BASE - 5400.0) == "1.5h ago", ago(BASE - 5400.0))
finally:
    worker_mod.time.time = real_time

# --------------------------------------------------------------------- hidden

if worker_mod.IS_WINDOWS:
    check("hidden() returns creationflags/startupinfo on Windows",
          "creationflags" in hidden() and "startupinfo" in hidden(), hidden())
else:
    check("hidden() is a no-op off Windows", hidden() == {}, hidden())


# --------------------------------------------------------- a minimal worker

class _Worker(Worker):
    THREAD_NAME = "test-worker"

    def __init__(self):
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.counters = {}

    def _loop(self):
        self._stop.wait()


# ------------------------------------------------------------------- _join

w = _Worker()
w._spawn()
w._join(timeout=0.1)
check("a thread that outlives the join timeout stays attached",
      w.running and w._thread is not None, (w.running, w._thread))

w._stop.set()
w._join(timeout=2.0)
check("...and a join that actually finishes detaches it",
      not w.running and w._thread is None, (w.running, w._thread))

# ----------------------------------------------------------------------_bump

b = _Worker()
old_interval = sys.getswitchinterval()
sys.setswitchinterval(0.0001)
try:
    threads = [threading.Thread(target=lambda: [b._bump("n") for _ in range(2000)])
               for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
finally:
    sys.setswitchinterval(old_interval)
check("_bump's counter is exact under concurrent callers (the lock holds)",
      b.counters.get("n") == 20 * 2000, b.counters.get("n"))


# ------------------------------------------------------ _finish_stop_draining

class _DrainWorker(_Worker):
    def __init__(self, budget_s):
        super().__init__()
        self._stop.set()   # begin_stop already ran; _join returns at once
        self._budget_s = budget_s

    def inflight(self):
        return [1]   # never empties, so drain() always runs its full timeout

    def _inflight_budget_s(self):
        return self._budget_s


d = _DrainWorker(budget_s=0.2)
deadline = time.monotonic() + 5.0   # far more time left than the budget
started = time.monotonic()
d._finish_stop_draining(deadline)
elapsed = time.monotonic() - started
check("_finish_stop_draining bounds the drain by the in-flight budget, not "
      "the whole remaining deadline (min, not max)",
      elapsed < 1.0, elapsed)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")

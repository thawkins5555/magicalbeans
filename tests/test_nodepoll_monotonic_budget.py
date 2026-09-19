"""A poll/walk budget deadline must be immune to a backward wall-clock step
(NTP correction, DST, a suspended VM resuming) -- it is measured on
time.monotonic(), never time.time(). Worker.drain() is the simplest of the
four sites converted for this (the others are netpath/nodepoll/
identify_mixin.py, vlan_mixin.py and vendor_sensor_psu_mixin.py's walk
budgets, exercised indirectly by the SNMP walk suites); this pins the
mechanism directly, with time.time() pinned to a frozen, wildly wrong value
throughout the wait so a regression back to wall-clock deadline math would
hang rather than silently pass.
"""
import sys
import threading
import time as real_time

import _paths  # noqa: F401
import netpath.worker as worker_mod

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _FrozenWallClock:
    """time() never advances (simulating a wall clock stuck, or stepped, at
    some other instant); monotonic()/sleep() fall through to the real clock,
    so a monotonic-based deadline still elapses in real time."""

    def __init__(self, frozen_at: float):
        self._frozen_at = frozen_at

    def time(self) -> float:
        return self._frozen_at

    def __getattr__(self, name):
        return getattr(real_time, name)


class _AlwaysBusy(worker_mod.Worker):
    def inflight(self):
        return [1]


clock = _FrozenWallClock(0.0)          # 1970-01-01: as wrong as a wall clock gets
worker_mod.time = clock
try:
    worker = _AlwaysBusy()
    result = {}

    def _run():
        started = real_time.monotonic()
        result["drained"] = worker.drain(timeout_s=0.2)
        result["elapsed"] = real_time.monotonic() - started

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=5.0)

    check("drain() returns within 5s despite a frozen/wrong wall clock "
          "(a regression to time.time() here would hang instead)",
          not thread.is_alive())
    if not thread.is_alive():
        check("drain() reports the work never cleared", result["drained"] is False)
        check("...having actually waited out its real budget on the monotonic "
              "clock, not an instantly-expired or never-expiring wall-clock one",
              0.15 <= result["elapsed"] <= 2.0, result.get("elapsed"))
finally:
    worker_mod.time = real_time

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

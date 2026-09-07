"""procstats.py: the RAM/CPU readout the service console's status card shows
once a second. Standalone rather than through ConsoleWindow — PySide6 is not
a dependency of this suite, whether or not it is installed.
"""
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import procstats  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------------------- read_self()

first = procstats.read_self()
check("read_self() reports positive resident memory",
      first.get("rss_bytes", 0) > 0, str(first))
check("...and a wall clock timestamp",
      first.get("wall", 0) > 0, str(first))

# Burn some CPU so a second sample can show ticks moving, on whichever
# platform answered the first one.
deadline = time.time() + 0.3
busy = 0
while time.time() < deadline:
    busy += 1
second = procstats.read_self()

if "cpu_ticks_s" in first:
    check("cpu_ticks_s is non-decreasing across a busy loop",
          second.get("cpu_ticks_s", -1) >= first["cpu_ticks_s"],
          f"{first['cpu_ticks_s']} -> {second.get('cpu_ticks_s')}")
else:
    print("SKIP  cpu_ticks_s not available on this platform")

# -------------------------------------------------------------- cpu_percent()

check("cpu_percent() is None with no prior sample",
      procstats.cpu_percent({}, second) is None)
check("cpu_percent() is None when the wall clock did not advance",
      procstats.cpu_percent({"cpu_ticks_s": 1.0, "wall": 100.0},
                            {"cpu_ticks_s": 2.0, "wall": 100.0}) is None)
check("cpu_percent() is None without cpu_ticks_s on either side",
      procstats.cpu_percent({"wall": 1.0}, {"wall": 2.0}) is None)

half_core = procstats.cpu_percent({"cpu_ticks_s": 1.0, "wall": 0.0},
                                  {"cpu_ticks_s": 1.5, "wall": 1.0})
check("cpu_percent() maths: half a core-second over one wall second is 50%",
      half_core == 50.0, str(half_core))

two_cores = procstats.cpu_percent({"cpu_ticks_s": 0.0, "wall": 0.0},
                                  {"cpu_ticks_s": 2.0, "wall": 1.0})
check("...two core-seconds over one wall second is 200%",
      two_cores == 200.0, str(two_cores))

if FAILS:
    print(f"\n{len(FAILS)} check(s) failed: " + ", ".join(FAILS))
    raise SystemExit(1)
print("\nall checks passed")

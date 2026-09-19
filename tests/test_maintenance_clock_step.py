"""A backward wall-clock step (NTP correction, VM resume) must not stall
Service.run_maintenance()'s 15-minute gate for the size of the step.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on
failure.
"""
import os
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web import Service, service as service_mod

TMPDIR = _paths.tmpdir("maintenance_clock_step_")

FAILS: list[str] = []


def check(name, ok, detail="") -> None:
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")


def new_service():
    return Service(*[os.path.join(TMPDIR, name + ".db") for name in DB_NAMES])


class FakeClock:
    def __init__(self, t):
        self.t = t

    def time(self):
        return self.t


def main() -> int:
    service = new_service()
    runs = []
    service._run_maintenance_body = lambda force=False: runs.append(1)

    clock = FakeClock(1000.0)
    real_time = service_mod.time
    service_mod.time = clock
    try:
        service.run_maintenance()
        check("an interval already elapsed since _last_maintenance runs",
              len(runs) == 1, f"runs={len(runs)}")

        clock.t = 500.0  # a 500 s backward step
        service.run_maintenance()
        check("right after a backward step, the gate still holds (no double run)",
              len(runs) == 1, f"runs={len(runs)}")

        clock.t = 500.0 + service_mod.MAINTENANCE_INTERVAL_S - 1
        service.run_maintenance()
        check("...and stays held for one interval measured from the step, "
              "not from the pre-step timestamp",
              len(runs) == 1, f"runs={len(runs)}")

        clock.t = 500.0 + service_mod.MAINTENANCE_INTERVAL_S
        service.run_maintenance()
        check("...but never longer than one interval from the step",
              len(runs) == 2, f"runs={len(runs)}")
    finally:
        service_mod.time = real_time

    print()
    if FAILS:
        print(f"FAILURES: {len(FAILS)}")
        for item in FAILS:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

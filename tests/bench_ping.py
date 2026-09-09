"""What one ICMP probe costs on each path this host can take.

Deliberately not a test_*.py: the answer is a property of the operating
system under it, so this prints numbers rather than asserting them
(run_all.py only picks up test_*.py).

    python3 tests/bench_ping.py [probes ...] [--target 127.0.0.1]
                                [--count 3] [--fleet 2000] [--interval 60]

Each `probes` figure is one run of every mode NETPATH_PING_MODE offers.

The reason this exists is RUNBOOK.md:368-375: there is no unprivileged ICMP
socket on Windows, so the poller forks a real `ping.exe` per probe, three per
device per poll, measured there at 15.6 ms each — about 94 seconds of
process-creation work per 60-second window across a 2,000-device fleet,
before SNMP has cost anything. That figure is quoted in an operator-facing
runbook and nothing re-measures it, so this does, on whatever machine is
asking.

127.0.0.1 by default, which is what makes it runnable anywhere: the target
answers immediately on every platform, so what is left in the measurement is
the cost of the MECHANISM — a fork/exec, or a socket — rather than the
network. That is the number the poll pool actually pays.

Every mode is asked through ipam_scan's own `_icmp_socket_kind()` and
`ping_mode_summary()` rather than through anything this file knows about
ICMP, so a new implementation added to ipam_scan.py (a Windows
iphlpapi/IcmpSendEcho path, say) shows up here as a new `kind` and a new set
of numbers without this bench being touched.
"""
import os
import statistics
import sys
import time

import _paths  # noqa: F401  (puts the repo root on sys.path)

from netpath import ipam_scan

# "auto" is what the application runs as; the other two are the overrides
# _PING_MODE_ENV documents. auto is listed first so the default path is the
# first row read.
MODES = ("auto", "socket", "subprocess")


def pct(values, fraction: float) -> float:
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * fraction))
    return ordered[max(0, min(len(ordered) - 1, index))]


def force(mode: str):
    """Put this process in `mode` and report the kind it resolves to.

    The detected kind is cached in a module global for the life of a process
    (that is the point of it — a probe per call would cost more than the
    probe), so the cache is reset here between modes. tests/test_icmp_socket.py
    resets the same global for the same reason.
    """
    if mode == "auto":
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)
    else:
        os.environ[ipam_scan._PING_MODE_ENV] = mode
    ipam_scan._icmp_kind_cache = "unchecked"
    try:
        return _kind_text(ipam_scan._icmp_socket_kind()), None
    except OSError as exc:
        return "-", str(exc)


def _kind_text(kind) -> str:
    return kind if kind else "subprocess"


def probe_run(target: str, probes: int) -> tuple[list, str]:
    """Per-probe milliseconds for `probes` calls to ping_once, or the reason
    the mode cannot run here."""
    times = []
    for _ in range(probes):
        started = time.perf_counter()
        try:
            ipam_scan.ping_once(target, timeout_ms=1000)
        except OSError as exc:
            return times, str(exc)
        times.append((time.perf_counter() - started) * 1000.0)
    return times, ""


def run(target: str, probes: int, count: int, fleet: int, interval: int) -> None:
    print(f"\n{probes} probes to {target}, per mode")
    print(f"  {'mode':<12} {'kind':<12} {'probes':>7} {'mean ms':>9} "
          f"{'p95 ms':>9} {'total s':>9}")
    means = {}
    for mode in MODES:
        kind, error = force(mode)
        if error:
            print(f"  {mode:<12} {kind:<12} {'-':>7} {'-':>9} {'-':>9} {'-':>9}"
                  f"   {error}")
            continue
        started = time.perf_counter()
        times, failed = probe_run(target, probes)
        total = time.perf_counter() - started
        if failed or not times:
            print(f"  {mode:<12} {kind:<12} {len(times):>7} {'-':>9} {'-':>9} "
                  f"{total:>9.2f}   {failed}")
            continue
        means[mode] = statistics.fmean(times)
        print(f"  {mode:<12} {kind:<12} {probes:>7} "
              f"{statistics.fmean(times):>9.2f} {pct(times, 0.95):>9.2f} "
              f"{total:>9.2f}")

    # The shape the runbook argues about: ping_count probes per device per
    # poll, every poll, for a whole fleet. A probe cost is abstract; seconds
    # of work that have to fit inside one poll window are not.
    print(f"\n  what that is per poll cycle: {fleet:,} devices x {count} probes "
          f"every {interval} s")
    print(f"  {'mode':<12} {'per device ms':>14} {'per cycle s':>12} "
          f"{'% of the window':>16}")
    for mode, mean in means.items():
        per_device = mean * count
        per_cycle = per_device * fleet / 1000.0
        print(f"  {mode:<12} {per_device:>14.1f} {per_cycle:>12.1f} "
              f"{100.0 * per_cycle / interval:>15.0f}%")


def main(argv) -> int:
    sizes = []
    target = "127.0.0.1"
    count = 3               # nodesdb DEFAULTS["ping_count"]
    fleet = 2000            # the fleet size RUNBOOK.md:368-375 argues about
    interval = 60
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in ("--target", "--count", "--fleet", "--interval"):
            index += 1
            value = argv[index]
            if item == "--target":
                target = value
            elif item == "--count":
                count = int(value)
            elif item == "--fleet":
                fleet = int(value.replace("_", ""))
            else:
                interval = int(value)
        else:
            sizes.append(int(item.replace("_", "")))
        index += 1

    previous = os.environ.get(ipam_scan._PING_MODE_ENV)
    try:
        force("auto")
        summary = ipam_scan.ping_mode_summary()
        print(f"ping_mode_summary(): {summary}")
        print(f"_icmp_socket_kind(): {ipam_scan._icmp_socket_kind()!r}   "
              f"(None means every probe is a fork/exec of ping)")
        for probes in sizes or [100]:
            run(target, probes, count, fleet, interval)
    finally:
        os.environ.pop(ipam_scan._PING_MODE_ENV, None)
        if previous is not None:
            os.environ[ipam_scan._PING_MODE_ENV] = previous
        ipam_scan._icmp_kind_cache = "unchecked"
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

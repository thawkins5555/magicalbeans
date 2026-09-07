"""RAM and CPU used by this process, for the service console's status card.

Uses ctypes against the Win32 API instead of psutil, to avoid a new
dependency. `GetCurrentProcess()` returns a pseudo-handle that needs no
`CloseHandle`.
"""

from __future__ import annotations

import os
import sys
import time

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)

    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _FILETIME_P = ctypes.POINTER(wintypes.FILETIME)
    _kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE, _FILETIME_P, _FILETIME_P, _FILETIME_P, _FILETIME_P)

    class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    _psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(_PROCESS_MEMORY_COUNTERS), wintypes.DWORD)

    def _filetime_units(ft) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    # FILETIME units are 100ns, so ticks/CLOCK_TICKS is seconds of CPU time.
    CLOCK_TICKS = 1e7

    def _read_raw() -> dict:
        out = {}
        handle = _kernel32.GetCurrentProcess()
        creation, exit_time, kernel, user = (wintypes.FILETIME(), wintypes.FILETIME(),
                                              wintypes.FILETIME(), wintypes.FILETIME())
        if _kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user)):
            out["ticks"] = _filetime_units(kernel) + _filetime_units(user)

        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
        if _psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            out["rss_bytes"] = counters.WorkingSetSize
        out["wall"] = time.time()
        return out
else:
    CLOCK_TICKS = (float(os.sysconf("SC_CLK_TCK"))
                   if hasattr(os, "sysconf") else 100.0)

    def _read_raw() -> dict:
        out = {}
        try:
            with open("/proc/self/stat", encoding="utf-8") as handle:
                raw = handle.read()
            tail = raw[raw.rfind(")") + 2:].split()
            # After the comm field, field 1 is state; utime is field 12,
            # stime field 13 (0-based) of that remainder.
            out["ticks"] = int(tail[11]) + int(tail[12])
        except (OSError, ValueError, IndexError):
            pass
        try:
            with open("/proc/self/status", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        out["rss_bytes"] = int(line.split()[1]) * 1024
                        break
        except (OSError, ValueError, IndexError):
            pass
        if "rss_bytes" not in out:
            try:
                import resource
                out["rss_bytes"] = (
                    resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
            except Exception:
                pass
        out["wall"] = time.time()
        return out


def read_self() -> dict:
    """`rss_bytes`, `cpu_ticks_s` (CPU seconds consumed so far) and `wall`
    (when the sample was taken) for the running process. A key is missing,
    not zero, when the platform could not answer it."""
    raw = _read_raw()
    out = {"wall": raw.get("wall", time.time())}
    if "rss_bytes" in raw:
        out["rss_bytes"] = raw["rss_bytes"]
    if "ticks" in raw:
        out["cpu_ticks_s"] = raw["ticks"] / CLOCK_TICKS
    return out


def cpu_percent(before: dict, after: dict) -> float | None:
    """Percent of one core consumed between two `read_self()` samples, or
    `None` when there isn't enough to compute it (first sample, clock skew,
    or a platform that could not answer)."""
    if not before or not after:
        return None
    if "cpu_ticks_s" not in before or "cpu_ticks_s" not in after:
        return None
    seconds = after.get("wall", 0) - before.get("wall", 0)
    if seconds <= 0:
        return None
    return round(100.0 * (after["cpu_ticks_s"] - before["cpu_ticks_s"]) / seconds, 1)

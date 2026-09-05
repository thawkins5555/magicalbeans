#!/usr/bin/env python3
"""Run the whole SappiWhere demo: fleet, app, seed, incidents, UI walk.

    python3 demo/scenario.py --count 250 --out demo/out
    python3 demo/scenario.py --count 25  --out demo/out --fast --skip-ui

This script owns every process it needs and stops all of them in a `finally`,
even when a step raises:

  * an SMTP sink on 127.0.0.1:1025 (`python3 -m smtpd -n -c DebuggingServer`,
    with a stdlib fallback for Python 3.12+ where `smtpd` was removed), its
    stdout in `out/mail-<count>.log`
  * `demo/fleet.py --count N --control-port 8099` (the simulated devices)
  * `python3 -m netpath --headless ... --db out/data-<count>/netpath.db`, run
    with `PATH=demo/bin:$PATH` so it picks up the scripted ping/traceroute
    shims rather than the real ones
  * `demo/seed.py`, then the eight incident steps, then `demo/ui_walk.mjs`

Around every incident step it takes a metric snapshot — `/api/state`,
`/api/debug` (node_counters, per-worker elapsed), open alerts grouped by
rule, the mail sink's message count, the app's CPU% and RSS (from
`/proc/<pid>/stat` and `/proc/<pid>/status` on Linux, or `GetProcessTimes`
and `GetProcessMemoryInfo` via ctypes on Windows), and the fleet's own
`/state` — and writes `out/results-<count>.json` plus a readable
`out/results-<count>.md`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:
    from seed import Client, ApiError, error_text          # noqa: E402
except Exception as exc:                                    # noqa: BLE001
    print("demo/seed.py must sit beside demo/scenario.py (%s)" % exc)
    raise

APP_PORT = 8443
FLEET_CONTROL_PORT = 8099
SMTP_PORT = 1025
SSH_BASE_PORT = 2201                    # demo/fake_ssh.py's own default

# DebuggingServer prints this before every message body; counting it counts
# delivered mail. The fallback sink below prints the same line on purpose.
MAIL_SEPARATOR = "---------- MESSAGE FOLLOWS ----------"

# A stdlib SMTP sink for Python 3.12+, where `smtpd` no longer exists. Same
# output shape as smtpd.DebuggingServer so the counting is identical.
FALLBACK_SINK = r"""
import socketserver, sys, threading
class H(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: (self.wfile.write((s + "\r\n").encode()), self.wfile.flush())
        w("220 demo-sink ESMTP")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            upper = text.upper()
            if upper.startswith(("HELO", "EHLO")):
                w("250 demo-sink")
            elif upper.startswith(("MAIL", "RCPT")):
                w("250 OK")
            elif upper.startswith("DATA"):
                w("354 End with .")
                body = []
                while True:
                    part = self.rfile.readline()
                    if not part or part in (b".\r\n", b".\n"):
                        break
                    body.append(part.decode("utf-8", "replace"))
                print("---------- MESSAGE FOLLOWS ----------")
                sys.stdout.write("".join(body))
                print("------------ END MESSAGE ------------")
                sys.stdout.flush()
                w("250 Queued")
            elif upper.startswith("QUIT"):
                w("221 Bye")
                return
            elif upper.startswith("RSET"):
                w("250 OK")
            else:
                w("250 OK")
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
S(("127.0.0.1", PORT), H).serve_forever()
"""


# ------------------------------------------------------------------ helpers

def http_json(url: str, body=None, timeout: float = 20.0):
    """(status, payload). Never raises; a dead endpoint comes back as 0."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            try:
                return response.status, json.loads(raw.decode("utf-8"))
            except ValueError:
                return response.status, {"raw": raw[:400].decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw.decode("utf-8"))
        except ValueError:
            return exc.code, {"error": raw[:400].decode("utf-8", "replace")}
    except Exception as exc:                                # noqa: BLE001
        return 0, {"error": "%s: %s" % (type(exc).__name__, exc)}


if sys.platform == "win32":
    # No /proc on Windows, so the same two numbers (CPU ticks consumed and
    # resident memory) come from the Win32 API instead, via ctypes rather
    # than a new dependency (no psutil). PROCESS_QUERY_LIMITED_INFORMATION
    # is enough for both GetProcessTimes and GetProcessMemoryInfo and, unlike
    # PROCESS_QUERY_INFORMATION, is grantable even against a process owned by
    # another user/session.
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
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
        """A FILETIME as a single 100-nanosecond count."""
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    def _read_proc(pid: int) -> dict:
        out = {}
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION,
                                       False, pid)
        if not handle:
            return {}
        try:
            creation, exit_time, kernel, user = (wintypes.FILETIME(),
                                                  wintypes.FILETIME(),
                                                  wintypes.FILETIME(),
                                                  wintypes.FILETIME())
            if not _kernel32.GetProcessTimes(
                    handle, ctypes.byref(creation), ctypes.byref(exit_time),
                    ctypes.byref(kernel), ctypes.byref(user)):
                return {}
            # Kernel+user time, in 100ns units — the same field GetProcessTimes
            # always reports, so this is the Windows equivalent of the Linux
            # path's utime+stime jiffies. CLOCK_TICKS below is set to 1e7 (the
            # number of 100ns units per second) on this platform for exactly
            # this reason, so cpu_percent()'s ticks/CLOCK_TICKS division comes
            # out in seconds unchanged, without cpu_percent knowing which OS
            # produced the numbers.
            out["ticks"] = _filetime_units(kernel) + _filetime_units(user)

            counters = _PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
            if _psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                           counters.cb):
                # WorkingSetSize is bytes; VmRSS on Linux is kB, so divide
                # down to match the unit the rest of this file expects.
                out["rss_kb"] = counters.WorkingSetSize // 1024
        except OSError:
            return {}
        finally:
            _kernel32.CloseHandle(handle)
        out["wall"] = time.time()
        return out

    # FILETIME units are 100ns, so ticks/CLOCK_TICKS is seconds of CPU time.
    CLOCK_TICKS = 1e7
else:
    def _read_proc(pid: int) -> dict:
        """utime+stime ticks and VmRSS for a live pid; {} once it is gone."""
        out = {}
        try:
            with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
                raw = handle.read()
            tail = raw[raw.rfind(")") + 2:].split()
            # After the comm field, field 1 is state; utime is field 12,
            # stime field 13 (0-based) of that remainder.
            out["ticks"] = int(tail[11]) + int(tail[12])
            out["threads"] = int(tail[17])
        except (OSError, ValueError, IndexError):
            return {}
        try:
            with open("/proc/%d/status" % pid, encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        out["rss_kb"] = int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            pass
        out["wall"] = time.time()
        return out

    CLOCK_TICKS = (float(os.sysconf("SC_CLK_TCK"))
                   if hasattr(os, "sysconf") else 100.0)


def read_proc(pid: int) -> dict:
    """CPU ticks (see CLOCK_TICKS) and RSS in kB for a live pid; {} once it
    is gone. `/proc` on Linux, the Win32 API via ctypes on Windows."""
    return _read_proc(pid)


def cpu_percent(before: dict, after: dict) -> float | None:
    if not before or not after:
        return None
    seconds = after.get("wall", 0) - before.get("wall", 0)
    if seconds <= 0:
        return None
    ticks = after.get("ticks", 0) - before.get("ticks", 0)
    return round(100.0 * (ticks / CLOCK_TICKS) / seconds, 1)


def count_mail(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if MAIL_SEPARATOR in line)
    except OSError:
        return 0


def wait_for_line(path: str, needle: str, timeout: float, process=None) -> bool:
    """Poll a log file until `needle` shows up (or the process dies)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            return False
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                if needle in handle.read():
                    return True
        except OSError:
            pass
        time.sleep(0.25)
    return False


def terminate(process, name: str, log) -> None:
    if process is None or process.poll() is not None:
        return
    log("[stop] %s (pid %d)" % (name, process.pid))
    try:
        # On Windows, Popen.terminate() and .kill() are the same call
        # (TerminateProcess) — there is no SIGTERM to ask nicely with first,
        # so the "try soft, then hard" shape below degrades to trying the
        # same thing twice there, which is harmless.
        process.terminate()
        process.wait(timeout=10)
    except Exception:                                       # noqa: BLE001
        try:
            process.kill()
            process.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            pass


# ------------------------------------------------------------------ runner

def _suffix(args) -> str:
    """What to append to this run's database and results names, so runs of
    the same size in different configurations do not overwrite each other."""
    parts = []
    if getattr(args, "defaults", False):
        parts.append("-defaults")
    if getattr(args, "topology", False):
        parts.append("-topology")
    return "".join(parts)


class Scenario:
    def __init__(self, args):
        self.args = args
        self.out = os.path.abspath(args.out)
        os.makedirs(self.out, exist_ok=True)
        self.count = args.count
        self.scale = 0.25 if args.fast else 1.0
        # A defaults run keeps its own databases: it is a different
        # configuration of the same fleet, and mixing the two would make
        # the retention and alert figures unreadable.
        self.data_dir = os.path.join(
            self.out, "data-%d%s" % (self.count, _suffix(args)))
        self.mail_log = os.path.join(self.out, "mail-%d.log" % self.count)
        self.app_log = os.path.join(self.out, "app-%d.log" % self.count)
        self.fleet_log = os.path.join(self.out, "fleet-%d.log" % self.count)
        self.ssh_log = os.path.join(self.out, "fake-ssh-%d.log" % self.count)
        self.run_log = os.path.join(self.out, "scenario-%d.log" % self.count)
        self.base = "http://127.0.0.1:%d" % args.port
        self.fleet_base = "http://127.0.0.1:%d" % args.control_port
        self.ssh_base_port = args.ssh_base_port
        self.ssh_started = False
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self.handles: list = []
        self.client: Client | None = None
        self.app_pid = None
        self.steps: list[dict] = []
        self.notes: list[str] = []
        self._plan: list[dict] | None = None
        self._log_handle = open(self.run_log, "a", encoding="utf-8")

    # -- logging ----------------------------------------------------------

    def log(self, message: str) -> None:
        line = "%s %s" % (time.strftime("%H:%M:%S"), message)
        print(line, flush=True)
        self._log_handle.write(line + "\n")
        self._log_handle.flush()

    def wait(self, seconds: float, why: str) -> float:
        seconds = max(1.0, seconds * self.scale)
        self.log("       waiting %.0fs (%s)" % (seconds, why))
        time.sleep(seconds)
        return seconds

    def sampled_wait(self, seconds: float, why: str) -> tuple[float, dict]:
        """Wait, sampling /api/debug's in-flight pollers as we go.

        A single before/after read of `node_workers` almost always catches an
        idle moment and reports zero, so poll latency has to be sampled
        across the step rather than measured at its edges.
        """
        seconds = max(1.0, seconds * self.scale)
        self.log("       waiting %.0fs (%s)" % (seconds, why))
        deadline = time.time() + seconds
        elapsed_values: list[float] = []
        busy: list[int] = []
        interval = max(1.0, seconds / 40.0)
        while time.time() < deadline:
            time.sleep(min(interval, max(0.2, deadline - time.time())))
            try:
                debug = self.client.get("/api/debug", since=0)
            except ApiError:
                continue
            workers = debug.get("node_workers") or []
            busy.append(sum(1 for w in workers if w.get("kind") == "polling"))
            elapsed_values.extend(w["elapsed"] for w in workers
                                  if w.get("kind") == "polling" and w.get("elapsed"))
        sampled = {
            "samples": len(busy),
            "avg_busy_pollers": round(sum(busy) / len(busy), 2) if busy else 0,
            "max_busy_pollers": max(busy) if busy else 0,
            "avg_poll_elapsed_s": round(sum(elapsed_values) / len(elapsed_values), 3)
                                  if elapsed_values else 0,
            "max_poll_elapsed_s": round(max(elapsed_values), 3) if elapsed_values else 0,
        }
        return seconds, sampled

    # -- processes --------------------------------------------------------

    def spawn(self, name: str, argv: list[str], log_path: str, env=None,
              cwd=None) -> subprocess.Popen:
        handle = open(log_path, "w", encoding="utf-8")
        self.handles.append(handle)
        self.log("[start] %s: %s" % (name, " ".join(argv)))
        # start_new_session detaches each child from our process group/
        # session (POSIX setsid) so a Ctrl+C delivered to the terminal's
        # foreground group reaches this script but not the children, letting
        # the finally block above stop them in order instead of everything
        # dying at once. CPython silently ignores this argument on Windows
        # (subprocess.Popen), where there is no equivalent notion of a
        # session leader; terminate()/kill() below still work fine there
        # since they act on the child's own handle rather than a group.
        process = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                                   env=env, cwd=cwd or REPO,
                                   start_new_session=True)
        self.procs.append((name, process))
        return process

    def start_smtp_sink(self) -> None:
        try:
            import smtpd                                     # noqa: F401
            argv = [sys.executable, "-u", "-m", "smtpd", "-n",
                    "-c", "DebuggingServer", "127.0.0.1:%d" % SMTP_PORT]
        except Exception:                                    # noqa: BLE001
            self.notes.append("stdlib smtpd is gone on this Python; using the "
                              "built-in fallback SMTP sink")
            argv = [sys.executable, "-u", "-c",
                    "PORT=%d\n%s" % (SMTP_PORT, FALLBACK_SINK)]
        self.spawn("smtp-sink", argv, self.mail_log)
        time.sleep(1.0)

    def start_fleet(self) -> bool:
        fleet = os.path.join(HERE, "fleet.py")
        if not os.path.exists(fleet):
            self.notes.append("demo/fleet.py is missing — the fleet was not "
                              "started and every device-state step is a no-op")
            self.log("[warn] demo/fleet.py not found; continuing without it")
            return False
        process = self.spawn("fleet", [sys.executable, "-u", fleet,
                                       "--count", str(self.count),
                                       "--control-port", str(self.args.control_port)],
                             self.fleet_log)
        if not wait_for_line(self.fleet_log, "listening", 120, process):
            self.notes.append("demo/fleet.py never printed 'listening'")
            self.log("[warn] fleet did not report listening; see %s"
                     % os.path.basename(self.fleet_log))
            return False
        self.log("[ok] fleet listening on control port %d" % self.args.control_port)
        return True

    def start_fake_ssh(self) -> bool:
        """The SSH personas ConfigRX's platform sweep (configrx_platforms())
        and seed.py's own live ASA walk connect to. If a base port is
        already bound (another instance is running there), fake_ssh.py still
        prints 'listening' — each persona's own bind failure only reaches its
        own thread's stderr — so this only reports "did not start at all";
        a partial bind failure surfaces later as a connect error on that one
        persona's port instead.
        """
        script = os.path.join(HERE, "fake_ssh.py")
        if not os.path.exists(script):
            self.notes.append("demo/fake_ssh.py is missing — the ConfigRX "
                              "platform sweep was skipped")
            self.log("[warn] demo/fake_ssh.py not found; continuing without it")
            return False
        process = self.spawn("fake-ssh", [sys.executable, "-u", script,
                                          "--base-port", str(self.ssh_base_port)],
                             self.ssh_log)
        if not wait_for_line(self.ssh_log, "listening", 30, process):
            self.notes.append("demo/fake_ssh.py never printed 'listening' on "
                              "base port %d" % self.ssh_base_port)
            self.log("[warn] fake SSH did not report listening; see %s"
                     % os.path.basename(self.ssh_log))
            return False
        self.log("[ok] fake SSH personas listening from port %d"
                 % self.ssh_base_port)
        return True

    def start_app(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        env = dict(os.environ)
        env["PATH"] = os.path.join(HERE, "bin") + os.pathsep + env.get("PATH", "")
        # The scripted ping shim on that PATH is the whole point: it answers
        # from the fleet's device state. Socket ICMP would bypass PATH and
        # reach the loopback addresses directly, where the kernel always
        # answers, so a "down" device would look up. Force the subprocess
        # path so the shim keeps deciding.
        env["NETPATH_PING_MODE"] = "subprocess"
        # ...and the shim has to be told where the fleet is. It defaults to
        # 8099 (demo/bin/ping's fleet_alive), which is this file's own
        # default control port, so at default settings everything worked and
        # nothing revealed the omission. Pass --control-port anything else --
        # which any run sharing a machine with another fleet must do -- and
        # the shim asked port 8099, found nothing, and fell through to
        # "assume alive". A device the fleet had been told to take down then
        # answered ping perfectly while its SNMP stayed dark, so the outage
        # steps raised `snmp_failing_ping_ok` instead of `device_down` and
        # the run measured the wrong rule without ever failing.
        env["FLEET_CONTROL_PORT"] = str(self.args.control_port)
        env.setdefault("PYTHONUNBUFFERED", "1")
        process = self.spawn(
            "app", [sys.executable, "-u", "-m", "netpath", "--headless",
                    "--host", "127.0.0.1", "--port", str(self.args.port),
                    "--db", os.path.join(self.data_dir, "netpath.db")],
            self.app_log, env=env)
        if not wait_for_line(self.app_log, "serving", 180, process):
            raise RuntimeError("the app never printed 'serving'; see %s"
                               % self.app_log)
        self.app_pid = process.pid
        self.log("[ok] app serving on %s (pid %d)" % (self.base, self.app_pid))

    # -- seeding ----------------------------------------------------------

    def run_seed(self) -> dict:
        seed = os.path.join(HERE, "seed.py")
        argv = [sys.executable, "-u", seed, "--base", self.base,
                "--count", str(self.count), "--out", self.out,
                "--workers", str(self.args.workers),
                "--ssh-base-port", str(self.ssh_base_port)]
        if getattr(self.args, "topology", False):
            argv.append("--topology")
        if getattr(self.args, "defaults", False):
            # A run at shipped settings: seed.py then makes none of the
            # campaign's overrides, so the numbers can be read beside a
            # customer's own install rather than only against each other.
            argv.append("--defaults")
        self.log("[seed] %s" % " ".join(argv))
        seed_log = os.path.join(self.out, "seed-stdout-%d.log" % self.count)
        with open(seed_log, "w", encoding="utf-8") as handle:
            result = subprocess.run(argv, cwd=REPO, stdout=handle,
                                    stderr=subprocess.STDOUT, check=False)
        summary_path = os.path.join(self.out, "seed_summary.json")
        summary = {}
        try:
            with open(summary_path, encoding="utf-8") as handle:
                summary = json.load(handle)
        except (OSError, ValueError):
            pass
        self.log("[seed] exit=%d, %s devices added in %ss"
                 % (result.returncode,
                    summary.get("devices", {}).get("added", "?"),
                    summary.get("devices", {}).get("seconds", "?")))
        return {"returncode": result.returncode, "summary": summary,
                "stdout_log": os.path.basename(seed_log)}

    def connect(self) -> None:
        creds_path = os.path.join(self.out, "creds.txt")
        from seed import read_creds
        creds = read_creds(creds_path)
        self.client = Client(self.base)
        self.client.login("admin", creds.get("admin_password", "admin"))
        self.log("[ok] API client signed in as admin")

    def wait_for_first_cycle(self) -> dict:
        """Poll until >=95% of the fleet is up, or five minutes go by."""
        budget = 300 * self.scale
        deadline = time.time() + budget
        best = 0
        started = time.time()
        while time.time() < deadline:
            try:
                devices = self.client.get("/api/nodes/devices")["devices"]
            except ApiError as exc:
                self.log("[poll] /api/nodes/devices failed: %s" % exc)
                time.sleep(5)
                continue
            up = sum(1 for d in devices if d.get("status") == "up")
            polled = sum(1 for d in devices if d.get("last_poll_ts"))
            best = max(best, up)
            fraction = up / max(len(devices), 1)
            self.log("[poll] %d/%d up (%.0f%%), %d polled at least once"
                     % (up, len(devices), fraction * 100, polled))
            # 95% up is the target, but the fleet deliberately contains
            # devices that can never come up (personas.SPECIALS: wrong
            # community, auth failure, scheduled-dark), so every device
            # having been polled once also counts as the first full cycle.
            full_cycle = devices and polled == len(devices)
            if fraction >= 0.95 or full_cycle:
                elapsed = round(time.time() - started, 1)
                self.log("[ok] first full poll cycle after %.1fs (%s)"
                         % (elapsed, "95%% up" if fraction >= 0.95
                            else "every device polled once"))
                return {"reached_95pct": fraction >= 0.95,
                        "full_cycle": bool(full_cycle), "seconds": elapsed,
                        "up": up, "polled": polled, "total": len(devices)}
            time.sleep(10)
        elapsed = round(time.time() - started, 1)
        self.notes.append("the fleet never reached 95%% up (best %d) in %.0fs"
                          % (best, budget))
        self.log("[warn] gave up waiting for 95%% up (best %d)" % best)
        return {"reached_95pct": False, "seconds": elapsed, "up": best}

    # -- ConfigRX platform sweep -------------------------------------------

    # demo/fake_ssh.py binds only 127.0.0.1, and Nodes needs a unique IP per
    # device, so the single device it exists for (personas.py's
    # "configrx-ssh-01", pinned to that address) is re-pointed by ssh_port
    # and vendor_override across these personas rather than one device per
    # persona. (label, --base-port offset, configrx_vendors.py key, whether
    # the vendor needs the enable secret.) demo/configrx_probe.py exercises
    # the full 12-persona matrix directly against the capture functions,
    # without this one-device-at-a-time constraint.
    CONFIGRX_SWEEP = (
        ("cisco-nxos", 7, "cisco-nxos", False,
         "a large capture — the baseline the next persona's shrinks against"),
        ("cisco-asa", 10, "cisco-asa", True,
         "enable-mode escalation: login lands at user EXEC, needs the "
         "stored enable secret to reach privileged EXEC before show "
         "running-config is even accepted"),
        ("mikrotik", 4, "mikrotik", False,
         "a small but complete capture right after a large one — under a "
         "fifth of it, so it should land as 'suspect' rather than 'changed'"),
    )

    def _configrx_wait(self, device_id: int, timeout: float = 20.0) -> dict:
        """Poll GET /api/configrx/devices/<id> until the backup in flight
        finishes, or `timeout` runs out."""
        deadline = time.time() + timeout
        device: dict = {}
        while time.time() < deadline:
            try:
                device = self.client.get(
                    "/api/configrx/devices/%d" % device_id)["device"]
            except ApiError:
                time.sleep(1)
                continue
            if not device.get("backing_up") and not device.get("backup_queued"):
                return device
            time.sleep(1)
        return device

    def configrx_platforms(self) -> dict:
        """Walks ConfigRX's SSH platforms end to end against demo/fake_ssh.py:
        a real backup on a platform that needs enable mode (cisco-asa), and a
        genuine shrink landing as 'suspect' rather than 'changed'."""
        self.log("")
        self.log("=== ConfigRX platform sweep ===")
        result: dict = {"device": "configrx-ssh-01", "runs": []}
        if not self.ssh_started:
            self.notes.append("ConfigRX platform sweep skipped: "
                              "demo/fake_ssh.py did not start")
            return result
        try:
            devices = self.client.get("/api/nodes/devices")["devices"]
        except ApiError as exc:
            self.notes.append("ConfigRX platform sweep skipped: could not "
                              "list devices (%s)" % exc)
            return result
        device_id = next((d["id"] for d in devices
                          if d.get("name") == "configrx-ssh-01"), None)
        if device_id is None:
            self.notes.append(
                "ConfigRX platform sweep skipped: no 'configrx-ssh-01' "
                "device (personas.fleet_plan needs --count >= 14; this run "
                "used --count %d)" % self.count)
            return result

        for label, offset, vendor, needs_enable, why in self.CONFIGRX_SWEEP:
            port = self.ssh_base_port + offset
            self.client.post("/api/configrx/devices/%d/config" % device_id, {
                "backup_enabled": True, "vendor_override": vendor,
                "ssh_port": port, "ssh_username": "demo"})
            cred = {"ssh_username": "demo", "ssh_password": "demo"}
            if needs_enable:
                cred["enable_secret"] = "demo"
            self.client.post(
                "/api/configrx/devices/%d/credential" % device_id, cred)
            status, payload, _ = self.client.raw(
                "POST", "/api/configrx/devices/%d/backup" % device_id, {})
            run = {"persona": label, "vendor": vendor, "port": port,
                  "why": why, "queue_status": status}
            if status >= 400:
                run["queue_error"] = error_text(payload)
                self.log("       configrx %-12s -> queue failed: %s"
                         % (label, run["queue_error"]))
            else:
                device = self._configrx_wait(device_id)
                run["last_backup_status"] = device.get("last_backup_status")
                run["last_backup_error"] = device.get("last_backup_error")
                self.log("       configrx %-12s (127.0.0.1:%d) -> %s%s"
                         % (label, port, device.get("last_backup_status"),
                            (": " + device["last_backup_error"])
                            if device.get("last_backup_error") else ""))
            result["runs"].append(run)
        return result

    # -- fleet control ----------------------------------------------------

    def fleet_event(self, action: str, ips=None, select=None, arg=None) -> dict:
        body = {"action": action}
        if ips:
            body["ips" if len(ips) != 1 else "ip"] = ips if len(ips) != 1 else ips[0]
        if select:
            body["select"] = select
        if arg is not None:
            body["arg"] = arg
        status, payload = http_json(self.fleet_base + "/event", body)
        self.log("       fleet %s %s -> HTTP %s%s"
                 % (action, select or (ips[:3] if ips else ""), status,
                    "" if status == 200 else " " + error_text(payload)))
        if status != 200:
            note = ("the fleet control API at %s did not accept events "
                    "(first failure: %s) — device-state steps did nothing"
                    % (self.fleet_base, error_text(payload)))
            if note not in self.notes:
                self.notes.append(note)
        return {"action": action, "status": status, "response": payload,
                "body": body}

    def fleet_state(self) -> dict:
        status, payload = http_json(self.fleet_base + "/state")
        return payload if status == 200 else {"error": error_text(payload)}

    def plan(self) -> list[dict]:
        """The authoritative device list. demo/personas.py when it is there,
        the fleet's own /state next (its `devices` is a dict keyed by IP),
        and a bare loopback range as the last resort."""
        if self._plan is not None:
            return self._plan
        try:
            from personas import fleet_plan            # type: ignore
            self._plan = list(fleet_plan(self.count))
            return self._plan
        except Exception:                              # noqa: BLE001
            pass
        state = self.fleet_state()
        devices = state.get("devices")
        rows = []
        if isinstance(devices, dict):
            rows = [dict(info, ip=ip) for ip, info in devices.items()
                    if isinstance(info, dict)]
        elif isinstance(devices, list):
            rows = [d for d in devices if isinstance(d, dict) and d.get("ip")]
        if not rows:
            from seed import loopback_ip
            rows = [{"index": i, "ip": loopback_ip(i), "persona": "cisco_access",
                     "site": "Site-A"} for i in range(self.count)]
        self._plan = rows
        return self._plan

    def fleet_ips(self, limit: int, skip: int = 0, persona: str = "",
                  site: str = "") -> list[str]:
        rows = self.plan()
        if persona:
            rows = [r for r in rows if r.get("persona") == persona]
        if site:
            rows = [r for r in rows if r.get("site") == site]
        return [r["ip"] for r in rows[skip:skip + limit] if r.get("ip")]

    # -- generators -------------------------------------------------------

    def generator(self, kind: str, sources, rate, duration, extra=None):
        script = os.path.join(HERE, "generators.py")
        if not os.path.exists(script):
            self.notes.append("demo/generators.py is missing — the %s burst "
                              "was skipped" % kind)
            self.log("[warn] demo/generators.py not found; skipping %s" % kind)
            return None
        argv = [sys.executable, "-u", script, kind,
                "--sources", ",".join(sources),
                "--rate", str(rate), "--duration", str(duration)]
        argv.extend(extra or [])
        log_path = os.path.join(self.out, "gen-%s-%d.log" % (kind, self.count))
        return self.spawn("gen-%s" % kind, argv, log_path)

    # -- measurement ------------------------------------------------------

    def snapshot(self) -> dict:
        snap = {"ts": time.time()}
        try:
            state = self.client.get("/api/state")
        except ApiError as exc:
            state = {"error": str(exc)}
        snap["state"] = {
            "device_counts": state.get("nodes", {}).get("device_counts"),
            "device_count": state.get("nodes", {}).get("device_count"),
            "nodes_counters": state.get("nodes", {}).get("counters"),
            "alerts_open": state.get("alerts", {}).get("open_count"),
            "alerts_counters": state.get("alerts", {}).get("counters"),
            "syslog_counters": state.get("syslog", {}).get("counters"),
            "snmp_counters": state.get("snmp", {}).get("counters"),
            "netflow_counters": state.get("collector", {}).get("counters"),
        }
        try:
            debug = self.client.get("/api/debug", since=0)
        except ApiError as exc:
            debug = {"error": str(exc)}
        node_workers = debug.get("node_workers") or []
        elapsed = [w.get("elapsed", 0) for w in node_workers if w.get("elapsed")]
        snap["debug"] = {
            "node_counters": debug.get("node_counters"),
            "node_workers": len(node_workers),
            "node_worker_max_elapsed": round(max(elapsed), 3) if elapsed else 0,
            "node_worker_avg_elapsed":
                round(sum(elapsed) / len(elapsed), 3) if elapsed else 0,
            "summary": debug.get("summary"),
        }
        snap["alerts"] = self.alert_rows()
        snap["mail"] = count_mail(self.mail_log)
        snap["fleet"] = self.fleet_summary()
        snap["proc"] = read_proc(self.app_pid) if self.app_pid else {}
        return snap

    def alert_rows(self) -> dict:
        """Every alert the server will hand back, indexed for windowing.

        get_alerts caps `limit` at 2000 (netpath/web/api.py:2973-2994), so a
        very large outage can truncate; that is recorded rather than hidden.
        """
        try:
            rows = self.client.get("/api/alerts", limit=2000)["alerts"]
        except ApiError as exc:
            return {"error": str(exc), "rows": []}
        return {
            "rows": [{"rule": r.get("rule_name") or r.get("rule_id"),
                      "state": r.get("state"),
                      "opened_ts": r.get("opened_ts"),
                      "resolved_ts": r.get("resolved_ts")} for r in rows],
            "truncated": len(rows) >= 2000,
            "open": sum(1 for r in rows if r.get("state") == "open"),
        }

    def fleet_summary(self) -> dict:
        state = self.fleet_state()
        if "error" in state:
            return state
        # Keep whatever scalar totals the fleet reports; its exact shape is
        # another builder's, so nothing here assumes a specific key set.
        return {k: v for k, v in state.items()
                if isinstance(v, (int, float, str, bool))}

    @staticmethod
    def window_counts(before: dict, after: dict) -> dict:
        """Alerts opened and cleared between the two snapshots, by rule."""
        t0 = before.get("ts", 0)
        t1 = after.get("ts", time.time())
        opened: dict[str, int] = {}
        cleared: dict[str, int] = {}
        for row in (after.get("alerts") or {}).get("rows", []):
            rule = str(row.get("rule"))
            ts = row.get("opened_ts")
            if ts and t0 <= ts <= t1:
                opened[rule] = opened.get(rule, 0) + 1
            ts = row.get("resolved_ts")
            if ts and t0 <= ts <= t1:
                cleared[rule] = cleared.get(rule, 0) + 1
        return {"opened_by_rule": opened, "cleared_by_rule": cleared,
                "opened_total": sum(opened.values()),
                "cleared_total": sum(cleared.values())}

    def run_step(self, number: int, name: str, action, seconds: float) -> dict:
        self.log("")
        self.log("=== step %d: %s ===" % (number, name))
        before = self.snapshot()
        detail = {}
        try:
            detail = action() or {}
        except Exception as exc:                            # noqa: BLE001
            detail = {"error": "%s: %s" % (type(exc).__name__, exc)}
            self.log("[warn] step %d action failed: %s" % (number, detail["error"]))
        waited, sampled = self.sampled_wait(seconds, name)
        after = self.snapshot()

        counters_before = (before.get("debug") or {}).get("node_counters") or {}
        counters_after = (after.get("debug") or {}).get("node_counters") or {}
        polls = {key: (counters_after.get(key, 0) - counters_before.get(key, 0))
                 for key in set(counters_before) | set(counters_after)
                 if isinstance(counters_after.get(key, 0), (int, float))}

        result = {
            "step": number, "name": name, "detail": detail,
            "duration_s": round(after["ts"] - before["ts"], 1),
            "waited_s": round(waited, 1),
            **self.window_counts(before, after),
            "emails": after.get("mail", 0) - before.get("mail", 0),
            "poll_deltas": polls,
            "sampled": sampled,
            "node_worker_max_elapsed_s": sampled.get("max_poll_elapsed_s"),
            "node_worker_avg_elapsed_s": sampled.get("avg_poll_elapsed_s"),
            "cpu_percent": cpu_percent(before.get("proc"), after.get("proc")),
            "rss_mb": round((after.get("proc") or {}).get("rss_kb", 0) / 1024.0, 1),
            "open_alerts_after": (after.get("alerts") or {}).get("open"),
            "device_counts_after": (after.get("state") or {}).get("device_counts"),
            "alerts_truncated": (after.get("alerts") or {}).get("truncated"),
        }
        self.log("--- step %d done: +%d alerts, -%d cleared, %d emails, "
                 "cpu %s%%, rss %sMB"
                 % (number, result["opened_total"], result["cleared_total"],
                    result["emails"], result["cpu_percent"], result["rss_mb"]))
        self.steps.append(result)
        return result

    # -- the eight incidents ---------------------------------------------

    def incidents(self) -> None:
        # Index 0 is the core switch; indices 2..12 are the scripted special
        # cases (personas.SPECIALS), so the bulk sets start past them.
        core = self.fleet_ips(1)
        access = self.fleet_ips(100, skip=11, persona="cisco_access")
        reboot_set = self.fleet_ips(20, skip=11, persona="cisco_access")
        auth_set = self.fleet_ips(5, skip=11, persona="cisco_access")
        sources = self.fleet_ips(20)
        self.log("[plan] core=%s, %d flap targets, %d reboot, %d auth-fail"
                 % (core, len(access), len(reboot_set), len(auth_set)))

        self.run_step(1, "baseline", lambda: {"note": "steady state"}, 120)

        def outage():
            events = [self.fleet_event("down", ips=core),
                      self.fleet_event("down", select={"persona": "cisco_access",
                                                       "site": "Site-A",
                                                       "limit": 500})]
            return {"events": events}
        # down_after_failures (3) x the 60 s profile interval means the
        # third failed poll lands around 180 s; give the engine a tick or two
        # past that so the device_down alerts and their emails are inside
        # the window that counts them.
        self.run_step(2, "core outage + Site-A access layer down", outage, 240)

        def outage_over():
            events = [
                self.fleet_event("up", ips=core),
                self.fleet_event("up", select={"persona": "cisco_access",
                                               "site": "Site-A", "limit": 500}),
            ]
            return {"events": events}
        self.run_step(3, "outage recovery (core + Site-A back)", outage_over, 150)

        def flaps():
            # fleet.py's apply() takes the interface index itself as `arg`
            # (demo/fleet.py:570), not a dict.
            return {"events": [self.fleet_event("flap_start", ips=access, arg=7)]}
        self.run_step(4, "interface flap storm (if 7 on 100 switches)", flaps, 120)

        def reboots():
            return {"events": [self.fleet_event("reboot", ips=reboot_set)]}
        self.run_step(5, "reboot 20 devices", reboots, 120)

        def auth_fail():
            return {"events": [self.fleet_event("auth_fail_on", ips=auth_set)]}
        self.run_step(6, "SNMP auth failure on 5 devices", auth_fail, 90)

        def bursts():
            duration = max(5, int(60 * self.scale))
            started = [
                self.generator("traps", sources, 200, duration, ["--mix", "storm"]),
                self.generator("syslog", sources, 400, duration,
                               ["--framing", "newline"]),
                # Part of the burst over TCP with octet counting, so the
                # framing path gets exercised too (syslog accept_tcp was
                # switched on by seed.py step 8).
                self.generator("syslog", sources, 200, duration,
                               ["--tcp", "--framing", "octet"]),
            ]
            return {"generators": sum(1 for p in started if p is not None)}
        self.run_step(7, "trap + syslog burst (storm mix, TCP octet framing)",
                      bursts, 75)

        def netflow():
            duration = max(5, int(60 * self.scale))
            started = self.generator("netflow", sources, 200, duration,
                                     ["--version", "mixed"])
            return {"generators": 1 if started else 0}
        self.run_step(8, "netflow burst (mixed v5/v9, 200 flows/s)", netflow, 75)

        def recovery():
            events = [
                self.fleet_event("flap_stop", ips=access),
                self.fleet_event("auth_fail_off", ips=auth_set),
            ]
            return {"events": events}
        self.run_step(9, "recovery (flaps stop, auth restored)", recovery, 150)

    # -- UI walk ----------------------------------------------------------

    def run_ui(self) -> dict:
        walk = os.path.join(HERE, "ui_walk.mjs")
        node = shutil.which("node")
        if not node:
            self.notes.append("node is not on PATH — the UI walk was skipped")
            return {"skipped": "node not found"}
        if not os.path.exists(walk):
            return {"skipped": "demo/ui_walk.mjs not found"}
        ui_out = os.path.join(self.out, "ui")
        argv = [node, walk, "--base", self.base,
                "--creds", os.path.join(self.out, "creds.txt"),
                "--out", ui_out, "--tag", str(self.count)]
        self.log("[ui] %s" % " ".join(argv))
        log_path = os.path.join(self.out, "ui-walk-%d.log" % self.count)
        with open(log_path, "w", encoding="utf-8") as handle:
            result = subprocess.run(argv, cwd=REPO, stdout=handle,
                                    stderr=subprocess.STDOUT, check=False)
        metrics = {}
        try:
            with open(os.path.join(ui_out, "metrics-%d.json" % self.count),
                      encoding="utf-8") as handle:
                metrics = json.load(handle)
        except (OSError, ValueError):
            pass
        self.log("[ui] exit=%d" % result.returncode)
        return {"returncode": result.returncode, "metrics": metrics,
                "log": os.path.basename(log_path)}

    # -- reporting --------------------------------------------------------

    def write_results(self, extra: dict) -> None:
        payload = {"count": self.count, "fast": self.args.fast,
                   "base": self.base, "generated": time.time(),
                   "notes": self.notes, "steps": self.steps, **extra}
        json_path = os.path.join(self.out, "results-%d%s.json" % (self.count, _suffix(self.args)))
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=1, default=str)

        rows = []
        for step in self.steps:
            opened = ", ".join("%s=%d" % (k, v) for k, v in
                               sorted(step["opened_by_rule"].items())) or "—"
            cleared = ", ".join("%s=%d" % (k, v) for k, v in
                                sorted(step["cleared_by_rule"].items())) or "—"
            polls = step.get("poll_deltas") or {}
            rows.append(
                "| %d %s | %.0fs | %s | %s | %d | %s / %s / %s / %s | %s | %s | %s%% | %s |"
                % (step["step"], step["name"], step["duration_s"],
                   opened, cleared, step["emails"],
                   polls.get("polls", "—"), polls.get("ok", "—"),
                   polls.get("timeout", "—"), polls.get("auth_fail", "—"),
                   polls.get("overruns", "—"),
                   step.get("node_worker_avg_elapsed_s", "—"),
                   step.get("cpu_percent", "—"), step.get("rss_mb", "—")))

        lines = [
            "# SappiWhere demo run — %d devices" % self.count,
            "",
            "Generated %s%s from `demo/scenario.py`."
            % (time.strftime("%Y-%m-%d %H:%M:%S"),
               " (--fast, waits scaled 4x down)" if self.args.fast else ""),
            "",
            "| Step | Duration | Alerts opened (by rule) | Alerts cleared (by rule) "
            "| Emails | Polls / ok / timeout / auth_fail | Overruns "
            "| Avg poll latency (s) | CPU% | RSS MB |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        lines.extend(rows)
        lines.extend([
            "",
            "Poll counts are deltas of `/api/debug`'s `node_counters` across the "
            "step. Poll latency is sampled from `/api/debug`'s in-flight "
            "`node_workers` about once a second, so a small fleet whose polls "
            "finish between samples reads 0 — the counters above are the "
            "reliable signal at that size. CPU% is the app process's own "
            "utime+stime over the step; RSS is its VmRSS at the end of it.",
            "",
        ])
        seed = extra.get("seed", {}).get("summary", {})
        devices = seed.get("devices", {})
        if devices:
            lines.extend([
                "## Seeding",
                "",
                "- %s devices added in %ss (%s devices/s) via one "
                "`POST /api/nodes/devices` each — there is no bulk-add endpoint."
                % (devices.get("added"), devices.get("seconds"),
                   devices.get("devices_per_second")),
                "",
            ])
        refusals = seed.get("refusals") or []
        if refusals:
            lines.append("## Credential-store refusals (recorded as evidence)")
            lines.append("")
            for refusal in refusals:
                lines.append("- `%s` -> HTTP %s: %s"
                             % (refusal.get("endpoint"), refusal.get("status"),
                                refusal.get("error")))
            lines.append("")
        sweep = extra.get("configrx_platforms") or {}
        runs = sweep.get("runs") or []
        if runs:
            lines.extend([
                "## ConfigRX platform sweep",
                "",
                "One live device (`%s`) re-pointed across demo/fake_ssh.py's "
                "personas — the fake server binds only 127.0.0.1, and Nodes "
                "requires a unique IP per device, so one device stands in "
                "for all of them in turn. `demo/configrx_probe.py` covers "
                "every persona directly against the capture functions, "
                "without that constraint." % sweep.get("device"),
                "",
                "| Persona (127.0.0.1:port) | Vendor | What it proves | Result |",
                "| --- | --- | --- | --- |",
            ])
            for run in runs:
                outcome = run.get("last_backup_status") or run.get(
                    "queue_error") or "?"
                if run.get("last_backup_error"):
                    outcome += " — " + run["last_backup_error"]
                lines.append(
                    "| %s (%s) | %s | %s | %s |"
                    % (run["persona"], run["port"], run["vendor"],
                       run.get("why", ""), outcome))
            lines.append("")
        ui_metrics = (extra.get("ui") or {}).get("metrics") or {}
        if ui_metrics:
            lines.extend([
                "## UI walk",
                "",
                "- Nodes table filled %s/%s rows in %s ms after "
                "`App.refreshNow('nodes')`."
                % (ui_metrics.get("nodes_table_rows"),
                   ui_metrics.get("device_count"),
                   ui_metrics.get("nodes_fill_ms")),
                "- `/api/nodes/devices` payload: %s bytes in %s ms."
                % (ui_metrics.get("devices_payload_bytes"),
                   ui_metrics.get("devices_payload_ms")),
                "- Long tasks observed: %s (longest %s ms)."
                % (ui_metrics.get("longtask_entries_observed"),
                   ui_metrics.get("longtask_longest_ms")),
                "",
            ])
        if self.notes:
            lines.append("## Notes")
            lines.append("")
            lines.extend("- %s" % note for note in self.notes)
            lines.append("")

        md_path = os.path.join(self.out, "results-%d%s.md" % (self.count, _suffix(self.args)))
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
        self.log("[ok] wrote %s and %s"
                 % (os.path.basename(json_path), os.path.basename(md_path)))

    # -- lifecycle --------------------------------------------------------

    def stop_everything(self) -> None:
        for name, process in reversed(self.procs):
            terminate(process, name, self.log)
        for handle in self.handles:
            try:
                handle.close()
            except Exception:                               # noqa: BLE001
                pass
        if self.client is not None:
            self.client.close()
        try:
            self._log_handle.close()
        except Exception:                                   # noqa: BLE001
            pass

    def run(self) -> int:
        extra = {}
        try:
            self.start_smtp_sink()
            extra["fleet_started"] = self.start_fleet()
            self.ssh_started = self.start_fake_ssh()
            self.start_app()
            extra["seed"] = self.run_seed()
            self.connect()
            extra["first_cycle"] = self.wait_for_first_cycle()
            extra["configrx_platforms"] = self.configrx_platforms()
            self.incidents()
            if not self.args.skip_ui:
                extra["ui"] = self.run_ui()
            else:
                extra["ui"] = {"skipped": "--skip-ui"}
            return 0
        except Exception as exc:                            # noqa: BLE001
            self.notes.append("run aborted: %s: %s" % (type(exc).__name__, exc))
            self.log("[error] %s: %s" % (type(exc).__name__, exc))
            import traceback
            traceback.print_exc()
            return 1
        finally:
            try:
                self.write_results(extra)
            except Exception as exc:                        # noqa: BLE001
                print("could not write results: %s" % exc)
            self.stop_everything()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=250)
    parser.add_argument("--out", default=os.path.join(HERE, "out"))
    parser.add_argument("--port", type=int, default=APP_PORT)
    parser.add_argument("--control-port", type=int, default=FLEET_CONTROL_PORT)
    parser.add_argument("--ssh-base-port", type=int, default=SSH_BASE_PORT,
                        help="base port for the demo/fake_ssh.py personas "
                             "this run starts (default 2201)")
    parser.add_argument("--workers", type=int, default=32,
                        help="nodes poll_workers seed.py should set")
    parser.add_argument("--skip-ui", action="store_true",
                        help="do not run demo/ui_walk.mjs at the end")
    parser.add_argument("--fast", action="store_true",
                        help="scale every wait down 4x for a dry run")
    parser.add_argument("--topology", action="store_true",
                        help="set upstream_id on the Site-A devices, so the "
                             "outage step shows the alert rollup")
    parser.add_argument("--defaults", action="store_true",
                        help="seed with the shipped settings: no threshold, "
                             "grace, interval, worker or mail-cap overrides")
    args = parser.parse_args(argv)

    scenario = Scenario(args)

    # Ctrl+C must still reach the finally block that stops the children.
    def on_signal(signum, _frame):
        raise KeyboardInterrupt("signal %d" % signum)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass

    return scenario.run()


if __name__ == "__main__":
    raise SystemExit(main())

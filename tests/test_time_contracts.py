"""Every timestamp the browser shows goes through one vocabulary, and every
background worker is called one thing.

Static checks over the shipped frontend, in the same spirit as
test_frontend_contracts.py: each of these was true once, and each is a
one-line grep to keep true.

  * one ago() — seven modules used to carry their own, in three behaviours;
  * no module formats a Date itself (toLocaleString and friends): the
    absolute form is App.when, the relative one App.ago, a Time column is
    App.timeCell;
  * no Time column is a bare wall clock (App.clock) outside app.js;
  * the two search pages say "N of M shown", never "N shown" alone;
  * every refresh rate the loop reads has an input on Settings;
  * each module's strip, toggle and settings dialog use the same noun.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")

failures = []


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


def check(condition, message):
    print(("OK   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


# ssh.js is the one script that runs without app.js — the terminal is its
# own page and loads nothing of the application — so it cannot call App.when
# and keeps one local date rendering. Every other module has App.
MODULES = [f for f in sorted(os.listdir(STATIC))
           if f.endswith(".js") and f not in ("app.js", "boot.js", "login.js", "ssh.js")]
APP = read("app.js")
INDEX = read("index.html")

# --------------------------------------------------------------------------
# 1. One relative-time vocabulary.
for name in MODULES:
    body = read(name)
    check("function ago(" not in body, f"{name}: no private ago()")
    dates = [m for m in re.findall(r"new Date\([^)]*\)\.toLocale\w*String\(", body)]
    check(not dates, f"{name}: no toLocale*String on a Date ({len(dates)} found)")
    check(".toISOString()" not in body, f"{name}: no toISOString (exports use App.isoLocal)")
    # A Time column that shows the clock alone has no date; App.timeCell adds
    # one when the row is not from today.
    clocks = re.findall(r"App\.clock\(", body)
    check(not clocks, f"{name}: no App.clock in a module ({len(clocks)} found)")
for fn in ("function ago(", "function when(", "function timeCell(", "function agoCell(",
           "function isoLocal(", "function timeZoneLabel(", "function countLabel("):
    check(fn in APP, f"app.js defines {fn.split()[1]}")

# --------------------------------------------------------------------------
# 2. Honest counts.
for name, unit in (("syslog.js", "messages"), ("snmp.js", "traps")):
    body = read(name)
    check(f"App.countLabel(search.{unit}.length, total)" in body,
          f"{name}: the count says what it is out of")
    check("} shown`" not in body, f"{name}: no bare 'N shown'")

# --------------------------------------------------------------------------
# 3. Every refresh rate the loop reads has a control.
keys = set(re.findall(r"['.](\w+_refresh_s)\b", APP))
check(len(keys) >= 11, f"rateFor reads {len(keys)} refresh keys")
missing = []
for key in sorted(keys):
    page = key[:-len("_refresh_s")]
    if f'id="set-refresh-{page}"' not in INDEX:
        missing.append(key)
check(not missing, "every refresh rate has an input (missing: %s)" % (missing or "none"))
check('id="set-refresh-debug" min="1"' in INDEX, "the Debug rate input cannot ask for a fraction the floor ignores")

# --------------------------------------------------------------------------
# 4. One noun per module: status fallback, toggle pair, and the Dashboard.
NOUNS = {
    "nodes.js": ("Poller stopped", "Stop poller", "Start poller"),
    "alerts.js": ("Alert engine stopped", "Stop alert engine", "Start alert engine"),
    "netflow.js": ("Collector stopped", "Stop collector", "Start collector"),
    "snmp.js": ("Receiver stopped", "Stop receiver", "Start receiver"),
    "syslog.js": ("Collector stopped", "Stop collector", "Start collector"),
    "wireless.js": ("Poller stopped", "Stop poller", "Start poller"),
    "configrx.js": ("Worker stopped", "Stop worker", "Start worker"),
    "ipam.js": ("Worker stopped", "Stop worker", "Start worker"),
}
for name, (stopped, stop, start) in NOUNS.items():
    body = read(name)
    check(stopped in body and stop in body and start in body,
          f"{name}: strip and toggle agree on the noun ({stopped!r})")
check('id="ipam-toggle"' in INDEX and "/api/ipam/worker" in read("ipam.js"), "IPAM has a start/stop toggle")
check("<legend>LISTENER</legend>" not in read("snmp.js") and "<legend>RECEIVER</legend>" in read("snmp.js"),
      "SNMP settings call it a receiver, like its strip")
check("<legend>LISTENER</legend>" not in read("syslog.js"), "Syslog settings call it a collector, like its strip")
check("tile('Workers'" in read("dashboard.js"), "the Dashboard tile is 'Workers'")
check("App.tile" in read("dashboard.js") and "function tile(" not in read("dashboard.js"),
      "the Dashboard draws its tiles with the shared App.tile")

# --------------------------------------------------------------------------
# 5. Labels that follow state.
check("'Collapse silent hops'" in read("netpath.js") and 'aria-pressed' in read("netpath.js"),
      "route-expand names its other half and exposes pressed state")
check("btn.textContent = 'Poll now'" in read("wireless.js"), "the wireless Poll now button is restored")

# --------------------------------------------------------------------------
# 6. The zone is stated.
check('id="set-timezone"' in INDEX and "timeZoneLabel" in read("settings.js"), "Settings names the time zone")
check(read("syslog.js").count("title: App.timeZoneTitle()") == 1, "the Syslog Time column carries the zone")

print()
if failures:
    print("FAILED %d check(s):" % len(failures))
    for message in failures:
        print("  - " + message)
    sys.exit(1)
print("ALL TIME AND VOCABULARY CONTRACTS HOLD")

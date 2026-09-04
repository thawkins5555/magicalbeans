"""alertsdb.py's own maintenance-window arithmetic and webhook URL
validation, in isolation from the engine and the web API — the weekly
recurrence math in particular is easy to get subtly wrong (off-by-one on
which week's occurrence "now" falls into) and is worth pinning directly
rather than only through whatever schedule the engine-level suite happens
to exercise.
"""
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import (AlertsDatabase, MAX_WINDOW_DAYS,
                              is_window_active, validate_webhook_url)

TMPDIR = _paths.tmpdir("alert_maintenance_windows_db_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


db = AlertsDatabase(os.path.join(TMPDIR, "alerts.db"))

# ------------------------------------------------------- one-off windows

now = time.time()
one_off = db.add_window("One-off", "devices", now + 10, now + 70,
                        scope_device_ids=[1, 2])
row = db.window(one_off)
check("a future one-off window is inactive", not is_window_active(row, now))
check("...active once its span starts", is_window_active(row, now + 20))
check("...inactive again once its span ends", not is_window_active(row, now + 71))

# ------------------------------------------------------------- weekly

week = 7 * 86400.0
start = now - 3 * week - 10          # first occurrence began 3 weeks ago
weekly = db.add_window("Weekly", "devices", start, start + 60,
                       scope_device_ids=[1], recurrence="weekly")
row = db.window(weekly)
check("a weekly window is active RIGHT NOW (mid-span of the current occurrence)",
      is_window_active(row, now))
check("...inactive an hour after this week's span ended",
      not is_window_active(row, now + 3600))
check("...active again next week, same offset into the cycle",
      is_window_active(row, now + week))
check("...and the week after that", is_window_active(row, now + 2 * week))
check("...inactive before the window's own first occurrence ever began",
      not is_window_active(row, start - week - 1))

# --------------------------------------------------------------- caps

try:
    db.add_window("Too long", "devices", now, now + (MAX_WINDOW_DAYS + 1) * 86400,
                  scope_device_ids=[1])
    check("a window over the day cap is refused", False)
except ValueError:
    check("a window over the day cap is refused", True)

try:
    db.add_window("Backwards", "devices", now, now - 5, scope_device_ids=[1])
    check("a window that ends before it starts is refused", False)
except ValueError:
    check("a window that ends before it starts is refused", True)

try:
    db.add_window("Bad recurrence", "devices", now, now + 60,
                  scope_device_ids=[1], recurrence="monthly")
    check("an unsupported recurrence value is refused", False)
except ValueError:
    check("an unsupported recurrence value is refused", True)

# A weekly window whose own occurrence spans >= 7 days satisfies
# is_window_active's (now - start_ts) % week < duration test at every
# instant — permanently active, silencing its whole scope forever. The
# 14-day MAX_WINDOW_DAYS cap alone does not catch this (8 days is well
# under it), so add_window/update_window need their own, tighter check
# for the weekly case specifically.
try:
    db.add_window("Permanent weekly", "devices", now, now + 8 * 86400,
                  scope_device_ids=[1], recurrence="weekly")
    check("an 8-day weekly window is refused", False)
except ValueError as exc:
    check("an 8-day weekly window is refused", True)
    check("...with a message explaining why",
          "7 days" in str(exc) or "permanently" in str(exc), str(exc))

# The same 8-day span is fine as a one-off — the 14-day cap is the only
# limit that shape has, unchanged.
one_off_8day = db.add_window("8-day one-off", "devices", now, now + 8 * 86400,
                             scope_device_ids=[1])
check("an 8-day one-off window is still accepted",
      db.window(one_off_8day) is not None)

# A 6-day weekly window is under the 7-day boundary and must still work —
# this is the ordinary "closed for maintenance every weekend" case.
six_day_weekly = db.add_window("6-day weekly", "devices", now, now + 6 * 86400,
                               scope_device_ids=[1], recurrence="weekly")
check("a 6-day weekly window is accepted",
      db.window(six_day_weekly) is not None)

# update_window must catch the same shape — editing an existing window
# into a permanent one is exactly as bad as creating it that way.
editable = db.add_window("Editable", "devices", now, now + 3 * 86400,
                         scope_device_ids=[1], recurrence="weekly")
try:
    db.update_window(editable, end_ts=now + 8 * 86400)
    check("update_window refuses stretching a weekly window to 8 days", False)
except ValueError:
    check("update_window refuses stretching a weekly window to 8 days", True)

# ---------------------------------------------------- scope resolution

group_window = db.add_window("Group scope", "group", now - 5, now + 60,
                             scope_group_id=42)
covered = db.window_covered_device_ids([("7", 42), ("8", 99)], now=now)
check("a device in the covered group is covered", "7" in covered, covered)
check("a device in a different group is not", "8" not in covered, covered)
check("window_covers_device answers the same for one device",
      db.window_covers_device("7", 42, now=now) is not None)
check("...and None for a device outside the scope",
      db.window_covers_device("8", 99, now=now) is None)

# ---------------------------------------------- deleting, editing, ending

db.update_window(group_window, name="Group scope, renamed", end_ts=now + 3600)
row = db.window(group_window)
check("update_window changes what it is given", row["name"] == "Group scope, renamed")
check("...and leaves the rest (scope_kind) alone", row["scope_kind"] == "group")

changed = db.end_window_now(group_window)
row = db.window(group_window)
check("end_window_now stops it covering anything as of now",
      not is_window_active(row, time.time()))
check("...and reports that it actually changed something", changed)

check("remove_window actually removes it", db.remove_window(group_window))
check("...and a second delete reports nothing removed",
      not db.remove_window(group_window))

# A weekly window past its first occurrence — is_window_active is what
# actually decides "active", and it never looks at the stored end_ts once
# recurrence is set, only at (now - start_ts) % week. end_window_now's own
# guard has to agree, or "End now" silently does nothing for exactly this
# shape: the stored end_ts is three weeks stale while this week's
# occurrence is active right now.
recurring = db.add_window("Weekly, three weeks in", "devices",
                          now - 3 * week - 10, now - 3 * week + 60,
                          scope_device_ids=[3], recurrence="weekly")
row = db.window(recurring)
check("setup: this weekly window is active right now, mid-occurrence",
      is_window_active(row, now))

changed = db.end_window_now(recurring)
check("end_window_now reports it changed a weekly window past its first "
      "occurrence", changed)
row = db.window(recurring)
# Checked against a fresh timestamp, not the stale `now` captured above —
# end_window_now sets end_ts to the moment IT ran, a little later than
# that, so "active" is still the honest answer for the instant just before
# the call. What must be false is "active right now, after ending it".
just_ended = time.time()
check("...it stops being active immediately", not is_window_active(row, just_ended))
check("...recurrence is cleared so it cannot start back up", row["recurrence"] is None)
check("...and stays inactive next week too (permanently ended, not paused)",
      not is_window_active(row, just_ended + week))

# A one-off window ended early — the ordinary case end_window_now has
# always handled, still working the same way.
future_one_off = db.add_window("Future one-off", "devices", now + 100, now + 200,
                               scope_device_ids=[4])
changed = db.end_window_now(future_one_off)
check("ending a future one-off window reports it changed", changed)
row = db.window(future_one_off)
check("...and it is inactive even during its old planned span",
      not is_window_active(row, now + 150))

# An already-ended one-off window: end_window_now must stay a genuine
# no-op, not silently rewrite an already-closed record's end_ts to now.
past_one_off = db.add_window("Already ended", "devices", now - 200, now - 100,
                             scope_device_ids=[5])
old_end_ts = db.window(past_one_off)["end_ts"]
changed = db.end_window_now(past_one_off)
check("ending an already-ended one-off window reports no change", not changed)
check("...and its end_ts is left untouched",
      db.window(past_one_off)["end_ts"] == old_end_ts)

# ---------------------------------------------------------- webhook URL

validate_webhook_url("")               # webhooks off / unset: never an error
validate_webhook_url("https://hooks.example.com/x")
validate_webhook_url("http://127.0.0.1:9999/x")
validate_webhook_url("http://localhost/x")
validate_webhook_url("http://10.1.2.3/x")

for bad in ("http://example.com/x", "ftp://example.com/x", "not a url",
           "http://8.8.8.8/x"):
    try:
        validate_webhook_url(bad)
        check(f"refuses {bad!r}", False)
    except ValueError:
        check(f"refuses {bad!r}", True)

try:
    db.save_settings({"webhook_url": "http://example.com/hook"})
    check("save_settings itself refuses a plaintext public webhook_url", False)
except ValueError:
    check("save_settings itself refuses a plaintext public webhook_url", True)


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

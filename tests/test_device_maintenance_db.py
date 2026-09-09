"""Indefinite per-device maintenance mode at the storage layer: the period
table, its idempotent writer, the fold into quiet_device_ids, retention,
merge and device deletion — in isolation from the engine and the web API.

The assertion that decides the design is "a device can be BOTH muted and in
maintenance, with the mute's until_ts untouched": a sentinel row in
alert_mutes could not hold both, because ux_mute_entity is UNIQUE per
entity, and mute()'s own upsert would silently end somebody's maintenance
in an hour.
"""
import math
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase

TMPDIR = _paths.tmpdir("device_maintenance_db_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def fresh(name):
    return AlertsDatabase(os.path.join(TMPDIR, f"{name}.db"))


# ------------------------------------------------ set / open / clear

db = fresh("basic")
check("a device with no period is not in maintenance",
      db.open_maintenance(1) is None)

row = db.set_maintenance(1, by="op", reason="rewiring rack 4")
check("set_maintenance returns the open period it wrote",
      row is not None and row["ended_ts"] is None
      and row["started_by"] == "op" and row["reason"] == "rewiring rack 4",
      dict(row) if row else None)
check("...and open_maintenance now answers with it",
      db.open_maintenance(1) is not None)
check("...with no expiry column to read at all",
      "until_ts" not in row.keys(), list(row.keys()))

# Idempotence: the second press must not restart the clock or rewrite who
# set it — "since when, and by whom" is the whole of the record.
time.sleep(0.02)
again = db.set_maintenance(1, by="someone else", reason="different reason")
check("a second set_maintenance returns the SAME period untouched",
      again["id"] == row["id"] and again["started_ts"] == row["started_ts"]
      and again["started_by"] == "op" and again["reason"] == "rewiring rack 4",
      dict(again))
check("...and there is still exactly one row for the device",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 1").fetchone()[0] == 1)

check("clear_maintenance reports that it ended one", db.clear_maintenance(1, by="op2"))
check("...the device is out of maintenance", db.open_maintenance(1) is None)
closed = db._conn.execute("SELECT * FROM device_maintenance WHERE device_id = 1").fetchone()
check("...but the row STAYS on file, closed and stamped — the availability"
      " report replays it, which is exactly what a mute cannot do",
      closed is not None and closed["ended_ts"] is not None
      and closed["ended_by"] == "op2", dict(closed) if closed else None)
check("clearing again reports nothing to clear", not db.clear_maintenance(1))

# Re-entering writes a SECOND row rather than reopening the first.
second = db.set_maintenance(1, by="op3")
check("re-entering maintenance writes a NEW period, not an upsert of the old",
      second["id"] != row["id"] and db._conn.execute(
          "SELECT COUNT(*) FROM device_maintenance WHERE device_id = 1"
      ).fetchone()[0] == 2, second["id"])


# ------------------------------------ a device may be muted AND in maintenance

db = fresh("both")
until = db.mute("device", "7", 6.0, by="op", reason="working on it")["until_ts"]
maint = db.set_maintenance(7, by="op", reason="out of service")
check("**a device can be muted AND in maintenance at once**",
      db.mute_row("device", "7") is not None
      and db.open_maintenance(7) is not None)
check("...and the mute's own until_ts is untouched by the maintenance write",
      db.mute_row("device", "7")["until_ts"] == until,
      (db.mute_row("device", "7")["until_ts"], until))
check("...ending the maintenance leaves the mute standing",
      db.clear_maintenance(7) and db.mute_row("device", "7") is not None)
check("...and unmuting leaves a fresh maintenance period standing",
      bool(db.set_maintenance(7)) and db.unmute("device", "7")
      and db.open_maintenance(7) is not None)


# ------------------------------------------------------------- retention

db = fresh("prune")
old_open = db.set_maintenance(11, by="op")
db._conn.execute("UPDATE device_maintenance SET started_ts = ? WHERE id = ?",
                 (time.time() - 400 * 86400, old_open["id"]))
db.set_maintenance(12, by="op")
db.clear_maintenance(12)
recent_closed = db.open_maintenance(12)
db._conn.execute(
    "UPDATE device_maintenance SET started_ts = ?, ended_ts = ? WHERE device_id = 12",
    (time.time() - 400 * 86400, time.time() - 399 * 86400))
db.set_maintenance(13, by="op")
db.clear_maintenance(13)             # closed just now, well inside retention
db._conn.commit()

db.prune(30.0)
check("prune deletes a CLOSED period older than the cutoff",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 12").fetchone()[0] == 0)
check("...leaves a closed period inside the cutoff alone",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 13").fetchone()[0] == 1)
check("...and never prunes an OPEN period, at any age",
      db.open_maintenance(11) is not None)


# --------------------------------------------------------- quiet_device_ids

db = fresh("quiet")
db.set_maintenance(21, by="op")                      # maintenance only
db.mute("device", "22", 2.0, by="op")                 # mute only
window_covered = {"23": time.time() + 3600}           # window-covered only
db.mute("device", "24", 2.0, by="op")
db.set_maintenance(24, by="op")                       # both

quiet = db.quiet_device_ids(window_covered=window_covered)
muted = db.muted_entity_ids("device", window_covered=window_covered)
check("quiet_device_ids carries the maintenance device",  "21" in quiet, quiet)
check("...the muted device", "22" in quiet, quiet)
check("...the window-covered device", "23" in quiet, quiet)
check("...and the device that is both", "24" in quiet, quiet)
check("muted_entity_ids carries only the mute and the window, NOT maintenance",
      set(muted) == {"22", "23", "24"}, muted)
check("...and every value in it is a finite float — no sentinel date an"
      " operator would sit waiting for",
      all(isinstance(v, float) and math.isfinite(v) for v in muted.values()),
      muted)
check("quiet_device_ids is a set of ids, not a dict of deadlines",
      isinstance(quiet, set), type(quiet).__name__)


# ------------------------------------------------------- maintenance_periods

db = fresh("periods")
now = time.time()
p_old = db.set_maintenance(31)
db.clear_maintenance(31)
db._conn.execute(
    "UPDATE device_maintenance SET started_ts = ?, ended_ts = ? WHERE id = ?",
    (now - 5000, now - 4000, p_old["id"]))
p_open = db.set_maintenance(32)
db._conn.execute("UPDATE device_maintenance SET started_ts = ? WHERE id = ?",
                 (now - 100, p_open["id"]))
p_far = db.set_maintenance(33)
db.clear_maintenance(33)
db._conn.execute(
    "UPDATE device_maintenance SET started_ts = ?, ended_ts = ? WHERE id = ?",
    (now - 90000, now - 89000, p_far["id"]))
db._conn.commit()

periods = db.maintenance_periods(now - 6000, now)
check("maintenance_periods returns a closed period overlapping the span",
      [r["id"] for r in periods.get("31", [])] == [p_old["id"]], periods)
check("...and an OPEN one, which has no end to compare against",
      [r["id"] for r in periods.get("32", [])] == [p_open["id"]], periods)
check("...and nothing that ended before the span began", "33" not in periods, periods)


# ---------------------------------------------------------------- merge

db = fresh("merge_repoint")
db.set_maintenance(41, by="op", reason="loser in maintenance")
moved = db.merge_device(41, 42, by="admin")
check("merging a device IN maintenance into one that is NOT repoints the period",
      db.open_maintenance(42) is not None and db.open_maintenance(41) is None,
      moved)
check("...and the merge reports it moved", moved.get("maintenance") == 1, moved)

db = fresh("merge_collide")
loser = db.set_maintenance(51, by="loser-op", reason="loser")
winner = db.set_maintenance(52, by="winner-op", reason="winner")
db.set_maintenance(51)               # no-op; both are already open
moved = db.merge_device(51, 52, by="admin")
check("merging when BOTH are in maintenance does not fail on the partial index",
      isinstance(moved, dict), moved)
check("...the WINNER's own open period stands, unchanged",
      db.open_maintenance(52)["id"] == winner["id"]
      and db.open_maintenance(52)["started_by"] == "winner-op",
      dict(db.open_maintenance(52)))
check("...the loser's is CLOSED, not dropped, and moved to the surviving id",
      db._conn.execute(
          "SELECT ended_ts, device_id FROM device_maintenance WHERE id = ?",
          (loser["id"],)).fetchone()["ended_ts"] is not None
      and db._conn.execute(
          "SELECT device_id FROM device_maintenance WHERE id = ?",
          (loser["id"],)).fetchone()["device_id"] == 52)
check("...and exactly one open period survives for the winner",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 52 AND ended_ts IS NULL").fetchone()[0] == 1)

db = fresh("merge_closed")
db.set_maintenance(61)
db.clear_maintenance(61)
db.merge_device(61, 62)
check("a loser's CLOSED periods move wholesale — they are its availability"
      " history, now reported under the surviving id",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 62").fetchone()[0] == 1
      and db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                           " device_id = 61").fetchone()[0] == 0)


# ------------------------------------------------------------ forget_device

db = fresh("forget")
db.set_maintenance(71, by="op", reason="open")
db.clear_maintenance(71)
db.set_maintenance(71, by="op", reason="open again")
db.mute("device", "71", 4.0, by="op")
db.set_maintenance(72, by="op")               # a bystander
db.mute("device", "72", 4.0, by="op")
db.forget_device(71)
check("forget_device leaves the device no open period",
      db.open_maintenance(71) is None)
check("...no closed one either — a rowid SQLite reissues must not inherit one",
      db._conn.execute("SELECT COUNT(*) FROM device_maintenance WHERE"
                       " device_id = 71").fetchone()[0] == 0)
check("...and no mute, for the same inheritance reason",
      db.mute_row("device", "71") is None)
check("...while the next device along is untouched",
      db.open_maintenance(72) is not None
      and db.mute_row("device", "72") is not None)


# --------------------------------------------- clearing re-arms held notices

db = fresh("rearm")
rule = db.rule_by_key("device_down")


def held(dedup, entity_kind, entity_id, *, age_s=0.0):
    """An alert whose held first notice was closed out by maintenance."""
    row, _ = db.open_or_increment(rule["id"], dedup, entity_kind, str(entity_id),
                                  "core1", 2, "is down", "", time.time() - age_s)
    db.mark_notified(row["id"], maintenance_held=True)
    return row["id"]


device_alert = held("d:80", "device", 80)
port_alert = held("i:80:3", "interface", "80:3")
other_alert = held("d:81", "device", 81)
sent_alert, _ = db.open_or_increment(rule["id"], "d:80:sent", "device", "80",
                                     "core1", 2, "is down", "", time.time())
db.mark_notified(sent_alert["id"])             # a genuine notification
sent_stamp = db.alert(sent_alert["id"])["last_notified_ts"]

db.set_maintenance(80, by="op")
check("clear_maintenance re-arms the device's own held notice",
      db.clear_maintenance(80, by="op") is True
      and db.alert(device_alert)["last_notified_ts"] is None)
check("...and the held notice of an alert on one of its PORTS, which is what"
      " put the port's device into maintenance in the first place",
      db.alert(port_alert)["last_notified_ts"] is None)
check("...and not an alert that was genuinely notified before maintenance",
      db.alert(sent_alert["id"])["last_notified_ts"] == sent_stamp)
check("...and not another device's",
      db.alert(other_alert)["last_notified_ts"] is not None)

old = held("d:82", "device", 82, age_s=4.0 * 3600)
db.set_maintenance(82, by="op")
db.clear_maintenance(82, by="op")
check("**a notice held through a four-hour maintenance is due the moment it"
      " ends, not written off as backlog — the flag says the notice is"
      " genuinely owed, which is what the grace floor cannot tell**",
      any(r["id"] == old for r in db.alerts_due_first_notify(time.time() - 240)),
      [r["id"] for r in db.alerts_due_first_notify(time.time() - 240)])

db.mark_notified(old)
check("...and the sweep's own stamp disarms the flag, so a later maintenance"
      " toggle cannot replay a notice that has gone out",
      db.clear_maintenance(82, by="op") is False
      and db.alert(old)["last_notified_ts"] is not None)
db.set_maintenance(82, by="op")
db.clear_maintenance(82, by="op")
check("...even across a whole second maintenance period",
      db.alert(old)["last_notified_ts"] is not None)

acked = held("d:83", "device", 83)
gone = held("d:84", "device", 84)
db.acknowledge(acked, "op")
db.resolve(gone, by="op")
db.set_maintenance(83, by="op")
db.set_maintenance(84, by="op")
db.clear_maintenance(83, by="op")
db.clear_maintenance(84, by="op")
check("an ACKNOWLEDGED alert is not re-armed — somebody already has it",
      db.alert(acked)["last_notified_ts"] is not None)
check("...nor a resolved one",
      db.alert(gone)["last_notified_ts"] is not None)


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

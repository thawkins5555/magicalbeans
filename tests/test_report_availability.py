"""netpath/report.py's device_availability_report(), against real
NodesDatabase/AlertsDatabase instances (in-memory, same schema and public
methods the running application uses) rather than hand-rolled fakes — the
whole point of this report is that device_status_segments, windows() and
mutes() are the source of truth, so a test double for any of them would be
testing this module's assumptions about them, not the module itself.

Five things, matching what the task asked this module to prove:
  1. a device up the whole window reads 100%
  2. two separate outages report as two outages, with the right total
     downtime, the right longest outage, and the right MTTR
  3. a device added mid-window is not charged for the time before it
     existed
  4. a maintenance-window device and a muted device are both
     distinguishable from a genuinely down one — three devices, same raw
     down time, three different net figures
  5. (test_report_topn.py covers top-N ranking separately, and the
     realistic-scale query cost)
"""
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.nodesdb import NodesDatabase
from netpath.report import device_availability_report

TMPDIR = _paths.tmpdir("report_availability_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_dbs():
    nodesdb = NodesDatabase(":memory:")
    alertsdb = AlertsDatabase(":memory:")
    return nodesdb, alertsdb


def set_created(db, device_id, ts):
    db._conn.execute("UPDATE devices SET created_ts = ? WHERE id = ?", (ts, device_id))
    db._conn.commit()


def set_status(db, device_id, status):
    db._conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))
    db._conn.commit()


def event_at(db, device_id, kind, ts, detail=""):
    """record_device_event always stamps time.time(); back-date it, the
    same trick every other historical-fixture test in this repo uses when
    the public API has no timestamp parameter to hand it directly."""
    db.record_device_event(device_id, kind, detail)
    db._conn.execute(
        "UPDATE device_events SET ts = ? WHERE id = (SELECT MAX(id) FROM device_events"
        " WHERE device_id = ? AND kind = ?)",
        (ts, device_id, kind))
    db._conn.commit()


# ------------------------------------------------------- 1. always up

nodesdb, alertsdb = new_dbs()
now = time.time()
t0, t1 = now - 10 * 3600, now
did = nodesdb.add_device("10.0.1.1", "always-up")
set_created(nodesdb, did, t0 - 3600)
set_status(nodesdb, did, "up")
event_at(nodesdb, did, "up", t0 - 1800, "responding again")

rep = device_availability_report(nodesdb, [did], t0, t1, alertsdb=alertsdb)
d = rep.devices[0]
check("always-up: availability_pct is 100", d.availability_pct == 100.0, str(d.availability_pct))
check("always-up: up_s spans the whole window", d.up_s == t1 - t0, str(d.up_s))
check("always-up: no outages", d.outage_count == 0 and not d.outages)
check("always-up: not still down", not d.still_down)

# --------------------------------------------------- 2. two outages

nodesdb, alertsdb = new_dbs()
now = time.time()
t0, t1 = now - 10 * 3600, now
did = nodesdb.add_device("10.0.1.2", "two-outages")
set_created(nodesdb, did, t0 - 3600)
set_status(nodesdb, did, "up")
event_at(nodesdb, did, "up", t0 - 1800, "responding again")

# outage A: 30 min, 8 hours ago. outage B: 90 min, 3 hours ago. Both
# recovered — MTTR should be their average, not weighted by anything else.
a_down, a_up = t0 + 3600, t0 + 3600 + 1800
b_down, b_up = t0 + 6 * 3600, t0 + 6 * 3600 + 5400
event_at(nodesdb, did, "down", a_down, "not responding")
event_at(nodesdb, did, "up", a_up, "responding again")
event_at(nodesdb, did, "down", b_down, "not responding")
event_at(nodesdb, did, "up", b_up, "responding again")

rep = device_availability_report(nodesdb, [did], t0, t1, alertsdb=alertsdb)
d = rep.devices[0]
check("two outages: outage_count is 2", d.outage_count == 2, str(d.outage_count))
check("two outages: total down_s is 30+90 minutes", d.down_s == 1800.0 + 5400.0, str(d.down_s))
check("two outages: longest is the 90-minute one", d.longest_outage_s == 5400.0,
     str(d.longest_outage_s))
check("two outages: mttr is the mean of 1800 and 5400", d.mttr_s == (1800.0 + 5400.0) / 2,
     str(d.mttr_s))
check("two outages: availability_pct reflects exactly the observed down time",
     abs(d.availability_pct - 100.0 * (1 - 7200.0 / (t1 - t0))) < 1e-6,
     str(d.availability_pct))
check("two outages: neither is still ongoing", not d.still_down)
check("two outages: neither outage is truncated at either end",
     not any(o.truncated_start or o.ongoing for o in d.outages))

# ------------------------------------------------ 3. created mid-window

nodesdb, alertsdb = new_dbs()
now = time.time()
t0, t1 = now - 10 * 3600, now
did = nodesdb.add_device("10.0.1.3", "born-mid-window")
created = t0 + 4 * 3600           # exists for only the last 6 of 10 hours
set_created(nodesdb, did, created)
set_status(nodesdb, did, "up")
# The "up" event lands exactly at creation, not a moment after, so the
# effective window has no leading instant of "unknown" of its own to
# confuse this check with the (already covered) pre-creation exclusion.
event_at(nodesdb, did, "up", created, "responding again")

rep = device_availability_report(nodesdb, [did], t0, t1, alertsdb=alertsdb)
d = rep.devices[0]
check("born mid-window: excludes exactly the pre-creation time",
     d.excluded_before_created_s == 4 * 3600.0, str(d.excluded_before_created_s))
check("born mid-window: effective_start is created_ts, not t0",
     d.effective_start == created, str(d.effective_start))
check("born mid-window: up_s only covers the post-creation span",
     d.up_s == t1 - created, str(d.up_s))
check("born mid-window: reads 100%, not penalised for time before it existed",
     d.availability_pct == 100.0, str(d.availability_pct))
check("born mid-window: says so in its own caveats",
     any("created" in c for c in d.caveats), str(d.caveats))

# --------------------------------- 4. maintenance vs mute vs genuinely down

nodesdb, alertsdb = new_dbs()
now = time.time()
t0, t1 = now - 10 * 3600, now

maint_id = nodesdb.add_device("10.0.1.10", "under-maintenance")
mute_id = nodesdb.add_device("10.0.1.11", "muted")
plain_id = nodesdb.add_device("10.0.1.12", "genuinely-down")

# The SAME 4-hour outage on all three devices, starting 2 hours into the
# window and recovering well before it ends (bounded on both sides, so
# this also exercises the ordinary "fully observed outage" path rather
# than the ongoing one block 2 already covers) — the only difference
# between them is what alertsdb says about it afterwards.
down_start = t0 + 2 * 3600
up_ts = down_start + 4 * 3600
outage_raw_s = up_ts - down_start
for did in (maint_id, mute_id, plain_id):
    set_created(nodesdb, did, t0 - 3600)
    set_status(nodesdb, did, "up")
    event_at(nodesdb, did, "up", t0 - 1800, "responding again")
    event_at(nodesdb, did, "down", down_start, "not responding")
    event_at(nodesdb, did, "up", up_ts, "responding again")

# Maintenance window: a clean two-hour slice out of the MIDDLE of the
# outage — maintenance_windows keeps full history, so this is exactly as
# accurate for a report run today as one run the day it happened.
mid_lo, mid_hi = down_start + 3600, down_start + 3 * 3600
maint_excluded_s = mid_hi - mid_lo
alertsdb.add_window("cutover", "devices", mid_lo, mid_hi, scope_device_ids=[maint_id])

# Mute: created one hour into the SAME outage. Its until_ts has to be in
# the future relative to REAL now for mutes() to see it at all (an
# already-expired mute is deleted — see the module docstring) — and since
# this whole outage already finished in the past relative to real now,
# any such mute necessarily outlives the outage itself. So unlike the
# maintenance window, a mute can only ever exclude "from when it was
# created onward", never a bounded middle slice — unavoidable given
# alertsdb has no record of a mute being lifted early, only of when it
# will next expire. That asymmetry is the point of this fixture, not an
# inconsistency in it.
mute_created = down_start + 3600
mute_excluded_s = up_ts - mute_created
alertsdb._conn.execute(
    "INSERT INTO alert_mutes(entity_kind, entity_id, until_ts, created_ts,"
    " created_by, reason) VALUES ('device', ?, ?, ?, 'op', 'known issue')",
    (str(mute_id), now + 3600, mute_created))
alertsdb._conn.commit()

rep = device_availability_report(
    nodesdb, [maint_id, mute_id, plain_id], t0, t1, alertsdb=alertsdb)
by_id = {d.device_id: d for d in rep.devices}

check("maintenance device: the two-hour slice is excluded, not down",
     by_id[maint_id].down_s == outage_raw_s - maint_excluded_s
     and by_id[maint_id].maintenance_excluded_s == maint_excluded_s,
     f"down_s={by_id[maint_id].down_s} excl={by_id[maint_id].maintenance_excluded_s}")
check("muted device: from when it was muted onward is excluded instead",
     by_id[mute_id].down_s == outage_raw_s - mute_excluded_s
     and by_id[mute_id].mute_excluded_s == mute_excluded_s,
     f"down_s={by_id[mute_id].down_s} excl={by_id[mute_id].mute_excluded_s}")
check("plain device: nothing excluded, the full outage counts",
     by_id[plain_id].down_s == outage_raw_s
     and by_id[plain_id].maintenance_excluded_s == 0
     and by_id[plain_id].mute_excluded_s == 0,
     str(by_id[plain_id].down_s))
check("all three: recovered before the window ended, none still down",
     not any(by_id[i].still_down for i in (maint_id, mute_id, plain_id)))
check("global caveat names the mute-history limitation",
     any("mute" in c and "delete" in c for c in rep.global_caveats),
     str(rep.global_caveats))

# ------------------------------------------------- no alertsdb supplied

nodesdb, _ = new_dbs()
now = time.time()
t0, t1 = now - 10 * 3600, now
did = nodesdb.add_device("10.0.1.20", "no-alerts-db")
set_created(nodesdb, did, t0 - 3600)
set_status(nodesdb, did, "up")
event_at(nodesdb, did, "up", t0 - 1800, "responding again")
rep = device_availability_report(nodesdb, [did], t0, t1, alertsdb=None)
check("no alertsdb: a caveat says exclusion was skipped, not silently applied",
     any("skipped" in c for c in rep.global_caveats), str(rep.global_caveats))


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

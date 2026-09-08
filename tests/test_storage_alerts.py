"""Alerts for a database running out of room: the maintenance sweep's
sampler, and the two system rules it raises through.

Nothing in the product noticed storage before this. A cap silently deleting
the oldest records every fifteen minutes looks identical, from the Alerts
page, to a site keeping everything -- and a volume with nothing left on it
stops every database writing at once, whatever their caps say.

Sizes are stubbed on each store rather than written: what is being pinned is
the band arithmetic and which entity each occurrence names, and filling a
real 512 MB cap to prove it would take 512 MB. The last section drives a
real AlertEngine tick so the row in alerts.db, not just the call, is what
the clear has to close.
"""
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.web import service as service_mod
from netpath.web import Service

TMPDIR = _paths.tmpdir("storage_alerts_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


MB = 1024 * 1024
CAPPED = [store for store in service_mod.STORES if store.cap_key]


class Recorder:
    """Stands in for the alert engine, so a sweep can be read as the calls it
    made rather than as rows a tick later."""

    def __init__(self):
        self.raised = []
        self.cleared = []

    def system_occurrence(self, rule_key, entity_id, label, severity=None,
                          extra=None, message=""):
        self.raised.append({"rule": rule_key, "entity": entity_id,
                            "label": label, "severity": severity,
                            "extra": dict(extra or {}), "message": message})

    def clear_system_occurrence(self, rule_key, entity_id):
        self.cleared.append((rule_key, entity_id))


# ------------------------------------------------- 1. the two rules ship

rules_db = AlertsDatabase(os.path.join(TMPDIR, "rules.db"))
for key, severity in (("db_near_cap", 3), ("disk_space_low", 3)):
    row = rules_db.rule_by_key(key)
    check(f"{key} ships as a built-in rule",
          row is not None and row["kind"] == "system"
          and row["source_kind"] == key and row["severity"] == severity,
          dict(row) if row else None)
    check(f"...and {key} closes itself if the service stops mid-condition, "
          "rather than leaving a size alert open for ever",
          row is not None and row["auto_resolve_after_s"],
          dict(row) if row else None)
rules_db.close()


# ------------------------------------------------------ 2. the sampler

DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")
folder = os.path.join(TMPDIR, "service")
os.makedirs(folder, exist_ok=True)
service = Service(*[os.path.join(folder, name + ".db") for name in DB_NAMES])

real_engine = service.alert_engine
real_disk_space = service_mod.disk_space
DISK = [50 * 1024 * MB, 100 * 1024 * MB]      # free, total -- half empty
service_mod.disk_space = lambda _service: (DISK[0], DISK[1])

for store in CAPPED:
    service.settings[store.cap_key] = 512
service.settings["disk_free_warn_pct"] = 10
service.settings["disk_free_critical_pct"] = 5


def set_size(store, share):
    db = service_mod.db_for(service, store)
    db.size_bytes = lambda: int(512 * MB * share)


def sweep():
    recorder = Recorder()
    service.alert_engine = recorder
    service._sample_storage_alerts()
    return recorder


for store in CAPPED:
    set_size(store, 0.10)
quiet = sweep()
check("an empty fleet of databases raises nothing",
      not [row for row in quiet.raised if row["rule"] == "db_near_cap"],
      quiet.raised)
check("...and clears every capped store by name, so a sweep after the "
      "condition ends closes the alert that store opened",
      sorted(entity for rule, entity in quiet.cleared if rule == "db_near_cap")
      == sorted(store.name for store in CAPPED),
      quiet.cleared)

trace = next(store for store in CAPPED if store.name == "trace")
set_size(trace, 0.86)
warned = sweep()
near = [row for row in warned.raised if row["rule"] == "db_near_cap"]
check("a store over 85% of its cap raises db_near_cap, and only that store",
      len(near) == 1 and near[0]["entity"] == "trace", near)
check("...at the severity poll_pool_saturated uses",
      near and near[0]["severity"] == 3, near)
check("...naming the file, its size, its cap and the setting that governs "
      "it, so the alert is actionable from the alert",
      near and near[0]["extra"]["path"].endswith("netpath.db")
      and near[0]["extra"]["cap_bytes"] == 512 * MB
      and near[0]["extra"]["setting"] == "max_trace_db_mb"
      and "max_trace_db_mb" in near[0]["message"]
      and "86%" in near[0]["message"],
      near[0] if near else None)
check("...and the stores still in room are cleared in the same pass",
      "trace" not in [entity for rule, entity in warned.cleared
                      if rule == "db_near_cap"]
      and len([entity for rule, entity in warned.cleared
               if rule == "db_near_cap"]) == len(CAPPED) - 1,
      warned.cleared)

set_size(trace, 0.97)
high = [row for row in sweep().raised if row["rule"] == "db_near_cap"]
check("past 95% it escalates rather than reading the same as 86%",
      len(high) == 1 and high[0]["severity"] == 2, high)

# 0.82 is between the raise band and the clear band: a store held just under
# its cap by the trims would otherwise open and close on alternate sweeps.
set_size(trace, 0.82)
held = sweep()
check("between the bands nothing is raised and nothing is cleared -- the "
      "trims keep a busy store just under its cap for ever",
      not [row for row in held.raised if row["rule"] == "db_near_cap"]
      and "trace" not in [entity for rule, entity in held.cleared
                          if rule == "db_near_cap"],
      (held.raised, held.cleared))

set_size(trace, 0.50)
back = sweep()
check("and back under the clear band the store's own alert is cleared",
      ("db_near_cap", "trace") in back.cleared, back.cleared)

for store in CAPPED:
    set_size(store, 0.99)
everything = sweep()
entities = [row["entity"] for row in everything.raised
            if row["rule"] == "db_near_cap"]
check("every database gets an alert of its own rather than one that flaps "
      "between them",
      sorted(entities) == sorted(store.name for store in CAPPED), entities)

for store in CAPPED:
    service.settings[store.cap_key] = 0
uncapped = sweep()
check("an uncapped store is skipped entirely, not divided by zero",
      not [row for row in uncapped.raised if row["rule"] == "db_near_cap"]
      and not [entity for rule, entity in uncapped.cleared
               if rule == "db_near_cap"],
      (uncapped.raised, uncapped.cleared))


# --------------------------------------------------- 3. the volume itself

check("a half-empty volume raises nothing and clears the alert",
      ("disk_space_low", "data") in uncapped.cleared
      and not [row for row in uncapped.raised if row["rule"] == "disk_space_low"],
      (uncapped.raised, uncapped.cleared))

DISK[0] = 8 * 1024 * MB                        # 8% free, warn at 10
low = [row for row in sweep().raised if row["rule"] == "disk_space_low"]
check("below the warning threshold the volume raises disk_space_low",
      len(low) == 1 and low[0]["severity"] == 3, low)
check("...naming the directory, what is left of the volume and the setting "
      "that decides when this fires",
      low and low[0]["extra"]["free_bytes"] == 8 * 1024 * MB
      and low[0]["extra"]["setting"] == "disk_free_warn_pct"
      and folder in low[0]["message"],
      low[0] if low else None)

DISK[0] = 2 * 1024 * MB                        # 2% free, critical at 5
critical = [row for row in sweep().raised if row["rule"] == "disk_space_low"]
check("below the critical threshold it escalates",
      len(critical) == 1 and critical[0]["severity"] == 2, critical)

DISK[0] = 50 * 1024 * MB
check("and back above the warning threshold it clears",
      ("disk_space_low", "data") in sweep().cleared)


# ------------------------------------- 4. through the engine, end to end

service.alert_engine = real_engine
for store in CAPPED:
    service.settings[store.cap_key] = 512
set_size(trace, 0.92)
service._sample_storage_alerts()
service.alert_engine._tick()


def open_rows(key, entity):
    rule = service.alerts_db.rule_by_key(key)
    return [row for row in service.alerts_db.alerts(state="open",
                                                    rule_id=rule["id"])
            if row["entity_id"] == entity]


check("the sampler's occurrence becomes an open alert on the Alerts page",
      len(open_rows("db_near_cap", "trace")) == 1,
      [dict(row) for row in open_rows("db_near_cap", "trace")])
check("...deduped per store, so each database has one row of its own",
      open_rows("db_near_cap", "trace")[0]["dedup_key"]
      == "db_near_cap:system:trace" if open_rows("db_near_cap", "trace") else False)

set_size(trace, 0.10)
service._sample_storage_alerts()
service.alert_engine._tick()
check("and the sweep that finds it back in room resolves that row",
      not open_rows("db_near_cap", "trace"),
      [dict(row) for row in open_rows("db_near_cap", "trace")])

service_mod.disk_space = real_disk_space
service.shutdown()
shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

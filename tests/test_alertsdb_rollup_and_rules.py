"""Two additions to alertsdb.py, specified by the alert-rollup work in
alertengine.py (ping-shims) but implemented here since alertsdb.py is not
that agent's file:

  1. alerts.rolled_up_into — a foreign key to the alert a rollup absorbed
     this one into, distinct from resolved_by (which stays '' for a
     rollup absorption exactly as it always has, so an operator-resolve
     check does not mistake one for a hand resolve). resolve_by_dedup's
     new optional parameter sets it; every existing call site that omits
     the parameter is unaffected. alerts_rolled_up_into(parent_id) reads
     it back, structured, for a parent's own detail view.
  2. alert_count_for_rule + a hardened remove_rule — deleting a custom
     rule with real alert history would cascade-delete that history
     (rules.id is alerts.rule_id's ON DELETE CASCADE parent); the count
     is what a caller uses to refuse with "N alerts reference this rule"
     instead of disabling, and the WHERE clause is defense in depth for
     any caller that does not check first.
"""
import time

from _paths import tmpdir

from netpath.alertsdb import AlertsDatabase

TMPDIR = tmpdir("alertsdb_rollup_rules_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> AlertsDatabase:
    return AlertsDatabase(f"{TMPDIR}/{name}.db")


def add_custom_rule(db: AlertsDatabase, key: str) -> int:
    """A bare custom threshold rule, inserted directly -- add_rule's own
    validation is a web-API-layer concern this suite has no reason to
    exercise."""
    with db._lock:
        cur = db._conn.execute(
            "INSERT INTO rules(key, name, kind, source_kind, severity,"
            " enabled, is_builtin, device_filter, notify, threshold,"
            " clear_threshold, for_polls, created_ts)"
            " VALUES (?,?,'threshold','cpu_pct',4,1,0,'',1,90.0,80.0,2,?)",
            (key, key, time.time()))
        db._conn.commit()
        return cur.lastrowid


def open_alert(db: AlertsDatabase, rule_id: int, dedup_key: str) -> int:
    now = time.time()
    with db._lock:
        cur = db._conn.execute(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, state, count, opened_ts,"
            " last_ts, extra_json) VALUES (?,?,'device','1','dev1',4,'m',"
            "'open',1,?,?,'{}')", (rule_id, dedup_key, now, now))
        db._conn.commit()
        return cur.lastrowid


# ---------------------------------------------------------- rolled_up_into

db = new_db("rollup")
rule_id = add_custom_rule(db, "cpu_high_custom_1")
parent_id = open_alert(db, rule_id, "parent:device:1")
child_id = open_alert(db, rule_id, "child:device:1")
untouched_id = open_alert(db, rule_id, "untouched:device:1")

resolved = db.resolve_by_dedup("child:device:1", by="", rolled_up_into=parent_id)
check("resolve_by_dedup with rolled_up_into stores the parent's id",
      resolved is not None and resolved["rolled_up_into"] == parent_id, resolved)
check("...and resolved_by is still '' -- a rollup absorption must never "
      "read as an operator resolve",
      resolved["resolved_by"] == "", resolved)

not_rolled_up = db.resolve_by_dedup("untouched:device:1")
check("every existing call site (no rolled_up_into argument) is unaffected: "
      "the column stays NULL",
      not_rolled_up is not None and not_rolled_up["rolled_up_into"] is None,
      not_rolled_up)

absorbed = db.alerts_rolled_up_into(parent_id)
check("alerts_rolled_up_into(parent) returns exactly the one alert rolled "
      "up into it, not the other resolved alert",
      len(absorbed) == 1 and absorbed[0]["id"] == child_id, absorbed)

still_open = db.alerts(state="unresolved")
check("the parent itself is untouched -- still open, nothing resolved it",
      any(a["id"] == parent_id for a in still_open), still_open)
db.close()

# ------------------------------------------------ alert_count_for_rule / remove_rule

db = new_db("rules")
rule_with_history = add_custom_rule(db, "cpu_high_custom_2")
open_alert(db, rule_with_history, "a:device:1")
resolved_id = open_alert(db, rule_with_history, "b:device:1")
db.resolve_by_dedup("b:device:1")   # one open, one resolved -- both must count

check("alert_count_for_rule counts every state, not just open ones",
      db.alert_count_for_rule(rule_with_history) == 2,
      db.alert_count_for_rule(rule_with_history))

check("remove_rule refuses a custom rule with real alert history",
      db.remove_rule(rule_with_history) is False, None)
check("...and the rule itself is untouched, not silently gone",
      db.rule_by_key("cpu_high_custom_2") is not None, None)
check("...and its alerts are untouched too (no cascade slipped through)",
      db.alert_count_for_rule(rule_with_history) == 2,
      db.alert_count_for_rule(rule_with_history))

rule_without_history = add_custom_rule(db, "cpu_high_custom_3")
check("a custom rule with zero alerts ever raised has count 0",
      db.alert_count_for_rule(rule_without_history) == 0, None)
check("remove_rule deletes it",
      db.remove_rule(rule_without_history) is True, None)
check("...and it is actually gone",
      db.rule_by_key("cpu_high_custom_3") is None, None)

builtin = db.rule_by_key("cpu_high")
check("a built-in rule is still refused regardless of alert history "
      "(unchanged behaviour, sanity check)",
      builtin is not None and db.remove_rule(builtin["id"]) is False, None)
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

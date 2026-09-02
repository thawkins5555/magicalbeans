"""An alert resolved by an operator does not re-open for the same breach
run: only a clear observation followed by a fresh breach re-opens it. Drives
AlertEngine directly against a threshold rule (cpu_high) and a NetPath
threshold rule (netpath_unreachable), and separately proves the engine's own
auto-resolve (resolved_by == '') is not mistaken for a hand resolve."""
import os
import sqlite3
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.nodesdb import NodesDatabase
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.ipamdb import IpamDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_operator_resolve_")


def build():
    nodes = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(TMPDIR, "alerts.db"))
    # No new-device hold and no rollup: both would give a breach a reason to
    # be dropped or absorbed that has nothing to do with what this suite is
    # testing, and email stays off (the default) so nothing here needs SMTP.
    alerts.save_settings({"email_enabled": False, "rollup_enabled": False,
                          "new_device_grace_s": 0})
    netpath_db = NetpathDatabase(os.path.join(TMPDIR, "netpath.db"))
    engine = AlertEngine(alerts, nodes_db=nodes,
                         snmp_db=SnmpTrapDatabase(os.path.join(TMPDIR, "traps.db")),
                         syslog_db=SyslogDatabase(os.path.join(TMPDIR, "syslog.db")),
                         ipam_db=IpamDatabase(os.path.join(TMPDIR, "ipam.db")),
                         netpath_db=netpath_db)
    return nodes, alerts, netpath_db, engine


def add_device(nodes, ip, name):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


def sample(nodes, device_id, key, value, ts):
    """One CPU metric sample at an explicit time, the way a poll would
    write it. cpu_high ships threshold=90, clear_threshold=80, for_polls=2."""
    nodes.record_metric_sample(device_id, key, "CPU", "%", "gauge", ts, value)


def seed_trace(netpath_db, target_id, ts, loss_pct, reached=0, rtt_ms=None):
    """A trace row written directly, the way record_trace would store one,
    without needing a real tracer.TraceResult. netpath_unreachable ships
    threshold=100, clear_threshold=100, for_polls=3 against trace_loss_pct."""
    conn = sqlite3.connect(netpath_db.path)
    conn.execute(
        "INSERT INTO traces(target_id, started_ts, duration_s, status, reached,"
        " hop_count, rtt_ms, loss_pct, path_sig, error, icmp_code, icmp_from)"
        " VALUES (?,?,?,'ok',?,1,?,?,NULL,NULL,NULL,NULL)",
        (target_id, ts, 0.05, 1 if reached else 0, rtt_ms, loss_pct))
    conn.commit()
    conn.close()


def open_rows(alerts, rule_id, entity_id):
    return [a for a in alerts.alerts(state="open", rule_id=rule_id)
            if a["entity_id"] == str(entity_id)]


# ============================================================ 1. threshold rule
nodes, alerts, netpath_db, engine = build()
did = add_device(nodes, "10.5.5.5", "core-sw-a")
engine._tick()          # seeds every drain cursor; nothing to evaluate yet
cpu_rule = alerts.rule_by_key("cpu_high")

base = time.time()
sample(nodes, did, "cpu_pct", 99.0, base)
engine._tick()
assert open_rows(alerts, cpu_rule["id"], did) == [], \
    "one sample must not satisfy for_polls=2"
sample(nodes, did, "cpu_pct", 99.0, base + 65)
engine._tick()
opened = open_rows(alerts, cpu_rule["id"], did)
assert len(opened) == 1, opened
alert_id = opened[0]["id"]
print(f"cpu_high opened on the second breaching poll (alert #{alert_id}) OK")

assert alerts.resolve_many([alert_id], "operator") == 1
resolved_row = alerts.alert(alert_id)
assert resolved_row["state"] == "resolved" and resolved_row["resolved_by"] == "operator"
print("operator resolved it by hand OK")

# The metric never moved: three more ticks re-derive from the same still-
# breaching sample, exactly what used to reopen it as a new row within
# seconds. It must not, and nothing must be notified about it either.
notified_before = engine.counters["opened"]
for _ in range(3):
    engine._tick()
assert open_rows(alerts, cpu_rule["id"], did) == [], \
    "an operator-resolved alert must not re-open while the same breach holds"
assert alerts.alert(alert_id)["state"] == "resolved", \
    "the resolved row itself must be left alone"
assert len(alerts.alerts(rule_id=cpu_rule["id"])) == 1, \
    "no second row for the same dedup_key"
assert engine.counters["opened"] == notified_before, \
    "no alert was (re-)opened, so nothing was notified either"
print("three ticks of the same still-breaching metric: no new row, "
     "no notification OK")

# A clear observation, then a fresh breach run: this one is allowed to open.
sample(nodes, did, "cpu_pct", 10.0, base + 130)
engine._tick()
sample(nodes, did, "cpu_pct", 99.0, base + 195)
engine._tick()
assert open_rows(alerts, cpu_rule["id"], did) == [], \
    "one poll of the new run must not satisfy for_polls=2 either"
sample(nodes, did, "cpu_pct", 99.0, base + 260)
engine._tick()
reopened = open_rows(alerts, cpu_rule["id"], did)
assert len(reopened) == 1, reopened
assert reopened[0]["id"] != alert_id, \
    "the new run must open as a new row, not resurrect the resolved one"
print(f"a clear sample plus a fresh for_polls-long breach re-opens as a new "
     f"row (#{reopened[0]['id']}) OK")
nodes.close(); alerts.close(); netpath_db.close()


# =========================================================== 2. netpath rule
nodes2, alerts2, netpath2, engine2 = build()
target_id = netpath2.add_target("10.6.6.6", label="branch-gw", interval_s=300,
                                warn_rtt_ms=150.0)
engine2._tick()
np_rule = alerts2.rule_by_key("netpath_unreachable")

base2 = time.time()
for i in range(3):                    # for_polls=3, unreachable every trace
    seed_trace(netpath2, target_id, base2 + i * 310, 100.0, reached=False)
    engine2._tick()
opened2 = open_rows(alerts2, np_rule["id"], target_id)
assert len(opened2) == 1, opened2
np_alert_id = opened2[0]["id"]
print(f"netpath_unreachable opened on the third unreachable trace "
     f"(alert #{np_alert_id}) OK")

assert alerts2.resolve_many([np_alert_id], "operator") == 1
for _ in range(3):
    engine2._tick()                  # no new trace: same run, must stay shut
assert open_rows(alerts2, np_rule["id"], target_id) == [], \
    "an operator-resolved NetPath alert must not re-open for the same run"
assert alerts2.alert(np_alert_id)["state"] == "resolved"
print("three ticks with no new trace: NetPath alert stays resolved OK")

seed_trace(netpath2, target_id, base2 + 1000, 0.0, reached=True, rtt_ms=8.0)
engine2._tick()                      # clears the streak
for i in range(3):
    seed_trace(netpath2, target_id, base2 + 1300 + i * 310, 100.0, reached=False)
    engine2._tick()
reopened2 = open_rows(alerts2, np_rule["id"], target_id)
assert len(reopened2) == 1, reopened2
assert reopened2[0]["id"] != np_alert_id
print(f"a reached trace plus a fresh 3-trace outage re-opens NetPath as a "
     f"new row (#{reopened2[0]['id']}) OK")
nodes2.close(); alerts2.close(); netpath2.close()


# ============================================ 3. engine auto-resolve is not an operator
nodes3, alerts3, netpath3, engine3 = build()
did3 = add_device(nodes3, "10.7.7.7", "edge-sw-b")
engine3._tick()
cpu_rule3 = alerts3.rule_by_key("cpu_high")

base3 = time.time()
sample(nodes3, did3, "cpu_pct", 99.0, base3)
engine3._tick()
sample(nodes3, did3, "cpu_pct", 99.0, base3 + 65)
engine3._tick()
first = open_rows(alerts3, cpu_rule3["id"], did3)
assert len(first) == 1, first
first_id = first[0]["id"]

# The device itself recovers (a genuine clear), which the engine resolves on
# its own — CLEARS/threshold auto-resolves always write '' to resolved_by,
# never a username (see AlertsDatabase.operator_resolved_since).
sample(nodes3, did3, "cpu_pct", 10.0, base3 + 130)
engine3._tick()
auto_resolved = alerts3.alert(first_id)
assert auto_resolved["state"] == "resolved", auto_resolved
assert auto_resolved["resolved_by"] == "", \
    f"engine auto-resolve must write '', got {auto_resolved['resolved_by']!r}"
print("the engine's own clear auto-resolves with resolved_by == '' OK")

# It must be free to re-open immediately — an auto-resolve is not a hand
# resolve, so there is no "same run" to protect it from.
sample(nodes3, did3, "cpu_pct", 99.0, base3 + 195)
engine3._tick()
sample(nodes3, did3, "cpu_pct", 99.0, base3 + 260)
engine3._tick()
second = open_rows(alerts3, cpu_rule3["id"], did3)
assert len(second) == 1, second
assert second[0]["id"] != first_id
print("a breach after an engine auto-resolve re-opens without being "
     "mistaken for an operator's resolve OK")
nodes3.close(); alerts3.close(); netpath3.close()

print("\nALL OPERATOR-RESOLVE ASSERTIONS PASSED")

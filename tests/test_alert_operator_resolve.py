"""An alert resolved by an operator does not re-open for the same breach
run: only a clear observation followed by a fresh breach re-opens it. Drives
AlertEngine directly against a threshold rule (cpu_high) and a NetPath
threshold rule (netpath_unreachable), and separately proves the engine's own
auto-resolve (resolved_by == '') is not mistaken for a hand resolve.

Sections 4-7 are the rollup half of the same promise: resolving a "Device not
responding" alert by hand also covers the alerts that outage was hiding, for
as long as the device is still down. Before 4.37.0, resolving three device
outages released their suppressed children within one tick — three fresh
"Packet loss to device high" rows, and three more emails, five seconds after
"Resolved 3 of 3".
"""
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


def build(rollup=False, suffix=""):
    nodes = NodesDatabase(os.path.join(TMPDIR, f"nodes{suffix}.db"))
    alerts = AlertsDatabase(os.path.join(TMPDIR, f"alerts{suffix}.db"))
    # No new-device hold, and no rollup unless a section asks for it: both
    # would give a breach a reason to be dropped or absorbed that has nothing
    # to do with what sections 1-3 test, and email stays off (the default) so
    # nothing here needs SMTP. Sections 4-7 turn rollup on, because rollup is
    # exactly what they are about.
    alerts.save_settings({"email_enabled": False, "rollup_enabled": bool(rollup),
                          "new_device_grace_s": 0})
    netpath_db = NetpathDatabase(os.path.join(TMPDIR, f"netpath{suffix}.db"))
    engine = AlertEngine(alerts, nodes_db=nodes,
                         snmp_db=SnmpTrapDatabase(os.path.join(TMPDIR, f"traps{suffix}.db")),
                         syslog_db=SyslogDatabase(os.path.join(TMPDIR, f"syslog{suffix}.db")),
                         ipam_db=IpamDatabase(os.path.join(TMPDIR, f"ipam{suffix}.db")),
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

# ================================== 4. a hand-resolved rollup parent, three devices
# The operator's report: tick three "Device not responding" rows, press
# Resolve, get "Resolved 3 of 3" — and five seconds later three brand-new
# "Packet loss to device high" alerts for the same three devices, with three
# more emails. The children were only ever suppressed because the parent was
# OPEN (open_by_dedup counts open and acked, never resolved), so resolving
# the parent released every one of them while the devices were still down.
def down_poll(nodes, device_id, ts, loss=100.0):
    """One poll of a device that is not answering.

    Two writes, both of which nodepoll makes on every such poll: the device
    row's live state — `status` is the fact the parent-resolve rule
    re-checks — and the ping_loss_pct metric sample, which is 100 for a
    device that answered nothing."""
    nodes.record_poll(device_id, ping_ok=False, ping_rtt_ms=None, snmp_ok=None,
                      snmp_error=None, identity=None, uptime_ticks=None,
                      status="down", reachable=False)
    nodes.record_metric_sample(device_id, "ping_loss_pct", "Packet loss", "%",
                               "gauge", ts, loss)


def up_poll(nodes, device_id, ts, loss):
    """The same device answering again, still lossy: status leaves "down",
    which is what ends the parent-resolve suppression."""
    nodes.record_poll(device_id, ping_ok=True, ping_rtt_ms=5.0, snmp_ok=None,
                      snmp_error=None, identity=None, uptime_ticks=None,
                      status="up", reachable=True)
    nodes.record_metric_sample(device_id, "ping_loss_pct", "Packet loss", "%",
                               "gauge", ts, loss)


nodes4, alerts4, netpath4, engine4 = build(rollup=True, suffix="_rollup")
devices4 = [add_device(nodes4, f"10.8.8.{n}", f"dist-sw-{n}") for n in (1, 2, 3)]
engine4._tick()                      # seeds the drain cursors
down_rule = alerts4.rule_by_key("device_down")
loss_rule = alerts4.rule_by_key("packet_loss_high")

base4 = time.time()
for device_id in devices4:
    down_poll(nodes4, device_id, base4)
    nodes4.record_device_event(device_id, "down", "not responding")
engine4._tick()
parents = [open_rows(alerts4, down_rule["id"], d) for d in devices4]
assert all(len(rows) == 1 for rows in parents), parents
parent_ids = [rows[0]["id"] for rows in parents]
assert all(open_rows(alerts4, loss_rule["id"], d) == [] for d in devices4), \
    "packet loss needs 60 s of sample time (for_seconds), not one sample"

# Second sample 70 s later: the loss has now been sustained past for_seconds,
# so every one of the three breaches — and every one is suppressed behind its
# device's open outage.
rolled_before = engine4.counters["rolled_up"]
for device_id in devices4:
    down_poll(nodes4, device_id, base4 + 70)
engine4._tick()
assert engine4.counters["rolled_up"] - rolled_before >= 3, \
    f"three breaching children must be rolled up, got " \
    f"{engine4.counters['rolled_up'] - rolled_before}"
assert all(open_rows(alerts4, loss_rule["id"], d) == [] for d in devices4), \
    "a suppressed child must not be an open row"
print("three devices down, three packet-loss breaches rolled up under them OK")

# The bulk Resolve an operator actually presses: resolve_many with the
# session username is exactly what POST /api/alerts/bulk-resolve calls.
assert alerts4.resolve_many(parent_ids, "operator") == 3
assert all(alerts4.alert(i)["state"] == "resolved" for i in parent_ids)
print("bulk resolve: 3 of 3 device outages resolved by hand OK")

# The very next tick. _operator_resolves is refreshed at the top of _tick,
# before anything is applied, so the resolve that landed a moment ago is
# already in hand on this first tick after the click.
opened_before = engine4.counters["opened"]
for device_id in devices4:
    down_poll(nodes4, device_id, base4 + 140)
engine4._tick()
still_open = {d: open_rows(alerts4, loss_rule["id"], d) for d in devices4}
assert all(rows == [] for rows in still_open.values()), \
    ("resolving the outage must cover the alerts it was hiding while the "
     "devices are still down; these re-opened: "
     + str({d: [r["message"] for r in rows]
            for d, rows in still_open.items() if rows}))
assert engine4.counters["opened"] == opened_before, \
    "nothing opened, so nothing was notified about either"
assert all(alerts4.alert(i)["state"] == "resolved" for i in parent_ids), \
    "and the parents stay resolved"
print("the tick after the bulk resolve: no packet-loss rows, no notification OK")

# Three more ticks, still down, still nothing.
for _ in range(3):
    engine4._tick()
assert all(open_rows(alerts4, loss_rule["id"], d) == [] for d in devices4)
print("three further ticks while the devices stay down: still nothing OK")

# The suppression is not permanent: the moment a device answers again the
# parent's condition no longer holds, and a child that is STILL breaching on
# its own account opens normally. (30 % loss on a device that is up is a real
# packet-loss alert, not an artefact of an outage.)
for device_id in devices4:
    up_poll(nodes4, device_id, base4 + 210, 30.0)
engine4._tick()
released = {d: open_rows(alerts4, loss_rule["id"], d) for d in devices4}
assert all(len(rows) == 1 for rows in released.values()), \
    f"a device that answers again must release its children: {released}"
print("the devices answer again while still lossy: packet loss opens on its "
      "own account OK")
nodes4.close(); alerts4.close(); netpath4.close()


# ============================ 5. acknowledge is the contrast, and always was
# Acknowledging the parents suppresses the children through the ordinary
# rollup path (open_by_dedup counts 'acked' as open), which is why Resolve
# and Acknowledge behaved differently and the difference looked arbitrary.
nodes5, alerts5, netpath5, engine5 = build(rollup=True, suffix="_ack")
devices5 = [add_device(nodes5, f"10.9.9.{n}", f"acc-sw-{n}") for n in (1, 2, 3)]
engine5._tick()
down_rule5 = alerts5.rule_by_key("device_down")
loss_rule5 = alerts5.rule_by_key("packet_loss_high")

base5 = time.time()
for device_id in devices5:
    down_poll(nodes5, device_id, base5)
    nodes5.record_device_event(device_id, "down", "not responding")
engine5._tick()
parent_ids5 = [open_rows(alerts5, down_rule5["id"], d)[0]["id"] for d in devices5]
for device_id in devices5:
    down_poll(nodes5, device_id, base5 + 70)
engine5._tick()

assert alerts5.acknowledge_many(parent_ids5, "operator") == 3
for device_id in devices5:
    down_poll(nodes5, device_id, base5 + 140)
engine5._tick()
assert all(open_rows(alerts5, loss_rule5["id"], d) == [] for d in devices5), \
    "an acknowledged outage keeps hiding its children (it always did)"
assert all(alerts5.alert(i)["state"] == "acked" for i in parent_ids5)
print("acknowledging the three outages keeps the children suppressed too OK")
nodes5.close(); alerts5.close(); netpath5.close()


# ================================= 6. the same rule for a NetPath parent
# A NetPath destination has no "status" column to re-check, so the parent's
# condition is asked of the child's own breach run instead: a run that began
# at or before the hand resolve is the run the operator resolved.
nodes6, alerts6, netpath6, engine6 = build(rollup=True, suffix="_np")
target6 = netpath6.add_target("10.10.10.10", label="dc-gw", interval_s=300,
                              warn_rtt_ms=150.0)
engine6._tick()
unreach_rule = alerts6.rule_by_key("netpath_unreachable")
unstable_rule = alerts6.rule_by_key("netpath_path_unstable")

# Trace timestamps run up to now rather than out from it: a trace's own
# started_ts is what the child's breach run is measured in, and comparing a
# run that began in the future against a resolve that happened now would
# prove nothing about a real destination, whose traces are always in the past.
base6 = time.time() - 5 * 310
for i in range(5):        # five traces: enough for the windowed unstable rule
    seed_trace(netpath6, target6, base6 + i * 310, 100.0, reached=False)
    engine6._tick()
assert len(open_rows(alerts6, unreach_rule["id"], target6)) == 1
np_parent_id = open_rows(alerts6, unreach_rule["id"], target6)[0]["id"]
assert open_rows(alerts6, unstable_rule["id"], target6) == [], \
    "the unstable child is suppressed behind the unreachable parent"

assert alerts6.resolve_many([np_parent_id], "operator") == 1
for _ in range(3):
    engine6._tick()
assert open_rows(alerts6, unstable_rule["id"], target6) == [], \
    "resolving the unreachable parent must cover the child it was hiding"
print("a hand-resolved NetPath parent covers its suppressed children OK")

# A trace that gets through resets the child's run; a fresh outage after it
# is a new run and opens normally.
seed_trace(netpath6, target6, base6 + 2000, 0.0, reached=True, rtt_ms=9.0)
engine6._tick()
for i in range(5):
    seed_trace(netpath6, target6, base6 + 2300 + i * 310, 100.0, reached=False)
    engine6._tick()
assert len(open_rows(alerts6, unreach_rule["id"], target6)) == 1, \
    "a fresh outage re-opens the parent itself"
print("a reached trace plus a fresh outage re-opens the NetPath parent OK")
nodes6.close(); alerts6.close(); netpath6.close()


# ================================ 7. DHCP scope thresholds get the same gate
# The one threshold evaluator 4.34.0's operator gate never reached. A scope
# at 90 % is still at 90 % on the next DHCP poll, so a hand-resolved "DHCP
# scope running out of leases" came back at the next tick, over and over,
# until somebody actually widened the scope.
nodes7, alerts7, netpath7, engine7 = build(suffix="_dhcp")
ipam7 = engine7.ipam_db
server7 = ipam7.add_dhcp_server("10.20.0.5", "dhcp-a")
SCOPE = {"scope_id": "10.20.1.0", "name": "Floor 1", "start_ip": "10.20.1.10",
         "end_ip": "10.20.1.29", "mask": "255.255.255.0", "state": "active"}


def dhcp_poll(used):
    """One DHCP poll: the scope snapshot (which is what moves polled_ts, the
    only thing that advances a DHCP streak) and `used` leases in it. The
    range holds 20 addresses, so 18 is 90 % — over the shipped 85 % — and 14
    is 70 %, under the 75 % clear."""
    time.sleep(0.01)
    ipam7.replace_dhcp_scopes(server7, [SCOPE])
    ipam7.replace_dhcp_leases(server7, [
        {"scope_id": SCOPE["scope_id"], "ip": f"10.20.1.{10 + i}",
         "mac": f"00:11:22:33:44:{i:02x}", "address_state": "active"}
        for i in range(used)])


scope_rule = alerts7.rule_by_key("dhcp_scope_exhaustion")
scope_entity = f"{server7}:{SCOPE['scope_id']}"
engine7._tick()

dhcp_poll(18)
engine7._tick()
scope_alerts = open_rows(alerts7, scope_rule["id"], scope_entity)
assert len(scope_alerts) == 1, scope_alerts
scope_alert_id = scope_alerts[0]["id"]
print(f"dhcp_scope_exhaustion opened at 90 % (alert #{scope_alert_id}) OK")

assert alerts7.resolve_many([scope_alert_id], "operator") == 1
for _ in range(3):
    dhcp_poll(18)             # the scope is still full on every later poll
    engine7._tick()
assert open_rows(alerts7, scope_rule["id"], scope_entity) == [], \
    "a hand-resolved scope alert must stay resolved while the scope stays full"
assert len(alerts7.alerts(rule_id=scope_rule["id"])) == 1, \
    "no second row for the same scope"
print("three more polls of the same full scope: no new row OK")

dhcp_poll(14)                 # 70 %: under the clear threshold, run over
engine7._tick()
dhcp_poll(18)                 # and full again: a new run, which may open
engine7._tick()
reopened7 = open_rows(alerts7, scope_rule["id"], scope_entity)
assert len(reopened7) == 1 and reopened7[0]["id"] != scope_alert_id, reopened7
print(f"a poll under the clear threshold plus a fresh breach re-opens as a "
      f"new row (#{reopened7[0]['id']}) OK")
nodes7.close(); alerts7.close(); netpath7.close()


print("\nALL OPERATOR-RESOLVE ASSERTIONS PASSED")

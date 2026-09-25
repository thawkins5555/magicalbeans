"""dhcp_poll_failed: a DHCP server that stops answering polls raises after
two consecutive failures, stays one alert while the streak continues, and
resolves the moment a poll succeeds again. Same build() harness as
test_alert_engine.py's DHCP section, kept in its own file per the plan.
"""
import os

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("dhcp_poll_alert_")
_SEQ = [0]


def build(**settings):
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = {"email_enabled": False, "rollup_enabled": False,
              "new_device_grace_s": 0, "notify_rollup_delay_s": 0}
    values.update(settings)
    alerts.save_settings(values)
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    netpath_db = NetpathDatabase(os.path.join(folder, "netpath.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam, netpath_db=netpath_db)
    return nodes, alerts, snmp, syslog, ipam, engine


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


PASSED = []


def ok(line):
    PASSED.append(line)
    print("  " + line + " OK")


# ==================================================================== A1
print("A1 — dhcp_poll_failed: two failures raise, a third increments, a "
      "success resolves, a fresh streak reopens")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    server = ipam.add_dhcp_server("10.40.0.5", "dhcp-a1")

    ipam.set_dhcp_poll_result(server, False, "connection refused")
    engine._tick()
    assert open_rows(alerts, "dhcp_poll_failed", server) == []
    ok("one failed poll raises nothing (for_polls=2)")

    ipam.set_dhcp_poll_result(server, False, "connection refused")
    engine._tick()
    opened = open_rows(alerts, "dhcp_poll_failed", server)
    assert len(opened) == 1, opened
    assert opened[0]["severity"] == 4, opened[0]["severity"]
    assert "connection refused" in opened[0]["message"], opened[0]["message"]
    assert opened[0]["count"] == 1, opened[0]["count"]
    alert_id = opened[0]["id"]
    ok("a second consecutive failure raises severity 4 with the error text")

    ipam.set_dhcp_poll_result(server, False, "connection refused")
    engine._tick()
    still = open_rows(alerts, "dhcp_poll_failed", server)
    assert len(still) == 1 and still[0]["id"] == alert_id, still
    assert still[0]["count"] == 2, still[0]["count"]
    ok("a third failure increments the same open alert, not a second one")

    ipam.set_dhcp_poll_result(server, True)
    engine._tick()
    assert open_rows(alerts, "dhcp_poll_failed", server) == []
    ok("the next successful poll resolves it")

    ipam.set_dhcp_poll_result(server, False, "timed out")
    engine._tick()
    ipam.set_dhcp_poll_result(server, False, "timed out")
    engine._tick()
    reopened = open_rows(alerts, "dhcp_poll_failed", server)
    assert len(reopened) == 1 and reopened[0]["id"] != alert_id, reopened
    ok("a fresh streak of failures reopens as a new alert")
finally:
    nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================================== A2
print("\nA2 — repeated ticks between polls do not re-raise or re-increment")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    server2 = ipam.add_dhcp_server("10.40.0.6", "dhcp-a2")
    ipam.set_dhcp_poll_result(server2, False, "no route to host")
    ipam.set_dhcp_poll_result(server2, False, "no route to host")
    engine._tick()
    opened = open_rows(alerts, "dhcp_poll_failed", server2)
    assert len(opened) == 1, opened
    for _ in range(5):
        engine._tick()   # poll_failures unchanged between real polls
    still = open_rows(alerts, "dhcp_poll_failed", server2)
    assert len(still) == 1 and still[0]["count"] == 1, still
    ok("count stays 1 across several ticks with no new poll")
finally:
    nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================================== A3
print("\nA3 — a second dhcp_event rule at a different for_polls does not "
      "double-raise or steal the built-in's count (P2 cross-rule matching)")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    alerts.add_rule("custom_dhcp_poll_5", "Custom slow DHCP poll rule",
                    "dhcp_event", "poll_failed", for_polls=5)
    server3 = ipam.add_dhcp_server("10.40.0.7", "dhcp-a3")

    ipam.set_dhcp_poll_result(server3, False, "connection refused")
    engine._tick()
    ipam.set_dhcp_poll_result(server3, False, "connection refused")
    engine._tick()

    builtin = open_rows(alerts, "dhcp_poll_failed", server3)
    assert len(builtin) == 1 and builtin[0]["count"] == 1, builtin
    ok("the built-in rule raises once at its own for_polls=2, count stays 1")

    assert open_rows(alerts, "custom_dhcp_poll_5", server3) == []
    ok("the custom rule at for_polls=5 stays closed after two failures")
finally:
    nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


print(f"\nALL {len(PASSED)} DHCP-POLL-ALERT ASSERTIONS PASSED")

"""Per-port threshold alerting, the comparison direction, and the email
severity floor (5.1.0).

Each numbered section proves one rule of the contract against a real
AlertEngine tick on fresh temporary databases, in the test_alert_engine.py
idiom. Metric keys are recorded by hand -- `record_metric_sample(did,
"sfp_rx_dbm.7", ...)` -- so nothing here depends on the poller having been
taught to write them.
"""
import http.client
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.alertrules import (ROLLED_UP_BY, ROLLUP_ENTITY_KINDS, Occurrence,
                                interface_label)
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_per_port_")
_SEQ = [0]

PASSED = []
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    (PASSED if ok else FAILS).append(name)


def build(**settings):
    """(nodes, alerts, engine) plus the three stores the engine also needs.

    Email off, rollup off, no new-device hold and no roll-up notification
    delay, for the same reason test_alert_engine.build() turns them off: each
    would give an occurrence a reason to be dropped that has nothing to do
    with what is under test. A section that wants one says so.
    """
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


def add_device(nodes, ip, name):
    return nodes.add_device(ip, name=name, group_id=nodes.ensure_default_group())


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


def go_down(nodes, device_id):
    conn = sqlite3.connect(nodes.path)
    conn.execute("UPDATE devices SET status = 'down' WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    nodes.record_device_event(device_id, "down", "stopped responding")


def close_all(*stores):
    for store in stores:
        store.close()


PORTS = [
    {"if_index": 7, "descr": "GigabitEthernet1/0/7", "alias": "uplink to core",
     "admin_status": "up", "oper_status": "up"},
    {"if_index": 8, "descr": "GigabitEthernet1/0/8", "alias": "",
     "admin_status": "up", "oper_status": "up"},
]


# ==================================================================== P1
print("P1 - a per-port breach opens one interface alert that names the port")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.0.1", "core-sw")
    nodes.replace_interfaces(did, PORTS)
    base = time.time()
    for i in range(2):          # if_in_util_high ships for_polls = 2
        nodes.record_metric_sample(did, "if_in_util_pct.7", "Gi1/0/7 in_util_pct",
                                   "%", "gauge", base + i, 97.0)
        # The device-level worst-port key is written too, exactly as the
        # poller writes it. It must NOT produce a second, device-scoped alert.
        nodes.record_metric_sample(did, "if_in_util_pct", "busiest port",
                                   "%", "gauge", base + i, 97.0)
        engine._tick()
    rows = open_rows(alerts, "if_in_util_high")
    check("one alert, not two: the device-level worst-port key is skipped "
          "once the device reports per-port children",
          len(rows) == 1, [dict(r) for r in rows])
    row = rows[0]
    check("it is an interface entity keyed <device_id>:<if_index>",
          row["entity_kind"] == "interface" and row["entity_id"] == f"{did}:7",
          dict(row))
    check("the dedup key keeps its rule:entity_kind:entity_id shape",
          row["dedup_key"] == f"if_in_util_high:interface:{did}:7",
          row["dedup_key"])
    check("the label carries the device, the ifDescr and the ifAlias",
          row["entity_label"] == "core-sw / GigabitEthernet1/0/7 (uplink to core)",
          row["entity_label"])
    check("the message names the unit", "97.0 %" in row["message"], row["message"])
    extra = json.loads(row["extra_json"])
    check("extra_json carries if_index, interface_name and interface_alias",
          (extra.get("if_index"), extra.get("interface_name"),
           extra.get("interface_alias"))
          == ("7", "GigabitEthernet1/0/7", "uplink to core"), extra)
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P2
print("\nP2 - a rule whose metric has no children is still device-scoped")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.1.1", "router")
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(did, "cpu_pct", "CPU", "%", "gauge",
                                   base + i, 97.0)
        engine._tick()
    rows = open_rows(alerts, "cpu_high")
    check("cpu_high still opens one device alert",
          len(rows) == 1 and rows[0]["entity_kind"] == "device"
          and rows[0]["entity_id"] == str(did), [dict(r) for r in rows])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P3
print("\nP3 - a 'below' rule breaches downward and clears upward")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.2.1", "access-sw")
    nodes.replace_interfaces(did, PORTS)
    rule = alerts.rule_by_key("sfp_rx_power_low")
    check("sfp_rx_power_low ships comparison 'below' at -22/-20",
          (rule["comparison"], rule["threshold"], rule["clear_threshold"])
          == ("below", -22.0, -20.0), dict(rule))
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(did, "sfp_rx_dbm.7", "Gi1/0/7 Rx power",
                                   "dBm", "gauge", base + i, -25.0)
        engine._tick()
    rows = open_rows(alerts, "sfp_rx_power_low")
    check("-25 dBm opens the alert on the port",
          len(rows) == 1 and rows[0]["entity_id"] == f"{did}:7",
          [dict(r) for r in rows])

    # -21 is inside the hysteresis band: past the threshold, not past the
    # clear. Nothing may change.
    nodes.record_metric_sample(did, "sfp_rx_dbm.7", "Gi1/0/7 Rx power", "dBm",
                               "gauge", base + 5, -21.0)
    engine._tick()
    check("-21 dBm holds it open (inside the hysteresis band)",
          len(open_rows(alerts, "sfp_rx_power_low")) == 1)

    nodes.record_metric_sample(did, "sfp_rx_dbm.7", "Gi1/0/7 Rx power", "dBm",
                               "gauge", base + 6, -19.0)
    engine._tick()
    check("-19 dBm clears it", open_rows(alerts, "sfp_rx_power_low") == [])

    # -40 dBm is the floor a transceiver clamps to with no fiber in it or
    # its port powered down: further past the threshold than the -25 that
    # opened the alert above, and the one reading that must open nothing.
    for i in range(4):
        nodes.record_metric_sample(did, "sfp_rx_dbm.8", "Gi1/0/8 Rx power",
                                   "dBm", "gauge", base + 10 + i, -40.0)
        engine._tick()
    check("-40 dBm on another port opens nothing at all -- a dark optic is "
          "not a dim one, however many polls it stays that way",
          open_rows(alerts, "sfp_rx_power_low") == [],
          [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P4
print("\nP4 - a clear threshold on the wrong side of a 'below' rule is refused")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    from netpath import alertsdb as alertsdb_mod
    low = alerts.rule_by_key("sfp_rx_power_low")
    raised = None
    try:
        # A clear BELOW the threshold on a 'below' rule: the value would have
        # to fall further to clear than it did to breach, so the alert could
        # never close.
        alerts.set_device_threshold(1, "sfp_rx_power_low", threshold=-22.0,
                                    clear_threshold=-30.0)
    except ValueError as exc:
        raised = exc
    check("a device override with clear below threshold on a 'below' rule "
          "raises", raised is not None and "must be above" in str(raised),
          str(raised))
    # And the right way round is accepted.
    alerts.set_device_threshold(1, "sfp_rx_power_low", threshold=-24.0,
                                clear_threshold=-21.0)
    rows = alerts.device_thresholds(1)
    check("...and the correct direction is accepted",
          len(rows) == 1 and rows[0]["threshold"] == -24.0, [dict(r) for r in rows])
    # An 'above' rule is unchanged: clear must still sit below.
    raised = None
    try:
        alerts.set_device_threshold(1, "cpu_high", threshold=70.0,
                                    clear_threshold=80.0)
    except ValueError as exc:
        raised = exc
    check("an 'above' rule still refuses a clear above its threshold",
          raised is not None and "must be below" in str(raised), str(raised))
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P5
print("\nP5 - two bad ports are two alerts, and one clears on its own")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.3.1", "sw-two-ports")
    nodes.replace_interfaces(did, PORTS)
    base = time.time()
    for i in range(2):
        for if_index in (7, 8):
            nodes.record_metric_sample(
                did, f"if_in_util_pct.{if_index}", f"port {if_index}", "%",
                "gauge", base + i, 97.0)
        engine._tick()
    rows = open_rows(alerts, "if_in_util_high")
    check("both ports alert separately",
          sorted(r["entity_id"] for r in rows) == [f"{did}:7", f"{did}:8"],
          [dict(r) for r in rows])
    check("the port with no ifAlias is named by its ifDescr alone",
          [r["entity_label"] for r in rows if r["entity_id"] == f"{did}:8"]
          == ["sw-two-ports / GigabitEthernet1/0/8"], [dict(r) for r in rows])

    nodes.record_metric_sample(did, "if_in_util_pct.8", "port 8", "%", "gauge",
                               base + 5, 10.0)
    engine._tick()
    rows = open_rows(alerts, "if_in_util_high")
    check("port 8 recovering leaves port 7's alert open",
          [r["entity_id"] for r in rows] == [f"{did}:7"], [dict(r) for r in rows])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P6
print("\nP6 - a per-device override applies to that device's ports")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.4.1", "hot-closet-sw")
    nodes.replace_interfaces(did, PORTS)
    # An override is keyed by device, never by port: an operator tuning a
    # switch's numbers must not have to repeat themselves 48 times.
    alerts.set_device_threshold(did, "if_in_util_high", threshold=50.0,
                                clear_threshold=40.0)
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(did, "if_in_util_pct.7", "port 7", "%",
                                   "gauge", base + i, 60.0)
        engine._tick()
    rows = open_rows(alerts, "if_in_util_high")
    check("60 % breaches the device's own 50 % override on the port",
          len(rows) == 1 and rows[0]["entity_id"] == f"{did}:7",
          [dict(r) for r in rows])
    check("the alert reports the effective threshold it was judged against",
          json.loads(rows[0]["extra_json"]).get("threshold") == "50.0",
          rows[0]["extra_json"])

    alerts.set_device_threshold(did, "if_in_util_high", threshold=None,
                                clear_threshold=None, enabled=False)
    engine._tick()
    check("disabling the rule for the device resolves its port alerts too",
          open_rows(alerts, "if_in_util_high") == [])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P7
print("\nP7 - the streak key is a string entity id at both ends")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    engine._tick()
    did = add_device(nodes, "10.20.5.1", "streak-sw")
    nodes.replace_interfaces(did, PORTS)
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(did, "if_in_util_pct.7", "port 7", "%",
                                   "gauge", base + i, 97.0)
        engine._tick()
    keys = [key for key in engine._breach_streaks if key[1] == f"{did}:7"]
    check("_evaluate_thresholds keys the streak on the entity id as a string",
          keys == [(alerts.rule_by_key("if_in_util_high")["id"], f"{did}:7")],
          list(engine._breach_streaks))
    rule = alerts.rule_by_key("if_in_util_high")
    occurrence = Occurrence(kind="threshold", source_kind="if_in_util_pct",
                            entity_kind="interface", entity_id=f"{did}:7",
                            entity_label="x", ts=time.time(), message="")
    check("_child_first_breach_ts finds that same streak from the occurrence",
          engine._child_first_breach_ts(rule, occurrence) == base,
          engine._child_first_breach_ts(rule, occurrence))
    device_occurrence = Occurrence(
        kind="threshold", source_kind="cpu_pct", entity_kind="device",
        entity_id=str(did), entity_label="x", ts=time.time(), message="")
    check("and a device occurrence still resolves through the same lookup",
          engine._child_first_breach_ts(alerts.rule_by_key("cpu_high"),
                                        device_occurrence) is None)
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P8
print("\nP8 - rollup absorbs port thresholds, and never interface_down")

check("ROLLUP_ENTITY_KINDS admits interface entities",
      "interface" in ROLLUP_ENTITY_KINDS, sorted(ROLLUP_ENTITY_KINDS))
check("but ROLLED_UP_BY is the gate: interface_down has no parent",
      "interface_down" not in ROLLED_UP_BY and
      "interface_flapping" not in ROLLED_UP_BY and
      "interface_up" not in ROLLED_UP_BY, sorted(ROLLED_UP_BY))

nodes, alerts, snmp, syslog, ipam, engine = build(rollup_enabled=True)
try:
    engine._tick()
    did = add_device(nodes, "10.20.6.1", "doomed-sw")
    nodes.replace_interfaces(did, PORTS)
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(did, "if_in_util_pct.7", "port 7", "%",
                                   "gauge", base + i, 97.0)
        engine._tick()
    nodes.record_interface_event(
        nodes.interfaces(did)[0]["id"], "link_down", "Gi1/0/7: up -> down")
    engine._tick()
    check("the port's utilization alert and its link-down alert are both open",
          len(open_rows(alerts, "if_in_util_high")) == 1
          and len(open_rows(alerts, "interface_down")) == 1)

    go_down(nodes, did)
    engine._tick()
    check("the outage absorbs the port's threshold alert",
          open_rows(alerts, "if_in_util_high") == [],
          [dict(r) for r in open_rows(alerts, "if_in_util_high")])
    check("...and leaves interface_down alone",
          len(open_rows(alerts, "interface_down")) == 1,
          [dict(r) for r in open_rows(alerts, "interface_down")])
    parent = open_rows(alerts, "device_down")
    absorbed = alerts.alerts_rolled_up_into(parent[0]["id"])
    check("the absorbed port alert points at the outage it went into",
          [r["entity_id"] for r in absorbed] == [f"{did}:7"],
          [dict(r) for r in absorbed])

    # And a fresh breach while the device is still down stays suppressed,
    # rather than re-opening on the next tick.
    for i in range(2):
        nodes.record_metric_sample(did, "if_in_util_pct.7", "port 7", "%",
                                   "gauge", base + 20 + i, 97.0)
        engine._tick()
    check("a port still breaching under an open outage does not re-open",
          open_rows(alerts, "if_in_util_high") == [],
          [dict(r) for r in open_rows(alerts, "if_in_util_high")])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# ==================================================================== P9
print("\nP9 - the upgrade migration resolves the old device-scoped if_ alerts")

_SEQ[0] += 1
folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
os.makedirs(folder, exist_ok=True)
alerts_path = os.path.join(folder, "alerts.db")
store = AlertsDatabase(alerts_path)
rule = store.rule_by_key("if_in_util_high")
cpu_rule = store.rule_by_key("cpu_high")
now = time.time()
with store._lock:
    for rule_id, key, kind, entity in (
            (rule["id"], "if_in_util_high", "device", "9"),
            (cpu_rule["id"], "cpu_high", "device", "9")):
        store._conn.execute(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, detail, state, opened_ts, last_ts)"
            " VALUES (?,?,?,?,?,4,?,'','open',?,?)",
            (rule_id, f"{key}:{kind}:{entity}", kind, entity, "sw9",
             "planted", now, now))
    # The migration has to run for the first time on the REOPEN, so undo the
    # bookkeeping row this fresh database wrote for itself.
    store._conn.execute("DELETE FROM schema_migrations"
                        " WHERE name = 'per_port_threshold_alerts_1'")
    store._conn.commit()
store.close()

store = AlertsDatabase(alerts_path)
open_if = open_rows(store, "if_in_util_high")
check("the planted device-scoped if_in_util_high alert is resolved on upgrade",
      open_if == [], [dict(r) for r in open_if])
resolved = [r for r in store.alerts(state="resolved")
            if r["dedup_key"].startswith("if_in_util_high:")]
check("...with a note saying why, and resolved_by '' so it is not a hand "
      "resolve",
      len(resolved) == 1 and "per port" in (resolved[0]["rollup_note"] or "")
      and resolved[0]["resolved_by"] == "",
      [dict(r) for r in resolved])
check("a device-scoped alert of a rule that did NOT move is untouched",
      len(open_rows(store, "cpu_high")) == 1,
      [dict(r) for r in open_rows(store, "cpu_high")])
store.close()


# =================================================================== P10
print("\nP10 - metrics_for_families uses the index and reads only real ports")

nodes, alerts, snmp, syslog, ipam, engine = build()
try:
    did = add_device(nodes, "10.20.7.1", "family-sw")
    stamp = time.time()
    for key, value in (("if_in_error_rate", 4.0),
                       ("if_in_error_rate.7", 5.0),
                       ("if_in_error_rate_x", 6.0),      # a sibling, not a port
                       ("if_in_error_rate.7.2", 7.0),    # not an ifIndex
                       ("sfp_rx_dbm.7", -25.0)):
        nodes.record_metric_sample(did, key, key, "", "gauge", stamp, value)
    rows = nodes.metrics_for_families(["if_in_error_rate", "sfp_rx_dbm"])
    got = sorted(row["key"] for row in rows)
    check("the family read returns the parent, its port children and nothing "
          "with a different name",
          got == ["if_in_error_rate", "if_in_error_rate.7",
                  "if_in_error_rate.7.2", "sfp_rx_dbm.7"], got)
    check("the sibling key if_in_error_rate_x is excluded by the range bounds",
          "if_in_error_rate_x" not in got, got)
    check("unit comes back with the row (the message names it)",
          all("unit" in row.keys() for row in rows))

    plan = nodes.series_db._conn.execute(
        "EXPLAIN QUERY PLAN SELECT device_id, key, label, unit, last_value,"
        " last_ts FROM metrics WHERE (key = ? OR (key >= ? AND key < ?))"
        " OR (key = ? OR (key >= ? AND key < ?))",
        ["if_in_error_rate", "if_in_error_rate.", "if_in_error_rate/",
         "sfp_rx_dbm", "sfp_rx_dbm.", "sfp_rx_dbm/"]).fetchall()
    text = " | ".join(str(row["detail"]) for row in plan)
    check("the query plan never scans the metrics table",
          "SCAN metrics" not in text, text)
    check("...it searches ix_metrics_key instead",
          "ix_metrics_key" in text, text)

    # The dotted tail is not a port, so the evaluator must not treat it as
    # one: only .7 becomes a target.
    for i in range(2):
        nodes.record_metric_sample(did, "if_in_error_rate.7.2", "x", "", "gauge",
                                   stamp + i, 900.0)
        nodes.record_metric_sample(did, "if_in_error_rate.7", "port 7", "err/s",
                                   "gauge", stamp + i, 900.0)
        engine._tick()
    rows = open_rows(alerts, "if_in_errors_high")
    check("only the key whose whole tail is an ifIndex alerts as a port",
          [r["entity_id"] for r in rows] == [f"{did}:7"], [dict(r) for r in rows])
finally:
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# =================================================================== P11
print("\nP11 - interface_label")

check("descr plus a distinct alias reads as 'descr (alias)'",
      interface_label({"descr": "Gi1/0/7", "alias": "uplink", "if_index": 7})
      == "Gi1/0/7 (uplink)")
check("an alias that repeats the descr is not appended twice",
      interface_label({"descr": "Gi1/0/7", "alias": "gi1/0/7", "if_index": 7})
      == "Gi1/0/7")
check("no descr falls back to the alias alone",
      interface_label({"descr": "", "alias": "uplink", "if_index": 7}) == "uplink")
check("neither falls back to if<n>",
      interface_label({"descr": "", "alias": "", "if_index": 7}) == "if7")
check("a missing row falls back to the index it was given",
      interface_label(None, 12) == "if12")


# =================================================================== P12
print("\nP12 - the email severity floor")


class Mail:
    """alertmail.send, counted."""

    def __init__(self):
        self.subjects = []

    def __call__(self, settings, password, to_addrs, subject, body, is_html):
        self.subjects.append(subject)


class Receiver:
    """A local webhook receiver, so the floor can be shown NOT to gate it."""

    def __init__(self):
        self.received = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                outer.received.append(json.loads(self.rfile.read(length)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/hook"
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


MAIL_SETTINGS = {"email_enabled": True, "smtp_host": "relay.invalid",
                 "smtp_to_default": ["noc@example.invalid"]}

check("the shipped floor is 7, which mails everything",
      AlertsDatabase.DEFAULTS["notify_min_severity"] == 7)

receiver = Receiver()
real_send = alertmail.send
nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_min_severity=4, webhook_enabled=True, webhook_url=receiver.url,
    webhook_timeout_s=3.0, **MAIL_SETTINGS)
sent = Mail()
alertmail.send = sent
try:
    engine._webhook.start()
    engine._tick()
    did = add_device(nodes, "10.20.8.1", "recovering-sw")
    # device_up ships severity 5, one worse than a floor of 4.
    nodes.record_device_event(did, "up", "responding again")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert engine._webhook.wait_idle(10.0)
    rows = open_rows(alerts, "device_up")
    check("the severity-5 alert still opens", len(rows) == 1, [dict(r) for r in rows])
    check("...but nothing was mailed about it", sent.subjects == [], sent.subjects)
    check("...and it is stamped, so the roll-up sweep never re-asks",
          rows[0]["last_notified_ts"] is not None, dict(rows[0]))
    check("the webhook still posted: the floor is about a mailbox",
          len(receiver.received) == 1, receiver.received)

    # 95 C breaches both chassis rules, which read the same metric on purpose
    # (severity 2 and severity 4). Both sit at or under a floor of 4, so both
    # mail -- which also settles that the floor is inclusive at its own value.
    other = add_device(nodes, "10.20.8.2", "hot-sw")
    base = time.time()
    for i in range(2):
        nodes.record_metric_sample(other, "temp_chassis_c", "Chassis", "°C",
                                   "gauge", base + i, 95.0)
        engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("severity 2 and severity 4 both mail under a floor of 4",
          sorted(s.split("]")[0] for s in sent.subjects)
          == ["[CRITICAL", "[WARNING"], sent.subjects)
finally:
    alertmail.send = real_send
    engine.stop()
    receiver.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)

# Floor 7 (the default) mails the same severity-5 alert.
nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_min_severity=7, **MAIL_SETTINGS)
sent = Mail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.9.1", "recovering-sw")
    nodes.record_device_event(did, "up", "responding again")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("at the default floor of 7 the same alert is mailed",
          len(sent.subjects) == 1, sent.subjects)
finally:
    alertmail.send = real_send
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)

# A floored alert whose first notice is HELD must be closed out by the sweep
# rather than asked about on every tick for ever.
nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_min_severity=4, notify_rollup_delay_s=1, **MAIL_SETTINGS)
sent = Mail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.10.1", "held-sw")
    nodes.record_device_event(did, "up", "responding again")
    engine._tick()
    row = open_rows(alerts, "device_up")[0]
    check("with the hold on, the floored alert's notice starts pending",
          row["last_notified_ts"] is None, dict(row))
    # 2x slack on the 1 s hold.
    time.sleep(2.0)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    row = open_rows(alerts, "device_up")[0]
    check("the roll-up sweep stamps it instead of mailing it",
          row["last_notified_ts"] is not None and sent.subjects == [],
          (dict(row), sent.subjects))
    check("...and it is no longer due",
          alerts.alerts_due_first_notify(time.time()) == [],
          [dict(r) for r in alerts.alerts_due_first_notify(time.time())])
finally:
    alertmail.send = real_send
    engine.stop()
    close_all(nodes, alerts, snmp, syslog, ipam)


# =================================================================== P13
print("\nP13 - the floor round-trips through the settings store")

_SEQ[0] += 1
folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
os.makedirs(folder, exist_ok=True)
store = AlertsDatabase(os.path.join(folder, "alerts.db"))
check("a fresh store reports the shipped floor",
      store.settings()["notify_min_severity"] == 7)
store.save_settings({"notify_min_severity": 3})
store.close()
store = AlertsDatabase(os.path.join(folder, "alerts.db"))
check("...and a saved one survives a reopen as an int",
      store.settings()["notify_min_severity"] == 3,
      store.settings()["notify_min_severity"])
store.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
print(f"{len(PASSED)} PER-PORT ASSERTIONS PASSED")
raise SystemExit(1 if FAILS else 0)

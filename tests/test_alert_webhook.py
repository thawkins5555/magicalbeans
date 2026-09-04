"""The outbound webhook channel: delivered at the same points email is
(open, clear, renotify — through the same _notify _webhook_notify hooks
into — and the roll-up digest), its own hourly budget, a failure recorded
against the alert, and a redirect refused outright.

A real local http.server.HTTPServer stands in for the receiver — Slack,
PagerDuty, whatever — rather than a monkeypatch of alertmail.send_webhook,
so what is under test is the real urllib request this application makes on
the wire, headers included.
"""
import http.client
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine, DIGEST_THRESHOLD
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_webhook_")
_SEQ = [0]

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


WEBHOOK_SETTINGS = {"email_enabled": False, "rollup_enabled": False,
                    "new_device_grace_s": 0, "notify_rollup_delay_s": 0,
                    "webhook_enabled": True, "webhook_headers": ["X-Test: yes"],
                    "webhook_timeout_s": 3.0}


def build(webhook_url, **settings):
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = dict(WEBHOOK_SETTINGS)
    values["webhook_url"] = webhook_url
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
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


def go_down(nodes, device_id, detail="stopped responding"):
    import sqlite3
    conn = sqlite3.connect(nodes.path)
    conn.execute("UPDATE devices SET status = 'down' WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    nodes.record_device_event(device_id, "down", detail)


def come_up(nodes, device_id, detail="responding again"):
    import sqlite3
    conn = sqlite3.connect(nodes.path)
    conn.execute("UPDATE devices SET status = 'up' WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    nodes.record_device_event(device_id, "up", detail)


class Receiver:
    """A local HTTP server recording every POST it gets, headers and JSON
    body both. `status` controls what it answers with; `redirect_to` makes
    it answer 302 instead, to exercise the client's own redirect refusal."""

    def __init__(self, status=200, redirect_to=None):
        self.status = status
        self.redirect_to = redirect_to
        self.received = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = raw
                outer.received.append({
                    "body": body,
                    "headers": {k: v for k, v in self.headers.items()},
                })
                if outer.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/hook"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


# ======================================================================= C1
print("C1 — delivered on a fresh alert, with the documented JSON shape")

receiver = Receiver()
nodes, alerts, snmp, syslog, ipam, engine = build(receiver.url)
try:
    engine._webhook.start()
    dev = add_device(nodes, "10.8.0.1", "sw1")
    engine._tick()                   # seed cursors
    go_down(nodes, dev)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    check("exactly one delivery for one fresh alert",
          len(receiver.received) == 1, len(receiver.received))
    if receiver.received:
        payload = receiver.received[0]["body"]
        check("payload carries the documented fields",
              {"alert_id", "rule", "rule_name", "kind", "entity_label",
               "message", "detail", "ts", "state", "subject"} <= payload.keys(),
              payload)
        check("rule is the rule's key, not its display name",
              payload["rule"] == "device_down", payload["rule"])
        check("state is 'open' for a fresh alert",
              payload["state"] == "open", payload["state"])
        check("subject is the rendered {{device_name}} is not responding line",
              "sw1" in payload["subject"] and "not responding" in payload["subject"],
              payload["subject"])
        check("the configured extra header made it onto the request",
              receiver.received[0]["headers"].get("X-Test") == "yes",
              receiver.received[0]["headers"])
    alert_id = alerts.alerts(state="unresolved")[0]["id"]
    rows = alerts.notifications_for(alert_id)
    check("a notification row records the delivery, kind webhook_alert",
          any(r["kind"] == "webhook_alert" and r["ok"] for r in rows),
          [(r["kind"], r["ok"]) for r in rows])
finally:
    engine._webhook.stop()
    receiver.stop()


# ======================================================================= C2
print("\nC2 — delivered again on clear, state='clear'")

receiver = Receiver()
nodes, alerts, snmp, syslog, ipam, engine = build(receiver.url)
try:
    engine._webhook.start()
    dev = add_device(nodes, "10.8.0.2", "sw2")
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    come_up(nodes, dev)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    # Recovering raises two things, exactly as email sees them: a "clear" for
    # the device_down alert this resolves, and its own fresh "device
    # recovered" alert (device_up is a rule in its own right, not rolled up
    # here — rollup_enabled is off in WEBHOOK_SETTINGS). Three deliveries,
    # not two.
    by_rule = {(r["body"]["rule"], r["body"]["state"]) for r in receiver.received}
    check("device_down: open then clear; device_up: its own open",
          by_rule == {("device_down", "open"), ("device_down", "clear"),
                     ("device_up", "open")},
          by_rule)
finally:
    engine._webhook.stop()
    receiver.stop()


# ======================================================================= C3
print("\nC3 — a mass outage goes out as one digest, mirroring the email one")

receiver = Receiver()
nodes, alerts, snmp, syslog, ipam, engine = build(
    receiver.url, notify_rollup_delay_s=1)
try:
    engine._webhook.start()
    devices = [add_device(nodes, f"10.8.1.{i}", f"sw{i}")
              for i in range(DIGEST_THRESHOLD + 2)]
    engine._tick()
    for device_id in devices:
        go_down(nodes, device_id)
    engine._tick()
    check("nothing sent yet — still inside the roll-up hold",
          not receiver.received, len(receiver.received))
    time.sleep(1.2)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    check("exactly one delivery for the whole mass outage",
          len(receiver.received) == 1, len(receiver.received))
    if receiver.received:
        payload = receiver.received[0]["body"]
        check("digest state is 'digest' with alert_id null",
              payload["state"] == "digest" and payload["alert_id"] is None, payload)
        check("the digest lists every alert it speaks for",
              len(payload.get("alerts", [])) == len(devices),
              payload.get("alerts"))
finally:
    engine._webhook.stop()
    receiver.stop()


# ======================================================================= C4
print("\nC4 — a failing receiver records why, and does not raise into the tick")

receiver = Receiver(status=500)
nodes, alerts, snmp, syslog, ipam, engine = build(receiver.url)
try:
    engine._webhook.start()
    dev = add_device(nodes, "10.8.2.1", "sw3")
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    alert_id = alerts.alerts(state="unresolved")[0]["id"]
    rows = alerts.notifications_for(alert_id)
    webhook_rows = [r for r in rows if r["kind"] == "webhook_alert"]
    check("one notification row, recorded as failed",
          len(webhook_rows) == 1 and not webhook_rows[0]["ok"], webhook_rows)
    check("...with the HTTP status in the error text",
          "500" in (webhook_rows[0]["error"] or ""), webhook_rows[0]["error"])
    check("the engine counted it as a webhook error",
          engine.counters["webhook_errors"] == 1, engine.counters)
finally:
    engine._webhook.stop()
    receiver.stop()


# ======================================================================= C5
print("\nC5 — webhook_max_per_hour is its own budget, separate from email's")

receiver = Receiver()
nodes, alerts, snmp, syslog, ipam, engine = build(
    receiver.url, webhook_max_per_hour=1)
try:
    engine._webhook.start()
    d1 = add_device(nodes, "10.8.3.1", "sw4")
    d2 = add_device(nodes, "10.8.3.2", "sw5")
    engine._tick()
    go_down(nodes, d1)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    go_down(nodes, d2)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    check("only the first alert's webhook actually went out",
          len(receiver.received) == 1, len(receiver.received))
    check("the engine's suppressed counter caught the second one",
          engine.counters["webhook_suppressed"] == 1, engine.counters)
    second_alert = [r for r in alerts.alerts(state="unresolved")
                    if r["entity_id"] == str(d2)][0]
    rows = alerts.notifications_for(second_alert["id"])
    check("...and it is recorded on the alert as a budget refusal",
          any("webhook limit" in (r["error"] or "") for r in rows),
          [(r["kind"], r["error"]) for r in rows])
finally:
    engine._webhook.stop()
    receiver.stop()


# ======================================================================= C6
print("\nC6 — a receiver that redirects is refused, not followed")

target = Receiver()                  # where a followed redirect would land
receiver = Receiver(redirect_to=target.url)
nodes, alerts, snmp, syslog, ipam, engine = build(receiver.url)
try:
    engine._webhook.start()
    dev = add_device(nodes, "10.8.4.1", "sw6")
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    assert engine._webhook.wait_idle(10.0)
    check("the redirecting receiver was hit once", len(receiver.received) == 1,
          len(receiver.received))
    check("the redirect target was never reached", not target.received,
          target.received)
    alert_id = alerts.alerts(state="unresolved")[0]["id"]
    rows = [r for r in alerts.notifications_for(alert_id) if r["kind"] == "webhook_alert"]
    check("the failure is recorded against the alert",
          len(rows) == 1 and not rows[0]["ok"], rows)
finally:
    engine._webhook.stop()
    receiver.stop()
    target.stop()


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

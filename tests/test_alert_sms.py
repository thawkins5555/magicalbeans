"""Twilio SMS on alerts: the one-line text builder, the real urllib request
send_sms makes (Basic auth, form fields, From vs Messaging Service, Twilio's
error JSON surfaced), SmsQueue's breaker, the settings validation and the
encrypted-token storage. Engine sections (per-rule notify_sms, floor, cap,
clear, digest, sms_failing) follow the sender half.
"""
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail, dpapi
from netpath.alertsdb import AlertsDatabase, validate_sms_settings
from netpath.alertengine import AlertEngine, DIGEST_THRESHOLD
from netpath.alertrules import SEVERITY_NAMES
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_sms_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------ 1. sms_text
text = alertmail.sms_text("[CRITICAL]", "Device not responding", "acc-sw-070",
                          "No reply to 5 polls\n in a row")
check("sms_text is one line: [TAG] rule - entity: message",
      text == "[CRITICAL] Device not responding - acc-sw-070: No reply to 5 polls in a row", text)
long = alertmail.sms_text("[X]", "r" * 100, "e" * 100, "m" * 100)
check("a long text is cut to one 160-character segment",
      len(long) == 160 and long.endswith("..."), (len(long), long[-3:]))
check("...using GSM-7 characters only, so the cut text stays one segment",
      all(ord(c) < 128 for c in long), long)
check("no tag and no entity still reads sensibly",
      alertmail.sms_text("", "Rule", "", "msg") == "Rule: msg",
      alertmail.sms_text("", "Rule", "", "msg"))
check("is_e164 accepts +15551234567 and refuses a bare or short number",
      alertmail.is_e164("+15551234567") and not alertmail.is_e164("5551234567")
      and not alertmail.is_e164("+1234567") and not alertmail.is_e164("+0155512"))

# ------------------------------------------------------- 2. Twilio stub
SEEN = []
REPLY = {"status": 201, "body": {"sid": "SM1", "status": "queued"}}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        SEEN.append({"path": self.path,
                     "auth": self.headers.get("Authorization", ""),
                     "ctype": self.headers.get("Content-Type", ""),
                     "form": {k: v[0] for k, v in parse_qs(raw).items()}})
        body = json.dumps(REPLY["body"]).encode("utf-8")
        self.send_response(REPLY["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if REPLY["status"] in (301, 302, 307):
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
alertmail.TWILIO_API_BASE = f"http://127.0.0.1:{server.server_port}"

SID = "AC" + "a" * 32
BASE = {"twilio_account_sid": SID, "twilio_from": "+15550001111",
        "twilio_messaging_service_sid": "", "sms_timeout_s": 3.0}

try:
    alertmail.send_sms(BASE, "tok", "+15551234567", "hello")
    check("send_sms posts to /2010-04-01/Accounts/<SID>/Messages.json",
          SEEN and SEEN[-1]["path"] == f"/2010-04-01/Accounts/{SID}/Messages.json",
          SEEN[-1:] )
    import base64
    want = "Basic " + base64.b64encode(f"{SID}:tok".encode()).decode()
    check("...with HTTP Basic auth of SID:token", SEEN[-1]["auth"] == want, SEEN[-1]["auth"])
    check("...form-encoded To/From/Body",
          SEEN[-1]["ctype"].startswith("application/x-www-form-urlencoded")
          and SEEN[-1]["form"] == {"To": "+15551234567", "From": "+15550001111",
                                   "Body": "hello"}, SEEN[-1])
    alertmail.send_sms({**BASE, "twilio_messaging_service_sid": "MG" + "b" * 32},
                       "tok", "+15551234567", "hi")
    check("a Messaging Service SID replaces From",
          SEEN[-1]["form"].get("MessagingServiceSid") == "MG" + "b" * 32
          and "From" not in SEEN[-1]["form"], SEEN[-1]["form"])

    for bad, name in (({**BASE, "twilio_account_sid": ""}, "no Account SID"),
                      ({**BASE, "twilio_account_sid": "../x"}, "a malformed Account SID"),
                      ({**BASE, "twilio_from": ""}, "no From and no Messaging Service")):
        try:
            alertmail.send_sms(bad, "tok", "+15551234567", "x")
            check(f"send_sms refuses {name}", False)
        except ValueError as exc:
            check(f"send_sms refuses {name}", "Twilio" in str(exc), str(exc))
    try:
        alertmail.send_sms(BASE, None, "+15551234567", "x")
        check("send_sms refuses a missing token", False)
    except ValueError as exc:
        check("send_sms refuses a missing token", "token" in str(exc), str(exc))
    try:
        alertmail.send_sms(BASE, "tok", "5551234567", "x")
        check("send_sms refuses a non-E.164 number before any request", False)
    except ValueError as exc:
        check("send_sms refuses a non-E.164 number before any request",
              "E.164" in str(exc), str(exc))

    SK_SID = "SK" + "a" * 32
    api_key_settings = {**BASE, "twilio_auth_mode": "api_key", "twilio_api_key_sid": SK_SID}
    alertmail.send_sms(api_key_settings, "secret", "+15551234567", "hi")
    check("api_key mode posts to the same Messages.json path",
          SEEN[-1]["path"] == f"/2010-04-01/Accounts/{SID}/Messages.json", SEEN[-1]["path"])
    want_key = "Basic " + base64.b64encode(f"{SK_SID}:secret".encode()).decode()
    check("...with HTTP Basic auth of ApiKeySID:secret", SEEN[-1]["auth"] == want_key,
          SEEN[-1]["auth"])
    try:
        alertmail.send_sms({**api_key_settings, "twilio_api_key_sid": "SKshort"}, "secret",
                           "+15551234567", "x")
        check("send_sms refuses a malformed API Key SID", False)
    except ValueError as exc:
        check("send_sms refuses a malformed API Key SID", "API Key SID" in str(exc), str(exc))
    try:
        alertmail.send_sms({**BASE, "twilio_auth_mode": "bogus"}, "tok", "+15551234567", "x")
        check("send_sms refuses an unknown auth mode", False)
    except ValueError as exc:
        check("send_sms refuses an unknown auth mode",
              str(exc) == "Twilio authentication method must be auth_token or api_key", str(exc))
    try:
        alertmail.send_sms(api_key_settings, None, "+15551234567", "x")
        check("send_sms refuses a missing API key secret", False)
    except ValueError as exc:
        check("send_sms refuses a missing API key secret",
              str(exc) == "No Twilio API key secret stored", str(exc))

    REPLY["status"] = 400
    REPLY["body"] = {"code": 21211, "message": "The 'To' number is not a valid phone number.",
                     "status": 400}
    try:
        alertmail.send_sms(BASE, "tok", "+15551234567", "x")
        check("a Twilio 4xx raises", False)
    except ValueError as exc:
        check("a Twilio 4xx raises with Twilio's own code and message",
              str(exc) == "Twilio error 21211: The 'To' number is not a valid phone number.",
              str(exc))
    REPLY["status"] = 302
    REPLY["body"] = {}
    try:
        alertmail.send_sms(BASE, "tok", "+15551234567", "x")
        check("a redirect is refused, never followed", False)
    except Exception as exc:
        check("a redirect is refused, never followed", "redirect" in str(exc).lower(), str(exc))
    REPLY["status"] = 201
    REPLY["body"] = {"sid": "SM2"}
finally:
    pass

# ------------------------------------------------------- 3. SmsQueue
real_send_sms = alertmail.send_sms
calls = []
results = []
breaker = []


def fake_send_sms(settings, token, to_number, text):
    calls.append((to_number, text, token))
    if text.startswith("fail") or to_number == "+15550009999":
        raise ValueError("boom")


alertmail.send_sms = fake_send_sms
try:
    q = alertmail.SmsQueue(on_result=lambda job, ok, err: results.append((job, ok, err)),
                           on_breaker=lambda is_open, err: breaker.append((is_open, err)),
                           failures_to_open=2, cooldown_s=0.3)
    job = alertmail.SmsJob(settings=dict(BASE), token="tok",
                           to_numbers=["+15551234567", "+15557654321"],
                           text="hello", alert_id=1, kind="sms_alert")
    q.submit(job)
    q.wait_idle(3)
    check("SmsQueue sends one text per number",
          [c[0] for c in calls] == ["+15551234567", "+15557654321"], calls)
    check("...reports ok and clears the token from the job",
          results and results[-1][1] is True and job.token is None, results[-1:])
    check("SmsJob exposes to_addrs/subject for the shared result writer",
          job.to_addrs == job.to_numbers and job.subject == "hello")
    calls.clear()
    q.submit(alertmail.SmsJob(settings=dict(BASE), token="tok",
                              to_numbers=["+15550009999", "+15557654321"],
                              text="hello", alert_id=9))
    q.wait_idle(3)
    check("a bad first number does not stop the second from being texted",
          [c[0] for c in calls] == ["+15550009999", "+15557654321"], calls)
    check("...the job is ok with the failed number named in the error",
          results[-1][1] is True and results[-1][2] == "+15550009999: boom", results[-1][1:])
    check("...and a per-number failure does not count toward the breaker",
          not breaker and q._failures == 0, (breaker, q._failures))
    for _ in range(2):
        q.submit(alertmail.SmsJob(settings=dict(BASE), token="tok",
                                  to_numbers=["+15551234567"], text="fail", alert_id=2))
    q.wait_idle(3)
    check("a failed number names itself in the error",
          results[-1][1] is False and results[-1][2].startswith("+15551234567: boom"),
          results[-1][2])
    check("two failures open the SMS breaker", breaker and breaker[-1][0] is True, breaker)
    n = len(calls)
    q.submit(alertmail.SmsJob(settings=dict(BASE), token="tok",
                              to_numbers=["+15551234567"], text="hello", alert_id=3))
    q.wait_idle(3)
    check("...while open, nothing is attempted and the SMS breaker text is recorded",
          len(calls) == n and results[-1][2] == alertmail.SMS_BREAKER_ERROR, results[-1][2])
    time.sleep(0.35)
    q.submit(alertmail.SmsJob(settings=dict(BASE), token="tok",
                              to_numbers=["+15551234567"], text="hello", alert_id=4))
    q.wait_idle(3)
    check("...after the cooldown a probe goes out and closes it",
          len(calls) == n + 1 and results[-1][1] is True and breaker[-1][0] is False,
          (len(calls) - n, results[-1][1:], breaker[-1:]))
    check("the email breaker text is untouched",
          alertmail.MailQueue.breaker_error == alertmail.BREAKER_ERROR)
    q.stop()
finally:
    alertmail.send_sms = real_send_sms

# --------------------------------------- 4. settings validation, storage
for bad, name in (({"sms_to_default": ["5551234567"]}, "a bare number"),
                  ({"sms_to_default": "+15551234567, 12"}, "a bad number in a comma string"),
                  ({"twilio_from": "0800"}, "a bad From number"),
                  ({"twilio_account_sid": "AC12"}, "a short Account SID"),
                  ({"twilio_messaging_service_sid": "MG" + "z" * 32}, "a non-hex Messaging SID")):
    try:
        validate_sms_settings(bad)
        check(f"validate_sms_settings refuses {name}", False)
    except ValueError as exc:
        check(f"validate_sms_settings refuses {name}", bool(str(exc)))
validate_sms_settings({"sms_to_default": ["+15551234567", "+442071234567"],
                       "twilio_from": "", "twilio_account_sid": "",
                       "twilio_messaging_service_sid": ""})
check("...and accepts good numbers with empty SIDs", True)

for bad, name in (({"twilio_auth_mode": "bogus"}, "an unknown auth mode"),
                  ({"twilio_api_key_sid": "SKshort"}, "a malformed API Key SID")):
    try:
        validate_sms_settings(bad)
        check(f"validate_sms_settings refuses {name}", False)
    except ValueError as exc:
        check(f"validate_sms_settings refuses {name}", bool(str(exc)))
validate_sms_settings({"twilio_auth_mode": "api_key", "twilio_api_key_sid": "SK" + "a" * 32})
check("...and accepts a good API Key SID", True)

db = AlertsDatabase(os.path.join(TMPDIR, "alerts.db"))
s = db.settings()
check("settings carry the SMS defaults: off, no numbers, 30/hour, floor 7",
      s["sms_enabled"] is False and s["sms_to_default"] == [] and s["sms_max_per_hour"] == 30
      and s["sms_min_severity"] == 7 and s["has_sms_credential"] is False, s)
try:
    db.save_settings({"sms_to_default": ["nope"]})
    check("save_settings refuses a bad SMS number", False)
except ValueError:
    check("save_settings refuses a bad SMS number", True)
db.save_settings({"sms_to_default": ["+15551234567"], "sms_enabled": True})
check("...and stores a good one", db.settings()["sms_to_default"] == ["+15551234567"])
db.set_sms_credential(b"blob", "AC" + "c" * 32)
check("the token blob is stored in its own table and flagged in settings",
      db.sms_token_enc() == b"blob" and db.settings()["has_sms_credential"] is True)
check("...bound to the Account SID it was saved for",
      db.sms_credential_sid() == "AC" + "c" * 32, db.sms_credential_sid())
db.clear_sms_credential()
check("...and cleared", db.sms_token_enc() is None and not db.settings()["has_sms_credential"]
      and db.sms_credential_sid() == "")

db.set_sms_credential(b"blob2", "AC" + "d" * 32, "api_key", "SK" + "e" * 32)
check("set_sms_credential stores auth_mode and api_key_sid, round-tripped via the binding",
      db.sms_credential_binding() == {"account_sid": "AC" + "d" * 32, "auth_mode": "api_key",
                                      "api_key_sid": "SK" + "e" * 32}, db.sms_credential_binding())
check("sms_credential_sid still reads the account_sid alone",
      db.sms_credential_sid() == "AC" + "d" * 32, db.sms_credential_sid())
db.clear_sms_credential()
check("clearing resets the binding to auth_token with empty SIDs",
      db.sms_credential_binding() == {"account_sid": "", "auth_mode": "auth_token",
                                      "api_key_sid": ""}, db.sms_credential_binding())

old_path = os.path.join(TMPDIR, "old_shape.db")
old_conn = sqlite3.connect(old_path)
old_conn.execute("CREATE TABLE sms_credential (id INTEGER PRIMARY KEY CHECK (id = 1),"
                 " token_enc BLOB, account_sid TEXT NOT NULL DEFAULT '')")
old_conn.execute("INSERT INTO sms_credential(id, token_enc, account_sid) VALUES (1, ?, ?)",
                 (b"oldblob", "AC" + "9" * 32))
old_conn.commit()
old_conn.close()
old_db = AlertsDatabase(old_path)
check("an old-shape sms_credential table migrates: auth_mode defaults to auth_token",
      old_db.sms_credential_binding() == {"account_sid": "AC" + "9" * 32,
                                          "auth_mode": "auth_token", "api_key_sid": ""},
      old_db.sms_credential_binding())
old_db.close()

rule = db.rule_by_key("device_down")
check("every rule carries notify_sms, off by default", rule["notify_sms"] == 0)
db.update_rule(rule["id"], notify_sms=True)
check("...and it is editable", db.rule_by_key("device_down")["notify_sms"] == 1)
check("the sms_failing system rule is seeded with the smtp_failing template",
      db.rule_by_key("sms_failing") is not None
      and db.rule_by_key("sms_failing")["template_id"]
      == db.rule_by_key("smtp_failing")["template_id"])
db.close()

# ------------------------------------------------------- 5. engine sections
_SEQ = [0]
SMS_SETTINGS = {"email_enabled": False, "rollup_enabled": False,
                "new_device_grace_s": 0, "notify_rollup_delay_s": 0,
                "sms_enabled": True, "twilio_account_sid": "AC" + "a" * 32,
                "twilio_from": "+15550001111",
                "twilio_messaging_service_sid": "",
                "sms_to_default": ["+15551234567"]}
DEVICE_DOWN_TAG = "[{}]".format(SEVERITY_NAMES[1].upper())


def build_engine(**settings):
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = dict(SMS_SETTINGS)
    values.update(settings)
    alerts.save_settings(values)
    alerts.set_sms_credential(dpapi.protect(b"tok"), values["twilio_account_sid"])
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    netpath_db = NetpathDatabase(os.path.join(folder, "netpath.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam, netpath_db=netpath_db)
    return nodes, alerts, engine


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


real_send_sms = alertmail.send_sms
sms_calls = []


def fake_send_sms(settings, token, to_number, text):
    sms_calls.append((to_number, text))


alertmail.send_sms = fake_send_sms
try:
    # --------------------------------------------------------------- E1
    print("\nE1 — notify_sms off sends nothing; on, one text per number")
    nodes, alerts, engine = build_engine()
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        dev = add_device(nodes, "10.9.0.1", "sw1")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("notify_sms off by default: no text sent", not sms_calls, sms_calls)

        alerts.update_rule(rule["id"], notify_sms=True)
        come_up(nodes, dev)
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("notify_sms on: one text to the one configured number",
              len(sms_calls) == 1 and sms_calls[0][0] == "+15551234567", sms_calls)
        check("...body opens with the severity tag and names the device",
              sms_calls[0][1].startswith(DEVICE_DOWN_TAG) and "sw1" in sms_calls[0][1],
              sms_calls[0][1])
        alert_id = alerts.alerts(state="unresolved")[0]["id"]
        rows = alerts.notifications_for(alert_id)
        check("a sms_alert notification row is recorded, ok",
              any(r["kind"] == "sms_alert" and r["ok"] for r in rows),
              [(r["kind"], r["ok"]) for r in rows])
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E2
    print("\nE2 — notify off, notify_sms on still texts")
    nodes, alerts, engine = build_engine()
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify=False, notify_sms=True)
        dev = add_device(nodes, "10.9.0.2", "sw2")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("email off for the rule, SMS still sent", len(sms_calls) == 1, sms_calls)
    finally:
        engine._sms.stop()

    # -------------------------------------------------------------- E2b
    print("\nE2b — an SMS-only rule never emails or webhooks, even with both on")
    real_send = alertmail.send
    real_webhook = alertmail.send_webhook
    mails, hooks = [], []
    alertmail.send = lambda *a, **kw: mails.append(a)
    alertmail.send_webhook = lambda *a, **kw: hooks.append(a)
    nodes, alerts, engine = build_engine(
        email_enabled=True, smtp_host="relay.example", smtp_to_default=["ops@example.com"],
        webhook_enabled=True, webhook_url="https://hooks.example.com/x",
        notify_on_clear=True)
    engine._sms.start()
    engine._mail.start()
    engine._webhook.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify=False, notify_sms=True)
        up_rule = alerts.rule_by_key("device_up")
        alerts.update_rule(up_rule["id"], notify=False, notify_sms=False)
        dev = add_device(nodes, "10.9.0.22", "sw22")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        come_up(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        engine._mail.wait_idle(5.0)
        engine._webhook.wait_idle(5.0)
        check("the SMS-only rule texted the open and the clear",
              len(sms_calls) == 2, sms_calls)
        check("...and sent no email and no webhook", not mails and not hooks,
              (len(mails), len(hooks)))
    finally:
        engine._sms.stop()
        engine._mail.stop()
        engine._webhook.stop()
        alertmail.send = real_send
        alertmail.send_webhook = real_webhook

    # -------------------------------------------------------------- E2c
    print("\nE2c — a token saved for another Account SID is never sent")
    nodes, alerts, engine = build_engine()
    alerts.set_sms_credential(dpapi.protect(b"tok"), "AC" + "f" * 32)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.23", "sw23")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("no text goes out with a token bound to a different SID",
              not sms_calls, sms_calls)
        check("...and the reason is logged once",
              engine._sms_sid_mismatch_logged is True)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E2d
    print("\nE2d — engine sends in api_key mode when settings match the stored binding")
    sk = "SK" + "b" * 32
    nodes, alerts, engine = build_engine(twilio_auth_mode="api_key", twilio_api_key_sid=sk)
    alerts.set_sms_credential(dpapi.protect(b"secret"), SMS_SETTINGS["twilio_account_sid"],
                              "api_key", sk)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.24", "sw24")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("api_key mode: one text sent when the binding matches",
              len(sms_calls) == 1, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E2e
    print("\nE2e — a mismatched API Key SID in settings sends nothing")
    nodes, alerts, engine = build_engine(twilio_auth_mode="api_key", twilio_api_key_sid=sk)
    alerts.set_sms_credential(dpapi.protect(b"secret"), SMS_SETTINGS["twilio_account_sid"],
                              "api_key", "SK" + "c" * 32)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.25", "sw25")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("a mismatched API Key SID sends nothing", not sms_calls, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E2f
    print("\nE2f — a key SID left in settings does not block an auth_token send")
    nodes, alerts, engine = build_engine(twilio_auth_mode="auth_token",
                                         twilio_api_key_sid="SK" + "f" * 32)
    alerts.set_sms_credential(dpapi.protect(b"tok"), SMS_SETTINGS["twilio_account_sid"],
                              "auth_token", "")
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.26", "sw26")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("auth_token mode ignores a stale API Key SID in settings",
              len(sms_calls) == 1, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E2g
    print("\nE2g — settings switched back to auth_token after an api_key "
          "credential was stored (upgrade-then-switch) sends nothing")
    nodes, alerts, engine = build_engine(twilio_auth_mode="auth_token")
    alerts.set_sms_credential(dpapi.protect(b"secret"), SMS_SETTINGS["twilio_account_sid"],
                              "api_key", sk)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.27", "sw27")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("a settings mode switched back to auth_token against a stored "
              "api_key credential sends nothing", not sms_calls, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E3
    print("\nE3 — sms_min_severity below the alert's severity: no text")
    nodes, alerts, engine = build_engine(sms_min_severity=0)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.3", "sw3")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("the floor suppresses a text for a less severe alert",
              not sms_calls, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E4
    print("\nE4 — sms_max_per_hour caps the second alert")
    nodes, alerts, engine = build_engine(sms_max_per_hour=1)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev1 = add_device(nodes, "10.9.0.4", "sw4")
        dev2 = add_device(nodes, "10.9.0.5", "sw5")
        engine._tick()
        sms_calls.clear()
        go_down(nodes, dev1)
        go_down(nodes, dev2)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("only the first alert's text goes out", len(sms_calls) == 1, sms_calls)
        alert2 = alerts.alerts(state="unresolved", rule_id=rule["id"])
        alert2 = [a for a in alert2 if a["entity_id"] == str(dev2)][0]
        rows = alerts.notifications_for(alert2["id"])
        check("...the second alert gets a capped sms_alert row",
              any(r["kind"] == "sms_alert" and not r["ok"]
                  and "over the 1/hour text limit" in (r["error"] or "")
                  for r in rows),
              [(r["kind"], r["ok"], r["error"]) for r in rows])
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E5
    print("\nE5 — device recovers: a [RECOVER] clear text")
    nodes, alerts, engine = build_engine()
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.6", "sw6")
        engine._tick()
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        sms_calls.clear()
        come_up(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        clears = [c for c in sms_calls if c[1].startswith(alertmail.RECOVER_TAG)]
        check("a sms_clear text starting with [RECOVER] goes out",
              len(clears) == 1, sms_calls)
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E6
    print("\nE6 — a mass outage goes out as one sms_digest")
    nodes, alerts, engine = build_engine(notify_rollup_delay_s=1)
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        devices = [add_device(nodes, f"10.9.1.{i}", f"dsw{i}")
                  for i in range(DIGEST_THRESHOLD + 2)]
        engine._tick()
        sms_calls.clear()
        for device_id in devices:
            go_down(nodes, device_id)
        engine._tick()
        check("nothing sent yet — still inside the roll-up hold", not sms_calls)
        time.sleep(1.2)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("exactly one text for the whole mass outage", len(sms_calls) == 1, sms_calls)
        for device_id in devices:
            alert = [a for a in alerts.alerts(state="unresolved", rule_id=rule["id"])
                    if a["entity_id"] == str(device_id)][0]
            rows = alerts.notifications_for(alert["id"])
            check(f"device {device_id} has its own sms_digest row",
                  any(r["kind"] == "sms_digest" for r in rows),
                  [r["kind"] for r in rows])
    finally:
        engine._sms.stop()

    # --------------------------------------------------------------- E7
    print("\nE7 — the SMS breaker opens sms_failing and clears on success")
    nodes, alerts, engine = build_engine()
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)

        def failing_send_sms(settings, token, to_number, text):
            raise ValueError("boom")

        alertmail.send_sms = failing_send_sms
        engine._tick()
        for i in range(engine._sms.failures_to_open):
            dev = add_device(nodes, f"10.9.2.{i}", f"fsw{i}")
            go_down(nodes, dev)
            engine._tick()
            engine._sms.wait_idle(10.0)
        engine._tick()
        rows = alerts.alerts(state="unresolved")
        check("sms_failing opened once the breaker tripped",
              any(r["entity_id"] == "sms" for r in rows),
              [(r["entity_id"], r["message"]) for r in rows])
        check("sms_errors counted", engine.counters["sms_errors"] > 0, engine.counters)
        engine._sms._record_success()
        engine._tick()
        rows = alerts.alerts(state="unresolved")
        check("...and clears once the channel recovers",
              not any(r["entity_id"] == "sms" for r in rows),
              [(r["entity_id"], r["message"]) for r in rows])
    finally:
        alertmail.send_sms = fake_send_sms
        engine._sms.stop()

    # --------------------------------------------------------------- E8
    print("\nE8 — sms_sent counted on success")
    nodes, alerts, engine = build_engine()
    engine._sms.start()
    try:
        rule = alerts.rule_by_key("device_down")
        alerts.update_rule(rule["id"], notify_sms=True)
        dev = add_device(nodes, "10.9.0.9", "sw9")
        engine._tick()
        before = engine.counters["sms_sent"]
        go_down(nodes, dev)
        engine._tick()
        engine._sms.wait_idle(10.0)
        check("sms_sent counter increments", engine.counters["sms_sent"] > before,
              engine.counters)
    finally:
        engine._sms.stop()
finally:
    alertmail.send_sms = real_send_sms

server.shutdown()
print()
print("FAILURES:", FAILS)
if FAILS:
    raise SystemExit(1)

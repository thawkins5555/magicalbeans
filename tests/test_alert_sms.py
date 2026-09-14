"""Twilio SMS on alerts: the one-line text builder, the real urllib request
send_sms makes (Basic auth, form fields, From vs Messaging Service, Twilio's
error JSON surfaced), SmsQueue's breaker, the settings validation and the
encrypted-token storage. Engine sections (per-rule notify_sms, floor, cap,
clear, digest, sms_failing) follow the sender half.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase, validate_sms_settings

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
      len(long) == 160 and long.endswith("…"), (len(long), long[-3:]))
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
    if text.startswith("fail"):
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
db.set_sms_credential(b"blob")
check("the token blob is stored in its own table and flagged in settings",
      db.sms_token_enc() == b"blob" and db.settings()["has_sms_credential"] is True)
db.clear_sms_credential()
check("...and cleared", db.sms_token_enc() is None and not db.settings()["has_sms_credential"])
rule = db.rule_by_key("device_down")
check("every rule carries notify_sms, off by default", rule["notify_sms"] == 0)
db.update_rule(rule["id"], notify_sms=True)
check("...and it is editable", db.rule_by_key("device_down")["notify_sms"] == 1)
check("the sms_failing system rule is seeded with the smtp_failing template",
      db.rule_by_key("sms_failing") is not None
      and db.rule_by_key("sms_failing")["template_id"]
      == db.rule_by_key("smtp_failing")["template_id"])
db.close()

server.shutdown()
print()
print("FAILURES:", FAILS)
if FAILS:
    raise SystemExit(1)

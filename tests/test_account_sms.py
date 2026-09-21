"""Per-user SMS opt-in: GET/POST/DELETE /api/account/sms, the verification
code lifecycle, the app.db user_sms store, and the engine side (merging
opted-in numbers into the send list, turning a number off on a Twilio STOP
reply). No module permission gates any of these routes — only a session.
"""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail
from netpath.appdb import sms_status
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("account_sms_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"), initial_admin_password="admin")
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path,
                 body=json.dumps(body).encode() if body is not None else None,
                 headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": username,
                                  "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


def backdate_code(username, seconds):
    """Push a user_sms row's code_sent_ts back by `seconds`, the same trick
    section 6 uses inline, so a later start/DELETE call lands outside the
    60 s resend guard instead of tripping it."""
    service.app_db._conn.execute(
        "UPDATE user_sms SET code_sent_ts = code_sent_ts - ?"
        " WHERE username = ? COLLATE NOCASE", (seconds, username))
    service.app_db._conn.commit()


SID = "AC" + "a" * 32
NUMBER = "+15559990000"

SENT = []
real_send_sms = alertmail.send_sms


def fake_send_sms(settings, token, to_number, text):
    SENT.append((to_number, text))


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # A plain account with no grants at all — the SMS routes need nothing
    # but a signed-in session.
    status, payload = call("POST", "/api/users",
                           {"username": "grunt", "password": "Corr3ct-Horse-Battery",
                            "grants": {}}, token=admin)
    assert status == 200, (status, payload)
    grunt = login("grunt", "Corr3ct-Horse-Battery")

    # ------------------------------------------------------ 1. before setup
    status, payload = call("GET", "/api/account/sms", token=grunt)
    check("GET status is off with no row", status == 200 and payload["status"] == "off"
          and payload["number"] == "", (status, payload))
    check("...and available is False before Alerts SMS is set up",
          payload["available"] is False, payload)

    status, payload = call("POST", "/api/account/sms/start", {"number": NUMBER}, token=grunt)
    check("start without consent is a 400",
          status == 400 and "terms" in payload.get("error", ""), (status, payload))

    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True}, token=grunt)
    check("consent without terms is a 400 naming the Terms",
          status == 400 and "Terms" in payload.get("error", ""), (status, payload))

    status, payload = call("POST", "/api/account/sms/start",
                           {"number": "5551234567", "consent": True, "terms": True}, token=grunt)
    check("start with a non-E.164 number is a 400",
          status == 400 and "E.164" in payload.get("error", ""), (status, payload))

    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("start before Alerts SMS is configured is a 400",
          status == 400 and "not set up" in payload.get("error", ""), (status, payload))

    # ------------------------------------------------------ 2. set up Alerts SMS
    service.apply_settings("alerts", {
        "sms_enabled": True, "twilio_account_sid": SID,
        "twilio_from": "+15550001111"})
    service.alerts_db.set_sms_credential(b"fake-encrypted-blob", account_sid=SID,
                                         auth_mode="auth_token")
    alertmail.send_sms = fake_send_sms

    status, payload = call("GET", "/api/account/sms", token=grunt)
    check("available is True once Alerts SMS is configured", payload["available"] is True, payload)

    # ------------------------------------------------------------- 3. start
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("start succeeds", status == 200 and payload["status"] == "pending", (status, payload))
    check("...one text was sent", len(SENT) == 1, SENT)
    to_number, text = SENT[-1]
    check("...to the number given", to_number == NUMBER, to_number)
    digits = "".join(c for c in text if c.isdigit())
    check("...the text carries a 6-digit code", len(digits) >= 6, text)
    check("...and names STOP/HELP", "STOP" in text and "HELP" in text, text)

    verify_rows = service.alerts_db._conn.execute(
        "SELECT subject FROM notifications WHERE kind = 'sms_verify'"
        " ORDER BY ts DESC LIMIT 1").fetchall()
    check("the verify notification masks the code",
          bool(verify_rows) and "******" in verify_rows[0]["subject"],
          verify_rows)
    check("...and does not contain the actual code",
          bool(verify_rows) and digits[:6] not in verify_rows[0]["subject"],
          (verify_rows, digits))

    # ---------------------------------------------------- 4. resend too soon
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("resending within the window is a 400",
          status == 400 and "Wait" in payload.get("error", ""), (status, payload))
    check("...no second text was sent", len(SENT) == 1, SENT)

    # ------------------------------------------------------- 5. wrong code
    status, payload = call("POST", "/api/account/sms/confirm", {"code": "000000"}, token=grunt)
    check("a wrong code is a 400 with tries left",
          status == 400 and "tries left" in payload.get("error", ""), (status, payload))

    # -------------------------------------------------------- 6. expiry
    row = service.app_db.user_sms("grunt")
    service.app_db._conn.execute(
        "UPDATE user_sms SET code_sent_ts = ? WHERE username = 'grunt'",
        (row["code_sent_ts"] - 700,))
    service.app_db._conn.commit()
    status, payload = call("POST", "/api/account/sms/confirm", {"code": "000000"}, token=grunt)
    check("an expired code is a 400", status == 400 and "expired" in payload.get("error", ""),
          (status, payload))
    check("...and the row falls back to off",
          sms_status(service.app_db.user_sms("grunt")) == "off",
          sms_status(service.app_db.user_sms("grunt")))

    # ----------------------------------------------------- 7. start again, confirm
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("starting again after expiry succeeds", status == 200, (status, payload))
    to_number, text = SENT[-1]
    code = "".join(c for c in text if c.isdigit())[:6]

    status, payload = call("POST", "/api/account/sms/confirm", {"code": code}, token=grunt)
    check("the correct code confirms", status == 200 and payload["status"] == "on",
          (status, payload))
    check("a second (opt-in) text was sent", len(SENT) == 3, SENT)
    check("...it is the opt-in confirmation, not another code",
          "now opted in" in SENT[-1][1] and "STOP" in SENT[-1][1], SENT[-1])

    check("sms_opted_in_numbers reports the number",
          NUMBER in service.app_db.sms_opted_in_numbers(),
          service.app_db.sms_opted_in_numbers())

    # ------------------------------------------------------------ 8. delete
    status, payload = call("DELETE", "/api/account/sms", {}, token=grunt)
    check("DELETE stops a live opt-in", status == 200 and payload["status"] == "stopped"
          and payload["stopped_by"] == "user", (status, payload))
    check("...and the number leaves the opted-in list",
          NUMBER not in service.app_db.sms_opted_in_numbers(),
          service.app_db.sms_opted_in_numbers())

    backdate_code("grunt", 700)
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("start after a stop succeeds", status == 200 and payload["status"] == "pending",
          (status, payload))

    status, payload = call("DELETE", "/api/account/sms", {}, token=grunt)
    check("DELETE inside the resend window clears the code, not the row",
          status == 200 and payload["status"] == "off", (status, payload))
    row = service.app_db.user_sms("grunt")
    check("...the row itself is kept (guard stays intact)",
          row is not None and row["number"] == NUMBER, row)

    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("start->delete->start inside 60s is still gated",
          status == 400 and "Wait" in payload.get("error", ""), (status, payload))

    backdate_code("grunt", 70)
    status, payload = call("DELETE", "/api/account/sms", {}, token=grunt)
    check("DELETE outside the resend window forgets the row",
          status == 200 and payload["status"] == "off", (status, payload))
    status, payload = call("GET", "/api/account/sms", token=grunt)
    check("...GET now shows off with no number",
          status == 200 and payload["status"] == "off" and payload["number"] == "",
          (status, payload))

    # ------------------------------------------------------ 8a. lockout
    backdate_code("grunt", 700)
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    assert status == 200, (status, payload)
    for attempt in range(1, 5):
        status, payload = call("POST", "/api/account/sms/confirm", {"code": "000000"}, token=grunt)
        check(f"wrong code attempt {attempt} is a 400 with tries left",
              status == 400 and "tries left" in payload.get("error", ""), (status, payload))
    status, payload = call("POST", "/api/account/sms/confirm", {"code": "000000"}, token=grunt)
    check("the 5th wrong code locks out with 'Too many wrong codes'",
          status == 400 and "Too many wrong codes" in payload.get("error", ""), (status, payload))
    status, payload = call("GET", "/api/account/sms", token=grunt)
    check("...and GET shows off after lockout", status == 200 and payload["status"] == "off",
          (status, payload))

    # -------------------------------------------------- 8b. already-on refusal
    backdate_code("grunt", 700)
    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    assert status == 200, (status, payload)
    to_number, text = SENT[-1]
    code = "".join(c for c in text if c.isdigit())[:6]
    status, payload = call("POST", "/api/account/sms/confirm", {"code": code}, token=grunt)
    assert status == 200 and payload["status"] == "on", (status, payload)

    status, payload = call("POST", "/api/account/sms/start",
                           {"number": NUMBER, "consent": True, "terms": True}, token=grunt)
    check("start while already on is a 400", status == 400
          and "already on" in payload.get("error", ""), (status, payload))

    # ------------------------------------------------ 8c. per-account isolation
    status, payload = call("GET", "/api/account/sms", token=admin)
    check("a second account's SMS status is independent (off)",
          status == 200 and payload["status"] == "off", (status, payload))

    status, payload = call("DELETE", "/api/account/sms", {}, token=admin)
    check("...its own DELETE is a no-op", status == 200 and payload["status"] == "off",
          (status, payload))

    status, payload = call("GET", "/api/account/sms", token=grunt)
    check("...and leaves the first account's opt-in untouched",
          status == 200 and payload["status"] == "on", (status, payload))

    # ------------------------------------------------- 9. sms_stop_number
    other_number = "+15559990001"
    service.app_db.sms_start("grunt", other_number, "deadbeef", time.time())
    service.app_db.sms_confirm("grunt", time.time())
    stopped = service.app_db.sms_stop_number(other_number, time.time())
    check("sms_stop_number reports one row stopped", stopped == 1, stopped)
    row = service.app_db.user_sms("grunt")
    check("...stopped_by is 'stop'", row["stopped_by"] == "stop", dict(row))

    # ------------------------------------------- 9a. sms_stop_number: pending untouched
    ghost_number = "+15559990099"
    service.app_db.sms_start("ghost", ghost_number, "deadbeef", time.time())
    stopped = service.app_db.sms_stop_number(ghost_number, time.time())
    check("sms_stop_number ignores a pending (unconfirmed) row", stopped == 0, stopped)
    check("...the row is still pending",
          sms_status(service.app_db.user_sms("ghost")) == "pending",
          sms_status(service.app_db.user_sms("ghost")))

    # ---------------------------------------------------- 10. engine _sms_numbers
    engine = service.alert_engine
    service.app_db.sms_start("grunt", "+15559990002", "x", time.time())
    service.app_db.sms_confirm("grunt", time.time())
    numbers = engine._sms_numbers({"sms_to_default": ["+15550000000", "+15559990002"]})
    check("_sms_numbers merges admin defaults with opted-in numbers, deduped",
          numbers.count("+15559990002") == 1 and "+15550000000" in numbers, numbers)

    # ---------------------------------------------------- 11. _sms_result / STOP
    service.app_db.sms_forget("grunt")
    service.app_db.sms_start("grunt", "+15559990003", "x", time.time())
    service.app_db.sms_confirm("grunt", time.time())

    class FakeJob:
        settings = {"sms_to_default": []}
        kind = "sms_alert"
        to_numbers = ["+15559990003"]
        text = "hello"
        alert_id = None
        alert_ids = None
        number_errors = [("+15559990003", "Twilio error 21610: unsubscribed recipient")]

    engine._sms_result(FakeJob(), True, "")
    check("_sms_result stops a number that replied STOP (21610)",
          sms_status(service.app_db.user_sms("grunt")) == "stopped",
          sms_status(service.app_db.user_sms("grunt")))

    check("twilio_error_code parses the Twilio error code",
          alertmail.twilio_error_code("Twilio error 21610: unsubscribed recipient") == 21610)
    check("twilio_error_code is None for a non-Twilio error string",
          alertmail.twilio_error_code("boom") is None)
    check("TWILIO_STOP_CODE is 21610", alertmail.TWILIO_STOP_CODE == 21610)

    # ------------------------------------------------------- 12. delete_user
    service.app_db.sms_forget("grunt")
    service.app_db.sms_start("grunt", "+15559990004", "x", time.time())
    assert service.app_db.user_sms("grunt") is not None
    service.app_db.remove_user("grunt")
    check("delete_user removes the user_sms row too",
          service.app_db.user_sms("grunt") is None)

    # --------------------------------------- 13. public SMS terms/privacy
    def get_public(path):
        conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
        conn.request("GET", path)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, dict(response.getheaders()), raw

    status, head, body = get_public("/sms-terms")
    check("unauthenticated GET /sms-terms is 200 text/html",
          status == 200 and head.get("Content-Type", "").startswith("text/html"))
    check("/sms-terms mentions STOP",
          b"STOP" in body)
    check("/sms-terms has the version stamped in",
          b"__SW_VERSION__" not in body)

    status, head, body = get_public("/sms-privacy")
    check("unauthenticated GET /sms-privacy is 200 text/html",
          status == 200 and head.get("Content-Type", "").startswith("text/html"))
    check("/sms-privacy carries the carrier-required no-sharing sentence",
          b"No mobile information will be shared" in body)
finally:
    alertmail.send_sms = real_send_sms
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

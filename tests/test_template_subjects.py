"""5.30's severity-tagged subjects: alertmail.severity_tag/build_context, the
one-time reset that brings an unedited built-in template's subject up to the
new wording without ever touching a body or a custom template, and the three
digest subjects (email/webhook/SMS) leading with the worst severity in the
batch.
"""
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail
from netpath.alertengine import AlertEngine
from netpath.alertsdb import AlertsDatabase
from netpath.appdb import AppDatabase
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("template_subjects_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------- severity_tag itself
check("severity_tag brackets and upper-cases the name",
      alertmail.severity_tag(2) == "[CRITICAL]", alertmail.severity_tag(2))
check("build_context's own severity_tag agrees with the helper",
      alertmail.build_context(
          {"entity_label": "sw1", "message": "m", "detail": "", "severity": 4,
           "count": 1, "opened_ts": 0, "last_ts": 0},
          None)["severity_tag"] == alertmail.severity_tag(4))

# --------------------------------------------------- the one-time subject reset
print("1. the one-time built-in subject reset")
alerts = AlertsDatabase(os.path.join(TMPDIR, "reset.db"))
builtin_key = "device_down"
builtin_before = alerts._conn.execute(
    "SELECT subject, body, builtin_subject, builtin_body FROM templates"
    " WHERE key = ? AND is_builtin = 1", (builtin_key,)).fetchone()
check("setup: a fresh install already ships the current subject",
      builtin_before["subject"] == builtin_before["builtin_subject"], dict(builtin_before))

# Simulate a pre-5.30 install: an operator's own edit to a built-in subject,
# and a custom (non-builtin) template — neither may be touched the same way.
alerts._conn.execute(
    "UPDATE templates SET subject = ? WHERE key = ? AND is_builtin = 1",
    ("Old subject with no tag", builtin_key))
alerts._conn.execute(
    "INSERT INTO templates(key, name, subject, body, is_html, is_builtin,"
    " updated_ts) VALUES ('custom1', 'Custom', 'My own subject', 'body', 0, 0, ?)",
    (time.time(),))
alerts._conn.commit()
alerts._clear_private_setting("template_subjects_reset_5_30")
alerts._migrate()

after = alerts._conn.execute(
    "SELECT subject, body FROM templates WHERE key = ? AND is_builtin = 1",
    (builtin_key,)).fetchone()
check("the edited built-in subject is reset to the shipped wording",
      after["subject"] == builtin_before["builtin_subject"], after["subject"])
check("...and its body is untouched",
      after["body"] == builtin_before["body"], after["body"])
custom = alerts._conn.execute(
    "SELECT subject FROM templates WHERE key = 'custom1'").fetchone()
check("a non-builtin template's subject is never touched",
      custom["subject"] == "My own subject", custom["subject"])
check("the marker is set",
      alerts._private_setting("template_subjects_reset_5_30") is True)

print("2. a second open is a no-op")
alerts._conn.execute(
    "UPDATE templates SET subject = ? WHERE key = ? AND is_builtin = 1",
    ("Edited again, after the marker", builtin_key))
alerts._conn.commit()
alerts._migrate()
still = alerts._conn.execute(
    "SELECT subject FROM templates WHERE key = ? AND is_builtin = 1",
    (builtin_key,)).fetchone()
check("the marker being set stops the reset from running again",
      still["subject"] == "Edited again, after the marker", still["subject"])
alerts.close()

print("3. the one-time SappiWhere-in-subject strip")
alerts = AlertsDatabase(os.path.join(TMPDIR, "strip.db"))
alerts._conn.execute(
    "UPDATE templates SET subject = ? WHERE key = ? AND is_builtin = 1",
    ("[CRITICAL] SappiWhere: my wording", builtin_key))
alerts._conn.execute(
    "INSERT INTO templates(key, name, subject, body, is_html, is_builtin,"
    " updated_ts) VALUES ('custom2', 'Custom', 'SappiWhere: custom', 'body', 0, 0, ?)",
    (time.time(),))
alerts._conn.commit()
alerts._clear_private_setting("template_subjects_strip_5_58")
alerts._migrate()

after = alerts._conn.execute(
    "SELECT subject FROM templates WHERE key = ? AND is_builtin = 1",
    (builtin_key,)).fetchone()
check("SappiWhere is stripped out of the edited built-in subject",
      after["subject"] == "[CRITICAL] my wording", after["subject"])
custom = alerts._conn.execute(
    "SELECT subject FROM templates WHERE key = 'custom2'").fetchone()
check("a non-builtin template's subject is never touched by the strip",
      custom["subject"] == "SappiWhere: custom", custom["subject"])
check("the strip marker is set",
      alerts._private_setting("template_subjects_strip_5_58") is True)

alerts._conn.execute(
    "UPDATE templates SET subject = ? WHERE key = ? AND is_builtin = 1",
    ("SappiWhere: edited again, after the marker", builtin_key))
alerts._conn.commit()
alerts._migrate()
still = alerts._conn.execute(
    "SELECT subject FROM templates WHERE key = ? AND is_builtin = 1",
    (builtin_key,)).fetchone()
check("the strip marker being set stops it from running again",
      still["subject"] == "SappiWhere: edited again, after the marker", still["subject"])
alerts.close()

print("3b. an unedited 5.57 subject migrates through the strip release too")
alerts = AlertsDatabase(os.path.join(TMPDIR, "strip57.db"))
alerts._conn.execute(
    "UPDATE templates SET subject = ?, body = ?, updated_ts = 1.0"
    " WHERE key = ? AND is_builtin = 1",
    ("{{severity_tag}} SappiWhere: {{device_name}} is not responding",
     alertmail.BUILTIN_TEMPLATES["device_down"]["body"], builtin_key))
alerts._conn.commit()
alerts.close()

alerts = AlertsDatabase(os.path.join(TMPDIR, "strip57.db"))
migrated = alerts.template_by_key("device_down")
check("the 5.57 subject is migrated to the current wording on reopen",
      migrated["subject"] == alertmail.BUILTIN_TEMPLATES["device_down"]["subject"],
      migrated["subject"])
check("...and builtin_subject agrees",
      migrated["builtin_subject"] == alertmail.BUILTIN_TEMPLATES["device_down"]["subject"],
      migrated["builtin_subject"])
alerts.close()


# ------------------------------------------------------- the three digests
_SEQ = [0]


def build_engine():
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"engine{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    alerts.save_settings({"email_enabled": False, "rollup_enabled": False,
                          "webhook_enabled": False, "sms_enabled": False})
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    netpath_db = NetpathDatabase(os.path.join(folder, "netpath.db"))
    # An opted-in account number for section 6's SMS digest: 5.63.0 sends
    # only to app_db.sms_opted_in_numbers(), never a saved setting.
    app_db = AppDatabase(os.path.join(folder, "app.db"))
    app_db.sms_start("opuser", "+15005550001", "x", time.time())
    app_db.sms_confirm("opuser", time.time())
    return AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                       syslog_db=syslog, ipam_db=ipam, netpath_db=netpath_db,
                       app_db=app_db)


def alert(id, label, severity, message="down"):
    return {"id": id, "entity_label": label, "message": message, "severity": severity}


def rule(key="device_down", name="Device down", kind="device", notify=True, notify_sms=False):
    return {"key": key, "name": name, "kind": kind, "notify": notify, "notify_sms": notify_sms}


# One warning(4), one critical(2), one error(3) -- the worst is critical.
SENDABLE = [
    (alert(101, "sw1", 4), rule(), None),
    (alert(102, "sw2", 2), rule(), None),
    (alert(103, "sw3", 3), rule(), None),
]

print("4. the email digest subject")
engine = build_engine()
captured = []
engine._mail.submit = lambda job: (captured.append(job) or True)
engine._send_digest(SENDABLE, {"email_enabled": True, "smtp_host": "mail.example.com",
                              "smtp_to_default": ["ops@example.com"],
                              "webhook_enabled": False, "sms_enabled": False}, 300)
check("one email digest was built", len(captured) == 1, captured)
if captured:
    check("its subject leads with the worst severity's tag",
          captured[0].subject.startswith("[CRITICAL] "), captured[0].subject)
    check("its subject no longer names SappiWhere",
          "SappiWhere" not in captured[0].subject, captured[0].subject)

print("5. the webhook digest subject")
engine = build_engine()
captured = []
engine._webhook.submit = lambda job: (captured.append(job) or True)
engine._webhook_digest(SENDABLE, {"webhook_enabled": True,
                                 "webhook_url": "http://127.0.0.1:1/hook"}, 300)
check("one webhook digest was built", len(captured) == 1, captured)
if captured:
    check("its subject leads with the worst severity's tag",
          captured[0].subject.startswith("[CRITICAL] "), captured[0].subject)
    check("its subject no longer names SappiWhere",
          "SappiWhere" not in captured[0].subject, captured[0].subject)
    check("the payload's own subject agrees",
          captured[0].payload["subject"] == captured[0].subject, captured[0].payload)

print("6. the SMS digest text")
engine = build_engine()
captured = []
engine._sms.submit = lambda job: (captured.append(job) or True)
engine._sms_token = lambda settings: "test-token"
sms_sendable = [
    (alert(101, "sw1", 4), rule(notify_sms=True), None),
    (alert(102, "sw2", 2), rule(notify_sms=True), None),
]
engine._sms_digest(sms_sendable, {"sms_enabled": True, "twilio_account_sid": "ACxxx",
                                 "twilio_from": "+15005550006"}, 300)
check("one text digest was built", len(captured) == 1, captured)
if captured:
    check("the text leads with the worst severity's tag",
          captured[0].text.startswith("[CRITICAL]"), captured[0].text)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

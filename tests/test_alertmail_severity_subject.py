"""Severity leads the alert email's subject, not its sign-off. Proves:
build_context's severity_tag token is bracketed and upper-case; every one of
the six built-in templates leads its subject with {{severity_tag}} and no
longer ends its body in {{severity_name}}; and alertsdb._migrate_templates
upgrades an unedited template from any wording that key has ever shipped in
one step, while a template an operator has customised is never touched.
"""
from _paths import tmpdir

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase

TMPDIR = tmpdir("alertmail_severity_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------- severity_tag

_ALERT_ROW_SHAPE = {
    "entity_label": "sw1", "message": "m", "detail": "", "count": 1,
    "opened_ts": 0.0, "last_ts": 0.0, "resolved_ts": None,
}


def context_for(severity: int) -> dict:
    return alertmail.build_context({**_ALERT_ROW_SHAPE, "severity": severity}, None)


check("severity 2 (critical) renders as [CRITICAL]",
      context_for(2)["severity_tag"] == "[CRITICAL]", context_for(2))
check("severity 1 (alert) renders as [ALERT]",
      context_for(1)["severity_tag"] == "[ALERT]", context_for(1))
check("severity 4 (warning) renders as [WARNING]",
      context_for(4)["severity_tag"] == "[WARNING]", context_for(4))
check("an out-of-range severity still renders something bracketed, not a crash",
      context_for(9)["severity_tag"] == "[9]", context_for(9))
check("severity_tag is documented in the template editor's token palette",
      any(t["token"] == "severity_tag" for t in alertmail.token_reference()),
      alertmail.token_reference())

# ------------------------------------------------------------ [RECOVER]
#
# A resolution renders the generic device_up template through
# AlertEngine._notify_clear, so the subject led with the CLEARED alert's own
# level: "[CRITICAL] SappiWhere: sw1 has recovered" read, in a notification
# preview, as a new emergency.

def clear_context(severity: int, extra=None) -> dict:
    """What _notify_clear renders: the resolved row, with the recovery tags
    the engine passes through `extra`."""
    row = {**_ALERT_ROW_SHAPE, "severity": severity,
           "opened_ts": 300.0, "last_ts": 900.0, "resolved_ts": 900.0}
    return alertmail.build_context(row, None, extra=extra)


check("a recovery's severity_tag is [RECOVER], not the cleared alert's level",
      clear_context(2)["severity_tag"] == "[RECOVER]", clear_context(2))
check("...whatever the cleared alert's own severity was",
      clear_context(6)["severity_tag"] == "[RECOVER]", clear_context(6))
check("...and the engine's own extra (what _notify_clear passes) says the same",
      clear_context(2, {"severity_tag": alertmail.RECOVER_TAG,
                        "recover_tag": alertmail.RECOVER_TAG})["severity_tag"]
      == "[RECOVER]")
check("recover_tag is [RECOVER] on a recovery and empty on an opening alert",
      clear_context(2)["recover_tag"] == "[RECOVER]"
      and context_for(2)["recover_tag"] == "",
      (clear_context(2)["recover_tag"], context_for(2)["recover_tag"]))
check("an OPENING alert still leads with its own level — the standalone "
      "'Device recovered' rule is an alert in its own right, not a recovery "
      "of anything",
      context_for(5)["severity_tag"] == "[NOTICE]"
      and context_for(2)["severity_tag"] == "[CRITICAL]",
      (context_for(5), context_for(2)))
check("a resolved row still renders its downtime sentence as well as the tag",
      clear_context(2)["recovered_time"] and clear_context(2)["downtime_line"],
      clear_context(2))
check("the token palette says severity_tag reads [RECOVER] on a recovery",
      any(t["token"] == "severity_tag" and "[RECOVER]" in t["description"]
          for t in alertmail.token_reference()),
      alertmail.token_reference())
check("...and documents recover_tag itself",
      any(t["token"] == "recover_tag" for t in alertmail.token_reference()),
      alertmail.token_reference())
check("no built-in template text changed for any of this "
      "(_PREVIOUS_BUILTIN_TEMPLATES stays untouched)",
      alertmail.BUILTIN_TEMPLATES["device_up"]["subject"]
      == "{{severity_tag}} SappiWhere: {{device_name}} has recovered",
      alertmail.BUILTIN_TEMPLATES["device_up"]["subject"])

# --------------------------------------------------- every built-in template

for key, spec in alertmail.BUILTIN_TEMPLATES.items():
    check(f"{key}'s subject leads with {{{{severity_tag}}}}",
          spec["subject"].startswith("{{severity_tag}} "), spec["subject"])
    check(f"{key}'s body no longer signs off with the now-redundant "
          f"{{{{severity_name}}}}",
          spec["body"].rstrip().endswith("-- SappiWhere")
          and "{{severity_name}}" not in spec["body"], spec["body"])

# ------------------------------------------------------- upgrade: unedited

db = AlertsDatabase(f"{TMPDIR}/unedited.db")
now_before = db.template_by_key("device_down")["updated_ts"]
with db._lock:
    # Simulate a pre-upgrade install: an unedited device_down template still
    # holding exactly the wording shipped BEFORE this change (the one
    # entry in _PREVIOUS_BUILTIN_TEMPLATES["device_down"]).
    db._conn.execute(
        "UPDATE templates SET subject = ?, body = ?, updated_ts = 1.0"
        " WHERE key = 'device_down'",
        ("SappiWhere: {{device_name}} is not responding",
         "{{device_name}} ({{device_ip}}) stopped responding at "
         "{{opened_time}}.\n\n{{message}}\n\n"
         "This alert has occurred {{count}} time(s). It will clear "
         "automatically once the device responds again.\n\n"
         "-- SappiWhere, {{severity_name}}"))
    db._conn.commit()
db.close()

# Reopening runs _migrate_templates again, against the row just planted.
db = AlertsDatabase(f"{TMPDIR}/unedited.db")
migrated = db.template_by_key("device_down")
check("an unedited pre-O-60 device_down template is migrated to the new "
      "severity-tagged wording on the next open",
      migrated["subject"] == alertmail.BUILTIN_TEMPLATES["device_down"]["subject"]
      and migrated["body"] == alertmail.BUILTIN_TEMPLATES["device_down"]["body"],
      dict(migrated))
db.close()

# --------------------------------------------- upgrade: several releases behind

db = AlertsDatabase(f"{TMPDIR}/ancient.db")
with db._lock:
    # The ORIGINAL, pre-4.32.0 device_up wording -- two migrations behind,
    # not one. Proves the list-of-previous-versions fix actually reaches
    # this far back rather than only catching the most recent rewording.
    db._conn.execute(
        "UPDATE templates SET subject = ?, body = ?, updated_ts = 1.0"
        " WHERE key = 'device_up'",
        ("SappiWhere: {{device_name}} has recovered",
         "{{device_name}} ({{device_ip}}) is responding again as of "
         "{{last_time}}.\n\n{{message}}\n\n"
         "-- SappiWhere, {{severity_name}}"))
    db._conn.commit()
db.close()

db = AlertsDatabase(f"{TMPDIR}/ancient.db")
migrated = db.template_by_key("device_up")
check("a device_up template two releases behind (pre-4.32.0 wording) is "
      "still migrated all the way to the current text in one step",
      migrated["subject"] == alertmail.BUILTIN_TEMPLATES["device_up"]["subject"]
      and migrated["body"] == alertmail.BUILTIN_TEMPLATES["device_up"]["body"],
      dict(migrated))
db.close()

# ------------------------------------------------------- upgrade: customised

db = AlertsDatabase(f"{TMPDIR}/customised.db")
custom_subject = "URGENT: {{device_name}} needs attention"
custom_body = "Please look at {{device_name}}.\n\n-- the NOC"
with db._lock:
    db._conn.execute(
        "UPDATE templates SET subject = ?, body = ?, updated_ts = 1.0"
        " WHERE key = 'device_down'", (custom_subject, custom_body))
    db._conn.commit()
db.close()

db = AlertsDatabase(f"{TMPDIR}/customised.db")
untouched = db.template_by_key("device_down")
check("a template an operator actually customised is never touched by the "
      "migration, however many wordings this key has shipped",
      untouched["subject"] == custom_subject and untouched["body"] == custom_body,
      dict(untouched))
check("...but its builtin_subject/builtin_body (what 'Reset to built-in' "
      "restores) still becomes the new wording, same as always",
      untouched["builtin_subject"] == alertmail.BUILTIN_TEMPLATES["device_down"]["subject"],
      dict(untouched))
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

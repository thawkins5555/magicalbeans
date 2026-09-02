"""Alert email: {{token}} template rendering and stdlib SMTP sending.

No template engine — a small hand-rolled `{{token}}` regex substitution,
never Jinja2, matching the same "hand-rolled, not a dependency" rule the
rest of this app follows for BER/ASN.1, MIB parsing, and everything else.
"""

from __future__ import annotations

import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formataddr

BUILTIN_TEMPLATES = {
    "device_down": {
        "name": "Device not responding",
        "subject": "SappiWhere: {{device_name}} is not responding",
        "body": (
            "{{device_name}} ({{device_ip}}) stopped responding at {{opened_time}}.\n\n"
            "{{message}}\n\n"
            "This alert has occurred {{count}} time(s). It will clear "
            "automatically once the device responds again.\n\n"
            "-- SappiWhere, {{severity_name}}"
        ),
    },
    "device_up": {
        "name": "Device recovered",
        "subject": "SappiWhere: {{device_name}} has recovered",
        # "has recovered" rather than "is responding again": _notify_clear
        # renders this one template for every kind of resolution, including a
        # port coming back and a threshold dropping below its clear value, and
        # only some of those are a device answering again.
        "body": (
            "{{device_name}} ({{device_ip}}) has recovered as of {{recovered_time}}.\n\n"
            "Down since {{down_since}} — {{downtime}} in total.\n\n"
            "{{message}}\n\n"
            "-- SappiWhere, {{severity_name}}"
        ),
    },
    "device_rebooted": {
        "name": "Device rebooted",
        "subject": "SappiWhere: {{device_name}} rebooted",
        "body": (
            "{{device_name}} ({{device_ip}}) appears to have rebooted at {{last_time}}.\n\n"
            "Previous reported uptime: {{previous_uptime}}\n"
            "Current reported uptime: {{current_uptime}}\n\n"
            "{{message}}\n\n"
            "-- SappiWhere, {{severity_name}}"
        ),
    },
    "threshold_breach": {
        "name": "Threshold breach",
        "subject": "SappiWhere: {{entity_label}} — {{metric_label}} is {{value}}",
        "body": (
            "{{entity_label}} crossed a threshold at {{last_time}}.\n\n"
            "Metric: {{metric_label}}\n"
            "Current value: {{value}}\n"
            "Threshold: {{threshold}}\n\n"
            "{{message}}\n\n"
            "This alert has occurred {{count}} time(s). It will clear "
            "automatically once the value drops back below the clear threshold.\n\n"
            "-- SappiWhere, {{severity_name}}"
        ),
    },
    "trap_forwarded": {
        "name": "Forwarded event",
        "subject": "SappiWhere: {{rule_name}} — {{entity_label}}",
        "body": (
            "{{rule_name}} matched at {{last_time}}.\n\n"
            "Source: {{entity_label}}\n"
            "{{message}}\n\n"
            "Trap name: {{trap_name}}\n"
            "Trap OID: {{trap_oid}}\n"
            "Varbinds: {{varbinds}}\n\n"
            "This alert has occurred {{count}} time(s).\n\n"
            "-- SappiWhere, {{severity_name}}"
        ),
    },
}

_TOKEN = re.compile(r"\{\{(\w+)\}\}")

SEVERITY_NAMES = ["emergency", "alert", "critical", "error", "warning",
                  "notice", "informational", "debug"]


def render(text: str, context: dict) -> str:
    """{{token}} substitution. An unknown token renders as an empty string
    rather than leaving the literal {{token}} in a sent email — the caller
    should validate against token_reference() before saving a custom
    template, so this is a last-resort safety net, not the normal path."""
    return _TOKEN.sub(lambda m: str(context.get(m.group(1), "")), text)


def clock_text(ts) -> str:
    """A timestamp as local wall-clock text, or "" for a missing one."""
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


# The name this module used before the engine needed to format a timestamp
# the same way for an alert's own message text.
_clock = clock_text


def duration_text(seconds) -> str:
    """An outage's length in two units — "48 s", "14 m 09 s", "2 h 14 m",
    "3 d 07 h".

    Two units because one is not enough for the question this answers: "3.5 h"
    is how long the console prints an uptime, but "was it a three-hour outage
    or a three-and-a-half-hour one" is exactly what somebody writing it up
    needs. The minor unit is zero-padded so "2 h 4 m" cannot be read as
    "2 h 40 m".

    An unknown or non-positive duration renders as "" rather than "0 s": when
    the recovery could not be paired with an outage there is nothing to claim,
    and a zero-length outage would be a claim.
    """
    try:
        total = float(seconds)
    except (TypeError, ValueError):
        return ""
    if total <= 0:
        return ""
    total = int(round(total))
    if total < 60:
        return f"{total} s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes} m {secs:02d} s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes:02d} m"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours:02d} h"


def build_context(alert_row, rule_row, extra: dict | None = None) -> dict:
    """Every token available to every template — a superset, since a given
    template only uses the subset relevant to its own rule kind."""
    severity = alert_row["severity"]
    context = {
        "device_name": alert_row["entity_label"],
        "device_ip": alert_row["entity_id"],
        "entity_label": alert_row["entity_label"],
        "message": alert_row["message"],
        "detail": alert_row["detail"] or "",
        "severity": severity,
        "severity_name": SEVERITY_NAMES[severity] if 0 <= severity <= 7 else str(severity),
        "count": alert_row["count"],
        "opened_time": _clock(alert_row["opened_ts"]),
        "last_time": _clock(alert_row["last_ts"]),
        "rule_name": rule_row["name"] if rule_row else "",
        "previous_uptime": "", "current_uptime": "",
        "metric_label": "", "value": "", "threshold": "",
        "trap_name": "", "trap_oid": "", "varbinds": "",
        "down_since": "", "recovered_time": "", "downtime": "",
    }
    # Derived here, from the row, rather than only where the engine happens to
    # know them: a recovery sends TWO notifications — the "Device recovered"
    # alert in its own right, and the resolution of the outage it cleared —
    # and both render this same template. The resolution one is built from a
    # synthetic occurrence with no extras, so tokens threaded through the
    # occurrence alone would render empty on exactly the email that is about
    # the outage. A resolved alert already carries both timestamps.
    #
    # `extra` still updates last, so the engine's own values win where it has
    # better ones — the up event's timestamp is the moment the device answered,
    # while resolved_ts is whenever the engine's next tick noticed.
    resolved_ts = alert_row["resolved_ts"] if "resolved_ts" in alert_row.keys() else None
    if resolved_ts:
        context["down_since"] = _clock(alert_row["opened_ts"])
        context["recovered_time"] = _clock(resolved_ts)
        context["downtime"] = duration_text(resolved_ts - alert_row["opened_ts"])
    if extra:
        context.update(extra)
    return context


def token_reference() -> list[dict]:
    """[{token, description}] for the template editor's clickable palette."""
    return [
        {"token": "device_name", "description": "The device's display name"},
        {"token": "device_ip", "description": "The device's IP address"},
        {"token": "entity_label", "description": "The alerting object (device, or device / interface)"},
        {"token": "message", "description": "The alert's own summary message"},
        {"token": "detail", "description": "Extra detail text, if any"},
        {"token": "severity", "description": "Severity number, 0 (emergency) to 7 (debug)"},
        {"token": "severity_name", "description": "Severity name, e.g. 'critical'"},
        {"token": "count", "description": "How many times this alert has occurred"},
        {"token": "opened_time", "description": "When the alert first opened"},
        {"token": "last_time", "description": "When the alert most recently recurred"},
        {"token": "rule_name", "description": "The rule that fired"},
        {"token": "previous_uptime", "description": "Reported uptime before a reboot (device_rebooted only)"},
        {"token": "current_uptime", "description": "Reported uptime after a reboot (device_rebooted only)"},
        {"token": "metric_label", "description": "The metric name (threshold rules only)"},
        {"token": "value", "description": "The metric's current value (threshold rules only)"},
        {"token": "threshold", "description": "The configured threshold (threshold rules only)"},
        {"token": "down_since", "description": "When the problem started (resolution notifications only)"},
        {"token": "recovered_time", "description": "When it recovered (resolution notifications only)"},
        {"token": "downtime", "description": "How long it was down, e.g. '2 h 14 m' (resolution notifications only)"},
        {"token": "trap_name", "description": "The trap's resolved name (trap rules only)"},
        {"token": "trap_oid", "description": "The trap's OID (trap rules only)"},
        {"token": "varbinds", "description": "The trap's varbind summary (trap rules only)"},
    ]


def send(smtp_settings: dict, password: str | None, to_addrs: list[str],
        subject: str, body: str, is_html: bool = False) -> None:
    """stdlib smtplib + email.message.EmailMessage. Raises on any failure —
    the caller decides what to do with that; this never swallows an error."""
    host = str(smtp_settings.get("smtp_host", "")).strip()
    if not host:
        raise ValueError("No SMTP host configured")
    port = int(smtp_settings.get("smtp_port", 587))
    security = str(smtp_settings.get("smtp_security", "starttls"))
    verify = bool(smtp_settings.get("smtp_verify_cert", True))
    timeout = float(smtp_settings.get("smtp_timeout_s", 15.0))
    username = str(smtp_settings.get("smtp_username", "") or "")
    from_addr = str(smtp_settings.get("smtp_from", "") or username)
    from_name = str(smtp_settings.get("smtp_from_name", "") or "")

    if verify:
        context = ssl.create_default_context()
    else:
        # A deliberate opt-out, not a silent downgrade — the admin turned
        # certificate verification off explicitly in Settings.
        context = ssl._create_unverified_context()

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    message["To"] = ", ".join(to_addrs)
    if is_html:
        message.set_content("This message requires an HTML-capable mail reader.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    if security == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=timeout)
    try:
        smtp.ehlo()
        if security == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)
    finally:
        try:
            smtp.quit()
        except Exception:
            pass

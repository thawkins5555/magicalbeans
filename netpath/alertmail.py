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
        "body": (
            "{{device_name}} ({{device_ip}}) is responding again as of {{last_time}}.\n\n"
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


def _clock(ts) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


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
    }
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

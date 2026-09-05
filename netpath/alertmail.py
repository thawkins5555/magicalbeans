"""Alert email: {{token}} template rendering and stdlib SMTP sending.

No template engine — a small hand-rolled `{{token}}` regex substitution,
never Jinja2, matching the same "hand-rolled, not a dependency" rule the
rest of this app follows for BER/ASN.1, MIB parsing, and everything else.
"""

from __future__ import annotations

import json
import queue
import re
import smtplib
import ssl
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr
from urllib.parse import urlparse

# O-60: severity used to live only in the sign-off, "-- SappiWhere, error",
# where it cost a tap to see. Invisible at rehearsal scale (a handful of
# emails an hour) and obvious at real scale: Tier B's single site outage
# produced 29 near-identical subjects differing only by device name, and the
# one fact that decides whether an operator gets out of bed — is this
# critical or informational — sat at the bottom of the body. Every subject
# below now leads with {{severity_tag}} (see build_context — a bracketed,
# upper-case severity name, "[CRITICAL]") instead. The sign-off drops
# {{severity_name}} in the same change: once it is in the subject, a
# sign-off ending in a bare severity word ("-- SappiWhere, error") reads as
# a truncation, not information, so it is just "-- SappiWhere" now.
#
# This does not reopen the mail-threading question it looks like it would.
# A renotify of a still-open alert reuses this same template against the
# SAME alert row, whose severity does not change while it stays open, so
# every "still open" email for one alert carries the same tag. A clear
# renders a DIFFERENT template (device_up, unconditionally — see
# alertengine._notify_clear) with different subject wording already, so an
# open notice and its eventual recovery notice were never going to thread
# together by subject text, tag or no tag.
#
# Existing installs: changing the dict here only seeds a NEW alerts.db
# (_seed_templates is INSERT OR IGNORE). Reaching an existing, unedited
# install is alertsdb._PREVIOUS_BUILTIN_TEMPLATES/_migrate_templates's job —
# every template below has its pre-this-change text added there so the
# upgrade is not silently new-installs-only, the same discipline 4.32.0's
# device_up wording change already established.
BUILTIN_TEMPLATES = {
    "device_down": {
        "name": "Device not responding",
        "subject": "{{severity_tag}} SappiWhere: {{device_name}} is not responding",
        "body": (
            "{{device_name}} ({{device_ip}}) stopped responding at {{opened_time}}.\n\n"
            "{{message}}\n\n"
            "This alert has occurred {{count}} time(s). It will clear "
            "automatically once the device responds again.\n\n"
            "-- SappiWhere"
        ),
    },
    "device_up": {
        "name": "Device recovered",
        "subject": "{{severity_tag}} SappiWhere: {{device_name}} has recovered",
        # "has recovered" rather than "is responding again": _notify_clear
        # renders this one template for every kind of resolution, including a
        # port coming back and a threshold dropping below its clear value, and
        # only some of those are a device answering again.
        "body": (
            "{{device_name}} ({{device_ip}}) has recovered as of {{recovered_time}}.\n\n"
            # One token, not "Down since {{down_since}} — {{downtime}} in
            # total.": templates have no conditionals, so a recovery whose
            # outage start is unknown rendered the literal text
            # "Down since  —  in total." The whole sentence, trailing blank
            # line included, is built in build_context and is "" when there
            # is nothing honest to say.
            "{{downtime_line}}"
            "{{message}}\n\n"
            "-- SappiWhere"
        ),
    },
    "device_rebooted": {
        "name": "Device rebooted",
        "subject": "{{severity_tag}} SappiWhere: {{device_name}} rebooted",
        "body": (
            "{{device_name}} ({{device_ip}}) appears to have rebooted at {{last_time}}.\n\n"
            "Previous reported uptime: {{previous_uptime}}\n"
            "Current reported uptime: {{current_uptime}}\n\n"
            "{{message}}\n\n"
            "-- SappiWhere"
        ),
    },
    "threshold_breach": {
        "name": "Threshold breach",
        "subject": "{{severity_tag}} SappiWhere: {{entity_label}} — {{metric_label}} is {{value}}",
        "body": (
            "{{entity_label}} crossed a threshold at {{last_time}}.\n\n"
            "Metric: {{metric_label}}\n"
            "Current value: {{value}}\n"
            "Threshold: {{threshold}}\n\n"
            "{{message}}\n\n"
            "This alert has occurred {{count}} time(s). It will clear "
            "automatically once the value drops back below the clear threshold.\n\n"
            "-- SappiWhere"
        ),
    },
    # The generic non-outage notice. Six rules used to borrow "device_down",
    # whose subject is "{{device_name}} is not responding" — so seeding 250
    # devices produced 234 emails titled "acc-sw-070 is not responding" that
    # were actually "vendor MIB not uploaded". An operator reading the inbox
    # saw a site outage that was not happening.
    #
    # Deliberately not trap_forwarded, whose subject line is identical but
    # whose body names a Trap OID and varbinds: rendered for a poll overrun
    # those three lines are blank labels, which reads as a truncated message
    # rather than a short one.
    "event_notice": {
        "name": "Event notice",
        "subject": "{{severity_tag}} SappiWhere: {{rule_name}} — {{entity_label}}",
        "body": (
            "{{rule_name}} — {{entity_label}}\n\n"
            "{{message}}\n\n"
            "{{detail}}\n"
            "First seen {{opened_time}}; most recently {{last_time}}.\n"
            "This alert has occurred {{count}} time(s).\n\n"
            "-- SappiWhere"
        ),
    },
    "trap_forwarded": {
        "name": "Forwarded event",
        "subject": "{{severity_tag}} SappiWhere: {{rule_name}} — {{entity_label}}",
        "body": (
            "{{rule_name}} matched at {{last_time}}.\n\n"
            "Source: {{entity_label}}\n"
            "{{message}}\n\n"
            "Trap name: {{trap_name}}\n"
            "Trap OID: {{trap_oid}}\n"
            "Varbinds: {{varbinds}}\n\n"
            "This alert has occurred {{count}} time(s).\n\n"
            "-- SappiWhere"
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
    """A timestamp as local wall-clock text, or "" for a missing one.

    The UTC offset is part of the text, not decoration: every timestamp in
    an alert email is the *server's* wall clock, and a fleet spanning sites
    (or an operator reading the mail on a phone in another zone) has no way
    to tell which clock "02:14" was. An offset makes the same string usable
    in an incident write-up without asking where the server lives.
    """
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(ts))


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
    # Rounded BEFORE the test, not after: on the float, 0.4 s is "positive"
    # and then rendered as "0 s" -- the exact claim the paragraph above says
    # this function refuses to make. Seen live in a recovery message
    # ("responding again at 20:49:30 after 0 s down").
    total = int(round(total))
    if total <= 0:
        return ""
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
        # Filled by the engine when the device still exists; entity_id is a
        # database id, not an address, so it is never the fallback.
        "device_ip": "",
        "entity_label": alert_row["entity_label"],
        "message": alert_row["message"],
        "detail": alert_row["detail"] or "",
        "severity": severity,
        "severity_name": SEVERITY_NAMES[severity] if 0 <= severity <= 7 else str(severity),
        # A bracketed, upper-case tag for the front of a subject line —
        # "[CRITICAL]" — so severity is legible in a notification preview
        # without opening the message. See O-60: the same fact severity_name
        # already carries, just where it is actually read first.
        "severity_tag": "[{}]".format(
            (SEVERITY_NAMES[severity] if 0 <= severity <= 7 else str(severity)).upper()),
        "count": alert_row["count"],
        "opened_time": _clock(alert_row["opened_ts"]),
        "last_time": _clock(alert_row["last_ts"]),
        "rule_name": rule_row["name"] if rule_row else "",
        "previous_uptime": "", "current_uptime": "",
        "metric_label": "", "value": "", "threshold": "",
        "trap_name": "", "trap_oid": "", "varbinds": "",
        "down_since": "", "recovered_time": "", "downtime": "",
        "downtime_line": "",
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
    # After the update, never before: the engine supplies down_since and
    # downtime through `extra`, and the sentence has to describe whichever
    # values actually won.
    since = str(context.get("down_since") or "")
    length = str(context.get("downtime") or "")
    if since and length:
        context["downtime_line"] = f"Down since {since} — {length} in total.\n\n"
    elif since:
        context["downtime_line"] = f"Down since {since}.\n\n"
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
        {"token": "severity_tag", "description": "Severity as a bracketed, upper-case subject tag, e.g. '[CRITICAL]'"},
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
        {"token": "downtime_line", "description": "The whole 'Down since … — … in total.' sentence, or nothing when the outage start is unknown"},
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


# ------------------------------------------------------------ sender queue

# How many messages may wait to be sent. A mass outage produces one job per
# alert; beyond this the queue refuses rather than growing without bound, and
# the refusal is recorded against the alert (ok=0, "send queue full") so a
# dropped notification is visible in the alert's own detail pane instead of
# only in a counter.
QUEUE_SIZE = 500

# Consecutive failures that open the breaker, and how long it stays open.
# Five is enough to distinguish "one message bounced" from "the relay is
# gone"; fifteen minutes is short enough that a relay coming back is noticed
# within one maintenance window and long enough that a dead relay is not
# retried once per alert for an hour.
BREAKER_FAILURES = 5
BREAKER_COOLDOWN_S = 900.0

BREAKER_ERROR = "not attempted: alert email is failing (delivery paused)"


@dataclass
class MailJob:
    """One message to deliver, with everything `send` needs already
    resolved. Built on the engine's tick thread and handed to the queue, so
    nothing about it may need a database read later: the settings snapshot,
    the recipients and the rendered text all travel with the job."""
    settings: dict
    password: str | None
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    body: str = ""
    is_html: bool = False
    alert_id: int | None = None
    kind: str = "alert"
    # Set only for a roll-up digest (AlertEngine._send_digest): every alert
    # id this one message speaks for, so _mail_result can write each of them
    # its own notification row from a single delivery. None for every other
    # job, which still means exactly what alert_id alone always has.
    alert_ids: list | None = None


class MailQueue:
    """A bounded queue of MailJobs drained by one worker thread.

    Sending used to happen inline on the alert engine's tick. At the shipped
    smtp_timeout_s of 15 s, a site-wide outage with a dead relay meant 500
    alerts × 15 s of blocked tick — around two hours during which the engine
    evaluated nothing, noticed no recoveries and re-derived no thresholds.
    Even a healthy relay at a 0.2 s round trip took 12.3 s for that outage,
    against a 5 s tick. Delivery therefore happens here, off the tick, and
    the engine's only cost is an enqueue.

    The breaker is the second half of the same problem: without one, every
    alert keeps paying the relay's full timeout for as long as it is down.
    After BREAKER_FAILURES consecutive failures the queue stops attempting
    and completes jobs as failed immediately; after the cooldown the next
    job is let through as a half-open probe, and its result either closes
    the breaker or starts another cooldown.

    `on_result(job, ok, error)` and `on_breaker(is_open, error)` are called
    on the worker thread, so a caller that writes to a database from them
    needs that database to have its own lock — AlertsDatabase does.
    """

    def __init__(self, *, maxsize: int = QUEUE_SIZE, on_result=None,
                 on_breaker=None, failures_to_open: int = BREAKER_FAILURES,
                 cooldown_s: float = BREAKER_COOLDOWN_S):
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, int(maxsize)))
        self._on_result = on_result
        self._on_breaker = on_breaker
        self.failures_to_open = max(1, int(failures_to_open))
        self.cooldown_s = float(cooldown_s)
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._busy = False
        self._failures = 0
        self._open_since: float | None = None

    # ------------------------------------------------------------ lifecycle

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="alert-mail",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Ask the worker to finish and wait up to two seconds for it.

        Two seconds and not longer because the worker may be inside a
        blocking smtplib call with a 15 s timeout, and a shutdown that waits
        for a dead relay is a shutdown that appears to hang. The thread is a
        daemon, so an abandoned send cannot keep the process alive.
        """
        thread = self._thread
        self._thread = None
        self._stopping.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    # -------------------------------------------------------------- submit

    def submit(self, job: MailJob) -> bool:
        """Queue a message. False when the queue is full — the caller records
        that against the alert rather than blocking the tick thread."""
        if not self.running:
            self.start()
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            return False
        return True

    def depth(self) -> int:
        return self._queue.qsize()

    def breaker_open(self) -> bool:
        with self._lock:
            return self._open_since is not None

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """True once nothing is queued and nothing is in flight. For callers
        that need the queue settled before reading its effects — tests, and
        the maintenance pass before a database is closed."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            with self._lock:
                if self._queue.empty() and not self._busy:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    # -------------------------------------------------------------- worker

    def _run(self) -> None:
        # A short get() timeout rather than a shutdown sentinel at the back
        # of the queue: stop() must not have to wait for a backlog of jobs
        # aimed at a relay that is not answering.
        while not self._stopping.is_set():
            try:
                job = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                self._busy = True
            try:
                self._deliver(job)
            except Exception:
                traceback.print_exc()
            finally:
                with self._lock:
                    self._busy = False
                self._queue.task_done()

    def _deliver(self, job: MailJob) -> None:
        blocked = self._breaker_verdict()
        if blocked:
            self._finish(job, False, blocked)
            return
        try:
            # Resolved from the module namespace at call time, not captured
            # at construction, so a deployment (or a test) that replaces
            # alertmail.send is honoured by jobs already queued.
            send(job.settings, job.password, list(job.to_addrs), job.subject,
                 job.body, job.is_html)
        except Exception as exc:
            self._record_failure(str(exc) or exc.__class__.__name__)
            self._finish(job, False, str(exc) or exc.__class__.__name__)
        else:
            self._record_success()
            self._finish(job, True, "")

    def _breaker_verdict(self) -> str:
        """"" when this job may be attempted, otherwise why it was not."""
        with self._lock:
            if self._open_since is None:
                return ""
            if time.monotonic() - self._open_since >= self.cooldown_s:
                # Half open: this one job goes out. Its result decides
                # whether the breaker closes or the cooldown restarts.
                return ""
            return BREAKER_ERROR

    def _record_failure(self, error: str) -> None:
        with self._lock:
            self._failures += 1
            newly_open = (self._open_since is None
                          and self._failures >= self.failures_to_open)
            if newly_open or self._open_since is not None:
                # A failed half-open probe restarts the cooldown rather than
                # letting the next job through immediately.
                self._open_since = time.monotonic()
        if newly_open:
            self._fire_breaker(True, error)

    def _record_success(self) -> None:
        with self._lock:
            was_open = self._open_since is not None
            self._failures = 0
            self._open_since = None
        if was_open:
            self._fire_breaker(False, "")

    def _fire_breaker(self, is_open: bool, error: str) -> None:
        if self._on_breaker is None:
            return
        try:
            self._on_breaker(is_open, error)
        except Exception:
            traceback.print_exc()

    def _finish(self, job: MailJob, ok: bool, error: str) -> None:
        if self._on_result is None:
            return
        try:
            self._on_result(job, ok, error)
        except Exception:
            traceback.print_exc()


# --------------------------------------------------------- outbound webhook

# ~40 lines of urllib buys Slack, Teams, PagerDuty and every ticketing
# system at once, per the review this shipped from: one HTTP POST, JSON
# body, at the same points email already fires. The JSON shape is FIXED —
# not run through the {{token}} template engine the way the subject line is
# — so a receiver can parse it without knowing this application's template
# syntax. It is documented here, once, rather than only in whichever engine
# method happens to build the dict:
#
#   {
#     "alert_id": 123,              # null for a roll-up digest
#     "rule": "device_down",        # the rule's key
#     "rule_name": "Device not responding",
#     "kind": "device_event",       # the rule's kind — device_event, threshold, trap, ...
#     "entity_label": "acc-sw-070 (10.0.4.12)",
#     "message": "acc-sw-070 stopped responding",
#     "detail": "",
#     "ts": 1730000000.0,
#     "state": "open",              # open|clear|renotify|digest
#     "subject": "SappiWhere: acc-sw-070 is not responding",
#     # digest only: every alert the one delivery speaks for, so a receiver
#     # that only reads the top-level fields still gets a sane single-alert
#     # shape (rule/entity_label/message describe the FIRST one) and a
#     # receiver that wants the rest can walk this.
#     "alerts": [{"alert_id": 124, "rule": "device_down",
#                 "entity_label": "...", "message": "..."}],
#   }


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Raise rather than follow. A webhook URL is operator-configured (the
    same trust level as the SMTP relay setting), but the receiver at the
    OTHER end of a redirect it returns is not — following it would let
    whatever machine sent us to `/redirect` decide where the payload
    (including everything build_context puts in the JSON body) actually
    goes. redirect_request is the one extension point every 3xx handler
    (301/302/303/307/308) calls through, so overriding it here covers all
    of them rather than only the couple urllib's default handler names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"refusing to follow redirect to {newurl}",
            headers, fp)


def parse_headers(lines) -> list[tuple[str, str]]:
    """"Name: value" lines (webhook_headers' own storage shape, the same
    list-of-strings coerce_settings already knows how to type-check) into
    (name, value) pairs. A line with no colon, or an empty name, is skipped
    rather than raising — this runs on every send, and a malformed line
    already saved should cost that one header, not the whole delivery."""
    headers = []
    for line in lines or []:
        name, sep, value = str(line).partition(":")
        name = name.strip()
        if not sep or not name:
            continue
        headers.append((name, value.strip()))
    return headers


def send_webhook(url: str, headers: list[tuple[str, str]], timeout: float,
                 payload: dict) -> None:
    """One POST of `payload` as JSON. Raises on any failure — same contract
    as send() above, and the same caller-decides-what-to-do-with-it split
    between "how to send" (here) and "what a failure means" (the queue,
    the engine).

    Refuses anything but http(s) and refuses to follow a redirect (see
    _RefuseRedirects) — both are re-checked here even though
    alertsdb.validate_webhook_url already refused a bad URL at SAVE time,
    because that only ever runs against a value on its way into Settings: a
    URL already sitting in the database from before validation existed, or
    written by hand into alerts.db, reaches this function directly.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported webhook scheme: {parsed.scheme or '(none)'}")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "SappiWhere-alert-webhook/1.0")
    for name, value in headers:
        request.add_header(name, value)
    opener = urllib.request.build_opener(_RefuseRedirects)
    with opener.open(request, timeout=timeout) as response:
        status = response.status
    if status >= 300:
        raise ValueError(f"webhook receiver returned HTTP {status}")


# How many webhook deliveries may wait to be sent. Separate from QUEUE_SIZE
# rather than shared with it: the two channels have independent hourly
# budgets (see alertsdb.DEFAULTS' webhook_max_per_hour comment) precisely so
# a big webhook-only fleet does not compete with email for the same queue
# slots, and a receiver that is merely slow (not down) is exactly the case
# a deep queue helps with.
WEBHOOK_QUEUE_SIZE = 500


@dataclass
class WebhookJob:
    """One delivery, with everything send_webhook needs already resolved —
    same "nothing may need a database read later" contract as MailJob."""
    url: str
    headers: list = field(default_factory=list)
    timeout: float = 10.0
    payload: dict = field(default_factory=dict)
    # Carried alongside payload (which already has it as payload["subject"])
    # purely so _webhook_result can write a notification row the same shape
    # record_notification's other callers already write, without reaching
    # into the JSON body to find it.
    subject: str = ""
    alert_id: int | None = None
    kind: str = "webhook_alert"
    # Mirrors MailJob.alert_ids: set only for a roll-up digest, so
    # _webhook_result can still write every covered alert its own
    # notification row from the one delivery.
    alert_ids: list | None = None


class WebhookQueue:
    """A bounded queue of WebhookJobs drained by one worker thread — the
    same shape as MailQueue and for the same reason: a slow or dead
    receiver must cost the worker thread time, never the engine tick, which
    only ever pays the cost of an enqueue.

    No circuit breaker, unlike MailQueue: bounded retry is explicitly not
    required for this channel (a failed POST records why and counts toward
    the hourly budget, and that is the whole story), and webhook_max_per_hour
    already caps how often a dead receiver's timeout is paid at all. A
    breaker would be free to add but is one more piece of state to reason
    about for a channel the spec deliberately keeps simple.
    """

    def __init__(self, *, maxsize: int = WEBHOOK_QUEUE_SIZE, on_result=None):
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, int(maxsize)))
        self._on_result = on_result
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._busy = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="alert-webhook",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        thread = self._thread
        self._thread = None
        self._stopping.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def submit(self, job: WebhookJob) -> bool:
        if not self.running:
            self.start()
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            return False
        return True

    def depth(self) -> int:
        return self._queue.qsize()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            with self._lock:
                if self._queue.empty() and not self._busy:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                job = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                self._busy = True
            try:
                self._deliver(job)
            except Exception:
                traceback.print_exc()
            finally:
                with self._lock:
                    self._busy = False
                self._queue.task_done()

    def _deliver(self, job: WebhookJob) -> None:
        try:
            # Resolved from the module namespace at call time, like
            # MailQueue's own send — so a test that replaces
            # alertmail.send_webhook is honoured for jobs already queued.
            send_webhook(job.url, job.headers, job.timeout, job.payload)
        except Exception as exc:
            self._finish(job, False, str(exc) or exc.__class__.__name__)
        else:
            self._finish(job, True, "")

    def _finish(self, job: WebhookJob, ok: bool, error: str) -> None:
        if self._on_result is None:
            return
        try:
            self._on_result(job, ok, error)
        except Exception:
            traceback.print_exc()

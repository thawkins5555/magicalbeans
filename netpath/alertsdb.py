"""Storage for the Alerts module: rules, open/acknowledged/resolved alerts,
email templates, notification history, SMTP settings and credential, and
per-source evaluation cursors. At most one OPEN or ACKED alert exists per
`dedup_key` (a partial unique index, since the key recurs after a resolve);
a repeat increments that alert's `count` rather than opening a duplicate.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
from urllib.parse import urlparse

from . import alertrules
from .sqlitebase import SqliteStore, reclaim

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY,
    key             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,          -- 'device_event'|'interface_event'|'threshold'|'dhcp_threshold'|'netpath_threshold'|'trap'|'syslog'|'ipam'|'wireless_event'|'system'
    source_kind     TEXT,                   -- meaning depends on kind, see nodesdb/alertrules
    severity        INTEGER NOT NULL DEFAULT 4,   -- syslog 0-7 scale, shared across every module
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_builtin      INTEGER NOT NULL DEFAULT 0,
    device_filter   TEXT NOT NULL DEFAULT '',
    -- Whether this rule's alerts send email at all. A rule can be worth
    -- recording and not worth mailing about: mib_missing opens on every
    -- device with a recognised enterprise arc and no uploaded MIB, which on
    -- a fresh 250-device install is 234 emails in the first minute about a
    -- housekeeping task.
    notify          INTEGER NOT NULL DEFAULT 1,
    threshold       REAL,
    clear_threshold REAL,
    -- Which side of `threshold` is the fault: 'above' (default), or
    -- 'below' for a falling-is-bad metric (an optic's receive power),
    -- whose clear_threshold then sits ABOVE its threshold. See
    -- alertrules.breaches/evaluate_threshold.
    comparison      TEXT NOT NULL DEFAULT 'above',
    for_polls       INTEGER NOT NULL DEFAULT 1,
    -- Flapping rules only. NULL means "use the shipped defaults" so an
    -- upgraded install behaves exactly as before until someone changes it;
    -- see alertrules.evaluate_flapping.
    flap_window_s        INTEGER,
    flap_min_transitions INTEGER,
    -- Threshold rules only: require the breach to have lasted this many
    -- seconds of real sample time before alerting. NULL means "use
    -- for_polls" — the same NULL-is-the-shipped-default convention as the
    -- two flapping columns above. See alertrules.evaluate_threshold.
    for_seconds          INTEGER,
    -- Resolve an alert this rule opened once its last occurrence is this
    -- many seconds old. NULL (the default, and right for every rule about a
    -- STATE) means never: a device that is still down must stay open until
    -- it comes back. Set for the rules about a momentary EVENT — a reboot,
    -- a recovery notice, a trap — where nothing will ever clear the alert
    -- because the thing it reports already finished happening.
    auto_resolve_after_s INTEGER,
    template_id     INTEGER REFERENCES templates(id) ON DELETE SET NULL,
    created_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS templates (
    id              INTEGER PRIMARY KEY,
    key             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    is_html         INTEGER NOT NULL DEFAULT 0,
    is_builtin      INTEGER NOT NULL DEFAULT 0,
    builtin_subject TEXT,
    builtin_body    TEXT,
    updated_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    rule_id         INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    dedup_key       TEXT NOT NULL,
    entity_kind     TEXT NOT NULL,           -- 'device'|'interface'|'trap'|'syslog'|'ipam'
    entity_id       TEXT NOT NULL,
    entity_label    TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    message         TEXT NOT NULL,
    detail          TEXT,
    state           TEXT NOT NULL DEFAULT 'open',  -- open|acked|resolved
    count           INTEGER NOT NULL DEFAULT 1,
    opened_ts       REAL NOT NULL,
    last_ts         REAL NOT NULL,
    acked_ts        REAL,
    acked_by        TEXT,
    ack_note        TEXT,
    resolved_ts     REAL,
    resolved_by     TEXT,
    -- When a notification was last SUBMITTED for this alert, which is not
    -- last_ts: open_or_increment refreshes last_ts on every recurrence, so
    -- comparing against it made renotify_minutes unsatisfiable. See
    -- alerts_due_renotify.
    last_notified_ts REAL,
    -- The occurrence's template extras as JSON, so a renotify raised by the
    -- per-tick sweep (rather than by a fresh occurrence) can still render
    -- {{value}}, {{trap_name}} and the rest.
    extra_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_alerts_state_ts ON alerts(state, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_rule ON alerts(rule_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_active_dedup
    ON alerts(dedup_key) WHERE state IN ('open', 'acked');

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY,
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,           -- 'alert'|'renotify'|'clear'|'test'
                                              -- or the webhook channel's own
                                              -- 'webhook_'-prefixed versions
                                              -- of the same four (see
                                              -- alertengine._webhook_notify)
    ts              REAL NOT NULL,
    to_addr         TEXT NOT NULL,
    subject         TEXT NOT NULL,
    ok              INTEGER NOT NULL,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS ix_notifications_ts ON notifications(ts);
CREATE INDEX IF NOT EXISTS ix_notifications_alert ON notifications(alert_id);

-- Evaluation cursors: how far each source has already been drained, so a
-- restart does not re-evaluate a source's whole history as new occurrences.
CREATE TABLE IF NOT EXISTS meta (
    source          TEXT PRIMARY KEY,
    cursor_id       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Migrations that cannot run inside _migrate() because they depend on the
-- built-in templates and rules having been seeded first (_migrate runs
-- before _seed_templates/_seed_rules, and must, since seeding needs the
-- columns it adds). Each runs once, ever, keyed by name.
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT PRIMARY KEY,
    applied_ts REAL NOT NULL
);

-- A DPAPI blob cannot live in the generic JSON `settings` table alongside
-- ordinary string/number values, so it gets its own single-row table.
CREATE TABLE IF NOT EXISTS smtp_credential (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_enc BLOB
);

-- Per-device overrides of a threshold rule's own numbers. Generic over
-- rule_key rather than a temp-specific table: a core switch in a hot closet
-- and an access switch in a comms room do not share a sane chassis-
-- temperature threshold, and neither will CPU or memory once a site wants
-- the same per-device tuning for those — one table, keyed by whichever
-- threshold-kind rule it overrides, serves all of them with no further
-- migration.
--
-- threshold/clear_threshold NULL means "inherit the rule's own value" —
-- the same NULL-is-the-shipped-default convention rules.flap_window_s and
-- friends already use above — so an override that only wants to disable a
-- rule for one device (enabled=0) does not also have to restate its
-- numbers. enabled=0 means the rule never fires for this device at all,
-- distinct from setting threshold sky-high: it also has no clear_threshold
-- to speak of, and reads as "off" on the device's own page rather than a
-- number an operator has to interpret.
--
-- No id/rowid surrogate: (device_id, rule_key) is exactly the fact this
-- table records — at most one override per rule per device — so it is the
-- natural primary key, and AlertEngine.device_threshold_map's per-tick read
-- (see alertengine._evaluate_thresholds) wants exactly this device_id ->
-- row shape with no join required to get there.
CREATE TABLE IF NOT EXISTS device_thresholds (
    device_id       INTEGER NOT NULL,
    rule_key        TEXT NOT NULL,
    threshold       REAL,
    clear_threshold REAL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    updated_ts      REAL NOT NULL,
    PRIMARY KEY (device_id, rule_key)
);
"""

DEFAULTS = {
    "enabled": True,
    "min_severity": 7,             # evaluate this severity and worse (7 = everything)
    "retention_days": 180,          # resolved alerts + notification history
    # SMTP
    "email_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",    # none|starttls|ssl
    "smtp_verify_cert": True,
    "smtp_username": "",
    "smtp_from": "",
    "smtp_from_name": "SappiWhere",
    "smtp_to_default": [],          # fallback recipients
    "smtp_timeout_s": 15.0,
    # volume control
    # Distinct from min_severity above (a filter on syslog INGEST): a
    # numerically-higher alert still opens and lists, only the mailbox is
    # spared. Not applied to the webhook channel, which has its own gate.
    "notify_min_severity": 7,
    "renotify_minutes": 0,          # 0 = notify once per open alert, never again while open
    "notify_on_clear": True,
    "max_emails_per_hour": 60,
    # An alert's first email waits this long after it opens before going
    # out, so a mass outage's worth of alerts — each one real, each one
    # opening within seconds of the last while a poll cycle works through a
    # dead site — coalesce into one digest instead of one email apiece, and
    # so an alert that clears or gets rolled up under another one within the
    # wait never has to be un-sent. The alert itself still opens immediately
    # in the UI and database; only the OUTBOUND EMAIL is held. 0 disables
    # the hold — an alert's first notice goes out the moment it opens, the
    # only behaviour this database has ever had before this setting existed.
    # See AlertEngine._sweep_notify_rollup.
    "notify_rollup_delay_s": 240,
    # A device added a moment ago is usually mid-setup: wrong community, not
    # cabled yet, still booting. Alerts for it are held this long and then
    # fired only if the condition is still true. 0 disables the hold.
    "new_device_grace_s": 300,
    # When a device stops answering, resolve and suppress the alerts that only
    # restate the outage — high ping time, packet loss, and every SNMP-polled
    # metric — leaving one "Device not responding". See alertrules.ROLLED_UP_BY
    # for exactly which, and why interface alerts are not among them.
    "rollup_enabled": True,
    # A metric sample older than this is treated as absent by the threshold
    # evaluator: the streak resets and no occurrence is raised from it. Not a
    # multiple of the poll interval, because the interval is per profile and
    # per device while this is one number an operator can reason about; 900 s
    # is comfortably longer than the shipped 120 s interval with room for a
    # slow poll and a missed one. 0 disables the check, restoring the
    # pre-4.37 behaviour of alerting from a value of any age.
    "threshold_stale_s": 900,
    # Comma-joined column keys the alert table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
    # Outbound webhook: one HTTP POST per notification, alongside (or instead
    # of) email — Slack/Teams/PagerDuty/a ticketing system all speak this,
    # so one channel buys every one of them rather than shipping a client
    # for each. See alertmail.send_webhook and AlertEngine._webhook_notify.
    "webhook_enabled": False,
    "webhook_url": "",
    # "Name: value" lines, same shape smtp_to_default's own list-of-strings
    # setting already uses, so the settings type machinery (coerce_settings)
    # needs no new case. Parsed at send time — see alertmail.parse_headers.
    "webhook_headers": [],
    "webhook_timeout_s": 10.0,
    # A webhook receiver is a machine, not an inbox: max_emails_per_hour's
    # 60 is sized for a person's mailbox, and a Slack/PagerDuty endpoint can
    # take far more before anyone notices. Its own budget rather than
    # sharing the email one, so turning webhooks on for a big fleet does not
    # eat into the mail quota an operator already tuned.
    "webhook_max_per_hour": 600,
}

PENDING_SCHEMA = """
-- Occurrences held back because their device was added less than
-- new_device_grace_s ago. Held in the database rather than in memory so a
-- restart inside the window does not silently drop them, and so an operator
-- can see what is waiting. Each row is one occurrence, replayed and
-- re-checked once its time comes.
CREATE TABLE IF NOT EXISTS pending_alerts (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL,
    fire_after_ts REAL    NOT NULL,
    created_ts    REAL    NOT NULL,
    payload       TEXT    NOT NULL      -- the Occurrence, as JSON
);
CREATE INDEX IF NOT EXISTS ix_pending_due ON pending_alerts(fire_after_ts);

-- Entities whose new alerts are suppressed until until_ts: an operator
-- working on a device silences it for an hour rather than watching the same
-- outage arrive six times. entity_kind is "device" today; the column exists
-- so a future per-interface or per-AP mute needs no migration.
--
-- A mute stops what happens NEXT. Alerts already open stay open and are
-- worked normally — hiding them would lose the operator's own place in the
-- list. Nothing has to un-suppress when a mute lapses either: thresholds
-- re-derive from live metrics on the next tick and a still-down device
-- keeps recording events, so the alerts simply come back.
CREATE TABLE IF NOT EXISTS alert_mutes (
    id          INTEGER PRIMARY KEY,
    entity_kind TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    until_ts    REAL NOT NULL,
    created_ts  REAL NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mute_entity
    ON alert_mutes(entity_kind, entity_id);

-- A planned period during which alerts for a scope of devices behave as
-- though every one of them were muted: a weekend cutover, a maintenance
-- window on a site, a firmware rollout. Distinct from alert_mutes rather
-- than another row shape in it, because a window has a scope (a device
-- group, or an explicit list) and a fixed start/end an operator sets in
-- advance, where a mute is always "this one device, starting now, for N
-- hours" — cramming both into one table would make every mute reader carry
-- branches for a shape that ad-hoc muting never uses. What they share is the
-- ANSWER, not the storage: is_window_active + window_covered_device_ids
-- resolve a window down to the same {entity_id: until_ts} shape mutes()
-- already produces, and every reader (the engine's occurrence gate, the
-- device list, the single-device page) folds the two together there. See
-- muted_entity_ids and AlertEngine._muted/_muted_alert.
--
-- scope_kind is 'group' (every device currently in scope_group_id — a
-- device added to the group mid-window is covered, one added to a NEW group
-- of the same name is not, which is what "the group" means) or 'devices'
-- (exactly the ids in scope_device_ids, a JSON array, chosen once at
-- creation). Nullable columns rather than two tables, matching alert_mutes'
-- own "general enough for the next shape, no migration to add it" reasoning
-- above.
--
-- recurrence is NULL (a one-off window, exactly [start_ts, end_ts)) or
-- 'weekly' (the same clock-time span recurs every 7 days from start_ts,
-- forever, until the window is deleted or edited) — see is_window_active.
-- Deliberately the only two shapes: "none or weekly" covers the recurring
-- weekend cutover, and a monthly calendar is a feature in its own right.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    scope_kind        TEXT NOT NULL,       -- 'group'|'devices'
    scope_group_id    INTEGER,             -- nodesdb device_groups.id, when 'group'
    scope_device_ids  TEXT,                -- JSON array of device ids, when 'devices'
    start_ts          REAL NOT NULL,
    end_ts            REAL NOT NULL,
    recurrence        TEXT,                -- NULL|'weekly'
    created_ts        REAL NOT NULL,
    created_by        TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_maint_windows_start ON maintenance_windows(start_ts);
"""

# How long a mute may last. The dropdown offers 1/6/12/24 hours; the cap is
# here so a hand-made API call cannot silence a device until next year.
MAX_MUTE_HOURS = 24.0

# How long a single maintenance window occurrence may span. Long enough for
# any real cutover (a "weekend" is 60 hours) with room to spare; short enough
# that a fat-fingered end date years out cannot silence a device group
# indefinitely under the banner of "maintenance" rather than a mute. Applies
# to end_ts - start_ts, which for a weekly recurrence is the length of each
# WEEK's occurrence, not how long the window recurs for — a weekly window has
# no end date at all, see is_window_active.
MAX_WINDOW_DAYS = 14.0

_WEEK_S = 7 * 86400.0


def is_window_active(row, now: float | None = None) -> bool:
    """Whether `row` (a maintenance_windows row) covers anything right now.

    A one-off window (recurrence NULL) is the plain interval test. A weekly
    one recurs every 7 days from start_ts forever: `elapsed` is how far `now`
    sits into the current 7-day cycle, and the window is active exactly when
    that is still inside the occurrence's own duration — the same
    (end_ts - start_ts) span, replayed every week. A non-positive duration
    (a corrupt or hand-edited row) never matches, rather than matching
    everything forever the way a naive modulo could.
    """
    now = time.time() if now is None else now
    duration = row["end_ts"] - row["start_ts"]
    if duration <= 0:
        return False
    if row["recurrence"] == "weekly":
        if now < row["start_ts"]:
            return False
        return (now - row["start_ts"]) % _WEEK_S < duration
    return row["start_ts"] <= now < row["end_ts"]


def _window_occurrence_end(row, now: float) -> float:
    """When the CURRENT occurrence of `row` stops covering anything — for a
    one-off window, its own end_ts; for a weekly one, the end of this
    week's span (not next week's, and not the window's own end_ts, which for
    a recurring window is only the first occurrence's)."""
    duration = row["end_ts"] - row["start_ts"]
    if row["recurrence"] == "weekly":
        elapsed = (now - row["start_ts"]) % _WEEK_S
        return now - elapsed + duration
    return row["end_ts"]

# The sane range for notify_rollup_delay_s: coerce_settings only checks that
# it is a number, never that it is a sensible one, so a hand-made API call
# (or a fat-fingered UI value before the browser's own min= clamps it) could
# otherwise hold an alert's first email for a year. Clamped here, in
# settings(), rather than only where AlertEngine reads it, so every reader —
# the engine, the settings API response, a future one — sees the same
# already-sane number rather than each having to know the limit itself.
NOTIFY_ROLLUP_DELAY_MAX_S = 3600

# How far past notify_rollup_delay_s's own cutoff alerts_due_first_notify
# still looks for a genuinely pending alert, beyond which a never-notified
# alert is treated as history rather than something still owed a decision.
# Exists for the upgrade case: turning notify_rollup_delay_s on (4.47's
# default, 240s) for the first time makes EVERY alert this database has
# ever held with last_notified_ts still NULL "due" by the plain opened_ts
# <= cutoff test alone — months of long-resolved alerts nobody was ever
# going to email about, all landing on the first sweep after the upgrade
# as misleading "cleared within the roll-up window" rows, or (worse) all
# in one digest. An hour of grace on top of the delay is generous room for
# an engine outage that genuinely held a real alert's first notice — see
# _sweep_notify_rollup's restart-safety — while still drawing a firm line
# under "this is backlog, not a pending notification".
FIRST_NOTIFY_BACKLOG_GRACE_S = 3600.0


def _webhook_host_is_local(host: str) -> bool:
    """Whether `host` is loopback or an RFC1918 private address — the two
    cases plaintext http is allowed for a webhook URL, on the reasoning that
    both stay on this machine or this network and never cross the open
    internet in the clear. A bare hostname that is not a literal IP (and is
    not "localhost") answers False: without a DNS lookup here there is no
    honest way to know where it resolves, and refusing http for anything
    that is not OBVIOUSLY local is the safe default."""
    host = (host or "").strip().lower()
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def validate_webhook_url(url: str) -> None:
    """Raise ValueError for a webhook_url this application should refuse to
    save, not just refuse to send to. An empty string (webhooks off, or not
    yet configured) is always fine.

    https is required unless the host is loopback or RFC1918 — the same
    trust level the SMTP relay setting already gets (an operator-configured
    endpoint, not user input), but a webhook receiver is far more likely to
    sit on the open internet (Slack, PagerDuty, a ticketing SaaS) than an
    SMTP relay ever is, so plaintext is the exception here rather than the
    rule smtp_security defaults to. The scheme and redirect checks are
    repeated at SEND time in alertmail.send_webhook — this function only
    stops a bad URL from being saved in the first place, it is not the only
    guard.
    """
    url = (url or "").strip()
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("webhook_url must be an http:// or https:// URL")
    if parsed.scheme == "http" and not _webhook_host_is_local(parsed.hostname or ""):
        raise ValueError(
            "webhook_url must use https:// unless it points at localhost or"
            " a private (RFC1918) address")


def _check_published_threshold(rule_key: str, threshold, clear_threshold) -> None:
    """Raise ValueError if a number is being set on a rule whose threshold
    the PORT publishes (alertrules.PUBLISHED_THRESHOLD_RULES).

    Both writers — the rule editor and the per-device override — would
    otherwise accept the number, validate it, store it, and then have the
    engine ignore it for ever. The first operator to investigate a dark
    port would type a figure, watch nothing happen and conclude the feature
    is broken. Refusing out loud is the only honest answer.

    Only the NUMBERS are refused. Turning a rule off for one switch
    (enabled=False, both numbers None) is a statement about that switch and
    stays allowed.
    """
    if rule_key not in alertrules.PUBLISHED_THRESHOLD_RULES:
        return
    if threshold is None and clear_threshold is None:
        return
    raise ValueError(
        f"'{rule_key}' is judged against the limits each port's own optic "
        "publishes, so a threshold set here would be ignored. Nothing to "
        "set: a port alerts where its switch publishes limits and nowhere "
        "else.")


def _check_threshold_direction(rule, threshold, clear_threshold, *,
                               comparison: str | None = None,
                               allow_equal: bool = False) -> None:
    """Raise ValueError if `threshold`/`clear_threshold` (either may be None,
    meaning "inherit `rule`'s own value") would leave nothing to clear
    through.

    Which side is which is `comparison`'s to say. A clear on the wrong side
    of threshold is not a tuning choice, it is an alert that can never close.

    `allow_equal` is the difference between the two callers: a device
    OVERRIDE demands a real gap, while the RULE editor allows equal
    thresholds, since several shipped rules use them on purpose for a
    quantised metric with no gap to leave.

    Only checked when the CALLER is actually setting one of the two numbers.
    A call that only touches `enabled` (both None, pure inherit) has nothing
    numeric to validate -- rejecting it would refuse a plain "turn this rule
    off for one device" on the three rules above whose OWN shipped threshold
    equals its own clear_threshold, over a comparison that call never asked
    for.
    """
    if threshold is None and clear_threshold is None:
        return
    effective_threshold = rule["threshold"] if threshold is None else threshold
    effective_clear = rule["clear_threshold"] if clear_threshold is None else clear_threshold
    if effective_threshold is None or effective_clear is None:
        return
    if comparison is None:
        comparison = alertrules.comparison_of(rule)
    if comparison == "below":
        ok = (effective_clear >= effective_threshold if allow_equal
              else effective_clear > effective_threshold)
        side = "above"
    else:
        ok = (effective_clear <= effective_threshold if allow_equal
              else effective_clear < effective_threshold)
        side = "below"
    if not ok:
        raise ValueError(
            f"clear_threshold ({effective_clear}) must be {side} threshold"
            f" ({effective_threshold}) for rule '{rule['key']}', or the"
            " alert could never clear")


_RULE_EDITABLE = ("name", "severity", "enabled", "device_filter", "threshold",
                  "clear_threshold", "comparison", "for_polls", "for_seconds",
                  "template_id", "flap_window_s", "flap_min_transitions",
                  "auto_resolve_after_s", "notify")
_RULE_CUSTOM_EDITABLE = _RULE_EDITABLE + ("kind", "source_kind")

# 55 built-in rules: 8 device_event + 3 interface_event + 29 threshold +
# 3 trap + 1 syslog + 1 ipam + 2 wireless_event + 1 dhcp_threshold +
# 3 netpath_threshold + 4 system. Each `template` name is a
# templates.key —
# most non-primary rules reuse a generic template rather than a bespoke
# one, since only 6 ship; an admin can point any rule at any template.
_BUILTIN_RULES = [
    # key, name, kind, source_kind, severity, template, threshold, clear_threshold, for_polls
    ("device_down", "Device not responding", "device_event", "down", 1, "device_down", None, None, 1),
    ("device_up", "Device recovered", "device_event", "up", 5, "device_up", None, None, 1),
    ("device_rebooted", "Device rebooted", "device_event", "rebooted", 4, "device_rebooted", None, None, 1),
    ("device_auth_fail", "SNMP authentication failing", "device_event", "auth_fail", 3, "event_notice", None, None, 1),
    ("device_unsupported", "Device requires unsupported SNMP privacy", "device_event", "unsupported", 5, "event_notice", None, None, 1),
    ("poll_overrun", "Poll taking longer than its interval", "device_event", "poll_overrun", 4, "event_notice", None, None, 1),
    ("mib_missing", "Vendor MIB not uploaded for this device", "device_event", "mib_missing", 6, "event_notice", None, None, 1),
    # A device that answers ping while SNMP fails is invisible to
    # device_down (which is about reachability) and to every threshold rule
    # (whose metrics simply stop arriving), so the most common half-failure
    # in a fleet had no rule at all. The poller records an snmp_error device
    # event for it.
    ("snmp_failing_ping_ok", "SNMP failing while the device answers ping", "device_event", "snmp_error", 3, "event_notice", None, None, 1),
    ("interface_down", "Interface down", "interface_event", "link_down", 3, "event_notice", None, None, 1),
    ("interface_up", "Interface recovered", "interface_event", "link_up", 6, "device_up", None, None, 1),
    ("interface_flapping", "Interface flapping", "interface_event", "flapping", 3, "event_notice", None, None, 1),
    ("cpu_high", "CPU utilization high", "threshold", "cpu_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("mem_high", "Memory utilization high", "threshold", "mem_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_in_util_high", "Interface inbound utilization high", "threshold", "if_in_util_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_out_util_high", "Interface outbound utilization high", "threshold", "if_out_util_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_in_errors_high", "Interface inbound error rate high", "threshold", "if_in_error_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_out_errors_high", "Interface outbound error rate high", "threshold", "if_out_error_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_in_discards_high", "Interface inbound discard rate high", "threshold", "if_in_discard_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_out_discards_high", "Interface outbound discard rate high", "threshold", "if_out_discard_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("disk_high", "Storage utilization high", "threshold", "disk_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    # UPS-MIB (nodeoids.UPS_HEALTH) and the environmental-sensor poll
    # (nodepoll._poll_environment) both feed the threshold evaluator, which
    # only ever asks "is this number at or above X" (see
    # alertrules.evaluate_threshold) — every rule below is written so that
    # question is the right one to ask of its metric.
    #
    # ups_on_battery reads ups_on_battery_s (upsSecondsOnBattery) rather
    # than the more obvious-looking ups_output_source (upsOutputSource,
    # 3 = normal, 5 = battery): the evaluator has no notion of "equals",
    # only ">=", and >= 5 would also fire on booster(6) and reducer(7) —
    # real conditions, but not the one this rule is named for.
    # upsSecondsOnBattery is 0 on mains and a genuine elapsed count the
    # instant a UPS switches over, so >= 1 means exactly "on battery right
    # now" with no adjacent enum value to accidentally include. Zero
    # hysteresis (threshold == clear_threshold) is deliberate, the same
    # call netpath_unreachable below already makes for a quantised metric
    # that does not hover near a boundary the way a continuous one does —
    # a UPS is either running off the mains or it is not.
    ("ups_on_battery", "UPS running on battery power", "threshold", "ups_on_battery_s", 2, "threshold_breach", 1.0, 1.0, 1),
    # upsBatteryStatus (2 normal / 3 low / 4 depleted) is an ordered enum
    # where higher already means worse, so both rules below read it
    # directly with no inversion needed, at two different floors and two
    # different severities: batteryLow is worth a prompt look, but
    # batteryDepleted is the "replace it" alarm the gap analysis named.
    # Zero hysteresis again — an enum has no meaningful gap to leave.
    ("ups_battery_low", "UPS battery low", "threshold", "ups_battery_status", 3, "threshold_breach", 3.0, 3.0, 1),
    ("ups_battery_replace", "UPS battery depleted, replace it", "threshold", "ups_battery_status", 2, "threshold_breach", 4.0, 4.0, 1),
    ("ups_load_high", "UPS output load high", "threshold", "ups_output_load_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    # Temperature shipped as ONE rule over ONE metric key (temp_c) for
    # about a day of this campaign, and it was wrong: nodepoll writes a
    # room's ambient reading, a switch's own internal chassis reading and
    # an SFP's DOM reading through completely different normal ranges — a
    # comms closet alarms around 30 C, a switch chassis is fine at 45,
    # and an optic's DOM commonly runs 40-55 C by design (that spread is
    # the entire reason DOM exists). One threshold over all three read as
    # ten false "Temperature high" alerts on a 25-device fleet with
    # healthy switches and exactly one or two Room Alerts in it — the
    # same mib_missing email-storm shape a prior review of this product
    # already burned an operator's trust on once (see _BUILTIN_NOTIFY_OFF
    # above). nodepoll._poll_environment now classifies every temperature
    # reading into one of three metric keys before it is ever stored
    # (using the same ENTITY-SENSOR containment walk read_dom already
    # does, plus "does this device also have a humidity sensor" as the
    # room-vs-chassis signal — see that function's docstring for the
    # full reasoning), so each of the three rules below only ever sees
    # readings of its own kind and can carry a threshold that kind
    # actually means something at. All three are a starting point for a
    # site to tune, not a physical constant.
    #
    # Ambient: ASHRAE's own allowable (not merely recommended) range for
    # networking gear tops out around 35 C; 30/25 gives an operator
    # warning before a room reaches that ceiling rather than after.
    ("temp_ambient_high", "Ambient temperature high", "threshold", "temp_ambient_c", 4, "threshold_breach", 30.0, 25.0, 2),
    # Chassis: comfortably above the "45 C is fine" a healthy switch runs
    # at, in line with the internal-board alarm thresholds vendors
    # themselves ship (Cisco/Juniper environmental major-alarm levels
    # commonly sit in the 75-85 C range for this kind of sensor).
    ("temp_chassis_high", "Chassis temperature high", "threshold", "temp_chassis_c", 4, "threshold_breach", 75.0, 65.0, 2),
    # Critical sits ABOVE temp_chassis_high on the same metric, on purpose:
    # a chassis climbing past the vendor major-alarm range warrants a second,
    # more urgent alert rather than only a louder version of the first one.
    # severity 2 is this scale's actual "critical" (see alertrules.
    # SEVERITY_NAMES[2]) — 4 (temp_chassis_high's own "warning") would have
    # made the two indistinguishable in the inbox and on the severity filter.
    # Both rules reading temp_chassis_c means a device at 90 C breaches both;
    # alertrules.ROLLED_UP_BY suppresses temp_chassis_high while Critical is
    # open so that is one alert, not two saying the same thing at different
    # volumes — see that map's own comment for why this is a ROLLED_UP_BY
    # case rather than an outage rollup. temp_chassis_high itself is
    # UNCHANGED — same key, same name, same shipped 75.0/65.0 — so an
    # upgraded install's already-seeded rule (and any operator tuning of it)
    # survives exactly as it was.
    ("temp_chassis_critical", "Chassis temperature critical", "threshold", "temp_chassis_c", 2, "threshold_breach", 85.0, 78.0, 2),
    # Optic: comfortably above the "40-55 C is normal DOM" range, in line
    # with SFF-8472's own typical vendor-set high-warning/high-alarm
    # thresholds for a commercial-temperature transceiver.
    ("temp_optic_high", "Optic temperature high", "threshold", "temp_optic_c", 4, "threshold_breach", 80.0, 70.0, 2),
    # DOM keys nodepoll writes per interface (sfp_rx_dbm.<if>, etc.), so
    # each alerts on the port rather than the device.
    #
    # All eight ship with NO threshold at all, and that is the whole point
    # of the 5.3.0 change. A light level that means "failing" is a property
    # of the PART, not of the fleet: -22 dBm is comfortably inside a ZR
    # part's working range and already dead for an SR one, so the single
    # configurable number these two rules used to carry was wrong for most
    # of the optics it judged. Each port is now judged against the levels
    # its own transceiver publishes, learned by the poller into nodes.db's
    # interface_thresholds and read through
    # alertrules.PUBLISHED_THRESHOLD_RULES -- so a port whose switch
    # publishes nothing raises no optical power alert at all, which is the
    # honest answer and the one the operator chose over a global fallback.
    #
    # Four bands x two directions, because the transceiver publishes four:
    # the warning half is "look at this", the alarm half is "this is
    # failing now", and ROLLED_UP_BY pairs each warning under its alarm so
    # a port past both is one alert rather than two saying the same thing
    # at different volumes -- the temp_chassis_high/critical shape. Severity
    # 2 is this scale's actual "critical" (alertrules.SEVERITY_NAMES[2]).
    #
    # sfp_rx_power_low and sfp_tx_power_low keep their key, name, severity,
    # template and for_polls exactly as shipped, so an upgraded install's
    # tuning of any of those survives; only their threshold columns are
    # retired (see _clear_optic_power_thresholds).
    ("sfp_rx_power_low", "Optic receive power low", "threshold", "sfp_rx_dbm", 4, "threshold_breach", None, None, 2),
    ("sfp_rx_power_low_alarm", "Optic receive power critically low", "threshold", "sfp_rx_dbm", 2, "threshold_breach", None, None, 2),
    ("sfp_rx_power_high", "Optic receive power high", "threshold", "sfp_rx_dbm", 4, "threshold_breach", None, None, 2),
    ("sfp_rx_power_high_alarm", "Optic receive power critically high", "threshold", "sfp_rx_dbm", 2, "threshold_breach", None, None, 2),
    ("sfp_tx_power_low", "Optic transmit power low", "threshold", "sfp_tx_dbm", 4, "threshold_breach", None, None, 2),
    ("sfp_tx_power_low_alarm", "Optic transmit power critically low", "threshold", "sfp_tx_dbm", 2, "threshold_breach", None, None, 2),
    ("sfp_tx_power_high", "Optic transmit power high", "threshold", "sfp_tx_dbm", 4, "threshold_breach", None, None, 2),
    ("sfp_tx_power_high_alarm", "Optic transmit power critically high", "threshold", "sfp_tx_dbm", 2, "threshold_breach", None, None, 2),
    # Reads sfp_temp_c.<if>, distinct from temp_optic_high's device-wide
    # temp_optic_c. 70 C is inside SFF-8472's typical high-warning range.
    ("sfp_temp_high", "Optic temperature high (per port)", "threshold", "sfp_temp_c", 4, "threshold_breach", 70.0, 65.0, 2),
    # RH above ~80% starts to risk condensation on anything metal in the
    # room — unambiguous on its own: nothing but a dedicated environmental
    # monitor answers a humidity sensor at all, so this one metric key
    # never needed splitting.
    ("humidity_high", "Humidity high", "threshold", "humidity_pct", 4, "threshold_breach", 80.0, 70.0, 2),
    ("response_time_high", "Ping response time high", "threshold", "ping_rtt_ms", 5, "threshold_breach", 500.0, 300.0, 2),
    # Live from 4.25, when the poller started sending several probes per
    # poll and recording ping_loss_pct/ping_rtt_ms as real metrics; before
    # that both this and response_time_high above had no metric to read.
    ("packet_loss_high", "Packet loss to device high", "threshold", "ping_loss_pct", 4, "threshold_breach", 20.0, 5.0, 2),
    ("trap_critical", "Critical SNMP trap received", "trap", "", 2, "trap_forwarded", None, None, 1),
    ("trap_cold_start", "Device cold start trap", "trap", "coldStart", 4, "trap_forwarded", None, None, 1),
    ("trap_link_down_unmanaged", "Link-down trap from an unmanaged device", "trap", "linkDown", 3, "trap_forwarded", None, None, 1),
    ("syslog_critical", "Critical syslog message", "syslog", "", 2, "trap_forwarded", None, None, 1),
    ("ipam_new_conflict", "New IPAM address conflict", "ipam", "", 4, "trap_forwarded", None, None, 1),
    ("wireless_ap_removed", "Access point removed from its controller", "wireless_event", "ap_removed", 3, "event_notice", None, None, 1),
    # Distinct from ap_removed, and deliberately not rolled up under it: "the
    # controller lost this AP" and "the controller has it but it is not
    # working" are different facts with different remedies. An AP marked out
    # of service raises neither.
    ("wireless_ap_offline", "Access point offline", "wireless_event", "ap_offline", 3, "event_notice", None, None, 1),
    # DHCP scope utilization, as a percentage of the scope's address range
    # that is leased or reserved. Its own kind rather than a "threshold"
    # rule because the threshold evaluator reads Nodes' metrics table for a
    # Nodes device; a scope is neither. for_polls counts DHCP polls (every
    # 15 minutes by default), not engine ticks -- see
    # alertengine._evaluate_dhcp_thresholds.
    ("dhcp_scope_exhaustion", "DHCP scope running out of leases", "dhcp_threshold", "scope_utilization_pct", 3, "threshold_breach", 85.0, 75.0, 1),
    # NetPath destinations. Their own kind for the same reason DHCP has one:
    # the threshold evaluator reads Nodes' metrics table for a Nodes device,
    # and a traceroute destination is neither. for_polls counts that
    # destination's own traces (every 5 minutes by default), not engine ticks
    # -- see alertengine._evaluate_netpath_thresholds.
    #
    # All three ship deliberately hard to trip, because a path monitor that
    # cries wolf gets turned off:
    #
    # - Unreachable is 100% loss to the destination on three traces in a row,
    #   which on the shipped interval is a quarter of an hour of a destination
    #   answering nothing at all. It clears at 100 rather than at some lower
    #   figure because loss is quantised by the probe count and the clear test
    #   is `value < clear_threshold`: with the default 3 probes the only values
    #   are 0, 33.3, 66.7 and 100, so a clear of 50 left one answered probe
    #   (66.7) neither breaching nor clearing -- the alert stayed open, still
    #   labelled unreachable, while the destination was answering, and its
    #   rollup kept "path repeatedly failing" suppressed behind it. Clearing at
    #   100 means ANY answered probe ends it, at any probe count, which is what
    #   "unreachable" is supposed to mean. That leaves no hysteresis gap, and
    #   needs none: this metric does not drift around a threshold the way a
    #   continuous one does, and the three-trace streak is the anti-flap.
    # - Unstable is a windowed rule, and the only one of the three that can
    #   see a path that works intermittently -- consecutive-failure counting
    #   by definition cannot. Half the traces in the window must have failed,
    #   over at least five traces.
    # - Latency is measured against the destination's OWN warn threshold
    #   rather than a fixed millisecond figure, because "slow" means nothing
    #   across a LAN hop and a satellite link at once: 300 is three times
    #   whatever that destination is already configured to warn at, floored so
    #   a destination warned at a handful of milliseconds does not alert on
    #   ordinary jitter.
    ("netpath_unreachable", "NetPath destination unreachable", "netpath_threshold", "trace_loss_pct", 2, "threshold_breach", 100.0, 100.0, 3),
    ("netpath_path_unstable", "NetPath path repeatedly failing", "netpath_threshold", "trace_unreached_pct", 4, "threshold_breach", 50.0, 20.0, 1),
    ("netpath_latency_high", "NetPath latency far above normal", "netpath_threshold", "trace_rtt_warn_pct", 4, "threshold_breach", 300.0, 150.0, 3),
    # kind='system' is the application reporting on itself. Its occurrences
    # come from AlertEngine.system_occurrence rather than from a source
    # cursor, and source_kind is the rule key so one system condition matches
    # one system rule. No email is ever sent for a system rule (see
    # AlertEngine._notify): this one exists precisely because email is not
    # working, and the others would be reporting a fault in the machinery
    # they would have to use.
    ("smtp_failing", "Alert email is not being delivered", "system", "smtp_failing", 2, "event_notice", None, None, 1),
    # Raised by the poller when every worker is busy and the queue is not
    # draining: polls are being skipped, so every other rule in this table is
    # quietly evaluating stale data. Its own rule rather than a log line,
    # because "why did nothing alert" deserves an answer on the Alerts page.
    ("poll_pool_saturated", "Polling pool saturated — polls are being skipped", "system", "poll_pool_saturated", 3, "event_notice", None, None, 1),
    # Raised by the maintenance sweep once it has trimmed everything it can
    # and a database is still close to its cap: from here on every pass
    # deletes history to stay under it, which is a decision about how much
    # the site keeps and belongs with an operator rather than in a log line.
    # One alert per database — the store name is the entity_id.
    ("db_near_cap", "A database is close to its size cap", "system", "db_near_cap", 3, "event_notice", None, None, 1),
    # And the case no cap can help with. A cap governs one file; a volume
    # with nothing left stops every one of them writing at once.
    ("disk_space_low", "The volume holding the databases is low on free space", "system", "disk_space_low", 3, "event_notice", None, None, 1),
]

# Kept apart from _BUILTIN_RULES, like _BUILTIN_FOR_SECONDS below. Absent
# means 'above'. Only the optic POWER rules are low-water, and only their
# low halves: too much light is a real fault too (an optic looped back short,
# or a ZR part into a short run), and the transceiver publishes a ceiling for
# it, so the four high keys read the ordinary way round.
_BUILTIN_COMPARISON = {
    "sfp_rx_power_low": "below",
    "sfp_rx_power_low_alarm": "below",
    "sfp_tx_power_low": "below",
    "sfp_tx_power_low_alarm": "below",
}

# Shipped for_seconds, kept apart from _BUILTIN_RULES rather than widening
# all 32 rows with a column only one of them uses. Absent means NULL, which
# evaluate_threshold reads as "count polls, don't measure time".
#
# Packet loss is the one threshold where a single bad sample is routine: a
# probe lost to a busy CPU or a queued ARP is not an outage, and with the
# default ping_count of 3 one lost probe already reads as 33%. Requiring the
# loss to persist for a minute of real sample time is what makes the alert
# mean "this link is lossy" rather than "a packet went missing".
_BUILTIN_FOR_SECONDS = {"packet_loss_high": 60}

# Shipped auto_resolve_after_s, kept apart from _BUILTIN_RULES for the same
# reason as _BUILTIN_FOR_SECONDS. Absent means NULL, which is "never".
#
# Eleven built-in rules had no auto-resolve path at all: not in the CLEARS
# map, and not a threshold that can drop below a clear value. A device that
# went down and came back left a "Device recovered" alert (severity 5,
# "responding again at ...") sitting in the open list until somebody clicked
# Resolve, and on a fleet with normal daily flapping that is hundreds of rows
# a day of pure bookkeeping — after which the open count stops meaning
# "things that are wrong" and people stop reading the badge.
#
# Every rule here reports a momentary EVENT rather than a state, so the
# question "is it still true" has no answer: it happened, once, at a known
# time. The intervals are how long that fact is worth keeping in front of an
# operator, which is why a reboot (worth noticing tomorrow morning) outlasts
# a recovery notice (worth noticing this shift) and an unsupported-privacy
# verdict (a procurement problem, not an incident) outlasts both.
#
# Deliberately absent: device_down, mib_missing, device_auth_fail,
# interface_down and every threshold. Those are states with a real clear —
# a device answering, a MIB uploaded, a value dropping — and expiring one
# would mean closing an alert about a fault that is still happening.
_BUILTIN_AUTO_RESOLVE_S = {
    "device_up": 3600,
    "device_rebooted": 86400,
    "device_unsupported": 604800,
    "poll_overrun": 3600,
    "interface_up": 3600,
    "interface_flapping": 1800,
    "trap_critical": 86400,
    "trap_cold_start": 3600,
    "trap_link_down_unmanaged": 86400,
    "syslog_critical": 86400,
    "ipam_new_conflict": 604800,
    # Both of these report a CONDITION through repeated events rather than
    # through a state with a clear, so last_ts is what says whether it is
    # still happening: while the condition holds the events keep arriving and
    # the alert stays current, and when it stops the alert closes on its own.
    # An hour is comfortably longer than any poll interval; fifteen minutes
    # matches how quickly a poll pool recovers once the backlog clears.
    "snmp_failing_ping_ok": 3600,
    "poll_pool_saturated": 900,
    # The same shape, on the maintenance sweep's clock: the sweep re-raises
    # an open one every fifteen minutes for as long as the condition holds —
    # the hold band between the clear and the raise threshold included, or
    # this would close the alert that band exists to hold open — and when the
    # condition ends the sweep's own clear closes it. Two sweeps rather than
    # one, because this is only the backstop for a service that stopped
    # mid-condition and will never clear it itself.
    "db_near_cap": 1800,
    "disk_space_low": 1800,
}

_BUILTIN_TEMPLATE_KEYS = ("device_down", "device_up", "device_rebooted",
                         "threshold_breach", "trap_forwarded", "event_notice")

# key -> the template a rule was bound to BEFORE 4.37, for the rules whose
# shipped binding changed to event_notice. The migration only re-points a
# rule still on exactly this template, so an admin who has already pointed
# one somewhere of their own keeps their choice.
_EVENT_NOTICE_REBIND = {
    "device_auth_fail": "device_down",
    "device_unsupported": "device_down",
    "poll_overrun": "device_down",
    "mib_missing": "device_down",
    "interface_down": "device_down",
    "interface_flapping": "device_down",
    "wireless_ap_removed": "device_down",
    "wireless_ap_offline": "device_down",
    # New in this release and never in an operator's hands bound to
    # trap_forwarded, whose body would render three empty trap fields.
    "smtp_failing": "trap_forwarded",
}

# Rules that ship with email off. mib_missing is the onboarding storm: every
# device with a recognised enterprise arc and no uploaded MIB opens one on
# its first poll, which is 234 alerts and 234 emails within a minute of
# seeding 250 devices. The alerts are useful — they are the to-do list for
# MIB uploads — and mailing them is not.
_BUILTIN_NOTIFY_OFF = ("mib_missing",)


def _builtin_rule_defaults() -> dict:
    """key -> the shipped {notify, threshold, clear_threshold} _seed_rules
    writes for a brand new row of that key. Derived from _BUILTIN_RULES and
    _BUILTIN_NOTIFY_OFF rather than duplicated by hand, so this can never
    drift out of step with what a fresh install actually gets — see
    AlertsDatabase._dampen_new_builtin_siblings, the one place that compares
    a live row against it."""
    return {
        key: {
            "notify": 0 if key in _BUILTIN_NOTIFY_OFF else 1,
            "threshold": threshold,
            "clear_threshold": clear_threshold,
        }
        for (key, _name, _kind, _source_kind, _severity, _template_key,
             threshold, clear_threshold, _for_polls) in _BUILTIN_RULES
    }


# General statement of "a new built-in sharing a source_kind with an
# existing one": new rule's key -> the already-shipped rule it reads the
# same source_kind as. temp_chassis_critical (4.54.0) is the first entry —
# see AlertsDatabase._dampen_new_builtin_siblings for what this drives. The
# next such pair (a new rule added beside one that already reads a metric or
# event an operator may have tuned) is a one-line addition here, not another
# migration.
_NEW_SIBLING_OF = {
    "temp_chassis_critical": "temp_chassis_high",
    # 5.3.0's six new optic power rules, each beside the one shipped rule
    # over its own metric. An operator who muted or turned off "Optic
    # receive power low" because their fleet's optics sit near the old
    # global -22 dBm must not be handed three brand new rules over the very
    # same reading, emailing them, that they have never seen.
    "sfp_rx_power_low_alarm": "sfp_rx_power_low",
    "sfp_rx_power_high": "sfp_rx_power_low",
    "sfp_rx_power_high_alarm": "sfp_rx_power_low",
    "sfp_tx_power_low_alarm": "sfp_tx_power_low",
    "sfp_tx_power_high": "sfp_tx_power_low",
    "sfp_tx_power_high_alarm": "sfp_tx_power_low",
}

# The subset of _NEW_SIBLING_OF that 5.3.0 introduced, and all its second
# dampen pass is allowed to touch — see _named_migrations.
_OPTIC_POWER_SIBLINGS = ("sfp_rx_power_low_alarm", "sfp_rx_power_high",
                         "sfp_rx_power_high_alarm", "sfp_tx_power_low_alarm",
                         "sfp_tx_power_high", "sfp_tx_power_high_alarm")

# Template text as shipped by previous releases, verbatim, for every built-in
# whose wording has since changed. _seed_templates inserts OR IGNORE, so an
# existing install keeps its templates for ever — right for one an operator
# edited, wrong for one nobody touched. A body that still matches a shipped
# wording exactly is one nobody edited, and _migrate_templates rewrites it.
# Each key holds every past wording, tried in order, so an install that
# skipped releases is still recognised.
_PREVIOUS_BUILTIN_TEMPLATES = {
    "device_down": [
        {   # as shipped through 4.48.0, before severity moved into the subject
            "subject": "SappiWhere: {{device_name}} is not responding",
            "body": ("{{device_name}} ({{device_ip}}) stopped responding at "
                     "{{opened_time}}.\n\n{{message}}\n\n"
                     "This alert has occurred {{count}} time(s). It will clear "
                     "automatically once the device responds again.\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
    ],
    "device_up": [
        {   # as shipped before 4.32.0
            "subject": "SappiWhere: {{device_name}} has recovered",
            "body": ("{{device_name}} ({{device_ip}}) is responding again as of "
                     "{{last_time}}.\n\n{{message}}\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
        {   # as shipped from 4.32.0 through 4.48.0
            "subject": "SappiWhere: {{device_name}} has recovered",
            "body": ("{{device_name}} ({{device_ip}}) has recovered as of "
                     "{{recovered_time}}.\n\n{{downtime_line}}{{message}}\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
    ],
    "device_rebooted": [
        {
            "subject": "SappiWhere: {{device_name}} rebooted",
            "body": ("{{device_name}} ({{device_ip}}) appears to have rebooted at "
                     "{{last_time}}.\n\nPrevious reported uptime: {{previous_uptime}}\n"
                     "Current reported uptime: {{current_uptime}}\n\n{{message}}\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
    ],
    "threshold_breach": [
        {
            "subject": "SappiWhere: {{entity_label}} — {{metric_label}} is {{value}}",
            "body": ("{{entity_label}} crossed a threshold at {{last_time}}.\n\n"
                     "Metric: {{metric_label}}\nCurrent value: {{value}}\n"
                     "Threshold: {{threshold}}\n\n{{message}}\n\n"
                     "This alert has occurred {{count}} time(s). It will clear "
                     "automatically once the value drops back below the clear "
                     "threshold.\n\n-- SappiWhere, {{severity_name}}"),
        },
        {   # as shipped through 5.2.0, before {{threshold_source}} was added
            "subject": "{{severity_tag}} SappiWhere: {{entity_label}} — {{metric_label}} is {{value}}",
            "body": ("{{entity_label}} crossed a threshold at {{last_time}}.\n\n"
                     "Metric: {{metric_label}}\nCurrent value: {{value}}\n"
                     "Threshold: {{threshold}}\n\n{{message}}\n\n"
                     "This alert has occurred {{count}} time(s). It will clear "
                     "automatically once the value drops back below the clear "
                     "threshold.\n\n-- SappiWhere"),
        },
    ],
    "event_notice": [
        {
            "subject": "SappiWhere: {{rule_name}} — {{entity_label}}",
            "body": ("{{rule_name}} — {{entity_label}}\n\n{{message}}\n\n{{detail}}\n"
                     "First seen {{opened_time}}; most recently {{last_time}}.\n"
                     "This alert has occurred {{count}} time(s).\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
    ],
    "trap_forwarded": [
        {
            "subject": "SappiWhere: {{rule_name}} — {{entity_label}}",
            "body": ("{{rule_name}} matched at {{last_time}}.\n\n"
                     "Source: {{entity_label}}\n{{message}}\n\n"
                     "Trap name: {{trap_name}}\nTrap OID: {{trap_oid}}\n"
                     "Varbinds: {{varbinds}}\n\n"
                     "This alert has occurred {{count}} time(s).\n\n"
                     "-- SappiWhere, {{severity_name}}"),
        },
    ],
}


class AlertsDatabase(SqliteStore):
    SCHEMA = SCHEMA + PENDING_SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "alerts"
    OLDEST_TS_SQL = "SELECT MIN(opened_ts) FROM alerts"

    def _after_open(self) -> None:
        self._seed_templates()
        self._seed_rules()
        self._run_named_migrations()

    def _migrate(self) -> None:
        added = self.ensure_columns("rules", {
            "flap_window_s": "INTEGER",
            "flap_min_transitions": "INTEGER",
            "for_seconds": "INTEGER",
            "auto_resolve_after_s": "INTEGER",
            "notify": "INTEGER NOT NULL DEFAULT 1",
            "comparison": "TEXT NOT NULL DEFAULT 'above'",
        })
        if "notify" in added:
            self._conn.execute(
                "UPDATE rules SET notify = 0 WHERE key = 'mib_missing'")
        if "for_seconds" in added:
            # Seed the shipped default onto an existing database so it gets
            # sustained packet loss rather than single-sample behaviour. Only
            # this rule: every other threshold keeps counting polls.
            self._conn.execute(
                "UPDATE rules SET for_seconds = 60 WHERE key = 'packet_loss_high'")
        self._migrate_templates()
        self.ensure_columns("alerts", {
            "last_notified_ts": "REAL",
            "extra_json": "TEXT NOT NULL DEFAULT '{}'",
            # What this alert absorbed, one line per rolled-up alert. Its own
            # column rather than appended to `detail`, which
            # open_or_increment overwrites every time the alert recurs.
            "rollup_note": "TEXT NOT NULL DEFAULT ''",
            # The id of the alert THIS one was absorbed into, or NULL. A
            # child a rollup resolves writes resolved_by='' — the same value
            # an auto-clear writes, so it can reopen — which leaves nothing
            # on the child's own row saying why it cleared. ON DELETE SET
            # NULL, not CASCADE: deleting a parent must not take the alerts
            # it absorbed with it.
            "rolled_up_into":
                "INTEGER REFERENCES alerts(id) ON DELETE SET NULL",
        })
        # Both indexes here rather than in SCHEMA: that script runs before
        # this method, so an index over a column added just above would fail
        # on an upgraded install.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_alerts_rolled_up_into"
            " ON alerts(rolled_up_into)")
        # Backs operator_resolved_since (state = 'resolved' AND resolved_ts
        # >= ?, grouped by dedup_key): a range scan needs the equality column
        # first. ix_alerts_dedup_state led with dedup_key, which that query
        # does not constrain, and is dropped rather than kept — nothing else
        # asks about resolved rows.
        self._conn.execute("DROP INDEX IF EXISTS ix_alerts_dedup_state")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_alerts_state_resolved"
            " ON alerts(state, resolved_ts, dedup_key)")

    # Post-seed migrations, in the order they were introduced. A migration
    # belongs here rather than in _migrate() when it has to read or rewrite
    # the seeded built-ins — _migrate runs before seeding and has to, because
    # seeding needs the columns it adds.
    def _named_migrations(self) -> tuple:
        return (
            ("rekey_trap_syslog_alerts_1", self._rekey_trap_syslog_alerts),
            ("seed_auto_resolve_1", self._seed_auto_resolve),
            ("rebind_event_notice_1", self._rebind_event_notice),
            ("retire_temp_high_1", self._retire_temp_high),
            ("dampen_new_builtin_siblings_1", self._dampen_new_builtin_siblings),
            ("per_port_threshold_alerts_1", self._resolve_device_if_alerts),
            # A SECOND named entry for a method that already has one, and
            # deliberately so: dampen_new_builtin_siblings_1 is recorded on
            # every install upgraded since 4.54 and will never run again, so
            # 5.3.0's six new optic power rules would arrive un-dampened —
            # an operator who muted sfp_rx_power_low would get three new
            # rules emailing them about the very same reading. It passes the
            # six new keys and only those: the temperature pair is
            # dampen_new_builtin_siblings_1's decision, made in 4.54, and a
            # second pass over it would re-decide it against a sibling the
            # operator has muted since — reverting a Critical they
            # deliberately left on.
            #
            # BEFORE the clear below, which reads naturally — dampen looks at
            # the numbers while they are still there — but is NOT load-
            # bearing, and nothing here should be written as if it were. All
            # dampen inherits is enabled/notify, which the clear does not
            # touch, and the six new rules ship with NULL thresholds, so the
            # sibling's own retune has nothing to shift onto them. Run after
            # the clear it would read a threshold-only retune as pristine and
            # skip the pair — reaching the same rows either way.
            ("dampen_optic_power_siblings_1",
             lambda: self._dampen_new_builtin_siblings(
                 keys=_OPTIC_POWER_SIBLINGS)),
            ("clear_optic_power_thresholds_1", self._clear_optic_power_thresholds),
            # Last, because it is the CONSEQUENCE of the two above: they put
            # the rules into their 5.3.0 shape, this clears up the alerts
            # that shape orphaned. It reads only the alerts table, so its
            # position relative to the other two cannot change the outcome —
            # it is placed here because the sequence then reads in the order
            # the operator experiences it.
            ("resolve_unpublished_optic_power_alerts_1",
             self._resolve_unpublished_optic_power_alerts),
        )

    def _run_named_migrations(self) -> None:
        for name, run in self._named_migrations():
            with self._lock:
                done = self._conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE name = ?",
                    (name,)).fetchone()
            if done:
                continue
            run()
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO schema_migrations(name, applied_ts)"
                    " VALUES (?,?)", (name, time.time()))
                self._conn.commit()

    def _note(self, alert_id: int, line: str) -> None:
        """add_rollup_note without its own transaction, for use inside a
        migration that is already holding the lock and batching a commit."""
        row = self._conn.execute(
            "SELECT rollup_note FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        existing = (row["rollup_note"] if row else "") or ""
        if line in existing.split("\n"):
            return
        merged = (existing + "\n" + line).strip() if existing else line
        self._conn.execute("UPDATE alerts SET rollup_note = ? WHERE id = ?",
                           (merged, alert_id))

    def _seed_auto_resolve(self) -> None:
        """Give the shipped momentary-event rules their auto-resolve interval
        on a database that already existed.

        _seed_rules is INSERT OR IGNORE, so it cannot reach a rule that is
        already there; this is the other half. Only where the column is still
        NULL and only on built-ins, so an operator who has already chosen an
        interval (or deliberately blanked one) keeps their choice.
        """
        with self._lock:
            for key, seconds in _BUILTIN_AUTO_RESOLVE_S.items():
                self._conn.execute(
                    "UPDATE rules SET auto_resolve_after_s = ? WHERE key = ?"
                    " AND is_builtin = 1 AND auto_resolve_after_s IS NULL",
                    (seconds, key))
            self._conn.commit()

    def _rebind_event_notice(self) -> None:
        """Move the non-outage rules off the "is not responding" template.

        Only a rule still bound to exactly the template it shipped with is
        moved — the same "an operator's edit is not ours to touch" rule
        _migrate_templates already follows for template text. A rule someone
        has already pointed at a template of their own keeps that binding.
        """
        with self._lock:
            templates = {row["key"]: row["id"] for row in self._conn.execute(
                "SELECT key, id FROM templates").fetchall()}
            target = templates.get("event_notice")
            if target is None:
                return
            for key, previous_key in _EVENT_NOTICE_REBIND.items():
                previous = templates.get(previous_key)
                if previous is None:
                    continue
                self._conn.execute(
                    "UPDATE rules SET template_id = ? WHERE key = ?"
                    " AND is_builtin = 1 AND template_id = ?",
                    (target, key, previous))
            self._conn.commit()

    def _retire_temp_high(self) -> None:
        """Retire the single "Temperature high" rule over one "temp_c"
        metric key that this same feature briefly shipped, before
        nodepoll._poll_environment was corrected to classify a temperature
        reading into temp_ambient_c/temp_chassis_c/temp_optic_c instead —
        see _BUILTIN_RULES' comment above temp_ambient_high for why one
        key over a room, a chassis and an SFP's DOM read as false alerts
        on a healthy fleet. Nothing produces "temp_c" any more, so an
        installation that already seeded the old rule would otherwise keep
        a built-in that can never fire and never clear again.

        Retired only if it still looks exactly like what shipped —
        is_builtin, unmodified source_kind/threshold/clear_threshold — the
        same "an operator's edit is not ours to touch" test
        _rebind_event_notice already applies to a template binding. A
        customized copy is left alone; it will simply never fire, same as
        any other rule pointed at a metric key nothing produces."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM rules WHERE key = 'temp_high' AND is_builtin = 1"
                " AND source_kind = 'temp_c' AND threshold = 35.0"
                " AND clear_threshold = 30.0").fetchone()
            if row is None:
                return
            rule_id = row["id"]
            now = time.time()
            for alert in self._conn.execute(
                    "SELECT id FROM alerts WHERE rule_id = ?"
                    " AND state IN ('open','acked')", (rule_id,)).fetchall():
                self._conn.execute(
                    "UPDATE alerts SET state='resolved', resolved_ts=?,"
                    " resolved_by='' WHERE id=?", (now, alert["id"]))
                self._note(alert["id"],
                          "Resolved on upgrade: temp_high was split into "
                          "temp_ambient_high/temp_chassis_high/"
                          "temp_optic_high, each reading its own metric")
            # Disabled and renamed rather than deleted: rules.id is the
            # alerts table's own foreign key (ON DELETE CASCADE), so
            # deleting the row would take every alert this rule ever
            # raised down with it — exactly the history the resolve-with-
            # a-note step above exists to keep. A disabled, clearly
            # labelled row an operator can remove by hand from the rules
            # page is the reversible choice; a cascade a migration
            # silently triggered underneath them is not.
            self._conn.execute(
                "UPDATE rules SET enabled = 0, notify = 0,"
                " name = 'Temperature high (retired -- see"
                " temp_ambient_high / temp_chassis_high / temp_optic_high)'"
                " WHERE id = ?", (rule_id,))
            self._conn.commit()

    def _resolve_device_if_alerts(self) -> None:
        """Resolve the open device-scoped alerts of the interface threshold
        rules, once, on upgrade to 5.1.0: those rules used to read a
        device-level worst-port key, so old open alerts name no port and
        the evaluator no longer writes that key, meaning nothing will ever
        clear them.

        Scoped by `kind = 'threshold'` and source_kind LIKE 'if_%' rather
        than by dedup key, so it also catches a custom rule against one of
        those keys. Acked rows go too; resolved with a note rather than
        deleted, like _retire_temp_high.
        """
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT a.id FROM alerts a JOIN rules r ON r.id = a.rule_id"
                " WHERE a.state IN ('open','acked') AND a.entity_kind = 'device'"
                r" AND r.kind = 'threshold' AND r.source_kind LIKE 'if\_%' ESCAPE '\'"
            ).fetchall()
            for row in rows:
                self._conn.execute(
                    "UPDATE alerts SET state='resolved', resolved_ts=?,"
                    " resolved_by='' WHERE id=?", (now, row["id"]))
                self._note(row["id"],
                          "Resolved on upgrade: interface thresholds now alert "
                          "per port, naming the interface, so this device-wide "
                          "alert had nothing left to clear it")
            self._conn.commit()

    def _dampen_new_builtin_siblings(self, keys=None) -> None:
        """A NEW built-in rule must not arrive louder than an EXISTING one
        the operator already tuned, when both read the same source_kind.

        `keys` limits it to those new-rule keys, and a release that adds a
        SECOND named migration over this same method has to pass it: the
        pairs an earlier one already settled are settled, and re-deciding
        one against a sibling the operator has muted since would revert a
        choice they made deliberately (see _named_migrations). None means
        every pair, which is what the first such migration wants.

        _seed_rules runs before every named migration and is an INSERT OR
        IGNORE, so on an upgrade it seeds temp_chassis_critical (and any
        future rule in _NEW_SIBLING_OF) as enabled=1, notify=1 at its shipped
        numbers before this ever runs — right for a fresh install, where
        both rules are meant to ship on. It is wrong for an install where
        the operator already turned the EXISTING sibling off, muted it, or
        raised its thresholds because their own site runs hot: they would
        get a brand new Critical alert, emailing them, about a metric they
        deliberately silenced, from a rule they have never seen and never
        agreed to.

        For each (new_key, sibling_key) in _NEW_SIBLING_OF: if the sibling
        is_builtin and still reads exactly as shipped (enabled, notify,
        threshold, clear_threshold all match _builtin_rule_defaults), there
        is nothing to inherit — a fresh install, or an operator who left the
        sibling alone — and the new rule is left exactly as _seed_rules put
        it, on by design. Otherwise the new rule's enabled/notify are set to
        match the sibling's, and its own threshold/clear_threshold are
        shifted by the same absolute amount the sibling's were (0 if the
        sibling's numbers were not touched), so a rule shipped deliberately
        ABOVE its sibling (see _BUILTIN_RULES' comment on
        temp_chassis_critical) stays above it after the same retune.

        Only while the new rule still looks exactly like what _seed_rules
        just gave it — the same "an operator's edit is not ours to touch"
        guard _retire_temp_high applies to its own rule. Usually that also
        ends it: once it has acted (or an operator has edited the new rule
        by hand, including re-enabling it) the new rule no longer matches
        its own shipped defaults, and the guard turns every later call into
        a no-op. Not always, though — a sibling tuned in THRESHOLD alone
        leaves the new rule sitting exactly on its defaults, so the guard
        does not stop a second call. That is harmless rather than
        short-circuited: the write is the same write, so a re-run reaches
        the same state. Idempotent in effect; do not read the guard as a
        proof that it cannot run twice.
        """
        defaults = _builtin_rule_defaults()
        with self._lock:
            rows = {row["key"]: row for row in self._conn.execute(
                "SELECT id, key, enabled, notify, threshold, clear_threshold"
                " FROM rules WHERE is_builtin = 1").fetchall()}
            for new_key, sibling_key in _NEW_SIBLING_OF.items():
                if keys is not None and new_key not in keys:
                    continue
                new_row = rows.get(new_key)
                sibling_row = rows.get(sibling_key)
                new_default = defaults.get(new_key)
                sibling_default = defaults.get(sibling_key)
                if (new_row is None or sibling_row is None
                        or new_default is None or sibling_default is None):
                    continue
                if (new_row["enabled"], new_row["notify"],
                    new_row["threshold"], new_row["clear_threshold"]) != (
                        1, new_default["notify"], new_default["threshold"],
                        new_default["clear_threshold"]):
                    continue   # already touched -- by an operator, or by us
                if (sibling_row["enabled"], sibling_row["notify"],
                    sibling_row["threshold"], sibling_row["clear_threshold"]) == (
                        1, sibling_default["notify"], sibling_default["threshold"],
                        sibling_default["clear_threshold"]):
                    continue   # sibling untouched -- fresh install, or left alone
                threshold_shift = 0.0
                clear_shift = 0.0
                if (sibling_row["threshold"] is not None
                        and sibling_default["threshold"] is not None):
                    threshold_shift = sibling_row["threshold"] - sibling_default["threshold"]
                if (sibling_row["clear_threshold"] is not None
                        and sibling_default["clear_threshold"] is not None):
                    clear_shift = sibling_row["clear_threshold"] - sibling_default["clear_threshold"]
                new_threshold = (new_default["threshold"] + threshold_shift
                                if new_default["threshold"] is not None else None)
                new_clear = (new_default["clear_threshold"] + clear_shift
                            if new_default["clear_threshold"] is not None else None)
                self._conn.execute(
                    "UPDATE rules SET enabled = ?, notify = ?, threshold = ?,"
                    " clear_threshold = ? WHERE id = ?",
                    (sibling_row["enabled"], sibling_row["notify"],
                     new_threshold, new_clear, new_row["id"]))
            self._conn.commit()

    def _clear_optic_power_thresholds(self) -> None:
        """Retire the stored threshold/clear_threshold of the two optic
        POWER rules an earlier release shipped a global number on.

        From 5.3.0 the engine judges those rules against the levels the
        port's own transceiver publishes and never reads these columns again
        (alertrules.PUBLISHED_THRESHOLD_RULES), so a number left here cannot
        change what alerts — but it CAN sit on the Rules page reading as the
        live threshold when it is not, which is the worse wrong. An operator
        investigating a dark port would tune it, watch nothing happen, and
        conclude the feature is broken.

        Unconditional, unlike _retire_temp_high's "only if it still looks
        exactly as shipped" test. That guard exists to leave an operator's
        tuning alone; here their tuning is precisely what has stopped
        meaning anything, and leaving it on display is not respect for it.
        _dampen_new_builtin_siblings has already read those numbers by the
        time this runs — see _named_migrations.

        sfp_temp_high is NOT touched: only optical POWER moved to published
        limits. Open alerts are not this method's business either: an alert
        on a port that publishes a limit re-derives or clears on the next
        tick, and one on a port that publishes none is resolved by
        _resolve_unpublished_optic_power_alerts, which nothing else would.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE rules SET threshold = NULL, clear_threshold = NULL"
                " WHERE is_builtin = 1 AND key IN"
                " ('sfp_rx_power_low', 'sfp_tx_power_low')")
            self._conn.commit()

    def _resolve_unpublished_optic_power_alerts(self) -> None:
        """Resolve the open optic POWER alerts an earlier release raised
        against its global number, once, on upgrade to 5.3.0.

        From 5.3.0 those two rules are judged against the levels the port's
        own transceiver publishes and nothing else, so a port that publishes
        none is never evaluated for them again — and an alert already
        standing on such a port has nothing left to clear it: threshold
        rules carry no auto-resolve, and the dark-optic clear path needs a
        threshold to compare against. That is not a rare corner: only
        Cisco's entSensorThresholdTable carries the bands at all, so every
        Juniper, Arista and HP port answering the standard
        ENTITY-SENSOR-MIB is one, as is any Cisco port whose optic publishes
        no warning level or whose band fails _optic_band_sane.

        Both keys, every open row, acked ones too — an operator who ticked
        one off can no more clear it than one who did not. Resolved with a
        note rather than deleted, like _resolve_device_if_alerts, and
        resolved_by='' so none of it reads as a hand resolve. A port that
        DOES publish a limit and is still under it simply re-opens on the
        next tick.
        """
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT a.id FROM alerts a JOIN rules r ON r.id = a.rule_id"
                " WHERE a.state IN ('open','acked')"
                " AND r.key IN ('sfp_rx_power_low', 'sfp_tx_power_low')"
            ).fetchall()
            for row in rows:
                self._conn.execute(
                    "UPDATE alerts SET state='resolved', resolved_ts=?,"
                    " resolved_by='' WHERE id=?", (now, row["id"]))
                self._note(row["id"],
                          "Resolved on upgrade: optic power now alerts on the "
                          "levels the port's own transceiver publishes, and "
                          "this port publishes none")
            self._conn.commit()

    def _rekey_trap_syslog_alerts(self) -> None:
        """Bring open trap and syslog alerts onto the 4.37 dedup keys.

        Trap alerts were keyed on the trap OID alone and syslog alerts on the
        sending host alone; both now carry the source and, for syslog, a
        signature of the message. Leaving the old rows alone was not an
        option: their keys can never match again, so they would sit open
        forever while a new row opened beside each of them.

        Syslog rows are re-keyed exactly — the stored message is the same
        message the signature is computed from, so the operator's open alert
        keeps its history, its count and its acknowledgement. Two old rows
        that map onto one new key (the same host, two messages that share a
        signature) cannot both exist, since one open alert per dedup key is a
        database constraint; the later one is resolved with a note saying so.

        Trap rows cannot be re-keyed at all: the old key never recorded which
        device sent the trap, and that fact is not recoverable from the row.
        They are resolved with an explanation. resolved_by is '' throughout,
        the same convention every engine auto-resolve uses, so none of this
        is mistaken for a hand resolve later.
        """
        from .alertrules import syslog_signature
        now = time.time()
        with self._lock:
            rules = {row["id"]: row["key"] for row in
                     self._conn.execute("SELECT id, key FROM rules").fetchall()}
            taken = {row["dedup_key"] for row in self._conn.execute(
                "SELECT dedup_key FROM alerts WHERE state IN ('open','acked')"
            ).fetchall()}
            rows = self._conn.execute(
                "SELECT id, rule_id, dedup_key, entity_id, message FROM alerts"
                " WHERE state IN ('open','acked') AND entity_kind IN ('trap','syslog')"
                " ORDER BY id").fetchall()
            for row in rows:
                rule_key = rules.get(row["rule_id"])
                if not rule_key:
                    continue
                if row["dedup_key"].startswith(f"{rule_key}:trap:"):
                    self._conn.execute(
                        "UPDATE alerts SET state='resolved', resolved_ts=?,"
                        " resolved_by='' WHERE id=?", (now, row["id"]))
                    self._note(row["id"], "Resolved on upgrade: trap alerts "
                                          "are now keyed per source device")
                    taken.discard(row["dedup_key"])
                    continue
                entity_id = f'{row["entity_id"]}:{syslog_signature(row["message"] or "")}'
                new_key = f"{rule_key}:syslog:{entity_id}"
                if new_key == row["dedup_key"]:
                    continue
                if new_key in taken:
                    self._conn.execute(
                        "UPDATE alerts SET state='resolved', resolved_ts=?,"
                        " resolved_by='' WHERE id=?", (now, row["id"]))
                    self._note(row["id"], "Resolved on upgrade: another open "
                                          "alert now covers this message")
                    taken.discard(row["dedup_key"])
                    continue
                self._conn.execute(
                    "UPDATE alerts SET dedup_key=?, entity_id=? WHERE id=?",
                    (new_key, entity_id, row["id"]))
                taken.discard(row["dedup_key"])
                taken.add(new_key)
            self._conn.commit()

    def _migrate_templates(self) -> None:
        """Bring a built-in template whose shipped wording changed up to date,
        without ever overwriting an operator's own edit.

        Two separate updates, and the distinction between them is the whole
        point. `builtin_subject`/`builtin_body` are the shipped reference that
        "Reset to built-in" restores, so they always become the new text — an
        operator resetting a template must get this release's wording, not the
        one they upgraded away from. The live `subject`/`body` are only
        rewritten where they still match, character for character, what the
        previous release shipped: anything else is an edit somebody made and
        this migration has no business touching it.

        Runs before _seed_templates, so on a fresh database there is nothing
        to match and the new text is simply seeded.
        """
        from . import alertmail
        now = time.time()
        for key, previous_versions in _PREVIOUS_BUILTIN_TEMPLATES.items():
            current = alertmail.BUILTIN_TEMPLATES.get(key)
            if not current:
                continue
            self._conn.execute(
                "UPDATE templates SET builtin_subject = ?, builtin_body = ?"
                " WHERE key = ?", (current["subject"], current["body"], key))
            # Every wording this key has EVER shipped, not just the one
            # immediately before this release — see _PREVIOUS_BUILTIN_
            # TEMPLATES' own comment. At most one can match, since a
            # template holds one subject/body at a time; the loop just
            # tries each candidate rather than assuming which release an
            # install last upgraded from.
            for previous in previous_versions:
                self._conn.execute(
                    "UPDATE templates SET subject = ?, body = ?, updated_ts = ?"
                    " WHERE key = ? AND subject = ? AND body = ?",
                    (current["subject"], current["body"], now, key,
                     previous["subject"], previous["body"]))

    def _seed_templates(self) -> None:
        from . import alertmail
        now = time.time()
        with self._lock:
            for key in _BUILTIN_TEMPLATE_KEYS:
                spec = alertmail.BUILTIN_TEMPLATES[key]
                self._conn.execute(
                    "INSERT OR IGNORE INTO templates(key, name, subject, body,"
                    " is_html, is_builtin, builtin_subject, builtin_body, updated_ts)"
                    " VALUES (?,?,?,?,0,1,?,?,?)",
                    (key, spec["name"], spec["subject"], spec["body"],
                     spec["subject"], spec["body"], now))
            self._conn.commit()

    def _seed_rules(self) -> None:
        now = time.time()
        with self._lock:
            template_ids = {row["key"]: row["id"] for row in
                            self._conn.execute("SELECT key, id FROM templates").fetchall()}
            for (key, name, kind, source_kind, severity, template_key,
                 threshold, clear_threshold, for_polls) in _BUILTIN_RULES:
                self._conn.execute(
                    "INSERT OR IGNORE INTO rules(key, name, kind, source_kind,"
                    " severity, enabled, is_builtin, device_filter, notify,"
                    " threshold, clear_threshold, comparison, for_polls,"
                    " for_seconds, auto_resolve_after_s, template_id,"
                    " created_ts) VALUES (?,?,?,?,?,1,1,'',?,?,?,?,?,?,?,?,?)",
                    (key, name, kind, source_kind, severity,
                     0 if key in _BUILTIN_NOTIFY_OFF else 1, threshold,
                     clear_threshold, _BUILTIN_COMPARISON.get(key, "above"),
                     for_polls, _BUILTIN_FOR_SECONDS.get(key),
                     _BUILTIN_AUTO_RESOLVE_S.get(key),
                     template_ids.get(template_key), now))
            self._conn.commit()

    # --------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = super().settings()
        with self._lock:
            cred = self._conn.execute(
                "SELECT password_enc FROM smtp_credential WHERE id = 1").fetchone()
        values["notify_rollup_delay_s"] = max(0, min(
            int(values.get("notify_rollup_delay_s", 0) or 0),
            NOTIFY_ROLLUP_DELAY_MAX_S))
        values["has_smtp_credential"] = bool(cred and cred["password_enc"])
        return values

    def save_settings(self, values: dict) -> None:
        if "webhook_url" in values:
            validate_webhook_url(values["webhook_url"])
        super().save_settings(values)

    def set_smtp_credential(self, password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO smtp_credential(id, password_enc) VALUES (1, ?)"
                " ON CONFLICT(id) DO UPDATE SET password_enc=excluded.password_enc",
                (password_enc,))
            self._conn.commit()

    def clear_smtp_credential(self) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO smtp_credential(id, password_enc) VALUES (1, NULL)"
                " ON CONFLICT(id) DO UPDATE SET password_enc=NULL")
            self._conn.commit()

    def smtp_password_enc(self) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT password_enc FROM smtp_credential WHERE id = 1").fetchone()
        return bytes(row["password_enc"]) if row and row["password_enc"] else None

    # ------------------------------------------------------------------ rules

    def rules(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules ORDER BY is_builtin DESC, name COLLATE NOCASE"
            ).fetchall()

    def rule(self, rule_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()

    def rule_by_key(self, key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules WHERE key = ?", (key,)).fetchone()

    def add_rule(self, key: str, name: str, kind: str, source_kind: str, **fields) -> int:
        cols = ["key", "name", "kind", "source_kind", "created_ts"]
        vals = [key, name, kind, source_kind, time.time()]
        for field_key in _RULE_EDITABLE:
            if field_key in fields and field_key != "name":
                cols.append(field_key)
                vals.append(fields[field_key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO rules({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_rule(self, rule_id: int, **fields) -> None:
        row = self.rule(rule_id)
        if row is None:
            return
        allowed_keys = _RULE_EDITABLE if row["is_builtin"] else _RULE_CUSTOM_EDITABLE
        allowed = {k: v for k, v in fields.items() if k in allowed_keys}
        if not allowed:
            return
        # The same refusal set_device_threshold makes, on the other writer:
        # a number typed into the rule editor for one of these keys would be
        # stored and then ignored for ever. Only what this call is actually
        # setting is checked — an edit that touches neither column (renaming
        # the rule, turning it off) is none of this function's business.
        if "threshold" in allowed or "clear_threshold" in allowed:
            _check_published_threshold(
                row["key"] or "", allowed.get("threshold"),
                allowed.get("clear_threshold"))
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE rules SET {clauses} WHERE id = ?",
                (*allowed.values(), rule_id))
            self._conn.commit()

    def alert_count_for_rule(self, rule_id: int) -> int:
        """Every alert this rule ever raised, in any state — not just the
        open ones. What DELETE FROM rules would cascade-destroy along with
        the rule itself (rules.id is alerts.rule_id's ON DELETE CASCADE
        parent), so the caller can refuse a deletion that would take real
        history with it and offer disabling the rule instead. api.py reads
        this to say "N alerts" in that refusal; the count itself belongs
        here, next to the table it counts."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = ?",
                (rule_id,)).fetchone()[0]

    def remove_rule(self, rule_id: int) -> bool:
        """False for a rule that does not exist, is built-in, OR has ever
        raised an alert — the last one is defense in depth, not the primary
        guard. alert_count_for_rule is what the API is expected to check
        FIRST, so an operator sees "12 alerts reference this rule" rather
        than a delete that silently no-ops; this WHERE clause exists so a
        future caller that skips that check still cannot cascade-delete a
        custom rule's alert history by mistake (rules.id is alerts.rule_id's
        ON DELETE CASCADE parent)."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM rules WHERE id = ? AND is_builtin = 0"
                " AND id NOT IN (SELECT DISTINCT rule_id FROM alerts)",
                (rule_id,))
            self._conn.commit()
            return (cursor.rowcount or 0) > 0

    # ------------------------------------------------------- device thresholds

    def device_thresholds(self, device_id: int | None = None) -> list[sqlite3.Row]:
        """Every override, or just `device_id`'s — the fleet view and a
        single device's page share this one accessor. An override whose
        device was since deleted from Nodes still comes back here (nothing
        in this table references `devices`, on purpose — see
        AlertEngine._evaluate_thresholds' own comment on why that is
        harmless): the fleet view is exactly where an operator would notice
        and clean up a leftover row for a device that no longer exists.
        """
        with self._lock:
            if device_id is None:
                return self._conn.execute(
                    "SELECT * FROM device_thresholds ORDER BY device_id, rule_key"
                ).fetchall()
            return self._conn.execute(
                "SELECT * FROM device_thresholds WHERE device_id = ?"
                " ORDER BY rule_key", (device_id,)).fetchall()

    def device_threshold_map(self, rule_key: str) -> dict[int, sqlite3.Row]:
        """device_id -> override, for one rule — the shape
        AlertEngine._evaluate_thresholds wants, read once per rule per tick
        rather than once per device: this evaluator runs every 5 s over the
        whole fleet, and a query per device here would be the same
        regression metrics_for_keys' own batching already exists to avoid.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM device_thresholds WHERE rule_key = ?",
                (rule_key,)).fetchall()
        return {row["device_id"]: row for row in rows}

    def set_device_threshold(self, device_id: int, rule_key: str, *,
                             threshold: float | None, clear_threshold: float | None,
                             enabled: bool = True, now: float | None = None) -> None:
        """Create or replace `device_id`'s override of `rule_key`.

        `rule_key` must name a threshold-kind rule: device_thresholds only
        means anything to AlertEngine._evaluate_thresholds, which reads
        rule.threshold/clear_threshold the same way for every kind='threshold'
        row and no other kind at all. _check_threshold_direction is the other
        half of the validation — see its own docstring for why "clear_threshold
        below threshold" is the one direction this evaluator ever supports,
        not an assumption this function is making.
        """
        rule = self.rule_by_key(rule_key)
        if rule is None or rule["kind"] != "threshold":
            raise ValueError(
                f"'{rule_key}' does not name an existing threshold rule")
        _check_published_threshold(rule_key, threshold, clear_threshold)
        _check_threshold_direction(rule, threshold, clear_threshold)
        now = time.time() if now is None else now
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_thresholds(device_id, rule_key, threshold,"
                " clear_threshold, enabled, updated_ts) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(device_id, rule_key) DO UPDATE SET"
                " threshold = excluded.threshold,"
                " clear_threshold = excluded.clear_threshold,"
                " enabled = excluded.enabled, updated_ts = excluded.updated_ts",
                (device_id, rule_key, threshold, clear_threshold,
                 1 if enabled else 0, now))
            self._conn.commit()

    def clear_device_threshold(self, device_id: int, rule_key: str) -> bool:
        """False when there was no override to remove, so a caller can tell
        "deleted" from "there was nothing there"."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM device_thresholds WHERE device_id = ? AND rule_key = ?",
                (device_id, rule_key))
            self._conn.commit()
            return (cursor.rowcount or 0) > 0

    # -------------------------------------------------------------- templates

    def templates(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates ORDER BY is_builtin DESC, name COLLATE NOCASE"
            ).fetchall()

    def template(self, template_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()

    def template_by_key(self, key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates WHERE key = ?", (key,)).fetchone()

    def add_template(self, key: str, name: str, subject: str, body: str,
                     is_html: bool = False) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO templates(key, name, subject, body, is_html,"
                " is_builtin, updated_ts) VALUES (?,?,?,?,?,0,?)",
                (key, name, subject, body, 1 if is_html else 0, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def update_template(self, template_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("name", "subject", "body", "is_html")}
        if not allowed:
            return
        allowed["updated_ts"] = time.time()
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE templates SET {clauses} WHERE id = ?",
                (*allowed.values(), template_id))
            self._conn.commit()

    def reset_template(self, template_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE templates SET subject = builtin_subject, body = builtin_body,"
                " updated_ts = ? WHERE id = ? AND is_builtin = 1",
                (time.time(), template_id))
            self._conn.commit()

    def remove_template(self, template_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM templates WHERE id = ? AND is_builtin = 0", (template_id,))
            self._conn.commit()
            return (cursor.rowcount or 0) > 0

    # ---------------------------------------------------------------- alerts

    def _alert_filter(self, state, severity, rule_id, device_text, text,
                      t0, t1) -> tuple[str, list]:
        """The WHERE clause shared by `alerts()` and `count_alerts()`.

        One list showing "300 of 532" needs the same question answered twice,
        and a filter that drifts between the two makes the second number a
        lie about the first.
        """
        clauses, params = [], []
        if state == "unresolved":
            clauses.append("state IN ('open', 'acked')")
        elif state:
            clauses.append("state = ?")
            params.append(state)
        if severity is not None:
            clauses.append("severity <= ?")
            params.append(severity)
        if rule_id is not None:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if device_text:
            clauses.append("entity_label LIKE ?")
            params.append(f"%{device_text}%")
        if text:
            clauses.append("(message LIKE ? OR entity_label LIKE ?)")
            params.extend([f"%{text}%"] * 2)
        if t0 is not None:
            clauses.append("last_ts >= ?")
            params.append(t0)
        if t1 is not None:
            clauses.append("opened_ts <= ?")
            params.append(t1)
        return (f" WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def count_alerts(self, state: str | None = None, severity: int | None = None,
                     rule_id: int | None = None, device_text: str | None = None,
                     text: str | None = None, t0: float | None = None,
                     t1: float | None = None) -> int:
        """How many alerts match, ignoring the list's limit — so the UI can
        say how many it is not showing rather than implying there are none."""
        where, params = self._alert_filter(state, severity, rule_id,
                                           device_text, text, t0, t1)
        with self._lock:
            return int(self._conn.execute(
                f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0])

    def alerts(self, state: str | None = None, severity: int | None = None,
              rule_id: int | None = None, device_text: str | None = None,
              text: str | None = None, t0: float | None = None,
              t1: float | None = None, limit: int = 300,
              offset: int = 0) -> list[sqlite3.Row]:
        # `offset` defaults to 0, so an unpaged caller gets the first
        # `limit` rows as before; the route pairs it with count_alerts().
        where, params = self._alert_filter(state, severity, rule_id,
                                           device_text, text, t0, t1)
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM alerts{where} ORDER BY last_ts DESC LIMIT ? OFFSET ?",
                (*params, limit, offset)).fetchall()

    def alert(self, alert_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def open_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE state = 'open'"
            ).fetchone()["n"]

    def open_summary(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, MIN(severity) AS worst, COUNT(*) AS n FROM alerts"
                " WHERE state IN ('open', 'acked') GROUP BY state").fetchall()
        open_n = acked_n = 0
        worst = None
        for row in rows:
            if row["state"] == "open":
                open_n = row["n"]
            elif row["state"] == "acked":
                acked_n = row["n"]
            if worst is None or (row["worst"] is not None and row["worst"] < worst):
                worst = row["worst"]
        return {"open": open_n, "acked": acked_n, "worst": worst,
               "all_acked": open_n == 0 and acked_n > 0}

    def histogram(self, t0: float, t1: float, bucket_s: float = 3600) -> list[dict]:
        bucket_s = max(float(bucket_s), 60.0)
        start = int(t0 // bucket_s) * bucket_s
        slots = max(1, int((t1 - start) / bucket_s) + 1)
        buckets = [{"t0": start + i * bucket_s, "t1": start + (i + 1) * bucket_s,
                   "total": 0, "by_severity": {}} for i in range(slots)]
        with self._lock:
            rows = self._conn.execute(
                "SELECT CAST((opened_ts - ?) / ? AS INTEGER) AS slot,"
                " severity, COUNT(*) AS n FROM alerts"
                " WHERE opened_ts >= ? AND opened_ts <= ? GROUP BY slot, severity",
                (start, bucket_s, t0, t1)).fetchall()
        for row in rows:
            index = row["slot"]
            if index is None or not (0 <= index < slots):
                continue
            buckets[index]["total"] += row["n"]
            key = str(row["severity"])
            by = buckets[index]["by_severity"]
            by[key] = by.get(key, 0) + row["n"]
        return buckets

    def open_or_increment(self, rule_id: int, dedup_key: str, entity_kind: str,
                          entity_id: str, entity_label: str, severity: int,
                          message: str, detail: str, ts: float,
                          extra: dict | None = None) -> tuple[sqlite3.Row, bool]:
        """`extra` is the occurrence's template extras, kept on the row so a
        renotify built by the engine's sweep — which has no occurrence to
        read them from — renders the same tokens the first notification
        did."""
        extra_json = json.dumps(extra or {}, separators=(",", ":"))
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE alerts SET count = count + 1, last_ts = ?,"
                    " entity_label = ?, message = ?, detail = ?, extra_json = ?"
                    " WHERE id = ?",
                    (ts, entity_label, message, detail, extra_json, existing["id"]))
                self._conn.commit()
                row = self._conn.execute(
                    "SELECT * FROM alerts WHERE id = ?", (existing["id"],)).fetchone()
                return row, False
            cur = self._conn.execute(
                "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
                " entity_label, severity, message, detail, opened_ts, last_ts,"
                " extra_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (rule_id, dedup_key, entity_kind, entity_id, entity_label,
                 severity, message, detail, ts, ts, extra_json))
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
            return row, True

    def mark_notified(self, alert_id: int, ts: float | None = None) -> None:
        """Stamp when a notification was last submitted for this alert.

        Written at SUBMIT rather than on delivery: what renotify measures is
        "how long since we last told anyone", and a message sitting in the
        sender queue has already been told. Kept apart from last_ts, which
        every recurrence refreshes.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET last_notified_ts = ? WHERE id = ?",
                (time.time() if ts is None else ts, alert_id))
            self._conn.commit()

    def alerts_due_renotify(self, cutoff_ts: float) -> list[sqlite3.Row]:
        """Open alerts nobody has been told about since cutoff_ts.

        Acknowledged alerts are excluded on purpose: acknowledging is an
        operator saying "I have this", and continuing to nag them is the
        thing acknowledgement exists to stop. COALESCE falls back to
        opened_ts so an alert that opened while email was disabled starts its
        renotify clock from when it opened, not from never.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE state = 'open'"
                " AND COALESCE(last_notified_ts, opened_ts) <= ?"
                " ORDER BY severity, last_ts", (cutoff_ts,)).fetchall()

    def alerts_due_first_notify(self, cutoff_ts: float) -> list[sqlite3.Row]:
        """Alerts whose FIRST notification is still undecided: nobody has
        ever attempted to email about them (last_notified_ts IS NULL), and
        they are old enough that notify_rollup_delay_s has elapsed
        (opened_ts <= cutoff_ts) — but not so old that "still undecided" has
        stopped being plausible (opened_ts >= cutoff_ts -
        FIRST_NOTIFY_BACKLOG_GRACE_S). `cutoff_ts` is always `now - delay`
        (see _sweep_notify_rollup), so that floor reads as "opened within
        roughly the last delay-plus-an-hour" — comfortably wide for any
        real engine outage, and a hard line under an upgrade's entire
        pre-existing backlog of alerts nobody was ever going to email about
        (see FIRST_NOTIFY_BACKLOG_GRACE_S's own comment for why that upgrade
        case is the one this floor exists for).

        Not filtered on state, unlike alerts_due_renotify: an alert that
        cleared or was absorbed into a rollup parent while its notice was
        still held is exactly the case that needs a decision recorded (skip,
        with a reason) rather than silence, so a resolved row with no
        decision yet is just as "due" as an open one. See
        AlertEngine._sweep_notify_rollup.

        last_notified_ts IS NULL is what makes this restart-safe for free:
        it is a column on the row, not in-memory queue state, so a restart
        mid-hold picks the same alerts back up on the next tick rather than
        losing track of what it owed an email.
        """
        floor_ts = cutoff_ts - FIRST_NOTIFY_BACKLOG_GRACE_S
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE last_notified_ts IS NULL"
                " AND opened_ts <= ? AND opened_ts >= ?"
                " ORDER BY severity, opened_ts",
                (cutoff_ts, floor_ts)).fetchall()

    def expired_alerts(self, now: float) -> list[sqlite3.Row]:
        """Alerts whose rule gives them a lifetime that has run out.

        Measured from last_ts, not opened_ts: a trap that keeps arriving is
        still current, and its alert should expire an hour after the last one
        rather than an hour after the first. Acknowledged rows are included —
        acknowledging says "seen", not "keep this forever" — and the sweep
        that calls this resolves them without a clear email, because nobody
        needs telling that a week-old reboot notice has been tidied away.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT a.* FROM alerts a JOIN rules r ON r.id = a.rule_id"
                " WHERE a.state IN ('open','acked')"
                " AND r.auto_resolve_after_s IS NOT NULL"
                " AND r.auto_resolve_after_s > 0"
                " AND a.last_ts <= ? - r.auto_resolve_after_s",
                (now,)).fetchall()

    def resolve(self, alert_id: int, by: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                " WHERE id=? AND state IN ('open','acked')",
                (time.time(), by, alert_id))
            self._conn.commit()

    def resolve_many(self, alert_ids: list[int], by: str = "") -> int:
        if not alert_ids:
            return 0
        marks = ",".join("?" * len(alert_ids))
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                f" WHERE id IN ({marks}) AND state IN ('open','acked')",
                (time.time(), by, *alert_ids))
            self._conn.commit()
            return cursor.rowcount or 0

    # ------------------------------------------------- held occurrences

    def park_occurrence(self, device_id: int, fire_after_ts: float,
                        payload: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO pending_alerts(device_id, fire_after_ts,"
                " created_ts, payload) VALUES (?,?,?,?)",
                (device_id, fire_after_ts, time.time(), payload))
            self._conn.commit()
            return cur.lastrowid

    def due_occurrences(self, now: float) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM pending_alerts WHERE fire_after_ts <= ?"
                " ORDER BY fire_after_ts", (now,)).fetchall()

    def drop_occurrence(self, pending_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM pending_alerts WHERE id = ?",
                               (pending_id,))
            self._conn.commit()

    # -------------------------------------------------------------- mutes

    def mute(self, entity_kind: str, entity_id: str, hours: float,
             by: str = "", reason: str = "") -> sqlite3.Row | None:
        """Silence new alerts for an entity for `hours`, replacing any mute
        it already has — re-muting a device extends it rather than failing on
        the unique index, which is what pressing the button again means."""
        hours = max(0.0, min(float(hours), MAX_MUTE_HOURS))
        if hours <= 0:
            return None
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO alert_mutes(entity_kind, entity_id, until_ts,"
                " created_ts, created_by, reason) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(entity_kind, entity_id) DO UPDATE SET"
                " until_ts=excluded.until_ts, created_ts=excluded.created_ts,"
                " created_by=excluded.created_by, reason=excluded.reason",
                (entity_kind, str(entity_id), now + hours * 3600.0, now,
                 by, reason))
            self._conn.commit()
        return self.mute_row(entity_kind, entity_id)

    def mute_many(self, entity_kind: str, entity_ids: list[str], hours: float,
                  by: str = "", reason: str = "") -> list[sqlite3.Row]:
        """Bulk mute: one call, one hour figure, one reason, applied to every
        id in `entity_ids`. Same cap and replace-on-remute as mute(); a
        maintenance window is the mechanism for longer than MAX_MUTE_HOURS."""
        hours = max(0.0, min(float(hours), MAX_MUTE_HOURS))
        if hours <= 0 or not entity_ids:
            return []
        now = time.time()
        until = now + hours * 3600.0
        with self._lock:
            for entity_id in entity_ids:
                self._conn.execute(
                    "INSERT INTO alert_mutes(entity_kind, entity_id, until_ts,"
                    " created_ts, created_by, reason) VALUES (?,?,?,?,?,?)"
                    " ON CONFLICT(entity_kind, entity_id) DO UPDATE SET"
                    " until_ts=excluded.until_ts, created_ts=excluded.created_ts,"
                    " created_by=excluded.created_by, reason=excluded.reason",
                    (entity_kind, str(entity_id), until, now, by, reason))
            self._conn.commit()
        return [row for row in
               (self.mute_row(entity_kind, entity_id) for entity_id in entity_ids)
               if row is not None]

    def unmute(self, entity_kind: str, entity_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM alert_mutes WHERE entity_kind = ? AND entity_id = ?",
                (entity_kind, str(entity_id)))
            self._conn.commit()
        return bool(cur.rowcount)

    def mute_row(self, entity_kind: str, entity_id: str) -> sqlite3.Row | None:
        """The ACTIVE mute for an entity, or None. An expired row reads as no
        mute rather than being deleted here — reads happen on the hot path and
        prune() clears the rows out on the housekeeping pass."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alert_mutes WHERE entity_kind = ? AND"
                " entity_id = ? AND until_ts > ?",
                (entity_kind, str(entity_id), time.time())).fetchone()

    def mutes(self, entity_kind: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM alert_mutes WHERE until_ts > ?"
        args: list = [time.time()]
        if entity_kind:
            sql += " AND entity_kind = ?"
            args.append(entity_kind)
        with self._lock:
            return self._conn.execute(sql + " ORDER BY until_ts", args).fetchall()

    def muted_entity_ids(self, entity_kind: str = "device",
                         window_covered: dict[str, float] | None = None
                         ) -> dict[str, float]:
        """entity_id -> until_ts for every active mute of this kind, PLUS
        every device an active maintenance window covers right now, so every
        reader — the engine's per-tick occurrence gate, the Nodes device
        list — answers "is this device quiet" the same way for either
        mechanism.

        `window_covered` is resolved by the CALLER (window_covered_device_ids
        below) rather than here: a window's scope can be a device GROUP, and
        alertsdb has no nodesdb of its own to expand "group 4" into device
        ids without importing a module a step below it in the layering.
        Passing None (the default) answers exactly as before windows
        existed — every existing caller that has not been taught about
        windows yet keeps working unchanged.

        Where both a manual mute and a window cover the same device, the
        LATER until_ts wins — that is the later moment either mechanism
        stops applying, which is what "muted" ought to mean for a device
        covered by both.
        """
        ids = {row["entity_id"]: row["until_ts"] for row in self.mutes(entity_kind)}
        if entity_kind == "device" and window_covered:
            for device_id, until_ts in window_covered.items():
                if device_id not in ids or until_ts > ids[device_id]:
                    ids[device_id] = until_ts
        return ids

    def merge_device(self, old_device_id: int, new_device_id: int,
                     by: str = "") -> dict:
        """Two device rows turned out to be one: hand Alerts' half over to
        the surviving id. The winner's own threshold stands; the loser's
        copies over only where the winner has none. Open alerts against
        the loser are resolved, not repointed — their entity is gone, and
        an alert nobody can navigate to is worse than one closed with a
        reason. Everything else (a mute, pending occurrences, a
        maintenance window) simply moves.
        """
        old_key, new_key = str(old_device_id), str(new_device_id)
        moved = {"thresholds": 0, "pending": 0, "windows": 0, "mute": False}
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO device_thresholds(device_id, rule_key,"
                " threshold, clear_threshold, enabled, updated_ts)"
                " SELECT ?, rule_key, threshold, clear_threshold, enabled,"
                " updated_ts FROM device_thresholds WHERE device_id = ?",
                (new_device_id, old_device_id))
            moved["thresholds"] = cur.rowcount or 0
            self._conn.execute("DELETE FROM device_thresholds WHERE device_id = ?",
                               (old_device_id,))
            winner_mute = self._conn.execute(
                "SELECT 1 FROM alert_mutes WHERE entity_kind = 'device'"
                " AND entity_id = ?", (new_key,)).fetchone()
            if winner_mute is None:
                cur = self._conn.execute(
                    "UPDATE alert_mutes SET entity_id = ? WHERE entity_kind ="
                    " 'device' AND entity_id = ?", (new_key, old_key))
                moved["mute"] = bool(cur.rowcount)
            else:
                self._conn.execute(
                    "DELETE FROM alert_mutes WHERE entity_kind = 'device'"
                    " AND entity_id = ?", (old_key,))
            cur = self._conn.execute(
                "UPDATE pending_alerts SET device_id = ? WHERE device_id = ?",
                (new_device_id, old_device_id))
            moved["pending"] = cur.rowcount or 0
            open_ids = [row["id"] for row in self._conn.execute(
                "SELECT id FROM alerts WHERE entity_kind = 'device'"
                " AND entity_id = ? AND state IN ('open','acked')",
                (old_key,)).fetchall()]
            windows = self._conn.execute(
                "SELECT id, scope_device_ids FROM maintenance_windows"
                " WHERE scope_kind = 'devices'").fetchall()
            for row in windows:
                try:
                    ids = [int(i) for i in json.loads(row["scope_device_ids"] or "[]")]
                except (TypeError, ValueError):
                    continue
                if old_device_id not in ids:
                    continue
                rewritten = []
                for device_id in ids:
                    device_id = new_device_id if device_id == old_device_id else device_id
                    if device_id not in rewritten:
                        rewritten.append(device_id)
                self._conn.execute(
                    "UPDATE maintenance_windows SET scope_device_ids = ? WHERE id = ?",
                    (json.dumps(rewritten, separators=(",", ":")), row["id"]))
                moved["windows"] += 1
            self._conn.commit()
        if open_ids:
            self.resolve_many(open_ids, by=by or "merge")
        moved["resolved"] = len(open_ids)
        return moved

    def purge_expired_mutes(self, now: float | None = None) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alert_mutes WHERE until_ts <= ?",
                                     (now if now is not None else time.time(),))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------- maintenance windows

    def windows(self) -> list[sqlite3.Row]:
        """Every window, past, active and future — the list an operator's
        Maintenance windows page shows. Callers that only care whether a
        window is covering anything RIGHT NOW want active_windows()."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM maintenance_windows ORDER BY start_ts DESC"
            ).fetchall()

    def window(self, window_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM maintenance_windows WHERE id = ?",
                (window_id,)).fetchone()

    def active_windows(self, now: float | None = None) -> list[sqlite3.Row]:
        """Every window covering something RIGHT NOW — a small, Python-side
        filter over windows() rather than a recurrence-aware SQL WHERE
        clause, because a real deployment has a handful of maintenance
        windows at a time (unlike alerts or traps, which justify a live
        GROUP BY over thousands of rows), the same "small enough that Python
        is the honest cost" reasoning trim_to_size's own docstring already
        leans on elsewhere in this file."""
        now = time.time() if now is None else now
        return [row for row in self.windows() if is_window_active(row, now)]

    def _validate_window_scope(self, scope_kind: str, scope_group_id,
                               scope_device_ids) -> tuple:
        if scope_kind == "group":
            if not scope_group_id:
                raise ValueError("A maintenance window scoped to a group needs a group id")
            return "group", int(scope_group_id), None
        if scope_kind == "devices":
            ids = [int(i) for i in (scope_device_ids or [])]
            if not ids:
                raise ValueError("A maintenance window scoped to devices needs at least one")
            return "devices", None, json.dumps(ids, separators=(",", ":"))
        raise ValueError("scope_kind must be 'group' or 'devices'")

    def add_window(self, name: str, scope_kind: str, start_ts: float, end_ts: float,
                   scope_group_id=None, scope_device_ids=None,
                   recurrence: str | None = None, created_by: str = "",
                   reason: str = "") -> int:
        """A window may be created in advance — start_ts in the future is
        exactly the "planned weekend cutover" case, not an error."""
        name = (name or "").strip()
        if not name:
            raise ValueError("A maintenance window needs a name")
        if end_ts <= start_ts:
            raise ValueError("A maintenance window must end after it starts")
        if end_ts - start_ts > MAX_WINDOW_DAYS * 86400.0:
            raise ValueError(f"A maintenance window is capped at "
                             f"{MAX_WINDOW_DAYS:g} days")
        if recurrence not in (None, "", "weekly"):
            raise ValueError("recurrence must be 'weekly' or absent")
        if recurrence == "weekly" and end_ts - start_ts >= _WEEK_S:
            # is_window_active's own modulo test is what makes this a real
            # bug and not just a wasteful setting: (now - start_ts) % week
            # is always < duration once duration >= a week, so a window
            # this long recurring weekly is active at EVERY instant —
            # permanently silencing its whole scope, forever, with no
            # symptom beyond "why did nothing alert for three months".
            # MAX_WINDOW_DAYS (14) only bounds a single occurrence's span,
            # not this — a one-off window is still allowed the full 14
            # days, since it has an actual end.
            raise ValueError(
                "A weekly recurring window's occurrence must be under 7 "
                "days — a longer one would be active every instant of "
                "every week, silencing its scope permanently")
        scope_kind, scope_group_id, scope_device_ids = self._validate_window_scope(
            scope_kind, scope_group_id, scope_device_ids)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO maintenance_windows(name, scope_kind, scope_group_id,"
                " scope_device_ids, start_ts, end_ts, recurrence, created_ts,"
                " created_by, reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (name, scope_kind, scope_group_id, scope_device_ids,
                 float(start_ts), float(end_ts), recurrence or None, time.time(),
                 created_by, reason))
            self._conn.commit()
            return cur.lastrowid

    def update_window(self, window_id: int, **fields) -> None:
        """Edit before or while a window is active — a cutover that runs long
        gets its end_ts pushed out without having to be deleted and
        recreated (which would lose its id, and anything that links to it)."""
        row = self.window(window_id)
        if row is None:
            return
        name = fields.get("name", row["name"])
        start_ts = float(fields.get("start_ts", row["start_ts"]))
        end_ts = float(fields.get("end_ts", row["end_ts"]))
        recurrence = fields.get("recurrence", row["recurrence"])
        reason = fields.get("reason", row["reason"])
        if "scope_kind" in fields or "scope_group_id" in fields or "scope_device_ids" in fields:
            scope_kind, scope_group_id, scope_device_ids = self._validate_window_scope(
                fields.get("scope_kind", row["scope_kind"]),
                fields.get("scope_group_id", row["scope_group_id"]),
                fields.get("scope_device_ids",
                          json.loads(row["scope_device_ids"] or "[]")
                          if row["scope_kind"] == "devices" else None))
        else:
            scope_kind = row["scope_kind"]
            scope_group_id = row["scope_group_id"]
            scope_device_ids = row["scope_device_ids"]
        name = (name or "").strip()
        if not name:
            raise ValueError("A maintenance window needs a name")
        if end_ts <= start_ts:
            raise ValueError("A maintenance window must end after it starts")
        if end_ts - start_ts > MAX_WINDOW_DAYS * 86400.0:
            raise ValueError(f"A maintenance window is capped at "
                             f"{MAX_WINDOW_DAYS:g} days")
        if recurrence not in (None, "", "weekly"):
            raise ValueError("recurrence must be 'weekly' or absent")
        if recurrence == "weekly" and end_ts - start_ts >= _WEEK_S:
            # Same reasoning as add_window's own check just above — an
            # edit that turns an existing window weekly, or stretches an
            # already-weekly one's span, must be caught here too.
            raise ValueError(
                "A weekly recurring window's occurrence must be under 7 "
                "days — a longer one would be active every instant of "
                "every week, silencing its scope permanently")
        with self._lock:
            self._conn.execute(
                "UPDATE maintenance_windows SET name=?, scope_kind=?,"
                " scope_group_id=?, scope_device_ids=?, start_ts=?, end_ts=?,"
                " recurrence=?, reason=? WHERE id=?",
                (name, scope_kind, scope_group_id, scope_device_ids, start_ts,
                 end_ts, recurrence or None, reason, window_id))
            self._conn.commit()

    def end_window_now(self, window_id: int) -> bool:
        """"End now": stop covering anything from this moment, without
        deleting the window's own history (its name, scope and start remain
        on the record). A recurring window's recurrence is cleared in the
        same call — otherwise the next week's occurrence would start right
        back up, which is not what an operator ending a window early means.

        The `end_ts > now` half of the WHERE clause is the "already ended,
        nothing to do" guard for a ONE-OFF window — but a WEEKLY window's
        stored end_ts is only ever the FIRST occurrence's end; every later
        week's occurrence is judged by is_window_active's own
        (now - start_ts) % week test against start_ts, never by that column.
        Three weeks into a weekly window, end_ts sits three weeks in the
        past while this week's occurrence is active RIGHT NOW — applying
        the one-off guard to it made "End now" a silent no-op, and the
        window kept firing every week after. So the guard only applies when
        recurrence is NULL; a recurring window is always ended here, whatever
        its stored end_ts says, by dropping it to now and clearing
        recurrence — exactly the inert one-off [start_ts, now) shape
        is_window_active already treats as over for good.

        Returns whether a row was actually changed, so a caller does not
        report success for what was really a no-op.
        """
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE maintenance_windows SET end_ts=?, recurrence=NULL"
                " WHERE id=? AND (recurrence IS NOT NULL OR end_ts > ?)",
                (now, window_id, now))
            self._conn.commit()
        return bool(cur.rowcount)

    def remove_window(self, window_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM maintenance_windows WHERE id = ?", (window_id,))
            self._conn.commit()
        return bool(cur.rowcount)

    def _window_scope_matches(self, row, device_id: str, device_group_id) -> bool:
        if row["scope_kind"] == "group":
            return (device_group_id is not None and row["scope_group_id"] is not None
                    and int(device_group_id) == int(row["scope_group_id"]))
        try:
            ids = json.loads(row["scope_device_ids"] or "[]")
        except (TypeError, ValueError):
            return False
        return device_id in {str(i) for i in ids}

    def window_covered_device_ids(self, devices, now: float | None = None,
                                  windows=None) -> dict[str, float]:
        """entity_id -> the covering window's current until_ts, for every
        device in `devices` (an iterable of (device_id, device_group_id)
        pairs, exactly the two columns Nodes' own device rows already carry)
        that an active window covers.

        Scope resolution stays purely ids-in/ids-out on purpose: alertsdb
        has no nodesdb of its own, so the caller (AlertEngine, or the API
        layer, both of which already have a nodesdb) supplies the pairs
        rather than this module reaching sideways for one.
        """
        now = time.time() if now is None else now
        active = self.active_windows(now) if windows is None else windows
        if not active:
            return {}
        result: dict[str, float] = {}
        for device_id, device_group_id in devices:
            did = str(device_id)
            for row in active:
                if self._window_scope_matches(row, did, device_group_id):
                    until = _window_occurrence_end(row, now)
                    if did not in result or until > result[did]:
                        result[did] = until
        return result

    def window_covers_device(self, device_id, device_group_id,
                             now: float | None = None) -> float | None:
        """The single-device version of window_covered_device_ids, for a
        caller (a device's own page, the engine's per-alert clear check)
        that only ever asks about one device and would rather not build a
        one-item iterable to ask."""
        now = time.time() if now is None else now
        did = str(device_id)
        best = None
        for row in self.active_windows(now):
            if self._window_scope_matches(row, did, device_group_id):
                until = _window_occurrence_end(row, now)
                if best is None or until > best:
                    best = until
        return best

    def acknowledge_many(self, alert_ids: list[int], by: str = "") -> int:
        """Acknowledge exactly the given alerts — the selection-respecting
        counterpart to acknowledge_all, which deliberately ignores any
        selection and takes every open alert on the server."""
        if not alert_ids:
            return 0
        marks = ",".join("?" * len(alert_ids))
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE alerts SET state='acked', acked_ts=?, acked_by=?"
                f" WHERE id IN ({marks}) AND state='open'",
                (time.time(), by, *alert_ids))
            self._conn.commit()
            return cursor.rowcount or 0

    def resolve_by_dedup(self, dedup_key: str, by: str = "",
                        rolled_up_into: int | None = None) -> sqlite3.Row | None:
        """Resolves the one open/acked alert at `dedup_key`, if any.

        `rolled_up_into`, when given, additionally records the id of the
        alert this one was absorbed into — see the schema comment on
        alerts.rolled_up_into in _migrate for why that is a separate fact
        from `by`/`resolved_by`, which stays '' for a rollup absorption
        exactly as it always has. Every existing caller omits it and gets
        today's behaviour unchanged; only alertengine's rollup absorption
        (_absorb_subordinates/_absorb_downstream) passes it.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?,"
                " rolled_up_into=? WHERE id=?",
                (time.time(), by, rolled_up_into, row["id"]))
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (row["id"],)).fetchone()

    def resolve_by_dedup_prefix(self, prefix: str, by: str = "",
                                rolled_up_into: int | None = None
                                ) -> list[sqlite3.Row]:
        """resolve_by_dedup for a whole family of keys at once (a per-port
        rule's alerts share one "<rule>:interface:<device_id>:" prefix),
        oldest first.

        Bounds rather than LIKE: the prefix's last character is bumped by
        one for an exclusive upper bound, a range scan on
        ux_alerts_active_dedup -- an escaped LIKE (underscores in the key)
        couldn't use the index at all.
        """
        if not prefix:
            return []
        upper = prefix[:-1] + chr(ord(prefix[-1]) + 1)
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key >= ? AND dedup_key < ?"
                " AND state IN ('open','acked') ORDER BY opened_ts",
                (prefix, upper)).fetchall()
            if not rows:
                return []
            now = time.time()
            for row in rows:
                self._conn.execute(
                    "UPDATE alerts SET state='resolved', resolved_ts=?,"
                    " resolved_by=?, rolled_up_into=? WHERE id=?",
                    (now, by, rolled_up_into, row["id"]))
            self._conn.commit()
            marks = ",".join("?" * len(rows))
            return self._conn.execute(
                f"SELECT * FROM alerts WHERE id IN ({marks}) ORDER BY opened_ts",
                [row["id"] for row in rows]).fetchall()

    def alerts_rolled_up_into(self, parent_id: int) -> list[sqlite3.Row]:
        """Every alert absorbed DIRECTLY into `parent_id`'s rollup, oldest
        first — the structured form of what rollup_note already says in
        prose, for a parent's own detail view. Backed by
        ix_alerts_rolled_up_into.

        `rolled_up_into` can chain, and this method does not follow the
        chain: a child alert resolved by its own device's device_down
        (alertengine._absorb_subordinates) points at that device_down row,
        and if an ancestor's outage later absorbs that device_down TOO
        (_absorb_downstream), the device_down's own rolled_up_into moves to
        the ancestor -- but the grandchild alert's does not, because
        resolve_by_dedup only ever touches open/acked rows and the
        grandchild was already resolved by the time the ancestor's outage
        ran. So a caller that wants "the ultimate parent of this alert",
        rather than "what specifically absorbed it", has to follow
        rolled_up_into by hand until it hits an alert with no rolled_up_into
        of its own -- this treats one hop as the whole answer, which is
        right for a detail view ("this outage directly absorbed these") and
        wrong for anything that assumes the pointer is always the current,
        topmost outage."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE rolled_up_into = ?"
                " ORDER BY opened_ts", (parent_id,)).fetchall()

    # An alert the engine resolved on its own -- a CLEARS pair, a threshold
    # dropping back below clear_threshold, a rollup absorbing a child, a
    # NetPath destination that stopped being traced -- always writes '' to
    # resolved_by, the same convention every internal resolve_by_dedup(by="")
    # call already followed; 'engine' is accepted too for any future call
    # site that wants a non-empty marker without meaning a person. Every
    # resolve triggered by a person goes through the API with a real,
    # non-empty session username (write endpoints require a session), so
    # this predicate is exactly "resolved by hand".
    #
    # The COALESCE changes nothing about the one query that uses this. A NULL
    # resolved_by makes `NULL NOT IN ('', 'engine')` evaluate to NULL, and a
    # WHERE clause discards NULL exactly as it discards false — which is the
    # answer wanted, since a row with no resolved_by is not an operator
    # resolve. It is written out anyway because the predicate reads as a
    # statement about the data ("resolved by a person") rather than as a
    # filter that happens to work, and because a future caller that asks it
    # the other way round (NOT (...), or in a CASE) would get NULL where it
    # wanted true. Rows with a NULL resolved_by exist: a much older build, or
    # a hand edit in sqlite3.
    _OPERATOR_RESOLVE_SQL = "COALESCE(resolved_by, '') NOT IN ('', 'engine')"

    def operator_resolved_since(self, cutoff_ts: float) -> dict[str, float]:
        """dedup_key -> latest resolved_ts, for every dedup_key an operator
        resolved by hand at or after cutoff_ts. One indexed query
        (ix_alerts_state_resolved, whose leading (state, resolved_ts) is
        exactly this range scan) rather than one per breaching rule/device;
        AlertEngine runs this once per tick and caches the result."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT dedup_key, MAX(resolved_ts) AS ts FROM alerts"
                f" WHERE state = 'resolved' AND {self._OPERATOR_RESOLVE_SQL}"
                " AND resolved_ts >= ? GROUP BY dedup_key",
                (cutoff_ts,)).fetchall()
        return {row["dedup_key"]: row["ts"] for row in rows}

    def open_dedup_keys(self) -> set:
        """Every dedup_key with an open or acknowledged alert.

        One query for the whole set rather than open_by_dedup per candidate:
        the threshold evaluator asks "does this already have an alert" for
        every breaching device on every tick, and during a site outage that
        is hundreds of lookups a tick for an answer that is almost always
        yes.
        """
        with self._lock:
            return {row["dedup_key"] for row in self._conn.execute(
                "SELECT dedup_key FROM alerts WHERE state IN ('open','acked')"
            ).fetchall()}

    def open_by_dedup(self, dedup_key: str) -> sqlite3.Row | None:
        """The open (or acknowledged) alert for this dedup key, if any.

        Acknowledged counts as open on purpose: an operator who has seen the
        outage and ticked it off has not made the device reachable, so the
        alerts it implies are still redundant.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()

    # How many lines an alert's rollup note may hold. Distinct lines, not
    # repeats — those are skipped below — so this only bites where a single
    # outage genuinely absorbed dozens of different alerts, which since the
    # topology rollup means a site's worth of downstream devices. The note is
    # read by a person; past a screenful it stops informing and starts
    # costing a row rewrite per absorbed alert.
    MAX_ROLLUP_NOTE_LINES = 50

    def add_rollup_note(self, alert_id: int, line: str) -> None:
        """Appends one line to an alert's rollup note, skipping duplicates so
        a flapping device does not grow the same line hundreds of times."""
        with self._lock:
            row = self._conn.execute(
                "SELECT rollup_note FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                return
            existing = row["rollup_note"] or ""
            lines = existing.split("\n") if existing else []
            if line in lines:
                return
            if len(lines) >= self.MAX_ROLLUP_NOTE_LINES:
                return
            merged = (existing + "\n" + line).strip() if existing else line
            self._conn.execute("UPDATE alerts SET rollup_note = ? WHERE id = ?",
                               (merged, alert_id))
            self._conn.commit()

    def acknowledge(self, alert_id: int, by: str, note: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET state='acked', acked_ts=?, acked_by=?, ack_note=?"
                " WHERE id=? AND state='open'", (time.time(), by, note, alert_id))
            self._conn.commit()

    def acknowledge_all(self, by: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE alerts SET state='acked', acked_ts=?, acked_by=?"
                " WHERE state='open'", (time.time(), by))
            self._conn.commit()
            return cursor.rowcount or 0

    def unacknowledge(self, alert_id: int) -> None:
        """Undo a mistaken (or simply premature) Acknowledge, returning the
        alert to plain 'open'. acked_ts/acked_by/ack_note are cleared rather
        than kept alongside a new "unacked" marker — this alert is, again,
        exactly an unacknowledged one, and who reversed the acknowledgement
        and when is the API layer's own audit-log entry (alert.unack), the
        same place who acknowledged it in the first place is NOT recorded on
        the row either. Only from 'acked': an open alert has nothing to
        undo, and a resolved one is not brought back to life by this.

        No downstream state to reconcile: renotify_minutes' own sweep
        (alerts_due_renotify) already reads state='open', so an alert that
        goes back to 'open' here is simply due for renotify again on
        whatever the normal schedule already is — nothing special to it.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET state='open', acked_ts=NULL, acked_by=NULL,"
                " ack_note=NULL WHERE id=? AND state='acked'", (alert_id,))
            self._conn.commit()

    def unacknowledge_many(self, alert_ids: list[int]) -> int:
        """The bulk counterpart, mirroring acknowledge_many's own shape —
        acts on exactly the given ids, ignoring any that are not currently
        acked rather than raising for them."""
        if not alert_ids:
            return 0
        marks = ",".join("?" * len(alert_ids))
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE alerts SET state='open', acked_ts=NULL, acked_by=NULL,"
                f" ack_note=NULL WHERE id IN ({marks}) AND state='acked'",
                alert_ids)
            self._conn.commit()
            return cursor.rowcount or 0

    # ------------------------------------------------------------ notifications

    def record_notification(self, alert_id: int | None, kind: str, to_addr: str,
                            subject: str, ok: bool, error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO notifications(alert_id, kind, ts, to_addr, subject,"
                " ok, error) VALUES (?,?,?,?,?,?,?)",
                (alert_id, kind, time.time(), to_addr, subject, 1 if ok else 0, error))
            self._conn.commit()

    def notifications_for(self, alert_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM notifications WHERE alert_id = ? ORDER BY ts DESC",
                (alert_id,)).fetchall()

    # ----------------------------------------------------------------- cursors

    def cursor(self, source: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT cursor_id FROM meta WHERE source = ?", (source,)).fetchone()
        return row["cursor_id"] if row else 0

    def has_cursor(self, source: str) -> bool:
        """Whether `source` has ever been seeded, distinct from cursor()
        legitimately returning 0 once it has been. A fresh install must
        seed every cursor to each source's current max id on its first
        tick — never to 0 — so it doesn't evaluate a source's entire
        pre-existing history as brand new occurrences."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM meta WHERE source = ?", (source,)).fetchone()
        return row is not None

    def set_cursor(self, source: str, value: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(source, cursor_id) VALUES (?,?)"
                " ON CONFLICT(source) DO UPDATE SET cursor_id=excluded.cursor_id",
                (source, value))
            self._conn.commit()

    # ------------------------------------------------------------------ storage

    def prune(self, retention_days: float, max_rows: int = 0) -> int:
        """Deletes resolved alerts (and, via the FK, their notifications)
        older than the cutoff. Open/acknowledged alerts are never pruned
        by age or count — an alert nobody has resolved does not silently
        disappear from history because it has been open a long time."""
        removed = 0
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM alerts WHERE state = 'resolved' AND resolved_ts < ?",
                (cutoff,))
            removed += cursor.rowcount or 0
            if max_rows:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM alerts WHERE state = 'resolved'"
                ).fetchone()["n"]
                if total > max_rows:
                    cursor = self._conn.execute(
                        "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                        " WHERE state = 'resolved' ORDER BY resolved_ts ASC LIMIT ?)",
                        (total - max_rows,))
                    removed += cursor.rowcount or 0
            # Lapsed mutes read as "not muted" from the moment they expire;
            # this only stops the table growing a row per mute ever set.
            self._conn.execute("DELETE FROM alert_mutes WHERE until_ts <= ?",
                               (time.time(),))
            self._conn.commit()
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest resolved alerts until the file fits, reclaiming
        the freed pages between passes.

        The reclaim runs outside the delete's lock block: incremental vacuum
        frees pages in short steps that each take and release the lock, so a
        trim never blocks a write for longer than one step.
        """
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM alerts WHERE state = 'resolved'"
                ).fetchone()["n"]
                # A floor, not a target: below this there is nothing left to
                # delete that is not an operator's own history.
                exhausted = total <= 500
                if not exhausted:
                    chunk = max(int(total * 0.15), 200)
                    cursor = self._conn.execute(
                        "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                        " WHERE state = 'resolved' ORDER BY resolved_ts ASC LIMIT ?)",
                        (chunk,))
                    removed += cursor.rowcount or 0
                    self._conn.commit()
            if exhausted:
                break
            reclaim(self._conn, self._lock, label="alerts")
        return removed

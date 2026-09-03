"""Storage for the Alerts module: rule definitions, open/acknowledged/
resolved alerts, email templates, notification history, SMTP settings and
credential, and per-source evaluation cursors.

Alert volume is orders of magnitude lower than trap or syslog volume, so
unlike `syslogdb.py`/`snmptrapdb.py` there is no hourly rollup table for the
histogram — a live `GROUP BY` over `alerts` is always cheap enough, the same
reasoning `snmptrapdb.py` already used to justify skipping FTS5 search.

Exactly one OPEN or ACKED alert may exist per `dedup_key` at a time (a
partial unique index, not a full UNIQUE constraint, because the same
dedup_key legitimately recurs after a prior alert resolves) — a repeated
occurrence increments that alert's `count` rather than opening a duplicate.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

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
    "renotify_minutes": 0,          # 0 = notify once per open alert, never again while open
    "notify_on_clear": True,
    "max_emails_per_hour": 60,
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
"""

# How long a mute may last. The dropdown offers 1/6/12/24 hours; the cap is
# here so a hand-made API call cannot silence a device until next year.
MAX_MUTE_HOURS = 24.0

_RULE_EDITABLE = ("name", "severity", "enabled", "device_filter", "threshold",
                  "clear_threshold", "for_polls", "for_seconds", "template_id",
                  "flap_window_s", "flap_min_transitions", "auto_resolve_after_s",
                  "notify")
_RULE_CUSTOM_EDITABLE = _RULE_EDITABLE + ("kind", "source_kind")

# 35 built-in rules: 8 device_event + 3 interface_event + 11 threshold +
# 3 trap + 1 syslog + 1 ipam + 2 wireless_event + 1 dhcp_threshold +
# 3 netpath_threshold + 2 system. Each `template` name is a
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
]

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

# Template text as shipped by the PREVIOUS release, verbatim, for every
# built-in whose wording has since changed.
#
# _seed_templates inserts OR IGNORE, so an install that already has an
# alerts.db keeps its templates forever — which is right for one an operator
# edited and wrong for one nobody has touched, since that one is simply the
# old shipped text sitting where the new shipped text belongs. _migrate uses
# this to tell those two apart: a body that still matches exactly what the
# last release shipped is one nobody has edited.
#
# 4.32.0: the recovery template said "is responding again as of {{last_time}}",
# and last_time on a resolution notification is when the OUTAGE last recurred —
# a moment before the recovery, not the recovery. It now names the recovery
# time and how long the outage lasted.
_PREVIOUS_BUILTIN_TEMPLATES = {
    "device_up": {
        "subject": "SappiWhere: {{device_name}} has recovered",
        "body": ("{{device_name}} ({{device_ip}}) is responding again as of "
                 "{{last_time}}.\n\n{{message}}\n\n"
                 "-- SappiWhere, {{severity_name}}"),
    },
}


class AlertsDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.executescript(PENDING_SCHEMA)
            self._migrate()
            self._conn.commit()
        self._seed_templates()
        self._seed_rules()
        self._run_named_migrations()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS leaves an existing table alone, so a column
        added to `rules` after some installs already have an alerts.db has to
        be added explicitly — the same convention nodesdb.py, wirelessdb.py
        and db.py already use for their own post-release columns.
        """
        rules = {row["name"] for row in
                 self._conn.execute("PRAGMA table_info(rules)").fetchall()}
        for column in ("flap_window_s", "flap_min_transitions", "for_seconds",
                       "auto_resolve_after_s"):
            if column not in rules:
                self._conn.execute(
                    f"ALTER TABLE rules ADD COLUMN {column} INTEGER")
        if "notify" not in rules:
            self._conn.execute(
                "ALTER TABLE rules ADD COLUMN notify INTEGER NOT NULL DEFAULT 1")
            self._conn.execute(
                "UPDATE rules SET notify = 0 WHERE key = 'mib_missing'")
        if "for_seconds" not in rules:
            # Seed the shipped default onto an existing database, so an
            # install that already has alerts.db gets sustained packet loss
            # rather than the pre-4.31 single-sample behaviour. Only this
            # one rule: every other threshold keeps counting polls.
            self._conn.execute(
                "UPDATE rules SET for_seconds = 60 WHERE key = 'packet_loss_high'")
        self._migrate_templates()
        alerts = {row["name"] for row in
                  self._conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for column, kind, default in (("last_notified_ts", "REAL", None),
                                      ("extra_json", "TEXT", "'{}'")):
            if column not in alerts:
                self._conn.execute(
                    f"ALTER TABLE alerts ADD COLUMN {column} {kind}"
                    + (f" NOT NULL DEFAULT {default}" if default else ""))
        if "rollup_note" not in alerts:
            # What this alert absorbed, one line per rolled-up alert. Its own
            # column rather than appended to `detail`, which open_or_increment
            # overwrites every time the same alert recurs.
            self._conn.execute(
                "ALTER TABLE alerts ADD COLUMN rollup_note TEXT NOT NULL DEFAULT ''")
        # Backs operator_resolved_ts/operator_resolved_since: both filter on
        # (state, resolved_by) and group by dedup_key, so an index leading
        # with dedup_key and covering state and resolved_ts serves the exact
        # query the engine runs once per tick.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_alerts_dedup_state"
            " ON alerts(dedup_key, state, resolved_ts)")

    # Post-seed migrations, in the order they were introduced. A migration
    # belongs here rather than in _migrate() when it has to read or rewrite
    # the seeded built-ins — _migrate runs before seeding and has to, because
    # seeding needs the columns it adds.
    def _named_migrations(self) -> tuple:
        return (
            ("rekey_trap_syslog_alerts_1", self._rekey_trap_syslog_alerts),
            ("seed_auto_resolve_1", self._seed_auto_resolve),
            ("rebind_event_notice_1", self._rebind_event_notice),
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
        for key, previous in _PREVIOUS_BUILTIN_TEMPLATES.items():
            current = alertmail.BUILTIN_TEMPLATES.get(key)
            if not current:
                continue
            self._conn.execute(
                "UPDATE templates SET builtin_subject = ?, builtin_body = ?"
                " WHERE key = ?", (current["subject"], current["body"], key))
            self._conn.execute(
                "UPDATE templates SET subject = ?, body = ?, updated_ts = ?"
                " WHERE key = ? AND subject = ? AND body = ?",
                (current["subject"], current["body"], now, key,
                 previous["subject"], previous["body"]))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

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
                    " threshold, clear_threshold, for_polls, for_seconds,"
                    " auto_resolve_after_s, template_id,"
                    " created_ts) VALUES (?,?,?,?,?,1,1,'',?,?,?,?,?,?,?,?)",
                    (key, name, kind, source_kind, severity,
                     0 if key in _BUILTIN_NOTIFY_OFF else 1, threshold,
                     clear_threshold, for_polls, _BUILTIN_FOR_SECONDS.get(key),
                     _BUILTIN_AUTO_RESOLVE_S.get(key),
                     template_ids.get(template_key), now))
            self._conn.commit()

    # --------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
            cred = self._conn.execute(
                "SELECT password_enc FROM smtp_credential WHERE id = 1").fetchone()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        values["has_smtp_credential"] = bool(cred and cred["password_enc"])
        return values

    def save_settings(self, values: dict) -> None:
        with self._lock:
            for key, value in values.items():
                if key not in DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)))
            self._conn.commit()

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
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE rules SET {clauses} WHERE id = ?",
                (*allowed.values(), rule_id))
            self._conn.commit()

    def remove_rule(self, rule_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM rules WHERE id = ? AND is_builtin = 0", (rule_id,))
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

    def alerts(self, state: str | None = None, severity: int | None = None,
              rule_id: int | None = None, device_text: str | None = None,
              text: str | None = None, t0: float | None = None,
              t1: float | None = None, limit: int = 300) -> list[sqlite3.Row]:
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
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM alerts{where} ORDER BY last_ts DESC LIMIT ?",
                (*params, limit)).fetchall()

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

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM pending_alerts").fetchone()
        return row["n"] if row else 0

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

    def muted_entity_ids(self, entity_kind: str = "device") -> dict[str, float]:
        """entity_id -> until_ts for every active mute of this kind. Read once
        per engine tick, so the per-occurrence check is a dict lookup rather
        than a query."""
        return {row["entity_id"]: row["until_ts"]
                for row in self.mutes(entity_kind)}

    def purge_expired_mutes(self, now: float | None = None) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alert_mutes WHERE until_ts <= ?",
                                     (now if now is not None else time.time(),))
            self._conn.commit()
        return cur.rowcount or 0

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

    def resolve_by_dedup(self, dedup_key: str, by: str = "") -> sqlite3.Row | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                " WHERE id=?", (time.time(), by, row["id"]))
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (row["id"],)).fetchone()

    # An alert the engine resolved on its own -- a CLEARS pair, a threshold
    # dropping back below clear_threshold, a rollup absorbing a child, a
    # NetPath destination that stopped being traced -- always writes '' to
    # resolved_by, the same convention every internal resolve_by_dedup(by="")
    # call already followed; 'engine' is accepted too for any future call
    # site that wants a non-empty marker without meaning a person. Every
    # resolve triggered by a person goes through the API with a real,
    # non-empty session username (write endpoints require a session), so
    # this predicate is exactly "resolved by hand".
    _OPERATOR_RESOLVE_SQL = "resolved_by NOT IN ('', 'engine')"

    def operator_resolved_ts(self, dedup_key: str) -> float | None:
        """The latest resolved_ts of a `resolved` alert with this dedup_key
        that an operator resolved by hand, or None when the alert has never
        been resolved or was only ever auto-resolved by the engine.

        Used by AlertEngine to decide whether a still-breaching (or still
        down) condition is the SAME run an operator already resolved --
        see operator_resolved_since for the per-tick bulk form of this same
        query, which is what the engine actually calls on its hot path.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(resolved_ts) AS ts FROM alerts WHERE dedup_key = ?"
                f" AND state = 'resolved' AND {self._OPERATOR_RESOLVE_SQL}",
                (dedup_key,)).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    def operator_resolved_since(self, cutoff_ts: float) -> dict[str, float]:
        """dedup_key -> latest resolved_ts, for every dedup_key an operator
        resolved by hand at or after cutoff_ts. One indexed query
        (ix_alerts_dedup_state) rather than one per breaching rule/device;
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

    def add_rollup_note(self, alert_id: int, line: str) -> None:
        """Appends one line to an alert's rollup note, skipping duplicates so
        a flapping device does not grow the same line hundreds of times."""
        with self._lock:
            row = self._conn.execute(
                "SELECT rollup_note FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                return
            existing = row["rollup_note"] or ""
            if line in existing.split("\n"):
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

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

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
                if total <= 500:
                    break
                chunk = max(int(total * 0.15), 200)
                cursor = self._conn.execute(
                    "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                    " WHERE state = 'resolved' ORDER BY resolved_ts ASC LIMIT ?)",
                    (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed

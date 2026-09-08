"""AlertEngine: the evaluation scheduler.

Drains new device/interface events (from Nodes), SNMP traps, Syslog
messages and IPAM conflicts; evaluates Nodes metric thresholds; matches
occurrences against enabled rules; opens/increments/resolves alerts; and
rate-limits and sends email notifications.

A single fixed 5-second tick, not a per-entity variable interval the way
polling is — evaluation has no "this device is due" concept, only "is
there anything new to look at right now," which matches IpamWorker's
cadence rather than Monitor's per-target scheduling.
"""

from __future__ import annotations

import inspect
import json
import threading
import time
import traceback
from dataclasses import asdict

from . import alertmail
from . import namelookup
from .alertrules import CLEARS, PUBLISHED_HYSTERESIS, \
    PUBLISHED_THRESHOLD_RULES, ROLLED_UP_BY, ROLLS_UP, ROLLUP_ENTITY_KINDS, \
    UNMANAGED_ONLY_RULES, Occurrence, breaches, dedup_key, device_id_for, \
    comparison_of, evaluate_flapping, evaluate_threshold, interface_label, \
    match_device, same_metric_pair, syslog_signature
from .eventlog import ALERTS, ERROR, NODES, NullLog
from .nodesdb import TIMELINE_ONLY_EVENT_KINDS
from .worker import Worker, ago

TICK_S = 5.0

# device_events kinds that exist only to back the status timeline's split
# SNMP/ping lanes (see nodesdb.device_method_segments) and carry no alert
# meaning of their own — snmp_ok/ping_ok flipping is already covered by
# `down`/`up`/`snmp_error`/`auth_fail`. _drain_device_events below turns
# EVERY device_events row into an Occurrence (it matches on the whole
# table, not a kind whitelist), so these are skipped explicitly rather than
# silently doubling the engine's per-tick event volume with occurrences no
# rule will ever match. The set itself is nodesdb's, shared with the
# overview histogram, so a fifth timeline-only kind cannot be added to one
# reader's list and missed by the other's.
_TIMELINE_ONLY_EVENT_KINDS = TIMELINE_ONLY_EVENT_KINDS

# How far back operator_resolved_since looks for a hand resolve. Long enough
# that an alert resolved Friday evening still stays closed Monday morning;
# short enough that the query stays cheap and a resolve from months ago
# cannot suppress an unrelated new breach run indefinitely. A cleared
# observation ends suppression well before this ever matters in practice —
# this is a backstop, not the mechanism.
OPERATOR_RESOLVE_WINDOW_S = 7 * 86400.0

# How much of a source backlog one tick will work through. A collector that
# stored while the engine was stopped can leave hundreds of thousands of rows
# behind the cursor, and draining them all in one tick would starve every
# other source. Whatever is left is reported as counters["backlog"]; the
# cursor only advances over rows actually applied, so nothing is skipped.
DRAIN_ROW_BUDGET = 5000
DRAIN_TIME_BUDGET_S = 2.0

# The sane range for notify_rollup_delay_s: an hour is longer than anyone
# would hold an outage's first notice, and 0 disables the hold entirely.
NOTIFY_ROLLUP_DELAY_MAX_S = 3600.0

# More than this many alerts sendable in one roll-up flush go out as a
# single digest instead of one email each — see _sweep_notify_rollup and
# _send_digest. Three is small enough that an operator with one or two
# outages still gets the familiar per-alert subject line and template; the
# 250-device review's "5 real alerts" case is already over the threshold
# and digests, which is the right call too — the digest exists for the
# 377-alert case as much as the ordinary Tuesday with a small handful.
DIGEST_THRESHOLD = 3

# _rollup_parent's third answer, beside "this open alert already says it" and
# "nothing does". It means "an outage implies this, but there is no open row
# to hang a note on" — the parent was resolved by hand while the device is
# still down, or the outage is an upstream device's whose own alert an
# operator has already worked. Suppressing without a note is right there: an
# operator who resolved the outage has said they know about it, and handing
# them the six alerts it implies is the opposite of what they asked for.
SUPPRESSED = object()


class AlertEngine(Worker):
    STOPPED_TEXT = "Alert engine stopped"
    THREAD_NAME = "alert-engine"

    def __init__(self, db, *, nodes_db, snmp_db, syslog_db, ipam_db, app_db=None,
                 wireless_db=None, netpath_db=None, log=None):
        self.db = db
        self.nodes_db = nodes_db
        self.snmp_db = snmp_db
        self.syslog_db = syslog_db
        self.ipam_db = ipam_db
        self.app_db = app_db
        # Optional: an engine constructed without it simply never raises
        # wireless occurrences, so existing callers keep working unchanged.
        self.wireless_db = wireless_db
        # Same contract for NetPath's traceroute store.
        self.netpath_db = netpath_db
        self.log = log or NullLog()
        self._stop = threading.Event()
        # (rule_id, entity_id) -> (last sample ts, streak, first breach ts,
        # effective threshold, effective clear). entity_id is always a
        # STRING ("7" for a device, "7:12" for a port) so the key's type
        # never depends on which shape the rule produced; the trailing
        # threshold/clear pair lets a changed device override reset the
        # streak without widening the key itself. See _evaluate_thresholds
        # and _child_first_breach_ts.
        self._breach_streaks: dict[tuple, tuple[float | None, int, float | None,
                                                float | None, float | None]] = {}
        # DHCP scopes keep (last polled_ts, streak, first breach ts) rather
        # than a bare count: the engine ticks every few seconds but DHCP is
        # polled every few minutes, so for_polls must count polls, not
        # ticks — and the first breach ts is what tells one breach run from
        # the next, so a scope alert an operator resolved by hand stays
        # resolved while the scope stays full.
        self._dhcp_streaks: dict[tuple, tuple[float | None, int, float | None]] = {}
        # (read at, the roots asked for, the rows) for the fleet-wide read of
        # the limits transceivers publish about themselves. The poller
        # rewrites those once an hour per device, so re-reading them every
        # five-second tick would be a whole-table scan for an answer that
        # cannot have changed. See _published_thresholds.
        self._published_cache: tuple = (0.0, None, None)
        # And again for NetPath destinations, keyed on the trace's own
        # started_ts: a destination is traced every five minutes by default
        # while this engine ticks every five seconds, so a streak that
        # advanced per tick would satisfy "three traces" in fifteen seconds.
        self._netpath_streaks: dict[tuple, tuple[float | None, int, float | None]] = {}
        # dedup_key -> latest resolved_ts of a hand resolve, refreshed once
        # per tick from AlertsDatabase.operator_resolved_since (one indexed
        # query) rather than queried per breaching rule/device. See
        # _evaluate_thresholds and _evaluate_netpath_thresholds: a breach
        # whose first_breach_ts is at or before this timestamp is the same
        # run an operator already resolved, and does not re-open.
        self._operator_resolves: dict[str, float] = {}
        # Rollup PARENT dedup keys resolved by hand while the parent's
        # condition was still true, and when the cover started.
        # _operator_resolves only reaches back OPERATOR_RESOLVE_WINDOW_S, so
        # without this a device hand-resolved and left down opens every
        # still-breaching child in one tick seven days later. A cover ends
        # when the device answers, never on a clock.
        self._parent_covers: dict[str, float] = {}
        # rule key -> the enabled rule row, rebuilt once per tick from the
        # rules _tick already reads: _parent_operator_resolved needs one per
        # suppressed occurrence, and the table cannot change mid-tick.
        self._rules_by_key: dict = {}
        # dedup-key-shaped ("<entity_kind>:<entity_id>") -> whether that
        # entity's rollup parent condition still holds, memoised for the
        # duration of one tick so N children of one dead device cost one
        # device read rather than N.
        self._parent_conditions: dict = {}
        self._sent_this_hour: list[float] = []
        self._suppression_logged_hour: int | None = None
        # source -> the id this tick's drain reached. Written to `meta` by
        # _flush_cursors AFTER every occurrence has been applied, never
        # before: a cursor that commits at drain time is a promise the batch
        # was handled, and an exception in the apply loop used to break that
        # promise silently and permanently. See _advance_cursor.
        self._cursor_advances: dict[str, int] = {}
        # Per-tick drain budget bookkeeping, reset at the top of _tick.
        self._drain_rows = 0
        self._drain_deadline = 0.0
        # Whether a reader accepts a `limit` keyword, keyed by qualified
        # name. Every shipped source does; the fallback exists so an engine
        # built against an older database module still drains (unlimited
        # fetch, sliced here) rather than raising on every tick.
        self._limit_support: dict[str, bool] = {}
        # Delivery runs on its own thread: sending inline on the tick meant a
        # dead relay froze evaluation for as long as the outage lasted, which
        # is exactly when evaluation matters most. See alertmail.MailQueue.
        self._mail = alertmail.MailQueue(on_result=self._mail_result,
                                         on_breaker=self._mail_breaker)
        # Same reasoning, same shape, for the webhook channel — see
        # alertmail.WebhookQueue.
        self._webhook = alertmail.WebhookQueue(on_result=self._webhook_result)
        # Webhook's own hourly budget, kept apart from _sent_this_hour: a
        # webhook receiver is a machine, not an inbox, and the two channels
        # must not compete for the same quota. See webhook_max_per_hour.
        self._webhook_sent_this_hour: list[float] = []
        self._webhook_suppression_logged_hour: int | None = None
        # Occurrences raised by the application about itself (the mail path,
        # the poll pool) rather than read from a source. Appended from any
        # thread — the mail worker raises the SMTP one — and drained on the
        # tick thread like every other source. See system_occurrence.
        self._system_lock = threading.Lock()
        self._system_occurrences: list[Occurrence] = []
        self._system_clears: list[tuple[str, str]] = []
        self.counters = {"evaluated": 0, "opened": 0, "resolved": 0,
                         "emails_sent": 0, "suppressed": 0, "send_errors": 0,
                         "rolled_up": 0, "muted": 0, "apply_errors": 0,
                         "backlog": 0, "webhooks_sent": 0, "webhook_errors": 0,
                         "webhook_suppressed": 0}
        self._last_tick_ts: float = 0.0

    def start(self) -> None:
        self.stop()
        self._stop.clear()
        self._mail.start()
        self._webhook.start()
        self._spawn()

    def reconfigure(self, settings: dict) -> None:
        enabled = settings.get("enabled", True)
        if enabled and not self.running:
            self.start()
        elif not enabled and self.running:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        self._join()
        self._mail.stop()
        self._webhook.stop()

    def shutdown(self) -> None:
        self.stop()

    def _running_text(self) -> str:
        return f"Running · last tick {ago(self._last_tick_ts)}"

    def state(self) -> dict:
        return {"running": self.running, "last_tick": self._last_tick_ts}

    # ------------------------------------------------------------------ loop

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
                self._last_tick_ts = time.time()
            except Exception:
                traceback.print_exc()
                self.log.add(ERROR, "Alert engine tick failed", detail=traceback.format_exc())
            self._stop.wait(TICK_S)

    def _tick(self) -> None:
        settings = self.db.settings()
        if not settings.get("enabled", True):
            return
        # One indexed query per tick, not one per breaching rule/device:
        # _evaluate_thresholds, _evaluate_dhcp_thresholds,
        # _evaluate_netpath_thresholds and _parent_operator_resolved all
        # consult this cache to decide whether a breach is the same run an
        # operator already resolved by hand. Read here, at the top of the
        # tick and before anything is applied, so a resolve that landed a
        # moment ago is already in hand on the FIRST tick after the click —
        # which is the tick a bulk resolve has to survive.
        self._operator_resolves = self.db.operator_resolved_since(
            time.time() - OPERATOR_RESOLVE_WINDOW_S)
        self._cursor_advances.clear()
        self._drain_rows = 0
        self._drain_deadline = time.monotonic() + DRAIN_TIME_BUDGET_S
        self.counters["backlog"] = 0
        self._parent_conditions = {}
        self._upstream_outage_cache = {}
        occurrences = []
        occurrences += self._drain_device_events(settings)
        occurrences += self._drain_interface_events(settings)
        occurrences += self._drain_traps(settings)
        occurrences += self._drain_syslog(settings)
        occurrences += self._drain_ipam_conflicts(settings)
        occurrences += self._drain_ap_events(settings)
        occurrences += self._drain_system_occurrences()
        occurrences += self._evaluate_thresholds(settings)
        occurrences += self._evaluate_dhcp_thresholds(settings)
        occurrences += self._evaluate_netpath_thresholds(settings)
        rules = [r for r in self.db.rules() if r["enabled"]]
        self._rules_by_key = {r["key"]: r for r in rules if r["key"]}
        occurrences += self._drain_pending()
        # Read once per tick rather than per occurrence, and usually empty —
        # when nothing is muted the gate below costs one dict truth test.
        # window_covered is folded in here rather than left for _muted to ask
        # about separately: a maintenance window behaves EXACTLY like a
        # device mute for occurrence gating (see the maintenance_windows
        # schema comment in alertsdb.py), so one dict serves both. Resolved
        # against nodesdb.devices() only when a window is actually active —
        # active_windows() is one cheap query, so a fleet with no window
        # running today (almost always) never pays for the device read at
        # all.
        window_covered = None
        active_windows = self.db.active_windows()
        if active_windows:
            window_covered = self.db.window_covered_device_ids(
                ((row["id"], row["device_group_id"]) for row in self.nodes_db.devices()),
                windows=active_windows)
        muted = self.db.muted_entity_ids("device", window_covered=window_covered)
        for occurrence in occurrences:
            self.counters["evaluated"] += 1
            # Per occurrence, not per tick. The apply path is not
            # exception-free — template lookup, context building, rendering
            # and the rollup queries all run against SQLite, and an
            # OperationalError (locked, disk full) can surface from any of
            # them. One raised here used to abort the whole batch, and
            # because the cursors had already committed, the rest of that
            # batch was gone for good. A poisoned occurrence is now counted,
            # logged with its traceback, and skipped; its source's cursor
            # still advances past it, so the engine makes progress rather
            # than re-reading the same bad row every five seconds forever.
            try:
                if self._hold_for_new_device(occurrence, settings):
                    continue
                if muted and self._muted(occurrence, muted):
                    continue
                self._apply(rules, occurrence, settings)
            except Exception:
                self.counters["apply_errors"] += 1
                self.log.add(ERROR,
                             f"Alert occurrence for {occurrence.entity_label} "
                             f"could not be applied",
                             detail=traceback.format_exc())
        # Only now, once every occurrence above has been applied (or
        # deliberately skipped), does any source's cursor move.
        self._flush_cursors()
        self._sweep_expired(settings)
        self._sweep_renotify(settings)
        self._sweep_notify_rollup(settings)

    # -------------------------------------------------- system occurrences

    def system_occurrence(self, rule_key: str, entity_id: str, label: str,
                          severity: int | None = None, extra: dict | None = None,
                          message: str = "") -> None:
        """Raise an occurrence about the application itself.

        Callable from any thread — the mail worker raises the SMTP one and
        the poller raises pool saturation — because the condition is noticed
        wherever it happens, not on the tick. The occurrence is queued and
        applied by the next _tick like any other, so rules, dedup, mute and
        rollup all behave exactly as they do for a device event.

        `rule_key` doubles as the occurrence's source_kind, which is what
        makes one system rule match one system condition rather than every
        system rule opening on every one.
        """
        occurrence = Occurrence(
            kind="system", source_kind=rule_key, entity_kind="system",
            entity_id=str(entity_id), entity_label=label, ts=time.time(),
            message=message or label, severity=severity,
            extra=dict(extra or {}))
        with self._system_lock:
            self._system_occurrences.append(occurrence)

    def clear_system_occurrence(self, rule_key: str, entity_id: str) -> None:
        """The other half: the condition has ended, so resolve its alert on
        the next tick. Resolved with resolved_by '' like every other engine
        auto-resolve, so it is never mistaken for a hand resolve."""
        with self._system_lock:
            self._system_clears.append((rule_key, str(entity_id)))

    def _drain_system_occurrences(self) -> list[Occurrence]:
        with self._system_lock:
            pending = self._system_occurrences
            clears = self._system_clears
            self._system_occurrences = []
            self._system_clears = []
        for rule_key, entity_id in clears:
            rule = self.db.rule_by_key(rule_key)
            if rule is None:
                continue
            if self.db.resolve_by_dedup(f"{rule['key']}:system:{entity_id}", by=""):
                self.counters["resolved"] += 1
        return pending

    def _mail_result(self, job, ok: bool, error: str) -> None:
        """One delivery finished, on the mail worker's thread. AlertsDatabase
        has its own RLock, so the notification row is safe to write here.

        job.alert_ids, when set, is a roll-up digest naming every alert it
        covers (see _send_digest) — one delivery, but every alert it spoke
        for gets its own notification row, so each alert's own history still
        shows whether and when it was told about. job.alert_id alone (the
        ordinary case) keeps the single row every other caller has always
        written.
        """
        if ok:
            self.counters["emails_sent"] += 1
        else:
            self.counters["send_errors"] += 1
        alert_ids = getattr(job, "alert_ids", None) or [job.alert_id]
        for alert_id in alert_ids:
            self.db.record_notification(alert_id, job.kind,
                                        ", ".join(job.to_addrs), job.subject,
                                        ok, error)

    def _mail_breaker(self, is_open: bool, error: str) -> None:
        """The mail path itself became (un)usable. Raised as an ordinary
        alert so the failure that silences every other alert is the one
        thing that cannot be silenced by it — no email is sent for a
        kind='system' rule, see _notify."""
        if is_open:
            self.system_occurrence(
                "smtp_failing", "smtp", "Alert email", severity=2,
                extra={"error": error},
                message=f"Alert email is failing and delivery is paused: {error}")
        else:
            self.clear_system_occurrence("smtp_failing", "smtp")

    def _webhook_result(self, job, ok: bool, error: str) -> None:
        """The webhook counterpart of _mail_result — same shape, a separate
        counter pair (webhooks_sent/webhook_errors) so an operator watching
        the two channels can tell them apart, and to_addr holds the URL
        rather than a recipient list, which is what an operator reading the
        alert's notification history wants to see for a webhook row."""
        if ok:
            self.counters["webhooks_sent"] += 1
        else:
            self.counters["webhook_errors"] += 1
        alert_ids = getattr(job, "alert_ids", None) or [job.alert_id]
        for alert_id in alert_ids:
            self.db.record_notification(alert_id, job.kind, job.url,
                                        job.subject, ok, error)

    # ------------------------------------------------------- drain plumbing

    def _advance_cursor(self, source: str, value: int) -> None:
        """Remember how far `source` was drained, without writing it yet.

        Deferred rather than committed inside the drain because a cursor is
        the engine's statement that everything up to that id has been turned
        into alerts. Writing it before the apply loop made that statement
        early, and an exception mid-loop then discarded the rest of the
        batch permanently — the drain would never hand those rows back.
        _flush_cursors writes these at the end of the tick instead.
        """
        if value > self._cursor_advances.get(source, 0):
            self._cursor_advances[source] = value

    def _flush_cursors(self) -> None:
        for source, value in self._cursor_advances.items():
            if value > self.db.cursor(source):
                self.db.set_cursor(source, value)
        self._cursor_advances.clear()

    def _accepts_limit(self, fetch) -> bool:
        """Whether a `*_since` reader takes a `limit` keyword.

        Every shipped one does. Asked rather than assumed so that an engine
        running against a database module that predates the keyword falls
        back to an unlimited fetch and a Python slice instead of raising on
        every tick — the drain budget is a nicety, draining at all is not.
        """
        name = getattr(fetch, "__qualname__", repr(fetch))
        known = self._limit_support.get(name)
        if known is None:
            try:
                known = "limit" in inspect.signature(fetch).parameters
            except (TypeError, ValueError):
                known = False
            self._limit_support[name] = known
        return known

    def _read_forward(self, source: str, fetch, cursor: int, max_id_fn=None):
        """Yield rows newer than `cursor`, oldest first, in id order.

        Pages rather than issuing one fixed-size read: a source that fell
        behind (the engine was stopped, or a syslog burst outran the tick)
        used to catch up at one batch per tick, which at 500 rows a batch and
        12 ticks a minute is slower than the burst that caused it. This keeps
        asking for the next batch until the source is caught up or the
        per-tick budget is spent, and reports whatever is left as `backlog`
        so being behind is visible instead of merely quiet.
        """
        paged = self._accepts_limit(fetch)
        batch = 2000 if paged else DRAIN_ROW_BUDGET
        at = cursor
        caught_up = False
        while True:
            if paged:
                rows = fetch(at, limit=batch)
            else:
                rows = list(fetch(at))[:batch]
            if not rows:
                caught_up = True
                break
            for row in rows:
                yield row
                if row["id"] > at:
                    at = row["id"]
            self._drain_rows += len(rows)
            if len(rows) < batch:
                caught_up = True
                break
            if (self._drain_rows >= DRAIN_ROW_BUDGET
                    or time.monotonic() >= self._drain_deadline):
                break
        if not caught_up and max_id_fn is not None:
            try:
                self.counters["backlog"] += max(0, int(max_id_fn()) - int(at))
            except Exception:
                pass

    def _device_for_source(self, cache: dict, source: str):
        """The managed device that sent this trap or syslog message, or None.

        A per-drain dict rather than a query per row: a burst of traps is
        overwhelmingly from a handful of sources, and a mass syslog event is
        the same host many times. None is a real answer, cached as such —
        "this address is not a device we poll" is exactly what
        trap_link_down_unmanaged needs, and re-asking for it every row would
        be the most expensive lookup of the drain.
        """
        if not source:
            return None
        if source in cache:
            return cache[source]
        lookup = getattr(self.nodes_db, "device_by_ip", None)
        device = lookup(source) if lookup is not None else None
        cache[source] = device
        return device

    def _source_name(self, device, source: str) -> str:
        """A display name for a trap/syslog sender, given a cached device row.

        nodes_db is withheld from resolve_name when the cache already
        answered "not a device we poll", because resolve_name's own
        device_by_ip fallback would repeat exactly the lookup that produced
        that answer, once per row. The DNS-cache half still runs.
        """
        return namelookup.resolve_name(
            self.nodes_db if device is not None else None, self.app_db,
            source, device=device) or source

    def _muted(self, occurrence: Occurrence, muted: dict) -> bool:
        """True when this occurrence is about a device an operator silenced.

        Per device rather than per rule, so it sits here beside
        _hold_for_new_device rather than inside _apply: muting a switch means
        "stop telling me about that switch", not "stop telling me about one
        rule on it". _occurrence_device resolves interface occurrences to
        their parent device too, so a muted switch's ports go quiet with it,
        and returns None for everything structurally outside Nodes — traps
        from unpolled hosts, syslog, IPAM, DHCP scopes, APs — which therefore
        cannot be muted by a device mute.
        """
        device = self._occurrence_device(occurrence)
        if device is None:
            return False
        if str(device["id"]) not in muted:
            return False
        self.counters["muted"] += 1
        return True

    def _muted_alert(self, alert_row) -> bool:
        """Whether an existing alert's device is muted OR covered by an
        active maintenance window.

        Its own lookup rather than the per-tick dict, because the clear path
        runs inside the drains — before _tick reads that dict — and a clear
        is rare enough that one query costs nothing.
        """
        device_id = device_id_for(alert_row["entity_kind"], alert_row["entity_id"])
        if device_id is None:
            return False
        if self.db.mute_row("device", str(device_id)) is not None:
            return True
        device = self.nodes_db.device(device_id)
        device_group_id = device["device_group_id"] if device is not None else None
        return self.db.window_covers_device(device_id, device_group_id) is not None

    # ------------------------------------------- newly added device hold

    # Source kinds whose condition is a STATE that can still be true five
    # minutes later, paired with how to ask the current data whether it is.
    # Everything else that is device-scoped is a momentary event — "rebooted",
    # "recovered", "poll took too long" — which cannot be re-checked, because
    # by definition it already happened; those are dropped rather than
    # replayed, which is what "don't alert on a device I just added" means for
    # them.
    #
    # Threshold occurrences are absent on purpose: _evaluate_thresholds re-derives
    # them from current values on every tick, so one suppressed inside the
    # window simply comes back on the next tick after it. Parking those too
    # would fire the same alert twice.
    _STATEFUL_SOURCES = ("down", "mib_missing", "link_down")

    def _occurrence_device(self, occurrence: Occurrence):
        """The device an occurrence is about, or None when it is not about one.

        Traps from unpolled devices, syslog from an unknown host, IPAM
        conflicts, DHCP scopes and wireless AP events are all structurally
        outside this — they never resolve to a row in Nodes' device table, so
        they can never be held back. That is a property of the lookup rather
        than a list of exemptions somebody has to remember to update.
        """
        device_id = device_id_for(occurrence.entity_kind, occurrence.entity_id)
        if device_id is None:
            return None
        return self.nodes_db.device(device_id)

    def _hold_for_new_device(self, occurrence: Occurrence, settings) -> bool:
        """True when this occurrence was held back rather than applied.

        A device added moments ago is usually still being set up — wrong
        community, not cabled, still booting — and the alerts that produces
        are noise about the setup, not about the network. Held for
        new_device_grace_s and then re-checked, so a device that really is
        down is reported late rather than never.
        """
        grace = float(settings.get("new_device_grace_s", 300) or 0)
        if grace <= 0 or getattr(occurrence, "replayed", False):
            return False
        device = self._occurrence_device(occurrence)
        if device is None:
            return False
        created = device["created_ts"] or 0
        if not created or time.time() - created >= grace:
            return False
        if occurrence.source_kind in self._STATEFUL_SOURCES:
            self.db.park_occurrence(
                device["id"], created + grace, json.dumps(asdict(occurrence)))
        self.counters["held"] = self.counters.get("held", 0) + 1
        return True

    def _drain_pending(self) -> list[Occurrence]:
        """Occurrences whose hold has expired and whose condition is still
        true. One that has cleared in the meantime is dropped: the whole
        point of holding is that a device settling in should not alert."""
        out = []
        for row in self.db.due_occurrences(time.time()):
            self.db.drop_occurrence(row["id"])
            try:
                occurrence = Occurrence(**json.loads(row["payload"]))
            except (TypeError, ValueError):
                continue
            if not self._still_true(occurrence):
                self.log.add(ALERTS,
                            f"Held alert for {occurrence.entity_label} dropped: "
                            f"the condition cleared during the new-device "
                            f"grace period")
                continue
            # Marked so the hold does not catch it a second time — the device
            # is still younger than the grace period at this exact moment.
            occurrence.replayed = True
            out.append(occurrence)
        return out

    def _still_true(self, occurrence: Occurrence) -> bool:
        """Whether a held condition still holds, asked of current state
        rather than of the event that first reported it."""
        device = self._occurrence_device(occurrence)
        if device is None:
            return False
        if occurrence.source_kind == "down":
            return device["status"] == "down"
        if occurrence.source_kind == "mib_missing":
            return device["mib_covered"] == 0
        if occurrence.source_kind == "link_down":
            try:
                if_index = int(str(occurrence.entity_id).split(":")[1])
            except (IndexError, ValueError):
                return False
            interface_id = self.nodes_db.interface_id_for(device["id"], if_index)
            if interface_id is None:
                return False
            interface = self.nodes_db.interface_by_id(interface_id)
            return interface is not None and interface["oper_status"] == "down"
        return False

    # --------------------------------------------------------------- drains

    def _recovery_text(self, device, row, resolved) -> tuple[str, str, dict]:
        """(message, detail, template extras) for a device that answered again.

        Says when it came back and how long it was gone, because "responding
        again" on its own leaves both questions to be reconstructed from two
        other timestamps in two other places.

        When the device went down is taken from the outage alert this recovery
        just resolved — its opened_ts IS the down transition — and, when there
        is no such alert (the rule disabled, the device muted, the alert held
        for a newly added device or resolved by hand), from the device's own
        event log instead. When neither knows, the downtime clause is left out
        rather than guessed at: an outage of unknown length is not a
        zero-length one.

        The event-log fallback needs one more bound than "the newest down
        before this up", because an `up` event is NOT written only after a
        `down`: nodepoll records one on any non-up to up transition, an
        `unsupported` status and a credential failure included. So a device
        that went down last Tuesday, recovered, and today came back from a
        broken community string would pair today's recovery with Tuesday's
        outage and report a multi-day downtime that never happened. A `down`
        only counts when no `up` sits between it and this one — i.e. when it
        is the transition THIS recovery ends.

        Recovery time is the event's own timestamp, which is the poll that saw
        the device answer — not the moment this tick got round to it, which is
        up to one tick later and unboundedly later after a restart.
        """
        recovered_ts = row["ts"]
        down_since = resolved["opened_ts"] if resolved else None
        if down_since is None:
            previous = self.nodes_db.last_device_event_before(
                device["id"], "down", recovered_ts)
            down_since = previous["ts"] if previous else None
            if down_since is not None:
                recovered_before = self.nodes_db.last_device_event_before(
                    device["id"], "up", recovered_ts)
                if recovered_before and recovered_before["ts"] >= down_since:
                    down_since = None
        downtime = alertmail.duration_text(
            recovered_ts - down_since) if down_since else ""
        lead = row["detail"] or "responding again"
        clock = alertmail.clock_text(recovered_ts)
        message = f"{lead} at {clock}"
        if downtime:
            message = f"{message} after {downtime} down"
        detail = (f"Down since {alertmail.clock_text(down_since)}."
                  if down_since else "")
        extra = {"recovered_time": clock,
                 "down_since": alertmail.clock_text(down_since) if down_since else "",
                 "downtime": downtime}
        return message, detail, extra

    def _drain_device_events(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("device_events"):
            self.db.set_cursor("device_events", self.nodes_db.max_device_event_id())
            return []
        cursor = self.db.cursor("device_events")
        occurrences = []
        max_id = cursor
        for row in self._read_forward("device_events",
                                      self.nodes_db.device_events_since, cursor,
                                      self.nodes_db.max_device_event_id):
            max_id = max(max_id, row["id"])
            if row["kind"] in _TIMELINE_ONLY_EVENT_KINDS:
                continue
            device = self.nodes_db.device(row["device_id"])
            if device is None:
                continue
            label = namelookup.resolve_name(
                self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
            # The paired alert is resolved BEFORE the occurrence is built, not
            # after: resolving is what hands back the outage's own opened_ts,
            # and a recovery notice that cannot say how long the outage lasted
            # is missing the one fact somebody reads it for.
            resolved, cleared_rule = None, None
            clears_key = ("device_event", row["kind"])
            if clears_key in CLEARS:
                cleared_rule = self.db.rule_by_key(CLEARS[clears_key])
                if cleared_rule:
                    paired_dedup = f"{cleared_rule['key']}:device:{device['id']}"
                    resolved = self.db.resolve_by_dedup(paired_dedup, by="")
            message = row["detail"] or f"{label}: {row['kind']}"
            detail, extra = "", {}
            if row["kind"] == "up":
                message, detail, extra = self._recovery_text(device, row, resolved)
            occurrence = Occurrence(
                kind="device_event", source_kind=row["kind"], entity_kind="device",
                entity_id=str(device["id"]), entity_label=label, ts=row["ts"],
                message=message, detail=detail,
                device_name=device["name"] or "", device_ip=device["ip"],
                extra=extra)
            occurrences.append(occurrence)
            if row["kind"] == "up":
                occurrences.extend(self._replay_downstream_outages(device))
            if resolved:
                self.counters["resolved"] += 1
                self._notify_clear(resolved, cleared_rule, settings, extra=extra)
        if max_id > cursor:
            self._advance_cursor("device_events", max_id)
        return occurrences

    def _replay_downstream_outages(self, device) -> list[Occurrence]:
        """`down` occurrences for devices behind an upstream that just
        recovered and are still down themselves.

        The other end of the topology rollup, and the reason it is safe. A
        device whose outage was suppressed (or absorbed) under its upstream
        has no open alert and will never produce a second `down` event, so
        without this it would go quiet the moment the upstream recovered —
        the network's remaining fault would be the one thing nobody was told
        about. Asked of the device's CURRENT status rather than of what was
        suppressed earlier, so a site that came back cleanly replays nothing.

        Marked replayed so the new-device hold does not park them again.
        """
        ids_of = getattr(self.nodes_db, "downstream_ids", None)
        if ids_of is None:
            return []
        child_ids = ids_of(device["id"])
        if not child_ids:
            return []
        out = []
        for child in self.nodes_db.devices_by_ids(child_ids):
            if not child["enabled"] or child["status"] != "down":
                continue
            label = namelookup.resolve_name(
                self.nodes_db, self.app_db, child["ip"], device=child) or child["ip"]
            occurrence = Occurrence(
                kind="device_event", source_kind="down", entity_kind="device",
                entity_id=str(child["id"]), entity_label=label, ts=time.time(),
                message=f"{label}: still not responding now that the upstream "
                        f"outage has cleared",
                device_name=child["name"] or "", device_ip=child["ip"])
            occurrence.replayed = True
            out.append(occurrence)
        return out

    def _drain_interface_events(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("interface_events"):
            self.db.set_cursor("interface_events", self.nodes_db.max_interface_event_id())
            return []
        cursor = self.db.cursor("interface_events")
        occurrences = []
        max_id = cursor
        touched_interfaces: set[int] = set()
        for row in self._read_forward("interface_events",
                                      self.nodes_db.interface_events_since, cursor,
                                      self.nodes_db.max_interface_event_id):
            max_id = max(max_id, row["id"])
            touched_interfaces.add(row["interface_id"])
            interface = self.nodes_db.interface_by_id(row["interface_id"])
            if interface is None:
                continue
            device = self.nodes_db.device(interface["device_id"])
            if device is None:
                continue
            device_label = namelookup.resolve_name(
                self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
            label = f"{device_label} / {interface_label(interface)}"
            occurrences.append(Occurrence(
                kind="interface_event", source_kind=row["kind"], entity_kind="interface",
                entity_id=f"{device['id']}:{interface['if_index']}", entity_label=label,
                ts=row["ts"], message=row["detail"] or f"{label}: {row['kind']}",
                device_name=device["name"] or "", device_ip=device["ip"]))
            if row["kind"] == "link_up":
                cleared_rule = self.db.rule_by_key(CLEARS.get(("interface_event", "link_up"), ""))
                if cleared_rule:
                    paired_dedup = f"{cleared_rule['key']}:interface:{device['id']}:{interface['if_index']}"
                    resolved = self.db.resolve_by_dedup(paired_dedup, by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, cleared_rule, settings)
        # The flapping rule's own thresholds, looked up once rather than per
        # interface. NULL columns mean "as shipped", so an install that has
        # never touched them behaves exactly as it did before they existed.
        flap_rule = self.db.rule_by_key("interface_flapping")
        flap_window = float((flap_rule and flap_rule["flap_window_s"]) or 600)
        # Floored at 2: one transition is not a flap, and a 0 or negative
        # written straight to the API (the editor's field will not produce
        # one) would otherwise open an alert on every single link event.
        flap_min = max(2, int((flap_rule and flap_rule["flap_min_transitions"])
                              or 3))
        for interface_id in touched_interfaces:
            # since_s must follow the configured window: the default lookback
            # is 15 minutes, so a longer window would silently see nothing to
            # count. The row limit is generous for the same reason.
            recent = [dict(r) for r in self.nodes_db.recent_interface_events_for(
                interface_id, since_s=max(flap_window, 900.0),
                limit=max(flap_min * 10, 50))]
            if not evaluate_flapping(recent, window_s=flap_window,
                                     min_transitions=flap_min):
                continue
            interface = self.nodes_db.interface_by_id(interface_id)
            if interface is None:
                continue
            device = self.nodes_db.device(interface["device_id"])
            if device is None:
                continue
            device_label = namelookup.resolve_name(
                self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
            label = f"{device_label} / {interface_label(interface)}"
            occurrences.append(Occurrence(
                kind="interface_event", source_kind="flapping", entity_kind="interface",
                entity_id=f"{device['id']}:{interface['if_index']}", entity_label=label,
                ts=time.time(), message=f"{label} is flapping",
                device_name=device["name"] or "", device_ip=device["ip"]))
        if max_id > cursor:
            self._advance_cursor("interface_events", max_id)
        return occurrences

    def _drain_traps(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("traps"):
            self.db.set_cursor("traps", self.snmp_db.max_id())
            return []
        cursor = self.db.cursor("traps")
        occurrences = []
        max_id = cursor
        devices: dict = {}
        for row in self._read_forward("traps", self.snmp_db.traps_since,
                                      cursor, self.snmp_db.max_id):
            max_id = max(max_id, row["id"])
            # A trap alert used to name only the trap ("linkDown"), because
            # nothing on the occurrence said which box sent it: device_name
            # was empty, so a rule's device_filter could not match a trap at
            # all, and the label an operator read named a fault with no
            # subject. The sending address is in hand on every row; the
            # managed device behind it usually is too.
            device = self._device_for_source(devices, row["source"])
            source_label = self._source_name(device, row["source"])
            trap_label = row["trap_name"] or row["trap_oid"] or "trap"
            occurrences.append(Occurrence(
                kind="trap", source_kind=row["trap_kind"] or "", entity_kind="trap",
                # Source AND oid. Keyed on the OID alone, 200 linkDown traps
                # from 200 switches collapsed into one alert row naming no
                # device, and open_or_increment overwrote its message with
                # each one, so 250 faults on 250 devices read as three rows.
                entity_id=f'{row["source"]}:{row["trap_oid"] or ""}',
                entity_label=f"{source_label}: {trap_label}",
                ts=row["ts"], message=row["varbind_text"] or "",
                device_name=(device["name"] if device else "") or "",
                device_ip=row["source"],
                # traps.severity has been stored since the receiver shipped
                # and the occurrence simply never carried it, so every trap
                # of any severity satisfied a rule's severity floor.
                severity=row["severity"],
                managed=device is not None,
                extra={"trap_name": row["trap_name"] or "", "trap_oid": row["trap_oid"] or "",
                      "varbinds": row["varbind_text"] or ""}))
        if max_id > cursor:
            self._advance_cursor("traps", max_id)
        return occurrences

    def _drain_syslog(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("syslog"):
            self.db.set_cursor("syslog", self.syslog_db.max_id())
            return []
        cursor = self.db.cursor("syslog")
        min_severity = int(settings.get("min_severity", 7))
        occurrences = []
        max_id = cursor
        devices: dict = {}
        for row in self._read_forward("syslog", self.syslog_db.rows_since,
                                      cursor, self.syslog_db.max_id):
            max_id = max(max_id, row["id"])
            if row["severity"] > min_severity:
                continue
            device = self._device_for_source(devices, row["source"])
            # Same "don't override a real self-reported host" rule as the
            # Syslog page's own Host column, so an alert opened from a
            # message shows the same name the Syslog page shows for it.
            if row["host"] and row["host"] != row["source"]:
                label = row["host"]
            else:
                label = self._source_name(device, row["source"])
            occurrences.append(Occurrence(
                kind="syslog", source_kind="", entity_kind="syslog",
                # Source AND message signature: keyed on the host alone, a
                # %SYS-2-MALLOCFAIL and an %OSPF-4-ERRRCV on the same switch
                # were one row whose message was whichever arrived last.
                entity_id=f'{row["source"]}:{syslog_signature(row["message"] or "")}',
                entity_label=label,
                ts=row["ts"], message=row["message"] or "",
                # The device's own name where the sender is one we poll, so a
                # rule's device_filter matches syslog the same way it matches
                # a poll event; the self-reported host otherwise, which is
                # the only name an unmanaged sender has.
                device_name=(device["name"] if device else "") or row["host"] or "",
                device_ip=row["source"],
                severity=row["severity"],
                managed=device is not None))
        if max_id > cursor:
            self._advance_cursor("syslog", max_id)
        return occurrences

    def _drain_ipam_conflicts(self, settings) -> list[Occurrence]:
        all_conflicts = self.ipam_db.conflicts(include_resolved=True)
        if not self.db.has_cursor("ipam_conflicts"):
            seed = max((row["id"] for row in all_conflicts), default=0)
            self.db.set_cursor("ipam_conflicts", seed)
            return []
        cursor = self.db.cursor("ipam_conflicts")
        rows = [row for row in all_conflicts if row["id"] > cursor]
        occurrences = []
        max_id = cursor
        for row in rows:
            max_id = max(max_id, row["id"])
            label = namelookup.resolve_name(
                self.nodes_db, self.app_db, row["ip"]) or row["ip"]
            occurrences.append(Occurrence(
                kind="ipam", source_kind="", entity_kind="ipam",
                entity_id=str(row["id"]), entity_label=label,
                ts=row["detected_ts"],
                message=f"{row['ip']}: conflicting MAC addresses "
                        f"{row['mac_a']} and {row['mac_b']}",
                device_ip=row["ip"]))
        if max_id > cursor:
            self._advance_cursor("ipam_conflicts", max_id)
        self._pair_ipam_resolutions(all_conflicts, settings)
        return occurrences

    def _pair_ipam_resolutions(self, all_conflicts, settings) -> None:
        """Resolve the alert for an IPAM conflict a person has marked
        resolved in the IPAM module.

        The alert and the conflict row were tracked entirely separately, so
        clearing the conflict left its alert open forever — the same pairing
        mib_present already has with mib_missing, which this restores for the
        one module that had the two halves and never joined them.

        One query for the module's open alerts and a set intersection, rather
        than a resolve_by_dedup per resolved conflict: the conflicts list
        includes every conflict ever recorded, and almost all of them are
        both resolved and long since alerted about.
        """
        rule = self.db.rule_by_key("ipam_new_conflict")
        if rule is None:
            return
        resolved_ids = {str(row["id"]) for row in all_conflicts
                        if row["resolved_ts"]}
        if not resolved_ids:
            return
        for alert_row in self.db.alerts(state="unresolved", rule_id=rule["id"],
                                        limit=2000):
            if alert_row["entity_kind"] != "ipam":
                continue
            if alert_row["entity_id"] not in resolved_ids:
                continue
            resolved = self.db.resolve_by_dedup(alert_row["dedup_key"], by="")
            if resolved:
                self.counters["resolved"] += 1
                self._notify_clear(resolved, rule, settings)

    def _drain_ap_events(self, settings) -> list[Occurrence]:
        """Wireless AP lifecycle events — today just ap_removed, raised by
        wirelessdb.prune_stale when a controller stops reporting an AP.
        Same cursor shape as every other drain above. An AP a human marked
        out of service never produces one of these in the first place, so
        no filtering is needed here."""
        if self.wireless_db is None:
            return []
        if not self.db.has_cursor("ap_events"):
            self.db.set_cursor("ap_events", self.wireless_db.max_ap_event_id())
            return []
        cursor = self.db.cursor("ap_events")
        rows = list(self._read_forward("ap_events",
                                       self.wireless_db.ap_events_since, cursor,
                                       self.wireless_db.max_ap_event_id))
        occurrences = []
        max_id = cursor
        # One controllers query per drain, not one per event row: a burst
        # (a mass decommission) can hand back up to 2000 rows that mostly
        # share the same handful of controllers.
        controllers = {c["id"]: c for c in self.wireless_db.controllers()} if rows else {}
        for row in rows:
            max_id = max(max_id, row["id"])
            controller = controllers.get(row["controller_id"])
            label = row["name"] or row["wtp_id"]
            occurrences.append(Occurrence(
                kind="wireless_event", source_kind=row["kind"], entity_kind="ap",
                entity_id=f"{row['controller_id']}:{row['vdom']}:{row['wtp_id']}",
                entity_label=label, ts=row["ts"],
                message=row["detail"] or f"{label}: {row['kind']}",
                device_name=controller["name"] if controller else "",
                device_ip=controller["ip"] if controller else ""))
            # ap_returned resolves a standing removed-alert for the same
            # AP, the way device up resolves device_down.
            clears_key = ("wireless_event", row["kind"])
            if clears_key in CLEARS:
                cleared_rule = self.db.rule_by_key(CLEARS[clears_key])
                if cleared_rule:
                    paired_dedup = (f"{cleared_rule['key']}:ap:"
                                    f"{row['controller_id']}:{row['vdom']}:{row['wtp_id']}")
                    resolved = self.db.resolve_by_dedup(paired_dedup, by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, cleared_rule, settings)
        if max_id > cursor:
            self._advance_cursor("ap_events", max_id)
        return occurrences

    def _evaluate_thresholds(self, settings) -> list[Occurrence]:
        """Device metrics against their threshold rules, per port where the
        device reports per port.

        A rule names a metric FAMILY, not one key: `if_in_util_pct` is both
        a device-wide value and one `if_in_util_pct.<if>` per interface,
        while `sfp_rx_dbm` is only ever per interface. Where a device
        reports children, the parent key is skipped and each port is
        evaluated as its own `interface` entity ("<device_id>:<if_index>"),
        so two bad ports are two alerts that clear independently.

        The streak advances on a NEW SAMPLE, not an engine tick (ticks run
        every five seconds against a sixty-second default poll), and is
        kept per TARGET so one hot port cannot count toward another's
        for_polls. first_breach_ts rides along so for_seconds measures in
        sample time.

        Also settles whether an operator resolved THIS breach run: a hand
        resolve at or after first_breach_ts keeps it closed rather than
        reopening as a new row; a clear observation resets first_breach_ts
        so the next breach starts a new run. Keyed on the alert's OWN dedup
        key -- resolving a rollup PARENT never touches a child's key, which
        is why children stay free to re-open (see _parent_operator_resolved).

        In-memory state, so a restart rebuilds every streak from scratch.
        Deliberately not persisted -- see INTERNALS.md.
        """
        occurrences = []
        rules = [r for r in self.db.rules() if r["enabled"] and r["kind"] == "threshold"]
        if not rules:
            return occurrences
        # Per-device overrides, read once per RULE per tick rather than once
        # per DEVICE, for the same reason metrics_for_families is batched
        # below. Keyed by device even for an interface target: an override
        # tuned for a hot closet is about the switch, not one port.
        overrides_by_rule = {r["id"]: self.db.device_threshold_map(r["key"])
                             for r in rules}
        # One query for the families the enabled rules actually name, not a
        # full `SELECT *` per device -- at 2,000 devices with ~90 metrics
        # each that was 400,000 rows every five seconds for four live rules.
        wanted = sorted({r["source_kind"] for r in rules if r["source_kind"]})
        metric_rows = self.nodes_db.metrics_for_families(wanted)
        roots = set(wanted)
        metrics_by_device_key = {}
        # (device_id, root) -> [(if_index, metric row)]
        children: dict[tuple, list] = {}
        for metric in metric_rows:
            key = metric["key"]
            if key in roots:
                metrics_by_device_key[(metric["device_id"], key)] = metric
                continue
            root, _, suffix = key.partition(".")
            # A child's whole tail after the first dot must be an interface
            # index -- excludes a sibling key like if_in_error_rate_x.
            if root in roots and suffix.isdigit():
                children.setdefault((metric["device_id"], root), []).append(
                    (int(suffix), metric))
        device_ids = sorted({m["device_id"] for m in metric_rows})
        devices = {d["id"]: d for d in self.nodes_db.devices_by_ids(device_ids)}
        # A sample this old is treated as absent, so a streak already
        # satisfied doesn't keep re-raising forever from a stale last_value.
        # Resets the streak but does NOT resolve the alert -- a device gone
        # quiet is device_down's or the rollup's fault to report, not a
        # recovery.
        stale_after = float(settings.get("threshold_stale_s", 900) or 0)
        now = time.time()
        # One indexed fleet-wide read for the whole pass, cached across
        # ticks: the rules in PUBLISHED_THRESHOLD_RULES are judged against
        # the port's own transceiver and nothing else.
        published = self._published_thresholds(rules, now)
        # dict(rule) is not free, and a per-port rule needs a copy for every
        # port whose published limit differs. Without these two caches a
        # 2,000-device fleet at 48 optics a switch built three quarters of a
        # million throwaway dicts per tick. Keyed on the effective pair,
        # since that is the only thing the copy changes.
        rule_dicts: dict[int, dict] = {}
        eval_cache: dict[tuple, dict] = {}
        # Per (rule, entity) state lived forever otherwise, leaking an entry
        # per deleted device; only targets this tick actually saw carry over.
        live_streaks: dict[tuple, tuple] = {}
        # Loaded on first use and only when a breach has no new sample behind
        # it, so a tick with nothing breaching costs nothing extra.
        open_keys: set | None = None
        for device_id in device_ids:
            device = devices.get(device_id)
            if device is None:
                continue
            label = None
            interfaces = None
            for rule in rules:
                child_rows = children.get((device_id, rule["source_kind"]))
                if child_rows:
                    targets = [("interface", f"{device_id}:{if_index}", if_index, metric)
                               for if_index, metric in sorted(child_rows)]
                else:
                    targets = [("device", str(device_id), None,
                                metrics_by_device_key.get(
                                    (device_id, rule["source_kind"])))]
                # An override row for a device Nodes no longer knows about is
                # harmless by construction: this loop only ever looks one up
                # for a device_id it already pulled from metrics_by_device_key
                # / devices_by_ids above, so a deleted device's leftover row
                # is simply never fetched, let alone acted on.
                override = overrides_by_rule.get(rule["id"], {}).get(device_id)
                if override is not None and not override["enabled"]:
                    # enabled=0 means this rule never fires for THIS device,
                    # so whatever is open must be resolved now rather than
                    # frozen at its last value -- unlike a rule disabled
                    # globally or a device removed entirely, both bigger,
                    # rarer actions. by='' so it reads as automatic, not a
                    # hand resolve: re-enabling and breaching again must open
                    # a fresh alert, not find itself permanently suppressed.
                    # Both entity shapes are resolved, not just this tick's
                    # targets -- the device may have alerted per port
                    # yesterday and device-wide before that.
                    resolved = self.db.resolve_by_dedup(
                        f"{rule['key']}:device:{device_id}", by="")
                    if resolved:
                        self.counters["resolved"] += 1
                    self.counters["resolved"] += len(
                        self.db.resolve_by_dedup_prefix(
                            f"{rule['key']}:interface:{device_id}:", by=""))
                    # Skip before touching the streak at all, and never
                    # written into live_streaks below, so turning it back on
                    # later starts a fresh streak rather than resuming
                    # whatever was counted before it was switched off.
                    continue
                base_threshold = rule["threshold"]
                base_clear = rule["clear_threshold"]
                if override is not None:
                    # NULL on the override row means "inherit the rule's own
                    # value" (see the device_thresholds schema comment in
                    # alertsdb.py), so only a non-NULL column overrides it.
                    if override["threshold"] is not None:
                        base_threshold = override["threshold"]
                    if override["clear_threshold"] is not None:
                        base_clear = override["clear_threshold"]
                # A rule whose limit the PORT publishes reads that and
                # nothing else: not rule.threshold, not the override's
                # numbers. The override's `enabled` flag above still applies
                # -- see alertrules.PUBLISHED_THRESHOLD_RULES.
                published_for = PUBLISHED_THRESHOLD_RULES.get(rule["key"] or "")
                for entity_kind, entity_id, if_index, metric in targets:
                    threshold, clear_threshold = base_threshold, base_clear
                    if published_for is not None:
                        root, column = published_for
                        limits = published.get((device_id, root, if_index))
                        limit = limits[column] if limits is not None else None
                        if limit is None:
                            # The dominant path on a real fleet, and one dict
                            # lookup: this port's switch publishes no limit
                            # for this band, so there is nothing to judge it
                            # against. Skipped BEFORE the streak is touched
                            # and never written into live_streaks, so an
                            # optic that starts publishing tomorrow starts a
                            # fresh streak rather than resuming one counted
                            # against a number that was never applied.
                            continue
                        threshold = limit
                        # A transceiver publishes a level, not a band; this
                        # app supplies the gap. See PUBLISHED_HYSTERESIS.
                        gap = PUBLISHED_HYSTERESIS.get(root, 0.0)
                        clear_threshold = (threshold + gap
                                           if comparison_of(rule) == "below"
                                           else threshold - gap)
                    eval_rule = rule
                    if (threshold != rule["threshold"]
                            or clear_threshold != rule["clear_threshold"]):
                        # evaluate_threshold's own signature stays untouched --
                        # its hysteresis state machine, and its tests, do not
                        # need to know overrides exist. It reads threshold/
                        # clear_threshold off whatever mapping it is handed,
                        # and sqlite3.Row already satisfies the same mapping
                        # protocol (.keys() + __getitem__) a plain dict does,
                        # so a dict copy with just those two fields swapped is
                        # indistinguishable to it from a real rule row.
                        cache_key = (rule["id"], threshold, clear_threshold)
                        eval_rule = eval_cache.get(cache_key)
                        if eval_rule is None:
                            if rule["id"] not in rule_dicts:
                                rule_dicts[rule["id"]] = dict(rule)
                            eval_rule = dict(rule_dicts[rule["id"]])
                            eval_rule["threshold"] = threshold
                            eval_rule["clear_threshold"] = clear_threshold
                            eval_cache[cache_key] = eval_rule
                    value = metric["last_value"] if metric else None
                    sample_ts = metric["last_ts"] if metric else None
                    stale = (stale_after > 0 and sample_ts is not None
                             and now - sample_ts > stale_after)
                    if stale:
                        value, sample_ts = None, None
                    # Keyed on (rule, entity id) alone -- NOT the effective
                    # threshold/clear pair -- because _child_first_breach_ts
                    # has to find this same streak given only a rule and an
                    # occurrence, on behalf of a rollup PARENT resolved by
                    # hand. The effective pair rides inside the entry instead
                    # and is compared below, so a changed override still
                    # starts a fresh streak without widening the key.
                    streak_key = (rule["id"], entity_id)
                    previous_ts, streak, first_breach_ts, prev_threshold, prev_clear = (
                        self._breach_streaks.get(streak_key, (None, 0, None, None, None)))
                    if prev_threshold != threshold or prev_clear != clear_threshold:
                        # The effective pair moved (override or the rule's own
                        # threshold/clear_threshold edited) -- treated like a
                        # target never seen before: a streak counted against
                        # numbers that no longer apply is not evidence, so it
                        # must not count toward for_polls under the new ones,
                        # and a hand-resolved but still-breaching alert
                        # re-opens as a new run.
                        previous_ts, streak, first_breach_ts = None, 0, None
                    if stale:
                        # Otherwise breach_seconds would span the silent gap
                        # and fire for_seconds instantly on resume.
                        first_breach_ts = None
                    # The same predicate evaluate_threshold itself uses, so a
                    # 'below' rule's streak counts what that rule calls breach.
                    over = breaches(eval_rule, value)
                    if not over:
                        streak = 0
                    elif sample_ts != previous_ts:
                        streak += 1
                        if first_breach_ts is None:
                            first_breach_ts = sample_ts
                    # Sample time, not wall-clock: a device that stopped being
                    # polled must not accumulate breach seconds while silent.
                    breach_seconds = (0.0 if first_breach_ts is None or sample_ts is None
                                      else max(0.0, sample_ts - first_breach_ts))
                    result = evaluate_threshold(eval_rule, value, streak, breach_seconds)
                    if result == "clear":
                        # Ends on an OBSERVED CLEAR, not the first sample back
                        # inside threshold -- resetting inside the hysteresis
                        # band let a value wobbling near the limit re-open an
                        # alert an operator had resolved by hand.
                        first_breach_ts = None
                    # Replaces the stored dict at the end of the pass; the
                    # effective pair rides along so the next tick can tell a
                    # real override change from business as usual.
                    live_streaks[streak_key] = (
                        sample_ts, streak, first_breach_ts, threshold, clear_threshold)
                    if result == "":
                        continue
                    if label is None:
                        # Resolved at most once per device per tick, and only
                        # for a device that has something to report.
                        label = namelookup.resolve_name(
                            self.nodes_db, self.app_db, device["ip"],
                            device=device) or device["ip"]
                    entity_label = label
                    extra = {
                        "metric_label": metric["label"] if metric else rule["source_kind"],
                        "value": str(value),
                        # The EFFECTIVE threshold (device override, if any),
                        # not rule["threshold"]: the extra is what the
                        # email/UI shows as "Threshold:", and that must read
                        # as the number this device was actually judged
                        # against.
                        "threshold": str(threshold),
                        # Says WHERE that number came from, because for the
                        # optic power rules it is not on the Rules page at
                        # all: an operator reading "Threshold: -14.4" for one
                        # port and "-8.2" for the next needs to know why they
                        # differ before they go looking for the setting.
                        "threshold_source": (" (published by the optic)"
                                             if published_for is not None
                                             else ""),
                    }
                    if result == "breach" and sample_ts is not None and sample_ts == previous_ts:
                        # Nothing new and already open: no label, no read.
                        if open_keys is None:
                            open_keys = self.db.open_dedup_keys()
                        probe = Occurrence(
                            kind="threshold", source_kind=rule["source_kind"],
                            entity_kind=entity_kind, entity_id=entity_id,
                            entity_label="", ts=0.0, message="")
                        if dedup_key(rule, probe) in open_keys:
                            continue
                    if entity_kind == "interface" and result == "breach":
                        if interfaces is None:
                            # One read per device per tick, and only for a
                            # device with a per-port target that has something
                            # to say.
                            interfaces = {row["if_index"]: row for row
                                          in self.nodes_db.interfaces(device_id)}
                        row = interfaces.get(if_index)
                        entity_label = f"{label} / {interface_label(row, if_index)}"
                        extra["if_index"] = str(if_index)
                        extra["interface_name"] = (
                            (row["descr"] if row is not None else "") or "")
                        extra["interface_alias"] = (
                            (row["alias"] if row is not None else "") or "")
                    if result == "breach":
                        # The unit is in the message because a per-port optic
                        # reading is meaningless without it: "-24.1" is a
                        # number, "-24.1 dBm" is a fault.
                        unit = (metric["unit"] if metric is not None
                                and "unit" in metric.keys() else "") or ""
                        occurrence = Occurrence(
                            kind="threshold", source_kind=rule["source_kind"],
                            entity_kind=entity_kind, entity_id=entity_id,
                            entity_label=entity_label, ts=time.time(),
                            message=f"{entity_label}: {rule['name']} "
                                    f"({value}{' ' + unit if unit else ''})",
                            device_name=device["name"] or "", device_ip=device["ip"],
                            extra=extra,
                            # Pins this occurrence to THIS rule so _apply
                            # cannot cross-match it onto another rule sharing
                            # the same source_kind.
                            rule_key=rule["key"] or "")
                        if self._operator_resolved(rule, occurrence, first_breach_ts):
                            # Stays closed until a clear observation is
                            # followed by a new breach.
                            continue
                        if sample_ts is not None and sample_ts == previous_ts:
                            # No new sample, so no new occurrence -- raising it
                            # anyway bumped `count` every tick regardless of
                            # how often the metric was actually sampled.
                            # Still raised when nothing is open for this key,
                            # which is how a threshold re-derives after a
                            # rollup parent clears or a resolve while ongoing.
                            if open_keys is None:
                                open_keys = self.db.open_dedup_keys()
                            if dedup_key(rule, occurrence) in open_keys:
                                continue
                        occurrences.append(occurrence)
                    elif result == "clear":
                        dedup = dedup_key(rule, Occurrence(
                            kind="threshold", source_kind=rule["source_kind"],
                            entity_kind=entity_kind, entity_id=entity_id,
                            entity_label=entity_label, ts=time.time(), message=""))
                        resolved = self.db.resolve_by_dedup(dedup, by="")
                        if resolved:
                            self.counters["resolved"] += 1
                            self._notify_clear(resolved, rule, settings)
        self._breach_streaks = live_streaks
        return occurrences

    # How long the published-threshold snapshot is reused, against the
    # poller's 3600 s write cadence. Short enough that an optic swapped this
    # minute is judged against its new limits within one, long enough that
    # 719 of every 720 ticks cost nothing.
    _PUBLISHED_CACHE_S = 60.0

    def _published_thresholds(self, rules, now: float) -> dict:
        """(device_id, metric root, ifIndex) -> the limits that port's own
        transceiver publishes, for the roots the ENABLED rules actually
        name — see alertrules.PUBLISHED_THRESHOLD_RULES.

        {} immediately when no such rule is enabled, so a site that has
        turned optic power alerting off pays nothing at all for it.
        """
        roots = sorted({PUBLISHED_THRESHOLD_RULES[key][0] for key in
                        ((r["key"] or "") for r in rules)
                        if key in PUBLISHED_THRESHOLD_RULES})
        if not roots:
            return {}
        reader = getattr(self.nodes_db, "interface_thresholds_for_roots", None)
        if reader is None:
            return {}
        stamp, cached_roots, cached = self._published_cache
        if cached is not None and cached_roots == roots \
                and now - stamp < self._PUBLISHED_CACHE_S:
            return cached
        rows = reader(roots)
        self._published_cache = (now, roots, rows)
        return rows

    def _evaluate_dhcp_thresholds(self, settings) -> list[Occurrence]:
        """DHCP scope utilization, evaluated the same way as a device
        threshold but against IPAM rather than Nodes.

        It cannot reuse _evaluate_thresholds, which iterates nodes_db
        devices and stamps entity_kind="device"; a DHCP scope is none of
        those, so it gets its own evaluator and rule kind.

        Utilization is (leased + reserved) / range size, computed exactly
        the way the DHCP page computes it (api.get_ipam_dhcp_scopes), so
        the number in an alert is the number on screen.

        The streak subtlety: for_polls is documented as "N consecutive
        polls", and everywhere else in this engine a poll is a Nodes poll.
        DHCP is polled every 15 minutes while this engine ticks every 5
        seconds, so counting ticks would make for_polls=2 mean "10 seconds"
        rather than "two polls". The streak therefore only advances when a
        scope's polled_ts actually moves.

        It carries first_breach_ts for the same reason _evaluate_thresholds
        does, and applies the same operator gate: a scope that is full is
        still full at the next poll, so an alert an operator resolved by
        hand came straight back — this was the one threshold evaluator that
        never got the 4.34.0 gate. A poll that finds the scope back under
        its clear threshold ends the run, and the next breach opens
        normally.
        """
        if self.ipam_db is None:
            return []
        rules = [r for r in self.db.rules()
                 if r["enabled"] and r["kind"] == "dhcp_threshold"]
        if not rules:
            return []

        from .ipamdb import scope_size

        leases_by_scope: dict[tuple, list] = {}
        for lease in self.ipam_db.dhcp_leases():
            leases_by_scope.setdefault(
                (lease["server_id"], lease["scope_id"]), []).append(lease)
        servers = {row["id"]: row for row in self.ipam_db.dhcp_servers()}

        occurrences = []
        # Loaded on first use, same as _evaluate_thresholds: a tick with
        # nothing breaching costs nothing extra.
        open_keys: set | None = None
        for scope in self.ipam_db.dhcp_scopes():
            total = scope_size(scope["start_ip"], scope["end_ip"])
            if not total:
                # A scope with no usable range (or one this build cannot
                # size) has no utilization to speak of; skipping is honest,
                # whereas 0% would read as "plenty of room".
                continue
            leases = leases_by_scope.get((scope["server_id"], scope["scope_id"]), [])
            reserved = sum(1 for row in leases if row["is_reservation"])
            used = len(leases)          # reservations occupy addresses too
            value = 100.0 * used / total
            server = servers.get(scope["server_id"])
            label = (f"{scope['name'] or scope['scope_id']} on "
                     f"{scope['server_label'] or (server['address'] if server else '')}")
            entity_id = f"{scope['server_id']}:{scope['scope_id']}"

            for rule in rules:
                streak_key = (rule["id"], entity_id)
                previous_ts, streak, first_breach_ts = self._dhcp_streaks.get(
                    streak_key, (None, 0, None))
                polled_ts = scope["polled_ts"]
                threshold = rule["threshold"]
                over = threshold is not None and value >= threshold
                if not over:
                    streak = 0
                elif polled_ts != previous_ts:
                    streak += 1
                    if first_breach_ts is None:
                        first_breach_ts = polled_ts

                # Sample time, not wall-clock, for the same reason
                # _evaluate_thresholds uses sample_ts: breach_seconds must
                # span polls, not five-second engine ticks.
                breach_seconds = (0.0 if first_breach_ts is None or polled_ts is None
                                  else max(0.0, polled_ts - first_breach_ts))
                result = evaluate_threshold(rule, value, streak, breach_seconds)
                if result == "clear":
                    # Only a poll that finds the scope back under its clear
                    # threshold ends the run — see the same reasoning in
                    # _evaluate_thresholds. A scope that drops from 90 % to
                    # 80 % is still nearly full, and treating that as a
                    # recovery re-opened an alert an operator had resolved.
                    first_breach_ts = None
                self._dhcp_streaks[streak_key] = (polled_ts, streak, first_breach_ts)
                occurrence = Occurrence(
                    kind="dhcp_threshold", source_kind=rule["source_kind"],
                    entity_kind="dhcp_scope", entity_id=entity_id,
                    entity_label=label, ts=time.time(),
                    message=f"{label}: {used}/{total} addresses in use "
                            f"({value:.1f}%)",
                    device_name=scope["server_label"] or "",
                    device_ip=(server["address"] if server else ""),
                    extra={"metric_label": "scope utilization",
                           "value": f"{value:.1f}",
                           "threshold": str(rule["threshold"]),
                           "leased": str(used - reserved),
                           "reserved": str(reserved),
                           "total": str(total),
                           "available": str(max(0, total - used))})
                if result == "breach":
                    if self._operator_resolved(rule, occurrence, first_breach_ts):
                        # The same run an operator already resolved by hand.
                        # A scope at 96 % is still at 96 % on the next DHCP
                        # poll, so without this the alert an operator closed
                        # came back at the next tick — the same defect as the
                        # device thresholds, in the one evaluator that never
                        # got the gate. A poll that finds the scope back
                        # under its clear threshold resets first_breach_ts
                        # above, so the next breach is a new run and opens.
                        continue
                    if polled_ts is not None and polled_ts == previous_ts:
                        # Nothing has been polled since the last tick — same
                        # guard as _evaluate_thresholds: count means scope
                        # polls, not five-second engine ticks, so re-raising
                        # the same poll bumped `count` every tick instead of
                        # every 15-minute DHCP poll.
                        if open_keys is None:
                            open_keys = self.db.open_dedup_keys()
                        if dedup_key(rule, occurrence) in open_keys:
                            continue
                    occurrences.append(occurrence)
                elif result == "clear":
                    resolved = self.db.resolve_by_dedup(
                        dedup_key(rule, occurrence), by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, rule, settings)
        return occurrences

    # The metrics a NetPath rule can be about, and what each one is called
    # in the rule editor. Keyed by rules.source_kind, the same way every
    # other threshold kind names its metric.
    NETPATH_METRIC_LABELS = {
        "trace_loss_pct": "packet loss to the destination",
        "trace_unreached_pct": "traces that did not reach the destination",
        "trace_rtt_warn_pct": "round-trip time against this destination's warn threshold",
    }

    # Below this, a "three times the warn threshold" rule is measuring
    # ordinary jitter rather than a degradation: a destination warned at 5 ms
    # would alert at 15 ms, which a three-probe mean crosses on a busy switch
    # for no reason at all.
    NETPATH_MIN_WARN_RTT_MS = 20.0

    # How many traces a windowed metric needs before it means anything. A
    # window holding two traces makes one bad trace 50%, which would fire a
    # "half the traces failed" rule on a single event — the opposite of what
    # a windowed rule is for.
    NETPATH_MIN_WINDOW_TRACES = 5

    def _netpath_metrics(self, target, trace, wants_window: bool = True) -> dict:
        """{source_kind: (value, message, extra)} for one destination's newest
        trace. A metric that cannot honestly be computed is absent, and an
        absent metric neither fires nor clears its rule.

        `wants_window` is False when no enabled rule consumes the windowed
        share, which skips the only query here that is not already in hand:
        reach_summary reads a whole window per destination, changes only
        when a trace lands, and would otherwise run twelve times a minute
        per destination under the lock Monitor writes traces with.

        Only the destination hop is ever measured, which is the same rule the
        route graph and the timeline follow (monitor.classify): intermediate
        routers rate-limit ICMP as a matter of policy, so their loss says
        nothing about the path. For the same reason there is no per-hop rule
        here at all — and the live per-hop probe counters are cumulative since
        the last path change, so a hop that was lossy last week would keep any
        average over them high indefinitely.
        """
        host = target["host"]
        label = target["label"] or host
        metrics: dict = {}

        loss = trace["loss_pct"]
        if loss is not None:
            if trace["reached"]:
                message = f"{label}: {loss:.0f}% packet loss to {host}"
            elif trace["icmp_code"]:
                # A refusal names the router and the reason, which is a
                # different conversation from silence and usually points at an
                # ACL or a routing change.
                message = (f"{label}: {host} unreachable — "
                           f"{trace['icmp_code']} from {trace['icmp_from']}")
            else:
                message = f"{label}: no reply from {host}"
            metrics["trace_loss_pct"] = (
                float(loss), message,
                {"metric_label": self.NETPATH_METRIC_LABELS["trace_loss_pct"],
                 "value": f"{loss:.0f}", "trace_status": trace["status"],
                 "icmp_code": trace["icmp_code"] or "",
                 "icmp_from": trace["icmp_from"] or ""})

        # A window rather than the newest trace: this is the rule that catches
        # a path that works intermittently, which consecutive-failure counting
        # by definition cannot see. Six intervals, or an hour, whichever is
        # longer, so a destination traced twice an hour is judged over enough
        # of them to mean something.
        interval = float(target["interval_s"] or 300)
        t1 = trace["started_ts"]
        window = max(3600.0, 6 * interval)
        summary = (self.netpath_db.reach_summary(target["id"], t1 - window, t1)
                   if wants_window else {"measured": 0, "unreached": 0})
        if summary["measured"] >= self.NETPATH_MIN_WINDOW_TRACES:
            share = 100.0 * summary["unreached"] / summary["measured"]
            metrics["trace_unreached_pct"] = (
                share,
                f"{label}: {summary['unreached']} of the last "
                f"{summary['measured']} traces did not reach {host} "
                f"({share:.0f}%)",
                {"metric_label": self.NETPATH_METRIC_LABELS["trace_unreached_pct"],
                 "value": f"{share:.0f}",
                 "window_traces": str(summary["measured"]),
                 "window_minutes": f"{window / 60:.0f}"})

        # Latency only on a trace that got through. rtt_ms is the destination
        # hop's mean where there is one, but on a refusal it is the time to
        # the router that refused — a real measurement of the wrong thing, and
        # reached=0 is the stored fact that rules it out.
        warn = float(target["warn_rtt_ms"] or 0)
        rtt = trace["rtt_ms"]
        if trace["reached"] and rtt is not None and warn > 0:
            scale = max(warn, self.NETPATH_MIN_WARN_RTT_MS)
            share = 100.0 * float(rtt) / scale
            metrics["trace_rtt_warn_pct"] = (
                share,
                f"{label}: {float(rtt):.0f} ms to {host}, {share / 100:.1f}x "
                # `scale`, not `warn`: below the floor the two differ, and
                # printing the multiple against one while computing it against
                # the other renders "1.5x its 5 ms warn threshold" for a 30 ms
                # reading. Where the floor applied, say so rather than quoting a
                # threshold the number was not measured against.
                + (f"its {warn:.0f} ms warn threshold"
                   if scale == warn else
                   f"the {scale:.0f} ms floor (its {warn:.0f} ms warn "
                   f"threshold is below it)"),
                {"metric_label": self.NETPATH_METRIC_LABELS["trace_rtt_warn_pct"],
                 "value": f"{share:.0f}", "rtt_ms": f"{float(rtt):.0f}",
                 "warn_rtt_ms": f"{warn:.0f}"})
        return metrics

    def _evaluate_netpath_thresholds(self, settings) -> list[Occurrence]:
        """NetPath destinations against their threshold rules.

        A third threshold evaluator for the same reason there is a second one:
        _evaluate_thresholds iterates Nodes devices and reads the Nodes
        metrics table, and a traceroute destination is neither. Its entity is
        a NetPath target, its sample is a completed trace, and its "poll" is
        that destination's own trace interval.

        Which is the part that matters for noise. The engine ticks every five
        seconds; a destination is traced every five minutes by default. A
        streak counted in ticks would turn "three consecutive traces" into
        fifteen seconds, so it is counted against the trace's own started_ts —
        the same discipline the device and DHCP evaluators use, for the same
        reason.

        Statuses that record a fault in the measurement rather than in the
        path — a traceroute that could not run, a slot skipped because the
        previous run was still going — produce no sample at all: they leave
        every streak exactly as it was rather than counting as a failure.

        The streak also carries first_breach_ts, the same third element
        _breach_streaks carries for a Nodes device, so a breach an operator
        resolved by hand can be told apart from the next one: see the
        operator_resolved_since check right below the streak update.
        """
        if self.netpath_db is None:
            return []
        rules = [r for r in self.db.rules()
                 if r["enabled"] and r["kind"] == "netpath_threshold"]
        if not rules:
            return []
        wants_window = any((r["source_kind"] or "") == "trace_unreached_pct"
                          for r in rules)
        targets = [t for t in self.netpath_db.targets() if t["enabled"]]
        latest = self.netpath_db.last_traces([t["id"] for t in targets])

        occurrences = []
        live = set()
        # Loaded on first use, same as _evaluate_thresholds: a tick with
        # nothing breaching costs nothing extra.
        open_keys: set | None = None
        for target in targets:
            trace = latest.get(target["id"])
            if trace is None:
                continue
            live.add(str(target["id"]))
            if trace["status"] in ("error", "overrun"):
                continue
            label = target["label"] or target["host"]
            entity_id = str(target["id"])
            metrics = self._netpath_metrics(target, trace, wants_window)
            for rule in rules:
                source = rule["source_kind"] or ""
                if source not in metrics:
                    # Drop the streak rather than leaving it standing. A metric
                    # goes absent when it cannot be computed honestly -- the
                    # window fell below its sample floor, or the destination
                    # was not reached so latency is unmeasurable -- and that is
                    # a break in the consecutive run, not a pause in it.
                    # Leaving it would let two breaching traces, a half-hour
                    # outage, and one more breaching trace add up to the three
                    # in a row this rule asks for. _evaluate_thresholds drops
                    # its streak on a missing sample for the same reason.
                    self._netpath_streaks.pop((rule["id"], entity_id), None)
                    continue
                value, message, extra = metrics[source]
                streak_key = (rule["id"], entity_id)
                previous_ts, streak, first_breach_ts = self._netpath_streaks.get(
                    streak_key, (None, 0, None))
                sample_ts = trace["started_ts"]
                threshold = rule["threshold"]
                over = threshold is not None and value >= threshold
                if not over:
                    streak = 0
                elif sample_ts != previous_ts:
                    streak += 1
                    if first_breach_ts is None:
                        first_breach_ts = sample_ts

                # Sample time, not wall-clock, for the same reason
                # _evaluate_thresholds uses sample_ts: breach_seconds must
                # span traces, not five-second engine ticks.
                breach_seconds = (0.0 if first_breach_ts is None or sample_ts is None
                                  else max(0.0, sample_ts - first_breach_ts))
                result = evaluate_threshold(rule, value, streak, breach_seconds)
                if result == "clear":
                    # An observed clear ends the run, the same rule as the
                    # other two evaluators — a trace that got through, not
                    # merely one that was less bad than the last.
                    first_breach_ts = None
                self._netpath_streaks[streak_key] = (sample_ts, streak, first_breach_ts)
                occurrence = Occurrence(
                    kind="netpath_threshold", source_kind=source,
                    entity_kind="netpath_target", entity_id=entity_id,
                    entity_label=label, ts=time.time(), message=message,
                    device_name=label, device_ip=target["host"],
                    extra={**extra, "threshold": str(threshold)})
                if result == "breach":
                    if self._operator_resolved(rule, occurrence, first_breach_ts):
                        # Same breach run an operator already resolved by
                        # hand; see the matching check in
                        # _evaluate_thresholds.
                        continue
                    if sample_ts is not None and sample_ts == previous_ts:
                        # Nothing has been traced since the last tick — same
                        # guard as _evaluate_thresholds: count means traces,
                        # not five-second engine ticks, so re-raising the
                        # same trace bumped `count` every tick instead of
                        # every trace interval.
                        if open_keys is None:
                            open_keys = self.db.open_dedup_keys()
                        if dedup_key(rule, occurrence) in open_keys:
                            continue
                    occurrences.append(occurrence)
                elif result == "clear":
                    resolved = self.db.resolve_by_dedup(
                        dedup_key(rule, occurrence), by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, rule, settings)
        self._sweep_netpath_alerts(rules, live)
        return occurrences

    def _sweep_netpath_alerts(self, rules, live: set) -> None:
        """Resolve open NetPath alerts whose destination is no longer being
        traced.

        A threshold alert clears by being re-evaluated and found to have
        dropped below its clear value — which cannot happen for a destination
        that was disabled or deleted, because there is nothing left to
        evaluate. Without this the alert would sit open forever, and disabling
        a destination is a normal thing to do while working on a link.

        resolved_by is written as '' rather than a descriptive string,
        matching every other engine auto-resolve (see AlertsDatabase.
        operator_resolved_since): an operator-shaped string here would read
        as a hand resolve and permanently suppress a destination that gets
        re-enabled and starts breaching the same rule again.
        """
        for rule in rules:
            for row in self.db.alerts(state="unresolved", rule_id=rule["id"]):
                if row["entity_kind"] != "netpath_target":
                    continue
                if row["entity_id"] in live:
                    continue
                self.db.resolve(row["id"], by="")
                self.counters["resolved"] += 1
                # No clear email: nobody needs telling that a destination they
                # just turned off has stopped being measured.

    def _operator_resolved(self, rule, occurrence: Occurrence,
                          first_breach_ts) -> bool:
        """True when an operator resolved THIS breach run by hand, so it must
        not re-open as a new row.

        The one gate all three threshold evaluators ask, rather than the three
        verbatim copies they had (and the fourth that was missed for a whole
        release, leaving DHCP scope alerts re-opening five seconds after every
        hand resolve). `_operator_resolves` is the per-tick
        `operator_resolved_since` cache; a resolve at or after the run began is
        a resolve OF that run, since a run only ends on an observed clear.
        """
        resolved_ts = self._operator_resolves.get(dedup_key(rule, occurrence))
        return (resolved_ts is not None and first_breach_ts is not None
                and first_breach_ts <= resolved_ts)

    # ---------------------------------------------------------------- apply

    # ------------------------------------------------------------- rollup

    def _device_probe(self, occurrence: Occurrence):
        """`occurrence` as a question about its DEVICE, for the rollup
        lookups, or None when it is about no device at all.

        For an OUTAGE parent -- every entry in ROLLED_UP_BY whose parent is
        device_down -- the parent is a fact about the switch, recorded
        against the device, so an interface child asking unprojected would
        find nothing and never be suppressed. Only `interface` is projected;
        a netpath_target's parent is about that target and must be asked
        about unchanged.

        NOT for a same-metric pair (alertrules.same_metric_pair): both halves
        of the optic power pairs are about ONE PORT, so projecting the child
        onto its switch would ask about an alert that is never keyed that
        way, and the pairing would silently never fire. Both callers below
        make that choice before calling; this function has no way to see it.
        """
        if occurrence.entity_kind != "interface":
            return occurrence
        device_id = device_id_for(occurrence.entity_kind, occurrence.entity_id)
        if device_id is None:
            return None
        return Occurrence(
            kind=occurrence.kind, source_kind=occurrence.source_kind,
            entity_kind="device", entity_id=str(device_id),
            entity_label=occurrence.entity_label, ts=occurrence.ts,
            message=occurrence.message, device_name=occurrence.device_name,
            device_ip=occurrence.device_ip)

    def _rollup_parent(self, rule, occurrence: Occurrence):
        """The open alert that already says what `rule` is about to say,
        SUPPRESSED, or None.

        Three answers, in order:

        1. The same device's own parent alert is open — the original rollup,
           see alertrules.ROLLED_UP_BY for which rules have one.
        2. The parent is `device_down`, it is NOT open, and the device is
           still down. That is the case an operator creates by triaging: the
           natural action on an outage is to resolve it, and the moment they
           did, every child re-derived on the next tick — device_down cannot
           come back to re-suppress them, because it is event-driven and no
           second `down` event is ever recorded. Triaging an outage would
           otherwise be punished with more noise than it removed.
        3. `device_down` itself, for a device whose upstream is down. This is
           the topology half: without it a core switch failure arrives as one
           alert per access switch behind it, each true and none of them the
           one worth reading.
        4. A child rule (case 1's `parent_key`) whose device's OWN
           device_down is not open for the same reason case 3 exists: an
           ancestor's outage got there first, so there is never a
           device_down alert to check against. A child rolls up exactly as
           far as device_down does, so it asks case 3's topology question on
           behalf of a different rule.
        """
        if occurrence.entity_kind not in ROLLUP_ENTITY_KINDS:
            return None
        # ROLLED_UP_BY, not the entity kind, is what admits a rule: e.g.
        # interface_down has no entry there, so it falls straight through.
        parent_key = ROLLED_UP_BY.get(rule["key"] or "")
        if parent_key:
            # The per-tick snapshot _tick builds from the rules it has
            # already read, not a rule_by_key() query per suppressed
            # occurrence: the rules table cannot change mid-tick, and
            # _parent_operator_resolved has always used the snapshot —
            # reading the two from different places let one see a rule the
            # other did not. _rules_by_key holds only ENABLED rules, which is
            # exactly the `parent_rule["enabled"]` test this made by hand.
            parent_rule = self._rules_by_key.get(parent_key)
            if parent_rule is None:
                return None
            # A same-metric pair is about the same port; anything else is
            # about the switch. See _device_probe.
            probe = (occurrence if same_metric_pair(rule, parent_rule)
                     else self._device_probe(occurrence))
            if probe is None:
                return None
            parent = self.db.open_by_dedup(dedup_key(parent_rule, probe))
            if parent is not None:
                return parent
            # No open parent alert for THIS device. Before falling through to
            # _parent_operator_resolved (case 2, immediately below this in
            # _apply), ask case 3's own question on this device's behalf: is
            # device_down itself covered by an ancestor's outage? Only for
            # parent_key == "device_down" — a NetPath child's parent,
            # netpath_unreachable, has no topology to walk, and
            # _upstream_outage is specifically about nodesdb's device chain.
            if parent_key == "device_down" and probe.entity_kind == "device":
                covered = self._upstream_outage(parent_rule, probe)
                if covered is not None:
                    return covered
            # The operator-resolved route is _parent_operator_resolved's
            # question, immediately below this in _apply: it asks the same
            # predicate but also remembers the cover and logs it once.
            # Answering it here too would suppress before that runs.
            return None
        if (rule["key"] or "") == "device_down" and occurrence.entity_kind == "device":
            return self._upstream_outage(rule, occurrence)
        return None

    def _parent_still_failing(self, occurrence: Occurrence,
                              entity_id=None) -> bool:
        """Whether the device this occurrence rolls up to is still down.

        The one predicate behind every kind of outage suppression, memoised
        per tick so N children of one dead device cost one device read:

        - a parent alert that is open (`_rollup_parent`);
        - a parent an operator resolved by hand while the device was still
          down (`_parent_operator_resolved`, which adds the cover that
          outlives the resolve window);
        - a parent that never opened an alert at all, and an upstream
          ancestor in another device's outage (`_upstream_outage`).

        All four used to ask the question their own way — two of them by
        reading `device["status"]`, which is the poller's last written state
        rather than the rule's own predicate. `_still_true` re-evaluates the
        `down` condition itself, so a device the poller has not reached yet
        does not read as recovered.
        """
        entity_id = occurrence.entity_id if entity_id is None else entity_id
        cache_key = ("device_down", occurrence.entity_kind, str(entity_id))
        if cache_key not in self._parent_conditions:
            probe = Occurrence(
                kind="device_event", source_kind="down",
                entity_kind=occurrence.entity_kind, entity_id=entity_id,
                entity_label=occurrence.entity_label, ts=occurrence.ts,
                message="")
            self._parent_conditions[cache_key] = self._still_true(probe)
        return self._parent_conditions[cache_key]

    def _upstream_outage(self, rule, occurrence: Occurrence):
        """The outage of the nearest ancestor that is also down.

        Walks upwards rather than checking only the immediate upstream: in a
        site outage the whole chain goes at once, and whichever device the
        engine happened to see first is the one holding the open alert. The
        walk is cycle-safe and depth-capped in nodesdb.upstream_chain.

        An ancestor with an open outage alert returns that alert, so the
        child is absorbed into it and says so in its rollup note. An ancestor
        that is still down but whose alert an operator resolved by hand
        returns SUPPRESSED instead — the same cover `_parent_operator_resolved`
        applies within one device, applied up the chain, so resolving a site's
        outage does not re-open every switch behind it on the next tick.

        getattr rather than a direct call so an engine running against a
        database module without the topology columns behaves exactly as it
        did before them.

        Memoised per tick per device, same shape as _parent_still_failing's
        cache and for the same reason: case 4 above asks this once per
        rollup child (a dozen or so rule keys) on top of case 3's own ask
        for the device_down occurrence itself, all for the SAME device in
        the SAME outage, and the answer — which ancestor, if any, covers it
        — cannot change mid-tick. Without this a site outage covering N
        devices costs N times a dozen chain walks instead of N.
        """
        chain_of = getattr(self.nodes_db, "upstream_chain", None)
        if chain_of is None:
            return None
        cache_key = (rule["key"] or "", occurrence.entity_id)
        if cache_key in self._upstream_outage_cache:
            return self._upstream_outage_cache[cache_key]
        result = self._upstream_outage_uncached(rule, occurrence)
        self._upstream_outage_cache[cache_key] = result
        return result

    def _upstream_outage_uncached(self, rule, occurrence: Occurrence):
        chain_of = self.nodes_db.upstream_chain
        try:
            device_id = int(occurrence.entity_id)
        except (TypeError, ValueError):
            return None
        covered = None
        for ancestor_id in chain_of(device_id):
            ancestor_dedup = f"{rule['key']}:device:{ancestor_id}"
            parent = self.db.open_by_dedup(ancestor_dedup)
            if parent is not None:
                return parent
            if covered is not None:
                continue
            # No open alert for this ancestor. It covers what is behind it
            # only if somebody RESOLVED its outage by hand and the outage is
            # still real — the same condition _parent_operator_resolved
            # applies within one device. "Still down" alone is not enough:
            # in a site failure every device is down and none of them has an
            # alert yet, so suppressing on that would leave the whole site
            # silent with nothing to attach the silence to. The upstream's
            # own alert opens first, and everything behind it rolls into it.
            resolved_ts = self._operator_resolves.get(ancestor_dedup)
            covered_since = self._parent_covers.get(ancestor_dedup)
            if resolved_ts is None and covered_since is None:
                continue
            if self._parent_still_failing(occurrence, entity_id=ancestor_id):
                if covered_since is None:
                    self._parent_covers[ancestor_dedup] = (
                        resolved_ts or time.time())
                covered = SUPPRESSED
            else:
                self._parent_covers.pop(ancestor_dedup, None)
        return covered

    def _parent_operator_resolved(self, rule, occurrence: Occurrence) -> bool:
        """True when an operator resolved this occurrence's rollup PARENT by
        hand and the parent's condition still holds.

        A rollup child is otherwise suppressed only while its parent alert
        is open or acknowledged, because a resolved parent must not suppress
        forever. But resolving "Device not responding" for a device that is
        still down releases every alert the outage was hiding — a dead
        device reports 100 % loss on every poll — so they all re-open on the
        next tick. The threshold gate cannot see this: it is keyed on the
        CHILD's own dedup key, and nobody resolved the child.

        So: an operator's resolve of a parent covers the children it was
        hiding, for as long as the parent's condition still holds. "Still
        holds" is asked of current state, never of the resolve:

        - `device_down`: the device's status is still "down", the same
          question the outage alert answers. Once a cover takes effect its
          parent key is remembered in _parent_covers, so it outlives the
          resolve falling out of OPERATOR_RESOLVE_WINDOW_S — otherwise every
          child of a long-dead device opens at once seven days later.
        - a parent with no such state to re-read (`netpath_unreachable`):
          the child's breach run must have begun at or before the resolve,
          the same first_breach_ts <= resolved_ts test the threshold gate
          uses.

        Costs no query: the parent rule comes from _rules_by_key, the resolve
        from _operator_resolves, and the device read is memoised per tick in
        _parent_conditions, so N children of one dead device ask once.
        """
        parent_key = ROLLED_UP_BY.get(rule["key"] or "")
        if not parent_key or occurrence.entity_kind not in ROLLUP_ENTITY_KINDS:
            return False
        parent_rule = self._rules_by_key.get(parent_key)
        if parent_rule is None:
            # Absent from the per-tick map means disabled or gone, which is
            # what _rollup_parent's own enabled test means: a rule that is
            # not running cannot be suppressing anything.
            return False
        # An outage parent is a fact about the device, so a per-port child
        # asks about its switch; a same-metric pair is about the port itself
        # -- see _device_probe.
        probe = (occurrence if same_metric_pair(rule, parent_rule)
                 else self._device_probe(occurrence))
        if probe is None:
            return False
        parent_dedup = dedup_key(parent_rule, probe)
        resolved_ts = self._operator_resolves.get(parent_dedup)
        if parent_key == "device_down":
            # A cover this engine already established outlives the resolve's
            # seven-day window: the question "is this device still down"
            # answers itself from current state, and the answer does not
            # become less true with age.
            covered_since = self._parent_covers.get(parent_dedup)
            if resolved_ts is None and covered_since is None:
                return False
            if not self._parent_still_failing(probe):
                # The device answered. The cover is over — a child still
                # breaching on its own account opens on this very tick.
                self._parent_covers.pop(parent_dedup, None)
                return False
            if covered_since is None:
                self._parent_covers[parent_dedup] = resolved_ts or time.time()
                # One line, the first time a device's cover takes effect, so
                # the silence that follows has a trace somebody can find. In
                # NODES rather than ALERTS because the question it answers —
                # "why is this dead device not alerting?" — is asked from the
                # Nodes page, where the device is visibly down.
                self.log.add(NODES,
                            f"{occurrence.entity_label}: outage alert resolved "
                            f"by hand while the device is still down — the "
                            f"alerts that outage implies stay suppressed until "
                            f"it answers again",
                            target=occurrence.device_ip)
            return True
        if resolved_ts is None:
            return False
        first_breach_ts = self._child_first_breach_ts(rule, occurrence)
        return first_breach_ts is not None and first_breach_ts <= resolved_ts

    def _child_first_breach_ts(self, rule, occurrence: Occurrence):
        """When the breach run behind this threshold occurrence began, out of
        the streak state its evaluator already keeps, or None for an
        occurrence that is an event rather than a run.

        Looked up by (rule, entity id) alone -- _evaluate_thresholds's own
        streak key -- since that's all a rollup parent's resolve gives us
        here. The entity id is used as the string it already is, never
        int()-ed: a per-port threshold's is "7:12", and coercing it would
        make the two halves of this contract silently stop agreeing.
        """
        if occurrence.kind == "threshold":
            entry = self._breach_streaks.get(
                (rule["id"], str(occurrence.entity_id)))
        elif occurrence.kind == "netpath_threshold":
            entry = self._netpath_streaks.get((rule["id"], str(occurrence.entity_id)))
        elif occurrence.kind == "dhcp_threshold":
            entry = self._dhcp_streaks.get((rule["id"], str(occurrence.entity_id)))
        else:
            return None
        return entry[2] if entry else None

    # --------------------------------------------- notification roll-up

    def _notify_rollup_delay(self, settings) -> float:
        """notify_rollup_delay_s, clamped to [0, NOTIFY_ROLLUP_DELAY_MAX_S].

        Read and sanity-checked at the point of use rather than validated on
        the way into the database, the same convention _hold_for_new_device
        and _sweep_renotify already use for new_device_grace_s and
        renotify_minutes. 0 (the default clamp on anything unparsable) means
        the hold is off — see every caller below, which treats <= 0 as
        "behave exactly as before this setting existed."
        """
        try:
            delay = float(settings.get("notify_rollup_delay_s", 240) or 0)
        except (TypeError, ValueError):
            delay = 0.0
        return max(0.0, min(delay, NOTIFY_ROLLUP_DELAY_MAX_S))

    def _skip_held_open_notify(self, alert_row, settings, reason: str) -> bool:
        """Close out an alert's still-pending FIRST notification without
        sending it, when the roll-up hold is what is pending it.

        True only when it actually acted — the hold is on
        (notify_rollup_delay_s > 0) AND nobody has attempted this alert's
        open notice yet (last_notified_ts IS NULL). Both must hold: at
        delay 0 this is a permanent no-op, which is what makes 0 an exact
        passthrough to the engine's pre-4.47 behaviour; and an alert whose
        open notice already went out (or was already decided some other
        way) must never be re-recorded here, or a second "not sent" row
        would sit next to a real notification.

        record_notification uses kind "alert": this decides the OPEN
        notice, whatever later closed the alert (a clear, an absorption, an
        expiry, a hand resolve) — it is not itself a clear notification.
        mark_notified stamps last_notified_ts so alerts_due_first_notify
        never asks about this alert again — see its own docstring on why
        that column, not an in-memory set, is what "due" means.
        """
        if self._notify_rollup_delay(settings) <= 0:
            return False
        if "last_notified_ts" not in alert_row.keys() \
                or alert_row["last_notified_ts"] is not None:
            return False
        self.db.record_notification(alert_row["id"], "alert", "", "", False, reason)
        self.db.mark_notified(alert_row["id"])
        return True

    def _occurrence_from_alert_row(self, alert_row, rule_row) -> Occurrence:
        """Rebuild the Occurrence an alert row was opened from, out of its
        own stored extras — for a caller with no fresh occurrence to hand
        _notify, _rollup_parent or _parent_operator_resolved: the renotify
        sweep, and the roll-up flush sweep below it, both need to ask
        questions an Occurrence answers about an alert that is not
        recurring right now.
        """
        try:
            extra = json.loads(alert_row["extra_json"] or "{}")
        except (TypeError, ValueError):
            extra = {}
        return Occurrence(
            kind=rule_row["kind"], source_kind=rule_row["source_kind"] or "",
            entity_kind=alert_row["entity_kind"], entity_id=alert_row["entity_id"],
            entity_label=alert_row["entity_label"], ts=alert_row["last_ts"],
            message=alert_row["message"], detail=alert_row["detail"] or "",
            extra=extra if isinstance(extra, dict) else {})

    def _absorb_subordinates(self, parent_rule, occurrence: Occurrence,
                             parent_row, settings) -> None:
        """Resolve the alerts a just-opened parent makes redundant.

        Resolved rather than left open, because an operator working the list
        should see one row for one outage — and the recovery path puts them
        back on their own: device_up resolves device_down through CLEARS, and
        _evaluate_thresholds re-derives every threshold from live metrics on
        the very next tick, so a metric that is genuinely still breaching
        re-opens without anything having to un-suppress it.

        That re-derivation covers every threshold child but not the
        event-driven poll_overrun, which has no CLEARS pair; absorbing it is
        still right, since the next overrun after recovery opens a fresh
        alert from its own event.

        Deliberately silent: no clear email for an absorbed alert. "Packet
        loss recovered" while the device is still down would be a lie.

        resolved_by is '' here, not "rolled up into <parent>": that line goes
        on the PARENT's rollup_note. Writing it onto the child would make an
        automatic rollup indistinguishable from a hand resolve to
        operator_resolved_since, and a still-breaching child must be free to
        re-open on the next tick's re-derivation.

        A child absorbed here may have opened moments ago with its first
        email still held (see _sweep_notify_rollup); that email must never go
        out, so it is closed out here rather than left to the flush sweep.
        """
        for child_key in ROLLS_UP.get(parent_rule["key"] or "", ()):
            child_rule = self.db.rule_by_key(child_key)
            if child_rule is None:
                continue
            for resolved in self._absorb_one(child_rule, occurrence,
                                             parent_row["id"]):
                self.counters["resolved"] += 1
                self.db.add_rollup_note(
                    parent_row["id"],
                    f"Resolved “{child_rule['name']}” — implied by this outage")
                self._skip_held_open_notify(
                    resolved, settings,
                    f"not sent: rolled up under “{parent_row['entity_label']}”")
        if (parent_rule["key"] or "") == "device_down" \
                and occurrence.entity_kind == "device":
            self._absorb_downstream(parent_rule, occurrence, parent_row, settings)

    def _absorb_one(self, child_rule, occurrence: Occurrence,
                    parent_id: int | None) -> list:
        """Every open alert of `child_rule` that `occurrence`'s outage
        absorbs: the entity's own, plus -- for a device -- each of its
        ports', since a dead switch's ports report nothing exactly because
        the switch does not.

        Two lookups, not one range over both: the device's own key is an
        exact match, and a range wide enough to cover it would also cover a
        device id that merely starts with the same digits.
        """
        rows = []
        resolved = self.db.resolve_by_dedup(
            dedup_key(child_rule, occurrence), by="", rolled_up_into=parent_id)
        if resolved:
            rows.append(resolved)
        if occurrence.entity_kind == "device":
            rows += self.db.resolve_by_dedup_prefix(
                f"{child_rule['key']}:interface:{occurrence.entity_id}:",
                by="", rolled_up_into=parent_id)
        return rows

    def _absorb_downstream(self, rule, occurrence: Occurrence, parent_row,
                           settings) -> None:
        """Resolve the outages of everything behind a device that just went
        down, when their alerts opened before this one did.

        _rollup_parent covers the other order — a downstream outage noticed
        after the upstream one is suppressed before it opens. Both orders
        happen: a power event takes the whole site at once and which device
        the poller reaches first is arbitrary. This is exactly the order the
        review's 499-device outage hit: 377 device-down alerts opened, each
        with its own first email held, before the core's own alert caught up
        and absorbed them here.

        Silent, like every other absorption: no clear email for an alert that
        was never a separate problem. If the upstream comes back and a
        downstream device is still down, _replay_downstream_outages re-raises
        it — a device the engine has stopped alerting about must not stay
        silent once the excuse for the silence is gone.
        """
        ids_of = getattr(self.nodes_db, "downstream_ids", None)
        if ids_of is None:
            return
        try:
            device_id = int(occurrence.entity_id)
        except (TypeError, ValueError):
            return
        for child_id in ids_of(device_id):
            resolved = self.db.resolve_by_dedup(
                f"{rule['key']}:device:{child_id}", by="",
                rolled_up_into=parent_row["id"])
            if resolved:
                self.counters["resolved"] += 1
                self.db.add_rollup_note(
                    parent_row["id"],
                    f"Resolved “{resolved['entity_label']}” — implied by the "
                    f"upstream outage of {occurrence.entity_label}")
                self._skip_held_open_notify(
                    resolved, settings,
                    f"not sent: rolled up under “{parent_row['entity_label']}”")
                # resolved['device_down'] alert is gone, but that downstream
                # device's OWN packet_loss_high/cpu_high/etc never get an
                # is_new occurrence of their own to trigger _absorb_subordinates
                # from - THIS device's device_down alert is what they roll up
                # under, and it just proved it will never open one. Without
                # this, a downstream device with (say) a packet_loss_high alert
                # already open when the site outage reached it stayed on the
                # Alerts page for the rest of the outage, fully covered in
                # every way except this one.
                self._absorb_children_of(
                    resolved["entity_id"], resolved["entity_label"],
                    occurrence.ts, parent_row["id"], settings)

    def _absorb_children_of(self, device_id, device_label: str, ts: float,
                            note_alert_id: int | None, settings) -> None:
        """Resolve `device_id`'s own already-open ROLLED_UP_BY children under
        "device_down" - packet_loss_high, cpu_high, and the rest.

        Exists for the two places a device's OWN device_down alert never
        opens a row, so _absorb_subordinates' is_new branch never runs for
        it: a downstream device _absorb_downstream just resolved, and a
        device whose "down" event arrives after an ancestor's alert is
        already open. In both, whatever the device had already opened on its
        own account has nothing left to trigger its absorption.

        Bounded like _absorb_subordinates: one indexed resolve_by_dedup per
        name in ROLLS_UP["device_down"] (about a dozen keys), never a scan.

        note_alert_id names the alert an operator would find the note on —
        the ancestor's, where the outage has one open; None for the
        operator-resolved-but-still-down cover, which has no open row (see
        _ROLLUP_NO_ROW_REASON). Doubles as resolve_by_dedup's
        rolled_up_into, since the alert a screen folds a child under is the
        alert the note is on.
        """
        probe = Occurrence(kind="device_event", source_kind="down",
                           entity_kind="device", entity_id=device_id,
                           entity_label=device_label, ts=ts, message="")
        for child_key in ROLLS_UP.get("device_down", ()):
            child_rule = self.db.rule_by_key(child_key)
            if child_rule is None:
                continue
            for resolved in self._absorb_one(child_rule, probe, note_alert_id):
                self.counters["resolved"] += 1
                if note_alert_id is not None:
                    self.db.add_rollup_note(
                        note_alert_id,
                        f"Resolved “{child_rule['name']}” — implied by the "
                        f"outage covering {device_label}")
                    self._skip_held_open_notify(
                        resolved, settings,
                        f"not sent: rolled up under an outage covering {device_label}")
                else:
                    self._skip_held_open_notify(
                        resolved, settings, self._ROLLUP_NO_ROW_REASON)

    def _apply(self, rules, occurrence: Occurrence, settings) -> None:
        rollup = bool(settings.get("rollup_enabled", True))
        for rule in rules:
            if rule["kind"] != occurrence.kind:
                continue
            # A rule's source_kind, when set, is which event/metric it is
            # about; an occurrence that is about something else is not this
            # rule's business. "threshold" belongs on this list and used to be
            # missing, which meant a single CPU breach opened all eleven
            # threshold alerts for that device — every one of them carrying
            # the CPU occurrence's message.
            #
            # syslog and ipam are deliberately absent: their occurrences
            # always carry source_kind "", so filtering on it would silently
            # stop matching any custom rule that has one set.
            if rule["kind"] in ("device_event", "interface_event", "trap",
                                "wireless_event", "threshold", "dhcp_threshold",
                                "netpath_threshold", "system"):
                if (rule["source_kind"] or "") and rule["source_kind"] != occurrence.source_kind:
                    continue
            if rule["kind"] == "threshold" and occurrence.rule_key:
                # Two threshold rules CAN legitimately share a source_kind —
                # ups_battery_low/ups_battery_replace already did, and
                # temp_chassis_high/temp_chassis_critical now read the same
                # temp_chassis_c metric on purpose (see alertsdb._BUILTIN_
                # RULES). Without this, the occurrence _evaluate_thresholds
                # built for evaluating ONE of them also matched the OTHER
                # here (same kind, same source_kind), double-incrementing it
                # with the wrong rule's message and defeating the streak
                # accounting evaluate_threshold just did for its own rule.
                # occurrence.rule_key pins an occurrence to the one rule that
                # actually raised it; empty (every occurrence not from
                # _evaluate_thresholds, and one parked before this field
                # existed) leaves matching exactly as it was.
                if rule["key"] != occurrence.rule_key:
                    continue
            if (rule["kind"] in ("syslog", "trap")
                    and not (rule["source_kind"] or "")
                    and occurrence.severity is not None):
                # Lower number = more severe (RFC 5424): the rule's own
                # severity is the threshold it fires at — "this severity
                # and worse" — not just a label stamped on the resulting
                # alert. Traps were exempt, so "Critical SNMP trap received"
                # opened at severity 2 for fifty informational config-save
                # traps.
                #
                # Only for a rule with NO source_kind, i.e. one that is about
                # every trap or every message. A rule naming one trap already
                # says exactly which fact it is about, and the shipped
                # coldStart rule (severity 4) would otherwise never fire: a
                # trap with no severity mapping decodes as 5, which is worse
                # than 4 on this scale.
                if occurrence.severity > rule["severity"]:
                    continue
            if (rule["key"] or "") in UNMANAGED_ONLY_RULES and occurrence.managed:
                # "Link-down trap from an unmanaged device" has advertised
                # this check since it shipped and never performed it, so a
                # managed switch's port flap raised three alerts: this one,
                # trap_critical, and interface_down from polling.
                continue
            if not match_device(rule, occurrence):
                continue
            key = dedup_key(rule, occurrence)
            if rollup:
                parent = self._rollup_parent(rule, occurrence)
                if parent is SUPPRESSED:
                    # Implied by an outage with no open row to annotate: the
                    # parent was hand-resolved while the device is still
                    # down, or the upstream's own alert has been worked.
                    self.counters["rolled_up"] += 1
                    if (rule["key"] or "") == "device_down":
                        # This occurrence IS a device_down: this device's
                        # own outage alert will never open one of its own
                        # either, so nothing else ever sweeps its OTHER
                        # already-open children — see _absorb_children_of.
                        self._absorb_children_of(
                            occurrence.entity_id, occurrence.entity_label,
                            occurrence.ts, None, settings)
                    continue
                if parent is not None:
                    # Not opened at all, so no email and no row to work. The
                    # parent says where it went, so the latency alert an
                    # operator expected to see is accounted for rather than
                    # just missing.
                    self.counters["rolled_up"] += 1
                    self.db.add_rollup_note(
                        parent["id"],
                        f"Suppressed “{rule['name']}” — implied by this outage")
                    if (rule["key"] or "") == "device_down":
                        self._absorb_children_of(
                            occurrence.entity_id, occurrence.entity_label,
                            occurrence.ts, parent["id"], settings)
                    continue
                if self._parent_operator_resolved(rule, occurrence):
                    # The parent was resolved by hand while its condition
                    # still holds, so this child is still implied by it and
                    # still suppressed — see _parent_operator_resolved. Only
                    # counted, not noted: there is no open parent row to
                    # write a rollup note onto, and the resolved one is
                    # finished work an operator should not see growing.
                    self.counters["rolled_up"] += 1
                    continue
            row, is_new = self.db.open_or_increment(
                rule["id"], key, occurrence.entity_kind, occurrence.entity_id,
                occurrence.entity_label, rule["severity"], occurrence.message,
                occurrence.detail, occurrence.ts, extra=occurrence.extra)
            if is_new:
                self.counters["opened"] += 1
                if rollup and (rule["key"] or "") in ROLLS_UP:
                    self._absorb_subordinates(rule, occurrence, row, settings)
                # notify_rollup_delay_s > 0 holds this alert's first email
                # rather than sending it here: _sweep_notify_rollup picks it
                # up, once it is old enough, from last_notified_ts being
                # still NULL on the row _apply just inserted — no in-memory
                # queue to lose on a restart, no branch here beyond the one
                # skipped call. At 0 (the exact behaviour this replaces)
                # _notify runs right here, exactly as it always has.
                if self._notify_rollup_delay(settings) <= 0:
                    self._notify(row, rule, occurrence, settings)
            # Renotify is NOT decided here any more. It used to compare
            # against row["last_ts"], which open_or_increment had just set to
            # this occurrence's timestamp a statement earlier, so the
            # difference was always about zero and the condition could not be
            # satisfied for any renotify_minutes above five seconds. Worse,
            # this path is only reached when a NEW occurrence arrives, and an
            # event-driven rule (a device that stays down, a trap) produces
            # exactly one. _sweep_renotify sweeps open alerts instead.

    # ------------------------------------------------------------- expiry

    def _sweep_expired(self, settings) -> None:
        """Close alerts whose rule gives them a lifetime that has run out.

        No clear email: a rule with an auto-resolve interval reports
        something that already finished happening, and "resolved: device
        rebooted" a day later tells an operator nothing they can act on. The
        alert leaves the open list, which is the whole point — an open count
        that includes yesterday's recoveries is a count nobody trusts.

        resolved_by is '' like every other engine auto-resolve, so an expired
        alert never suppresses a genuine new breach run later.
        """
        for row in self.db.expired_alerts(time.time()):
            self.db.resolve(row["id"], by="")
            self.counters["resolved"] += 1
            # An expiring alert whose own open notice was still held closes
            # that out too, with its own reason — the roll-up flush sweep
            # would otherwise have to guess why a "resolved" row it never
            # decided about got that way.
            self._skip_held_open_notify(
                row, settings,
                "not sent: alert auto-resolved within the roll-up window")

    # ------------------------------------------------------------ renotify

    def _sweep_renotify(self, settings) -> None:
        """Tell the operator again about alerts still open and unacknowledged.

        A sweep over open alerts rather than a branch on the occurrence path,
        because most alerts worth re-notifying about produce no further
        occurrences at all: a device that stays down records one `down`
        event, a trap arrives once, an IPAM conflict is detected once. An
        admin who sets "re-notify every 30 minutes" for an unattended
        overnight shift means "keep telling me until somebody deals with it",
        and the occurrence path could only ever have honoured that for
        threshold rules.

        The occurrence handed to _notify is rebuilt from the alert row, with
        its stored extras, so a threshold renotify still renders {{value}}
        and a trap renotify still renders {{trap_name}}.
        """
        minutes = float(settings.get("renotify_minutes", 0) or 0)
        if minutes <= 0:
            return
        # Minus one tick, so an alert due at exactly N minutes is not
        # deferred to the following tick every single time.
        cutoff = time.time() - (minutes * 60 - TICK_S)
        delay = self._notify_rollup_delay(settings)
        for row in self.db.alerts_due_renotify(cutoff):
            if delay > 0 and row["last_notified_ts"] is None:
                # Its own FIRST notice is still held for roll-up coalescing
                # (or was skipped and left pending on a mute — see
                # _sweep_notify_rollup) — COALESCE(last_notified_ts,
                # opened_ts) in alerts_due_renotify's own query still makes
                # this row "due" from opened_ts alone, same as an alert that
                # opened while email was off always has. Renotifying about
                # something the operator has not been told about yet would
                # announce it twice: once as a "reminder" before the actual
                # notice ever went out.
                continue
            rule = self.db.rule(row["rule_id"])
            if rule is None or not rule["enabled"]:
                continue
            occurrence = self._occurrence_from_alert_row(row, rule)
            self._notify(row, rule, occurrence, settings, renotify=True)

    # -------------------------------------------------------------- notify

    def _notify(self, alert_row, rule_row, occurrence: Occurrence, settings,
               renotify: bool = False, notify_kind: str | None = None,
               template_override=None) -> None:
        # A system rule is about the application's own health, and today the
        # only one is "email is not being delivered". Mailing about that
        # would be either impossible or a loop, so system alerts live on the
        # Alerts page and nowhere else.
        if rule_row["kind"] == "system":
            return
        # A rule can be worth recording and not worth mailing about. The
        # alert still opens, is still listed, is still counted — only the
        # inbox is spared. Guarded on the column's presence so an engine
        # against a database that predates it keeps notifying, which is the
        # behaviour every rule had before.
        if "notify" in rule_row.keys() and not rule_row["notify"]:
            return
        # The webhook channel's own decision, entirely independent of
        # email's below it: its own enabled flag, its own URL, its own
        # hourly budget (webhook_max_per_hour) and its own queue, so an
        # operator can run one channel with the other off. Reached from
        # every caller of _notify — a fresh alert's own notice, a renotify,
        # a clear (through _notify_clear's template_override) and a small
        # roll-up flush's per-alert release — which is every decision point
        # except the digest, which has no single alert row; see
        # _send_digest's own webhook call.
        self._webhook_notify(alert_row, rule_row, occurrence, settings,
                             notify_kind or ("renotify" if renotify else "alert"),
                             template_override)
        # The email severity floor, deliberately below the webhook dispatch
        # above: a chat room or ticket queue has its own enabled flag and
        # budget and must keep getting everything.
        #
        # mark_notified, not a bare return: alerts_due_first_notify reads a
        # NULL last_notified_ts as "still due", so a floored alert left
        # unstamped would come back through _sweep_notify_rollup forever.
        floor = int(settings.get("notify_min_severity", 7) or 0)
        if alert_row["severity"] > floor:
            self.db.mark_notified(alert_row["id"])
            return
        now = time.time()
        hour_ago = now - 3600
        self._sent_this_hour = [ts for ts in self._sent_this_hour if ts >= hour_ago]
        max_per_hour = int(settings.get("max_emails_per_hour", 60))
        current_hour = int(now // 3600)
        if max_per_hour and len(self._sent_this_hour) >= max_per_hour:
            self.counters["suppressed"] += 1
            # A row per suppressed send, not just a global counter. In the
            # review's 500-device outage, 60 alerts were emailed and 440 were
            # dropped with no record on the alert at all: the only trace was
            # this counter and one ERROR line an hour in a 3,000-entry
            # in-memory ring that the poller overwrites in about ninety
            # seconds. An operator asking "were we told about site 14" could
            # not be answered. Now the alert's own detail pane says nobody
            # was told, and why.
            self.db.record_notification(
                alert_row["id"], notify_kind or ("renotify" if renotify else "alert"),
                "", "", False,
                f"not sent: over the {max_per_hour}/hour email limit")
            if self._suppression_logged_hour != current_hour:
                self._suppression_logged_hour = current_hour
                self.log.add(ERROR, f"Alert email volume over {max_per_hour}/hour — "
                                    f"suppressing further sends for the rest of this hour")
            return

        if not settings.get("email_enabled") or not settings.get("smtp_host"):
            return

        if template_override is not None:
            template = template_override
        else:
            template = (self.db.template(rule_row["template_id"])
                       if rule_row["template_id"] else None)
        if template is None:
            return
        # alerts.entity_id is the device's stable database id, not its IP
        # (so an IP change later doesn't orphan the dedup key) — the
        # {{device_ip}} token needs the real address looked up fresh,
        # rather than defaulting to entity_id the way build_context()'s
        # bare device_name/device_ip fallback would.
        extra = dict(occurrence.extra)
        device_ip = self._device_ip_for(alert_row)
        if device_ip:
            extra["device_ip"] = device_ip
        context = alertmail.build_context(alert_row, rule_row, extra=extra)
        subject = alertmail.render(template["subject"], context)
        body = alertmail.render(template["body"], context)

        # Stored as a list since the recipients-list UI shipped; a plain
        # comma-separated string is still handled here so a deployment
        # upgrading from before that change doesn't lose its setting on
        # the first tick after upgrade, before it's ever re-saved.
        raw_to = settings.get("smtp_to_default", [])
        if isinstance(raw_to, str):
            to_addrs = [a.strip() for a in raw_to.split(",") if a.strip()]
        else:
            to_addrs = [str(a).strip() for a in raw_to if str(a).strip()]
        if not to_addrs:
            return

        password = None
        if self.app_db is not None:
            blob = self.db.smtp_password_enc()
            if blob:
                try:
                    from . import dpapi
                    password = dpapi.unprotect(blob).decode("utf-8")
                except Exception:
                    password = None

        kind = notify_kind or ("renotify" if renotify else "alert")
        job = alertmail.MailJob(
            settings=dict(settings), password=password, to_addrs=list(to_addrs),
            subject=subject, body=body, is_html=bool(template["is_html"]),
            alert_id=alert_row["id"], kind=kind)
        password = None
        # The quota counts ATTEMPTS, not successes. Appending only on success
        # meant a dead relay consumed no quota at all: 500 alerts produced 500
        # attempts, none of which the hourly cap stopped, and each paid the
        # full SMTP timeout. An attempt is what costs time, so an attempt is
        # what is rationed.
        self._sent_this_hour.append(now)
        # Stamped on submit even when the queue refuses below: the renotify
        # clock measures "how long since we last tried to tell anyone", and
        # re-trying a full queue every tick would only fill it faster.
        self.db.mark_notified(alert_row["id"], now)
        if not self._mail.submit(job):
            # Bounded on purpose; a refusal is recorded against the alert so
            # the drop shows in its own detail pane rather than only in a
            # global counter.
            self.counters["send_errors"] += 1
            self.db.record_notification(alert_row["id"], kind, ", ".join(to_addrs),
                                        subject, False, "send queue full")

    def _webhook_notify(self, alert_row, rule_row, occurrence: Occurrence,
                        settings, kind: str, template_override=None) -> None:
        """One JSON POST for one alert, at exactly the point _notify reached
        for email — see the call site's own comment for which decision
        points that covers. `kind` is _notify's own "alert"/"renotify"/
        "clear" vocabulary; the JSON payload's "state" field says "open"
        for "alert", matching what the rest of this application calls a
        freshly-opened alert (alerts.state itself is 'open', not 'alert').

        Deliberately does not require a template: email returns with
        nothing sent when a rule has no template_id, because there is no
        body to render, but a webhook's JSON body is fixed shape (see the
        schema comment above WebhookQueue) and does not need one — only the
        one line rendered FROM a template (the subject) is optional, and
        falls back to the rule's own name when there is none.
        """
        if not settings.get("webhook_enabled"):
            return
        url = str(settings.get("webhook_url") or "").strip()
        if not url:
            return
        now = time.time()
        hour_ago = now - 3600
        self._webhook_sent_this_hour = [
            ts for ts in self._webhook_sent_this_hour if ts >= hour_ago]
        max_per_hour = int(settings.get("webhook_max_per_hour", 600) or 0)
        current_hour = int(now // 3600)
        webhook_kind = f"webhook_{kind}"
        if max_per_hour and len(self._webhook_sent_this_hour) >= max_per_hour:
            self.counters["webhook_suppressed"] += 1
            self.db.record_notification(
                alert_row["id"], webhook_kind, url, "", False,
                f"not sent: over the {max_per_hour}/hour webhook limit")
            if self._webhook_suppression_logged_hour != current_hour:
                self._webhook_suppression_logged_hour = current_hour
                self.log.add(ERROR, f"Alert webhook volume over {max_per_hour}/hour"
                                    f" — suppressing further sends for the rest of"
                                    f" this hour")
            return
        if template_override is not None:
            template = template_override
        else:
            template = (self.db.template(rule_row["template_id"])
                       if rule_row["template_id"] else None)
        extra = dict(occurrence.extra)
        device_ip = self._device_ip_for(alert_row)
        if device_ip:
            extra["device_ip"] = device_ip
        context = alertmail.build_context(alert_row, rule_row, extra=extra)
        subject = (alertmail.render(template["subject"], context)
                  if template is not None else (rule_row["name"] or ""))
        payload = {
            "alert_id": alert_row["id"],
            "rule": rule_row["key"] or "",
            "rule_name": rule_row["name"],
            "kind": rule_row["kind"],
            "entity_label": alert_row["entity_label"],
            "message": alert_row["message"],
            "detail": alert_row["detail"] or "",
            "ts": now,
            "state": "open" if kind == "alert" else kind,
            "subject": subject,
        }
        self._webhook_sent_this_hour.append(now)
        job = alertmail.WebhookJob(
            url=url, headers=alertmail.parse_headers(settings.get("webhook_headers", [])),
            timeout=float(settings.get("webhook_timeout_s", 10.0) or 10.0),
            payload=payload, subject=subject, alert_id=alert_row["id"],
            kind=webhook_kind)
        if not self._webhook.submit(job):
            self.counters["webhook_errors"] += 1
            self.db.record_notification(alert_row["id"], webhook_kind, url,
                                        subject, False, "send queue full")

    def _device_ip_for(self, alert_row) -> str:
        """Best-effort recovery of the real device address for the
        {{device_ip}} token. alerts.entity_id is a device-kind alert's
        stable database id ("7") or an interface-kind alert's
        "device_id:if_index" pair — never the address itself, so a
        device's IP changing later never orphans its dedup key. Looked up
        fresh at send time (not carried on the Occurrence) so it stays
        correct even if the IP changed between when the alert opened and
        when it is later notified about or resolved."""
        try:
            if alert_row["entity_kind"] == "device":
                device_id = int(alert_row["entity_id"])
            elif alert_row["entity_kind"] == "interface":
                device_id = int(str(alert_row["entity_id"]).split(":")[0])
            elif alert_row["entity_kind"] == "dhcp_scope":
                # "<server_id>:<scope_id>"; the nearest real address is the
                # DHCP server's, which is what an operator would connect to.
                if self.ipam_db is None:
                    return ""
                server = self.ipam_db.dhcp_server(
                    int(str(alert_row["entity_id"]).split(":")[0]))
                return server["address"] if server else ""
            elif alert_row["entity_kind"] == "netpath_target":
                # A NetPath alert's entity_id is the destination's row id.
                # The address actually traced to is the useful one, since the
                # destination may have been entered as a hostname; the typed
                # host is the fallback when nothing has got through yet.
                if self.netpath_db is None:
                    return ""
                target_id = int(alert_row["entity_id"])
                target = self.netpath_db.target(target_id)
                return (self.netpath_db.destination_ip(target_id)
                        or (target["host"] if target else ""))
            elif alert_row["entity_kind"] == "ap":
                # An AP alert's entity_id is "controller_id:vdom:wtp_id";
                # the nearest meaningful address is the controller's own.
                # Without this branch the template's {{device_ip}} fell
                # back to the raw entity_id string.
                if self.wireless_db is None:
                    return ""
                controller = self.wireless_db.controller(
                    int(str(alert_row["entity_id"]).split(":")[0]))
                return controller["ip"] if controller else ""
            else:
                return ""
        except (TypeError, ValueError):
            return ""
        device = self.nodes_db.device(device_id)
        return device["ip"] if device else ""

    def _notify_clear(self, alert_row, rule_row, settings, extra=None) -> None:
        """Sends a resolution notification for an alert that the CLEARS
        map (or a threshold dropping back below clear_threshold) just
        auto-resolved. Gated by notify_on_clear so an admin who only
        wants to hear about problems, not their resolution, can turn it
        off — reuses _notify's own email_enabled/rate-limit/to_addrs
        plumbing rather than duplicating it, with a fixed 'clear'
        notification kind (the notifications table already reserves this
        value) and no renotify semantics.

        Deliberately renders the generic 'device_up' template rather than
        the cleared alert's own rule template: the cleared rule's own
        wording describes the original problem ("X stopped responding"),
        which would read backwards on a resolution email. 'device_up'
        doubles as the generic recovered template for interface_up and
        threshold clears too, per the same reasoning that shipped only 5
        built-in templates instead of one per rule."""
        if not settings.get("notify_on_clear", True):
            return
        # An alert whose own OPEN notice is still held (or was already
        # skipped for some other reason and left pending — see
        # _sweep_notify_rollup) must not get a "recovered" email either:
        # nobody was ever told there was a problem, so telling them it is
        # over is a message about nothing. A no-op at delay 0, same as every
        # other _skip_held_open_notify call — see its own docstring.
        if self._skip_held_open_notify(
                alert_row, settings,
                "not sent: cleared within the roll-up window"):
            return
        # A muted device sends no email at all, resolutions included. The
        # alert itself still resolves — the list stays truthful whatever the
        # mute says — but "muted" has to mean the operator's inbox goes
        # quiet, or the mute has silenced only half of what it promised.
        if self._muted_alert(alert_row):
            return
        template = self.db.template_by_key("device_up")
        if template is None:
            return
        occurrence = Occurrence(
            kind=rule_row["kind"], source_kind=rule_row["source_kind"] or "",
            entity_kind=alert_row["entity_kind"], entity_id=alert_row["entity_id"],
            entity_label=alert_row["entity_label"], ts=time.time(),
            message=f"Resolved: {alert_row['message']}",
            # Recovery timestamps and downtime are derived from the resolved
            # row by alertmail.build_context, so every clear carries them
            # whether or not its caller had anything better. A caller that
            # does — the device drain knows the exact poll the device answered
            # on — passes it here and it wins.
            extra=dict(extra or {}))
        self._notify(alert_row, rule_row, occurrence, settings,
                     notify_kind="clear", template_override=template)

    # ------------------------------------------------- roll-up flush sweep

    # The two _rollup_parent/_parent_operator_resolved answers that carry no
    # open row to name in a "rolled up under X" message — the outage's own
    # alert was resolved by hand while the condition it reports is still
    # true. Shared text rather than composed per call site, since both
    # branches below mean exactly the same thing to an operator reading the
    # notification history: this was implied by an outage somebody already
    # knows about and has worked.
    _ROLLUP_NO_ROW_REASON = ("not sent: rolled up under an outage whose own "
                             "alert was resolved by hand while it is still true")

    def _sweep_notify_rollup(self, settings) -> None:
        """Deliver (or finally give up on) the FIRST notification of every
        alert whose notify_rollup_delay_s hold has elapsed.

        Reads alerts_due_first_notify rather than keeping its own queue:
        the row IS the queue, so a restart mid-hold picks up where it left
        off. A no-op when the hold is off (delay <= 0), which is what makes
        0 an exact passthrough.

        Per due alert, in order:

        1. Already resolved. The two paths that resolve one on purpose stamp
           last_notified_ts themselves (see _skip_held_open_notify), so this
           branch means something else closed it — a hand resolve, most
           likely — and there is nothing more specific to say than that it
           cleared before its notice went out.
        2. Still covered by a rollup parent RIGHT NOW, asked with the exact
           predicate _apply asks before opening a fresh occurrence
           (_rollup_parent, then _parent_operator_resolved).
        3. Muted. Left pending rather than decided — a mute is temporary,
           and a device unmuted before anyone sees this should still get the
           notice. Mirrors _notify_clear's own mute check.
        4. Otherwise sendable, one at a time or as a digest — see
           DIGEST_THRESHOLD.

        The system-rule and notify-column guards _notify opens with are
        asked here first: a rule this engine will never mail must not sit
        "due" forever, re-asking every five seconds.
        """
        delay = self._notify_rollup_delay(settings)
        if delay <= 0:
            return
        due = self.db.alerts_due_first_notify(time.time() - delay)
        if not due:
            return
        rollup = bool(settings.get("rollup_enabled", True))
        floor = int(settings.get("notify_min_severity", 7) or 0)
        sendable = []
        for alert_row in due:
            rule_row = self.db.rule(alert_row["rule_id"])
            if rule_row is None or not rule_row["enabled"]:
                self.db.mark_notified(alert_row["id"])
                continue
            if rule_row["kind"] == "system" or (
                    "notify" in rule_row.keys() and not rule_row["notify"]):
                self.db.mark_notified(alert_row["id"])
                continue
            if alert_row["severity"] > floor:
                # Below the email floor. Asked here as well as in _notify
                # because this sweep is the one path that can hand an alert
                # to _send_digest instead, and because a "due" alert nothing
                # will ever mail must stop being due.
                self.db.mark_notified(alert_row["id"])
                continue
            if alert_row["state"] == "resolved":
                self._skip_held_open_notify(
                    alert_row, settings,
                    "not sent: cleared within the roll-up window")
                continue
            occurrence = self._occurrence_from_alert_row(alert_row, rule_row)
            if rollup:
                parent = self._rollup_parent(rule_row, occurrence)
                if parent is SUPPRESSED:
                    self._skip_held_open_notify(
                        alert_row, settings, self._ROLLUP_NO_ROW_REASON)
                    continue
                if parent is not None:
                    self._skip_held_open_notify(
                        alert_row, settings,
                        f"not sent: rolled up under “{parent['entity_label']}”")
                    continue
                if self._parent_operator_resolved(rule_row, occurrence):
                    self._skip_held_open_notify(
                        alert_row, settings, self._ROLLUP_NO_ROW_REASON)
                    continue
            if self._muted_alert(alert_row):
                continue
            sendable.append((alert_row, rule_row, occurrence))
        if not sendable:
            return
        if len(sendable) > DIGEST_THRESHOLD:
            self._send_digest(sendable, settings, delay)
        else:
            for alert_row, rule_row, occurrence in sendable:
                self._notify(alert_row, rule_row, occurrence, settings)
                # _notify only stamps last_notified_ts itself on its own
                # send-submitted path (the "attempt clock" comment on that
                # line) — every one of its OTHER returns (webhook delivered
                # but email is off or unconfigured, no template, no
                # recipients, or over max_emails_per_hour) leaves the row
                # NULL. Those are not "nothing happened" here: this alert
                # was DUE and this loop just released it, webhook included
                # (webhook fired unconditionally inside _notify above,
                # exactly once), so the attempt clock must tick regardless
                # of which of those branches _notify took, or
                # alerts_due_first_notify keeps handing the same alert back
                # every tick forever — a webhook re-sent every 5s on a
                # webhook-only install, or a fresh "not sent: over the
                # limit" row on every tick of an over-cap one. Mirrors the
                # guard-by-guard stamps _send_digest makes for the same
                # reason on the >DIGEST_THRESHOLD branch above; harmless to
                # call again here when _notify's own send-path already
                # stamped it a moment earlier.
                self.db.mark_notified(alert_row["id"])

    def _send_digest(self, sendable, settings, delay_s: float) -> None:
        """One email for every alert in `sendable`, counted once against
        max_emails_per_hour — the whole point of coalescing a mass outage's
        alerts is that it costs the budget one send, not one per alert.

        Not _notify with a batch template: every template is written for
        one alert's tokens and a digest has no single {{device_name}} to
        render, so the body is built directly rather than through
        alertmail.render.

        Guards mirror _notify's, in the same order — hourly budget, email
        configured, somebody to send to. Each guard that stops the send must
        still close out every alert's pending decision, or they sit "due"
        forever.
        """
        # The webhook channel's own digest, entirely independent of email's
        # below it — same reasoning as _notify's own webhook call.
        self._webhook_digest(sendable, settings, delay_s)
        # Defensive: _sweep_notify_rollup is the only caller and already
        # applied the floor, but a digest is the one place a batch of alerts
        # reaches the relay without passing through _notify's own guards.
        floor = int(settings.get("notify_min_severity", 7) or 0)
        for alert_row, _rule_row, _occurrence in sendable:
            if alert_row["severity"] > floor:
                self.db.mark_notified(alert_row["id"])
        sendable = [entry for entry in sendable
                    if entry[0]["severity"] <= floor]
        if not sendable:
            return
        now = time.time()
        hour_ago = now - 3600
        self._sent_this_hour = [ts for ts in self._sent_this_hour if ts >= hour_ago]
        max_per_hour = int(settings.get("max_emails_per_hour", 60))
        current_hour = int(now // 3600)
        if max_per_hour and len(self._sent_this_hour) >= max_per_hour:
            self.counters["suppressed"] += 1
            reason = f"not sent: over the {max_per_hour}/hour email limit"
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.record_notification(alert_row["id"], "alert", "", "",
                                            False, reason)
                self.db.mark_notified(alert_row["id"], now)
            if self._suppression_logged_hour != current_hour:
                self._suppression_logged_hour = current_hour
                self.log.add(ERROR, f"Alert email volume over {max_per_hour}/hour — "
                                    f"suppressing further sends for the rest of this hour")
            return
        if not settings.get("email_enabled") or not settings.get("smtp_host"):
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.mark_notified(alert_row["id"], now)
            return
        raw_to = settings.get("smtp_to_default", [])
        if isinstance(raw_to, str):
            to_addrs = [a.strip() for a in raw_to.split(",") if a.strip()]
        else:
            to_addrs = [str(a).strip() for a in raw_to if str(a).strip()]
        if not to_addrs:
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.mark_notified(alert_row["id"], now)
            return
        password = None
        if self.app_db is not None:
            blob = self.db.smtp_password_enc()
            if blob:
                try:
                    from . import dpapi
                    password = dpapi.unprotect(blob).decode("utf-8")
                except Exception:
                    password = None
        minutes = max(1, round(delay_s / 60.0))
        subject = (f"SappiWhere: {len(sendable)} alerts opened in the last "
                  f"{minutes} minute{'s' if minutes != 1 else ''}")
        lines = [f"{row['entity_label']}: {row['message']}"
                for row, _rule_row, _occurrence in sendable]
        body = ("\n\n".join(lines) +
               f"\n\nThese {len(sendable)} alerts have each occurred once so "
               f"far and are individually visible on the Alerts page.\n\n"
               f"-- SappiWhere")
        job = alertmail.MailJob(
            settings=dict(settings), password=password, to_addrs=list(to_addrs),
            subject=subject, body=body, is_html=False,
            alert_id=sendable[0][0]["id"], kind="alert",
            alert_ids=[row["id"] for row, _rule_row, _occurrence in sendable])
        password = None
        self._sent_this_hour.append(now)
        for alert_row, _rule_row, _occurrence in sendable:
            self.db.mark_notified(alert_row["id"], now)
        if not self._mail.submit(job):
            self.counters["send_errors"] += 1
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.record_notification(alert_row["id"], "alert",
                                            ", ".join(to_addrs), subject,
                                            False, "send queue full")

    def _webhook_digest(self, sendable, settings, delay_s: float) -> None:
        """One webhook delivery for every alert in `sendable`, mirroring
        _send_digest's own one-email-for-many shape and counted once
        against webhook_max_per_hour for the same reason. Unlike the email
        digest, the JSON body is not a bespoke plain-text format — it is the
        fixed schema's own "alerts" list (see the comment above
        WebhookQueue), so a receiver parses a digest exactly the way it
        parses a single notification, just with more rows.
        """
        if not settings.get("webhook_enabled"):
            return
        url = str(settings.get("webhook_url") or "").strip()
        if not url:
            return
        now = time.time()
        hour_ago = now - 3600
        self._webhook_sent_this_hour = [
            ts for ts in self._webhook_sent_this_hour if ts >= hour_ago]
        max_per_hour = int(settings.get("webhook_max_per_hour", 600) or 0)
        current_hour = int(now // 3600)
        if max_per_hour and len(self._webhook_sent_this_hour) >= max_per_hour:
            self.counters["webhook_suppressed"] += 1
            reason = f"not sent: over the {max_per_hour}/hour webhook limit"
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.record_notification(alert_row["id"], "webhook_digest",
                                            url, "", False, reason)
            if self._webhook_suppression_logged_hour != current_hour:
                self._webhook_suppression_logged_hour = current_hour
                self.log.add(ERROR, f"Alert webhook volume over {max_per_hour}/hour"
                                    f" — suppressing further sends for the rest of"
                                    f" this hour")
            return
        minutes = max(1, round(delay_s / 60.0))
        subject = (f"SappiWhere: {len(sendable)} alerts opened in the last "
                  f"{minutes} minute{'s' if minutes != 1 else ''}")
        alerts = [{"alert_id": row["id"], "rule": rule_row["key"] or "",
                   "rule_name": rule_row["name"], "entity_label": row["entity_label"],
                   "message": row["message"]}
                  for row, rule_row, _occurrence in sendable]
        first_row, first_rule, _occ = sendable[0]
        payload = {
            "alert_id": None, "rule": first_rule["key"] or "",
            "rule_name": first_rule["name"], "kind": first_rule["kind"],
            "entity_label": first_row["entity_label"], "message": first_row["message"],
            "detail": "", "ts": now, "state": "digest", "subject": subject,
            "alerts": alerts,
        }
        self._webhook_sent_this_hour.append(now)
        job = alertmail.WebhookJob(
            url=url, headers=alertmail.parse_headers(settings.get("webhook_headers", [])),
            timeout=float(settings.get("webhook_timeout_s", 10.0) or 10.0),
            payload=payload, subject=subject, kind="webhook_digest",
            alert_ids=[row["id"] for row, _rule_row, _occurrence in sendable])
        if not self._webhook.submit(job):
            self.counters["webhook_errors"] += 1
            for alert_row, _rule_row, _occurrence in sendable:
                self.db.record_notification(alert_row["id"], "webhook_digest",
                                            url, subject, False, "send queue full")

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
from . import hostresolve
from .alertrules import CLEARS, ROLLED_UP_BY, ROLLS_UP, ROLLUP_ENTITY_KINDS, \
    Occurrence, dedup_key, evaluate_flapping, evaluate_threshold, match_device
from .eventlog import ALERTS, ERROR, NullLog

TICK_S = 5.0

# How far back operator_resolved_since looks for a hand resolve. Long enough
# that an alert resolved Friday evening still stays closed Monday morning;
# short enough that the query stays cheap and a resolve from months ago
# cannot suppress an unrelated new breach run indefinitely. A cleared
# observation ends suppression well before this ever matters in practice —
# this is a backstop, not the mechanism.
OPERATOR_RESOLVE_WINDOW_S = 7 * 86400.0

# How much of a source backlog one tick will work through. A collector that
# has been storing while the engine was stopped (or a syslog burst) can leave
# hundreds of thousands of rows behind the cursor; draining all of them in one
# tick would hold the tick thread for minutes and starve every other source.
# The drains therefore page forward until one of these two budgets is spent,
# and whatever is left is reported as counters["backlog"] so an operator can
# see the engine is behind rather than guessing from a quiet Alerts page. The
# cursor still only advances over rows that were actually applied, so nothing
# is skipped — the next tick simply carries on from where this one stopped.
DRAIN_ROW_BUDGET = 5000
DRAIN_TIME_BUDGET_S = 2.0


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return f"{age / 3600:.1f}h ago"


class AlertEngine:
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
        self._thread: threading.Thread | None = None
        # (rule_id, device_id) -> (last sample ts, streak, first breach ts).
        # The sample ts is what makes the streak count polls rather than
        # ticks; the first breach ts is what lets for_seconds measure a
        # duration. See _evaluate_thresholds.
        self._breach_streaks: dict[tuple, tuple[float | None, int, float | None]] = {}
        # DHCP scopes keep (last polled_ts, streak) rather than a bare
        # count: the engine ticks every few seconds but DHCP is polled
        # every few minutes, so for_polls must count polls, not ticks.
        self._dhcp_streaks: dict[tuple, tuple[float | None, int]] = {}
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
                         "backlog": 0}
        self.error: str | None = None
        self._last_tick_ts: float = 0.0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self.stop()
        self._stop.clear()
        self._mail.start()
        self._thread = threading.Thread(target=self._loop, name="alert-engine", daemon=True)
        self._thread.start()

    def reconfigure(self, settings: dict) -> None:
        enabled = settings.get("enabled", True)
        if enabled and not self.running:
            self.start()
        elif not enabled and self.running:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        self._mail.stop()

    def shutdown(self) -> None:
        self.stop()

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return "Engine stopped"
        return f"Running · last tick {_ago(self._last_tick_ts)}"

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
        # _evaluate_thresholds and _evaluate_netpath_thresholds both consult
        # this cache to decide whether a breach is the same run an operator
        # already resolved by hand.
        self._operator_resolves = self.db.operator_resolved_since(
            time.time() - OPERATOR_RESOLVE_WINDOW_S)
        self._cursor_advances.clear()
        self._drain_rows = 0
        self._drain_deadline = time.monotonic() + DRAIN_TIME_BUDGET_S
        self.counters["backlog"] = 0
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
        occurrences += self._drain_pending()
        # Read once per tick rather than per occurrence, and usually empty —
        # when nothing is muted the gate below costs one dict truth test.
        muted = self.db.muted_entity_ids("device")
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
        self._sweep_renotify(settings)

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
        has its own RLock, so the notification row is safe to write here."""
        if ok:
            self.counters["emails_sent"] += 1
        else:
            self.counters["send_errors"] += 1
        self.db.record_notification(job.alert_id, job.kind,
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
        """Whether an existing alert's device is muted.

        Its own lookup rather than the per-tick dict, because the clear path
        runs inside the drains — before _tick reads that dict — and a clear
        is rare enough that one query costs nothing.
        """
        try:
            if alert_row["entity_kind"] == "device":
                device_id = str(int(alert_row["entity_id"]))
            elif alert_row["entity_kind"] == "interface":
                device_id = str(int(str(alert_row["entity_id"]).split(":")[0]))
            else:
                return False
        except (TypeError, ValueError):
            return False
        return self.db.mute_row("device", device_id) is not None

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
        try:
            if occurrence.entity_kind == "device":
                return self.nodes_db.device(int(occurrence.entity_id))
            if occurrence.entity_kind == "interface":
                # "<device_id>:<if_index>"
                return self.nodes_db.device(
                    int(str(occurrence.entity_id).split(":")[0]))
        except (TypeError, ValueError):
            return None
        return None

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
            device = self.nodes_db.device(row["device_id"])
            if device is None:
                continue
            label = hostresolve.resolve_name(
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
            if resolved:
                self.counters["resolved"] += 1
                self._notify_clear(resolved, cleared_rule, settings, extra=extra)
        if max_id > cursor:
            self._advance_cursor("device_events", max_id)
        return occurrences

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
            device_label = hostresolve.resolve_name(
                self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
            label = f"{device_label} / {interface['descr'] or interface['if_index']}"
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
            device_label = hostresolve.resolve_name(
                self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
            label = f"{device_label} / {interface['descr'] or interface['if_index']}"
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
        for row in self._read_forward("traps", self.snmp_db.traps_since,
                                      cursor, self.snmp_db.max_id):
            max_id = max(max_id, row["id"])
            occurrences.append(Occurrence(
                kind="trap", source_kind=row["trap_kind"] or "", entity_kind="trap",
                entity_id=row["trap_oid"] or "", entity_label=row["trap_name"] or row["trap_oid"] or row["source"],
                ts=row["ts"], message=row["varbind_text"] or "", device_ip=row["source"],
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
        for row in self._read_forward("syslog", self.syslog_db.rows_since,
                                      cursor, self.syslog_db.max_id):
            max_id = max(max_id, row["id"])
            if row["severity"] > min_severity:
                continue
            # Same "don't override a real self-reported host" rule as the
            # Syslog page's own Host column, so an alert opened from a
            # message shows the same name the Syslog page shows for it.
            if row["host"] and row["host"] != row["source"]:
                label = row["host"]
            else:
                label = hostresolve.resolve_name(
                    self.nodes_db, self.app_db, row["source"]) or row["source"]
            occurrences.append(Occurrence(
                kind="syslog", source_kind="", entity_kind="syslog",
                entity_id=row["source"], entity_label=label,
                ts=row["ts"], message=row["message"] or "", device_ip=row["source"],
                severity=row["severity"]))
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
            label = hostresolve.resolve_name(
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
        return occurrences

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
        """Device metrics against their threshold rules.

        The streak advances on a NEW SAMPLE, not on an engine tick. This
        engine ticks every five seconds; a device is polled every sixty by
        default, so counting ticks made `for_polls = 2` mean "ten seconds"
        and, worse, kept counting a value that had stopped changing — one
        bad sample satisfied any for_polls a few ticks later and went on
        satisfying it forever. metric["last_ts"] is what tells the two
        apart, exactly as _evaluate_dhcp_thresholds gates on polled_ts.

        The same state carries first_breach_ts, so a rule with for_seconds
        can ask how long the breach has actually lasted in sample time
        rather than in ticks.

        It also settles whether an operator resolved THIS breach run: if
        _operator_resolves (refreshed once per tick from
        AlertsDatabase.operator_resolved_since) has a hand resolve at or
        after first_breach_ts, the run stays closed rather than reopening as
        a new row — an operator resolving an alert while its condition still
        holds is exactly the case this streak is otherwise blind to, since
        open_or_increment only ever looks at open/acked rows. A clear
        observation resets first_breach_ts (above), so the very next breach
        is a new run and opens normally.

        This is in-memory state, so a restart forgets it: the first tick
        after restart rebuilds every streak from scratch, first_breach_ts
        becomes "since restart", and a still-breaching alert an operator had
        resolved re-opens once more. Deliberately not persisted — see
        INTERNALS.md.
        """
        occurrences = []
        rules = [r for r in self.db.rules() if r["enabled"] and r["kind"] == "threshold"]
        if not rules:
            return occurrences
        for device in self.nodes_db.devices():
            if not device["enabled"]:
                continue
            metrics_by_key = {m["key"]: m for m in self.nodes_db.metrics(device["id"])}
            for rule in rules:
                metric = metrics_by_key.get(rule["source_kind"])
                value = metric["last_value"] if metric else None
                sample_ts = metric["last_ts"] if metric else None
                streak_key = (rule["id"], device["id"])
                previous_ts, streak, first_breach_ts = self._breach_streaks.get(
                    streak_key, (None, 0, None))
                threshold = rule["threshold"]
                over = (value is not None and threshold is not None
                        and value >= threshold)
                if not over:
                    streak, first_breach_ts = 0, None
                elif sample_ts != previous_ts:
                    streak += 1
                    if first_breach_ts is None:
                        first_breach_ts = sample_ts
                self._breach_streaks[streak_key] = (sample_ts, streak, first_breach_ts)
                # Sample time, not wall-clock: a device that stopped being
                # polled must not accumulate breach seconds while silent.
                breach_seconds = (0.0 if first_breach_ts is None or sample_ts is None
                                  else max(0.0, sample_ts - first_breach_ts))
                result = evaluate_threshold(rule, value, streak, breach_seconds)
                label = hostresolve.resolve_name(
                    self.nodes_db, self.app_db, device["ip"], device=device) or device["ip"]
                if result == "breach":
                    occurrence = Occurrence(
                        kind="threshold", source_kind=rule["source_kind"],
                        entity_kind="device", entity_id=str(device["id"]),
                        entity_label=label, ts=time.time(),
                        message=f"{label}: {rule['name']} ({value})",
                        device_name=device["name"] or "", device_ip=device["ip"],
                        extra={"metric_label": metric["label"] if metric else rule["source_kind"],
                              "value": str(value), "threshold": str(rule["threshold"])})
                    resolved_ts = self._operator_resolves.get(dedup_key(rule, occurrence))
                    if (resolved_ts is not None and first_breach_ts is not None
                            and first_breach_ts <= resolved_ts):
                        # An operator resolved this exact breach run by hand;
                        # it stays closed until a clear observation (which
                        # resets first_breach_ts above) is followed by a new
                        # breach — see AlertsDatabase.operator_resolved_since.
                        continue
                    occurrences.append(occurrence)
                elif result == "clear":
                    dedup = dedup_key(rule, Occurrence(
                        kind="threshold", source_kind=rule["source_kind"],
                        entity_kind="device", entity_id=str(device["id"]),
                        entity_label=label, ts=time.time(), message=""))
                    resolved = self.db.resolve_by_dedup(dedup, by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, rule, settings)
        return occurrences

    def _evaluate_dhcp_thresholds(self, settings) -> list[Occurrence]:
        """DHCP scope utilization, evaluated the same way as a device
        threshold but against IPAM rather than Nodes.

        This cannot reuse _evaluate_thresholds: that one iterates
        nodes_db.devices(), reads values out of the Nodes metrics table and
        stamps entity_kind="device". A DHCP scope is none of those, so it
        gets its own evaluator and its own rule kind.

        Utilization is (leased + reserved) / range size, computed exactly
        the way the DHCP page computes it (api.get_ipam_dhcp_scopes), so
        the number in an alert is the number on screen.

        The streak subtlety: for_polls is documented as "N consecutive
        polls", and everywhere else in this engine a poll is a Nodes poll.
        DHCP is polled every 15 minutes while this engine ticks every 5
        seconds, so counting ticks would make for_polls=2 mean "10 seconds"
        rather than "two polls". The streak therefore only advances when a
        scope's polled_ts actually moves.
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
                previous_ts, streak = self._dhcp_streaks.get(streak_key, (None, 0))
                polled_ts = scope["polled_ts"]
                threshold = rule["threshold"]
                over = threshold is not None and value >= threshold
                if not over:
                    streak = 0
                elif polled_ts != previous_ts:
                    streak += 1
                self._dhcp_streaks[streak_key] = (polled_ts, streak)

                result = evaluate_threshold(rule, value, streak)
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
                    streak, first_breach_ts = 0, None
                elif sample_ts != previous_ts:
                    streak += 1
                    if first_breach_ts is None:
                        first_breach_ts = sample_ts
                self._netpath_streaks[streak_key] = (sample_ts, streak, first_breach_ts)

                result = evaluate_threshold(rule, value, streak)
                occurrence = Occurrence(
                    kind="netpath_threshold", source_kind=source,
                    entity_kind="netpath_target", entity_id=entity_id,
                    entity_label=label, ts=time.time(), message=message,
                    device_name=label, device_ip=target["host"],
                    extra={**extra, "threshold": str(threshold)})
                if result == "breach":
                    resolved_ts = self._operator_resolves.get(dedup_key(rule, occurrence))
                    if (resolved_ts is not None and first_breach_ts is not None
                            and first_breach_ts <= resolved_ts):
                        # Same breach run an operator already resolved by
                        # hand; see the matching check in
                        # _evaluate_thresholds.
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

    # ---------------------------------------------------------------- apply

    # ------------------------------------------------------------- rollup

    def _rollup_parent(self, rule, occurrence: Occurrence):
        """The open alert that already says what `rule` is about to say, or
        None. See alertrules.ROLLED_UP_BY for which rules have a parent."""
        parent_key = ROLLED_UP_BY.get(rule["key"] or "")
        if not parent_key or occurrence.entity_kind not in ROLLUP_ENTITY_KINDS:
            return None
        parent_rule = self.db.rule_by_key(parent_key)
        if parent_rule is None or not parent_rule["enabled"]:
            return None
        return self.db.open_by_dedup(dedup_key(parent_rule, occurrence))

    def _absorb_subordinates(self, parent_rule, occurrence: Occurrence,
                             parent_row) -> None:
        """Resolve the alerts a just-opened parent makes redundant.

        Resolved rather than left open, because an operator working the list
        should see one row for one outage — and the recovery path puts them
        back on their own: device_up resolves device_down through CLEARS, and
        _evaluate_thresholds re-derives every threshold from live metrics on
        the very next tick, so a metric that is genuinely still breaching
        re-opens without anything having to un-suppress it.

        That re-derivation covers every threshold child, but not the
        event-driven one: poll_overrun is a momentary event with no CLEARS
        pair, so nothing re-opens it from state. Absorbing it is still
        right — the next overrun after the device recovers records its own
        event and opens a fresh alert — but the mechanism is a new event,
        not a re-derivation.

        Deliberately silent: no clear email goes out for an absorbed alert.
        Fewer emails for one outage is the whole point, and "packet loss
        recovered" while the device is still down would be a lie.

        resolved_by is '' here, not a "rolled up into <parent>" string: that
        line is recorded on the PARENT's rollup_note instead (below), which
        is where an operator looking at the outage would read it. Writing it
        onto the child's own resolved_by would make an automatic rollup look
        exactly like a hand resolve to operator_resolved_since, and once the
        device recovers a still-breaching child threshold has to be free to
        re-open on the very next tick's re-derivation, not stay suppressed as
        though someone had resolved that breach run themselves.
        """
        for child_key in ROLLS_UP.get(parent_rule["key"] or "", ()):
            child_rule = self.db.rule_by_key(child_key)
            if child_rule is None:
                continue
            resolved = self.db.resolve_by_dedup(
                dedup_key(child_rule, occurrence), by="")
            if resolved:
                self.counters["resolved"] += 1
                self.db.add_rollup_note(
                    parent_row["id"],
                    f"Resolved “{child_rule['name']}” — implied by this outage")

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
            if rule["kind"] == "syslog" and occurrence.severity is not None:
                # Lower number = more severe (RFC 5424): the rule's own
                # severity is the threshold it fires at — "this severity
                # and worse" — not just a label stamped on the resulting
                # alert.
                if occurrence.severity > rule["severity"]:
                    continue
            if not match_device(rule, occurrence):
                continue
            key = dedup_key(rule, occurrence)
            if rollup:
                parent = self._rollup_parent(rule, occurrence)
                if parent is not None:
                    # Not opened at all, so no email and no row to work. The
                    # parent says where it went, so the latency alert an
                    # operator expected to see is accounted for rather than
                    # just missing.
                    self.counters["rolled_up"] += 1
                    self.db.add_rollup_note(
                        parent["id"],
                        f"Suppressed “{rule['name']}” — implied by this outage")
                    continue
            row, is_new = self.db.open_or_increment(
                rule["id"], key, occurrence.entity_kind, occurrence.entity_id,
                occurrence.entity_label, rule["severity"], occurrence.message,
                occurrence.detail, occurrence.ts, extra=occurrence.extra)
            if is_new:
                self.counters["opened"] += 1
                if rollup and (rule["key"] or "") in ROLLS_UP:
                    self._absorb_subordinates(rule, occurrence, row)
                self._notify(row, rule, occurrence, settings)
            # Renotify is NOT decided here any more. It used to compare
            # against row["last_ts"], which open_or_increment had just set to
            # this occurrence's timestamp a statement earlier, so the
            # difference was always about zero and the condition could not be
            # satisfied for any renotify_minutes above five seconds. Worse,
            # this path is only reached when a NEW occurrence arrives, and an
            # event-driven rule (a device that stays down, a trap) produces
            # exactly one. _sweep_renotify sweeps open alerts instead.

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
        for row in self.db.alerts_due_renotify(cutoff):
            rule = self.db.rule(row["rule_id"])
            if rule is None or not rule["enabled"]:
                continue
            try:
                extra = json.loads(row["extra_json"] or "{}")
            except (TypeError, ValueError):
                extra = {}
            occurrence = Occurrence(
                kind=rule["kind"], source_kind=rule["source_kind"] or "",
                entity_kind=row["entity_kind"], entity_id=row["entity_id"],
                entity_label=row["entity_label"], ts=row["last_ts"],
                message=row["message"], detail=row["detail"] or "",
                extra=extra if isinstance(extra, dict) else {})
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
        now = time.time()
        hour_ago = now - 3600
        self._sent_this_hour = [ts for ts in self._sent_this_hour if ts >= hour_ago]
        max_per_hour = int(settings.get("max_emails_per_hour", 60))
        current_hour = int(now // 3600)
        if max_per_hour and len(self._sent_this_hour) >= max_per_hour:
            self.counters["suppressed"] += 1
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

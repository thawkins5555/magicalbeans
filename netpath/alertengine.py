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

import threading
import time
import traceback

from . import alertmail
from .alertrules import CLEARS, Occurrence, dedup_key, evaluate_flapping, \
    evaluate_threshold, match_device
from .eventlog import ERROR, NullLog

TICK_S = 5.0


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
    def __init__(self, db, *, nodes_db, snmp_db, syslog_db, ipam_db, app_db=None, log=None):
        self.db = db
        self.nodes_db = nodes_db
        self.snmp_db = snmp_db
        self.syslog_db = syslog_db
        self.ipam_db = ipam_db
        self.app_db = app_db
        self.log = log or NullLog()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._breach_streaks: dict[tuple, int] = {}
        self._sent_this_hour: list[float] = []
        self._suppression_logged_hour: int | None = None
        self.counters = {"evaluated": 0, "opened": 0, "resolved": 0,
                         "emails_sent": 0, "suppressed": 0, "send_errors": 0}
        self.error: str | None = None
        self._last_tick_ts: float = 0.0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self.stop()
        self._stop.clear()
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
        occurrences = []
        occurrences += self._drain_device_events(settings)
        occurrences += self._drain_interface_events(settings)
        occurrences += self._drain_traps(settings)
        occurrences += self._drain_syslog(settings)
        occurrences += self._drain_ipam_conflicts(settings)
        occurrences += self._evaluate_thresholds(settings)
        rules = [r for r in self.db.rules() if r["enabled"]]
        for occurrence in occurrences:
            self.counters["evaluated"] += 1
            self._apply(rules, occurrence, settings)

    # --------------------------------------------------------------- drains

    def _drain_device_events(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("device_events"):
            self.db.set_cursor("device_events", self.nodes_db.max_device_event_id())
            return []
        cursor = self.db.cursor("device_events")
        occurrences = []
        rows = self.nodes_db.device_events_since(cursor)
        max_id = cursor
        for row in rows:
            max_id = max(max_id, row["id"])
            device = self.nodes_db.device(row["device_id"])
            if device is None:
                continue
            label = device["name"] or device["ip"]
            occurrence = Occurrence(
                kind="device_event", source_kind=row["kind"], entity_kind="device",
                entity_id=str(device["id"]), entity_label=label, ts=row["ts"],
                message=row["detail"] or f"{label}: {row['kind']}",
                device_name=device["name"] or "", device_ip=device["ip"])
            occurrences.append(occurrence)
            clears_key = ("device_event", row["kind"])
            if clears_key in CLEARS:
                cleared_rule = self.db.rule_by_key(CLEARS[clears_key])
                if cleared_rule:
                    paired_dedup = f"{cleared_rule['key']}:device:{device['id']}"
                    resolved = self.db.resolve_by_dedup(paired_dedup, by="")
                    if resolved:
                        self.counters["resolved"] += 1
                        self._notify_clear(resolved, cleared_rule, settings)
        if max_id > cursor:
            self.db.set_cursor("device_events", max_id)
        return occurrences

    def _drain_interface_events(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("interface_events"):
            self.db.set_cursor("interface_events", self.nodes_db.max_interface_event_id())
            return []
        cursor = self.db.cursor("interface_events")
        rows = self.nodes_db.interface_events_since(cursor)
        occurrences = []
        max_id = cursor
        touched_interfaces: set[int] = set()
        for row in rows:
            max_id = max(max_id, row["id"])
            touched_interfaces.add(row["interface_id"])
            interface = self.nodes_db.interface_by_id(row["interface_id"])
            if interface is None:
                continue
            device = self.nodes_db.device(interface["device_id"])
            if device is None:
                continue
            label = f"{device['name'] or device['ip']} / {interface['descr'] or interface['if_index']}"
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
        for interface_id in touched_interfaces:
            recent = [dict(r) for r in
                     self.nodes_db.recent_interface_events_for(interface_id)]
            if not evaluate_flapping(recent):
                continue
            interface = self.nodes_db.interface_by_id(interface_id)
            if interface is None:
                continue
            device = self.nodes_db.device(interface["device_id"])
            if device is None:
                continue
            label = f"{device['name'] or device['ip']} / {interface['descr'] or interface['if_index']}"
            occurrences.append(Occurrence(
                kind="interface_event", source_kind="flapping", entity_kind="interface",
                entity_id=f"{device['id']}:{interface['if_index']}", entity_label=label,
                ts=time.time(), message=f"{label} is flapping",
                device_name=device["name"] or "", device_ip=device["ip"]))
        if max_id > cursor:
            self.db.set_cursor("interface_events", max_id)
        return occurrences

    def _drain_traps(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("traps"):
            self.db.set_cursor("traps", self.snmp_db.max_id())
            return []
        cursor = self.db.cursor("traps")
        rows = self.snmp_db.traps_since(cursor)
        occurrences = []
        max_id = cursor
        for row in rows:
            max_id = max(max_id, row["id"])
            occurrences.append(Occurrence(
                kind="trap", source_kind=row["trap_kind"] or "", entity_kind="trap",
                entity_id=row["trap_oid"] or "", entity_label=row["trap_name"] or row["trap_oid"] or row["source"],
                ts=row["ts"], message=row["varbind_text"] or "", device_ip=row["source"],
                extra={"trap_name": row["trap_name"] or "", "trap_oid": row["trap_oid"] or "",
                      "varbinds": row["varbind_text"] or ""}))
        if max_id > cursor:
            self.db.set_cursor("traps", max_id)
        return occurrences

    def _drain_syslog(self, settings) -> list[Occurrence]:
        if not self.db.has_cursor("syslog"):
            self.db.set_cursor("syslog", self.syslog_db.max_id())
            return []
        cursor = self.db.cursor("syslog")
        min_severity = int(settings.get("min_severity", 7))
        rows = self.syslog_db.rows_since(cursor)
        occurrences = []
        max_id = cursor
        for row in rows:
            max_id = max(max_id, row["id"])
            if row["severity"] > min_severity:
                continue
            occurrences.append(Occurrence(
                kind="syslog", source_kind="", entity_kind="syslog",
                entity_id=row["source"], entity_label=row["host"] or row["source"],
                ts=row["ts"], message=row["message"] or "", device_ip=row["source"]))
        if max_id > cursor:
            self.db.set_cursor("syslog", max_id)
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
            occurrences.append(Occurrence(
                kind="ipam", source_kind="", entity_kind="ipam",
                entity_id=str(row["id"]), entity_label=row["ip"],
                ts=row["detected_ts"],
                message=f"{row['ip']}: conflicting MAC addresses "
                        f"{row['mac_a']} and {row['mac_b']}",
                device_ip=row["ip"]))
        if max_id > cursor:
            self.db.set_cursor("ipam_conflicts", max_id)
        return occurrences

    def _evaluate_thresholds(self, settings) -> list[Occurrence]:
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
                streak_key = (rule["id"], device["id"])
                threshold = rule["threshold"]
                if value is not None and threshold is not None and value >= threshold:
                    streak = self._breach_streaks.get(streak_key, 0) + 1
                else:
                    streak = 0
                self._breach_streaks[streak_key] = streak
                result = evaluate_threshold(rule, value, streak)
                label = device["name"] or device["ip"]
                if result == "breach":
                    occurrences.append(Occurrence(
                        kind="threshold", source_kind=rule["source_kind"],
                        entity_kind="device", entity_id=str(device["id"]),
                        entity_label=label, ts=time.time(),
                        message=f"{label}: {rule['name']} ({value})",
                        device_name=device["name"] or "", device_ip=device["ip"],
                        extra={"metric_label": metric["label"] if metric else rule["source_kind"],
                              "value": str(value), "threshold": str(rule["threshold"])}))
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

    # ---------------------------------------------------------------- apply

    def _apply(self, rules, occurrence: Occurrence, settings) -> None:
        for rule in rules:
            if rule["kind"] != occurrence.kind:
                continue
            if rule["kind"] in ("device_event", "interface_event", "trap"):
                if (rule["source_kind"] or "") and rule["source_kind"] != occurrence.source_kind:
                    continue
            if not match_device(rule, occurrence):
                continue
            key = dedup_key(rule, occurrence)
            row, is_new = self.db.open_or_increment(
                rule["id"], key, occurrence.entity_kind, occurrence.entity_id,
                occurrence.entity_label, rule["severity"], occurrence.message,
                occurrence.detail, occurrence.ts)
            if is_new:
                self.counters["opened"] += 1
            renotify_minutes = float(settings.get("renotify_minutes", 0))
            should_notify = is_new
            if not is_new and renotify_minutes > 0 and row["state"] == "open":
                if time.time() - row["last_ts"] >= renotify_minutes * 60 - TICK_S:
                    should_notify = True
            if should_notify:
                self._notify(row, rule, occurrence, settings, renotify=not is_new)

    # -------------------------------------------------------------- notify

    def _notify(self, alert_row, rule_row, occurrence: Occurrence, settings,
               renotify: bool = False, notify_kind: str | None = None,
               template_override=None) -> None:
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

        to_addrs = [a.strip() for a in str(settings.get("smtp_to_default", "")).split(",")
                   if a.strip()]
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
        try:
            alertmail.send(settings, password, to_addrs, subject, body,
                           bool(template["is_html"]))
            self._sent_this_hour.append(now)
            self.counters["emails_sent"] += 1
            self.db.record_notification(alert_row["id"], kind, ", ".join(to_addrs),
                                        subject, True)
        except Exception as exc:
            self.counters["send_errors"] += 1
            self.db.record_notification(alert_row["id"], kind, ", ".join(to_addrs),
                                        subject, False, str(exc))
        finally:
            password = None

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
            else:
                return ""
        except (TypeError, ValueError):
            return ""
        device = self.nodes_db.device(device_id)
        return device["ip"] if device else ""

    def _notify_clear(self, alert_row, rule_row, settings) -> None:
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
        template = self.db.template_by_key("device_up")
        if template is None:
            return
        occurrence = Occurrence(
            kind=rule_row["kind"], source_kind=rule_row["source_kind"] or "",
            entity_kind=alert_row["entity_kind"], entity_id=alert_row["entity_id"],
            entity_label=alert_row["entity_label"], ts=time.time(),
            message=f"Resolved: {alert_row['message']}")
        self._notify(alert_row, rule_row, occurrence, settings,
                     notify_kind="clear", template_override=template)

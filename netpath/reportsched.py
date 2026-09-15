"""Scheduled emailed reports: due-date math, rendering and the send loop.

Storage lives in nodesdb (report_schedules); this module owns the three
things that are not storage -- next_due (when a schedule fires next),
render (the subject/body/CSV a firing produces, reusing netpath/report.py's
three report builders the way api.py's own routes already do), and run_due
(the tick service.py calls once a minute).
"""

from __future__ import annotations

import calendar
import json
import time

from . import alertmail
from . import csvout
from . import report as reportmod
from .eventlog import SYSTEM

CADENCES = ("daily", "weekly", "monthly")
KINDS = ("availability", "top_metrics", "firmware", "sfp")

# Body text formats a period as whole days; 20 rows is what an inbox reads
# in one screen without an attachment.
_BODY_ROW_CAP = 20

# Kept equal to api.py's REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S: a
# schedule always ranks the whole fleet, so it is the whole-fleet case of
# that same live-request cost ceiling, checked again here in case a row
# predates api.py's own write-time cap.
_TOP_METRICS_MAX_WINDOW_S = 7 * 86400.0


def _local_at(base_ts: float, *, day_delta: int, hour: int, minute: int) -> float:
    """A local-calendar timestamp `day_delta` days from base_ts's own day,
    at hour:minute. Month/year rollover and DST are left to mktime's
    normalisation of an out-of-range tm_mday, the standard trick for
    calendar arithmetic in local time."""
    lt = time.localtime(base_ts)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + day_delta,
                        int(hour), int(minute), 0, 0, 0, -1))


def _month_at(year: int, month: int, day_of_month: int, hour: int, minute: int) -> float:
    last = calendar.monthrange(year, month)[1]
    day = max(1, min(int(day_of_month), last))
    return time.mktime((year, month, day, int(hour), int(minute), 0, 0, 0, -1))


def _add_month(year: int, month: int) -> tuple[int, int]:
    total = (month - 1) + 1
    return year + total // 12, total % 12 + 1


def next_due(row, after_ts: float) -> float:
    """The next local-time instant strictly after `after_ts` this schedule
    is due, given its cadence/hour/minute(/weekday|day_of_month). `row` is a
    sqlite3.Row or a plain dict; both support row["cadence"] etc."""
    cadence = row["cadence"]
    hour, minute = int(row["hour"]), int(row["minute"])
    if cadence == "daily":
        candidate = _local_at(after_ts, day_delta=0, hour=hour, minute=minute)
        if candidate <= after_ts:
            candidate = _local_at(after_ts, day_delta=1, hour=hour, minute=minute)
        return candidate
    if cadence == "weekly":
        weekday = int(row["weekday"])   # 0=Monday, time.struct_time's own convention
        lt = time.localtime(after_ts)
        delta = (weekday - lt.tm_wday) % 7
        candidate = _local_at(after_ts, day_delta=delta, hour=hour, minute=minute)
        if candidate <= after_ts:
            candidate = _local_at(after_ts, day_delta=delta + 7, hour=hour, minute=minute)
        return candidate
    if cadence == "monthly":
        day_of_month = int(row["day_of_month"])
        lt = time.localtime(after_ts)
        candidate = _month_at(lt.tm_year, lt.tm_mon, day_of_month, hour, minute)
        if candidate <= after_ts:
            year, month = _add_month(lt.tm_year, lt.tm_mon)
            candidate = _month_at(year, month, day_of_month, hour, minute)
        return candidate
    raise ValueError(f"unknown cadence {cadence!r}")


def _fmt_duration(seconds) -> str:
    total = int(round(seconds or 0))
    if total <= 0:
        return "0m"
    h, m = divmod(total // 60, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d}d {h:02d}h"
    if h:
        return f"{h}h {m:02d}m"
    return f"{m}m"


def _device_ids_for_group(nodes_db, device_group_id) -> list[int]:
    rows = (nodes_db.devices(device_group_id=int(device_group_id))
           if device_group_id else nodes_db.devices())
    return [row["id"] for row in rows]


def _render_availability(service, params: dict, now: float):
    period_days = float(params.get("period_days") or 7)
    t1, t0 = now, now - period_days * 86400
    device_ids = _device_ids_for_group(service.nodes_db, params.get("device_group_id"))
    result = reportmod.device_availability_report(
        service.nodes_db, device_ids, t0, t1, alertsdb=service.alerts_db,
        hostnames=service.app_db.hostnames)
    devices = result.devices
    groups_by_id = {g["id"]: g["name"] for g in service.nodes_db.device_groups()}
    devices_by_id = {row["id"]: row for row in service.nodes_db.devices_by_ids(device_ids)}

    def group_name(device_id):
        row = devices_by_id.get(device_id)
        return (groups_by_id.get(row["device_group_id"]) or "") if row else ""

    # Worst availability first: what an operator opens the report to see.
    ranked = sorted(devices, key=lambda d: (
        d.availability_pct if d.availability_pct is not None else -1.0))

    up_count = sum(1 for d in devices if (d.availability_pct or 0) >= 99.9)
    subject = f"Availability report — {period_days:.0f} day(s), {len(devices)} device(s)"
    lines = [subject,
            f"Period: {time.strftime('%Y-%m-%d', time.localtime(t0))} to "
            f"{time.strftime('%Y-%m-%d', time.localtime(t1))}",
            f"{len(devices)} device(s), {up_count} at or above 99.9% availability", ""]
    for d in ranked[:_BODY_ROW_CAP]:
        pct = f"{d.availability_pct:.2f}%" if d.availability_pct is not None else "—"
        lines.append(f"  {d.name[:32]:<32} {pct:>8}  down {_fmt_duration(d.down_s)}  "
                    f"outages {d.outage_count}")
    if len(ranked) > _BODY_ROW_CAP:
        lines.append(f"  ... and {len(ranked) - _BODY_ROW_CAP} more (see the attached CSV)")
    body = "\n".join(lines) + "\n"

    header = ["device_id", "name", "ip", "group", "availability_pct", "up_s", "down_s",
             "outage_count", "longest_outage_s", "mttr_s", "still_down", "currently_disabled",
             "excluded_before_created_s", "maintenance_excluded_s",
             "maintenance_mode_excluded_s", "mute_excluded_s", "caveats"]
    csv_rows = [[d.device_id, d.name, d.ip, group_name(d.device_id), d.availability_pct,
                d.up_s, d.down_s, d.outage_count, d.longest_outage_s, d.mttr_s,
                1 if d.still_down else 0, 1 if d.currently_disabled else 0,
                d.excluded_before_created_s, d.maintenance_excluded_s,
                d.maintenance_mode_excluded_s, d.mute_excluded_s, "; ".join(d.caveats)]
               for d in devices]
    return subject, body, csvout.csv_text(header, csv_rows)


def _render_top_metrics(service, params: dict, now: float):
    period_days = float(params.get("period_days") or 7)
    if period_days * 86400 > _TOP_METRICS_MAX_WINDOW_S:
        raise ValueError(
            f"period_days ({period_days:.0f}) exceeds the whole-fleet top_metrics "
            f"cost ceiling ({_TOP_METRICS_MAX_WINDOW_S / 86400:.0f} days)")
    metric_key = str(params.get("metric_key") or "").strip()
    if not metric_key:
        raise ValueError("top_metrics report has no metric_key configured")
    top_n = max(1, min(int(params.get("top_n") or 20), 500))
    t1, t0 = now, now - period_days * 86400
    result = reportmod.top_metric_ranking(
        service.nodes_db, metric_key, t0, t1, n=top_n,
        hostnames=service.app_db.hostnames)

    subject = f"Top {top_n} — {metric_key} over {period_days:.0f} day(s)"
    lines = [subject,
            f"Period: {time.strftime('%Y-%m-%d', time.localtime(t0))} to "
            f"{time.strftime('%Y-%m-%d', time.localtime(t1))}",
            f"{len(result.rows)} row(s), ranked by {result.rank_by}", ""]
    for r in result.rows[:_BODY_ROW_CAP]:
        label = f"{r.label}{f' #{r.if_index}' if r.if_index is not None else ''}"
        peak = "—" if r.peak is None else f"{r.peak:.2f}"
        mean = "—" if r.mean is None else f"{r.mean:.2f}"
        lines.append(f"  {r.device_name[:24]:<24} {label[:28]:<28} peak {peak:>10} "
                    f"mean {mean:>10} {r.unit}")
    if len(result.rows) > _BODY_ROW_CAP:
        lines.append(f"  ... and {len(result.rows) - _BODY_ROW_CAP} more "
                    "(see the attached CSV)")
    body = "\n".join(lines) + "\n"

    header = ["device_id", "device_name", "device_ip", "metric_key", "label",
             "if_index", "peak", "mean", "unit", "n_hours"]
    csv_rows = [[r.device_id, r.device_name, r.device_ip, r.key, r.label,
                r.if_index, r.peak, r.mean, r.unit, r.n_hours] for r in result.rows]
    return subject, body, csvout.csv_text(header, csv_rows)


_FIRMWARE_CSV_HEADER = ["device_id", "name", "ip", "vendor", "model_hint",
                        "sw_version", "sw_image", "sw_image_file", "last_poll_ts",
                        "device", "name_source", "fw_version", "sw_source", "fw_source"]


def _render_firmware(service, params: dict, now: float):
    report = reportmod.firmware_inventory(
        service.nodes_db, hostnames=service.app_db.hostnames)
    subject = (f"Firmware inventory — {report.device_count} device(s), "
              f"{report.version_count} version(s)")
    lines = [subject,
            f"Generated {time.strftime('%Y-%m-%d %H:%M', time.localtime(now))}",
            f"{report.unknown_count} device(s) with no reported software version", ""]
    for r in report.rows[:_BODY_ROW_CAP]:
        lines.append(f"  {r.name[:28]:<28} {r.vendor[:16]:<16} "
                    f"{(r.sw_version or '—')[:24]:<24}")
    if len(report.rows) > _BODY_ROW_CAP:
        lines.append(f"  ... and {len(report.rows) - _BODY_ROW_CAP} more "
                    "(see the attached CSV)")
    body = "\n".join(lines) + "\n"

    csv_rows = [[r.device_id, r.name, r.ip, r.vendor, r.model_hint, r.sw_version,
                r.sw_image, r.sw_image_file, r.last_poll_ts, r.device, r.name_source,
                r.fw_version, r.sw_source, r.fw_source] for r in report.rows]
    return subject, body, csvout.csv_text(_FIRMWARE_CSV_HEADER, csv_rows)


def _render_sfp(service, params: dict, now: float):
    device_ids = _device_ids_for_group(service.nodes_db, params.get("device_group_id"))
    include_empty = params.get("include_empty") is True or str(
        params.get("include_empty", "")).strip().lower() in ("1", "true", "yes")
    report = reportmod.sfp_inventory(
        service.nodes_db, device_ids=device_ids, hostnames=service.app_db.hostnames,
        include_empty=include_empty)
    subject = (f"SFP inventory — {report.port_count} port(s) on "
              f"{report.device_count} device(s), {report.dom_count} DOM / "
              f"{report.sfp_count} SFP / {report.copper_count} COP")
    lines = [subject,
            f"Generated {time.strftime('%Y-%m-%d %H:%M', time.localtime(now))}", ""]
    for r in report.rows[:_BODY_ROW_CAP]:
        lines.append(f"  {r.name[:28]:<28} {r.port[:20]:<20} {r.kind:<10} "
                    f"{r.medium:<6}")
    if len(report.rows) > _BODY_ROW_CAP:
        lines.append(f"  ... and {len(report.rows) - _BODY_ROW_CAP} more "
                    "(see the attached CSV)")
    body = "\n".join(lines) + "\n"

    csv_rows = [[r.device_id, r.name, r.ip, r.if_index, r.port, r.alias, r.kind,
                r.medium, r.media, r.oper_status, r.admin_status, r.speed_bps,
                r.last_seen_ts, r.device] for r in report.rows]
    return subject, body, csvout.csv_text(reportmod.SFP_CSV_HEADER, csv_rows)


_RENDERERS = {
    "availability": _render_availability,
    "top_metrics": _render_top_metrics,
    "firmware": _render_firmware,
    "sfp": _render_sfp,
}


def render(service, row, now: float) -> tuple[str, str, str, str]:
    """(subject, body_text, csv_text, filename) for one schedule row, firing
    at `now`. Raises ValueError for an unknown kind or a kind missing a
    required param (e.g. top_metrics with no metric_key) -- run_due records
    that as the schedule's last_status rather than letting it propagate."""
    kind = row["kind"]
    renderer = _RENDERERS.get(kind)
    if renderer is None:
        raise ValueError(f"unknown report kind {kind!r}")
    params = json.loads(row["params_json"] or "{}")
    subject, body, csv_text = renderer(service, params, now)
    subject = f"{row['name']}: {subject}"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    filename = f"sappiwhere-report-{kind}-{stamp}.csv"
    return subject, body, csv_text, filename


def run_due(service, now: float) -> int:
    """Sends every schedule whose next_run_ts has arrived. Returns how many were due."""
    nodes_db = service.nodes_db
    due = nodes_db.due_report_schedules(now)
    for row in due:
        _run_one_schedule(service, row, now)
    return len(due)


def _run_one_schedule(service, row, now: float) -> None:
    """One schedule's next_due/render/send, wrapped in one try so a bad row
    (or a transient render/send failure) cannot abort the rest of the tick."""
    nodes_db = service.nodes_db
    schedule_id, name = row["id"], row["name"]
    advanced = False
    try:
        # Advanced before the render/send below, so a crash mid-send cannot repeat this run on the next tick.
        nodes_db.update_report_schedule(schedule_id, next_run_ts=next_due(row, now))
        advanced = True

        subject, body, csv_text, filename = render(service, row, now)
        recipients = json.loads(row["recipients"] or "[]")
        creds = service.alert_engine.smtp_credentials() if service.alert_engine else None
        if creds is None:
            status = "not sent: email is not configured"
        elif not recipients:
            status = "not sent: no recipients configured"
        else:
            settings, password = creds
            try:
                alertmail.send(settings, password, recipients, subject, body,
                               attachments=[(filename, csv_text.encode("utf-8"),
                                            "text", "csv")])
                status = f"sent to {len(recipients)} recipient(s)"
            except Exception as exc:
                status = f"failed to send: {exc}"
    except Exception as exc:
        status = f"failed: {exc}"
        if not advanced:
            # A row whose cadence fields do not compute must not be asked again every minute forever.
            nodes_db.update_report_schedule(schedule_id, next_run_ts=now + 86400)
    nodes_db.record_report_schedule_run(schedule_id, status)
    service.log.add(SYSTEM, f"Scheduled report {name!r}: {status}")

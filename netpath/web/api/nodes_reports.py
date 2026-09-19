"""Handlers: Nodes reports and scheduled reports."""

from __future__ import annotations

import functools
import json
import time

from ...eventlog import NODES as NODES_CATEGORY
from ... import nodesdb
from ... import report as reportmod

from ._shared import _GROUP_EDITABLE_BODY, _audit, _audit_diff, _clean_priv_proto, _clear_credential, _csv_response, _device_event_json, _id_list, _may_read_secrets, _num, _pick, _refuse_orphaned_v3_secret, _require, _store_v3_credential, _window
from .nodes import _group_json


# ------------------------------------------------------------------ reports
#
# netpath/report.py owns the computation (device_availability_report,
# top_metric_ranking) and the four ways a gap in device_status_segments is
# NOT "the device was down". These two routes are the thin dispatch on top:
# query-string parsing, resolving "no device_ids given" to the whole fleet,
# and refusing a whole-fleet top-N request wider than a week rather than
# letting it block a request thread for minutes. Narrowing device_ids is the
# caller's way round it. device_availability_report has no equivalent known
# cost at fleet scale, so nothing here caps it.
REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S = 7 * 86400.0
REPORT_TOP_METRICS_MAX_N = 500


def get_nodes_reports_availability(service, params, body) -> dict:
    """Availability/outage/MTTR for a device or the whole fleet over
    [t0, t1] (default the last 7 days) — see report.device_availability_report
    for what "available" means and the four things a gap in the history is
    deliberately NOT treated as. `device_ids` (comma-separated) narrows it;
    omitted, every device on file is reported on."""
    t0, t1 = _window(params, default_span_s=7 * 86400.0)
    device_ids = _id_list(params.get("device_ids"))
    if device_ids is None:
        device_ids = [row["id"] for row in service.nodes_db.devices()]
    result = reportmod.device_availability_report(
        service.nodes_db, device_ids, t0, t1, alertsdb=service.alerts_db,
        hostnames=service.app_db.hostnames)
    return result.to_dict()


def get_nodes_reports_top_metrics(service, params, body) -> dict:
    """The top (or bottom) `n` metric series by peak or mean value over
    [t0, t1] (default the last 7 days) — "which twenty links came closest to
    saturation" is `key=if_in_util_pct.%&like=1`; "which devices ran
    hottest" is `key=cpu_pct&rank_by=mean`. See report.top_metric_ranking
    for the query itself and its cost at fleet scale.

    A whole-fleet-equivalent ask over more than 7 days is refused outright
    rather than left to block the request thread for minutes — narrow
    `device_ids` or ask for a shorter window instead. "Whole-fleet-
    equivalent" is scaled by how many devices this request resolves to
    (`device_ids` omitted
    ends up covering every device on file, same as `device_ids` naming
    every device explicitly — the two must refuse identically, since they
    produce the identical query), scaled against the window: half the
    fleet over 14 days costs the same as the whole fleet over 7, so the
    cap applies to that scaled figure rather than to a literal device_ids-
    was-omitted check, which a caller who happens to enumerate every id
    would otherwise walk straight past.
    """
    key = str(params.get("key", "")).strip()
    if not key:
        raise ValueError("key is required")
    t0, t1 = _window(params, default_span_s=7 * 86400.0)
    device_ids = _id_list(params.get("device_ids"))
    total_devices = service.nodes_db.device_count()
    covered = min(len(set(device_ids)), total_devices) if device_ids else total_devices
    if total_devices and covered:
        scaled_window_s = (t1 - t0) * (covered / total_devices)
        if scaled_window_s > REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S:
            raise ValueError(
                f"this would rank {covered} of {total_devices} device(s) over "
                f"{(t1 - t0) / 86400:.1f} day(s) — too slow for a live request "
                f"(measured ~100s at 2,000 devices for a month in "
                f"report.top_metric_ranking's own benchmark) — narrow "
                f"device_ids further or request a shorter window")
    rank_by = str(params.get("rank_by") or "peak")
    if rank_by not in ("peak", "mean"):
        raise ValueError("rank_by must be 'peak' or 'mean'")
    like = str(params.get("like", "")).strip().lower() in ("1", "true", "yes")
    ascending = str(params.get("ascending", "")).strip().lower() in ("1", "true", "yes")
    n = max(1, min(int(_num(params, "n", 20, int) or 20), REPORT_TOP_METRICS_MAX_N))
    result = reportmod.top_metric_ranking(
        service.nodes_db, key, t0, t1, n=n, rank_by=rank_by,
        ascending=ascending, like=like, device_ids=device_ids,
        hostnames=service.app_db.hostnames)
    return result.to_dict()


_FIRMWARE_CSV_HEADER = ["device_id", "name", "ip", "vendor", "model_hint",
                        "sw_version", "sw_image", "sw_image_file", "last_poll_ts",
                        "device", "name_source", "fw_version", "sw_source", "fw_source"]


def _firmware_report(service, params):
    """Shared body of the JSON route and the CSV one, so they cannot drift."""
    return reportmod.firmware_inventory(
        service.nodes_db, _id_list(params.get("device_ids")),
        hostnames=service.app_db.hostnames)


def get_nodes_reports_firmware(service, params, body) -> dict:
    """What software every device is running. `device_ids` narrows to a group."""
    return _firmware_report(service, params).to_dict()


def get_nodes_reports_firmware_export(service, params, body) -> dict:
    """The same report as a CSV file, built server-side."""
    report = _firmware_report(service, params)
    csv_rows = [[r.device_id, r.name, r.ip, r.vendor, r.model_hint, r.sw_version,
                 r.sw_image, r.sw_image_file, r.last_poll_ts,
                 r.device, r.name_source, r.fw_version, r.sw_source, r.fw_source]
                for r in report.rows]
    return _csv_response("firmware", _FIRMWARE_CSV_HEADER, csv_rows)


def _truthy(value) -> bool:
    """The lax "1/true/yes" form a query string or a JSON string param uses."""
    return str(value).strip().lower() in ("1", "true", "yes")


def _sfp_report(service, params):
    return reportmod.sfp_inventory(
        service.nodes_db, _id_list(params.get("device_ids")),
        hostnames=service.app_db.hostnames,
        include_empty=_truthy(params.get("include_empty", "")))


def get_nodes_reports_sfp(service, params, body) -> dict:
    return _sfp_report(service, params).to_dict()


def get_nodes_reports_sfp_export(service, params, body) -> dict:
    report = _sfp_report(service, params)
    csv_rows = [[r.device_id, r.name, r.ip, r.if_index, r.port, r.alias, r.kind,
                r.medium, r.media, r.oper_status, r.admin_status, r.speed_bps,
                r.last_seen_ts, r.device] for r in report.rows]
    return _csv_response("sfp", reportmod.SFP_CSV_HEADER, csv_rows)


def _psu_report(service, params):
    return reportmod.single_psu_report(
        service.nodes_db, _id_list(params.get("device_ids")),
        hostnames=service.app_db.hostnames)


def get_nodes_reports_psu(service, params, body) -> dict:
    """Stack members (or standalone switches) running on a single power
    supply. `device_ids` narrows to a group."""
    return _psu_report(service, params).to_dict()


def get_nodes_reports_psu_export(service, params, body) -> dict:
    report = _psu_report(service, params)
    csv_rows = [[r.device_id, r.name, r.ip, r.member, r.psu_total, r.psu_present,
                r.psu_down, r.supplies, r.stack_power, r.covered, r.last_ts, r.device]
                for r in report.rows]
    return _csv_response("psu", reportmod.PSU_CSV_HEADER, csv_rows)


# --------------------------------------------------- scheduled reports (F)

_REPORT_SCHEDULE_KINDS = ("availability", "top_metrics", "firmware", "sfp", "psu")
_REPORT_SCHEDULE_CADENCES = ("daily", "weekly", "monthly")
_REPORT_SCHEDULE_RECIPIENTS_MAX = 20


def _clean_report_schedule_recipients(raw) -> list[str]:
    """The same lax "must contain @" rule the Alerts recipients Add button
    applies (alerts.js), so a schedule cannot save an address the Alerts
    page itself would refuse."""
    if isinstance(raw, str):
        items = [a.strip() for a in raw.split(",") if a.strip()]
    else:
        items = [str(a).strip() for a in (raw or []) if str(a).strip()]
    if not items:
        raise ValueError("At least one recipient is required")
    if len(items) > _REPORT_SCHEDULE_RECIPIENTS_MAX:
        raise ValueError(
            f"At most {_REPORT_SCHEDULE_RECIPIENTS_MAX} recipients are allowed")
    for addr in items:
        if "@" not in addr:
            raise ValueError(f"{addr!r} does not look like an email address")
    return items


def _clean_report_schedule_params(kind: str, params) -> dict:
    """Params per kind, the shape reportsched.py's own renderers read back:
    availability {period_days, device_group_id?}, top_metrics {period_days,
    metric_key, top_n}, firmware {} (nothing of its own to configure), sfp
    {include_empty, device_group_id?}, psu {device_group_id?}."""
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    if kind == "availability":
        period_days = _num(params, "period_days", 7, float)
        if not (0 < period_days <= 366):
            raise ValueError("period_days must be between 0 and 366")
        cleaned = {"period_days": period_days}
        group_id = params.get("device_group_id")
        if group_id not in (None, ""):
            try:
                cleaned["device_group_id"] = int(group_id)
            except (TypeError, ValueError):
                raise ValueError("device_group_id must be an integer")
        return cleaned
    if kind == "top_metrics":
        period_days = _num(params, "period_days", 7, float)
        # A schedule always ranks the whole fleet (no device_ids to narrow
        # it), so this is the same cap get_nodes_reports_top_metrics applies
        # to a whole-fleet request -- a scheduled run has no request thread
        # to time out, but the query is exactly as slow.
        top_metrics_max_days = REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S / 86400.0
        if not (0 < period_days <= top_metrics_max_days):
            raise ValueError(
                f"period_days must be between 0 and {top_metrics_max_days:.0f} "
                "for a whole-fleet top_metrics schedule")
        metric_key = str(params.get("metric_key", "")).strip()
        if not metric_key:
            raise ValueError("metric_key is required for a top_metrics report")
        top_n = _num(params, "top_n", 20, int)
        if not (1 <= top_n <= 500):
            raise ValueError("top_n must be between 1 and 500")
        return {"period_days": period_days, "metric_key": metric_key, "top_n": top_n}
    if kind == "sfp":
        cleaned = {"include_empty": _truthy(params.get("include_empty"))}
        group_id = params.get("device_group_id")
        if group_id not in (None, ""):
            try:
                cleaned["device_group_id"] = int(group_id)
            except (TypeError, ValueError):
                raise ValueError("device_group_id must be an integer")
        return cleaned
    if kind == "psu":
        cleaned = {}
        group_id = params.get("device_group_id")
        if group_id not in (None, ""):
            try:
                cleaned["device_group_id"] = int(group_id)
            except (TypeError, ValueError):
                raise ValueError("device_group_id must be an integer")
        return cleaned
    return {}   # firmware takes no params of its own


def _report_schedule_fields(body) -> dict:
    """Validated write-fields for add_report_schedule/update_report_schedule.
    The New/Edit dialog always submits the whole form, so POST and PUT share
    this one validation rather than PUT allowing a partial, possibly
    inconsistent, patch (a weekly schedule saved with no weekday, say)."""
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    if len(name) > 60:
        raise ValueError("Name must be 60 characters or fewer")

    kind = str(body.get("kind", "")).strip()
    if kind not in _REPORT_SCHEDULE_KINDS:
        raise ValueError("kind must be one of " + ", ".join(_REPORT_SCHEDULE_KINDS))

    cadence = str(body.get("cadence", "")).strip()
    if cadence not in _REPORT_SCHEDULE_CADENCES:
        raise ValueError("cadence must be one of " + ", ".join(_REPORT_SCHEDULE_CADENCES))

    hour = _num(body, "hour", None, int)
    if hour is None or not (0 <= hour <= 23):
        raise ValueError("hour must be 0-23")
    minute = _num(body, "minute", None, int)
    if minute is None or not (0 <= minute <= 59):
        raise ValueError("minute must be 0-59")

    weekday = day_of_month = None
    if cadence == "weekly":
        weekday = _num(body, "weekday", None, int)
        if weekday is None or not (0 <= weekday <= 6):
            raise ValueError("weekday (0=Monday) is required for a weekly schedule")
    elif cadence == "monthly":
        day_of_month = _num(body, "day_of_month", None, int)
        if day_of_month is None or not (1 <= day_of_month <= 31):
            raise ValueError("day_of_month (1-31) is required for a monthly schedule")

    return {
        "name": name, "kind": kind,
        "params_json": json.dumps(
            _clean_report_schedule_params(kind, body.get("params") or {})),
        "cadence": cadence, "hour": hour, "minute": minute,
        "weekday": weekday, "day_of_month": day_of_month,
        "recipients": json.dumps(
            _clean_report_schedule_recipients(body.get("recipients"))),
        "enabled": bool(body.get("enabled", True)),
    }


def _report_schedule_json(row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "kind": row["kind"],
        "params": json.loads(row["params_json"] or "{}"),
        "cadence": row["cadence"], "hour": row["hour"], "minute": row["minute"],
        "weekday": row["weekday"], "day_of_month": row["day_of_month"],
        "recipients": json.loads(row["recipients"] or "[]"),
        "enabled": bool(row["enabled"]),
        "next_run_ts": row["next_run_ts"], "last_run_ts": row["last_run_ts"],
        "last_status": row["last_status"],
    }


def get_nodes_report_schedules(service, params, body) -> dict:
    return {"schedules": [_report_schedule_json(r)
                          for r in service.nodes_db.report_schedules()]}


def post_nodes_report_schedule(service, params, body) -> dict:
    from ... import reportsched
    fields = _report_schedule_fields(body)
    next_run_ts = reportsched.next_due(fields, time.time())
    schedule_id = service.nodes_db.add_report_schedule(
        fields["name"], fields["kind"], fields["params_json"], fields["cadence"],
        fields["hour"], fields["minute"], fields["weekday"], fields["day_of_month"],
        fields["recipients"], enabled=fields["enabled"], next_run_ts=next_run_ts)
    _audit(service, params, "report.schedule", target=fields["name"], detail="created")
    return {"id": schedule_id}


def put_nodes_report_schedule(service, params, body, schedule_id) -> dict:
    from ... import reportsched
    _require(service.nodes_db.report_schedule(schedule_id), "report schedule")
    fields = _report_schedule_fields(body)
    fields["next_run_ts"] = reportsched.next_due(fields, time.time())
    service.nodes_db.update_report_schedule(schedule_id, **fields)
    _audit(service, params, "report.schedule", target=fields["name"], detail="updated")
    return {"ok": True}


def delete_nodes_report_schedule(service, params, body, schedule_id) -> dict:
    row = _require(service.nodes_db.report_schedule(schedule_id), "report schedule")
    service.nodes_db.delete_report_schedule(schedule_id)
    _audit(service, params, "report.schedule", target=row["name"], detail="deleted")
    return {"ok": True}


def post_nodes_report_schedule_run(service, params, body, schedule_id) -> dict:
    """Send now, outside the schedule -- does not move next_run_ts, so a
    manual send never displaces the automatic one."""
    from ... import reportsched
    row = _require(service.nodes_db.report_schedule(schedule_id), "report schedule")
    try:
        subject, body_text, csv_text, filename = reportsched.render(
            service, row, time.time())
    except Exception as exc:
        status = f"failed: {exc}"
        service.nodes_db.record_report_schedule_run(schedule_id, status)
        return {"ok": False, "status": status}
    recipients = json.loads(row["recipients"] or "[]")
    creds = service.alert_engine.smtp_credentials() if service.alert_engine else None
    if creds is None:
        status = "not sent: email is not configured"
    else:
        from ... import alertmail
        settings, password = creds
        try:
            alertmail.send(settings, password, recipients, subject, body_text,
                           attachments=[(filename, csv_text.encode("utf-8"),
                                        "text", "csv")])
            status = f"sent to {len(recipients)} recipient(s)"
        except Exception as exc:
            status = f"failed to send: {exc}"
    service.nodes_db.record_report_schedule_run(schedule_id, status)
    _audit(service, params, "report.schedule", target=row["name"],
          detail=f"send now: {status}")
    return {"ok": status.startswith("sent"), "status": status}


def get_nodes_device_events(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    since_s = _num(params, "since_s", None)
    # The per-method lane events are drawn on the timeline, never listed:
    # every outage would otherwise show three rows (down, snmp_down,
    # ping_down) that all say the same thing. poll_overrun is dropped too --
    # operational noise, not a device event -- but device_events() itself
    # still returns it to any other caller (alerting reads the table direct).
    device_events = service.nodes_db.device_events(
        device_id=device_id, since_s=since_s,
        exclude_kinds=tuple(nodesdb.DIALOG_HIDDEN_EVENT_KINDS))
    interface_events = [
        {"id": ev["id"], "interface_id": ev["interface_id"],
         "if_index": ev["if_index"], "descr": ev["descr"],
         "ts": ev["ts"], "kind": ev["kind"], "detail": ev["detail"]}
        for ev in service.nodes_db.interface_events_for_device(device_id, since_s=since_s)]
    return {
        "device_events": [_device_event_json(r) for r in device_events],
        "interface_events": interface_events,
    }


def post_nodes_device_credential(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    # The EFFECTIVE blob, not the row's: a device with none of its own
    # under a profile that holds one polls at authPriv, and warning it
    # about a privacy password it inherits would be the Test button's
    # old contradiction again.
    priv_stored = bool(service.nodes_db.effective_config(row).get("v3_priv_pass_enc"))
    return _store_v3_credential(
        service, params, body, priv_stored=priv_stored,
        store=functools.partial(service.nodes_db.set_device_credential, device_id),
        category=NODES_CATEGORY,
        message=f"Stored an SNMPv3 credential for {row['ip']}",
        target=f"device:{row['ip']}",
        unavailable=(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. The device can still be reached by typing the "
            "password into Test each time; nothing will be saved here."))


def delete_nodes_device_credential(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.nodes_db.clear_device_credential, device_id),
        category=NODES_CATEGORY,
        message=f"Cleared the stored SNMPv3 credential for {row['ip']}",
        target=f"device:{row['ip']}")


def _device_group_json(row) -> dict:
    return {"id": row["id"], "name": row["name"], "created_ts": row["created_ts"]}


def get_nodes_device_groups(service, params, body) -> dict:
    return {"groups": [_device_group_json(r) for r in service.nodes_db.device_groups()]}


def post_nodes_device_group(service, params, body) -> dict:
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    device_group_id = service.nodes_db.add_device_group(name)
    service.log.add(NODES_CATEGORY, f"Added device group {name}")
    _audit(service, params, "device_group.create", target=name)
    return {"id": device_group_id}


def put_nodes_device_group(service, params, body, device_group_id) -> dict:
    _require(service.nodes_db.device_group(device_group_id), "device group")
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    service.nodes_db.rename_device_group(device_group_id, name)
    _audit(service, params, "device_group.update", target=str(device_group_id),
          detail=f"renamed to {name}")
    return {"ok": True}


def delete_nodes_device_group(service, params, body, device_group_id) -> dict:
    row = _require(service.nodes_db.device_group(device_group_id), "device group")
    service.nodes_db.remove_device_group(device_group_id)
    service.log.add(NODES_CATEGORY, f"Removed device group {row['name']}")
    _audit(service, params, "device_group.delete", target=row["name"])
    return {"ok": True}


def get_nodes_groups(service, params, body) -> dict:
    reveal = _may_read_secrets(service, params, "nodes")
    return {"groups": [_group_json(service, r, reveal)
                       for r in service.nodes_db.groups()]}


def post_nodes_group(service, params, body) -> dict:
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    fields = {k: v for k, v in body.items()
             if k in _GROUP_EDITABLE_BODY and k != "name"}
    _clean_priv_proto(fields)
    group_id = service.nodes_db.add_group(name, **fields)
    service.log.add(NODES_CATEGORY, f"Added polling profile {name}")
    _audit(service, params, "profile.create", target=f"profile:{name}")
    return {"id": group_id}


def put_nodes_group(service, params, body, group_id) -> dict:
    # Captured for the audit diff below — the same discarded-row shape
    # put_nodes_device had: this is the literal "changed the threshold from
    # 90 to 99" case, since poll intervals/community defaults live in
    # _GROUP_EDITABLE_BODY.
    before = _require(service.nodes_db.group(group_id), "polling profile")
    fields = _pick(body, _GROUP_EDITABLE_BODY)
    _clean_priv_proto(fields)
    _refuse_orphaned_v3_secret(fields, before)
    service.nodes_db.update_group(group_id, **fields)
    detail = _audit_diff(before, fields)
    if detail:
        _audit(service, params, "profile.update", target=f"profile:{before['name']}",
              detail=detail)
    return {"ok": True}


def delete_nodes_group(service, params, body, group_id) -> dict:
    row = _require(service.nodes_db.group(group_id), "polling profile")
    in_use = service.nodes_db.device_count_for_group(group_id)
    if in_use:
        raise ValueError(f"{in_use} device(s) still use this profile — "
                         "move them to another profile first")
    service.nodes_db.remove_group(group_id)
    service.log.add(NODES_CATEGORY, f"Removed polling profile {row['name']}")
    _audit(service, params, "profile.delete", target=f"profile:{row['name']}")
    return {"ok": True}


def post_nodes_group_default(service, params, body, group_id) -> dict:
    row = _require(service.nodes_db.group(group_id), "polling profile")
    service.nodes_db.set_default_group(group_id)
    service.log.add(NODES_CATEGORY, f"{row['name']} is now the default polling profile")
    _audit(service, params, "profile.set_default", target=f"profile:{row['name']}")
    return {"ok": True}


def post_nodes_group_credential(service, params, body, group_id) -> dict:
    row = _require(service.nodes_db.group(group_id), "polling profile")
    return _store_v3_credential(
        service, params, body, priv_stored=bool(row["v3_priv_pass_enc"]),
        store=functools.partial(service.nodes_db.set_group_credential, group_id),
        category=NODES_CATEGORY,
        message=f"Stored an SNMPv3 credential for profile {row['name']}",
        target=f"profile:{row['name']}",
        unavailable=(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only."))


def delete_nodes_group_credential(service, params, body, group_id) -> dict:
    row = _require(service.nodes_db.group(group_id), "polling profile")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.nodes_db.clear_group_credential, group_id),
        category=NODES_CATEGORY,
        message=f"Cleared the stored SNMPv3 credential for profile {row['name']}")

"""Handlers: alert rules, mutes and maintenance mode/windows."""

from __future__ import annotations

import json
import math
import time

from ... import alertrules
from ...alertrules import device_id_for
from ... import alertsdb
from ...alertsdb import is_window_active
from ...eventlog import ALERTS as ALERTS_CATEGORY

from ._shared import BULK_DEVICE_ID_MAX, _alert_filters, _audit, _audit_diff, _bulk_ids, _clear_credential, _csv_response, _encrypt_secret, _hist_window, _maintenance_json, _page, _pick, _require


# ------------------------------------------------------------------ alerts

def _alert_device_id(row) -> int | None:
    """The Nodes device an alert row is about, or None when it is about
    nothing in Nodes.

    One line, because the rule itself lives in alertrules.device_id_for —
    the same module (and the same function) the engine's mute check and hold
    lookup use, so a device alert, an interface alert resolving to the switch
    the port is on, and everything structurally outside Nodes cannot drift
    apart between the engine and the wire format. Sent on every alert row so
    the page can offer Mute without reimplementing the rule in JavaScript.
    """
    return device_id_for(row["entity_kind"], row["entity_id"])


def _alert_device_ids(service, rows) -> set:
    """The subset of the devices a batch of alert rows names that Nodes still
    has, as a set of ids.

    One question, asked once for the whole page rather than per row: an alert
    list is up to 2000 rows and most of them are about the same handful of
    devices. A device that has been removed while its alerts stayed in
    history is simply absent from the answer, which is how _alert_json decides
    to report no device at all rather than offering a Mute the API would
    reject. Unsorted on purpose — this feeds an IN (...) list, which has no
    order to respect; devices_by_ids chunks it.
    """
    wanted = {device_id for device_id in (_alert_device_id(r) for r in rows)
              if device_id is not None}
    return {row["id"] for row in service.nodes_db.devices_by_ids(wanted)}


def _alert_json(row, present_ids: set) -> dict:
    """One alert row on the wire. `present_ids` is required, not optional:
    it decides whether device_id is reported at all, and omitting it reports
    every alert as being about no device — which greys out the Mute control
    across the page for no visible reason. Build it with _alert_device_ids.

    No device_name: the page renders the entity_label the engine already put
    on the alert, and never read one."""
    from ... import alertmail

    severity = row["severity"]
    device_id = _alert_device_id(row)
    if device_id is not None and device_id not in present_ids:
        device_id = None
    return {
        "id": row["id"], "rule_id": row["rule_id"], "dedup_key": row["dedup_key"],
        "entity_kind": row["entity_kind"], "entity_id": row["entity_id"],
        "entity_label": row["entity_label"], "severity": severity,
        "device_id": device_id,
        "severity_name": alertmail.SEVERITY_NAMES[severity] if 0 <= severity <= 7
                        else str(severity),
        "message": row["message"], "detail": row["detail"], "state": row["state"],
        "count": row["count"], "opened_ts": row["opened_ts"], "last_ts": row["last_ts"],
        "acked_ts": row["acked_ts"], "acked_by": row["acked_by"],
        "ack_note": row["ack_note"], "resolved_ts": row["resolved_ts"],
        "resolved_by": row["resolved_by"],
        # Keyed defensively: an alerts.db from before the rollup column was
        # added is migrated on open, but a row handed here from another
        # source should still render rather than raise.
        "rollup_note": (row["rollup_note"] if "rollup_note" in row.keys() else ""),
    }


def _rule_json(row) -> dict:
    return {
        "id": row["id"], "key": row["key"], "name": row["name"], "kind": row["kind"],
        "source_kind": row["source_kind"], "severity": row["severity"],
        "enabled": bool(row["enabled"]), "is_builtin": bool(row["is_builtin"]),
        "device_filter": row["device_filter"], "threshold": row["threshold"],
        "flap_window_s": row["flap_window_s"],
        "flap_min_transitions": row["flap_min_transitions"],
        "clear_threshold": row["clear_threshold"], "for_polls": row["for_polls"],
        # Keyed defensively like the rest; 'above' is the implied default
        # when absent.
        "comparison": (row["comparison"] if "comparison" in row.keys()
                       else "above") or "above",
        # Keyed defensively for the same reason as rollup_note above.
        "for_seconds": (row["for_seconds"] if "for_seconds" in row.keys() else None),
        "template_id": row["template_id"], "created_ts": row["created_ts"],
        # Set by the rule editor since 4.37; keyed defensively like the rest.
        "auto_resolve_after_s": (row["auto_resolve_after_s"]
                                 if "auto_resolve_after_s" in row.keys() else None),
        "notify": (bool(row["notify"]) if "notify" in row.keys() else True),
        "notify_sms": (bool(row["notify_sms"]) if "notify_sms" in row.keys() else False),
    }


def _template_json(row, with_tokens: bool = False) -> dict:
    result = {
        "id": row["id"], "key": row["key"], "name": row["name"],
        "subject": row["subject"], "body": row["body"], "is_html": bool(row["is_html"]),
        "is_builtin": bool(row["is_builtin"]), "updated_ts": row["updated_ts"],
    }
    if with_tokens:
        from ... import alertmail
        result["tokens"] = alertmail.token_reference()
    return result


def get_alerts_overview(service, params, body) -> dict:
    t0, t1, bucket = _hist_window(params)
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": service.alerts_db.histogram(t0, t1, bucket),
        "summary": service.alerts_db.open_summary(),
        # Beside the open counts, because maintenance mode never expires: a
        # device left in it and forgotten is invisible everywhere alert
        # counts are read unless this says so.
        "maintenance_count": len(service.alerts_db.maintenance_device_ids()),
        "engine": {
            "running": service.alert_engine.running,
            "status": service.alert_engine.status_text(),
            "counters": service.alert_engine.counters,
        },
    }


def _alerts_rows_json(service, rows) -> list[dict]:
    rule_names = {r["id"]: r["name"] for r in service.alerts_db.rules()}
    present_ids = _alert_device_ids(service, rows)
    alerts = []
    for row in rows:
        alert = _alert_json(row, present_ids)
        alert["rule_name"] = rule_names.get(row["rule_id"], "")
        alerts.append(alert)
    return alerts


# ALERTS_LIST_CAP is the per-page ceiling a browser table should ever try
# to render, not a data limit: `offset` puts a page past the cap one request
# away rather than out of reach, and `total` says how many pages there are,
# so an operator paging through an incident is never quietly shown a
# truncated view.
ALERTS_LIST_CAP = 2000


def get_alerts(service, params, body) -> dict:
    filters = _alert_filters(params)
    limit, offset = _page(params, 300, ALERTS_LIST_CAP)
    rows = service.alerts_db.alerts(limit=limit, offset=offset, **filters)
    total = service.alerts_db.count_alerts(**filters)
    return {"alerts": _alerts_rows_json(service, rows), "total": total,
            "limit": limit, "offset": offset}


# The export ceiling. 50,000 is comfortably past anything a real incident
# produces — the alert engine collapses repeats into one row's `count`, so
# 50,000 rows is 50,000 distinct problems, not 50,000 flaps — while still
# bounding the CSV this route builds in memory per request.
ALERTS_EXPORT_CAP = 50000


def get_alerts_export(service, params, body) -> dict:
    filters = _alert_filters(params)
    rows = service.alerts_db.alerts(limit=ALERTS_EXPORT_CAP + 1, offset=0, **filters)
    truncated = len(rows) > ALERTS_EXPORT_CAP
    rows = rows[:ALERTS_EXPORT_CAP]
    alerts = _alerts_rows_json(service, rows)
    header = ["id", "severity_name", "state", "entity_label", "message",
             "rule_name", "count", "opened_ts", "last_ts",
             "acked_by", "acked_ts", "resolved_by", "resolved_ts"]
    csv_rows = [[a.get(key) for key in header] for a in alerts]
    return _csv_response("alerts", header, csv_rows, truncated=truncated,
                         cap=ALERTS_EXPORT_CAP)


def get_alert(service, params, body, alert_id) -> dict:
    row = _require(service.alerts_db.alert(alert_id), "alert")
    alert = _alert_json(row, _alert_device_ids(service, [row]))
    rule = service.alerts_db.rule(row["rule_id"])
    alert["rule_name"] = rule["name"] if rule else ""
    # What a per-rule mute is keyed on, for the detail pane's Mute alert.
    alert["rule_key"] = (rule["key"] or "") if rule else ""
    notifications = service.alerts_db.notifications_for(alert_id)
    return {"alert": alert, "notifications": [
        {"id": n["id"], "kind": n["kind"], "ts": n["ts"], "to_addr": n["to_addr"],
         "subject": n["subject"], "ok": bool(n["ok"]), "error": n["error"]}
        for n in notifications]}


def post_alert_ack(service, params, body, alert_id) -> dict:
    _require(service.alerts_db.alert(alert_id), "alert")
    service.alerts_db.acknowledge(alert_id, params.get("_username", ""),
                                  str(body.get("note", "")))
    _audit(service, params, "alert.ack", target=str(alert_id))
    return {"ok": True}


def post_alert_unack(service, params, body, alert_id) -> dict:
    _require(service.alerts_db.alert(alert_id), "alert")
    service.alerts_db.unacknowledge(alert_id)
    _audit(service, params, "alert.unack", target=str(alert_id))
    return {"ok": True}


def post_alert_resolve(service, params, body, alert_id) -> dict:
    _require(service.alerts_db.alert(alert_id), "alert")
    service.alerts_db.resolve(alert_id, params.get("_username", ""))
    _audit(service, params, "alert.resolve", target=str(alert_id))
    return {"ok": True}


def _mute_json(row) -> dict:
    """One mute row, with the pair a device_rule id encodes spelled out."""
    pair = (alertsdb.split_device_rule(row["entity_id"])
            if row["entity_kind"] == alertsdb.DEVICE_RULE_KIND else None)
    if pair is not None:
        device_id, rule_key = pair
    else:
        rule_key = None
        try:
            device_id = int(row["entity_id"])
        except (TypeError, ValueError):
            device_id = None
    return {"entity_kind": row["entity_kind"], "entity_id": row["entity_id"],
            "device_id": device_id, "rule_key": rule_key,
            "until_ts": row["until_ts"], "created_ts": row["created_ts"],
            "created_by": row["created_by"], "reason": row["reason"]}


def _mute_entity(service, body, require_rule: bool) -> tuple[str, str, int]:
    """The (kind, id, device id) a mute request names, refusing anything the engine would not actually check. `require_rule` is off on DELETE, so a rule deleted under a live mute is still liftable."""
    kind = str(body.get("entity_kind", "device")).strip() or "device"
    if kind not in ("device", alertsdb.DEVICE_RULE_KIND):
        # The column is general, so a per-interface or per-AP mute later
        # needs no migration; nothing else is muteable today.
        raise ValueError("Only devices can be muted")
    rule_key = str(body.get("rule_key", "") or "").strip()
    entity_id = str(body.get("entity_id", "")).strip()
    if kind == alertsdb.DEVICE_RULE_KIND and not rule_key:
        pair = alertsdb.split_device_rule(entity_id)
        if pair is None:
            raise ValueError("A device and a rule are required")
        entity_id, rule_key = str(pair[0]), pair[1]
    if not entity_id:
        raise ValueError("A device is required")
    try:
        device_id = int(entity_id)
    except (TypeError, ValueError):
        raise ValueError("A device is required")
    _require(service.nodes_db.device(device_id), "device")
    if not rule_key:
        return "device", str(device_id), device_id
    if require_rule and service.alerts_db.rule_by_key(rule_key) is None:
        raise ValueError(f"No rule with key {rule_key}")
    return (alertsdb.DEVICE_RULE_KIND,
            alertsdb.device_rule_entity(device_id, rule_key), device_id)


def get_alerts_mutes(service, params, body) -> dict:
    return {"mutes": [_mute_json(row) for row in service.alerts_db.mutes()]}


def post_alerts_mute(service, params, body) -> dict:
    kind, entity_id, device_id = _mute_entity(service, body, require_rule=True)
    try:
        hours = float(body.get("hours", 1))
    except (TypeError, ValueError):
        raise ValueError("Mute duration must be a number of hours")
    if hours <= 0:
        raise ValueError("Mute duration must be more than zero")
    row = service.alerts_db.mute(kind, entity_id, hours,
                                 by=params.get("_username", ""),
                                 reason=str(body.get("reason", "")))
    # Device id spelled out, since entity_id may be an unreadable joined device+rule_key.
    _audit(service, params, "alert.mute", target=f"{kind}:{entity_id}",
           detail=f"device {device_id}: {hours:g}h: "
                  f"{str(body.get('reason', ''))}")
    return {"mute": _mute_json(row)}


def delete_alerts_mute(service, params, body) -> dict:
    kind, entity_id, device_id = _mute_entity(service, body, require_rule=False)
    lifted = service.alerts_db.unmute(kind, entity_id)
    _audit(service, params, "alert.unmute", target=f"{kind}:{entity_id}",
           detail=f"device {device_id}")
    return {"lifted": lifted}


def _bulk_silence_device_ids(service, body) -> list[str]:
    """Every device id a bulk silencing request names — an explicit list, a
    device group's whole current membership, or both together, refusing
    (like _mute_entity above) a request that would end up silencing
    nothing. Shared by bulk mute and bulk maintenance mode: the two take the
    same scope, and only differ in what they then do with it."""
    # Optional here: a group_id alone is already a complete request.
    wanted = set(_bulk_ids(body, "device_ids", required=False))
    group_id = body.get("group_id")
    if group_id:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            raise ValueError("group_id must be a number")
        wanted |= {int(row["id"]) for row in
                  service.nodes_db.devices(device_group_id=group_id)}
    if not wanted:
        raise ValueError("device_ids and/or group_id is required, naming at "
                         "least one device")
    # Re-checked on the union: group membership is added after the cap.
    if len(wanted) > BULK_DEVICE_ID_MAX:
        raise ValueError(
            f"Too many devices in one request: {len(wanted)}, limit is "
            f"{BULK_DEVICE_ID_MAX}. Send them in batches.")
    present = {row["id"] for row in service.nodes_db.devices_by_ids(wanted)}
    ids = _require([str(i) for i in wanted if i in present], "device(s)")
    return sorted(ids, key=int)


def post_alerts_bulk_mute(service, params, body) -> dict:
    """One call, many devices — the planned-cutover case the ad-hoc mute
    route makes hundreds of calls. Same ad-hoc cap (MAX_MUTE_HOURS) as a
    single mute; a longer silence is what a maintenance WINDOW is for."""
    entity_ids = _bulk_silence_device_ids(service, body)
    try:
        hours = float(body.get("hours", 1))
    except (TypeError, ValueError):
        raise ValueError("Mute duration must be a number of hours")
    if hours <= 0:
        raise ValueError("Mute duration must be more than zero")
    reason = str(body.get("reason", ""))
    rows = service.alerts_db.mute_many("device", entity_ids, hours,
                                       by=params.get("_username", ""),
                                       reason=reason)
    _audit(service, params, "alert.mute_bulk",
          detail=f"{len(rows)} device(s), {hours:g}h: {reason}")
    return {"muted": len(rows), "mutes": [_mute_json(r) for r in rows]}


# ------------------------------------------------ device maintenance mode


def _maintenance_device(service, body):
    """The device row a maintenance request names, refused unless Nodes
    actually has it — the same reasoning _mute_entity gives: a suppression that
    silences nothing is worse than an error, because the operator walks away
    believing it worked.

    A body carrying `hours` or `until_ts` is refused rather than ignored.
    Silently dropping either is how somebody ends up believing they set a
    four-hour maintenance, so the message names the mechanism that does what
    they asked for instead.
    """
    if "hours" in body:
        raise ValueError("Maintenance mode has no duration — it stays on "
                         "until someone turns it off. Use a mute for a "
                         "1-hour to 7-day silence.")
    if "until_ts" in body:
        raise ValueError("Maintenance mode has no end time — it stays on "
                         "until someone turns it off. Use a maintenance "
                         "window for a planned span.")
    raw = str(body.get("device_id", "")).strip()
    if not raw:
        raise ValueError("A device is required")
    try:
        device_id = int(raw)
    except (TypeError, ValueError):
        raise ValueError("device_id must be a device id")
    return _require(service.nodes_db.device(device_id), "device")


def get_alerts_maintenance(service, params, body) -> dict:
    return {"maintenance": [_maintenance_json(row) for row in
                            service.alerts_db.maintenance_device_ids().values()]}


def post_alerts_maintenance(service, params, body) -> dict:
    """Put a device into indefinite maintenance mode. Idempotent: a device
    already in it comes back with the period it is already in, untouched,
    rather than a restarted clock and a rewritten owner."""
    device = _maintenance_device(service, body)
    reason = str(body.get("reason", ""))
    already = service.alerts_db.open_maintenance(device["id"]) is not None
    row = service.alerts_db.set_maintenance(
        device["id"], by=params.get("_username", ""), reason=reason)
    if not already:
        _audit(service, params, "alert.maintenance_on",
              target=f"device:{device['ip']}", detail=reason)
    return {"maintenance": _maintenance_json(row), "already": already}


def delete_alerts_maintenance(service, params, body) -> dict:
    """Body-on-DELETE, matching delete_alerts_mute — the device is the
    request, and this route has no id of its own to put in the path."""
    device = _maintenance_device(service, body)
    cleared = service.alerts_db.clear_maintenance(
        device["id"], by=params.get("_username", ""))
    if cleared:
        _audit(service, params, "alert.maintenance_off",
              target=f"device:{device['ip']}")
    return {"cleared": cleared}


def post_alerts_bulk_maintenance(service, params, body) -> dict:
    """One call, many devices, in or out — `clear` picks which. Two
    directions on one route rather than two, because the scope resolution
    (_bulk_silence_device_ids) is the whole of the work and a bulk selection
    is turned on and off from the same bar."""
    if "hours" in body or "until_ts" in body:
        raise ValueError("Maintenance mode has no duration or end time — it "
                         "stays on until someone turns it off. Use a mute or "
                         "a maintenance window for a bounded silence.")
    device_ids = _bulk_silence_device_ids(service, body)
    clear = bool(body.get("clear"))
    reason = str(body.get("reason", ""))
    username = params.get("_username", "")
    # One lock hold and one commit for the whole selection: the per-device
    # loop was two alerts.db statements and a commit per device, on the
    # request thread, while the alert engine ticked against the same file.
    if clear:
        changed = service.alerts_db.clear_maintenance_many(device_ids, by=username)
    else:
        changed = service.alerts_db.set_maintenance_many(device_ids, by=username,
                                                         reason=reason)
    _audit(service, params, "alert.maintenance_bulk",
          target=f"{len(device_ids)} devices",
          detail=f"{'off' if clear else 'on'}, {changed} changed: {reason}")
    return {"devices": len(device_ids), "changed": changed, "cleared": clear}


# --------------------------------------------------- maintenance windows

def _window_json(row) -> dict:
    try:
        device_ids = json.loads(row["scope_device_ids"] or "[]")
    except (TypeError, ValueError):
        device_ids = []
    return {
        "id": row["id"], "name": row["name"], "scope_kind": row["scope_kind"],
        "scope_group_id": row["scope_group_id"], "scope_device_ids": device_ids,
        "start_ts": row["start_ts"], "end_ts": row["end_ts"],
        "recurrence": row["recurrence"], "created_ts": row["created_ts"],
        "created_by": row["created_by"], "reason": row["reason"],
        # So the list can show "active now" without every viewer re-deriving
        # is_window_active from start/end/recurrence itself.
        "active": is_window_active(row),
    }


def get_alerts_windows(service, params, body) -> dict:
    return {"windows": [_window_json(r) for r in service.alerts_db.windows()]}


def _window_body_fields(service, body) -> dict:
    """The maintenance_windows columns a create/update request supplied,
    validated against Nodes where the field names something Nodes owns —
    alertsdb has no nodesdb of its own to check a group or device id is
    real, so that check happens here, once, for both routes below."""
    fields: dict = {}
    if "name" in body:
        fields["name"] = str(body["name"])
    if "start_ts" in body:
        try:
            fields["start_ts"] = float(body["start_ts"])
        except (TypeError, ValueError):
            raise ValueError("start_ts must be a number")
    if "end_ts" in body:
        try:
            fields["end_ts"] = float(body["end_ts"])
        except (TypeError, ValueError):
            raise ValueError("end_ts must be a number")
    if "recurrence" in body:
        fields["recurrence"] = body["recurrence"] or None
    if "reason" in body:
        fields["reason"] = str(body["reason"])
    if "scope_kind" in body:
        scope_kind = str(body["scope_kind"])
        fields["scope_kind"] = scope_kind
        if scope_kind == "group":
            group_id = body.get("scope_group_id")
            if not group_id or not service.nodes_db.device_group(int(group_id)):
                raise ValueError("No such device group")
            fields["scope_group_id"] = int(group_id)
            fields["scope_device_ids"] = None
        elif scope_kind == "devices":
            # Optional here: post_alerts_window's own loop refuses an empty one.
            wanted = set(_bulk_ids(body, "scope_device_ids", required=False))
            present = {row["id"] for row in service.nodes_db.devices_by_ids(wanted)}
            missing = wanted - present
            if missing:
                raise ValueError(f"No such device(s): {sorted(missing)}")
            fields["scope_group_id"] = None
            fields["scope_device_ids"] = sorted(wanted)
    return fields


def post_alerts_window(service, params, body) -> dict:
    fields = _window_body_fields(service, body)
    for required in ("name", "scope_kind", "start_ts", "end_ts"):
        if required not in fields:
            raise ValueError(f"{required} is required")
    window_id = service.alerts_db.add_window(
        fields["name"], fields["scope_kind"], fields["start_ts"], fields["end_ts"],
        scope_group_id=fields.get("scope_group_id"),
        scope_device_ids=fields.get("scope_device_ids"),
        recurrence=fields.get("recurrence"), created_by=params.get("_username", ""),
        reason=fields.get("reason", ""))
    _audit(service, params, "alert.window_create", target=fields["name"],
          detail=fields["scope_kind"])
    return {"window": _window_json(service.alerts_db.window(window_id))}


def put_alerts_window(service, params, body, window_id) -> dict:
    _require(service.alerts_db.window(window_id), "maintenance window")
    fields = _window_body_fields(service, body)
    service.alerts_db.update_window(window_id, **fields)
    _audit(service, params, "alert.window_update", target=str(window_id))
    return {"window": _window_json(service.alerts_db.window(window_id))}


def delete_alerts_window(service, params, body, window_id) -> dict:
    removed = service.alerts_db.remove_window(window_id)
    _audit(service, params, "alert.window_delete", target=str(window_id))
    return {"removed": removed}


def post_alerts_window_end(service, params, body, window_id) -> dict:
    _require(service.alerts_db.window(window_id), "maintenance window")
    changed = service.alerts_db.end_window_now(window_id)
    _audit(service, params, "alert.window_end", target=str(window_id))
    return {"window": _window_json(service.alerts_db.window(window_id)),
            "changed": changed}


def post_alerts_ack_all(service, params, body) -> dict:
    n = service.alerts_db.acknowledge_all(params.get("_username", ""))
    _audit(service, params, "alert.ack_all", detail=f"{n} alert(s)")
    return {"acknowledged": n}


def _bulk_alert_ids(body) -> list[int]:
    return _bulk_ids(body, "alert_ids", noun="alerts")


def post_alerts_bulk_ack(service, params, body) -> dict:
    alert_ids = _bulk_alert_ids(body)
    n = service.alerts_db.acknowledge_many(alert_ids, params.get("_username", ""))
    _audit(service, params, "alert.ack_bulk", detail=f"{n} of {len(alert_ids)}")
    return {"acknowledged": n}


def post_alerts_bulk_unack(service, params, body) -> dict:
    alert_ids = _bulk_alert_ids(body)
    n = service.alerts_db.unacknowledge_many(alert_ids)
    _audit(service, params, "alert.unack_bulk", detail=f"{n} of {len(alert_ids)}")
    return {"unacknowledged": n}


def post_alerts_bulk_resolve(service, params, body) -> dict:
    alert_ids = _bulk_alert_ids(body)
    n = service.alerts_db.resolve_many(alert_ids, params.get("_username", ""))
    _audit(service, params, "alert.resolve_bulk", detail=f"{n} of {len(alert_ids)}")
    return {"resolved": n}


def get_alerts_rules(service, params, body) -> dict:
    return {"rules": [_rule_json(r) for r in service.alerts_db.rules()]}


# The three rule kinds alertrules.evaluate_threshold decides, and so the
# three whose threshold/clear_threshold have to mean something.
_THRESHOLD_RULE_KINDS = ("threshold", "dhcp_threshold", "netpath_threshold")


def _validated_threshold_fields(kind: str, row, fields: dict, key: str = "") -> dict:
    """Refuse a threshold rule that can never raise, and refuse a threshold
    or clear threshold that is not a finite number.

    Nothing checked either field before, on the create route or the update
    route, and the Edit Rule dialog reached both with `Number(input.value)`
    — which is 0 for an empty box, not null. Every other optional numeric
    field in that same dialog maps blank to null explicitly and says so in a
    comment; these two did not. Clearing the Threshold box therefore saved
    `threshold = 0`, and the breach test is `value >= threshold`, so on the
    next tick every device reporting that metric breached at once: the
    fleet-wide page storm the rollup and digest machinery exists to spare
    the operator from, self-inflicted, and entirely legitimate as far as the
    engine could tell. Clearing the Clear threshold box saved
    `clear_threshold = 0`, and the clear test is `value < clear_threshold`,
    which for any metric that is never negative can never be satisfied — the
    alert raised normally and then stayed open forever.

    What is required here is `threshold` alone. A threshold rule without one
    cannot fire at all (alertrules.evaluate_threshold returns "" immediately
    when it is None), so its absence is never anything but a mistake.
    `clear_threshold` is deliberately NOT required: leaving it out is a
    coherent choice — the alert then closes on auto_resolve_after_s, on a
    paired CLEARS occurrence, or by hand — and demanding it would refuse
    rules this application has always accepted. What the blank box used to
    produce was not that coherent choice but a silent, unsatisfiable
    numeric one, and the dialog now sends null for blank, which means the
    coherent thing.

    Zero is not refused. It is a perfectly good threshold for a metric that
    can go negative — an environmental temperature sensor — so rejecting it
    outright would be wrong; what was wrong was inferring it from an empty
    box. `clear_threshold == threshold` also stays legal: several shipped
    rules (ups_on_battery, netpath_unreachable) set them equal on purpose,
    for quantised metrics that do not hover at a boundary the way a
    continuous one does."""
    if kind not in _THRESHOLD_RULE_KINDS:
        return fields
    rule_key = key or (row["key"] if row is not None and "key" in row.keys() else "")
    if rule_key in alertrules.PUBLISHED_THRESHOLD_RULES:
        # An optic power rule is judged against the levels the PORT publishes,
        # so neither column means anything on it. Handled here rather than
        # only in alertsdb so the "a threshold rule needs a threshold" refusal
        # below never fires on a rule that is supposed to have none, and so
        # the 400 an operator sees says which rule and why. alertsdb refuses
        # a number again on its own account — this is the message, not the
        # guard.
        if fields.get("threshold") is not None \
                or fields.get("clear_threshold") is not None:
            raise ValueError(
                f"'{rule_key}' is judged against the limits each port's own "
                "optic publishes, so a threshold set here would be ignored. "
                "There is nothing to set: a port alerts where its switch "
                "publishes limits and nowhere else.")
        fields.pop("threshold", None)
        fields.pop("clear_threshold", None)
    # Only what this request is actually setting. A rule already stored is
    # not this request's to validate: reading a key the body never mentioned
    # back and refusing on it would make an unrelated edit — disabling a
    # noisy rule with a NULL threshold, say — impossible, and would copy
    # untouched stored values back into `fields` to be rewritten on every
    # save.
    #
    # `threshold` is still required when the request supplies it as null, or
    # when a rule is created or changed INTO a threshold kind: those are the
    # paths that produce a rule that can never raise at all.
    creating_or_retyping = row is None or "kind" in fields
    for name in ("threshold", "clear_threshold"):
        if name in fields:
            value = fields[name]
        elif creating_or_retyping and row is not None and name in row.keys():
            value = row[name]
        elif creating_or_retyping:
            value = None
        else:
            continue
        if value is None:
            if name == "threshold":
                raise ValueError(
                    f"A {kind} rule needs a threshold; without one the rule "
                    f"can never raise an alert.")
            continue
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name.replace('_', ' ')} must be a number") from exc
        if not math.isfinite(number):
            raise ValueError(f"{name.replace('_', ' ')} must be a finite number")
        fields[name] = number
    stored_comparison = (row["comparison"] if row is not None
                         and "comparison" in row.keys() else "above") or "above"
    comparison = str(fields.get("comparison", stored_comparison) or "above")
    if comparison not in ("above", "below"):
        raise ValueError("comparison must be 'above' or 'below'")
    if "comparison" in fields:
        fields["comparison"] = comparison
    # A clear threshold on the wrong side is an alert that can never close,
    # and `comparison` decides which side is wrong, so a flipped rule is
    # refused here rather than discovered as a stuck alert later.
    # allow_equal because several shipped rules set the two equal on
    # purpose; see _check_threshold_direction's docstring.
    reference = {
        "key": (row["key"] if row is not None else key),
        "threshold": (row["threshold"] if row is not None else None),
        "clear_threshold": (row["clear_threshold"] if row is not None else None),
    }
    alertsdb._check_threshold_direction(
        reference, fields.get("threshold"), fields.get("clear_threshold"),
        comparison=comparison, allow_equal=True)
    return fields


ALERT_RULE_KEY_MAX = 80


def post_alerts_rule(service, params, body) -> dict:
    key = str(body.get("key", "")).strip()
    name = str(body.get("name", "")).strip()
    kind = str(body.get("kind", "")).strip()
    source_kind = str(body.get("source_kind", "") or "")
    if not key or not name or not kind:
        raise ValueError("key, name and kind are all required")
    # A rule key is a stable identifier, not prose: it is matched against
    # alertrules' own key constants and written into the page as an
    # attribute, so anything outside this charset is a mistake at best.
    if len(key) > ALERT_RULE_KEY_MAX or not all(
            char.isascii() and (char.isalnum() or char in "_-.") for char in key):
        raise ValueError(
            "A rule key may use letters, digits, underscore, hyphen and dot "
            f"only, up to {ALERT_RULE_KEY_MAX} characters")
    if kind not in ("device_event", "interface_event", "threshold",
                    "dhcp_threshold", "dhcp_event", "netpath_threshold",
                    "netpath_event", "trap", "syslog", "ipam",
                    "wireless_event", "system"):
        raise ValueError("Unrecognized rule kind")
    if service.alerts_db.rule_by_key(key):
        raise ValueError(f"A rule with key '{key}' already exists")
    fields = _pick(body, ("severity", "enabled", "device_filter", "threshold",
                          "clear_threshold", "comparison", "for_polls",
                          "for_seconds", "template_id", "auto_resolve_after_s",
                          "notify", "notify_sms"))
    fields = _validated_threshold_fields(kind, None, fields, key=key)
    rule_id = service.alerts_db.add_rule(key, name, kind, source_kind, **fields)
    service.log.add(ALERTS_CATEGORY, f"Added alert rule {name}")
    _audit(service, params, "alert_rule.create", target=key,
          detail=f"kind={kind}, severity={fields.get('severity', '')}")
    return {"id": rule_id}


# threshold/clear_threshold/enabled first in an update's audit detail — the
# "changed the threshold from 90 to 99" a post-mortem asks for — so if the
# diff overflows the 512-char clip appdb.audit applies, these three survive
# rather than whatever was last in the request body.
_ALERT_RULE_AUDIT_PRIORITY = ("threshold", "clear_threshold", "enabled")


def put_alerts_rule(service, params, body, rule_id) -> dict:
    row = _require(service.alerts_db.rule(rule_id), "rule")
    allowed_keys = ("name", "severity", "enabled", "device_filter", "threshold",
                    "clear_threshold", "comparison", "for_polls", "for_seconds",
                    "template_id", "flap_window_s", "flap_min_transitions",
                    "auto_resolve_after_s", "notify", "notify_sms")
    if not row["is_builtin"]:
        allowed_keys = allowed_keys + ("kind", "source_kind")
    fields = _pick(body, allowed_keys)
    # The kind an update leaves in place, not the one it arrived with: a
    # built-in cannot change kind at all, and a custom rule that is changing
    # kind has to satisfy the rules of the kind it is becoming.
    fields = _validated_threshold_fields(
        str(fields.get("kind", row["kind"]) or ""), row, fields)
    service.alerts_db.update_rule(rule_id, **fields)
    if fields:
        ordered = dict(sorted(
            fields.items(),
            key=lambda kv: (_ALERT_RULE_AUDIT_PRIORITY.index(kv[0])
                            if kv[0] in _ALERT_RULE_AUDIT_PRIORITY
                            else len(_ALERT_RULE_AUDIT_PRIORITY))))
        detail = _audit_diff(row, ordered)
        if detail:
            _audit(service, params, "alert_rule.update", target=row["name"], detail=detail)
    return {"ok": True}


def delete_alerts_rule(service, params, body, rule_id) -> dict:
    row = _require(service.alerts_db.rule(rule_id), "rule")
    if row["is_builtin"]:
        raise ValueError("A built-in rule cannot be deleted — disable it instead")
    # rules.id is alerts.rule_id's ON DELETE CASCADE parent, so deleting a
    # rule with history deletes that history too. remove_rule's own WHERE
    # clause refuses this as well; this check is what turns that silent
    # no-op into a message naming the count and offering `enabled` as the
    # alternative.
    count = service.alerts_db.alert_count_for_rule(rule_id)
    if count:
        raise ValueError(
            f"{row['name']} has raised {count} alert(s) — deleting it would "
            f"delete their history too. Disable it instead to stop it firing "
            f"without losing what it already recorded.")
    service.alerts_db.remove_rule(rule_id)
    service.log.add(ALERTS_CATEGORY, f"Removed alert rule {row['name']}")
    _audit(service, params, "alert_rule.delete", target=row["name"])
    return {"ok": True}


def get_alerts_templates(service, params, body) -> dict:
    return {"templates": [_template_json(r, with_tokens=True)
                          for r in service.alerts_db.templates()]}


def post_alerts_template(service, params, body) -> dict:
    key = str(body.get("key", "")).strip()
    name = str(body.get("name", "")).strip()
    subject = str(body.get("subject", ""))
    template_body = str(body.get("body", ""))
    if not key or not name or not subject or not template_body:
        raise ValueError("key, name, subject and body are all required")
    if service.alerts_db.template_by_key(key):
        raise ValueError(f"A template with key '{key}' already exists")
    template_id = service.alerts_db.add_template(
        key, name, subject, template_body, is_html=bool(body.get("is_html")))
    service.log.add(ALERTS_CATEGORY, f"Added email template {name}")
    return {"id": template_id}


def put_alerts_template(service, params, body, template_id) -> dict:
    _require(service.alerts_db.template(template_id), "template")
    fields = _pick(body, ("name", "subject", "body", "is_html"))
    service.alerts_db.update_template(template_id, **fields)
    return {"ok": True}


def post_alerts_template_reset(service, params, body, template_id) -> dict:
    row = _require(service.alerts_db.template(template_id), "template")
    if not row["is_builtin"]:
        raise ValueError("Only a built-in template has shipped text to reset to")
    service.alerts_db.reset_template(template_id)
    return {"ok": True}


def delete_alerts_template(service, params, body, template_id) -> dict:
    row = _require(service.alerts_db.template(template_id), "template")
    if row["is_builtin"]:
        raise ValueError(
            "A built-in template cannot be deleted — a rule referencing "
            "it would otherwise lose its wording silently")
    service.alerts_db.remove_template(template_id)
    service.log.add(ALERTS_CATEGORY, f"Removed email template {row['name']}")
    return {"ok": True}


def post_alerts_template_preview(service, params, body, template_id) -> dict:
    """Renders against a real recent alert (alert_id in the body) or a
    synthetic sample when none is given, so Preview works even before any
    alert of that kind has ever fired. Sends nothing.

    `subject`/`body`/`is_html` in the request are an in-progress EDIT, not
    yet saved — when present they render instead of the stored template's
    own values, falling back to the stored row for whichever of the three
    is absent. This is what lets a Preview button work against whatever is
    currently typed into the edit form without saving first: the template
    row itself is never read for writing here, only for whichever of these
    three fields the caller did not send a draft for.
    """
    from ... import alertmail

    row = _require(service.alerts_db.template(template_id), "template")
    subject = str(body["subject"]) if "subject" in body else row["subject"]
    template_body = str(body["body"]) if "body" in body else row["body"]
    is_html = bool(body["is_html"]) if "is_html" in body else bool(row["is_html"])
    alert_id = body.get("alert_id")
    if alert_id:
        alert_row = _require(service.alerts_db.alert(int(alert_id)), "alert")
        rule_row = service.alerts_db.rule(alert_row["rule_id"])
        context = alertmail.build_context(alert_row, rule_row)
    else:
        now = time.time()
        # The sample is a RESOLVED alert, opened a couple of hours ago: the
        # recovery template's whole subject is how long something was down,
        # and a sample with no resolution renders that sentence as blanks and
        # makes a correct template look broken.
        fake_alert = {"entity_label": "sample-device (10.20.3.5)",
                     "entity_id": "10.20.3.5", "message": "This is a sample alert.",
                     "detail": "", "severity": 4, "count": 1,
                     "opened_ts": now - 8040, "last_ts": now - 300,
                     "resolved_ts": now}
        context = alertmail.build_context(
            fake_alert, {"name": "Sample rule"},
            extra={"metric_label": "CPU", "value": "95%", "threshold": "90%",
                  "previous_uptime": "12d 4h", "current_uptime": "0d 0h 2m",
                  "trap_name": "coldStart", "trap_oid": "1.3.6.1.6.3.1.1.5.1",
                  "varbinds": "(sample)",
                  # Only the recovery template is ever sent as a resolution.
                  **({"severity_tag": alertmail.RECOVER_TAG,
                      "recover_tag": alertmail.RECOVER_TAG}
                     if row["key"] == "device_up" else
                     {"severity_tag": "[WARNING]", "recover_tag": ""})})
    return {"subject": alertmail.render(subject, context),
            "body": alertmail.render(template_body, context),
            "is_html": is_html}


def post_alerts_smtp_credential(service, params, body) -> dict:
    password = str(body.get("password", ""))
    if not password:
        raise ValueError("A password is required")
    try:
        encrypted = _encrypt_secret(password, (
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. A test email can still use a password typed "
            "into Test each time; nothing will be saved here."))
    finally:
        password = None
    service.alerts_db.set_smtp_credential(encrypted)
    service.log.add(ALERTS_CATEGORY, "Stored the SMTP credential")
    _audit(service, params, "credential.store", target="smtp")
    return {"ok": True}


def delete_alerts_smtp_credential(service, params, body) -> dict:
    return _clear_credential(
        service, params, clear=service.alerts_db.clear_smtp_credential,
        category=ALERTS_CATEGORY, message="Cleared the stored SMTP credential",
        target="smtp")


# The body fields that decide WHERE the test email goes and how the
# connection is protected. Overriding any of them while letting the STORED
# password be used would walk that credential out to any host and port on
# the network (`AUTH PLAIN` in the clear, to a listener of the caller's
# choosing). Testing an unsaved host is still allowed — with the password
# for that host typed in beside it.
_SMTP_DESTINATION_KEYS = ("smtp_host", "smtp_port", "smtp_security",
                          "smtp_verify_cert")

# Transports that actually protect a password on the wire. Anything else
# ("none", "plain", a typo) sends AUTH over cleartext TCP.
_SMTP_SECURE = ("ssl", "starttls")


def post_alerts_smtp_test(service, params, body) -> dict:
    """Sends a real test email, using in-progress-edit SMTP settings from
    the body when present, else the saved ones — the same "test what's
    typed before saving" idiom as IPAM's DHCP test and the SNMP Trap/
    Syslog "send test" buttons.

    The stored password is only ever sent to the stored destination. That
    is the whole of CREDENTIAL-SECURITY.md's promise that a stored
    credential can only be used or replaced, and this endpoint used to
    break it: every destination field was taken from the request body while
    the password came from the database.
    """
    from ... import alertmail, dpapi

    to_addr = str(body.get("to", "")).strip()
    if not to_addr:
        raise ValueError("A recipient address is required")
    settings = dict(service.alerts_settings)
    overridden = [key for key in _SMTP_DESTINATION_KEYS
                  if key in body
                  and str(body[key]) != str(settings.get(key, ""))]
    for key in ("smtp_host", "smtp_port", "smtp_security", "smtp_verify_cert",
               "smtp_username", "smtp_from", "smtp_from_name", "smtp_timeout_s"):
        if key in body:
            settings[key] = body[key]
    password = body.get("password")
    if password is None and overridden:
        raise ValueError(
            "This test changes " + ", ".join(overridden) + ", so it cannot use "
            "the saved password: type the password for that server into the "
            "test instead. The saved one is only ever sent to the saved "
            "server.")
    if password is None:
        blob = service.alerts_db.smtp_password_enc()
        if blob:
            try:
                password = dpapi.unprotect(blob).decode("utf-8")
            except Exception:
                password = None
    if password and str(settings.get("smtp_security", "")).lower() not in _SMTP_SECURE:
        if not service.settings.get("smtp_allow_plain_auth", False):
            raise ValueError(
                f"Sending a password over "
                f"'{settings.get('smtp_security') or 'none'}' would put it on "
                f"the wire in the clear. Use ssl or starttls, or leave the "
                f"password blank, or turn on \"Allow SMTP AUTH without "
                f"transport security\" in Settings.")
    if password and settings.get("smtp_verify_cert") is False:
        raise ValueError(
            "Sending a password to a server whose certificate is not "
            "verified defeats the point of the encryption. Turn certificate "
            "verification back on, or leave the password blank.")
    subject = "Alerts test email"
    body_text = "This is a test email from SappiWhere's Alerts module."
    try:
        alertmail.send(settings, password, [to_addr], subject, body_text)
        ok, error = True, ""
    except Exception as exc:
        ok, error = False, str(exc)
    finally:
        password = None
    service.alerts_db.record_notification(None, "test", to_addr, subject, ok, error)
    return {"ok": ok, "error": error} if not ok else {"ok": True}


def post_alerts_sms_credential(service, params, body) -> dict:
    """Stores the secret bound to (auth_mode, Account SID, API Key SID): the
    values in the body (the dialog sends what is typed, saved a moment
    later) or else the saved settings."""
    from ... import alertmail

    token = str(body.get("token", ""))
    if not token:
        raise ValueError("A token is required")
    saved_settings = service.alerts_settings
    auth_mode = str(body.get(
        "auth_mode", saved_settings.get("twilio_auth_mode", "auth_token")) or "auth_token").strip()
    if auth_mode not in ("auth_token", "api_key"):
        token = None
        raise ValueError("Twilio authentication method must be auth_token or api_key")
    account_sid = str(body.get(
        "account_sid", saved_settings.get("twilio_account_sid", "")) or "").strip()
    if not alertmail._ACCOUNT_SID.match(account_sid):
        token = None
        raise ValueError("Enter the Twilio Account SID (AC followed by 32 hex "
                         "characters) before storing its auth token")
    api_key_sid = str(body.get(
        "api_key_sid", saved_settings.get("twilio_api_key_sid", "")) or "").strip()
    if auth_mode == "api_key" and not alertmail._API_KEY_SID.match(api_key_sid):
        token = None
        raise ValueError("Enter the Twilio API Key SID (SK followed by 32 hex "
                         "characters) before storing its secret")
    try:
        encrypted = _encrypt_secret(token, (
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only; nothing will be saved here."))
    finally:
        token = None
    service.alerts_db.set_sms_credential(
        encrypted, account_sid, auth_mode, api_key_sid if auth_mode == "api_key" else "")
    service.log.add(ALERTS_CATEGORY, "Stored the Twilio API key secret"
                    if auth_mode == "api_key" else "Stored the Twilio auth token")
    _audit(service, params, "credential.store", target="sms")
    return {"ok": True}


def delete_alerts_sms_credential(service, params, body) -> dict:
    return _clear_credential(
        service, params, clear=service.alerts_db.clear_sms_credential,
        category=ALERTS_CATEGORY, message="Cleared the stored Twilio credential",
        target="sms")


def post_alerts_engine(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.alerts_settings["enabled"] = True
        service.alerts_db.save_settings({"enabled": True})
        service.alert_engine.start()
    elif action == "stop":
        service.alerts_settings["enabled"] = False
        service.alerts_db.save_settings({"enabled": False})
        service.alert_engine.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.alert_engine.running,
            "status": service.alert_engine.status_text()}


# Per-device overrides of a threshold rule's own numbers (alertsdb's
# device_thresholds table) -- a MAPPER-adjacent feature (a device dialog
# opened from the map wants to tune its own chassis-temperature limits),
# but the data and the rule it overrides are entirely an Alerts concern, so
# it lives beside the rest of the module's routes rather than under
# /api/mapper. See alertsdb.set_device_threshold for the validation this
# wraps: an unknown or non-threshold rule_key, or a clear_threshold on the
# wrong side of threshold, is its ValueError, not a second check here.

def _device_threshold_json(row) -> dict:
    return {"device_id": row["device_id"], "rule_key": row["rule_key"],
            "threshold": row["threshold"], "clear_threshold": row["clear_threshold"],
            "enabled": bool(row["enabled"]), "updated_ts": row["updated_ts"]}


def get_alerts_device_thresholds(service, params, body) -> dict:
    """Every override, or (with `device_id`) just one device's -- the fleet
    Alert Rules page and a single device's dialog share this route the same
    way they share alertsdb.device_thresholds itself."""
    device_id = params.get("device_id")
    rows = service.alerts_db.device_thresholds(int(device_id) if device_id else None)
    return {"device_thresholds": [_device_threshold_json(row) for row in rows]}


def post_alerts_device_threshold(service, params, body) -> dict:
    """Set an override, or (`clear: true`) remove it. One route for both,
    the same shape post_ipam_conflict_resolve-style routes elsewhere in this
    file already use for "do the thing, or undo it" pairs that share every
    other field."""
    if "device_id" not in body:
        raise ValueError("device_id is required")
    device_id = int(body["device_id"])
    rule_key = str(body.get("rule_key", "") or "")
    if not rule_key:
        raise ValueError("rule_key is required")
    if body.get("clear"):
        removed = service.alerts_db.clear_device_threshold(device_id, rule_key)
        _audit(service, params, "alerts.device_threshold.clear", target=str(device_id),
              detail=f"rule_key={rule_key}")
        return {"ok": True, "removed": removed}
    threshold = body.get("threshold")
    clear_threshold = body.get("clear_threshold")
    service.alerts_db.set_device_threshold(
        device_id, rule_key,
        threshold=float(threshold) if threshold is not None else None,
        clear_threshold=float(clear_threshold) if clear_threshold is not None else None,
        enabled=bool(body.get("enabled", True)))
    _audit(service, params, "alerts.device_threshold.set", target=str(device_id),
          detail=f"rule_key={rule_key}")
    return {"ok": True}

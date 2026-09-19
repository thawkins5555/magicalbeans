"""Handlers: wireless controllers and access points."""

from __future__ import annotations

import functools
import time

from ...eventlog import WIRELESS as WIRELESS_CATEGORY
from ...trapdecode import format_ticks

from ._shared import _clear_credential, _community_fields, _csv_response, _csv_time, _may_read_secrets, _pick, _refuse_controller_privacy, _require, _series_bucket_s, _store_v3_credential, _tri, _window


# ---------------------------------------------------------------- wireless

def _controller_json(row, reveal: bool = False) -> dict:
    return {
        "id": row["id"], "name": row["name"], "ip": row["ip"],
        "enabled": bool(row["enabled"]),
        "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        # Same has_credential convention as Nodes' device v3 password —
        # the encrypted blob itself is never sent to the browser.
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "last_poll_ts": row["last_poll_ts"],
        "last_poll_ok": _tri(row["last_poll_ok"]),
        "last_poll_error": row["last_poll_error"],
        "created_ts": row["created_ts"],
    }


# fgWcWtpRadioMode values for a radio that listens rather than serves. Its
# "operating power" describes a receiver, so the figure is not a transmit
# power at all and must not be read as one, averaged into one, or used to
# decide what unit the serving radios beside it are reporting in.
_SCAN_MODES = ("monitor", "sniffer")


def _is_scan_radio(radio) -> bool:
    return radio["mode"] in _SCAN_MODES


def _radio_json(row) -> dict:
    keys = row.keys()
    radio = {
        "radio_id": row["radio_id"], "channel": row["channel"],
        # Kept named for the MIB's own column, and always raw: whatever unit
        # the reader decides on, the number the agent sent stays visible so
        # the decision can be checked against the controller.
        "operating_power_dbm": row["operating_power_dbm"],
        "mode": (row["mode"] if "mode" in keys else None) or "",
        "station_count": row["station_count"],
        # channel_width has no column of its own; joined through the AP's profile name.
        "bssid": (row["bssid"] if "bssid" in keys else None) or "",
        "channel_width": (row["channel_width"] if "channel_width" in keys else None) or "",
    }
    # Named for what it is rather than converted into a percentage of
    # something: a scanning radio has no transmit power to express in any
    # unit, and 51 was never 51% of anything either.
    radio["is_scan"] = _is_scan_radio(radio)
    return radio


def _power_unit(service, powers) -> str:
    """How to read fgWcWtpSessionRadioOperatingPower for one controller.

    The MIB documents the column as dBm, but FortiOS is observed to put its
    0-100 tx-power *level* there instead — which is why a FortiAP reports 51
    for a radio that cannot physically exceed about 20 dBm. Rather than
    hard-coding either reading, this looks at what the controller actually
    returns: any value above a plausible dBm ceiling means the whole column
    is a percentage, since no radio in the same chassis switches units.
    Decided per controller, not per radio, so one AP cannot flip the label
    on its neighbours.

    `powers` must already exclude scanning radios. Feeding a monitor radio's
    receive figure in here was a real bug: one scanner reporting 51 flipped
    an entire controller's column to "% level", so a FAP-231F's serving
    radios at a genuine 17 and 20 dBm were relabelled as percentages.
    """
    from ...nodeoids import MAX_PLAUSIBLE_DBM

    configured = str(service.wireless_settings.get("radio_power_unit", "auto"))
    if configured in ("dbm", "percent"):
        return configured
    return "percent" if any(p > MAX_PLAUSIBLE_DBM for p in powers) else "dbm"


def _ap_uptime_s(row):
    """fgWcWtpSessionWtpUpTime aged forward from the poll that read it."""
    ticks = row["uptime_ticks"]
    read_at = row["uptime_ts"]
    if ticks is None or not read_at:
        return None
    return round(ticks / 100 + max(0.0, time.time() - read_at))


def _ap_json(service, row) -> dict:
    radios = [_radio_json(r) for r in service.wireless_db.radios_for(row["id"])]
    # The at-a-glance table shows one tx-power figure per AP; a real AP
    # has one radio per band, so this is the strongest of them rather
    # than an arbitrary "first" pick.
    # Scanning radios are excluded from both the unit detection and the
    # headline figure: neither question is about them.
    powers = [r["operating_power_dbm"] for r in radios
              if r["operating_power_dbm"] is not None and not r["is_scan"]]
    channels = [str(r["channel"]) for r in radios if r["channel"] not in (None, "")]
    radio_stations = [r["station_count"] for r in radios if r["station_count"] is not None]
    uptime_s = _ap_uptime_s(row)
    return {
        "id": row["id"], "controller_id": row["controller_id"],
        "wtp_id": row["wtp_id"], "vdom": row["vdom"], "name": row["name"],
        "status": row["status"], "model": row["model"],
        "mac_address": row["mac_address"], "station_count": row["station_count"],
        # The AP's own address as the controller reports it, and the
        # round-trip to it. None where there is no reading — an AP that does
        # not answer ICMP is not an AP with a 0 ms response.
        "ip": row["ip"] or "",
        "response_ms": row["response_ms"],
        "tx_power_dbm": max(powers) if powers else None,
        # How to label that number — see _power_unit. A per-AP field rather
        # than a global one so a site with a mix of controllers still gets
        # each one's own reading.
        "power_unit": _power_unit(service, powers),
        # Derived from the radio rows the poller already walks, so these
        # are selectable table columns without polling anything new.
        "radio_count": len(radios),
        "radio_modes": ", ".join(r["mode"] for r in radios if r["mode"]),
        "channels": ", ".join(channels),
        "bssids": ", ".join(r["bssid"] for r in radios if r["bssid"]),
        "profile": row["profile"] or "",
        "uptime_s": uptime_s,
        "uptime_text": format_ticks(round(uptime_s * 100)) if uptime_s is not None else "",
        "session_uptime_text": (format_ticks(row["session_uptime_ticks"])
                                if row["session_uptime_ticks"] is not None else ""),
        "radio_station_count": sum(radio_stations) if radio_stations else None,
        "out_of_service": bool(row["out_of_service"]),
        "radios": radios,
        "last_seen_ts": row["last_seen_ts"],
    }


def get_wireless_overview(service, params, body) -> dict:
    return {
        "controllers": [_controller_json(r, _may_read_secrets(
            service, params, "wireless"))
            for r in service.wireless_db.controllers()],
        "ap_counts": service.wireless_db.ap_counts(),
        "poller": {
            "running": service.wireless.running,
            "status": service.wireless.status_text(),
            "counters": service.wireless.counters,
        },
    }


def get_wireless_controllers(service, params, body) -> dict:
    reveal = _may_read_secrets(service, params, "wireless")
    return {"controllers": [_controller_json(r, reveal)
                            for r in service.wireless_db.controllers()]}


_CONTROLLER_EDITABLE_BODY = ("name", "ip", "enabled", "snmp_version",
                             "community", "v3_user", "v3_auth_proto")


def post_wireless_controller(service, params, body) -> dict:
    name = str(body.get("name", "")).strip()
    ip = str(body.get("ip", "")).strip()
    if not name or not ip:
        raise ValueError("A name and IP address are required")
    _refuse_controller_privacy(body)
    overrides = {k: v for k, v in body.items() if k in _CONTROLLER_EDITABLE_BODY
                and k not in ("name", "ip", "enabled")}
    controller_id = service.wireless_db.add_controller(name, ip, **overrides)
    service.log.add(WIRELESS_CATEGORY, f"Added wireless controller {name} ({ip})")
    return {"id": controller_id}


def put_wireless_controller(service, params, body, controller_id) -> dict:
    existing = _require(service.wireless_db.controller(controller_id), "controller")
    _refuse_controller_privacy(body)
    fields = _pick(body, _CONTROLLER_EDITABLE_BODY)
    # Same rule as the DHCP server above: the stored SNMPv3 password was
    # stored for one controller at one address, so moving the row to a
    # different address forgets it rather than offering it to whatever
    # answers at the new one on the next poll.
    moved = ("ip" in fields and str(fields["ip"]).strip() != str(existing["ip"] or ""))
    service.wireless_db.update_controller(controller_id, **fields)
    if moved and existing["v3_auth_pass_enc"]:
        service.wireless_db.set_credential(controller_id, None)
        service.log.add(WIRELESS_CATEGORY,
                        f"Cleared the stored credential for controller "
                        f"{existing['name']}: its address changed from "
                        f"{existing['ip']} to {fields['ip']}")
        return {"ok": True, "credential_cleared": True}
    return {"ok": True}


def delete_wireless_controller(service, params, body, controller_id) -> dict:
    row = _require(service.wireless_db.controller(controller_id), "controller")
    service.wireless_db.remove_controller(controller_id)
    service.log.add(WIRELESS_CATEGORY, f"Removed wireless controller {row['name']}")
    return {"ok": True}


def _store_controller_credential(service, controller_id, user, auth_proto, encrypted):
    # The controller row carries the v3 identity the poller reads; the secret
    # is stored apart from it. Both are written, or the store call fails.
    service.wireless_db.update_controller(controller_id, v3_user=user,
                                          v3_auth_proto=auth_proto)
    service.wireless_db.set_credential(controller_id, encrypted)


def post_wireless_controller_credential(service, params, body, controller_id) -> dict:
    row = _require(service.wireless_db.controller(controller_id), "controller")
    # allow_priv=False: the wireless poller speaks authNoPriv at most (see
    # fortipoll's docstring), so a privacy password typed for a controller
    # is refused in words rather than stored and silently never sent.
    return _store_v3_credential(
        service, params, body, allow_priv=False,
        store=functools.partial(_store_controller_credential, service, controller_id),
        category=WIRELESS_CATEGORY,
        message=f"Stored an SNMPv3 credential for {row['name']}",
        target=f"controller:{row['ip']}",
        unavailable=(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. Use a v1/v2c community, or SNMPv3 "
            "noAuthNoPriv, instead."))


def delete_wireless_controller_credential(service, params, body, controller_id) -> dict:
    row = _require(service.wireless_db.controller(controller_id), "controller")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.wireless_db.set_credential, controller_id, None),
        category=WIRELESS_CATEGORY,
        message=f"Cleared the stored SNMPv3 credential for {row['name']}",
        target=f"controller:{row['ip']}")


def post_wireless_controller_poll(service, params, body, controller_id) -> dict:
    _require(service.wireless_db.controller(controller_id), "controller")
    service.wireless.poll_now(controller_id)
    return {"ok": True}


def get_wireless_aps(service, params, body) -> dict:
    controller_id = params.get("controller_id")
    aps = service.wireless_db.access_points(
        controller_id=int(controller_id) if controller_id else None)
    text = (params.get("q") or "").strip().lower()
    result = [_ap_json(service, r) for r in aps]
    if text:
        result = [ap for ap in result if text in (ap["name"] or "").lower()
                 or text in (ap["mac_address"] or "").lower()
                 or text in (ap["model"] or "").lower()]
    # out_of_service is an admin marking, not a reported status, so it
    # takes precedence over whatever status the AP last reported: an AP
    # marked out of service is only ever listed under that state.
    state = (params.get("state") or "all").strip().lower()
    if state == "out_of_service":
        result = [ap for ap in result if ap["out_of_service"]]
    elif state == "online":
        result = [ap for ap in result if not ap["out_of_service"] and ap["status"] == "online"]
    elif state == "offline":
        result = [ap for ap in result if not ap["out_of_service"] and ap["status"] != "online"]
    # One "last reported" figure for the page as a whole: the most recent
    # successful poll across the controllers actually in view, which is
    # what makes every AP row's own age redundant. last_poll_ok matters:
    # record_poll stamps last_poll_ts on failed polls too, and without the
    # filter this read "just now" through an hours-long controller outage.
    controllers = service.wireless_db.controllers()
    if controller_id:
        controllers = [c for c in controllers if c["id"] == int(controller_id)]
    stamps = [c["last_poll_ts"] for c in controllers
              if c["last_poll_ts"] and c["last_poll_ok"]]
    return {"aps": result, "last_reported_ts": max(stamps) if stamps else None}


def get_wireless_aps_export(service, params, body) -> dict:
    """One row per AP, radios included as the same summary columns the
    table already shows (radio_count, radio_modes, channels,
    radio_station_count) rather than one row per radio — that is the
    granularity "+radios" means on a table where an AP is the row."""
    aps = get_wireless_aps(service, params, body)["aps"]
    header = ["name", "controller_id", "status", "model", "mac_address", "ip",
             "station_count", "tx_power_dbm", "power_unit", "radio_count",
             "radio_modes", "channels", "radio_station_count",
             "out_of_service", "last_seen_ts"]
    csv_rows = [[ap.get(key) for key in header] for ap in aps]
    return _csv_response("wireless-aps", header, csv_rows)


def post_wireless_ap_service(service, params, body, ap_id) -> dict:
    _require(service.wireless_db.access_point(int(ap_id)), "access point")
    service.wireless_db.set_out_of_service(int(ap_id), bool(body.get("out_of_service")))
    return {"ok": True, "out_of_service": bool(body.get("out_of_service"))}


def delete_wireless_ap(service, params, body, ap_id) -> dict:
    """Removes one AP row by hand. Needed because an out-of-service AP is
    deliberately exempt from prune_stale — without this there would be no
    way to retire one permanently once the controller stops reporting it."""
    _require(service.wireless_db.access_point(int(ap_id)), "access point")
    service.wireless_db.remove_ap(int(ap_id))
    return {"ok": True}


def _wireless_history_points(rows, value_key: str, bucket_s: float) -> list[dict]:
    """Raw {ts, value} points, or (bucket_s > 0) the same {ts, avg, min,
    max, n} shape nodesseriesdb.series' own bucketed branch returns --
    App.drawSeriesChart already draws either without caring which store
    it came from."""
    if bucket_s and bucket_s > 0:
        buckets: dict[float, list] = {}
        for row in rows:
            value = row[value_key]
            if value is None:
                continue
            slot = (row["ts"] // bucket_s) * bucket_s
            buckets.setdefault(slot, []).append(value)
        return [{"ts": slot, "avg": sum(vals) / len(vals), "min": min(vals),
                "max": max(vals), "n": len(vals)}
               for slot, vals in sorted(buckets.items())]
    return [{"ts": row["ts"], "value": row[value_key]} for row in rows
           if row[value_key] is not None]


def _wireless_history_series(service, ap_id: int, t0: float, t1: float,
                             bucket_s: float) -> list[dict]:
    """The AP-total clients series plus, per radio, a clients and a tx-power
    series -- exactly what fortipoll already samples, no new SNMP columns.
    Radio order is the radio id sorted, so the series list (and the two
    charts wireless.js builds from it) draws the same radios in the same
    order on every request."""
    raw = service.wireless_db.ap_history(ap_id, t0, t1)
    series = [{"key": "clients", "label": "Clients", "unit": "",
              "points": _wireless_history_points(raw["ap"], "station_count", bucket_s)}]
    by_radio: dict[str, list] = {}
    for row in raw["radios"]:
        by_radio.setdefault(row["radio_id"], []).append(row)
    for radio_id in sorted(by_radio):
        rows = by_radio[radio_id]
        series.append({"key": f"radio:{radio_id}:clients",
                       "label": f"Radio {radio_id} clients", "unit": "",
                       "points": _wireless_history_points(rows, "station_count", bucket_s)})
        series.append({"key": f"radio:{radio_id}:power",
                       "label": f"Radio {radio_id} tx power", "unit": "dBm",
                       "points": _wireless_history_points(rows, "operating_power_dbm",
                                                          bucket_s)})
    return series


def get_wireless_ap_history(service, params, body, ap_id) -> dict:
    _require(service.wireless_db.access_point(ap_id), "access point")
    t0, t1 = _window(params, 86400.0)
    bucket_s = _series_bucket_s(params, t0, t1)
    series = _wireless_history_series(service, ap_id, t0, t1, bucket_s)
    return {"t0": t0, "t1": t1, "bucket_s": bucket_s, "series": series}


def get_wireless_ap_history_export(service, params, body, ap_id) -> dict:
    ap = _require(service.wireless_db.access_point(ap_id), "access point")
    t0, t1 = _window(params, 86400.0)
    bucket_s = _series_bucket_s(params, t0, t1)
    series = _wireless_history_series(service, ap_id, t0, t1, bucket_s)
    header = ["time", "ts", "series", "value", "min", "max"]
    csv_rows = []
    for s in series:
        for p in s["points"]:
            value = p["avg"] if "avg" in p else p.get("value")
            csv_rows.append([_csv_time(p["ts"]), p["ts"], s["key"], value,
                            p.get("min"), p.get("max")])
    return _csv_response(f"wireless-ap-{ap['id']}-history", header, csv_rows)


def post_wireless_collector(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.wireless_settings["enabled"] = True
        service.wireless_db.save_settings({"enabled": True})
        service.wireless.start(service.wireless_settings)
    elif action == "stop":
        service.wireless_settings["enabled"] = False
        service.wireless_db.save_settings({"enabled": False})
        service.wireless.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.wireless.running,
            "status": service.wireless.status_text()}


def post_ipam_worker(service, params, body) -> dict:
    """Start or stop the IPAM worker from its strip. Goes through the same
    apply_settings the settings dialog does, so the choice persists exactly
    as the checkbox there does — the only control there used to be."""
    action = str(body.get("action", "")).lower()
    if action not in ("start", "stop"):
        raise ValueError("action must be start or stop")
    service.apply_settings("ipam", {"enabled": action == "start"})
    return {"running": service.ipam.running,
            "enabled": bool(service.ipam_settings.get("enabled", True))}

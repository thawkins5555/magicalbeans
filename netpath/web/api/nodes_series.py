"""Handlers: Nodes device metric series -- batch fetch, export and timeline."""

from __future__ import annotations

import re


from ._shared import _csv_response, _csv_time, _device_display_name, _require, _series_bucket_s, _window


# ------------------------------------------------------- batch series route
#
# One request for several devices'/metrics' series -- a bad or unseeable
# entry in `q` answers empty rather than failing the whole tile.

_SERIES_BATCH_MAX = 16
# Per-port metric keys nodepoll.py records -- get the interface's own
# descr/alias as their label instead of the metric's generic one.
_IFACE_METRIC_KEY_RE = re.compile(r"^if_(?:in|out)_bps\.(\d+)$")


def _parse_series_batch_q(raw: str) -> list[tuple[int, str]]:
    pairs = []
    for piece in str(raw or "").split(","):
        piece = piece.strip()
        if not piece:
            continue
        device_id_s, sep, metric_key = piece.partition(":")
        metric_key = metric_key.strip()
        if not sep or not metric_key:
            raise ValueError(
                f"q entries must be <device_id>:<metric_key>, not {piece!r}")
        try:
            device_id = int(device_id_s)
        except ValueError:
            raise ValueError(
                f"q entries must be <device_id>:<metric_key>, not {piece!r}")
        pairs.append((device_id, metric_key))
    if not pairs:
        raise ValueError("q is required")
    if len(pairs) > _SERIES_BATCH_MAX:
        raise ValueError(f"q accepts at most {_SERIES_BATCH_MAX} entries")
    return pairs


def get_nodes_series_batch(service, params, body) -> dict:
    """{t0, t1, series: [{device_id, device_name, metric_key, unit, label,
    points}, ...]}, in `q`'s order, for `q=<device_id>:<metric_key>[,...]`.
    Resolves each pair through NodesSeriesDatabase.metric_by_key (one
    indexed lookup) and reads interface labels for the whole batch in one
    query per distinct device, rather than one per pair."""
    pairs = _parse_series_batch_q(params.get("q", ""))
    t0, t1 = _window(params, 86400.0)
    bucket_s = _series_bucket_s(params, t0, t1)

    device_ids = sorted({device_id for device_id, _key in pairs})
    devices = {device_id: service.nodes_db.device(device_id)
              for device_id in device_ids}
    iface_device_ids = {device_id for device_id, key in pairs
                        if _IFACE_METRIC_KEY_RE.match(key)}
    port_labels: dict[int, dict[int, str]] = {}
    if iface_device_ids:
        for row in service.nodes_db.interface_port_labels_for_devices(iface_device_ids):
            port_labels.setdefault(row["device_id"], {})[row["if_index"]] = (
                row["descr"] or row["alias"] or "")

    series = []
    for device_id, key in pairs:
        device = devices.get(device_id)
        if device is None:
            series.append({"device_id": device_id, "device_name": "",
                          "metric_key": key, "unit": "", "label": key,
                          "points": []})
            continue
        device_name = _device_display_name(device)
        metric_row = service.nodes_db.metric_by_key(device_id, key)
        if metric_row is None:
            series.append({"device_id": device_id, "device_name": device_name,
                          "metric_key": key, "unit": "", "label": key,
                          "points": []})
            continue
        iface_match = _IFACE_METRIC_KEY_RE.match(key)
        if iface_match:
            if_index = int(iface_match.group(1))
            label = port_labels.get(device_id, {}).get(if_index) or f"if {if_index}"
        else:
            label = metric_row["label"]
        points = service.nodes_db.series(device_id, metric_row["id"], t0, t1,
                                         bucket_s=bucket_s)
        series.append({"device_id": device_id, "device_name": device_name,
                      "metric_key": key, "unit": metric_row["unit"],
                      "label": label, "points": points})
    return {"t0": t0, "t1": t1, "series": series}


# E2: capped well past what the History query builder's 8-row, one-window
# ask could ever return in practice (8 series x a raw window of samples),
# so the cap only ever bites a pathological bucket_s=0 request over a very
# wide window -- truncated rather than refused, the same shape every other
# capped export in this file takes.
SERIES_EXPORT_CAP = 200_000


def get_nodes_series_export(service, params, body) -> dict:
    """The History query builder's Export CSV: the same q=<device_id>:
    <metric_key>[,...] the chart/table already ran, reusing
    get_nodes_series_batch's own parsing and fetch so the two can never
    disagree about which points a given q names. Long format -- one row per
    point per series -- so a spreadsheet can pivot either way."""
    result = get_nodes_series_batch(service, params, body)
    header = ["time", "ts", "device", "metric", "unit", "value", "min", "max"]
    csv_rows = []
    truncated = False
    for s in result["series"]:
        if truncated:
            break
        for p in s["points"]:
            if len(csv_rows) >= SERIES_EXPORT_CAP:
                truncated = True
                break
            value = p["avg"] if "avg" in p else p.get("value")
            csv_rows.append([_csv_time(p["ts"]), p["ts"], s["device_name"],
                            s["label"] or s["metric_key"], s["unit"], value,
                            p.get("min"), p.get("max")])
    return _csv_response("history", header, csv_rows, truncated=truncated,
                         cap=SERIES_EXPORT_CAP)


def get_nodes_device_timeline(service, params, body, device_id) -> dict:
    device = service.nodes_db.device(device_id)
    _require(device, "device")
    t0, t1 = _window(params)
    segments = service.nodes_db.device_status_segments(device_id, t0, t1)
    # Per-method (snmp/ping) segments alongside the combined `segments`
    # above (kept — report.py and any other existing caller reads that),
    # for the timeline's split-lane view. `methods_enabled` is which methods
    # this device currently has enabled at all, from its effective profile
    # — the UI needs that to decide split-vs-single BEFORE any per-method
    # event has ever been recorded (a device polled by both since before
    # this version shipped has methods["snmp"/"ping"] == None until its
    # first transition). Named `methods_enabled`, not `polling`: a device
    # row's own `polling` field already means "a poll is running right now"
    # (see worker_state() below) — an unrelated, easily-confused meaning.
    methods = service.nodes_db.device_method_segments(device_id, t0, t1)
    config = service.nodes_db.effective_config(device)
    methods_enabled = {"snmp": bool(config.get("snmp_enabled")),
                       "ping": bool(config.get("ping_enabled"))}
    return {"t0": t0, "t1": t1, "segments": segments, "methods": methods,
            "methods_enabled": methods_enabled}

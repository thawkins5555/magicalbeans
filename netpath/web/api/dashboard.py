"""Handlers: the Dashboard's tiles and layout."""

from __future__ import annotations

import copy
import json
import math
import time

from ...analysis import MAX_TIMESTAMP
from ... import namelookup
from ... import permissions as _permissions
from ..service import STORES, db_for

from ._shared import ALERT_TOTAL_CAP, _audit, _device_event_json, _devices_for_rows, _fleet_counts, _num, _require, request_permissions


# --------------------------------------------------------------- dashboard
#
# The landing page after every sign-in. These two endpoints answer the
# questions a tile grid asks; everything else the grid needs is on
# /api/state, which every tab polls anyway.
#
# Permission-gated the way get_state is: never refused outright, but a
# section the account cannot read is absent rather than empty, so the front
# end leaves the tile out instead of drawing a zero that is not true.

# The metric keys the "worst" lists are built from. Named here rather than in
# the front end because they are the poller's vocabulary (nodepoll.py:1281,
# :1284 and nodeoids.py's per-vendor tables), not the browser's.
DASHBOARD_METRICS = (
    ("rtt", "ping_rtt_ms", "Slowest to answer", "ms", False),
    ("loss", "ping_loss_pct", "Worst packet loss", "%", False),
    ("cpu", "cpu_pct", "Highest CPU", "%", False),
)

DASHBOARD_OFFENDER_N = 10
DASHBOARD_OFFENDER_WINDOW_S = 86400.0
DASHBOARD_TTL_S = 2.0               # as STATE_COUNTS_TTL_S: one tab loses nothing
DASHBOARD_OFFENDERS_TTL_S = 30.0    # against the 60 s client cadence


def _dash_can(service, params, module: str) -> bool:
    granted = request_permissions(service, params)
    return _permissions.allows(granted.get(module), _permissions.READ)


def _dashboard_section(service, key: str, ttl_s: float, compute):
    # cached_poll shares one object; a deep copy keeps every response its own.
    return copy.deepcopy(service.cached_poll(key, ttl_s, compute))


def _dashboard_fleet(service) -> dict:
    poller = service.node_poller
    pool = poller.pool_state() if hasattr(poller, "pool_state") else {}
    counts, planned = _fleet_counts(service)
    # The same number the tile prints, so "and N more" cannot disagree with it.
    down_total = counts["down"]
    # device_name, not `name`: the raw column is the IP for a device nobody renamed.
    down = [{"device_id": row["id"],
             "name": namelookup.device_name(row) or row["ip"],
             "ip": row["ip"]}
            for row in service.nodes_db.devices(status="down", exclude_ids=planned,
                                                limit=DASHBOARD_OFFENDER_N)]
    return {
        "counts": counts,
        "running": poller.running,
        "pool": dict(pool or {}),
        "down": down,
        "down_more": max(0, down_total - len(down)),
    }


def _dashboard_alerts(service) -> dict:
    summary = service.alerts_db.open_summary()
    return {
        "open": summary.get("open", 0),
        "acked": summary.get("acked", 0),
        "worst": summary.get("worst"),
        "by_severity": service.alerts_db.open_counts_by_severity(),
        # A GROUP BY has no cap; the key stays because dashboard.js reads it.
        "counted_capped": False,
        "engine_running": service.alert_engine.running,
        "counters": dict(service.alert_engine.counters or {}),
    }


def _dashboard_storage(service) -> list[dict]:
    # Headroom worst-first, over STORES so no view disagrees about the store count.
    settings = service.settings or {}
    stores = []
    for store in STORES:
        db = db_for(service, store)
        if db is None:
            continue
        try:
            used = int(db.size_bytes())
        except Exception:                                 # noqa: BLE001
            continue
        cap_mb = settings.get(store.cap_key) if store.cap_key else None
        cap = int(cap_mb) * 1024 * 1024 if cap_mb else None
        stores.append({
            "label": store.label, "bytes": used, "cap_bytes": cap,
            "used_fraction": (used / cap) if cap else None,
        })
    stores.sort(key=lambda s: (s["used_fraction"] is None,
                               -(s["used_fraction"] or 0)))
    return stores


def get_dashboard(service, params, body) -> dict:
    """The cross-module numbers the tile grid shows, in one round trip."""
    result: dict = {}

    if _dash_can(service, params, "nodes"):
        result["fleet"] = _dashboard_section(
            service, "dashboard_fleet", DASHBOARD_TTL_S,
            lambda: _dashboard_fleet(service))

    if _dash_can(service, params, "alerts"):
        result["alerts"] = _dashboard_section(
            service, "dashboard_alerts", DASHBOARD_TTL_S,
            lambda: _dashboard_alerts(service))

    # Every background process, each by the noun its own tab uses for it.
    collectors = []
    for module, name, obj in (
            ("nodes", "Nodes poller", getattr(service, "node_poller", None)),
            ("alerts", "Alert engine", getattr(service, "alert_engine", None)),
            ("netflow", "NetFlow collector", getattr(service, "collector", None)),
            ("snmp", "SNMP trap receiver", getattr(service, "snmp", None)),
            ("syslog", "Syslog collector", getattr(service, "syslog", None)),
            ("ipam", "IPAM worker", getattr(service, "ipam", None)),
            ("wireless", "Wireless poller", getattr(service, "wireless", None)),
            ("configrx", "ConfigRX worker", getattr(service, "configrx", None))):
        if obj is None or not _dash_can(service, params, module):
            continue
        counters = dict(getattr(obj, "counters", {}) or {})
        collectors.append({
            "module": module, "name": name,
            "running": bool(getattr(obj, "running", False)),
            "counters": counters,
        })
    if collectors:
        result["collectors"] = collectors

    if _dash_can(service, params, "settings"):
        result["storage"] = _dashboard_section(
            service, "dashboard_storage", DASHBOARD_TTL_S,
            lambda: _dashboard_storage(service))

    return {"dashboard": result}


def _offender_rows(rows, n: int, value_key: str, unit: str) -> list[dict]:
    out = []
    for row in rows[:n]:
        # A row without sys_name (top_metric) falls back to the raw name.
        keys = row.keys()
        name = (namelookup.device_name(row) if "sys_name" in keys else row["name"])
        out.append({"device_id": row["device_id"],
                    "name": name or row["ip"],
                    "ip": row["ip"],
                    "value": row[value_key],
                    "unit": unit})
    return out


def _offender_node_lists(service, since: float, n: int) -> tuple[list, list]:
    """(event lists, metric lists); the gated alerts list goes between them."""
    events = service.nodes_db.count_events_by_device(since, limit=n)
    # Its own list so a flapping port is not hidden by a noisy device.
    flaps = service.nodes_db.count_interface_events_by_device(since, limit=n)
    head = [
        {"key": "events", "title": "Most device events (24 h)",
         "unit": "", "rows": _offender_rows(events, n, "n", "")},
        {"key": "interface_events", "title": "Most interface events (24 h)",
         "unit": "", "rows": _offender_rows(flaps, n, "n", "")},
    ]
    tail = []
    for key, metric, title, unit, ascending in DASHBOARD_METRICS:
        rows = service.nodes_db.top_metric(metric, n, ascending=ascending)
        tail.append({"key": key, "title": title, "unit": unit,
                     "rows": _offender_rows(rows, n, "last_value", unit)})
    return head, tail


def _offender_alert_list(service, since: float, n: int) -> dict:
    counts: dict[str, dict] = {}
    for row in service.alerts_db.alerts(t0=since, limit=ALERT_TOTAL_CAP):
        if row["entity_kind"] != "device":
            continue
        key = str(row["entity_id"])
        entry = counts.setdefault(
            key, {"device_id": _int_or_none(row["entity_id"]),
                  "name": row["entity_label"] or key, "ip": "",
                  "value": 0, "unit": ""})
        entry["value"] += 1
    ranked = sorted(counts.values(), key=lambda e: -e["value"])[:n]
    return {"key": "alerts", "title": "Most alerts (24 h)",
            "unit": "", "rows": ranked}


def get_dashboard_offenders(service, params, body) -> dict:
    """Six short "worst ten" lists, each row linking to its device.

    One query per list rather than one per device: `count_events_by_device`
    and `top_metric` exist for exactly this.
    """
    if not _dash_can(service, params, "nodes"):
        raise _permissions.Forbidden("Reading devices is not permitted")

    window_s = _num(params, "window_s", DASHBOARD_OFFENDER_WINDOW_S) or DASHBOARD_OFFENDER_WINDOW_S
    since = time.time() - float(window_s)
    n = int(_num(params, "n", DASHBOARD_OFFENDER_N, int) or DASHBOARD_OFFENDER_N)
    n = max(1, min(n, 50))
    # Only the shape dashboard.js asks for is cached: _poll_cache never
    # evicts, so caller-chosen window_s/n must not become keys.
    cached = window_s == DASHBOARD_OFFENDER_WINDOW_S and n == DASHBOARD_OFFENDER_N

    if cached:
        head, tail = _dashboard_section(
            service, "dashboard_offenders_nodes", DASHBOARD_OFFENDERS_TTL_S,
            lambda: _offender_node_lists(service, since, n))
    else:
        head, tail = _offender_node_lists(service, since, n)
    lists = list(head)
    if _dash_can(service, params, "alerts"):
        if cached:
            lists.append(_dashboard_section(
                service, "dashboard_offenders_alerts", DASHBOARD_OFFENDERS_TTL_S,
                lambda: _offender_alert_list(service, since, n)))
        else:
            lists.append(_offender_alert_list(service, since, n))
    lists.extend(tail)
    return {"window_s": window_s, "lists": lists}


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------- dashboard layout
#
# A per-account arrangement of the tile grid, stored as one compact JSON
# blob on the account's own `users` row (appdb.py, beside `theme`) — one
# dashboard per account, nothing shared between them.

# type key -> the module a tile needs read access to (None = any signed-in
# account may add and see it). The server's own copy of the catalogue:
# dashboard.js has the richer one (titles, renderers), this one only
# validates and gates.
DASHBOARD_TILE_TYPES = {
    "fleet": "nodes", "open_alerts": "alerts", "workers": None,
    "storage": "settings", "top_events": "nodes", "top_iface_events": "nodes",
    "top_alerts": "alerts", "top_rtt": "nodes", "top_loss": "nodes",
    "top_cpu": "nodes", "iface_traffic": "nodes", "device_metric": "nodes",
    "device_status": "nodes", "top_metric": "nodes", "recent_alerts": "alerts",
    "recent_events": "nodes", "note": None, "syslog_rate": "syslog",
    "trap_rate": "snmp", "netflow_top": "netflow",
    "wireless_summary": "wireless", "configrx_summary": "configrx",
    "ipam_subnets": "ipam", "https_monitors": "netpath",
}

_DASHBOARD_WIDE_TILES = ("fleet", "workers", "storage")

# Today's ten tiles, in today's order — an account that has never saved a
# layout of its own sees exactly what it always has.
DEFAULT_DASHBOARD_LAYOUT = {
    "version": 1,
    "tiles": [
        {"id": tile_id, "type": tile_id,
         "w": 2 if tile_id in _DASHBOARD_WIDE_TILES else 1,
         "h": 1, "config": {}}
        for tile_id in ("fleet", "open_alerts", "workers", "storage",
                        "top_events", "top_iface_events", "top_alerts",
                        "top_rtt", "top_loss", "top_cpu")
    ],
}

# Mirrors App.RANGES in app.js -- the only window choices dashboard.js offers.
_DASHBOARD_WINDOW_S_VALUES = (900, 3600, 21600, 86400, 259200, 604800, 2592000)

# A pinned t0/t1 range's widest allowed span -- mirrors app.js's WINDOW_MAX_S.
_DASHBOARD_MAX_SPAN_S = 2592000 * 4


def _dash_int(value, lo=None, hi=None, allowed=None):
    """One config value as a plain int, never a bool (a bool IS an int in
    Python, and `True` is not what `n: 1` means here) and within bounds."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"expected an integer, got {value!r}")
    if allowed is not None and value not in allowed:
        raise ValueError(f"{value!r} is not one of {allowed!r}")
    if lo is not None and value < lo:
        raise ValueError(f"{value!r} is below the minimum {lo}")
    if hi is not None and value > hi:
        raise ValueError(f"{value!r} is above the maximum {hi}")
    return value


def _dash_num(value, lo=None, hi=None):
    """A finite int or float, never a bool -- some metrics' y_max is fractional."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"expected a number, got {value!r}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"expected a finite number, got {value!r}")
    if lo is not None and value < lo:
        raise ValueError(f"{value!r} is below the minimum {lo}")
    if hi is not None and value > hi:
        raise ValueError(f"{value!r} is above the maximum {hi}")
    return value


def _dash_str(value, max_len):
    if not isinstance(value, str) or len(value) > max_len:
        raise ValueError(f"expected a string of at most {max_len} characters")
    return value


def _dash_bool(value):
    if not isinstance(value, bool):
        raise ValueError(f"expected true or false, got {value!r}")
    return value


def _dash_enum(*options):
    def validate(value):
        if value not in options:
            raise ValueError(f"{value!r} is not one of {options!r}")
        return value
    return validate


def _dash_list(item_validator, max_len, min_len=1):
    """A config value as a list of `min_len`..`max_len` items, each run
    through `item_validator` -- the interface_traffic tile's `interfaces`
    key is the one config value here that is itself a list rather than a
    scalar."""
    def validate(value):
        if not isinstance(value, list):
            raise ValueError(f"expected a list, got {value!r}")
        if not (min_len <= len(value) <= max_len):
            raise ValueError(
                f"expected between {min_len} and {max_len} item(s), got {len(value)}")
        return [item_validator(item) for item in value]
    return validate


def _dash_interface_pair(value):
    """One {device_id, if_index} entry of an iface_traffic tile's
    `interfaces` list -- exactly those two keys, both plain ints."""
    if not isinstance(value, dict) or set(value) != {"device_id", "if_index"}:
        raise ValueError(
            f"expected an object with exactly device_id and if_index, got {value!r}")
    return {"device_id": _dash_int(value["device_id"]),
            "if_index": _dash_int(value["if_index"])}


def _dash_interfaces(value):
    items = _dash_list(_dash_interface_pair, 8)(value)
    seen = set()
    for item in items:
        pair = (item["device_id"], item["if_index"])
        if pair in seen:
            raise ValueError(f"duplicate interface in the list: {item!r}")
        seen.add(pair)
    return items


# type key -> {config key: validator}. A type absent here (or a key absent
# from its entry) accepts no config keys at all — `config: {}` is the only
# legal value for the tile families with nothing to configure.
_DASHBOARD_CONFIG_SCHEMA = {
    "iface_traffic": {
        # device_id/if_index: legacy single-interface config, still
        # accepted -- a saved layout from before `interfaces` existed keeps
        # working, and the fetcher treats the pair as a one-entry list.
        "device_id": lambda v: _dash_int(v),
        "if_index": lambda v: _dash_int(v),
        "interfaces": _dash_interfaces,
        "name": lambda v: _dash_str(v, 60),
        "y_max": lambda v: _dash_int(v, 0, 10**13),
        "window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES),
        "t0": lambda v: _dash_int(v, 0, int(MAX_TIMESTAMP)),
        "t1": lambda v: _dash_int(v, 0, int(MAX_TIMESTAMP)),
    },
    "device_metric": {
        "device_id": lambda v: _dash_int(v),
        "metric_key": lambda v: _dash_str(v, 200),
        "name": lambda v: _dash_str(v, 60),
        "y_max": lambda v: _dash_num(v, 0, 10**15),
        "window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES),
        "t0": lambda v: _dash_int(v, 0, int(MAX_TIMESTAMP)),
        "t1": lambda v: _dash_int(v, 0, int(MAX_TIMESTAMP)),
    },
    "device_status": {"device_id": lambda v: _dash_int(v)},
    "top_metric": {
        "metric_key": lambda v: _dash_str(v, 200),
        "n": lambda v: _dash_int(v, 1, 50),
        "window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES),
        "rank_by": _dash_enum("peak", "mean"),
        "ascending": _dash_bool,
    },
    "recent_alerts": {
        "max_severity": lambda v: _dash_int(v, 0, 7),
        "n": lambda v: _dash_int(v, 1, 50),
    },
    "recent_events": {
        "n": lambda v: _dash_int(v, 1, 200),
        "since_s": lambda v: _dash_int(v, 60, 604800),
    },
    "note": {
        "title": lambda v: _dash_str(v, 200),
        "text": lambda v: _dash_str(v, 2000),
    },
    "syslog_rate": {"window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES)},
    "trap_rate": {"window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES)},
    "netflow_top": {
        "dimension": lambda v: _dash_str(v, 40),
        "n": lambda v: _dash_int(v, 1, 50),
        "window_s": lambda v: _dash_int(v, allowed=_DASHBOARD_WINDOW_S_VALUES),
    },
    "ipam_subnets": {"n": lambda v: _dash_int(v, 1, 50)},
}

_DASHBOARD_TILE_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _validate_dashboard_layout(layout) -> dict:
    """`layout` as a client (or a stored row) supplied it -> the cleaned,
    canonical form, or ValueError naming what was wrong — server.py answers
    every ValueError with 400. Never trusts a `config` value's shape past
    what the tile type declares: an unknown key or a wrong type is refused
    rather than stored and handed back to whatever reads it later."""
    if not isinstance(layout, dict) or layout.get("version") != 1:
        raise ValueError("layout.version must be 1")
    tiles = layout.get("tiles")
    if not isinstance(tiles, list):
        raise ValueError("layout.tiles must be a list")
    if len(tiles) > 60:
        raise ValueError("A dashboard layout may hold at most 60 tiles")
    seen_ids = set()
    clean_tiles = []
    for tile in tiles:
        if not isinstance(tile, dict):
            raise ValueError("Each tile must be an object")
        tile_id = tile.get("id")
        if (not isinstance(tile_id, str) or not (0 < len(tile_id) <= 32)
                or not set(tile_id) <= _DASHBOARD_TILE_ID_CHARS):
            raise ValueError(f"Bad tile id: {tile_id!r}")
        if tile_id in seen_ids:
            raise ValueError(f"Duplicate tile id: {tile_id}")
        seen_ids.add(tile_id)
        tile_type = tile.get("type")
        if tile_type not in DASHBOARD_TILE_TYPES:
            raise ValueError(f"Unknown tile type: {tile_type!r}")
        # The same integer coercion every config field gets, not a bare
        # `in (1, 2, 3)`: that literal check passes 1.0 straight through
        # (1.0 == 1) and would store a float where every reader expects
        # a Python int.
        try:
            w = _dash_int(tile.get("w"), allowed=(1, 2, 3))
        except ValueError as exc:
            raise ValueError(f"Tile {tile_id}: w must be 1, 2 or 3") from exc
        try:
            h = _dash_int(tile.get("h"), allowed=(1, 2))
        except ValueError as exc:
            raise ValueError(f"Tile {tile_id}: h must be 1 or 2") from exc
        config = tile.get("config")
        if not isinstance(config, dict):
            raise ValueError(f"Tile {tile_id}: config must be an object")
        schema = _DASHBOARD_CONFIG_SCHEMA.get(tile_type, {})
        clean_config = {}
        for key, value in config.items():
            # A key the client omitted never reaches here at all; an
            # explicit null is the same "not set" spelled the other way —
            # dropped rather than failed through the field's own (int/str)
            # validator, which null was never going to satisfy.
            if value is None:
                continue
            validator = schema.get(key)
            if validator is None:
                raise ValueError(
                    f"Tile {tile_id}: unknown config key {key!r} for {tile_type}")
            clean_config[key] = validator(value)
        _check_dash_t0_t1(tile_id, clean_config)
        clean_tiles.append({"id": tile_id, "type": tile_type,
                            "w": w, "h": h, "config": clean_config})
    return {"version": 1, "tiles": clean_tiles}


def _check_dash_t0_t1(tile_id: str, config: dict) -> None:
    """t0/t1 are validated one key at a time by the per-key loop above,
    which cannot see the other key -- so the pairing rule (both or
    neither, ordered, not absurdly wide) is checked here instead, once the
    whole config is in hand. A no-op for every tile type that has no t0/t1
    in its schema at all, since neither key is ever in `config` then."""
    has_t0, has_t1 = "t0" in config, "t1" in config
    if has_t0 != has_t1:
        raise ValueError(f"Tile {tile_id}: t0 and t1 must both be set, or neither")
    if not has_t0:
        return
    if config["t1"] <= config["t0"]:
        raise ValueError(f"Tile {tile_id}: t1 must be greater than t0")
    if config["t1"] - config["t0"] > _DASHBOARD_MAX_SPAN_S:
        raise ValueError(
            f"Tile {tile_id}: a pinned range may span at most "
            f"{_DASHBOARD_MAX_SPAN_S // 86400} days")


def get_dashboard_layout(service, params, body) -> dict:
    """The caller's saved tile arrangement, or the shipped default when
    they have never saved one — or when what is stored no longer parses
    (a layout saved by a future version, say): reported as the default
    rather than a 500, since the account can always Reset to recover."""
    stored = service.app_db.user_dashboard_layout(params.get("_username", ""))
    if stored:
        try:
            return {"layout": _validate_dashboard_layout(json.loads(stored)),
                    "default": False}
        except Exception:                                 # noqa: BLE001
            pass
    return {"layout": copy.deepcopy(DEFAULT_DASHBOARD_LAYOUT), "default": True}


def put_dashboard_layout(service, params, body) -> dict:
    """Save the caller's tile arrangement to their own account — self-
    service, own account only, like put_account_theme beside it."""
    username = params.get("_username", "")
    layout = _validate_dashboard_layout((body or {}).get("layout"))
    service.app_db.set_user_dashboard_layout(
        username, json.dumps(layout, separators=(",", ":")))
    _audit(service, params, "dashboard.layout",
          detail=f"{len(layout['tiles'])} tile(s)")
    return {"layout": layout, "default": False}


def delete_dashboard_layout(service, params, body) -> dict:
    """Clear the caller's saved layout — back to the shipped default."""
    service.app_db.set_user_dashboard_layout(params.get("_username", ""), "")
    _audit(service, params, "dashboard.layout", detail="reset to default")
    return {"layout": copy.deepcopy(DEFAULT_DASHBOARD_LAYOUT), "default": True}


def get_nodes_events(service, params, body) -> dict:
    """Fleet-wide recent device events, for the Dashboard's Recent events
    tile — get_nodes_device_events's own reader with no device filter,
    joined to device names the way the search routes are."""
    limit = max(1, min(int(_num(params, "limit", 50, int) or 50), 200))
    since_s = _num(params, "since_s", 86400.0)
    kinds_raw = params.get("kinds")
    kinds = ([piece.strip() for piece in kinds_raw.split(",") if piece.strip()][:20]
             if kinds_raw else None)
    rows = service.nodes_db.device_events(
        None, since_s=since_s, kinds=kinds, limit=limit)
    devices = _devices_for_rows(service, rows)
    events = []
    for row in rows:
        device = devices.get(row["device_id"])
        if device is None:
            continue
        events.append({**_device_event_json(row), "device_id": row["device_id"],
                       "device_name": namelookup.device_name(device),
                       "ip": device["ip"]})
    return {"events": events}


# Two fields the database and the write paths carry but the list
# serializers do not return, so a form has no way to show what is currently
# set. These two routes hand the front end the missing values; the front end
# merges whatever it is given, so they can disappear once the serializers
# carry them.


def get_nodes_device_upstream(service, params, body, device_id) -> dict:
    """The device this one hangs off, and the devices it could hang off.

    `PUT /api/nodes/devices/<id>` has accepted `upstream_id` since the
    topology rollup landed — an outage on a core switch raises one alert
    instead of five hundred — but nothing in the UI could set it, and
    `_device_json` does not return it, so a form had nothing to show.
    """
    row = _require(service.nodes_db.device(device_id), "device")
    keys = row.keys()
    upstream = row["upstream_id"] if "upstream_id" in keys else None
    # Everything except this device: the server refuses self and unknown ids
    # anyway (_clean_upstream_id), and offering them would only produce an
    # error the operator could have been spared.
    candidates = [
        {"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"]}
        for d in service.nodes_db.device_summaries()
        if d["id"] != device_id
    ]
    candidates.sort(key=lambda d: (d["name"] or "").lower())
    return {"upstream_id": upstream, "candidates": candidates}


def get_alerts_rule_extras(service, params, body) -> dict:
    """`auto_resolve_after_s` and `notify` per rule, keyed by rule id.

    Both are accepted by POST and PUT /api/alerts/rules and neither is in
    `_rule_json`, so the rule editor could set them but never show what they
    were. There are dozens of rules, not thousands, so one flat map is the
    whole answer.
    """
    extras = {}
    for row in service.alerts_db.rules():
        keys = row.keys()
        extras[str(row["id"])] = {
            "auto_resolve_after_s": (row["auto_resolve_after_s"]
                                     if "auto_resolve_after_s" in keys else None),
            "notify": (bool(row["notify"]) if "notify" in keys else True),
            "notify_sms": (bool(row["notify_sms"]) if "notify_sms" in keys else False),
        }
    return {"rules": extras}

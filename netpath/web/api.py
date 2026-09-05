"""JSON endpoints.

Each handler takes the service, the parsed query string and the decoded body,
and returns something json-serialisable. The HTTP plumbing is in server.py so
this file stays about the data.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import sqlite3
import json
import math
import secrets
import threading
import time

from ..alertrules import device_id_for
from ..alertsdb import is_window_active
from ..analysis import availability, build_timeline, build_topology
from .. import hostresolve
from ..services import format_bytes, format_packets, format_rate, port_name, protocol_name
from ..tracer import expected_budget, unreachable_text
from ..flowdb import DIMENSIONS
from ..ipamdb import scope_size
from ..eventlog import (ALERTS as ALERTS_CATEGORY, CATEGORIES,
                        CONFIGRX as CONFIGRX_CATEGORY,
                        ERROR as ERROR_CATEGORY, IPAM as IPAM_CATEGORY,
                        NODES as NODES_CATEGORY, SYSTEM as SYSTEM_CATEGORY,
                        WIRELESS as WIRELESS_CATEGORY)
from ..syslogparse import FACILITIES, SEVERITIES, facility_name, severity_name
from ..trapdecode import GENERIC_NAMES, VERSION_NAMES, enc_octets, format_ticks
from .. import trapoids
from .. import nodeoids
from .. import configrx
from .. import configrx_redact
from .. import sshterm
from .. import enterprises, mibcatalog, vendorid
from .. import nodesdb
from .. import permissions as _permissions
from .. import appdb as _appdb

MIN_BLOCK_PX = 3


# ---------------------------------------------------------------------- CSV
#
# Every export route below answers with JSON, not a raw file download: the
# response machinery in server.py sends one fully-buffered body per request
# and has no Content-Disposition path, and building one just for CSV would
# be a second way to hand a file to a browser alongside the one the OID
# walk download already established. get_nodes_device_oid_walk hands the
# file back as a `text` field and lets the browser do the Blob-and-anchor
# trick client-side (App.download, app.js) — every export here follows
# that precedent instead of inventing a competing mechanism.
#
# The csv module is what actually does the quoting: a device name with an
# embedded comma, a syslog message with an embedded quote or newline, is
# exactly what RFC 4180 quoting exists for, and hand-joining strings with
# commas gets it wrong the first time either shows up. The BOM is prepended
# to the text itself, not a header, since there is no raw response for a
# header to sit on — Excel opens a BOM-led file as UTF-8 instead of
# guessing a system codepage and mangling anything outside ASCII.
def _csv_text(header: list[str], rows) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows(rows)
    return "\ufeff" + buf.getvalue()


def _csv_filename(module: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    return f"sappiwhere-{module}-{stamp}.csv"


def _csv_response(module: str, header: list[str], rows, *, truncated: bool = False,
                  cap: int | None = None) -> dict:
    """The one shape every export handler below returns. `cap` is the
    export ceiling that applied (None when the underlying query has none —
    devices, interfaces, IPAM hosts, DHCP leases and wireless APs are none
    of them capped even on screen, so their export is not capped either);
    `truncated` is whether the result actually hit it, the same "there is
    more than this" signal the search screens already use for SEARCH_ROW_CAP."""
    rows = list(rows)
    return {"csv": _csv_text(header, rows), "filename": _csv_filename(module),
            "count": len(rows), "truncated": truncated, "cap": cap}


def _audit(service, params, action: str, target: str = "",
           detail: str = "") -> None:
    """One line in the on-disk audit trail (appdb.audit).

    Written alongside the event-log line most of these actions already
    produce, not instead of it: the ring is for watching the application
    work and is gone on the next restart, this is the record that answers
    "who changed that" a month later. Only authentication, authorization,
    credential and destructive-administration actions come here — this is
    not a second copy of the event log.
    """
    service.app_db.audit(params.get("_username", ""), params.get("_client", ""),
                         action, target, detail)


def _num(params, key, default=None, cast=float):
    value = params.get(key)
    if value in (None, ""):
        return default
    try:
        return cast(value)
    except (TypeError, ValueError):
        return default


def _window(params) -> tuple[float, float]:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 3600)
    if t1 <= t0:
        t1 = t0 + 60
    return t0, t1


# ------------------------------------------------------------------ general

# get_state is one omnibus endpoint every open tab polls regardless of
# which module it's looking at, so it's never permission-gated as a whole
# (the Dashboard it feeds is always reachable) — instead each per-module
# section is dropped from the response below when the signed-in user
# can't read that module, rather than the request being refused outright.
#
# The payload is two routes since 4.43.0. /api/config is what changes only
# when an operator changes it — every settings block, the grants, the constant
# vocabularies — and carries `config_version`; /api/state is what changes on
# its own — running flags, counters, counts, clocks — and repeats the version
# so the browser knows when to fetch the other half. Before the split every
# poll of every tab carried both: measured 10.9 KB every two seconds, of
# which 6-7 KB could not have changed since the last one.
#
# Both maps below are applied the same way: a module's keys are dropped for
# an account that cannot read it.
_CONFIG_MODULE_KEYS = {
    "netflow": ("flow_settings", "dimensions"),
    "syslog": ("syslog_settings",),
    "snmp": ("snmp_settings", "trap_kinds"),
    "ipam": ("ipam_settings",),
    "nodes": ("nodes_settings",),
    "alerts": ("alerts_settings",),
    "wireless": ("wireless_settings",),
    "configrx": ("configrx_settings",),
}
_STATE_MODULE_KEYS = {
    "netflow": ("collector",),
    "syslog": ("syslog",),
    "snmp": ("snmp",),
    "ipam": ("ipam",),
    "nodes": ("nodes",),
    "alerts": ("alerts",),
    "wireless": ("wireless",),
    "configrx": ("configrx",),
    "settings": ("storage",),
}

# Global settings only a Settings reader may see. "settings" itself stays in
# every response — every module's own refresh cadence lives in it and every
# tab needs those — but these keys are server internals with no reason to
# reach an account without Settings access: where the listener binds and
# which TLS material it loads, how long a sign-in lasts, which resolver the
# nslookup subprocesses are pointed at, and — Tier 1 #10 — the directory's
# address, its bind DN template (which names the plant's LDAP tree
# structure) and its cleartext opt-out.
SETTINGS_ONLY_KEYS = ("web_host", "web_port", "web_cert", "web_key",
                      "session_idle_minutes", "session_max_hours",
                      "dns_server", "asn_server",
                      "ldap_url", "ldap_bind_dn_template",
                      "ldap_allow_cleartext", "ldap_timeout_s")


def _visible_settings(settings: dict, granted: dict) -> dict:
    """`settings` as this caller may see it. One rule, used by both the
    endpoint that reads the settings and the one that writes them — they
    disagreed before, and post_settings echoing the unfiltered dict was
    half of the escalation the review found."""
    if _permissions.allows(granted.get("settings"), _permissions.READ):
        return settings
    return {k: v for k, v in settings.items() if k not in SETTINGS_ONLY_KEYS}


def _drop_unreadable(result: dict, granted: dict, module_keys: dict) -> None:
    for module, keys in module_keys.items():
        if not _permissions.allows(granted.get(module), _permissions.READ):
            for key in keys:
                result.pop(key, None)


def get_config(service, params, body) -> dict:
    """Everything the browser needs that only an operator can change.

    Fetched once at start-up and again whenever /api/state reports a new
    `config_version`. Never polled on its own: nothing in here moves by
    itself. Not gated as a whole, like /api/state — a module's block is
    dropped for an account that cannot read it."""
    from .. import __version__
    from ..selfupdate import (INSTALLED_AT_KEY, INSTALLED_COMMIT_KEY,
                              INSTALLED_TAG_KEY, updates_enabled)
    granted = service.app_db.permissions_for(params.get("_username", ""))
    result = {
        "config_version": service.config_version,
        "version": __version__,
        "permissions": granted,
        "update": {
            "installed_commit": service.app_db.meta(INSTALLED_COMMIT_KEY),
            "installed_tag": service.app_db.meta(INSTALLED_TAG_KEY),
            "installed_at": service.app_db.meta(INSTALLED_AT_KEY),
            # So the Settings page can say why the button does nothing,
            # rather than showing one that always fails.
            "enabled": updates_enabled(service.app_db),
        },
        "settings": service.settings,
        "flow_settings": service.flow_settings,
        "dimensions": list(DIMENSIONS),
        "categories": CATEGORIES,
        "severities": SEVERITIES,
        "facilities": FACILITIES,
        "syslog_settings": service.syslog_settings,
        "snmp_settings": service.snmp_settings,
        "trap_kinds": list(trapoids.KINDS),
        "ipam_settings": service.ipam_settings,
        "nodes_settings": service.nodes_settings,
        "alerts_settings": service.alerts_settings,
        "wireless_settings": service.wireless_settings,
        "configrx_settings": service.configrx_settings,
    }
    _drop_unreadable(result, granted, _CONFIG_MODULE_KEYS)
    # "settings" itself stays present even without Settings access — every
    # module's own refresh cadence (nodes_refresh_s and so on) lives in it,
    # and every tab needs to read those regardless of its own module's
    # grant. Only the keys in SETTINGS_ONLY_KEYS are stripped.
    result["settings"] = _visible_settings(result["settings"], granted)
    return result


def get_state(service, params, body) -> dict:
    """What changes on its own: every worker's running flag, status line
    and counters, the counts the tab badges show, the session clocks. Polled
    every two seconds by every open tab, so what it costs matters: the
    figures that cannot usefully change at that rate are served from a
    short cache (Service.cached_poll), and every count is a COUNT(*)."""
    session = service.sessions.get(params.get("_token", ""))
    idle_remaining = (service.sessions.idle_seconds - (time.time() - session["last_seen"])
                      if session else None)
    # The absolute ceiling is the other way a session ends, and staying at the
    # keyboard does not move it. It used to arrive with no warning at all: a
    # wallboard left up overnight simply became the sign-in page. Sent the
    # same way as the idle figure — server-authoritative, so a browser clock
    # that disagrees cannot make the countdown lie.
    max_remaining = (service.sessions.max_seconds - (time.time() - session["created"])
                     if session else None)
    granted = service.app_db.permissions_for(params.get("_username", ""))
    # One lookup, not two: this expression used to call user() twice.
    account = service.app_db.user(session["username"]) if session else None
    names = service.cached_poll("hostname_stats", 10, service.hostname_stats)
    result = {
        "config_version": service.config_version,
        "session": {
            "username": session["username"] if session else "",
            "must_change": bool(account["must_change"]) if account else False,
            "idle_timeout_minutes": service.sessions.idle_seconds // 60,
            "idle_seconds_remaining":
                max(0, round(idle_remaining)) if idle_remaining is not None else None,
            "max_seconds_remaining":
                max(0, round(max_remaining)) if max_remaining is not None else None,
        },
        "uptime_s": time.time() - service.started_at,
        "collector": {
            "running": service.collector.running,
            "status": service.collector.status_text(),
            "counters": service.collector.counters,
            "decoder": service.collector.decoder.stats,
        },
        "dns": {
            "running": bool(service.resolver._thread
                            and service.resolver._thread.is_alive()),
            **names,
        },
        "syslog": {
            "running": service.syslog.running,
            "status": service.syslog.status_text(),
            "counters": service.syslog.counters,
            "ports": service.syslog.ports,
            "fts": service.syslog_db.fts,
            "index_ready": service.syslog_db.index_ready,
            "index_done": service.syslog_db.index_progress[0],
            "index_total": service.syslog_db.index_progress[1],
        },
        "snmp": {
            "running": service.snmp.running,
            "status": service.snmp.status_text(),
            "counters": service.snmp.counters,
            "ports": service.snmp.ports,
            "decoder": service.snmp.decoder.stats,
        },
        "ipam": {
            "running": service.ipam.running,
            **service.ipam.state(),
            "open_conflicts": service.ipam_db.conflict_count(),
        },
        "nodes": {
            "running": service.node_poller.running,
            "status": service.node_poller.status_text(),
            "counters": service.node_poller.counters,
            "device_count": service.nodes_db.device_count(),
            "device_counts": service.nodes_db.device_counts(),
        },
        "alerts": {
            "running": service.alert_engine.running,
            "status": service.alert_engine.status_text(),
            "counters": service.alert_engine.counters,
            "open_count": service.alerts_db.open_count(),
            # The badge on the tab is coloured by this. A count alone
            # said "there are alerts" in the same amber whether the
            # worst of them was a notice or a device being down.
            "open_worst": service.alerts_db.open_summary()["worst"],
        },
        "wireless": {
            "running": service.wireless.running,
            "status": service.wireless.status_text(),
            "counters": service.wireless.counters,
            "ap_counts": service.wireless_db.ap_counts(),
            "controller_count": service.wireless_db.controller_count(),
        },
        "configrx": {
            "running": service.configrx.running,
            "status": service.configrx.status_text(),
            "counters": service.configrx.counters,
            # Which paramiko this process actually loaded, and what it can and
            # does offer — visible before a handshake fails rather than only
            # in the error text of one that already did.
            "ssh": configrx.ssh_algorithm_status(),
        },
        "storage": service.cached_poll("storage", 10, lambda: _storage(service)),
    }
    _drop_unreadable(result, granted, _STATE_MODULE_KEYS)
    return result


def _storage(service) -> dict:
    stores = (("app", service.app_db), ("trace", service.db), ("flow", service.flow_db),
              ("syslog", service.syslog_db), ("snmp", service.snmp_db),
              ("ipam", service.ipam_db), ("nodes", service.nodes_db),
              ("alerts", service.alerts_db), ("wireless", service.wireless_db),
              ("configrx", service.configrx_db))
    result = {f"{name}_path": db.path for name, db in stores}
    result.update({f"{name}_bytes": db.size_bytes() for name, db in stores})
    return result


# ------------------------------------------------------------------ netpath

def _valid_hostname_label(label: str) -> bool:
    return bool(label) and len(label) <= 63 and label[0] != "-" and label[-1] != "-" \
        and all(c.isalnum() or c == "-" for c in label)


def _valid_hostname(host: str) -> bool:
    return bool(host) and len(host) <= 253 \
        and all(_valid_hostname_label(label) for label in host.split("."))


def _validate_target_host(host: str) -> str:
    """A NetPath destination is traced, not polled, so unlike a Nodes device
    it may be a hostname as well as an address — but `999.999.999.999` used
    to be accepted as one and created a target that could never succeed. A
    string shaped like an IPv4 address (four dot-separated numeric groups)
    is held to being one rather than falling through to the hostname rule,
    which would otherwise wave it through as a very ordinary-looking name."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    looks_like_ipv4 = len(parts) == 4 and all(part.isdigit() for part in parts)
    if looks_like_ipv4 or not _valid_hostname(host):
        raise ValueError(
            f"{host!r} is not a valid address or hostname.")
    return host


def _target_json(service, row, last=None) -> dict:
    keys = row.keys()
    return {
        "id": row["id"],
        "host": row["host"],
        "label": row["label"],
        "interval_s": row["interval_s"],
        "max_hops": row["max_hops"],
        "probes": row["probes"],
        "timeout_s": row["timeout_s"] if "timeout_s" in keys else 2.0,
        "warn_rtt_ms": row["warn_rtt_ms"],
        "warn_loss": row["warn_loss"],
        "enabled": bool(row["enabled"]),
        "hop_probe_enabled": bool(row["hop_probe_enabled"]) if "hop_probe_enabled" in keys else False,
        "status": last["status"] if last else "none",
        "last_rtt_ms": last["rtt_ms"] if last else None,
        "last_run": last["started_ts"] if last else None,
    }


def get_targets(service, params, body) -> dict:
    rows = service.db.targets()
    last_traces = service.db.last_traces([row["id"] for row in rows])
    return {"targets": [_target_json(service, row, last_traces.get(row["id"]))
                        for row in rows]}


def post_target(service, params, body) -> dict:
    defaults = service.settings
    host = str(body.get("host", "")).strip()
    if not host:
        raise ValueError("A destination host or address is required")
    host = _validate_target_host(host)
    target_id = service.db.add_target(
        host=host,
        label=str(body.get("label") or host).strip(),
        interval_s=int(body.get("interval_s", defaults["default_interval_s"])),
        max_hops=int(body.get("max_hops", defaults["default_max_hops"])),
        probes=int(body.get("probes", defaults["default_probes"])),
        warn_rtt_ms=float(body.get("warn_rtt_ms", defaults["default_warn_rtt_ms"])),
        warn_loss=float(body.get("warn_loss", defaults["default_warn_loss"])),
        timeout_s=float(body.get("timeout_s", defaults["default_timeout_s"])),
    )
    service.monitor.trace_now(target_id)
    return {"id": target_id}


def put_target(service, params, body, target_id: int) -> dict:
    fields = {k: v for k, v in body.items()
              if k in {"host", "label", "interval_s", "max_hops", "probes",
                       "warn_rtt_ms", "warn_loss", "timeout_s", "enabled"}}
    # The same check the add route makes. Without it the validation there was
    # worth nothing: add a destination with a host that resolves, then edit it
    # to anything at all, and the traceroute thread spends every interval
    # failing against a name that cannot exist — which is the state this
    # release added that validation to stop.
    if "host" in fields:
        # str() first, the way the add route does it: `ip_address(123)` is a
        # perfectly valid address object, so an integer would be stored as
        # 0.0.0.123, and a null would raise AttributeError as a 500 rather
        # than a refusal.
        fields["host"] = _validate_target_host(str(fields["host"] or "").strip())
    service.db.update_target(target_id, **fields)
    if "hop_probe_enabled" in body:
        service.set_hop_probe_enabled(target_id, bool(body["hop_probe_enabled"]))
    return {"ok": True}


def delete_target(service, params, body, target_id: int) -> dict:
    service.db.remove_target(target_id)
    return {"ok": True}


def trace_now(service, params, body, target_id: int) -> dict:
    service.monitor.trace_now(target_id)
    return {"ok": True}


def _block_size(service, target, span: float, width_px: float) -> tuple[float, int]:
    """One block per poll, unless that would be finer than the display can draw."""
    interval = max(float(target["interval_s"]), 1.0)
    ceiling = max(int(max(width_px, 200) / MIN_BLOCK_PX), 20)
    multiple = max(1, math.ceil((span / interval) / ceiling))
    return interval * multiple, multiple


def get_timeline(service, params, body) -> dict:
    target_id = int(params.get("target", 0))
    target = service.db.target(target_id)
    if target is None:
        return {"buckets": [], "summary": {}}

    t0, t1 = _window(params)
    width = _num(params, "width", 1200)
    bucket_s, per_block = _block_size(service, target, t1 - t0, width)
    traces = service.db.traces_between(target_id, t0, t1)
    buckets = build_timeline(traces, t0, t1, bucket_s)
    ok_pct, avg_rtt, count = availability(traces)

    return {
        "t0": t0,
        "t1": t1,
        "bucket_s": bucket_s,
        "polls_per_block": per_block,
        "buckets": [
            {
                "t0": b.t0, "t1": b.t1, "status": b.status, "total": b.total,
                "avg_rtt": b.avg_rtt, "avg_loss": b.avg_loss,
                "max_loss": b.max_loss, "path_changed": b.path_changed,
                "icmp_code": b.icmp_code, "icmp_from": b.icmp_from,
                "icmp_text": unreachable_text(b.icmp_code) if b.icmp_code else "",
                "note": b.note,
                "counts": dict(b.counts),
            }
            for b in buckets
        ],
        "summary": {"healthy_pct": ok_pct, "avg_rtt": avg_rtt, "traces": count},
    }


def _topology_json(service, topo, refusal, target_id: int | None = None,
                   from_nodes: dict | None = None) -> dict:
    code, address = refusal
    # Continuous-probe stats: cumulative counters kept alongside whatever the
    # scheduled traceroutes themselves derived, so a hop shows both "what the
    # traceroute history looks like" and "what live pinging says right now".
    probe_stats = service.db.hop_stats_for_target(target_id) if target_id else {}
    nodes = []
    for node in topo.nodes.values():
        stats = probe_stats.get(node.ip) if node.ip else None
        probes = stats["probes"] if stats else 0
        answered = probes - (stats["lost"] if stats else 0)
        nodes.append({
            "key": f"{node.ttl}|{node.ip or ''}",
            "ttl": node.ttl,
            "ip": node.ip,
            "label": node.label,
            "hostname": node.hostname_label,
            # Where the name came from. A hop named from the Nodes inventory
            # rather than from a PTR record is a device this app monitors,
            # which is worth knowing and is not visible from the name itself.
            "hostname_source": (from_nodes or {}).get(node.ip or "", "dns"),
            "rtt": node.avg_rtt,
            "loss": node.avg_loss,
            "traces": node.traces,
            "share": topo.share(node.traces),
            "is_destination": node.is_destination,
            "is_timeout": node.is_timeout,
            "refusal": code if (address and node.ip == address) else None,
            "refusal_text": unreachable_text(code) if (address and node.ip == address) else "",
            "asn": node.asn,
            "asn_org": node.asn_org,
            "probe_count": probes,
            "probe_loss": (100.0 * stats["lost"] / probes) if stats and probes else None,
            "probe_rtt_min": stats["rtt_min"] if stats else None,
            "probe_rtt_avg": (stats["rtt_sum"] / answered) if stats and answered else None,
            "probe_rtt_max": stats["rtt_max"] if stats else None,
            "last_seen": node.last_seen,
        })
    edges = [
        {"src": f"{e.src[0]}|{e.src[1] or ''}",
         "dst": f"{e.dst[0]}|{e.dst[1] or ''}",
         "share": topo.share(e.traces),
         "last_seen": e.last_seen}
        for e in topo.edges
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "columns": {str(ttl): [f"{n.ttl}|{n.ip or ''}" for n in col]
                    for ttl, col in topo.columns.items()},
        "silent_runs": topo.silent_runs(),
        "total_traces": topo.total_traces,
        "distinct_paths": topo.distinct_paths,
        "refusal": {"code": code, "from": address,
                    "text": unreachable_text(code) if code else ""},
    }


def get_topology(service, params, body) -> dict:
    target_id = int(params.get("target", 0))
    target = service.db.target(target_id)
    if target is None:
        return {"nodes": [], "edges": [], "columns": {}, "total_traces": 0}

    pinned = _num(params, "at")
    if pinned:
        span = _num(params, "tolerance", float(target["interval_s"]))
        trace = service.db.trace_nearest(target_id, pinned, max_delta=max(span, 30))
        if trace is None:
            return {"nodes": [], "edges": [], "columns": {}, "total_traces": 0,
                    "snapshot": {"found": False, "at": pinned}}
        rows = service.db.hop_rows_for_trace(trace["id"])
        ips = {r["ip"] for r in rows}
        names = service.app_db.hostnames(ips)
        from_nodes = hostresolve.fill_from_nodes(service.nodes_db, names, ips)
        asn_data = service.app_db.asn_info(ips)
        topo = build_topology(rows, dest_ip=service.db.destination_ip(target_id),
                              hostnames=names, asn_data=asn_data)
        keys = trace.keys()
        code = trace["icmp_code"] if "icmp_code" in keys else None
        payload = _topology_json(service, topo, (code, trace["icmp_from"]
                                                 if "icmp_from" in keys else None),
                                 target_id, from_nodes)
        payload["snapshot"] = {
            "found": True,
            "at": trace["started_ts"],
            "status": trace["status"],
            "rtt_ms": trace["rtt_ms"],
            "loss_pct": trace["loss_pct"],
            "error": trace["error"],
            "icmp_code": code,
            "icmp_from": trace["icmp_from"] if "icmp_from" in keys else None,
        }
        return payload

    t0, t1 = _window(params)
    rows = service.db.hop_rows_between(target_id, t0, t1)
    ips = {r["ip"] for r in rows}
    names = service.app_db.hostnames(ips)
    # A hop with no PTR record that IS a device this app monitors gets that
    # device's name instead of the literal "no PTR record". Done here rather
    # than in monitor.Resolver because service.nodes_db is already in hand at
    # this layer — and because baking a Nodes name into the DNS cache would
    # have it aged out on a DNS schedule and go stale when the device is
    # renamed. See hostresolve.fill_from_nodes for the precedence.
    from_nodes = hostresolve.fill_from_nodes(service.nodes_db, names, ips)
    asn_data = service.app_db.asn_info(ips)
    # Aged against t1, the end of the window being drawn, so panning back into
    # last month still shows the path as it stood then. The pinned-snapshot
    # branch above deliberately skips this: one trace is one instant, and every
    # hop in it was by definition seen at that instant.
    stale_hours = float(service.settings.get("topology_stale_hours", 24.0) or 0)
    topo = build_topology(rows, dest_ip=service.db.destination_ip(target_id),
                          hostnames=names, asn_data=asn_data,
                          stale_after_s=max(stale_hours, 0.0) * 3600.0,
                          window_end=t1)

    code = address = None
    for trace in reversed(service.db.traces_between(target_id, t0, t1)):
        keys = trace.keys()
        if "icmp_code" in keys and trace["icmp_code"]:
            code, address = trace["icmp_code"], trace["icmp_from"]
            break
    payload = _topology_json(service, topo, (code, address), target_id, from_nodes)
    payload["snapshot"] = {"found": False}
    return payload


# ------------------------------------------------------------------ netflow

def _flow_filters(params) -> dict:
    return {
        "src_ip": params.get("src", ""),
        "dst_ip": params.get("dst", ""),
        "port": params.get("port") or None,
        "protocol": _num(params, "protocol", None, int),
        "exporter": params.get("exporter") or None,
    }


ADDRESS_DIMENSIONS = ("Source", "Destination", "Conversation")
ARROW = " \u2192 "


def _address_names(service, dimension: str, keys) -> dict:
    """Reverse-DNS names for the addresses behind a set of grouping keys.

    Only for the dimensions that are addresses. A conversation key holds two of
    them, so both sides are looked up and substituted.
    """
    if dimension not in ADDRESS_DIMENSIONS:
        return {}
    if not service.flow_settings.get("resolve_addresses"):
        return {}
    addresses = set()
    for key in keys:
        text = str(key or "")
        if not text or text.startswith("\u2014"):
            continue
        addresses.update(part.strip() for part in text.split(ARROW))
    return {ip: name for ip, name in service.app_db.hostnames(addresses).items() if name}


def _flow_label(service, dimension: str, key, names: dict | None = None) -> str:
    if key is None:
        return "unknown"
    text = str(key)
    if text.startswith("\u2014"):
        return text
    if dimension == "Application":
        return port_name(key, bool(service.flow_settings.get("resolve_ports", True)))
    if dimension == "Protocol":
        return protocol_name(key)
    if dimension in ("Ingress interface", "Egress interface"):
        return service.flow_db.interface_names().get(text, text)
    if dimension == "Exporter":
        # Same name the Exporter column shows, so the chart, the bars and the
        # table cannot disagree about what a device is called. filterByBar
        # sends the key rather than this label, so filtering still keys off
        # the address.
        return hostresolve.resolve_name(
            service.nodes_db, service.app_db, text) or text
    if dimension in ("Source AS", "Destination AS"):
        return f"AS{text}"
    if names and dimension in ADDRESS_DIMENSIONS:
        # Named where a name exists, address where it does not, so an internal
        # host with no PTR record still reads sensibly beside a named one.
        return ARROW.join(names.get(part.strip(), part.strip())
                          for part in text.split(ARROW))
    return text


def _flow_bucket(service, span: float) -> float:
    configured = int(service.flow_settings.get("bucket_seconds", 0) or 0)
    if configured:
        return float(configured)
    for limit, bucket in [(900, 10), (7200, 60), (43200, 300),
                          (172800, 900), (1209600, 3600)]:
        if span <= limit:
            return float(bucket)
    return 21600.0


def get_flow_overview(service, params, body) -> dict:
    t0, t1 = _window(params)
    span = t1 - t0
    dimension = params.get("dimension", "Application")
    filters = _flow_filters(params)
    bucket = _flow_bucket(service, span)
    top_n = int(service.flow_settings.get("top_n", 10))

    # One aggregate pass over the window feeds the chart, the top-N bars and
    # the totals line together; they used to be three separate scans (four,
    # counting the one series() made internally), which is what made a wide
    # window crawl.
    times, series, bucket_s, top_rows, totals = service.flow_db.overview(
        t0, t1, dimension, filters, bucket, series_limit=8, top_limit=top_n)

    names = _address_names(service, dimension,
                           list(series) + [row["key"] for row in top_rows])

    return {
        "t0": t0, "t1": t1, "bucket_s": bucket_s, "dimension": dimension,
        "times": times,
        "series": [{"name": _flow_label(service, dimension, key, names),
                    "values": values}
                   for key, values in series.items()],
        "top": [{"key": str(row["key"]),
                 "label": _flow_label(service, dimension, row["key"], names),
                 "bytes": row["bytes"] or 0,
                 "bytes_text": format_bytes(row["bytes"]),
                 "rate_text": format_rate(row["bytes"], span),
                 "packets": row["packets"] or 0,
                 "flows": row["flows"]}
                for row in top_rows],
        "totals": {
            "bytes": totals["bytes"], "packets": totals["packets"],
            "flows": totals["flows"],
            "bytes_text": format_bytes(totals["bytes"]),
            "rate_text": format_rate(totals["bytes"], span),
            "packets_text": format_packets(totals["packets"]),
        },
        "exporters": [{"address": row["address"], "version": row["version"],
                       "flows": row["flows"], "last_seen": row["last_seen"]}
                      for row in service.flow_db.exporters()],
    }


# The screen has always asked for the top 250 records by whichever order
# is selected (nf-order in index.html); FLOW_EXPORT_CAP is the export
# ceiling item 1 asked every capped list to lift — comfortably past what
# one export click should ever hand back, still far short of "do not
# buffer a million rows".
FLOW_SCREEN_LIMIT = 250
FLOW_EXPORT_CAP = 20000


def _flow_records_rows(service, params, limit: int) -> tuple[list[dict], bool]:
    """The row-producing half of get_flow_records, factored out so the
    export handler below can ask for FLOW_EXPORT_CAP rows through the
    identical filter/window/order path the screen uses for its 250 —
    same params, same permission gate, just a taller limit."""
    t0, t1 = _window(params)
    filters = _flow_filters(params)
    order = params.get("order", "bytes")
    rows = service.flow_db.flows(t0, t1, filters, limit=limit + 1, order=order)
    truncated = len(rows) > limit
    rows = rows[:limit]

    resolve_ports = bool(service.flow_settings.get("resolve_ports", True))
    names = {}
    if service.flow_settings.get("resolve_addresses"):
        addresses = {r["src_ip"] for r in rows} | {r["dst_ip"] for r in rows}
        names = {ip: name for ip, name
                 in service.app_db.hostnames(addresses).items() if name}
    interfaces = service.flow_db.interface_names()
    # A page of records comes from a handful of exporters, so one lookup per
    # distinct address is cheap. Resolved through the shared helper rather
    # than a bespoke query, so the Exporter column agrees with Syslog's Host
    # column and Alerts' Object column about what a device is called:
    # SNMP sysName, then a manual name that is not just the address, then
    # the reverse-DNS cache.
    exporter_names = {}
    for address in {r["exporter"] for r in rows if r["exporter"]}:
        name = hostresolve.resolve_name(service.nodes_db, service.app_db, address)
        if name and name != address:
            exporter_names[address] = name
    # Flow-to-path correlation: which NetPath target (if any) last traced a
    # route ending at each address, so the frontend can offer a "view route"
    # link without a per-row round trip.
    addr_targets = service.db.targets_by_destination_ips(
        {r["src_ip"] for r in rows} | {r["dst_ip"] for r in rows})

    records = []
    for row in rows:
        sampling = row["sampling"] or 1
        records.append({
            "ts": row["ts_end"],
            "src_ip": row["src_ip"],
            "src_name": names.get(row["src_ip"]),
            "src_port": port_name(row["src_port"], resolve_ports),
            # The number as well as the label: "443 https" sorts as text
            # between 44 and 45, which is not what clicking the column means.
            "src_port_num": row["src_port"],
            "src_target_id": addr_targets.get(row["src_ip"]),
            "dst_ip": row["dst_ip"],
            "dst_name": names.get(row["dst_ip"]),
            "dst_port": port_name(row["dst_port"], resolve_ports),
            "dst_port_num": row["dst_port"],
            "dst_target_id": addr_targets.get(row["dst_ip"]),
            "protocol": protocol_name(row["protocol"]),
            "bytes": (row["bytes"] or 0) * sampling,
            "bytes_text": format_bytes((row["bytes"] or 0) * sampling),
            "packets": (row["packets"] or 0) * sampling,
            "packets_text": format_packets((row["packets"] or 0) * sampling),
            "in_if": interfaces.get(f"{row['exporter']}:{row['in_if']}",
                                    str(row["in_if"])),
            "out_if": interfaces.get(f"{row['exporter']}:{row['out_if']}",
                                     str(row["out_if"])),
            "exporter": row["exporter"],
            # Beside the address, never instead of it: the tooltip shows
            # both, and the exporter filter keys off the address.
            "exporter_name": exporter_names.get(row["exporter"]),
        })
    return records, truncated


def get_flow_records(service, params, body) -> dict:
    records, _truncated = _flow_records_rows(service, params, FLOW_SCREEN_LIMIT)
    return {"records": records}


def get_flow_records_export(service, params, body) -> dict:
    records, truncated = _flow_records_rows(service, params, FLOW_EXPORT_CAP)
    header = ["ts", "src_ip", "src_name", "src_port", "dst_ip", "dst_name",
             "dst_port", "protocol", "bytes", "packets", "in_if", "out_if",
             "exporter", "exporter_name"]
    csv_rows = [[r.get(key) for key in header] for r in records]
    return _csv_response("netflow", header, csv_rows, truncated=truncated,
                         cap=FLOW_EXPORT_CAP)


def post_collector(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.flow_settings["enabled"] = True
        service.flow_db.save_settings({"enabled": True})
        service.collector.start(service.flow_settings)
    elif action == "stop":
        service.flow_settings["enabled"] = False
        service.flow_db.save_settings({"enabled": False})
        service.collector.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.collector.running,
            "status": service.collector.status_text()}


def post_test_packet(service, params, body) -> dict:
    """A v5 header declaring zero records: valid, decodable, carries nothing."""
    import socket
    host = "127.0.0.1"
    port = int(service.flow_settings.get("port", 2055))
    packet = bytes(1) + bytes([5]) + bytes(22)
    sent, error = True, None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (host, port))
        sock.close()
    except OSError as exc:
        sent, error = False, str(exc)

    script = (
        "$udp = [System.Net.Sockets.UdpClient]::new()\n"
        f'$udp.Connect("{host}", {port})\n'
        "$bytes = New-Object byte[] 24\n"
        "$bytes[1] = 5          # NetFlow v5 header, zero records\n"
        "[void]$udp.Send($bytes, $bytes.Length)\n"
        "$udp.Close()\n"
        f'Write-Host "sent 24 bytes to {host}:{port}"'
    )
    return {"sent": sent, "error": error, "host": host, "port": port,
            "script": script}


# ---------------------------------------------------------------------- SSH


def get_ssh_device(service, params, body, device_id) -> dict:
    """What the terminal window needs before it opens its socket: which
    device this is, whether it can log in without asking, and what is known
    about the device's host key. Gated on ("ssh", W) like the socket itself
    — there is no read-only half of "open a shell"."""
    device, host, port = _ssh_device_host(service, device_id)
    config = service.configrx_db.device_config(device_id)
    # nodes.js's displayName() precedence, the same one ConfigRX's device
    # list uses: the SNMP hostname wins unless the device is pinned to its
    # manual name, with the IP as the last resort. Resolved here, once — the
    # page shows what it is given rather than recomputing it.
    name = ((device["name"] if device["display_name_source"] == "manual" else None)
            or device["sys_name"] or device["name"] or device["ip"])
    available = configrx.paramiko_available()
    return {
        "device": {"id": device["id"], "ip": host, "name": name},
        "has_credential": bool(config and config["ssh_username"]
                               and config["ssh_password_enc"]),
        "ssh_port": port,
        "paramiko": {"available": available,
                     "message": "" if available else configrx.PARAMIKO_MISSING},
        "host_key": sshterm.stored_host_key(service, host, port),
    }


def ws_ssh_device(websocket, service, params, device_id) -> None:
    """The terminal's WebSocket. Hijacking: the connection is held for the
    whole session, so this takes the socket server.py already upgraded
    rather than a body, and returns nothing to serialise. server.py's
    _route has already established who is asking, that the page asking is
    this one (Origin), and that they hold ("ssh", W); the session token
    goes with them so the session can be ended the moment that sign-in is."""
    service.ssh_sessions.open(websocket, device_id,
                              params.get("_username", ""),
                              params.get("_client", ""),
                              params.get("_token", ""))


ws_ssh_device.hijack = True


# -------------------------------------------------------------------- debug


# Which module's grant an event category belongs to. eventlog.CATEGORIES is
# a display taxonomy, not an authorization one, so the mapping is written
# out here rather than assumed. The three that name no module of their own
# go to `settings`: `system` carries sign-in history and account changes,
# `error` carries every module's failure detail (including ConfigRX's), and
# `dns` names the addresses the resolver is working through. Holding
# `debug` alone still shows the worker tables, counters and schedules,
# which is what the Debug page is for.
_EVENT_CATEGORY_MODULE = {
    "trace": "netpath",
    "dns": "settings",
    "netflow": "netflow",
    "snmp": "snmp",
    "nodes": "nodes",
    "alerts": "alerts",
    "ipam": "ipam",
    "wireless": "wireless",
    "configrx": "configrx",
    "system": "settings",
    "error": "settings",
}


def get_debug(service, params, body) -> dict:
    since = int(_num(params, "since", 0, int) or 0)
    state = service.monitor.worker_state()
    schedule = service.monitor.next_runs()
    now = time.time()

    workers = []
    running = queued = 0
    targets = service.db.targets()
    last_traces = service.db.last_traces([target["id"] for target in targets])
    for target in targets:
        last = last_traces.get(target["id"])
        work = state.get(target["id"])
        keys = target.keys()
        timeout_s = float(target["timeout_s"]) if "timeout_s" in keys else 2.0
        entry = {
            "id": target["id"],
            "label": target["label"] or target["host"],
            "host": target["host"],
            "state": "scheduled" if target["enabled"] else "disabled",
            "elapsed": None,
            "budget": expected_budget(target["max_hops"], target["probes"], timeout_s),
            "last_run": last["started_ts"] if last else None,
            "duration": last["duration_s"] if last else None,
            "next_run": schedule.get(target["id"]),
            "interval_s": target["interval_s"],
            "status": last["status"] if last else "none",
        }
        if work:
            if work.get("started"):
                running += 1
                entry["state"] = "tracing"
                entry["elapsed"] = now - work["started"]
            else:
                queued += 1
                entry["state"] = "queued"
                entry["elapsed"] = now - (work.get("queued") or now)
        workers.append(entry)

    # The event log is one stream carrying every module's events, and
    # `debug: read` was enough to read all of them — device names and
    # addresses, DHCP server labels, ConfigRX failure detail, sign-in
    # history — with no grant on any of those modules. Each category is
    # filtered by the module it belongs to, so the Debug page shows a
    # caller their own modules' events and nothing else.
    granted = service.app_db.permissions_for(params.get("_username", ""))
    visible = {category for category, module in _EVENT_CATEGORY_MODULE.items()
               if _permissions.allows(granted.get(module), _permissions.READ)}
    events = [
        {"seq": e.seq, "ts": e.ts, "clock": e.clock, "category": e.category,
         "target": e.target, "message": e.message, "detail": e.detail}
        for e in service.log.since(since) if e.category in visible
    ]

    # One row per address currently out for a reverse lookup.
    dns_state = service.resolver.worker_state()
    dns_workers = sorted(
        [{"ip": ip, "elapsed": now - info["started"]}
         for ip, info in dns_state.items() if info["started"]],
        key=lambda row: row["elapsed"], reverse=True)

    # One row per subnet currently being scanned, one per DHCP server
    # currently being polled — both come from the same worker, so they share
    # a table rather than needing a section each for what is usually zero or
    # one row.
    ipam_state = service.ipam.state()
    ipam_workers = []
    if ipam_state.get("scan_started") or ipam_state.get("poll_started"):
        subnets_by_id = {s["id"]: s for s in service.ipam_db.subnets_by_ids(
            list(ipam_state.get("scan_started", {}).keys()))}
        servers_by_id = {s["id"]: s for s in service.ipam_db.dhcp_servers_by_ids(
            list(ipam_state.get("poll_started", {}).keys()))}
        for subnet_id, started in ipam_state.get("scan_started", {}).items():
            subnet = subnets_by_id.get(subnet_id)
            ipam_workers.append({
                "kind": "scan",
                "label": subnet["label"] if subnet else f"subnet #{subnet_id}",
                "elapsed": now - started,
            })
        for server_id, started in ipam_state.get("poll_started", {}).items():
            dhcp_server = servers_by_id.get(server_id)
            ipam_workers.append({
                "kind": "poll",
                "label": dhcp_server["label"] if dhcp_server else f"server #{server_id}",
                "elapsed": now - started,
            })
        ipam_workers.sort(key=lambda row: row["elapsed"], reverse=True)

    # One row per device currently being polled or queued to be — the
    # same "join worker_state against the entity list for a label" shape
    # the NetPath `workers` table above already uses, just without that
    # table's per-target budget/schedule columns, since a device's poll
    # has no fixed budget the way a trace's hop/probe counts imply one.
    node_state = service.node_poller.worker_state()
    node_workers = []
    if node_state:
        devices_by_id = {d["id"]: d for d in
                         service.nodes_db.devices_by_ids(list(node_state.keys()))}
        for device_id, work in node_state.items():
            device = devices_by_id.get(device_id)
            label = (device["name"] or device["ip"]) if device else f"device #{device_id}"
            if work.get("started"):
                node_workers.append({"kind": "polling", "label": label,
                                     "elapsed": now - work["started"]})
            else:
                node_workers.append({"kind": "queued", "label": label,
                                     "elapsed": now - (work.get("queued") or now)})
        node_workers.sort(key=lambda row: row["elapsed"], reverse=True)

    # One row per discovery scan currently sweeping, with its live
    # progress counters — same shape as the worker tables above plus the
    # probed/found columns a bounded sweep naturally has.
    discovery_scans = []
    for job in service.nodes_db.discovery_jobs(20):
        if job["state"] != "running":
            continue
        discovery_scans.append({
            "label": f"{job['target']} ({job['kind']})",
            "probed": job["probed"], "total": job["total"],
            "responded": job["responded"], "identified": job["identified"],
            "elapsed": now - job["started_ts"],
        })
    discovery_scans.sort(key=lambda row: row["elapsed"], reverse=True)

    return {
        "workers": workers,
        "dns_workers": dns_workers,
        "ipam_workers": ipam_workers,
        "node_workers": node_workers,
        # polls/ok/timeout/auth_fail/unsupported/errors/overruns — already
        # computed on every poll, previously never surfaced anywhere.
        "node_counters": service.node_poller.counters,
        "discovery_scans": discovery_scans,
        "events": events,
        "last_seq": service.log.last_seq,
        "targets": sorted({e["target"] for e in events if e["target"]}),
        "summary": {
            "scheduler": service.monitor.running,
            "workers_busy": running,
            "workers_total": service.monitor.workers,
            "queued": queued,
            "resolver": bool(service.resolver._thread
                             and service.resolver._thread.is_alive()),
            "dns_pending": len(dns_workers),
            "collector": service.collector.running,
            "packets": service.collector.counters["packets"],
            "ipam": service.ipam.running,
            "ipam_active": len(ipam_workers),
            "nodes": service.node_poller.running,
            "nodes_active": len(node_workers),
            "discovery_active": len(discovery_scans),
            "buffered": len(service.log.all()),
        },
    }


def post_debug_clear(service, params, body) -> dict:
    service.log.clear()
    return {"last_seq": service.log.last_seq}


# ----------------------------------------------------------------- settings

# Which module owns each settings scope, and what POST /api/settings does
# with it: {scope: (Service method name, response key)}. The route table
# derives the permission from THIS table (server._settings_requirement)
# rather than from permissions.MODULES — a module in MODULES with no entry
# here (`debug` was one) used to be authorized against itself and then fall
# through to the global writer, which is how a debug:write account rewrote
# the listener's bind address, TLS paths and the DNS server. Anything not
# named here is the Settings module's, by construction.
SETTINGS_SCOPES = {
    "netpath": ("apply_netpath_settings", "settings"),
    "netflow": ("apply_netflow_settings", "flow_settings"),
    "syslog": ("apply_syslog_settings", "syslog_settings"),
    "snmp": ("apply_snmp_settings", "snmp_settings"),
    "ipam": ("apply_ipam_settings", "ipam_settings"),
    "nodes": ("apply_nodes_settings", "nodes_settings"),
    "alerts": ("apply_alerts_settings", "alerts_settings"),
    "wireless": ("apply_wireless_settings", "wireless_settings"),
    "configrx": ("apply_configrx_settings", "configrx_settings"),
}


# Global settings that are not an operator's to change even with Settings
# write: turning this host's self-update on decides whether it will replace
# its own code from the internet, and the ldap_* keys decide who may sign
# in at all and where a password gets sent — both are administrator
# decisions in the same sense creating an account is, not preferences.
ADMIN_ONLY_SETTINGS = ("updates_enabled", "ldap_enabled", "ldap_url",
                      "ldap_bind_dn_template", "ldap_allow_cleartext",
                      "ldap_timeout_s")


def _is_admin(service, params) -> bool:
    granted = service.app_db.permissions_for(params.get("_username", ""))
    return _permissions.allows(granted.get("admin"), _permissions.WRITE)


def _may_change_admin_settings(service, params) -> bool:
    """Whether this caller may change ADMIN_ONLY_SETTINGS. Its own function
    so there is exactly one place the answer is decided."""
    return _is_admin(service, params)


# Mirrors the min/max already on each of these inputs in index.html: the
# Settings page refuses an out-of-range number before ever posting, but an
# API client can skip the browser entirely, so this route holds the global
# scope's numeric settings to the same bounds. None as a high means the
# field is open-ended (a database cap has a floor, never a ceiling).
_GLOBAL_SETTINGS_RANGES = {
    "dns_workers": (1, 32),
    "dns_timeout_s": (0.5, 30),
    "dns_cache_days": (1, 365),
    "asn_cache_days": (1, 365),
    "netpath_refresh_s": (1, 300),
    "nodes_refresh_s": (1, 3600),
    "alerts_refresh_s": (1, 3600),
    "netflow_refresh_s": (1, 3600),
    "snmp_refresh_s": (1, 3600),
    "syslog_refresh_s": (1, 3600),
    "ipam_refresh_s": (1, 3600),
    "wireless_refresh_s": (1, 3600),
    "configrx_refresh_s": (1, 3600),
    "dashboard_refresh_s": (1, 3600),
    "debug_refresh_s": (1, 60),
    "max_trace_db_mb": (16, None),
    "max_flow_db_mb": (16, None),
    "max_snmp_db_mb": (16, None),
    "max_syslog_db_mb": (16, None),
    "max_ipam_db_mb": (16, None),
    "max_nodes_db_mb": (16, None),
    "max_alerts_db_mb": (16, None),
    "session_idle_minutes": (1, 1440),
    "session_max_hours": (1, 168),
}


def _check_settings_ranges(values: dict) -> None:
    for key, (low, high) in _GLOBAL_SETTINGS_RANGES.items():
        if key not in values:
            continue
        value = values[key]
        if value < low or (high is not None and value > high):
            range_text = (f"between {low} and {high}" if high is not None
                         else f"at least {low}")
            raise ValueError(f"{key} must be {range_text}")


def _scope_defaults(scope: str) -> dict:
    """The defaults dict whose value types a scope's settings must match."""
    from .. import (alertsdb, appdb, configrxdb, db, flowdb, ipamdb, nodesdb,
                    snmptrapdb, syslogdb, wirelessdb)
    return {
        "netpath": db.NETPATH_DEFAULTS, "netflow": flowdb.DEFAULTS,
        "syslog": syslogdb.DEFAULTS, "snmp": snmptrapdb.DEFAULTS,
        "ipam": ipamdb.DEFAULTS, "nodes": nodesdb.DEFAULTS,
        "alerts": alertsdb.DEFAULTS, "wireless": wirelessdb.DEFAULTS,
        "configrx": configrxdb.DEFAULTS,
    }.get(scope, appdb.GLOBAL_DEFAULTS)


def post_settings(service, params, body) -> dict:
    from ..settingsutil import coerce_settings

    scope = str(body.get("scope", "global"))
    values = body.get("values") or {}
    if not isinstance(values, dict):
        raise ValueError("values must be an object")
    granted = service.app_db.permissions_for(params.get("_username", ""))
    touched = [key for key in ADMIN_ONLY_SETTINGS if key in values]
    if touched and not _may_change_admin_settings(service, params):
        raise _permissions.Forbidden(
            f"Changing {', '.join(touched)} needs administrator access")
    # Typed before anything is written. The apply_* methods update and save
    # first and coerce later (or never), and the loaders hand back whatever
    # was stored, so a null or "abc" for a numeric key was persisted and
    # then raised from the next start's int() — every start, until the
    # database was edited by hand.
    values = coerce_settings(_scope_defaults(scope), values, strict=True)
    _check_settings_ranges(values)
    # The keys, never the values: a settings value can be a credential-
    # adjacent path or a hostname, and an audit trail is a record of what
    # was touched, not a second copy of the configuration.
    _audit(service, params, "settings.change", target=scope,
           detail=", ".join(sorted(str(k) for k in values)) or "nothing")
    entry = SETTINGS_SCOPES.get(scope)
    if entry is None:
        applied = service.apply_global_settings(values)
        return {"settings": _visible_settings(applied, granted)}
    method, key = entry
    applied = getattr(service, method)(values)
    # NetPath's apply returns the merged settings dict, which carries the
    # global keys too; every other scope returns only its own module's.
    return {key: _visible_settings(applied, granted) if key == "settings" else applied}


def post_update(service, params, body) -> dict:
    from .. import selfupdate

    # Refused here as well as inside apply(): this is the one that produces
    # a 403 rather than a JSON error, so an operator sees a refusal rather
    # than a failed update, and nothing reaches the network at all.
    if not selfupdate.updates_enabled(service.app_db):
        raise _permissions.Forbidden(selfupdate.UPDATES_DISABLED_MESSAGE)
    _audit(service, params, "update.requested")
    db_path = getattr(service.app_db, "path", "")
    result = selfupdate.apply(service.app_db)
    if result.get("ok") and not result.get("up_to_date"):
        service.log.add(SYSTEM_CATEGORY,
                        f"Updated to {result.get('tag') or result['commit']}; "
                        f"restarting")
        # Through a connection of its own, not the service's: a successful
        # apply() has already stopped everything and closed app.db, so the
        # ordinary audit path could only fail here — which is what it did,
        # losing the record of who replaced this host's code and writing a
        # traceback to the log on every successful update.
        from ..appdb import write_audit
        write_audit(db_path, str(params.get("_username", "")),
                    str(params.get("_client", "")), "update.installed",
                    target=str(result.get("tag") or result.get("commit") or ""))
    elif not result.get("ok"):
        _audit(service, params, "update.refused",
               detail=str(result.get("error", "")))
    return result


# Maintenance actions that delete everything rather than applying a
# retention policy: `prune(0, 0)` means "every row". On a regulated network
# prune_syslog erases the evidence trail and prune_configrx erases every
# stored config. Each needs `confirm: true` in the body, and each is
# audited with the number of rows it destroyed.
_DESTRUCTIVE_MAINTENANCE = {
    "prune_traces", "prune_flows", "prune_syslog", "prune_snmp", "prune_ipam",
    "prune_nodes", "prune_alerts", "prune_configrx",
}


def post_maintenance(service, params, body) -> dict:
    action = str(body.get("action", ""))
    if action in _DESTRUCTIVE_MAINTENANCE and body.get("confirm") is not True:
        raise ValueError(
            f"{action} deletes stored history outright — it is not the "
            f"retention policy. Send \"confirm\": true to go ahead.")

    def done(message: str, counted: int) -> dict:
        _audit(service, params, f"maintenance.{action}",
               target=action, detail=f"{counted} row(s): {message}")
        service.log.add(SYSTEM_CATEGORY, f"Maintenance {action}: {message}")
        return {"message": message, "removed": counted}

    if action == "redns":
        removed = service.app_db.clear_hostnames()
        return done(f"Cleared {removed} cached names; "
                    f"lookups restart within 15s", removed)
    if action == "prune_traces":
        days = float(service.settings.get("trace_retention_days", 90))
        removed = service.db.prune(days)
        return done(f"Deleted {removed} traces older than {days:.0f} days",
                    removed)
    if action == "prune_flows":
        removed = service.flow_db.prune(0, 0)
        return done(f"Deleted {removed} flow records", removed)
    if action == "prune_syslog":
        removed = service.syslog_db.prune(0, 0)
        return done(f"Deleted {removed} syslog messages", removed)
    if action == "prune_snmp":
        removed = service.snmp_db.prune(0, 0)
        return done(f"Deleted {removed} stored traps", removed)
    if action == "prune_ipam":
        hosts = service.ipam_db.prune_hosts(0)
        conflicts = service.ipam_db.prune_conflicts(0)
        scans = service.ipam_db.prune_scans(0)
        return done(f"Deleted {hosts} host record(s), {conflicts} "
                    f"resolved conflict(s), {scans} scan record(s)",
                    hosts + conflicts + scans)
    if action == "prune_nodes":
        removed = service.nodes_db.prune(sample_days=0, event_days=0, discovery_days=0)
        return done(f"Deleted {removed} stored sample(s)/event(s)", removed)
    if action == "prune_alerts":
        removed = service.alerts_db.prune(0)
        return done(f"Deleted {removed} resolved alert(s)", removed)
    if action == "prune_configrx":
        removed = service.configrx_db.prune(0, 0)
        return done(f"Deleted {removed} stored config backup(s)", removed)
    # A 200 saying "Unknown action" made a typo in an automation script look
    # like a successful prune.
    raise ValueError(f"Unknown maintenance action {action!r}")


def get_audit(service, params, body) -> dict:
    """The on-disk audit trail. Administrator-only, and read-only: there is
    no endpoint anywhere that deletes from this table.

    `since` is the last id already seen (the same cursor shape the Debug
    page's event feed uses), `limit` how many rows to return at most,
    capped server-side.
    """
    since = int(_num(params, "since", 0, int) or 0)
    limit = int(_num(params, "limit", 500, int) or 500)
    rows = service.app_db.audit_events(since, limit)
    return {
        "events": [{"id": row["id"], "ts": row["ts"],
                    "username": row["username"], "client": row["client"],
                    "action": row["action"], "target": row["target"],
                    "detail": row["detail"]} for row in rows],
        "last_id": rows[-1]["id"] if rows else since,
        "max_id": service.app_db.audit_last_id(),
        "limit": min(max(1, limit), _appdb.AUDIT_MAX_LIMIT),
    }


# ------------------------------------------------------------------- syslog

def _syslog_filters(params) -> dict:
    return {
        "text": params.get("q", ""),
        "severity": params.get("severity") or None,
        "facility": params.get("facility") or None,
        "source": params.get("source", ""),
        "host": params.get("host", ""),
        "app": params.get("app", ""),
    }


def get_syslog_overview(service, params, body) -> dict:
    """Histogram plus the context the page needs; deliberately cheap."""
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    bucket = _num(params, "bucket", 3600)
    filters = _syslog_filters(params)

    buckets = service.syslog_db.histogram(t0, t1, bucket, filters)
    stats = service.syslog_db.stats()
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": buckets,
        "stats": stats,
        "sources": [{"source": row["source"], "count": row["n"],
                     "last_seen": row["last_seen"]}
                    for row in service.syslog_db.sources()],
    }


# The most rows a search returns whatever limit is asked for. Was an inline
# 2000 in two handlers; named so the response can say so and the page can
# read "300 of 4,120 shown" instead of "300 shown".
SEARCH_ROW_CAP = 2000

# Item 1: the on-screen search stays capped at SEARCH_ROW_CAP — that is a
# "do not try to render this many table rows" limit, not a data limit —
# but an export exists precisely to leave with more than a screen can
# hold, so both the syslog and SNMP trap exports get this taller ceiling
# instead.
EXPORT_ROW_CAP = 20000


def _syslog_search_rows(service, params, cap: int, *,
                        use_request_limit: bool = True
                        ) -> tuple[list[dict], bool, float, int, bool]:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    filters = _syslog_filters(params)

    started = time.time()
    # The screen's own request carries a `limit` (300 on-screen default,
    # or whatever page size the UI asked for) that this bounds against
    # `cap` — SEARCH_ROW_CAP for the screen. The export handler below asks
    # for use_request_limit=False instead of threading its own `limit`
    # through: the export buttons never send a limit param at all, so a
    # request has no way to distinguish "the caller explicitly wants only
    # 300 rows" from "the caller sent nothing and 300 is just the
    # screen's on-screen default" — reading that default as a request
    # here is what silently capped every export at 300 rows while the
    # response's own cap field still said EXPORT_ROW_CAP. An export
    # always wants every matching row up to the export ceiling, full stop.
    if use_request_limit:
        limit = int(_num(params, "limit", 300, int) or 300)
        effective = min(limit, cap)
    else:
        effective = cap
    rows = service.syslog_db.search(t0, t1, filters, limit=effective + 1)
    # One row past the limit says whether anything was left out; `len(rows)
    # >= effective` reported a cut-off for a window with exactly `effective`
    # matches, which was a lie the count label repeated.
    truncated = len(rows) > effective
    rows = rows[:effective]
    elapsed_ms = (time.time() - started) * 1000

    names = {}
    if service.syslog_settings.get("resolve_sources"):
        names = {ip: name for ip, name in
                 service.app_db.hostnames({row["source"] for row in rows}).items()
                 if name}

    # The message itself only supplies a host when the device bothers to
    # self-report one; fill the gap (blank, or just the source IP
    # repeated) from whichever of the Nodes SNMP identity or the DNS
    # cache knows a real name for that address — Nodes first, since it's
    # a locally-managed, polled identity rather than a PTR record. Unlike
    # the Source column's resolved name above, this always runs — it's
    # filling in what the Host column is supposed to mean, not an opt-in
    # display toggle.
    resolved_hosts = {}
    need = {row["source"] for row in rows
            if not row["host"] or row["host"] == row["source"]}
    for ip in need:
        name = hostresolve.resolve_name(service.nodes_db, service.app_db, ip)
        if name:
            resolved_hosts[ip] = name

    messages = [
        {
            "id": row["id"], "ts": row["ts"], "source": row["source"],
            "source_name": names.get(row["source"], ""),
            "host": (row["host"] or "") if row["host"] and row["host"] != row["source"]
                    else (resolved_hosts.get(row["source"], "") or row["host"] or ""),
            "app": row["app"] or "",
            "procid": row["procid"] or "", "msgid": row["msgid"] or "",
            "severity": row["severity"],
            "severity_name": severity_name(row["severity"]),
            "facility": row["facility"],
            "facility_name": facility_name(row["facility"]),
            "message": row["message"], "raw": row["raw"],
        }
        for row in rows
    ]
    return messages, truncated, elapsed_ms, effective, service.syslog_db.fts


def get_syslog_search(service, params, body) -> dict:
    messages, truncated, elapsed_ms, effective, fts = _syslog_search_rows(
        service, params, SEARCH_ROW_CAP)
    return {"took_ms": round(elapsed_ms, 1), "limit": effective, "cap": SEARCH_ROW_CAP,
            "truncated": truncated, "fts": fts, "messages": messages}


def get_syslog_search_export(service, params, body) -> dict:
    messages, truncated, _elapsed_ms, _effective, _fts = _syslog_search_rows(
        service, params, EXPORT_ROW_CAP, use_request_limit=False)
    header = ["id", "ts", "source", "source_name", "host", "app", "procid",
             "msgid", "severity_name", "facility_name", "message"]
    csv_rows = [[m.get(key) for key in header] for m in messages]
    return _csv_response("syslog", header, csv_rows, truncated=truncated,
                         cap=EXPORT_ROW_CAP)


def post_syslog_collector(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.syslog_settings["enabled"] = True
        service.syslog_db.save_settings({"enabled": True})
        service.syslog.start(service.syslog_settings)
    elif action == "stop":
        service.syslog_settings["enabled"] = False
        service.syslog_db.save_settings({"enabled": False})
        service.syslog.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.syslog.running,
            "status": service.syslog.status_text()}


def post_syslog_test(service, params, body) -> dict:
    """Send a message to our own listener, to prove the socket receives."""
    import socket as _socket
    host = "127.0.0.1"
    port = int(service.syslog_settings.get("port", 514))
    stamp = time.strftime("%b %d %H:%M:%S")
    line = (f"<134>{stamp} sappiwhere SappiWhere: loopback test message "
            f"at {stamp}").encode()
    sent, error = True, None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.sendto(line, (host, port))
        sock.close()
    except OSError as exc:
        sent, error = False, str(exc)

    script = (
        "$udp = [System.Net.Sockets.UdpClient]::new()\n"
        f'$udp.Connect("{host}", {port})\n'
        f'$bytes = [Text.Encoding]::ASCII.GetBytes("<134>{stamp} '
        'sappiwhere SappiWhere: loopback test message")\n'
        "[void]$udp.Send($bytes, $bytes.Length)\n"
        "$udp.Close()"
    )
    return {"sent": sent, "error": error, "host": host, "port": port,
            "script": script}


# --------------------------------------------------------------------- snmp

def _snmp_filters(params) -> dict:
    return {
        "text": params.get("q", ""),
        "severity": params.get("severity") or None,
        "version": params.get("version") or None,
        "kind": params.get("kind", ""),
        "source": params.get("source", ""),
        "oid": params.get("oid", ""),
        "community": params.get("community", ""),
    }


def get_snmp_overview(service, params, body) -> dict:
    """Histogram plus the context the page needs; deliberately cheap."""
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    bucket = _num(params, "bucket", 3600)
    filters = _snmp_filters(params)

    buckets = service.snmp_db.histogram(t0, t1, bucket, filters)
    stats = service.snmp_db.stats()
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": buckets,
        "stats": stats,
        "sources": [{"source": row["source"], "count": row["n"],
                     "last_seen": row["last_seen"]}
                    for row in service.snmp_db.recent_sources()],
        "kinds": [{"kind": row["trap_kind"], "count": row["n"]}
                  for row in service.snmp_db.kinds()],
    }


# EXPORT_ROW_CAP is defined once, alongside SEARCH_ROW_CAP above (both
# capped lists — syslog and SNMP traps — share it).
def _snmp_trap_rows(service, params, cap: int, *,
                    use_request_limit: bool = True
                    ) -> tuple[list[dict], bool, float]:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    filters = _snmp_filters(params)

    started = time.time()
    # Same use_request_limit reasoning as _syslog_search_rows above: the
    # export path cannot tell an explicit small limit from the screen's
    # own on-screen default arriving unasked, so export ignores the
    # request's limit entirely and always asks for the full cap.
    if use_request_limit:
        limit = int(_num(params, "limit", 300, int) or 300)
        effective = min(limit, cap)
    else:
        effective = cap
    rows = service.snmp_db.search(t0, t1, filters, limit=effective + 1)
    # One row past the limit says whether anything was left out; `len(rows)
    # >= effective` reported a cut-off for a window with exactly `effective`
    # matches, which was a lie the count label repeated.
    truncated = len(rows) > effective
    rows = rows[:effective]
    elapsed_ms = (time.time() - started) * 1000

    names = {}
    if service.snmp_settings.get("resolve_sources"):
        names = {ip: name for ip, name in
                 service.app_db.hostnames({row["source"] for row in rows}).items()
                 if name}

    traps = []
    for row in rows:
        try:
            varbinds = json.loads(row["varbinds"] or "[]")
        except ValueError:
            varbinds = []
        traps.append({
            "id": row["id"], "ts": row["ts"], "source": row["source"],
            "source_name": names.get(row["source"], ""),
            "version": row["version"],
            "version_name": VERSION_NAMES.get(row["version"], "?"),
            "community": row["community"] or "",
            "engine_id": row["engine_id"] or "",
            "security": row["security"] or "",
            "auth_state": row["auth_state"] or "",
            "trap_oid": row["trap_oid"] or "",
            "trap_name": row["trap_name"] or "",
            "trap_kind": row["trap_kind"] or "",
            "severity": row["severity"],
            "severity_name": severity_name(row["severity"]),
            "generic": row["generic"], "specific": row["specific"],
            "generic_name": (GENERIC_NAMES[row["generic"]]
                             if row["generic"] is not None
                             and 0 <= row["generic"] < len(GENERIC_NAMES) else ""),
            "enterprise": row["enterprise"] or "",
            "agent_addr": row["agent_addr"] or "",
            "uptime": row["uptime"] or 0,
            "uptime_text": format_ticks(row["uptime"] or 0),
            "is_inform": bool(row["is_inform"]),
            "varbind_n": row["varbind_n"],
            "varbinds": varbinds,
        })
    return traps, truncated, elapsed_ms, effective


def get_snmp_traps(service, params, body) -> dict:
    traps, truncated, elapsed_ms, effective = _snmp_trap_rows(service, params, SEARCH_ROW_CAP)
    return {"took_ms": round(elapsed_ms, 1), "limit": effective, "cap": SEARCH_ROW_CAP,
            "truncated": truncated, "traps": traps}


def get_snmp_traps_export(service, params, body) -> dict:
    traps, truncated, _elapsed_ms, _effective = _snmp_trap_rows(
        service, params, EXPORT_ROW_CAP, use_request_limit=False)
    header = ["id", "ts", "source", "source_name", "version_name", "trap_name",
             "trap_oid", "trap_kind", "severity_name", "community",
             "agent_addr", "is_inform"]
    csv_rows = [[t.get(key) for key in header] for t in traps]
    return _csv_response("snmp-traps", header, csv_rows, truncated=truncated,
                         cap=EXPORT_ROW_CAP)


def post_snmp_collector(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.snmp_settings["enabled"] = True
        service.snmp_db.save_settings({"enabled": True})
        service.snmp.start(service.snmp_settings)
    elif action == "stop":
        service.snmp_settings["enabled"] = False
        service.snmp_db.save_settings({"enabled": False})
        service.snmp.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.snmp.running,
            "status": service.snmp.status_text()}


def post_snmp_test(service, params, body) -> dict:
    """Send a real trap to our own listener, to prove the socket receives.

    The packet is built by the same encoder the inform acknowledgement uses,
    so a successful round trip exercises both halves.
    """
    import socket as _socket
    from ..trapdecode import build_v1_trap, build_v2c_trap

    host = "127.0.0.1"
    port = int(service.snmp_settings.get("port", 162))
    version = str(body.get("version", "v2c")).lower()
    community = (str(service.snmp_settings.get("accepted_communities", ""))
                 .replace(",", "\n").split("\n")[0].strip() or "public")
    ticks = int((time.time() - service.started_at) * 100)

    if version == "v1":
        packet = build_v1_trap(community, "1.3.6.1.4.1.8072.9999", host,
                               generic=0, specific=0, uptime_ticks=ticks)
    else:
        packet = build_v2c_trap(
            community, "1.3.6.1.6.3.1.1.5.1", ticks,
            [("1.3.6.1.2.1.1.5.0", enc_octets("sappiwhere")),
             ("1.3.6.1.2.1.1.6.0", enc_octets("loopback test trap"))])

    sent, error = True, None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.sendto(packet, (host, port))
        sock.close()
    except OSError as exc:
        sent, error = False, str(exc)

    # PowerShell has no SNMP client, so the equivalent is the same bytes on
    # the same socket. The trap is a fixed, valid coldStart, so it can be
    # sent verbatim from anywhere that can reach this listener.
    hexed = ",".join(f"0x{b:02X}" for b in packet)
    script = (
        "$udp = [System.Net.Sockets.UdpClient]::new()\n"
        f'$udp.Connect("{host}", {port})\n'
        f"$bytes = [byte[]]@({hexed})\n"
        "[void]$udp.Send($bytes, $bytes.Length)\n"
        "$udp.Close()"
    )
    command = (f"snmptrap -v 2c -c {community} {host}:{port} '' "
               f"1.3.6.1.6.3.1.1.5.1")
    return {"sent": sent, "error": error, "host": host, "port": port,
            "version": version, "community": community,
            "bytes": len(packet), "script": script, "command": command}


# ---------------------------------------------------------------------- ipam

def get_ipam_search(service, params, body) -> dict:
    query = (params.get("q") or "").strip()
    if len(query) < 2:
        return {"results": []}
    return {"results": service.ipam_search(query)}


def _subnet_json(row) -> dict:
    return {"id": row["id"], "cidr": row["cidr"], "label": row["label"],
            "vlan": row["vlan"], "enabled": bool(row["enabled"]),
            "created": row["created_ts"]}


def get_ipam_subnets(service, params, body) -> dict:
    from ..ipam_scan import subnet_size

    subnets = [_subnet_json(row) for row in service.ipam_db.subnets()]
    worker_state = service.ipam.state()
    # Only the most recent scan per subnet matters here; recent_scans()
    # returns newest-first across every subnet, so the first hit per id wins.
    latest: dict[int, dict] = {}
    for row in service.ipam_db.recent_scans(limit=1000):
        latest.setdefault(row["subnet_id"], dict(row))
    for subnet in subnets:
        subnet["scanning"] = subnet["id"] in worker_state["scanning"]
        last = latest.get(subnet["id"])
        subnet["last_scan"] = {
            "started": last["started_ts"], "finished": last["finished_ts"],
            "addresses": last["addresses"], "alive": last["alive"],
            "conflicts": last["conflicts"], "status": last["status"],
            "error": last["error"],
        } if last else None

        # Alive / previously-seen-but-down / never-seen, for the utilization
        # pie chart. Never-seen is a subtraction rather than a count, since
        # an address nothing has ever answered on has no row in `hosts` to
        # count in the first place.
        counts = service.ipam_db.host_counts(subnet["id"])
        try:
            total = subnet_size(subnet["cidr"])
        except ValueError:
            total = None
        never_seen = (max(0, total - counts["alive"] - counts["seen_down"])
                      if total is not None else None)
        subnet["usage"] = {"alive": counts["alive"], "seen_down": counts["seen_down"],
                           "never_seen": never_seen, "total": total}
    return {"subnets": subnets}


def post_ipam_subnet(service, params, body) -> dict:
    from ..ipam_scan import usable_addresses, SubnetTooLarge

    cidr = str(body.get("cidr", "")).strip()
    if not cidr:
        raise ValueError("A subnet in CIDR form is required, e.g. 10.20.3.0/24")
    max_addresses = int(service.ipam_settings.get("max_scan_addresses", 1024))
    try:
        usable_addresses(cidr, max_addresses)
    except SubnetTooLarge as exc:
        raise ValueError(str(exc))
    subnet_id = service.ipam_db.add_subnet(
        cidr, label=body.get("label") or cidr, vlan=body.get("vlan") or None)
    service.log.add(IPAM_CATEGORY, f"Added subnet {cidr}")
    return {"id": subnet_id}


def put_ipam_subnet(service, params, body, subnet_id) -> dict:
    fields = {k: v for k, v in body.items() if k in
             ("cidr", "label", "vlan", "enabled")}
    service.ipam_db.update_subnet(subnet_id, **fields)
    return {"ok": True}


def delete_ipam_subnet(service, params, body, subnet_id) -> dict:
    service.ipam_db.remove_subnet(subnet_id)
    service.log.add(IPAM_CATEGORY, f"Removed subnet #{subnet_id}")
    return {"ok": True}


def post_ipam_subnet_scan(service, params, body, subnet_id) -> dict:
    if not service.ipam_db.subnet(subnet_id):
        raise ValueError("No such subnet")
    service.ipam.scan_now(subnet_id)
    return {"ok": True}


def post_ipam_subnet_clear(service, params, body, subnet_id) -> dict:
    subnet = service.ipam_db.subnet(subnet_id)
    if not subnet:
        raise ValueError("No such subnet")
    if subnet_id in service.ipam.state()["scanning"]:
        raise ValueError(
            "A scan of this subnet is running right now — wait for it to "
            "finish before clearing, so it doesn't write results back in "
            "behind the clear.")
    result = service.ipam_db.clear_subnet_data(subnet_id)
    service.log.add(IPAM_CATEGORY,
                    f"Cleared discovered hosts and scan history for "
                    f"{subnet['label']} ({result['hosts']} host(s), "
                    f"{result['scans']} scan record(s))")
    return {"ok": True, **result}


def get_ipam_hosts(service, params, body) -> dict:
    subnet_id = params.get("subnet_id")
    rows = service.ipam_db.hosts(int(subnet_id) if subnet_id else None)
    names = {}
    if service.ipam_settings.get("resolve_hosts", True):
        names = {ip: name for ip, name in
                 service.app_db.hostnames({r["ip"] for r in rows}).items() if name}
    return {"hosts": [
        {"ip": r["ip"], "mac": r["mac"], "alive": bool(r["alive"]),
         "hostname": names.get(r["ip"], ""), "subnet_id": r["subnet_id"],
         "subnet_label": r["subnet_label"], "first_seen": r["first_seen"],
         "last_seen": r["last_seen"], "last_up": r["last_up"]}
        for r in rows]}


def get_ipam_hosts_export(service, params, body) -> dict:
    """The SUBNETS & HOSTS table. `subnet_id` is the one filter the JSON
    route itself applies server-side; "Alive only" is a client-side
    checkbox (ipam.js drawHosts), so the export takes the same `alive_only`
    presence-flag the Devices "only offline" filter uses and applies it
    here — the export honours what is on screen even though the screen
    itself never sent that filter to the server before now."""
    hosts = get_ipam_hosts(service, params, body)["hosts"]
    if params.get("alive_only") is not None:
        hosts = [h for h in hosts if h["alive"]]
    header = ["ip", "mac", "alive", "hostname", "subnet_label",
             "first_seen", "last_seen", "last_up"]
    csv_rows = [[h.get(key) for key in header] for h in hosts]
    return _csv_response("ipam-hosts", header, csv_rows)


def get_ipam_conflicts(service, params, body) -> dict:
    include_resolved = params.get("resolved") == "1"
    rows = service.ipam_db.conflicts(include_resolved=include_resolved)
    return {"conflicts": [
        {"id": r["id"], "ip": r["ip"], "mac_a": r["mac_a"], "mac_b": r["mac_b"],
         "source": r["source"], "detected": r["detected_ts"],
         "last_seen": r["last_seen_ts"], "resolved": r["resolved_ts"]}
        for r in rows]}


def post_ipam_conflict_resolve(service, params, body, conflict_id) -> dict:
    service.ipam_db.resolve_conflict(conflict_id)
    return {"ok": True}


def _dhcp_server_json(row) -> dict:
    return {"id": row["id"], "address": row["address"], "label": row["label"],
            "enabled": bool(row["enabled"]), "last_poll": row["last_poll_ts"],
            "last_status": row["last_status"], "last_error": row["last_error"],
            # The username is not sensitive on its own and is shown so the
            # form can be prefilled; the password never appears in any
            # response, encrypted or not — only whether one is stored.
            "username": row["username"], "has_credential": bool(row["password_enc"])}


def get_ipam_dhcp_servers(service, params, body) -> dict:
    servers = [_dhcp_server_json(row) for row in service.ipam_db.dhcp_servers()]
    worker_state = service.ipam.state()
    for server in servers:
        server["polling"] = server["id"] in worker_state["polling"]
    return {"servers": servers}


def post_ipam_dhcp_server(service, params, body) -> dict:
    address = str(body.get("address", "")).strip()
    if not address:
        raise ValueError("A hostname or address is required")
    server_id = service.ipam_db.add_dhcp_server(
        address, label=body.get("label") or address)
    service.log.add(IPAM_CATEGORY, f"Added DHCP server {address}")
    return {"id": server_id}


def put_ipam_dhcp_server(service, params, body, server_id) -> dict:
    existing = service.ipam_db.dhcp_server(server_id)
    if not existing:
        raise ValueError("No such DHCP server")
    fields = {k: v for k, v in body.items() if k in ("address", "label", "enabled")}
    # A stored credential belongs to the machine it was stored for. Pointing
    # the row at a different address and then pressing Test or Poll would
    # otherwise hand that account's password to whatever answers there —
    # the same retargeting the SMTP test allowed. Moving the row forgets the
    # credential; storing one again is a deliberate act naming the new host.
    moved = ("address" in fields
             and str(fields["address"]).strip() != str(existing["address"] or ""))
    service.ipam_db.update_dhcp_server(server_id, **fields)
    if moved and existing["password_enc"]:
        service.ipam_db.clear_dhcp_credential(server_id)
        service.log.add(IPAM_CATEGORY,
                        f"Cleared the stored credential for DHCP server "
                        f"{existing['label']}: its address changed from "
                        f"{existing['address']} to {fields['address']}")
        return {"ok": True, "credential_cleared": True}
    return {"ok": True}


def delete_ipam_dhcp_server(service, params, body, server_id) -> dict:
    service.ipam_db.remove_dhcp_server(server_id)
    service.log.add(IPAM_CATEGORY, f"Removed DHCP server #{server_id}")
    return {"ok": True}


def post_ipam_dhcp_server_poll(service, params, body, server_id) -> dict:
    if not service.ipam_db.dhcp_server(server_id):
        raise ValueError("No such DHCP server")
    service.ipam.poll_dhcp_now(server_id)
    return {"ok": True}


def post_ipam_dhcp_server_test(service, params, body, server_id) -> dict:
    from ..ipam_dhcp import DhcpUnavailable, test_connection
    from ..ipam_worker import credential_for_server

    server = service.ipam_db.dhcp_server(server_id)
    if not server:
        raise ValueError("No such DHCP server")

    # Testing an in-progress edit checks whatever is currently typed, before
    # it is saved; otherwise fall back to whatever credential already exists.
    username = body.get("username")
    password = body.get("password")
    if username is None:
        username, password = credential_for_server(server)

    try:
        result = test_connection(
            server["address"],
            timeout_s=float(service.ipam_settings.get("dhcp_timeout_s", 30)),
            username=username or None, password=password or None)
    except (DhcpUnavailable, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        username = password = None
    return result


def post_ipam_dhcp_server_credential(service, params, body, server_id) -> dict:
    from .. import dpapi

    server = service.ipam_db.dhcp_server(server_id)
    if not server:
        raise ValueError("No such DHCP server")
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. Use Windows Credential Manager instead: "
            f"cmdkey /add:{server['address']} /user:<account> /pass:<password>")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.ipam_db.set_dhcp_credential(server_id, username, encrypted)
    service.log.add(IPAM_CATEGORY,
                    f"Stored a credential for DHCP server {server['label']}")
    _audit(service, params, "credential.store",
           target=f"dhcp:{server['address']}", detail=f"username {username}")
    return {"ok": True}


def delete_ipam_dhcp_server_credential(service, params, body, server_id) -> dict:
    server = service.ipam_db.dhcp_server(server_id)
    if not server:
        raise ValueError("No such DHCP server")
    service.ipam_db.clear_dhcp_credential(server_id)
    service.log.add(IPAM_CATEGORY, f"Cleared the stored credential for DHCP "
                                   f"server {server['label']}")
    _audit(service, params, "credential.clear",
           target=f"dhcp:{server['address']}")
    return {"ok": True}


def _scope_subnet(scope_id: str, mask: str) -> str | None:
    """The scope's own network, in CIDR form — its ScopeId is the network
    address and SubnetMask its mask, which together describe the subnet the
    scope belongs to. Deliberately not derived from start_ip/end_ip: those
    mark the dynamic range, which is often narrower than the full subnet
    once exclusions and static reservations are accounted for."""
    import ipaddress
    if not scope_id or not mask:
        return None
    try:
        return str(ipaddress.ip_network(f"{scope_id}/{mask}", strict=False))
    except ValueError:
        return None


def get_ipam_dhcp_scopes(service, params, body) -> dict:
    server_id = params.get("server_id")
    rows = service.ipam_db.dhcp_scopes(int(server_id) if server_id else None)

    # Grouped by (server_id, scope_id) rather than scope_id alone: two
    # different DHCP servers can each have a scope named the same thing
    # (10.20.3.0 is a popular choice everywhere), and this runs across
    # every server's leases at once when no server_id filter is given.
    by_scope: dict[tuple, list] = {}
    for lease in service.ipam_db.dhcp_leases(int(server_id) if server_id else None):
        by_scope.setdefault((lease["server_id"], lease["scope_id"]), []).append(lease)

    scopes = []
    for r in rows:
        leases = by_scope.get((r["server_id"], r["scope_id"]), [])
        reserved = sum(1 for row in leases if row["is_reservation"])
        leased = len(leases) - reserved
        total = scope_size(r["start_ip"], r["end_ip"])
        available = max(0, total - leased - reserved) if total is not None else None
        scopes.append({
            "id": r["id"], "server_id": r["server_id"], "server_label": r["server_label"],
            "scope_id": r["scope_id"], "name": r["name"], "start_ip": r["start_ip"],
            "end_ip": r["end_ip"], "mask": r["mask"], "state": r["state"],
            "lease_duration_s": r["lease_duration_s"], "description": r["description"],
            "router": r["router"], "subnet": _scope_subnet(r["scope_id"], r["mask"]),
            "polled": r["polled_ts"],
            "usage": {"leased": leased, "reserved": reserved,
                     "available": available, "total": total},
        })
    return {"scopes": scopes}


def get_ipam_dhcp_leases(service, params, body) -> dict:
    server_id = params.get("server_id")
    scope_id = params.get("scope_id")
    rows = service.ipam_db.dhcp_leases(
        int(server_id) if server_id else None, scope_id or None)
    return {"leases": [
        {"id": r["id"], "server_id": r["server_id"], "server_label": r["server_label"],
         "scope_id": r["scope_id"], "ip": r["ip"], "mac": r["mac"],
         "hostname": r["hostname"], "address_state": r["address_state"],
         "lease_expires": r["lease_expires_ts"],
         "is_reservation": bool(r["is_reservation"]),
         "description": r["description"], "polled": r["polled_ts"]}
        for r in rows]}


def get_ipam_dhcp_leases_export(service, params, body) -> dict:
    leases = get_ipam_dhcp_leases(service, params, body)["leases"]
    header = ["server_label", "scope_id", "ip", "mac", "hostname",
             "address_state", "lease_expires", "is_reservation",
             "description", "polled"]
    csv_rows = [[lease.get(key) for key in header] for lease in leases]
    return _csv_response("ipam-dhcp-leases", header, csv_rows)


def get_ipam_dhcp_scope_history(service, params, body) -> dict:
    """Leased/reserved/total over time for one scope, for the trend chart
    above its lease table. One point per DHCP poll that landed in the
    window — usually tens to a few hundred, never enough to need bucketing."""
    server_id = params.get("server_id")
    scope_id = params.get("scope_id", "")
    if not server_id or not scope_id:
        return {"points": []}
    t0, t1 = _window(params)
    rows = service.ipam_db.scope_usage_history(int(server_id), scope_id, t0, t1)
    return {"points": [
        {"ts": r["polled_ts"], "leased": r["leased"], "reserved": r["reserved"],
         "total": r["total"]}
        for r in rows]}


# -------------------------------------------------------------------- nodes

def _tri(value):
    """None/0/1 -> None/False/True. A device's own override columns are
    NULL when "inherit from the group", which a blind bool() would
    collapse into False — indistinguishable from an explicit off."""
    return None if value is None else bool(value)


# The community string travels in the clear in every packet the protocol
# defines, so it is not a secret in the sense a password is — and it is
# still the only access control on many industrial devices, where the v2c
# community is what a PLC or RTU checks before answering, and sometimes
# before accepting a write. Handing every community in the estate to every
# read-only Nodes account is a lateral-movement gift regardless of what the
# wire already leaks. The value is shown to callers who could change it
# anyway (module WRITE); everyone else gets `has_community`, the same
# reduction `v3_auth_pass_enc` already gets.
def _community_fields(row, reveal: bool) -> dict:
    community = row["community"]
    fields = {"has_community": bool(community)}
    if reveal:
        fields["community"] = community
    return fields


def _may_read_secrets(service, params, module: str) -> bool:
    granted = service.app_db.permissions_for(params.get("_username", ""))
    return _permissions.allows(granted.get(module), _permissions.WRITE)


def _device_json(row, reveal: bool = False) -> dict:
    return {
        "id": row["id"], "ip": row["ip"], "name": row["name"],
        "group_id": row["group_id"], "device_group_id": row["device_group_id"],
        "display_name_source": row["display_name_source"],
        "enabled": bool(row["enabled"]),
        "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"],
        "snmp_retries": row["snmp_retries"],
        "ping_enabled": _tri(row["ping_enabled"]),
        "snmp_enabled": _tri(row["snmp_enabled"]),
        "oid_set": row["oid_set"], "mib_file_id": row["mib_file_id"],
        "ping_count": row["ping_count"], "ping_timeout_ms": row["ping_timeout_ms"],
        "unreachable_ping_only": row["unreachable_ping_only"],
        "mac_table_interval_s": row["mac_table_interval_s"],
        # LLDP/CDP, PoE and STP polling (Tier 1 #5/#7): the same
        # inherit-via-NULL override columns mac_table_interval_s already
        # models, exposed the same defensive way for a row from before the
        # migration that added them.
        "lldp_interval_s": (row["lldp_interval_s"] if "lldp_interval_s" in row.keys() else None),
        "poe_enabled": (_tri(row["poe_enabled"]) if "poe_enabled" in row.keys() else None),
        "stp_enabled": (_tri(row["stp_enabled"]) if "stp_enabled" in row.keys() else None),
        # The capability probe's verdict — True/False once probed, None
        # until the first poll gets to it — and, once stp_capable is true,
        # the bridge-wide state a topology/device pane reads. Per-port PoE
        # power and STP state live on the interfaces rows instead (see
        # get_nodes_device_interfaces); the topology-change COUNT is a
        # metric with history (see get_nodes_device_metrics), not a column
        # here — this is the device's current bridge identity, not a series.
        "poe_capable": (bool(row["poe_capable"]) if "poe_capable" in row.keys()
                        and row["poe_capable"] is not None else None),
        "stp_capable": (bool(row["stp_capable"]) if "stp_capable" in row.keys()
                        and row["stp_capable"] is not None else None),
        "stp_protocol_spec": (row["stp_protocol_spec"] if "stp_protocol_spec" in row.keys() else None),
        "stp_priority": (row["stp_priority"] if "stp_priority" in row.keys() else None),
        "stp_root_id": (row["stp_root_id"] if "stp_root_id" in row.keys() else None),
        "stp_root_cost": (row["stp_root_cost"] if "stp_root_cost" in row.keys() else None),
        "stp_root_port": (row["stp_root_port"] if "stp_root_port" in row.keys() else None),
        "stp_time_since_change_s": (row["stp_time_since_change_s"]
                                    if "stp_time_since_change_s" in row.keys() else None),
        "upstream_id": (row["upstream_id"] if "upstream_id" in row.keys() else None),
        # Vendor identification (4.32): keyed defensively for a row handed
        # in from an older-shaped source.
        "vendor_confidence": (row["vendor_confidence"] or ""
                              if "vendor_confidence" in row.keys() else ""),
        "vendor_override": (row["vendor_override"]
                            if "vendor_override" in row.keys() else None),
        "sys_descr": row["sys_descr"], "sys_name": row["sys_name"],
        "sys_object_id": row["sys_object_id"], "sys_contact": row["sys_contact"],
        "sys_location": row["sys_location"], "vendor": row["vendor"],
        # The vendor's own name for itself, where its key does not read as
        # one ("rockwellAutomation" -> "Rockwell Automation"). Presentation
        # only: `vendor` stays the token everything that behaves per-vendor
        # compares against, and a key with no display name serves itself.
        "vendor_label": nodeoids.vendor_label(row["vendor"] or ""),
        # What SNMP identification worked out, and which source spoke. Shown
        # beside the displayed vendor so an operator who has pointed vendor at
        # a custom OID can still see what the app itself detected — and can
        # tell an IANA arc assignment from a sysDescr substring guess.
        "vendor_detected": row["vendor_detected"],
        "vendor_source": row["vendor_source"] or "",
        "vendor_oid": row["vendor_oid"] or "",
        "location_oid": row["location_oid"] or "",
        "status": row["status"], "ping_ok": _tri(row["ping_ok"]),
        "ping_rtt_ms": row["ping_rtt_ms"], "snmp_ok": _tri(row["snmp_ok"]),
        "snmp_error": row["snmp_error"], "consecutive_fail": row["consecutive_fail"],
        "last_poll_ts": row["last_poll_ts"], "last_up_ts": row["last_up_ts"],
        "last_down_ts": row["last_down_ts"],
        "last_uptime_ticks": row["last_uptime_ticks"],
        "last_uptime_ts": row["last_uptime_ts"], "created_ts": row["created_ts"],
        "status_since_ts": _status_since(row),
        "sys_uptime_s": _sys_uptime_s(row),
    }


def _status_since(row):
    """When the device entered its current state — the question "is it up"
    is always followed by "since when", and the summary could not answer it.

    last_up_ts is the last poll that saw the device up (rewritten on every
    up poll), last_down_ts the last that saw it down. So a device that is up
    has been up since the last time it was seen down, and one that is down
    since it was last seen up; a device never seen in the other state has
    been in this one since it was added. Unknown states have no since."""
    status = row["status"]
    if status == "up":
        return row["last_down_ts"] or row["created_ts"]
    if status == "down":
        return row["last_up_ts"] or row["created_ts"]
    return None


def _sys_uptime_s(row):
    """The device's own sysUpTime, aged forward from when it was last read —
    the same pair reboot detection compares (nodepoll). None until read."""
    ticks = row["last_uptime_ticks"]
    read_at = row["last_uptime_ts"]
    if ticks is None or not read_at:
        return None
    return round(ticks / 100 + max(0.0, time.time() - read_at))


def _group_json(service, row, reveal: bool = False) -> dict:
    return {
        "id": row["id"], "name": row["name"], "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"],
        "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"], "snmp_retries": row["snmp_retries"],
        "ping_enabled": bool(row["ping_enabled"]), "snmp_enabled": bool(row["snmp_enabled"]),
        "oid_set": row["oid_set"], "mib_file_id": row["mib_file_id"],
        "ping_count": row["ping_count"], "ping_timeout_ms": row["ping_timeout_ms"],
        "unreachable_ping_only": row["unreachable_ping_only"],
        "mac_table_interval_s": row["mac_table_interval_s"],
        "vendor_oid": row["vendor_oid"] or "",
        "location_oid": row["location_oid"] or "",
        "is_default": bool(row["is_default"]),
        "created_ts": row["created_ts"],
        # The profile's own snmp_version/community/v3_* above are its
        # "primary" credential — always present, always tried first. This
        # is every ADDITIONAL credential the poller falls back to in
        # order when the primary doesn't work for a given device.
        "credentials": [_group_credential_json(r, reveal)
                        for r in service.nodes_db.group_credentials(row["id"])],
    }


def _group_credential_json(row, reveal: bool = False) -> dict:
    return {
        "id": row["id"], "group_id": row["group_id"], "label": row["label"],
        "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "created_ts": row["created_ts"],
    }


def _discovery_job_json(row) -> dict:
    return {"id": row["id"], "kind": row["kind"], "target": row["target"],
            "state": row["state"], "total": row["total"], "probed": row["probed"],
            "responded": row["responded"], "identified": row["identified"],
            "allow_ping_only": bool(row["allow_ping_only"]),
            "reviewed": bool(row["reviewed"]),
            "started_ts": row["started_ts"], "finished_ts": row["finished_ts"],
            "error": row["error"]}


def _device_display_name(row) -> str:
    """nodes.js's displayName() precedence: manual name if pinned to it,
    else the SNMP hostname, else the manual name anyway, else the IP."""
    return ((row["name"] if row["display_name_source"] == "manual" else None)
            or row["sys_name"] or row["name"] or row["ip"])


def _discovery_result_json(row, installed=None, devices_by_ip=None) -> dict:
    """`installed` is the set of MIB filenames present, and `devices_by_ip`
    an ip -> device row map, each passed by the caller once per listing so
    neither the MIB hint nor the already-added check is a query per row.
    `promoted_device_id` alone missed an address added to Nodes some other
    way — by hand, or from an earlier scan — so `devices_by_ip` is checked
    too; either source wins because promote() always reuses that same row."""
    existing = devices_by_ip.get(row["ip"]) if devices_by_ip else None
    existing_id = existing["id"] if existing else row["promoted_device_id"]
    existing_name = _device_display_name(existing) if existing else None
    return {"id": row["id"], "job_id": row["job_id"], "ip": row["ip"],
            "ping_ok": bool(row["ping_ok"]), "snmp_ok": bool(row["snmp_ok"]),
            "community_or_user": row["community_or_user"],
            "snmp_version": row["snmp_version"], "sys_descr": row["sys_descr"],
            "sys_name": row["sys_name"], "sys_object_id": row["sys_object_id"],
            "vendor": row["vendor"], "suggested_group_id": row["suggested_group_id"],
            "promoted_device_id": row["promoted_device_id"],
            "existing_device_id": existing_id,
            "existing_device_name": existing_name,
            **_discovery_identification(row, installed)}


def _discovery_identification(row, installed=None) -> dict:
    """What the sweep's arc hop found for a result, or blanks for a row
    written before 4.32."""
    keys = row.keys()
    arcs = []
    if "arcs" in keys and row["arcs"]:
        try:
            arcs = [int(a) for a in json.loads(row["arcs"])]
        except (TypeError, ValueError):
            arcs = []
    bundle_key = (row["suggest_bundle"] if "suggest_bundle" in keys else None) or None
    bundle = mibcatalog.bundle(bundle_key) if bundle_key else None
    bundle_installed = bool(bundle) and installed is not None and \
        all(fn in installed for fn, _url in bundle.files)
    return {
        "vendor_source": (row["vendor_source"] if "vendor_source" in keys else "") or "",
        "vendor_confidence": (row["vendor_confidence"]
                              if "vendor_confidence" in keys else "") or "",
        "arcs": arcs,
        "arc_names": [vendorid.arc_name(a) for a in arcs],
        "suggest_bundle": bundle_key,
        "suggest_bundle_installed": bundle_installed,
    }


_DEVICE_EDITABLE_BODY = ("name", "group_id", "device_group_id",
                         "display_name_source", "enabled",
                         "snmp_version", "community",
                         "v3_user", "v3_auth_proto", "poll_interval_s",
                         "snmp_timeout_s", "snmp_retries", "ping_enabled",
                         "snmp_enabled", "oid_set", "mib_file_id",
                         "ping_count", "ping_timeout_ms", "unreachable_ping_only",
                         "vendor_oid", "location_oid", "mac_table_interval_s",
                         "vendor_override", "upstream_id")
_GROUP_EDITABLE_BODY = ("name", "snmp_version", "community", "v3_user",
                        "v3_auth_proto", "poll_interval_s", "snmp_timeout_s",
                        "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                        "mib_file_id", "ping_count", "ping_timeout_ms",
                        "unreachable_ping_only", "vendor_oid", "location_oid",
                        "mac_table_interval_s")


def get_nodes_overview(service, params, body) -> dict:
    """Histogram of device-event counts plus status-strip context;
    mirrors get_snmp_overview's shape. nodesdb has no dedicated histogram
    method — device_events volume is orders of magnitude lower than SNMP
    trap volume, so a Python-side bucket pass over one window's rows is
    always cheap enough, the same reasoning alertsdb.py's own histogram
    already relies on for a live GROUP BY."""
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    bucket = _num(params, "bucket", 3600)
    events = service.nodes_db.device_events(since_s=max(0.0, time.time() - t0))
    buckets: dict[int, int] = {}
    for row in events:
        if row["ts"] < t0 or row["ts"] > t1:
            continue
        slot = int((row["ts"] - t0) // bucket)
        buckets[slot] = buckets.get(slot, 0) + 1
    histogram = [{"t": t0 + slot * bucket, "n": n} for slot, n in sorted(buckets.items())]
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": histogram,
        "device_counts": service.nodes_db.device_counts(),
        "poller": {
            "running": service.node_poller.running,
            "status": service.node_poller.status_text(),
            "counters": service.node_poller.counters,
        },
    }


def _device_filters(params) -> dict:
    group_id = params.get("group_id")
    device_group_id = params.get("device_group_id")
    return {
        "group_id": int(group_id) if group_id else None,
        "device_group_id": int(device_group_id) if device_group_id else None,
        "status": params.get("status") or None,
        "text": params.get("q") or None,
        # The frontend only ever sends this param when the "only offline"
        # checkbox is checked, so its mere presence is the signal — no
        # string-vs-boolean parsing of a possible "false" needed.
        "exclude_up": params.get("offline_only") is not None,
    }


def _device_rows_json(service, params, rows) -> list[dict]:
    worker_state = service.node_poller.worker_state()
    # A mute lives in the Alerts module but has to be visible here: an
    # operator who silenced a device an hour ago and then wonders why it
    # is quiet should be able to see why without opening Alerts. A
    # maintenance window is folded into the same field for the same reason
    # — muted_until is "why is this device quiet", and a window answers
    # that exactly as a mute does. window_covered_device_ids is asked with
    # the rows this call already fetched (id, device_group_id) rather than
    # a second devices() read.
    window_covered = service.alerts_db.window_covered_device_ids(
        ((row["id"], row["device_group_id"]) for row in rows))
    muted = service.alerts_db.muted_entity_ids("device", window_covered=window_covered)
    reveal = _may_read_secrets(service, params, "nodes")
    devices = []
    for row in rows:
        device = _device_json(row, reveal)
        device["polling"] = row["id"] in worker_state
        device["muted_until"] = muted.get(str(row["id"]))
        devices.append(device)
    return devices


# Item 2 of the API-heavy trio: get_nodes_devices returned the whole fleet
# every time, unconditionally — 2.86 MB decoded and a ~1s table fill at
# 2,000 devices, measured. Paging is opt-in rather than the new default:
# a caller that sends neither `limit` nor `offset` still gets everything
# back, exactly as before this existed, because nothing here can be sure
# it is the only caller (see test_frontend_contracts.py and tests/ui/ for
# what is pinned against the no-params shape). nodes.js is the one caller
# switched onto the paged form; DEVICE_LIST_DEFAULT_LIMIT is its default
# page size.
DEVICE_LIST_DEFAULT_LIMIT = 500
DEVICE_LIST_MAX_LIMIT = 2000


def get_nodes_devices(service, params, body) -> dict:
    filters = _device_filters(params)
    total = service.nodes_db.devices_count(**filters)
    if params.get("limit") is None and params.get("offset") is None:
        rows = service.nodes_db.devices(**filters)
        return {"devices": _device_rows_json(service, params, rows), "total": total}
    offset = max(0, int(_num(params, "offset", 0, int) or 0))
    limit = max(1, min(int(_num(params, "limit", DEVICE_LIST_DEFAULT_LIMIT, int)
                        or DEVICE_LIST_DEFAULT_LIMIT), DEVICE_LIST_MAX_LIMIT))
    rows = service.nodes_db.devices(limit=limit, offset=offset, **filters)
    return {"devices": _device_rows_json(service, params, rows),
            "total": total, "limit": limit, "offset": offset}


def get_nodes_devices_export(service, params, body) -> dict:
    """The Devices table's current filter, unpaged and uncapped: a CSV
    export exists to leave with everything that matched, not one page of
    it, and nodes_db.devices() already has no limit of its own to lift."""
    filters = _device_filters(params)
    rows = service.nodes_db.devices(**filters)
    devices = _device_rows_json(service, params, rows)
    header = ["id", "name", "ip", "status", "group_id", "device_group_id",
             "vendor", "sys_descr", "sys_name", "polling", "muted_until",
             "poll_interval_s", "last_poll_ts"]
    csv_rows = [[d.get("id"), d.get("name"), d.get("ip"), d.get("status"),
                d.get("group_id"), d.get("device_group_id"), d.get("vendor"),
                d.get("sys_descr"), d.get("sys_name"), d.get("polling"),
                d.get("muted_until"), d.get("poll_interval_s"), d.get("last_poll_ts")]
               for d in devices]
    return _csv_response("devices", header, csv_rows)


def get_nodes_mac_search(service, params, body) -> dict:
    """Where a MAC address has been seen, from the stored forwarding tables.

    Returns every (device, port) that learned it — an address on an uplink
    is on every switch between here and the host, and that is the normal
    case on a stacked network. The caller decides what to do with one
    answer versus several; picking one here would silently send an operator
    to the core switch for a problem on an access port.
    """
    text = params.get("q") or ""
    mac = nodesdb.looks_like_mac_search(text)
    if len(mac) < 4:
        return {"mac": "", "locations": [], "enabled_devices": 0}
    locations = []
    for row in service.nodes_db.mac_locations(mac):
        device = service.nodes_db.device(row["device_id"])
        if device is None:
            continue
        locations.append({
            "device_id": row["device_id"],
            "device_name": hostresolve.device_name(device),
            "if_index": row["if_index"],
            "if_descr": row["if_descr"] or f"Interface {row['if_index']}",
            "mac": row["mac"], "vlan": row["vlan"], "seen_ts": row["seen_ts"],
            "first_seen_ts": row["first_seen_ts"],
            "present": bool(row["present"]),
        })
    # How many devices are actually walking their forwarding tables, so the
    # frontend can say "nothing has been learned yet" rather than "not
    # found" when the feature is simply switched off everywhere. One query,
    # not effective_config() per device — this runs on a keystroke.
    return {"mac": mac, "locations": locations,
            "enabled_devices": service.nodes_db.mac_walk_enabled_count(),
            "retention_days": float(
                service.nodes_settings.get("mac_table_retention_days", 7))}


def _neighbor_local_port_labeler(service):
    """A (device_id, if_index) -> label closure for LLDP/CDP rows, backed by
    one interfaces() read per device it is actually asked about rather than
    the whole fleet's — a topology draw only ever touches the handful of
    devices that reported a neighbour, not the thousands that did not.
    Falls back to "if <N>" for a port whose interface row has not been
    polled yet (or was deleted since), which is still a legible label."""
    cache: dict[int, dict[int, str]] = {}

    def label(device_id, if_index):
        if if_index is None:
            return ""
        ports = cache.get(device_id)
        if ports is None:
            ports = {i["if_index"]: (i["descr"] or i["alias"] or "")
                     for i in service.nodes_db.interfaces(device_id)}
            cache[device_id] = ports
        return ports.get(if_index) or f"if {if_index}"
    return label


def _neighbor_json(row, local_port: str = "") -> dict:
    keys = row.keys()
    return {
        "device_id": row["device_id"], "if_index": row["if_index"],
        "local_port": local_port,
        "protocol": row["protocol"], "chassis_id": row["chassis_id"],
        "chassis_id_subtype": row["chassis_id_subtype"],
        "port_id": row["port_id"], "port_descr": row["port_descr"],
        "sys_name": row["sys_name"], "sys_descr": row["sys_descr"],
        "platform": row["platform"], "remote_address": row["remote_address"],
        "seen_ts": row["seen_ts"], "first_seen_ts": row["first_seen_ts"],
        "present": bool(row["present"]),
        "matched_device_id": row["matched_device_id"] if "matched_device_id" in keys else None,
        "matched_device_name": row["matched_device_name"] if "matched_device_name" in keys else None,
    }


def get_nodes_device_neighbors(service, params, body, device_id) -> dict:
    """The LLDP/CDP neighbours seen on one device's own ports — protocol,
    local/remote port, the remote sysName, and the best-effort device match
    nodesdb.neighbours_of already computes — for the detail pane's
    Neighbours section. Present and stale rows both come back (see
    replace_neighbors' ageing scheme); the client marks a stale one rather
    than this route filtering it out, the same choice get_nodes_device_
    events makes for interface events."""
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    rows = service.nodes_db.neighbours_of(device_id)
    label = _neighbor_local_port_labeler(service)
    return {"neighbors": [_neighbor_json(r, label(device_id, r["if_index"])) for r in rows]}


def get_nodes_device_neighbors_export(service, params, body, device_id) -> dict:
    """One device's own Neighbours table, exported — bounded by its own
    port count like the interfaces export beside it, so there is no export
    ceiling to lift here either."""
    neighbors = get_nodes_device_neighbors(service, params, body, device_id)["neighbors"]
    header = ["if_index", "local_port", "protocol", "chassis_id", "sys_name",
             "port_id", "platform", "remote_address", "matched_device_id",
             "matched_device_name", "present", "seen_ts", "first_seen_ts"]
    csv_rows = [[n.get(key) for key in header] for n in neighbors]
    return _csv_response("neighbours", header, csv_rows)


# Item 5's fleet-wide view: an L2 link graph, shaped for the client to draw
# directly rather than handing over the raw neighbour rows and making every
# caller re-derive the same graph. Two facts make the shaping worth doing
# here instead of in the browser: only nodesdb knows which chassis-id/
# sysName matches resolved to a real device (the join _NEIGHBOR_MATCH_SQL
# already computes), and only the server can afford an interfaces() read per
# reporting device to label a local port — the client would otherwise need
# a second request per device just to draw port labels on hover.
def _topology_dedup_key(device_id, if_index, matched_id, matched_if_index):
    """The undirected identity of one physical link. LLDP/CDP is normally
    walked from BOTH ends — the switch that owns this port and the device
    across the cable, if it walks its own table too — so the same cable
    arrives as two rows: (A, ifA) matched to (B, ifB), and separately
    (B, ifB) matched to (A, ifA). matched_if_index (nodesdb's join of the
    remote chassis MAC to the remote device's OWN interface) is what makes
    those two rows produce the identical frozenset key below, so the second
    row folds onto the first instead of drawing the same cable twice. A
    sysName-only match (no MAC, so no matched_if_index) cannot be paired
    this way — it gets its own key per row, which is a real second line on
    screen rather than a wrong guess at which port to pair it against."""
    if matched_if_index is not None:
        return frozenset({(device_id, if_index), (matched_id, matched_if_index)})
    return ("name-match", device_id, if_index)


def _topology_unknown_identity(row) -> str:
    """What makes two unmatched neighbour rows the SAME unknown neighbour —
    an AP or phone with no SNMP of its own, seen from two switches, ought to
    draw as one node with two edges, not two disconnected "unknown" boxes.
    Falls back to a row-unique key when neither a chassis id nor a sysName
    was reported at all, which is the honest answer for "nothing here
    identifies this neighbour beyond the port it was seen on"."""
    return (row["chassis_id"] or row["sys_name"]
            or f"row:{row['device_id']}:{row['if_index']}:{row['protocol']}:{row['rem_index']}")


def get_nodes_topology(service, params, body) -> dict:
    """The fleet-wide L2 graph a topology view draws: every Nodes device as
    a node (id/name/status/ip), plus one edge per distinct LLDP/CDP link —
    deduplicated per _topology_dedup_key so the ordinary case (both ends of
    a cable walk their own table) draws one line, not two. A neighbour with
    no device join (nothing in Nodes answers that chassis id or sysName)
    still draws, as its own synthetic node — dropping it would make an
    unmanaged AP or phone invisible instead of clearly unidentified, which
    is the wrong failure mode for a topology view."""
    devices = service.nodes_db.devices()
    device_by_id = {row["id"]: row for row in devices}
    nodes = [{"id": row["id"], "name": hostresolve.device_name(row) or row["ip"],
              "status": row["status"], "ip": row["ip"], "unknown": False}
             for row in devices]

    label = _neighbor_local_port_labeler(service)
    edges_by_key: dict = {}
    unknown_nodes: dict = {}
    for row in service.nodes_db.all_neighbours():
        if not row["present"]:
            continue    # the live graph, not the history — a vanished link should stop drawing
        device_id, if_index = row["device_id"], row["if_index"]
        matched_id = row["matched_device_id"]
        matched_if_index = row["matched_if_index"] if "matched_if_index" in row.keys() else None
        local_label = label(device_id, if_index)
        remote_port = row["port_id"] or row["port_descr"] or ""

        is_unknown = matched_id is None or matched_id not in device_by_id
        if not is_unknown:
            b_id, b_port = matched_id, (remote_port or label(matched_id, matched_if_index))
            key = _topology_dedup_key(device_id, if_index, matched_id, matched_if_index)
        else:
            identity = _topology_unknown_identity(row)
            unk = unknown_nodes.get(identity)
            if unk is None:
                unk = {"id": f"unknown:{identity}",
                       "name": row["sys_name"] or row["platform"] or row["chassis_id"]
                               or "Unidentified neighbour",
                       "status": "unknown", "ip": row["remote_address"] or "", "unknown": True}
                unknown_nodes[identity] = unk
            b_id, b_port = unk["id"], remote_port
            key = ("unknown", identity, device_id, if_index)

        edge = edges_by_key.get(key)
        if edge is None:
            edge = {"id": f"e{len(edges_by_key)}", "a_device_id": device_id,
                    "a_port": local_label, "b_device_id": b_id, "b_port": b_port,
                    "protocols": [], "unknown": is_unknown, "seen_ts": row["seen_ts"]}
            edges_by_key[key] = edge
        if row["protocol"] not in edge["protocols"]:
            edge["protocols"].append(row["protocol"])
        edge["seen_ts"] = max(edge["seen_ts"], row["seen_ts"])

    return {"nodes": nodes + list(unknown_nodes.values()), "edges": list(edges_by_key.values())}


def _topology_export_rows(service) -> list:
    device_by_id = {row["id"]: row for row in service.nodes_db.devices()}
    label = _neighbor_local_port_labeler(service)
    rows = []
    for row in service.nodes_db.all_neighbours():
        device = device_by_id.get(row["device_id"])
        matched_id = row["matched_device_id"]
        matched_name = row["matched_device_name"] if "matched_device_name" in row.keys() else None
        rows.append([
            row["device_id"], hostresolve.device_name(device) if device else "",
            row["if_index"], label(row["device_id"], row["if_index"]),
            row["protocol"], row["chassis_id"], row["sys_name"],
            row["port_id"] or row["port_descr"], row["platform"], row["remote_address"],
            matched_id, matched_name, bool(row["present"]), row["seen_ts"], row["first_seen_ts"],
        ])
    return rows


def get_nodes_topology_export(service, params, body) -> dict:
    """The neighbours/topology table as CSV: every stored LLDP/CDP row,
    present and stale alike (an export exists to leave with the whole
    picture, not only the live graph the on-screen view draws), fleet-wide
    like get_nodes_devices_export rather than filtered to one device."""
    header = ["device_id", "device_name", "if_index", "local_port", "protocol",
             "remote_chassis_id", "remote_sys_name", "remote_port", "platform",
             "remote_address", "matched_device_id", "matched_device_name",
             "present", "seen_ts", "first_seen_ts"]
    return _csv_response("topology", header, _topology_export_rows(service))


def post_nodes_device(service, params, body) -> dict:
    ip = _device_address(body)
    if service.nodes_db.device_by_ip(ip):
        raise ValueError(f"{ip} is already a device")
    group_id = body.get("group_id")
    device_group_id = body.get("device_group_id")
    _check_display_name_source(body)
    # The same two fields put_nodes_device handles specially; add_device's
    # filter dropped them without a word, so a device created with an
    # upstream or a vendor pin got neither. Validated before the insert so
    # a refused value does not leave a half-configured device behind (0 is
    # never a device id, and a device cannot be its own upstream before it
    # exists).
    upstream_id = (_clean_upstream_id(service, 0, body["upstream_id"])
                   if "upstream_id" in body else None)
    vendor_override = str(body.get("vendor_override") or "").strip()
    if len(vendor_override) > 64:
        raise ValueError("A vendor name is at most 64 characters")
    overrides = {k: v for k, v in body.items() if k in _DEVICE_EDITABLE_BODY
                and k not in ("name", "group_id", "device_group_id",
                              "display_name_source", "enabled",
                              "vendor_override", "upstream_id")}
    try:
        device_id = service.nodes_db.add_device(
            ip, name=body.get("name") or None,
            group_id=int(group_id) if group_id else None,
            device_group_id=int(device_group_id) if device_group_id else None,
            **overrides)
    except sqlite3.IntegrityError:
        # devices.ip is UNIQUE, so the check above is a courtesy that gives a
        # readable message; this is the same answer for the race where two
        # adds of one address arrive together, rather than a 500.
        raise ValueError(f"{ip} is already a device")
    # Not an add_device parameter: like device_group_id before it,
    # add_device's **overrides filter only knows credential/polling
    # columns and would silently drop it.
    if body.get("display_name_source"):
        service.nodes_db.update_device(
            device_id, display_name_source=body["display_name_source"])
    if upstream_id is not None:
        service.nodes_db.update_device(device_id, upstream_id=upstream_id)
    if vendor_override:
        service.nodes_db.set_vendor_override(
            device_id, vendor_override, params.get("_username", ""))
    service.log.add(NODES_CATEGORY, f"Added device {ip}")
    return {"id": device_id}


def get_nodes_device(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    reveal = _may_read_secrets(service, params, "nodes")
    device = _device_json(row, reveal)
    # effective_config resolves the profile's own community into the
    # device's, so it carries one too and follows the same rule.
    device["effective_config"] = {
        k: v for k, v in service.nodes_db.effective_config(row).items()
        if k != "v3_auth_pass_enc" and (reveal or k != "community")}
    device["group_name"] = None
    if row["group_id"]:
        group = service.nodes_db.group(row["group_id"])
        device["group_name"] = group["name"] if group else None
    device["polling"] = device_id in service.node_poller.worker_state()
    mute = service.alerts_db.mute_row("device", str(device_id))
    window_until = service.alerts_db.window_covers_device(
        device_id, row["device_group_id"])
    # The later of the two, matching muted_entity_ids' own tie-break: a
    # device can be both hand-muted and inside an active window at once,
    # and "muted until" ought to name whichever one stops applying last.
    device["muted_until"] = max(
        (v for v in (mute["until_ts"] if mute else None, window_until)
         if v is not None), default=None)
    device.update(_identification_json(service, row))
    return {"device": device}


def _identification_json(service, row) -> dict:
    """The vendor identification detail for one device: the stored evidence
    (parsed), whether a walk is running, where a learned vendor came from,
    and the catalog bundle to suggest, resolved to something a button can
    install."""
    keys = row.keys()
    evidence = vendorid._evidence_dict(row) if "vendor_evidence" in keys else {}
    learned_from = None
    if (row["vendor_source"] or "") == "learned":
        learned = service.nodes_db.learned_row(row["sys_object_id"] or "")
        if learned is not None:
            learned_from = {"device_id": learned["source_device_id"],
                            "set_by": learned["set_by"], "set_ts": learned["set_ts"]}
    suggest = None
    key = evidence.get("suggest_bundle")
    if key:
        bundle = mibcatalog.bundle(key)
        if bundle is not None:
            have = {mib["filename"] for mib in service.nodes_db.mib_files()}
            suggest = {"key": bundle.key, "name": bundle.name, "vendor": bundle.vendor,
                       "installed": all(fn in have for fn, _url in bundle.files)}
    learnable, learn_reason = service.nodes_db._learnable(row["sys_object_id"] or "")
    return {
        "vendor_evidence": evidence,
        "identified_ts": row["identified_ts"] if "identified_ts" in keys else None,
        "identifying": service.node_poller.identifying(row["id"]),
        "learned_from": learned_from,
        "suggest_bundle": suggest,
        "vendor_display": enterprises.display_name(row["vendor_detected"] or row["vendor"] or ""),
        "learnable": learnable, "learn_reason": learn_reason,
    }


def _check_display_name_source(body) -> None:
    value = body.get("display_name_source")
    if value is not None and value not in ("auto", "manual"):
        raise ValueError("display_name_source must be 'auto' or 'manual'")


def _clean_upstream_id(service, device_id, value):
    """The upstream device an alert rollup will look through, validated.

    Empty, null and 0 all mean "no upstream" — the form's blank option sends
    one of the three depending on the browser, and all three are the same
    answer. A device pointed at itself would make its own outage suppress
    itself, and a device pointed at an id that is not there would make the
    walk quietly do nothing; both are rejected here rather than tolerated,
    because a topology field that silently does nothing is exactly the
    failure the dead threshold rules already demonstrated.
    """
    if value in (None, "", 0, "0"):
        return None
    try:
        upstream = int(value)
    except (TypeError, ValueError):
        raise ValueError("upstream_id must be a device id")
    if upstream == int(device_id):
        raise ValueError("A device cannot be its own upstream device")
    if not service.nodes_db.device(upstream):
        raise ValueError("No such upstream device")
    return upstream


def _device_address(body) -> str:
    """The address a device is being added at, or a readable refusal.

    Devices are keyed by address and nothing here resolves names — the poller
    speaks SNMP and ICMP straight to what is stored — so a hostname is not a
    device address, and neither is `999.999.1.oops`, which this used to accept
    without a word. An unpollable row looked exactly like a device that was
    merely down, forever, which is the worst way to be told about a typo.

    IPv6 is allowed because the rest of the stack already handles it; a
    zone index is not, since it means nothing on another machine.
    """
    ip = str(body.get("ip", "")).strip()
    if not ip:
        raise ValueError("An IP address is required")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(
            f"{ip!r} is not an IP address. Devices are polled by address, "
            "so a name cannot be used here.") from None
    return ip


def put_nodes_device(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    _check_display_name_source(body)
    fields = {k: v for k, v in body.items() if k in _DEVICE_EDITABLE_BODY}
    if "upstream_id" in fields:
        fields["upstream_id"] = _clean_upstream_id(
            service, device_id, fields["upstream_id"])
    result = {"ok": True}
    if "vendor_override" in fields:
        # Not a plain column write: setting a vendor by hand also teaches
        # the fleet (when the sysObjectID is specific enough) and clearing
        # it re-decides the row, both of which nodesdb.set_vendor_override
        # owns. Everything else in the body still goes the ordinary way.
        value = fields.pop("vendor_override")
        value = str(value or "").strip()
        if len(value) > 64:
            raise ValueError("A vendor name is at most 64 characters")
        result["vendor"] = service.nodes_db.set_vendor_override(
            device_id, value or None, params.get("_username", ""))
    if fields:
        service.nodes_db.update_device(device_id, **fields)
    return result


def delete_nodes_device(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    service.nodes_db.remove_device(device_id)
    service.configrx_db.forget_device(device_id)
    service.log.add(NODES_CATEGORY, f"Removed device {row['ip']}")
    return {"ok": True}


def _bulk_device_ids(body) -> list[int]:
    ids = body.get("device_ids") or []
    if not ids:
        raise ValueError("device_ids is required")
    return [int(i) for i in ids]


def post_nodes_devices_bulk_update(service, params, body) -> dict:
    device_ids = _bulk_device_ids(body)
    fields = {}
    if "group_id" in body:
        group_id = body["group_id"]
        if group_id is not None and not service.nodes_db.group(group_id):
            raise ValueError("No such polling profile")
        fields["group_id"] = group_id
    if "device_group_id" in body:
        device_group_id = body["device_group_id"]
        if device_group_id is not None and not service.nodes_db.device_group(device_group_id):
            raise ValueError("No such group")
        fields["device_group_id"] = device_group_id
    if not fields:
        raise ValueError("Nothing to update")
    service.nodes_db.bulk_update_devices(device_ids, **fields)
    service.log.add(NODES_CATEGORY,
                    f"Bulk-updated {len(device_ids)} device(s): {', '.join(fields)}")
    return {"ok": True, "updated": len(device_ids)}


def post_nodes_devices_bulk_delete(service, params, body) -> dict:
    device_ids = _bulk_device_ids(body)
    removed = service.nodes_db.bulk_remove_devices(device_ids)
    for device_id in device_ids:
        service.configrx_db.forget_device(device_id)
    service.log.add(NODES_CATEGORY, f"Bulk-removed {removed} device(s)")
    return {"ok": True, "removed": removed}


# ------------------------------------------------------------ bulk import
#
# Item 3: onboarding was measured at 16.6 devices/s through the single-
# device POST route — 2,000 devices is over two minutes of API round
# trips before any of them has even been polled once. This route accepts
# the same fields the single POST accepts (see _DEVICE_EDITABLE_BODY),
# either as a JSON array of device objects or as pasted CSV text with a
# header row, validates every row before writing anything, and inserts
# whatever validated in one transaction (nodesdb.add_devices_bulk) — a
# conflict partway through cannot leave the fleet half-imported while the
# per-row disposition list below says otherwise.
#
# Accepted CSV columns (case-insensitive, spaces or underscores either
# way): address (or ip, required), name, group (or group_id — a polling
# profile, by name or numeric id), device_group (or device_group_id — by
# name or numeric id), snmp_version, community, v3_user, v3_auth_proto,
# poll_interval_s, snmp_timeout_s, snmp_retries, ping_enabled,
# snmp_enabled, vendor_override, display_name_source. An unrecognised
# column is ignored rather than refused, so a spreadsheet carrying extra
# inventory columns (asset tag, site, rack) still imports. upstream_id is
# deliberately not accepted here: a bulk paste has no reliable way to name
# a device that does not exist yet, and the single-device and Edit forms
# already cover setting it once devices exist.
BULK_IMPORT_MAX_ROWS = 2000

_BULK_IMPORT_ALIASES = {
    "address": "ip", "group": "group_id", "profile": "group_id",
    "device_group": "device_group_id", "snmp_community": "community",
}

# CSV arrives as strings; these are the override columns that are not text
# columns in the database, so a "1" or "true" typed into a spreadsheet
# cell needs turning into what add_device's **overrides already expects.
# Anything not listed (community, v3_user, v3_auth_proto, oid_set) passes
# through as text exactly as typed, on both the CSV and JSON paths.
_BULK_IMPORT_INT_FIELDS = ("snmp_version", "poll_interval_s", "snmp_timeout_s",
                          "snmp_retries", "ping_count", "ping_timeout_ms",
                          "mac_table_interval_s")
_BULK_IMPORT_BOOL_FIELDS = ("ping_enabled", "snmp_enabled", "unreachable_ping_only")


def _bulk_import_bool(value):
    if isinstance(value, bool) or value is None:
        return value
    text = str(value).strip().lower()
    return text in ("1", "true", "yes", "y", "on")


def _parse_bulk_import_rows(body) -> list[dict]:
    devices = body.get("devices")
    if isinstance(devices, list):
        if not all(isinstance(row, dict) for row in devices):
            raise ValueError("Every entry in 'devices' must be an object")
        return devices
    text = body.get("csv")
    if isinstance(text, str) and text.strip():
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("The pasted CSV has no header row")
        rows = []
        for raw in reader:
            row = {}
            for key, value in raw.items():
                if not key:
                    continue
                norm = key.strip().lower().replace(" ", "_")
                norm = _BULK_IMPORT_ALIASES.get(norm, norm)
                value = (value or "").strip()
                if value:                # a blank cell means "not specified"
                    row[norm] = value
            if row:                      # a wholly blank line, e.g. a trailing newline
                rows.append(row)
        return rows
    raise ValueError("Provide either a 'devices' array or 'csv' text")


def _resolve_bulk_named_id(value, lookup_rows):
    """`value` is a numeric id, a name to look up in `lookup_rows`
    (case-insensitively), or empty/absent for "none" — a CSV cell names a
    polling profile or a device group by the label an operator actually
    sees on screen, not by an id nobody pasting a spreadsheet would know."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        row = next((r for r in lookup_rows if r["id"] == int(text)), None)
        if row is None:
            raise ValueError(f"No such id: {text}")
        return int(text)
    row = next((r for r in lookup_rows if r["name"].lower() == text.lower()), None)
    if row is None:
        raise ValueError(f"No such name: {text!r}")
    return row["id"]


def post_nodes_devices_bulk_import(service, params, body) -> dict:
    rows = _parse_bulk_import_rows(body)
    if not rows:
        raise ValueError("No rows to import")
    if len(rows) > BULK_IMPORT_MAX_ROWS:
        raise ValueError(f"At most {BULK_IMPORT_MAX_ROWS:,} rows at a time")

    groups = service.nodes_db.groups()
    device_groups = service.nodes_db.device_groups()
    existing_ips = {d["ip"] for d in service.nodes_db.devices()}
    seen_in_batch = set()

    created, duplicate, invalid = [], [], []
    to_insert = []
    for i, raw in enumerate(rows, start=1):
        try:
            ip = _device_address(raw)
        except ValueError as exc:
            invalid.append({"row": i, "ip": str(raw.get("ip", "")), "reason": str(exc)})
            continue
        if ip in existing_ips or ip in seen_in_batch:
            duplicate.append({"row": i, "ip": ip, "reason": f"{ip} is already a device"})
            continue
        try:
            group_id = _resolve_bulk_named_id(raw.get("group_id"), groups)
            device_group_id = _resolve_bulk_named_id(raw.get("device_group_id"), device_groups)
            _check_display_name_source(raw)
            vendor_override = str(raw.get("vendor_override") or "").strip()
            if len(vendor_override) > 64:
                raise ValueError("A vendor name is at most 64 characters")
            overrides = {}
            for key, value in raw.items():
                if key not in _DEVICE_EDITABLE_BODY or key in (
                        "name", "group_id", "device_group_id", "display_name_source",
                        "enabled", "vendor_override", "upstream_id"):
                    continue
                if value in (None, ""):
                    continue
                if key in _BULK_IMPORT_INT_FIELDS:
                    try:
                        value = int(value)
                    except (TypeError, ValueError):
                        raise ValueError(f"{key} must be a whole number")
                elif key in _BULK_IMPORT_BOOL_FIELDS:
                    value = _bulk_import_bool(value)
                overrides[key] = value
        except ValueError as exc:
            invalid.append({"row": i, "ip": ip, "reason": str(exc)})
            continue
        seen_in_batch.add(ip)
        to_insert.append({
            "row": i, "ip": ip, "name": str(raw.get("name") or "").strip() or None,
            "group_id": group_id, "device_group_id": device_group_id,
            "overrides": overrides, "vendor_override": vendor_override,
            "display_name_source": raw.get("display_name_source") or None,
        })

    # Validation is entirely finished at this point — nothing below can add
    # to `invalid`. The insert is one transaction across every row that
    # validated; see add_devices_bulk's own docstring for why.
    device_ids = service.nodes_db.add_devices_bulk(to_insert) if to_insert else []
    for row, device_id in zip(to_insert, device_ids):
        if row["display_name_source"]:
            service.nodes_db.update_device(
                device_id, display_name_source=row["display_name_source"])
        if row["vendor_override"]:
            service.nodes_db.set_vendor_override(
                device_id, row["vendor_override"], params.get("_username", ""))
        created.append({"row": row["row"], "ip": row["ip"], "id": device_id})

    if created:
        service.log.add(NODES_CATEGORY, f"Bulk-imported {len(created)} device(s)")
        # The same post-add machinery post_nodes_device triggers for one
        # device, batched: a first poll and, where SNMP is enabled, a
        # vendor identification walk — the bulk-poll and bulk-identify
        # routes above are the un-batched originals this mirrors. Best
        # effort: a poller that cannot queue one of these does not undo an
        # insert that has already committed.
        for device_id in device_ids:
            try:
                service.node_poller.poll_now(device_id)
                device_row = service.nodes_db.device(device_id)
                if device_row is not None and service.nodes_db.effective_config(
                        device_row).get("snmp_enabled", True):
                    service.node_poller.start_identify(device_id, trigger="bulk-import")
            except Exception:                                     # noqa: BLE001
                pass

    return {"ok": True, "total": len(rows), "created": created,
            "duplicate": duplicate, "invalid": invalid}


def post_nodes_device_poll(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    # queued=False means a poll for this device was already in flight, so
    # this click started nothing. The button says so rather than reporting
    # "Polled" off the other poll's completion.
    return {"ok": True, "queued": bool(service.node_poller.poll_now(device_id))}


def post_nodes_devices_bulk_poll(service, params, body) -> dict:
    """Poll now for every ticked device — the bulk-bar counterpart of the
    detail pane's button, which only ever polls the one open device."""
    device_ids = _bulk_device_ids(body)
    existing = {d["id"] for d in service.nodes_db.devices_by_ids(device_ids)}
    queued, busy, missing = [], [], []
    for device_id in device_ids:
        if device_id not in existing:
            missing.append(device_id)
            continue
        (queued if service.node_poller.poll_now(device_id) else busy).append(device_id)
    if queued:
        service.log.add(NODES_CATEGORY, f"Poll now requested for {len(queued)} device(s)")
    return {"ok": True, "queued": queued, "already_polling": busy, "missing": missing}


def post_nodes_device_focus(service, params, body, device_id) -> dict:
    """The browser renews this every refresh tick while the device is
    selected on the Nodes tab; the short TTL means fast polling lapses on
    its own when the tab is left or the browser closes — deselection
    never needs its own request."""
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    interval = float(service.nodes_settings.get("focus_poll_interval_s", 3))
    service.node_poller.set_focus(device_id, ttl_s=15, interval_s=interval)
    return {"ok": True, "interval_s": interval}


def get_nodes_device_dom(service, params, body, device_id, if_index) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    sensors = service.node_poller.read_dom(int(device_id), int(if_index))
    return {"sensors": sensors}


def get_nodes_device_mac_table(service, params, body, device_id, if_index) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    macs = service.node_poller.read_mac_table(int(device_id), int(if_index))
    return {"macs": macs, "supported": macs is not None}


def _oid_name_table(service) -> dict:
    """OID -> name, from every uploaded MIB plus the built-in well-known
    table the Trap page already decodes with. One table, so uploading a MIB
    improves the OID browser the same moment it improves trap decoding."""
    names = dict(trapoids.WELL_KNOWN)
    # all_known_oids() is name -> OID (it feeds mibparse.resolve's `known`
    # dict); the browser needs the inverse.
    for name, oid in service.nodes_db.all_known_oids().items():
        if oid:
            names[oid] = name
    return names


def _decode_oid(names: dict, oid: str) -> tuple[str, str]:
    """(name, suffix) for one OID, by longest prefix. An object's own OID
    matches exactly; an instance ('...1.5.0') or a table row ('...1.1.4.7')
    matches its column and keeps the rest as the index, which is what makes
    a walked table readable. Unknown OIDs return ('', '') rather than a
    guess — a number is honest, an invented name is not."""
    parts = oid.split(".")
    for cut in range(len(parts), 0, -1):
        name = names.get(".".join(parts[:cut]))
        if name:
            return name, ".".join(parts[cut:])
    return "", ""


def get_nodes_device_oids(service, params, body, device_id) -> dict:
    """One subtree of a device's SNMP tree, walked live and decoded against
    every MIB this app knows. `oid` picks the subtree; without it the
    device's default set is reported so the dialog knows what to offer."""
    device = service.nodes_db.device(device_id)
    if not device:
        raise ValueError("No such device")
    bases = service.node_poller.browse_bases(int(device_id))
    base = (params.get("oid") or "").strip()
    if not base:
        return {"bases": bases, "rows": [], "base": "", "stopped": "",
                "complete": True, "walked": False}
    result = service.node_poller.walk_subtree(int(device_id), base)
    if result is None:
        return {"bases": bases, "rows": [], "base": base, "walked": False,
                "complete": False,
                "stopped": "SNMP is disabled for this device"}
    names = _oid_name_table(service)
    rows = []
    for row in result["rows"]:
        name, suffix = _decode_oid(names, row["oid"])
        value = row["value"]
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", "replace")
        rows.append({
            "oid": row["oid"], "name": name, "suffix": suffix,
            "type": row["type"],
            "value": row["text"] if row["text"] is not None else
                     ("" if value is None else str(value)),
        })
    return {"bases": bases, "base": result["base"], "rows": rows,
            "stopped": result["stopped"], "complete": result["complete"],
            "walked": True}


def post_nodes_device_oid_walk(service, params, body, device_id) -> dict:
    """Start a whole-device walk in the background, or report the one
    already running for this device. Refused politely rather than queued —
    a second walk of the same device would just fight the first for the
    agent's attention."""
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    return {"walk": service.node_poller.start_oid_walk(int(device_id))}


def get_nodes_device_oid_walk(service, params, body, device_id) -> dict:
    """Progress, or the finished walk. `download` asks for the file text:
    once handed over, the rows are dropped, since a walk exists to be
    downloaded once."""
    status = service.node_poller.oid_walk_status(
        int(device_id), with_rows=params.get("download") is not None)
    if status is None:
        return {"walk": None}
    if params.get("download") is None or status["state"] != "done":
        status.pop("walk", None)
        return {"walk": status}
    rows = status.pop("walk", [])
    text = _oid_walk_text(service, status, rows)
    service.node_poller.forget_oid_walk(int(device_id))
    return {"walk": status, "text": text,
            "filename": _oid_walk_filename(status)}


def delete_nodes_device_oid_walk(service, params, body, device_id) -> dict:
    return {"cancelled": service.node_poller.cancel_oid_walk(int(device_id))}


def post_nodes_device_identify(service, params, body, device_id) -> dict:
    """Re-identify: start the bounded vendor walk now, or report the one
    already running. A job, not a synchronous answer — the walk is up to
    20 s, the page refreshes every few seconds, and bulk cannot wait."""
    return {"job": service.node_poller.start_identify(int(device_id), trigger="manual")}


def get_nodes_device_identify(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    return {"job": service.node_poller.identify_status(int(device_id)),
            "result": {"vendor": row["vendor"], "vendor_detected": row["vendor_detected"],
                       "vendor_source": row["vendor_source"] or "",
                       "vendor_confidence": (row["vendor_confidence"] or ""
                                             if "vendor_confidence" in row.keys() else ""),
                       **_identification_json(service, row)}}


def delete_nodes_device_identify(service, params, body, device_id) -> dict:
    return {"cancelled": service.node_poller.cancel_identify(int(device_id))}


def post_nodes_devices_bulk_identify(service, params, body) -> dict:
    """Re-identify every ticked device. Id lists back, the bulk-poll shape:
    an operator who ticked twelve switches deserves to know which three
    were skipped and why."""
    device_ids = _bulk_device_ids(body)
    rows = {d["id"]: d for d in service.nodes_db.devices_by_ids(device_ids)}
    queued, running, snmp_off, missing = [], [], [], []
    for device_id in device_ids:
        row = rows.get(device_id)
        if row is None:
            missing.append(device_id)
            continue
        if not service.nodes_db.effective_config(row).get("snmp_enabled", True):
            snmp_off.append(device_id)
            continue
        if service.node_poller.identifying(device_id):
            running.append(device_id)
            continue
        service.node_poller.start_identify(device_id, trigger="manual")
        queued.append(device_id)
    if queued:
        service.log.add(NODES_CATEGORY,
                        f"Re-identify requested for {len(queued)} device(s)")
    return {"ok": True, "queued": queued, "already_running": running,
            "snmp_disabled": snmp_off, "missing": missing}


def _oid_walk_filename(status) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(status["started_ts"]))
    safe = "".join(c if c.isalnum() or c in "-_." else "-"
                   for c in (status.get("device_label") or "device"))
    return f"snmp-walk-{safe}-{stamp}.txt"


def _oid_walk_text(service, status, rows) -> str:
    """The downloaded file: a header stating what was walked and whether it
    finished, then one `OID = type: value` line per object with the decoded
    name where a MIB provides one.

    The header says outright when the walk was cut short and why. A
    truncated file that looks complete is the failure this whole feature
    could most easily cause — someone diffing two walks and concluding a
    device lost half its MIB when in fact the clock ran out.
    """
    names = _oid_name_table(service)
    started = time.strftime("%Y-%m-%d %H:%M:%S",
                            time.localtime(status["started_ts"]))
    head = [
        f"# SNMP walk of {status.get('device_label') or 'device'}",
        f"# Started {started}, from {status['base']}",
        f"# {len(rows)} object(s) in {status['elapsed']:.1f}s",
    ]
    if status["complete"]:
        head.append("# COMPLETE — the walk reached the end of the tree.")
    else:
        head.append(f"# INCOMPLETE — {status['stopped']}. Objects beyond that "
                    f"point are NOT in this file.")
    head.append("#")
    lines = list(head)
    for row in rows:
        value = row["value"]
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", "replace")
        text = row["text"] if row["text"] is not None else (
            "" if value is None else str(value))
        name, suffix = _decode_oid(names, row["oid"])
        label = f"  [{name}{'.' + suffix if suffix else ''}]" if name else ""
        lines.append(f"{row['oid']} = {row['type']}: {text}{label}")
    return "\n".join(lines) + "\n"


def post_nodes_device_test(service, params, body, device_id) -> dict:
    """Ping + SNMP against the in-progress-edit config carried in the
    body, falling back to the saved one for anything not overridden — the
    same "test what's typed before saving" idiom as IPAM's DHCP test.
    Builds the SNMP request directly with snmppoll rather than going
    through NodePoller/credential_for(), so a typed-but-unsaved v3
    password is used once, in memory, and never touches DPAPI — the same
    "usable without ever being persisted on a non-Windows box" property
    CREDENTIAL-SECURITY.md documents for every other credential form."""
    import random
    from .. import nodeoids
    from ..ipam_scan import ping_once
    from ..nodepoll import DEFAULT_SNMP_PORT, _Session, credential_for
    from ..snmppoll import (PDU_GET, PDU_REPORT, SnmpError, build_request,
                            build_v3_request, discovery_probe)
    from ..trapdecode import localized_key

    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    config = service.nodes_db.effective_config(row)
    # The edit form's overrides are tri-state (null means "inherit from
    # the profile", distinct from an explicit false) — an explicit null
    # here must fall through to the already-resolved effective config,
    # not blank the field out.
    for key in ("snmp_version", "poll_interval_s", "snmp_timeout_s", "snmp_retries",
               "ping_enabled", "snmp_enabled"):
        if key in body and body[key] is not None:
            config[key] = body[key]

    if "community" in body:
        identity = body.get("community") or None
    elif "v3_user" in body:
        identity = body.get("v3_user") or None
    else:
        identity = None
    auth_proto = body.get("v3_auth_proto") or config.get("v3_auth_proto")
    password = body.get("v3_auth_pass")
    if identity is None or (password is None and "v3_auth_pass" not in body):
        stored_identity, stored_proto, stored_password = credential_for(config)
        identity = identity if identity is not None else stored_identity
        auth_proto = auth_proto or stored_proto
        if password is None and "v3_auth_pass" not in body:
            password = stored_password

    result = {"ping": {"ok": None, "rtt_ms": None}, "snmp": {"ok": None, "error": None}}
    timeout_s = float(config.get("snmp_timeout_s", 3.0))
    if config.get("ping_enabled"):
        started = time.time()
        ping_ok = ping_once(row["ip"], timeout_ms=int(timeout_s * 1000))
        result["ping"]["ok"] = ping_ok
        if ping_ok:
            result["ping"]["rtt_ms"] = (time.time() - started) * 1000.0

    if config.get("snmp_enabled"):
        version = int(config.get("snmp_version", 1))
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        try:
            session = _Session(row["ip"], DEFAULT_SNMP_PORT, timeout_s,
                               int(config.get("snmp_retries", 2)))
            try:
                request_id = random.randint(1, 2 ** 16)
                if version in (0, 1):
                    packet = build_request(version, identity or "public", PDU_GET,
                                           request_id, oids)
                else:
                    engine_reply = session.request(discovery_probe())
                    auth_key = (localized_key(auth_proto, password, engine_reply.engine_id)
                               if auth_proto and password else None)
                    packet = build_v3_request(
                        random.randint(1, 2 ** 16), request_id,
                        PDU_GET, oids, engine_id=engine_reply.engine_id,
                        engine_boots=engine_reply.engine_boots,
                        engine_time=engine_reply.engine_time, user=identity or "",
                        auth_proto=auth_proto, auth_key=auth_key)
                response = session.request(packet, expect_request_id=request_id)
                if version >= 3 and response.pdu_tag == PDU_REPORT:
                    raise SnmpError("engine resync required (Report-PDU) — check "
                                    "the SNMPv3 username and auth password")
                if response.error_status == 16:
                    raise SnmpError("authorization error")
            finally:
                session.close()
            values = {vb["oid"]: vb["value"] for vb in response.varbinds
                     if vb["type"] not in ("noSuchObject", "noSuchInstance")}
            result["snmp"]["ok"] = True
            result["snmp"]["sys_descr"] = values.get(nodeoids.SYSTEM_SCALARS["sys_descr"])
            result["snmp"]["sys_name"] = values.get(nodeoids.SYSTEM_SCALARS["sys_name"])
            result["snmp"]["sys_uptime"] = values.get(nodeoids.SYSTEM_SCALARS["sys_uptime"])
        except (SnmpError, OSError) as exc:
            # OSError: _Session's socket() itself failed (descriptor
            # exhaustion); the same readable answer as a protocol failure.
            result["snmp"]["ok"] = False
            result["snmp"]["error"] = str(exc)
        finally:
            password = None
    return result


def get_nodes_device_interfaces(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    rows = service.nodes_db.interfaces(device_id)
    keys = rows[0].keys() if rows else ()
    # poe_admin/poe_detect_status/poe_power_mw/stp_state (Tier 1 #7): read
    # defensively like every other column a migration added, since a row
    # fetched before this wave's ALTER TABLE ran on this database simply
    # will not have them yet on the very first call after an upgrade.
    return {"interfaces": [
        {"id": r["id"], "if_index": r["if_index"], "descr": r["descr"],
         "alias": r["alias"], "phys_addr": r["phys_addr"], "speed_bps": r["speed_bps"],
         "admin_status": r["admin_status"], "oper_status": r["oper_status"],
         "in_bps": r["in_bps"], "out_bps": r["out_bps"],
         "in_error_rate": r["in_error_rate"], "out_error_rate": r["out_error_rate"],
         "last_in_errors": r["last_in_errors"], "last_out_errors": r["last_out_errors"],
         "last_in_octets": r["last_in_octets"], "last_out_octets": r["last_out_octets"],
         "last_seen_ts": r["last_seen_ts"],
         "poe_admin": (r["poe_admin"] if "poe_admin" in keys else None),
         "poe_detect_status": (r["poe_detect_status"] if "poe_detect_status" in keys else None),
         "poe_power_mw": (r["poe_power_mw"] if "poe_power_mw" in keys else None),
         "stp_state": (r["stp_state"] if "stp_state" in keys else None)}
        for r in rows]}


def get_nodes_device_interfaces_export(service, params, body, device_id) -> dict:
    """One device's port table. Bounded by its own port count — a device
    with thousands of interfaces is not a case this network has — so
    there is no export ceiling to lift here, only the same rows the JSON
    handler above already reads."""
    interfaces = get_nodes_device_interfaces(service, params, body, device_id)["interfaces"]
    header = ["if_index", "descr", "alias", "phys_addr", "speed_bps",
             "admin_status", "oper_status", "in_bps", "out_bps",
             "in_error_rate", "out_error_rate", "last_in_errors", "last_out_errors",
             "last_seen_ts", "poe_admin", "poe_detect_status", "poe_power_mw", "stp_state"]
    csv_rows = [[i.get(key) for key in header] for i in interfaces]
    return _csv_response("interfaces", header, csv_rows)


def get_nodes_device_metrics(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    rows = service.nodes_db.metrics(device_id)
    return {"metrics": [
        {"id": r["id"], "key": r["key"], "label": r["label"], "unit": r["unit"],
         "kind": r["kind"], "last_value": r["last_value"], "last_ts": r["last_ts"]}
        for r in rows]}


def get_nodes_device_series(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    metric_id = params.get("metric_id")
    if not metric_id:
        raise ValueError("metric_id is required")
    t0, t1 = _window(params)
    bucket_s = _num(params, "bucket_s", 0)
    if bucket_s < 0:
        bucket_s = 0
    bucket_s = min(bucket_s, (t1 - t0) / 2)
    points = service.nodes_db.series(device_id, int(metric_id), t0, t1, bucket_s=bucket_s)
    return {"t0": t0, "t1": t1, "points": points}


def get_nodes_device_timeline(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    t0, t1 = _window(params)
    segments = service.nodes_db.device_status_segments(device_id, t0, t1)
    return {"t0": t0, "t1": t1, "segments": segments}


def get_nodes_device_events(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    since_s = _num(params, "since_s", None)
    device_events = service.nodes_db.device_events(device_id=device_id, since_s=since_s)
    interface_events = [
        {"id": ev["id"], "interface_id": ev["interface_id"],
         "if_index": ev["if_index"], "descr": ev["descr"],
         "ts": ev["ts"], "kind": ev["kind"], "detail": ev["detail"]}
        for ev in service.nodes_db.interface_events_for_device(device_id, since_s=since_s)]
    return {
        "device_events": [
            {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "detail": r["detail"]}
            for r in device_events],
        "interface_events": interface_events,
    }


def post_nodes_device_credential(service, params, body, device_id) -> dict:
    from .. import dpapi

    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    user = str(body.get("v3_user", "")).strip()
    password = str(body.get("v3_auth_pass", ""))
    auth_proto = str(body.get("v3_auth_proto", "")).strip()
    if not user or not password or not auth_proto:
        raise ValueError("A username, auth protocol, and password are all required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. The device can still be reached by typing the "
            "password into Test each time; nothing will be saved here.")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.nodes_db.set_device_credential(device_id, user, auth_proto, encrypted)
    service.log.add(NODES_CATEGORY, f"Stored an SNMPv3 credential for {row['ip']}")
    _audit(service, params, "credential.store", target=f"device:{row['ip']}",
           detail=f"SNMPv3 user {user}")
    return {"ok": True}


def delete_nodes_device_credential(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    service.nodes_db.clear_device_credential(device_id)
    _audit(service, params, "credential.clear", target=f"device:{row['ip']}")
    service.log.add(NODES_CATEGORY,
                    f"Cleared the stored SNMPv3 credential for {row['ip']}")
    return {"ok": True}


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
    return {"id": device_group_id}


def put_nodes_device_group(service, params, body, device_group_id) -> dict:
    if not service.nodes_db.device_group(device_group_id):
        raise ValueError("No such device group")
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    service.nodes_db.rename_device_group(device_group_id, name)
    return {"ok": True}


def delete_nodes_device_group(service, params, body, device_group_id) -> dict:
    row = service.nodes_db.device_group(device_group_id)
    if not row:
        raise ValueError("No such device group")
    service.nodes_db.remove_device_group(device_group_id)
    service.log.add(NODES_CATEGORY, f"Removed device group {row['name']}")
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
    group_id = service.nodes_db.add_group(name, **fields)
    service.log.add(NODES_CATEGORY, f"Added polling profile {name}")
    return {"id": group_id}


def put_nodes_group(service, params, body, group_id) -> dict:
    if not service.nodes_db.group(group_id):
        raise ValueError("No such polling profile")
    fields = {k: v for k, v in body.items() if k in _GROUP_EDITABLE_BODY}
    service.nodes_db.update_group(group_id, **fields)
    return {"ok": True}


def delete_nodes_group(service, params, body, group_id) -> dict:
    row = service.nodes_db.group(group_id)
    if not row:
        raise ValueError("No such polling profile")
    in_use = service.nodes_db.device_count_for_group(group_id)
    if in_use:
        raise ValueError(f"{in_use} device(s) still use this profile — "
                         "move them to another profile first")
    service.nodes_db.remove_group(group_id)
    service.log.add(NODES_CATEGORY, f"Removed polling profile {row['name']}")
    return {"ok": True}


def post_nodes_group_default(service, params, body, group_id) -> dict:
    row = service.nodes_db.group(group_id)
    if not row:
        raise ValueError("No such polling profile")
    service.nodes_db.set_default_group(group_id)
    service.log.add(NODES_CATEGORY, f"{row['name']} is now the default polling profile")
    return {"ok": True}


def post_nodes_group_credential(service, params, body, group_id) -> dict:
    from .. import dpapi

    row = service.nodes_db.group(group_id)
    if not row:
        raise ValueError("No such polling profile")
    user = str(body.get("v3_user", "")).strip()
    password = str(body.get("v3_auth_pass", ""))
    auth_proto = str(body.get("v3_auth_proto", "")).strip()
    if not user or not password or not auth_proto:
        raise ValueError("A username, auth protocol, and password are all required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only.")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.nodes_db.set_group_credential(group_id, user, auth_proto, encrypted)
    service.log.add(NODES_CATEGORY,
                    f"Stored an SNMPv3 credential for profile {row['name']}")
    _audit(service, params, "credential.store", target=f"profile:{row['name']}",
           detail=f"SNMPv3 user {user}")
    return {"ok": True}


def delete_nodes_group_credential(service, params, body, group_id) -> dict:
    row = service.nodes_db.group(group_id)
    if not row:
        raise ValueError("No such polling profile")
    service.nodes_db.clear_group_credential(group_id)
    service.log.add(NODES_CATEGORY,
                    f"Cleared the stored SNMPv3 credential for profile {row['name']}")
    return {"ok": True}


# ---------------------------------------------------- additional credentials
#
# A profile's own snmp_version/community/v3_* columns (above) are its
# always-present "primary" credential. These endpoints manage the
# ADDITIONAL credentials a profile can hold in its group_credentials table
# — alternates the poller tries, in order, for any device on this profile
# that doesn't answer the primary. Same shape throughout as the primary
# credential's own endpoints just above.

_GROUP_CREDENTIAL_EDITABLE = ("label", "snmp_version", "community", "v3_user",
                              "v3_auth_proto")


def post_nodes_group_credentials(service, params, body, group_id) -> dict:
    row = service.nodes_db.group(group_id)
    if not row:
        raise ValueError("No such polling profile")
    fields = {k: v for k, v in body.items() if k in _GROUP_CREDENTIAL_EDITABLE}
    credential_id = service.nodes_db.add_group_credential(group_id, **fields)
    service.log.add(NODES_CATEGORY,
                    f"Added an additional SNMP credential to profile {row['name']}")
    return {"id": credential_id}


def put_nodes_group_credential(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    if not cred or cred["group_id"] != int(group_id):
        raise ValueError("No such credential")
    fields = {k: v for k, v in body.items() if k in _GROUP_CREDENTIAL_EDITABLE}
    service.nodes_db.update_group_credential(credential_id, **fields)
    return {"ok": True}


def delete_nodes_group_credential_row(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    if not cred or cred["group_id"] != int(group_id):
        raise ValueError("No such credential")
    service.nodes_db.remove_group_credential(credential_id)
    return {"ok": True}


def post_nodes_group_credential_secret(service, params, body, group_id, credential_id) -> dict:
    from .. import dpapi

    cred = service.nodes_db.group_credential(credential_id)
    if not cred or cred["group_id"] != int(group_id):
        raise ValueError("No such credential")
    user = str(body.get("v3_user", "")).strip()
    password = str(body.get("v3_auth_pass", ""))
    auth_proto = str(body.get("v3_auth_proto", "")).strip()
    if not user or not password or not auth_proto:
        raise ValueError("A username, auth protocol, and password are all required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only.")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.nodes_db.set_group_credential_password(credential_id, user, auth_proto, encrypted)
    service.log.add(NODES_CATEGORY, "Stored an SNMPv3 credential for an additional "
                                    f"credential on profile {cred['label'] or credential_id}")
    _audit(service, params, "credential.store",
           target=f"profile-credential:{cred['label'] or credential_id}",
           detail=f"SNMPv3 user {user}")
    return {"ok": True}


def delete_nodes_group_credential_secret(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    if not cred or cred["group_id"] != int(group_id):
        raise ValueError("No such credential")
    service.nodes_db.clear_group_credential_password(credential_id)
    _audit(service, params, "credential.clear",
           target=f"profile-credential:{cred['label'] or credential_id}")
    return {"ok": True}


def _discovery_communities_for_group(service, group_id: int) -> str:
    """Every v1/v2c community from this profile's credentials — its own
    primary one plus every group_credentials alternate — joined the same
    way the old free-text field was, so nodediscover.py itself needs no
    changes. A v3-only profile contributes nothing here (v3 identification
    was never in scope for a blind discovery sweep — see nodediscover.py's
    own docstring); an empty result means no SNMP is attempted at all,
    which post_nodes_discovery refuses up front unless the job allows
    ping-only devices."""
    group_row = service.nodes_db.group(group_id)
    if group_row is None:
        return ""
    rows = [group_row] + list(service.nodes_db.group_credentials(group_id))
    communities = []
    for row in rows:
        if row["snmp_version"] in (0, 1) and row["community"] and row["community"] not in communities:
            communities.append(row["community"])
    return ",".join(communities)


def _discovery_kind_for(target: str) -> tuple[str, str]:
    """A bare address or a /32 is a single-device job (which still tries
    SNMP without a ping reply — see nodediscover.py); anything else is a
    subnet sweep. There is no separate kind field to choose any more: the
    CIDR itself says which one was meant."""
    try:
        if "/" not in target:
            return "device", str(ipaddress.ip_address(target))
        network = ipaddress.ip_network(target, strict=False)
        if network.prefixlen == network.max_prefixlen:
            return "device", str(network.network_address)
        return "subnet", str(network)
    except ValueError as exc:
        raise ValueError(
            f"'{target}' is not an IP address or CIDR subnet") from exc


def post_nodes_discovery(service, params, body) -> dict:
    target = str(body.get("target", "")).strip()
    if not target:
        raise ValueError("A target is required")
    kind, target = _discovery_kind_for(target)
    group_id = body.get("group_id")
    if not group_id:
        raise ValueError("A polling profile is required")
    if not service.nodes_db.group(group_id):
        raise ValueError("No such polling profile")
    allow_ping_only = bool(body.get("allow_ping_only"))
    communities = _discovery_communities_for_group(service, group_id)
    if not communities and not allow_ping_only:
        raise ValueError(
            "This profile has no v1/v2c communities for discovery to try. "
            "Pick a profile with one, or allow ping-only devices.")
    # The never-scan list and the probe rate are global settings the
    # discovery job cannot see on its own (its settings dict is Nodes'),
    # so they are carried in with the per-job overrides. They are NOT
    # settable from the request body — a scan does not get to choose how
    # gentle it is with a plant segment.
    overrides = {
        "discovery_communities": communities,
        "never_scan_cidrs": service.settings.get("never_scan_cidrs", ""),
    }
    # Per-scan timing overrides from the Start-discovery dialog — they
    # live only in this job's settings, never in stored settings.
    for body_key, override_key, cast in (
            ("snmp_timeout_s", "discovery_snmp_timeout_s", float),
            ("ping_timeout_s", "discovery_ping_timeout_s", float),
            ("snmp_retries", "discovery_snmp_retries", int),
            ("ping_retries", "discovery_ping_retries", int)):
        value = body.get(body_key)
        if value is not None and str(value) != "":
            value = cast(value)
            if value < 0:
                raise ValueError(f"{body_key} cannot be negative")
            overrides[override_key] = value
    job_id = service.node_poller.start_discovery(
        kind, target, overrides=overrides, allow_ping_only=allow_ping_only)
    service.log.add(NODES_CATEGORY, f"Started {kind} discovery of {target}")
    return {"id": job_id}


def get_nodes_discovery(service, params, body) -> dict:
    limit = int(_num(params, "limit", 50, int) or 50)
    return {"jobs": [_discovery_job_json(r) for r in service.nodes_db.discovery_jobs(limit)]}


def get_nodes_discovery_job(service, params, body, job_id) -> dict:
    job = service.nodes_db.discovery_job(job_id)
    if not job:
        raise ValueError("No such discovery job")
    results = service.nodes_db.discovery_results(job_id)
    installed = {mib["filename"] for mib in service.nodes_db.mib_files()}
    # One pass over the fleet rather than a device_by_ip() per row — a scan
    # of a /22 can carry over a thousand results.
    devices_by_ip = {d["ip"]: d for d in service.nodes_db.devices()}
    return {"job": _discovery_job_json(job),
            "results": [_discovery_result_json(r, installed, devices_by_ip)
                        for r in results]}


def delete_nodes_discovery_job(service, params, body, job_id) -> dict:
    """DELETE on a running scan cancels it (the row stays, so its partial
    results can still be reviewed); DELETE on any finished/cancelled/
    errored scan removes it — and its results — from the list for good."""
    if not service.nodes_db.discovery_job(job_id):
        raise ValueError("No such discovery job")
    if service.node_poller.discovery_running(job_id):
        service.node_poller.cancel_discovery(job_id)
        return {"ok": True, "cancelled": True}
    service.nodes_db.remove_discovery_job(job_id)
    return {"ok": True, "removed": True}


def post_nodes_discovery_promote(service, params, body, job_id) -> dict:
    if not service.nodes_db.discovery_job(job_id):
        raise ValueError("No such discovery job")
    result_ids = body.get("result_ids") or []
    if not result_ids:
        raise ValueError("result_ids is required")
    device_ids = service.node_poller.promote(job_id, [int(r) for r in result_ids])
    service.log.add(NODES_CATEGORY,
                    f"Promoted {len(device_ids)} device(s) from discovery job #{job_id}")
    return {"device_ids": device_ids}


def post_nodes_discovery_reviewed(service, params, body, job_id) -> dict:
    """The approve/deny dialog for this job was answered (or dismissed) —
    either way it must never pop again, whatever was or wasn't added."""
    if not service.nodes_db.discovery_job(job_id):
        raise ValueError("No such discovery job")
    service.nodes_db.mark_job_reviewed(job_id)
    return {"ok": True}


def post_nodes_collector(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.nodes_settings["enabled"] = True
        service.nodes_db.save_settings({"enabled": True})
        service.node_poller.start(service.nodes_settings)
    elif action == "stop":
        service.nodes_settings["enabled"] = False
        service.nodes_db.save_settings({"enabled": False})
        service.node_poller.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.node_poller.running,
            "status": service.node_poller.status_text()}


def _mib_file_json(row) -> dict:
    return {"id": row["id"], "filename": row["filename"], "module": row["module"],
            "uploaded_ts": row["uploaded_ts"], "object_count": row["object_count"],
            "unresolved": json.loads(row["unresolved"] or "[]"),
            "parse_notes": row["parse_notes"]}


def _mib_object_json(row) -> dict:
    return {"id": row["id"], "mib_file_id": row["mib_file_id"], "name": row["name"],
            "oid": row["oid"], "description": row["description"], "syntax": row["syntax"],
            "enums": json.loads(row["enums"]) if row["enums"] else None,
            "is_notification": bool(row["is_notification"]), "edited": bool(row["edited"])}


def _object_to_dict(obj) -> dict:
    return {"name": obj.name, "oid": obj.oid, "description": obj.description,
            "syntax": obj.syntax, "enums": obj.enums,
            "is_notification": obj.is_notification}


def _known_oids_for_resolve(service) -> dict:
    from .. import mibparse
    return mibparse.known_oids_for(service.nodes_db)


def get_nodes_mibs(service, params, body) -> dict:
    return {"files": [_mib_file_json(r) for r in service.nodes_db.mib_files()]}


def post_nodes_mib(service, params, body) -> dict:
    """Upload is base64-encoded text inside the normal JSON body rather
    than multipart/form-data — server.py's body parser only accepts
    application/json for POST/PUT/DELETE, and touching that gate for one
    route is a bigger change than the ~33% base64 overhead is worth for a
    file capped at a few MB (max_mib_bytes).

    A zip is accepted too, and is the point of the feature: a vendor ships
    its MIBs as one archive whose members import each other in no particular
    order, so the whole set is stored first and resolved to a fixpoint
    afterwards. That makes upload order irrelevant, which is the single thing
    that used to make importing a real vendor bundle painful."""
    import base64
    from .. import mibcatalog, mibparse

    filename = str(body.get("filename", "")).strip() or "uploaded.mib"
    content_b64 = body.get("content")
    if not content_b64:
        raise ValueError("content (base64-encoded MIB text) is required")
    try:
        raw = base64.b64decode(content_b64, validate=False)
    except Exception:
        raise ValueError("content is not valid base64")
    max_bytes = int(service.nodes_settings.get("max_mib_bytes",
                                                nodesdb.DEFAULTS["max_mib_bytes"]))

    if mibcatalog.looks_like_zip(raw):
        members = mibcatalog.unpack_zip(
            raw, int(service.nodes_settings.get("max_mib_zip_files", 400)),
            max_bytes,
            int(service.nodes_settings.get("max_mib_bundle_bytes",
                                           64 * 1024 * 1024)))
        existing = {row["filename"] for row in service.nodes_db.mib_files()}
        loaded, skipped = [], []
        for name, text in members:
            if name in existing:
                skipped.append(name)
                continue
            mibparse.load_into(service.nodes_db, name, text,
                               _known_oids_for_resolve(service), max_bytes)
            existing.add(name)
            loaded.append(name)
        summary = mibparse.resolve_all(service.nodes_db, max_bytes)
        service._snmp_settings_with_mibs()
        service.log.add(NODES_CATEGORY,
                        f"Imported {len(loaded)} MIB(s) from {filename} "
                        f"({len(skipped)} already present); "
                        f"{summary['resolved_count']}/{summary['object_count']} "
                        f"object(s) resolved overall")
        return {"zip": True, "loaded": loaded, "skipped": skipped,
                "object_count": summary["object_count"],
                "resolved_count": summary["resolved_count"],
                "passes": summary["passes"]}

    if len(raw) > max_bytes:
        raise ValueError(f"File exceeds the {max_bytes:,} byte limit")
    text = raw.decode("utf-8", "replace")

    result = mibparse.load_into(service.nodes_db, filename, text,
                                _known_oids_for_resolve(service), max_bytes)
    service._snmp_settings_with_mibs()
    service.log.add(NODES_CATEGORY,
                    f"Uploaded MIB {filename} ({result['module'] or 'unknown module'}): "
                    f"{result['resolved_count']}/{result['object_count']} object(s) resolved")
    return result


def post_nodes_mibs_resolve_all(service, params, body) -> dict:
    """Re-resolve every stored MIB against every other, to a fixpoint —
    the one button that fixes a list of files uploaded in the wrong order
    without an admin having to guess which one to press Resolve on."""
    from .. import mibparse

    max_bytes = int(service.nodes_settings.get("max_mib_bytes",
                                                nodesdb.DEFAULTS["max_mib_bytes"]))
    summary = mibparse.resolve_all(service.nodes_db, max_bytes)
    service._snmp_settings_with_mibs()
    service.log.add(NODES_CATEGORY,
                    f"Re-resolved all MIBs: {summary['resolved_count']}/"
                    f"{summary['object_count']} object(s) resolved across "
                    f"{summary['files']} file(s)")
    return summary


def get_nodes_mib_catalog(service, params, body) -> dict:
    """The static catalog plus which bundles are already fully present.

    Reading this never touches the network, so the list is browsable on a
    server with no outbound access — only installing reaches out."""
    from .. import mibcatalog

    have = {row["filename"] for row in service.nodes_db.mib_files()}
    bundles = []
    for bundle in mibcatalog.CATALOG:
        present = sum(1 for filename, _ in bundle.files if filename in have)
        bundles.append({
            "key": bundle.key, "vendor": bundle.vendor, "name": bundle.name,
            "description": bundle.description, "source": bundle.source,
            "file_count": bundle.file_count, "present": present,
            "installed": present == bundle.file_count,
            "files": [filename for filename, _ in bundle.files],
            "arcs": list(bundle.arcs), "vendor_key": bundle.vendor_key,
        })
    return {"bundles": bundles, "job": service.mib_install_status()}


def post_nodes_mib_catalog_install(service, params, body, key) -> dict:
    return {"job": service.install_mib_bundle(str(key))}


def get_nodes_mib_catalog_status(service, params, body) -> dict:
    return {"job": service.mib_install_status()}


def get_nodes_mib(service, params, body, mib_file_id) -> dict:
    row = service.nodes_db.mib_file(mib_file_id)
    if not row:
        raise ValueError("No such MIB file")
    objects = service.nodes_db.mib_objects(mib_file_id)
    return {"file": _mib_file_json(row),
            "objects": [_mib_object_json(r) for r in objects]}


def delete_nodes_mib(service, params, body, mib_file_id) -> dict:
    row = service.nodes_db.mib_file(mib_file_id)
    if not row:
        raise ValueError("No such MIB file")
    service.nodes_db.remove_mib_file(mib_file_id)
    service._snmp_settings_with_mibs()
    service.log.add(NODES_CATEGORY, f"Removed MIB {row['filename']}")
    return {"ok": True}


def post_nodes_mib_resolve(service, params, body, mib_file_id) -> dict:
    """Re-parses the file's own stored text from scratch (mib_objects only
    keeps the final oid or NULL, not the parent/last_arc an unresolved
    object needs to retry) and resolves again against everything
    currently known — this is the whole "upload CISCO-SMI after
    CISCO-PROCESS-MIB, then hit resolve" story."""
    from .. import mibparse

    row = service.nodes_db.mib_file(mib_file_id)
    if not row:
        raise ValueError("No such MIB file")
    if not row["content"]:
        raise ValueError("This file's original text was not retained "
                         "(uploaded before this feature could re-resolve) "
                         "— re-upload it to enable Resolve.")
    max_bytes = int(service.nodes_settings.get("max_mib_bytes",
                                                nodesdb.DEFAULTS["max_mib_bytes"]))
    result = mibparse.parse(row["content"], max_bytes=max_bytes)
    resolved_count, unresolved = mibparse.resolve(
        result.objects, _known_oids_for_resolve(service))

    service.nodes_db.update_mib_file(
        mib_file_id, module=result.module, object_count=len(result.objects),
        unresolved=unresolved, parse_notes="; ".join(result.notes))
    service.nodes_db.replace_mib_objects(
        mib_file_id, [_object_to_dict(obj) for obj in result.objects])
    service._snmp_settings_with_mibs()
    service.log.add(NODES_CATEGORY,
                    f"Re-resolved MIB {row['filename']}: "
                    f"{resolved_count}/{len(result.objects)} object(s) resolved")
    return {"object_count": len(result.objects), "resolved_count": resolved_count,
            "unresolved": unresolved}


def put_nodes_mib_object(service, params, body, mib_file_id, obj_id) -> dict:
    objects = {r["id"]: r for r in service.nodes_db.mib_objects(mib_file_id)}
    if obj_id not in objects:
        raise ValueError("No such MIB object")
    fields = {k: v for k, v in body.items()
             if k in ("name", "oid", "description", "syntax", "enums")}
    service.nodes_db.update_mib_object(obj_id, **fields)
    service._snmp_settings_with_mibs()
    return {"ok": True}


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
    """One alert row on the wire. `present_ids` is required, not optional: it
    is what decides whether device_id is reported at all, and a caller that
    forgot it used to get every alert silently reported as being about no
    device — the Mute control greyed out across the whole page for no visible
    reason. Build it with _alert_device_ids.

    No device_name: the page renders the entity_label the engine already put
    on the alert, and never read one."""
    from .. import alertmail

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
        # Keyed defensively for the same reason as rollup_note above.
        "for_seconds": (row["for_seconds"] if "for_seconds" in row.keys() else None),
        "template_id": row["template_id"], "created_ts": row["created_ts"],
        # Set by the rule editor since 4.37; keyed defensively like the rest.
        "auto_resolve_after_s": (row["auto_resolve_after_s"]
                                 if "auto_resolve_after_s" in row.keys() else None),
        "notify": (bool(row["notify"]) if "notify" in row.keys() else True),
    }


def _template_json(row, with_tokens: bool = False) -> dict:
    result = {
        "id": row["id"], "key": row["key"], "name": row["name"],
        "subject": row["subject"], "body": row["body"], "is_html": bool(row["is_html"]),
        "is_builtin": bool(row["is_builtin"]), "updated_ts": row["updated_ts"],
    }
    if with_tokens:
        from .. import alertmail
        result["tokens"] = alertmail.token_reference()
    return result


def get_alerts_overview(service, params, body) -> dict:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    bucket = _num(params, "bucket", 3600)
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": service.alerts_db.histogram(t0, t1, bucket),
        "summary": service.alerts_db.open_summary(),
        "engine": {
            "running": service.alert_engine.running,
            "status": service.alert_engine.status_text(),
            "counters": service.alert_engine.counters,
        },
    }


def _alert_filters(params) -> dict:
    severity = params.get("severity")
    rule_id = params.get("rule_id")
    return {
        "state": params.get("state") or None,
        "severity": int(severity) if severity else None,
        "rule_id": int(rule_id) if rule_id else None,
        "device_text": params.get("device") or None,
        "text": params.get("q") or None,
        "t0": _num(params, "t0", None),
        "t1": _num(params, "t1", None),
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


# Item 2: the campaign that measured alerts_truncated at fleet scale found
# an operator paging through an incident looking at a truncated view at
# exactly the moment completeness mattered — GET /api/alerts capped `limit`
# at 2,000 with no way to see the rest. ALERTS_LIST_CAP is unchanged (still
# the per-page ceiling a browser table should ever try to render); `offset`
# is what is new, so a page past the cap is one more request away instead
# of unreachable, and `total` says how many pages that is.
ALERTS_LIST_CAP = 2000


def get_alerts(service, params, body) -> dict:
    filters = _alert_filters(params)
    limit = min(int(_num(params, "limit", 300, int) or 300), ALERTS_LIST_CAP)
    offset = max(0, int(_num(params, "offset", 0, int) or 0))
    rows = service.alerts_db.alerts(limit=limit, offset=offset, **filters)
    total = service.alerts_db.count_alerts(**filters)
    return {"alerts": _alerts_rows_json(service, rows), "total": total,
            "limit": limit, "offset": offset}


# The export ceiling item 1 asked for explicitly: "alerts export must be
# able to exceed the old 2,000 cap". 50,000 is comfortably past anything a
# real incident produces (the alert engine already collapses repeats into
# one row's `count`, so 50,000 open rows is 50,000 distinct problems, not
# 50,000 flaps) while still bounding the one CSV this route will ever
# build in memory per request.
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
    row = service.alerts_db.alert(alert_id)
    if not row:
        raise ValueError("No such alert")
    alert = _alert_json(row, _alert_device_ids(service, [row]))
    rule = service.alerts_db.rule(row["rule_id"])
    alert["rule_name"] = rule["name"] if rule else ""
    notifications = service.alerts_db.notifications_for(alert_id)
    return {"alert": alert, "notifications": [
        {"id": n["id"], "kind": n["kind"], "ts": n["ts"], "to_addr": n["to_addr"],
         "subject": n["subject"], "ok": bool(n["ok"]), "error": n["error"]}
        for n in notifications]}


def post_alert_ack(service, params, body, alert_id) -> dict:
    if not service.alerts_db.alert(alert_id):
        raise ValueError("No such alert")
    service.alerts_db.acknowledge(alert_id, params.get("_username", ""),
                                  str(body.get("note", "")))
    _audit(service, params, "alert.ack", target=str(alert_id))
    return {"ok": True}


def post_alert_unack(service, params, body, alert_id) -> dict:
    if not service.alerts_db.alert(alert_id):
        raise ValueError("No such alert")
    service.alerts_db.unacknowledge(alert_id)
    _audit(service, params, "alert.unack", target=str(alert_id))
    return {"ok": True}


def post_alert_resolve(service, params, body, alert_id) -> dict:
    if not service.alerts_db.alert(alert_id):
        raise ValueError("No such alert")
    service.alerts_db.resolve(alert_id, params.get("_username", ""))
    _audit(service, params, "alert.resolve", target=str(alert_id))
    return {"ok": True}


def _mute_json(row) -> dict:
    return {"entity_kind": row["entity_kind"], "entity_id": row["entity_id"],
            "until_ts": row["until_ts"], "created_ts": row["created_ts"],
            "created_by": row["created_by"], "reason": row["reason"]}


def _mute_entity(body) -> tuple[str, str]:
    """The (kind, id) a mute request names, refusing anything the engine
    would not actually check — a mute that silences nothing is worse than
    an error, because the operator walks away believing it worked."""
    kind = str(body.get("entity_kind", "device")).strip() or "device"
    if kind != "device":
        # The column is general, so a per-interface or per-AP mute later
        # needs no migration; nothing else is muteable today.
        raise ValueError("Only devices can be muted")
    entity_id = str(body.get("entity_id", "")).strip()
    if not entity_id:
        raise ValueError("A device is required")
    return kind, entity_id


def get_alerts_mutes(service, params, body) -> dict:
    return {"mutes": [_mute_json(row) for row in service.alerts_db.mutes()]}


def post_alerts_mute(service, params, body) -> dict:
    kind, entity_id = _mute_entity(body)
    try:
        device = service.nodes_db.device(int(entity_id))
    except (TypeError, ValueError):
        device = None
    if device is None:
        raise ValueError("No such device")
    try:
        hours = float(body.get("hours", 1))
    except (TypeError, ValueError):
        raise ValueError("Mute duration must be a number of hours")
    if hours <= 0:
        raise ValueError("Mute duration must be more than zero")
    row = service.alerts_db.mute(kind, entity_id, hours,
                                 by=params.get("_username", ""),
                                 reason=str(body.get("reason", "")))
    _audit(service, params, "alert.mute", target=f"{kind}:{entity_id}",
           detail=f"{hours:g}h: {str(body.get('reason', ''))}")
    return {"mute": _mute_json(row)}


def delete_alerts_mute(service, params, body) -> dict:
    kind, entity_id = _mute_entity(body)
    lifted = service.alerts_db.unmute(kind, entity_id)
    _audit(service, params, "alert.unmute", target=f"{kind}:{entity_id}")
    return {"lifted": lifted}


def _bulk_mute_device_ids(service, body) -> list[str]:
    """Every device id a bulk-mute request names — an explicit list, a
    device group's whole current membership, or both together, refusing
    (like _mute_entity above) a request that would end up silencing
    nothing."""
    ids = {str(i) for i in (body.get("device_ids") or [])}
    group_id = body.get("group_id")
    if group_id:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            raise ValueError("group_id must be a number")
        ids |= {str(row["id"]) for row in
               service.nodes_db.devices(device_group_id=group_id)}
    if not ids:
        raise ValueError("device_ids and/or group_id is required, naming at "
                         "least one device")
    try:
        wanted = {int(i) for i in ids}
    except (TypeError, ValueError):
        raise ValueError("device_ids must be device ids")
    present = {row["id"] for row in service.nodes_db.devices_by_ids(wanted)}
    ids = [i for i in ids if int(i) in present]
    if not ids:
        raise ValueError("No such device(s)")
    return sorted(ids, key=int)


def post_alerts_bulk_mute(service, params, body) -> dict:
    """One call, many devices — the planned-cutover case the ad-hoc mute
    route makes hundreds of calls. Same ad-hoc cap (MAX_MUTE_HOURS) as a
    single mute; a longer silence is what a maintenance WINDOW is for."""
    entity_ids = _bulk_mute_device_ids(service, body)
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
            ids = body.get("scope_device_ids") or []
            try:
                wanted = {int(i) for i in ids}
            except (TypeError, ValueError):
                raise ValueError("scope_device_ids must be device ids")
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
    if not service.alerts_db.window(window_id):
        raise ValueError("No such maintenance window")
    fields = _window_body_fields(service, body)
    service.alerts_db.update_window(window_id, **fields)
    _audit(service, params, "alert.window_update", target=str(window_id))
    return {"window": _window_json(service.alerts_db.window(window_id))}


def delete_alerts_window(service, params, body, window_id) -> dict:
    removed = service.alerts_db.remove_window(window_id)
    _audit(service, params, "alert.window_delete", target=str(window_id))
    return {"removed": removed}


def post_alerts_window_end(service, params, body, window_id) -> dict:
    if not service.alerts_db.window(window_id):
        raise ValueError("No such maintenance window")
    changed = service.alerts_db.end_window_now(window_id)
    _audit(service, params, "alert.window_end", target=str(window_id))
    return {"window": _window_json(service.alerts_db.window(window_id)),
            "changed": changed}


def post_alerts_ack_all(service, params, body) -> dict:
    n = service.alerts_db.acknowledge_all(params.get("_username", ""))
    _audit(service, params, "alert.ack_all", detail=f"{n} alert(s)")
    return {"acknowledged": n}


def _bulk_alert_ids(body) -> list[int]:
    ids = body.get("alert_ids") or []
    if not ids:
        raise ValueError("alert_ids is required")
    return [int(i) for i in ids]


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


def post_alerts_rule(service, params, body) -> dict:
    key = str(body.get("key", "")).strip()
    name = str(body.get("name", "")).strip()
    kind = str(body.get("kind", "")).strip()
    source_kind = str(body.get("source_kind", "") or "")
    if not key or not name or not kind:
        raise ValueError("key, name and kind are all required")
    if kind not in ("device_event", "interface_event", "threshold",
                    "dhcp_threshold", "netpath_threshold", "trap", "syslog",
                    "ipam", "wireless_event", "system"):
        raise ValueError("Unrecognized rule kind")
    if service.alerts_db.rule_by_key(key):
        raise ValueError(f"A rule with key '{key}' already exists")
    fields = {k: v for k, v in body.items() if k in
             ("severity", "enabled", "device_filter", "threshold",
              "clear_threshold", "for_polls", "for_seconds", "template_id",
              "auto_resolve_after_s", "notify")}
    rule_id = service.alerts_db.add_rule(key, name, kind, source_kind, **fields)
    service.log.add(ALERTS_CATEGORY, f"Added alert rule {name}")
    return {"id": rule_id}


def put_alerts_rule(service, params, body, rule_id) -> dict:
    row = service.alerts_db.rule(rule_id)
    if not row:
        raise ValueError("No such rule")
    allowed_keys = ("name", "severity", "enabled", "device_filter", "threshold",
                    "clear_threshold", "for_polls", "for_seconds", "template_id",
                    "flap_window_s", "flap_min_transitions",
                    "auto_resolve_after_s", "notify")
    if not row["is_builtin"]:
        allowed_keys = allowed_keys + ("kind", "source_kind")
    fields = {k: v for k, v in body.items() if k in allowed_keys}
    service.alerts_db.update_rule(rule_id, **fields)
    return {"ok": True}


def delete_alerts_rule(service, params, body, rule_id) -> dict:
    row = service.alerts_db.rule(rule_id)
    if not row:
        raise ValueError("No such rule")
    if row["is_builtin"]:
        raise ValueError("A built-in rule cannot be deleted — disable it instead")
    service.alerts_db.remove_rule(rule_id)
    service.log.add(ALERTS_CATEGORY, f"Removed alert rule {row['name']}")
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
    if not service.alerts_db.template(template_id):
        raise ValueError("No such template")
    fields = {k: v for k, v in body.items()
             if k in ("name", "subject", "body", "is_html")}
    service.alerts_db.update_template(template_id, **fields)
    return {"ok": True}


def post_alerts_template_reset(service, params, body, template_id) -> dict:
    row = service.alerts_db.template(template_id)
    if not row:
        raise ValueError("No such template")
    if not row["is_builtin"]:
        raise ValueError("Only a built-in template has shipped text to reset to")
    service.alerts_db.reset_template(template_id)
    return {"ok": True}


def delete_alerts_template(service, params, body, template_id) -> dict:
    row = service.alerts_db.template(template_id)
    if not row:
        raise ValueError("No such template")
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
    alert of that kind has ever fired. Sends nothing."""
    from .. import alertmail

    row = service.alerts_db.template(template_id)
    if not row:
        raise ValueError("No such template")
    alert_id = body.get("alert_id")
    if alert_id:
        alert_row = service.alerts_db.alert(int(alert_id))
        if not alert_row:
            raise ValueError("No such alert")
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
                  "varbinds": "(sample)"})
    return {"subject": alertmail.render(row["subject"], context),
            "body": alertmail.render(row["body"], context)}


def post_alerts_smtp_credential(service, params, body) -> dict:
    from .. import dpapi

    password = str(body.get("password", ""))
    if not password:
        raise ValueError("A password is required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. A test email can still use a password typed "
            "into Test each time; nothing will be saved here.")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.alerts_db.set_smtp_credential(encrypted)
    service.log.add(ALERTS_CATEGORY, "Stored the SMTP credential")
    _audit(service, params, "credential.store", target="smtp")
    return {"ok": True}


def delete_alerts_smtp_credential(service, params, body) -> dict:
    service.alerts_db.clear_smtp_credential()
    service.log.add(ALERTS_CATEGORY, "Cleared the stored SMTP credential")
    _audit(service, params, "credential.clear", target="smtp")
    return {"ok": True}


# The body fields that decide WHERE the test email goes and how the
# connection to it is protected. Overriding any of them and letting the
# stored password be used is how a stored SMTP credential was made to walk
# out to any host and port on the network (`AUTH PLAIN` in the clear, to a
# listener of the caller's choosing). Testing an unsaved host is still
# allowed — with the password for that host typed in beside it.
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
    from .. import alertmail, dpapi

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
    subject = "SappiWhere test email"
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
    from ..fortinetoids import MAX_PLAUSIBLE_DBM

    configured = str(service.wireless_settings.get("radio_power_unit", "auto"))
    if configured in ("dbm", "percent"):
        return configured
    return "percent" if any(p > MAX_PLAUSIBLE_DBM for p in powers) else "dbm"


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
    return {
        "id": row["id"], "controller_id": row["controller_id"],
        "wtp_id": row["wtp_id"], "vdom": row["vdom"], "name": row["name"],
        "status": row["status"], "model": row["model"],
        "mac_address": row["mac_address"], "station_count": row["station_count"],
        # The AP's own address as the controller reports it, and the
        # round-trip to it. None where it was not measured — an AP that does
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
    overrides = {k: v for k, v in body.items() if k in _CONTROLLER_EDITABLE_BODY
                and k not in ("name", "ip", "enabled")}
    controller_id = service.wireless_db.add_controller(name, ip, **overrides)
    service.log.add(WIRELESS_CATEGORY, f"Added wireless controller {name} ({ip})")
    return {"id": controller_id}


def put_wireless_controller(service, params, body, controller_id) -> dict:
    existing = service.wireless_db.controller(controller_id)
    if not existing:
        raise ValueError("No such controller")
    fields = {k: v for k, v in body.items() if k in _CONTROLLER_EDITABLE_BODY}
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
    row = service.wireless_db.controller(controller_id)
    if not row:
        raise ValueError("No such controller")
    service.wireless_db.remove_controller(controller_id)
    service.log.add(WIRELESS_CATEGORY, f"Removed wireless controller {row['name']}")
    return {"ok": True}


def post_wireless_controller_credential(service, params, body, controller_id) -> dict:
    from .. import dpapi

    row = service.wireless_db.controller(controller_id)
    if not row:
        raise ValueError("No such controller")
    user = str(body.get("v3_user", "")).strip()
    password = str(body.get("v3_auth_pass", ""))
    auth_proto = str(body.get("v3_auth_proto", "")).strip()
    if not user or not password or not auth_proto:
        raise ValueError("A username, auth protocol, and password are all required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. Use a v1/v2c community, or SNMPv3 "
            "noAuthNoPriv, instead.")
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.wireless_db.update_controller(controller_id, v3_user=user, v3_auth_proto=auth_proto)
    service.wireless_db.set_credential(controller_id, encrypted)
    service.log.add(WIRELESS_CATEGORY, f"Stored an SNMPv3 credential for {row['name']}")
    _audit(service, params, "credential.store",
           target=f"controller:{row['ip']}", detail=f"SNMPv3 user {user}")
    return {"ok": True}


def delete_wireless_controller_credential(service, params, body, controller_id) -> dict:
    row = service.wireless_db.controller(controller_id)
    if not row:
        raise ValueError("No such controller")
    service.wireless_db.set_credential(controller_id, None)
    service.log.add(WIRELESS_CATEGORY, f"Cleared the stored SNMPv3 credential for {row['name']}")
    _audit(service, params, "credential.clear", target=f"controller:{row['ip']}")
    return {"ok": True}


def post_wireless_controller_poll(service, params, body, controller_id) -> dict:
    if not service.wireless_db.controller(controller_id):
        raise ValueError("No such controller")
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
    ap = service.wireless_db.access_point(int(ap_id))
    if ap is None:
        raise ValueError("No such access point")
    service.wireless_db.set_out_of_service(int(ap_id), bool(body.get("out_of_service")))
    return {"ok": True, "out_of_service": bool(body.get("out_of_service"))}


def delete_wireless_ap(service, params, body, ap_id) -> dict:
    """Removes one AP row by hand. Needed because an out-of-service AP is
    deliberately exempt from prune_stale — without this there would be no
    way to retire one permanently once the controller stops reporting it."""
    ap = service.wireless_db.access_point(int(ap_id))
    if ap is None:
        raise ValueError("No such access point")
    service.wireless_db.remove_ap(int(ap_id))
    return {"ok": True}


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
    """Start or stop the IPAM worker from its strip. Goes through
    apply_ipam_settings so the choice persists exactly as the checkbox in
    the settings dialog does — the only control there used to be."""
    action = str(body.get("action", "")).lower()
    if action not in ("start", "stop"):
        raise ValueError("action must be start or stop")
    service.apply_ipam_settings({"enabled": action == "start"})
    return {"running": service.ipam.running,
            "enabled": bool(service.ipam_settings.get("enabled", True))}


# ----------------------------------------------------------------- configrx

def _configrx_device_json(service, device_row, worker_state=None) -> dict:
    config = service.configrx_db.device_config(device_row["id"])
    # Whether a backup is in flight for this device right now — the same join
    # the Nodes list does with node_poller.worker_state(). Without it the row
    # sat on the last COMPLETED attempt for the whole duration of a run, so a
    # backup taking a minute looked like nothing was happening.
    state = (worker_state or {}).get(device_row["id"])
    # Same precedence as nodes.js's displayName(): the SNMP-reported
    # hostname wins unless the device is explicitly pinned to its manual
    # name, with the IP as the last resort. ConfigRX has no display of its
    # own to compute this in, so it's done once here rather than trusting
    # device_row["name"] (the manual name) outright.
    name = ((device_row["name"] if device_row["display_name_source"] == "manual" else None)
           or device_row["sys_name"] or device_row["name"] or device_row["ip"])
    override = (config["vendor_override"] if config else "") or ""
    return {
        "id": device_row["id"], "ip": device_row["ip"],
        "name": name,
        "vendor": device_row["vendor"],
        # The vendor this device would ACTUALLY back up as, resolved the same
        # way configrx._backup_device resolves it: the explicit override, then
        # what SNMP detected (not the displayed vendor, which a custom vendor
        # OID may have replaced with a free-text name). The list used to show
        # Nodes' vendor verbatim while the worker used something else, so a
        # device could read "cisco" and back up as "hp" with no sign of it.
        "effective_vendor": override or nodesdb.detected_vendor(device_row) or "",
        "vendor_is_override": bool(override),
        "backup_enabled": bool(config["backup_enabled"]) if config else False,
        # Whether this device's captures are stored verbatim rather than
        # redacted (configrx_redact.py). Off unless somebody turned it on.
        "store_secrets": bool(config["store_secrets"]) if (
            config and "store_secrets" in config.keys()) else False,
        "ssh_port": config["ssh_port"] if config else 22,
        "ssh_username": (config["ssh_username"] if config else "") or "",
        # Same has_credential convention as every other stored password in
        # this app — the encrypted blob itself never reaches the browser.
        "has_credential": bool(config["ssh_password_enc"]) if config else False,
        # Same convention again, for the separate enable secret a vendor like
        # cisco-asa needs to reach privileged EXEC (see _do_enable).
        "has_enable_secret": bool(config["enable_secret_enc"]) if config else False,
        "vendor_override": (config["vendor_override"] if config else "") or "",
        "last_backup_ts": config["last_backup_ts"] if config else None,
        "last_backup_status": config["last_backup_status"] if config else None,
        "last_backup_error": config["last_backup_error"] if config else None,
        "backing_up": bool(state and state.get("started")),
        "backup_queued": bool(state and not state.get("started")),
    }


def _configrx_backup_json(row) -> dict:
    keys = row.keys()
    return {"id": row["id"], "device_id": row["device_id"], "ts": row["ts"],
            "sha256": row["sha256"], "size_bytes": row["size_bytes"],
            # So the UI can say whether what it is about to show has had
            # its secrets taken out. Keyed defensively for a row handed in
            # from an older-shaped source, as the device rows are.
            "redacted": bool(row["redacted"]) if "redacted" in keys else False}


def delete_configrx_backup(service, params, body, backup_id) -> dict:
    row = service.configrx_db.backup(backup_id)
    if row is None:
        raise ValueError("No such backup")
    removed = service.configrx_db.delete_backup(backup_id)
    if removed:
        service.log.add(CONFIGRX_CATEGORY,
                        f"Deleted a stored config backup for device {row['device_id']}")
    return {"ok": True, "removed": 1 if removed else 0}


def post_configrx_backups_bulk_delete(service, params, body) -> dict:
    ids = body.get("backup_ids") or []
    if not ids:
        raise ValueError("backup_ids is required")
    removed = service.configrx_db.delete_backups([int(i) for i in ids])
    service.log.add(CONFIGRX_CATEGORY, f"Deleted {removed} stored config backup(s)")
    return {"ok": True, "removed": removed}


def get_configrx_overview(service, params, body) -> dict:
    configs = service.configrx_db.all_device_configs()
    enabled = sum(1 for c in configs if c["backup_enabled"])
    errors = sum(1 for c in configs
                if c["backup_enabled"] and c["last_backup_status"] == "error")
    return {
        "worker": {
            "running": service.configrx.running,
            "status": service.configrx.status_text(),
            "counters": service.configrx.counters,
        },
        "devices_configured": len(configs),
        "devices_enabled": enabled,
        "devices_with_errors": errors,
    }


def get_configrx_devices(service, params, body) -> dict:
    """The device list is Nodes' own — ConfigRX has no device table of its
    own, per the product decision to reuse it wholesale rather than keep
    a second, parallel list in sync."""
    text = params.get("q") or None
    rows = service.nodes_db.devices(text=text)
    worker_state = service.configrx.worker_state()
    devices = [_configrx_device_json(service, r, worker_state) for r in rows]
    if params.get("enabled_only") is not None:
        devices = [d for d in devices if d["backup_enabled"]]
    # Filtered on the effective vendor, so picking "cisco" gives the devices
    # that will actually run Cisco's show-config command — including any
    # steered there by a per-device override.
    vendor = (params.get("vendor") or "").strip()
    if vendor:
        devices = [d for d in devices
                   if (d["effective_vendor"] or "(none)") == vendor]
    return {"devices": devices}


def get_configrx_device(service, params, body, device_id) -> dict:
    device = service.nodes_db.device(device_id)
    if not device:
        raise ValueError("No such device")
    return {"device": _configrx_device_json(
        service, device, service.configrx.worker_state())}


def post_configrx_device_config(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    fields = {k: v for k, v in body.items()
             if k in ("backup_enabled", "ssh_port", "ssh_username",
                      "vendor_override", "store_secrets")}
    if "ssh_port" in fields:
        try:
            port = int(fields["ssh_port"])
        except (TypeError, ValueError):
            raise ValueError("The SSH port must be a number from 1 to 65535.") from None
        if not 1 <= port <= 65535:
            raise ValueError("The SSH port must be a number from 1 to 65535.")
        fields["ssh_port"] = port
    if "store_secrets" in fields:
        fields["store_secrets"] = 1 if fields["store_secrets"] else 0
        _audit(service, params,
               "configrx.store_secrets", target=str(device_id),
               detail="on — captures will be stored verbatim"
                      if fields["store_secrets"] else "off")
    service.configrx_db.update_device_config(device_id, **fields)
    return {"ok": True}


def post_configrx_devices_bulk_config(service, params, body) -> dict:
    """Same 'one shared value for every selected device' semantics as
    Nodes' own bulk-update — a batch of switches sharing one local SSH
    account is the common case this exists for, not a per-row grid edit."""
    device_ids = _bulk_device_ids(body)
    # ssh_username belongs here as much as the other three: the database
    # layer has always allowed it (DEVICE_CONFIG_EDITABLE), and only this
    # allow-list withheld it, which meant a bulk settings dialog could set
    # everything about a batch of switches except who to log in as.
    fields = {k: v for k, v in body.items()
             if k in ("backup_enabled", "ssh_port", "vendor_override",
                      "ssh_username")}
    if not fields:
        raise ValueError("Nothing to update")
    existing = {d["id"] for d in service.nodes_db.devices_by_ids(device_ids)}
    updated = []
    for device_id in device_ids:
        if device_id in existing:
            service.configrx_db.update_device_config(device_id, **fields)
            updated.append(device_id)
    service.log.add(CONFIGRX_CATEGORY,
                    f"Bulk-updated {len(updated)} device(s): {', '.join(fields)}")
    return {"ok": True, "updated": len(updated), "device_ids": updated}


def post_configrx_devices_bulk_backup(service, params, body) -> dict:
    """Back up every ticked device now.

    Id lists back, not counts, mirroring post_nodes_devices_bulk_poll: an
    operator who ticked twelve switches and got "9 queued" still has to work
    out which three did not. The extra bucket Nodes has no counterpart to is
    `not_enabled` — a device with backups switched off is deliberately
    skipped rather than quietly backed up anyway.

    The worker being stopped fails the whole request ONCE, with the reason,
    rather than raising the same message per device: it is one fact about
    the server, not twelve facts about twelve switches.
    """
    device_ids = _bulk_device_ids(body)
    # One query for the whole selection rather than device() per id, the
    # same shape post_nodes_devices_bulk_poll uses.
    existing = {d["id"] for d in service.nodes_db.devices_by_ids(device_ids)}
    queued, busy, missing, not_enabled = [], [], [], []
    for device_id in device_ids:
        if device_id not in existing:
            missing.append(device_id)
            continue
        config = service.configrx_db.device_config(device_id)
        if not (config and config["backup_enabled"]):
            not_enabled.append(device_id)
            continue
        try:
            (queued if service.configrx.backup_now(device_id) else busy).append(device_id)
        except configrx.ConfigRxWorker.NotRunning as exc:
            raise ValueError(str(exc))
    if queued:
        service.log.add(CONFIGRX_CATEGORY,
                        f"Backup now requested for {len(queued)} device(s)")
    return {"ok": True, "queued": queued, "already_queued": busy,
            "missing": missing, "not_enabled": not_enabled}


def post_configrx_devices_bulk_credential(service, params, body) -> dict:
    from .. import dpapi

    device_ids = _bulk_device_ids(body)
    username = str(body.get("ssh_username", "")).strip()
    password = str(body.get("ssh_password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only, so ConfigRX refuses to store an SSH password "
            "here rather than keep it in plain text.")
    try:
        # Encrypted once, not once per device: it is the same plaintext
        # going to every selected device, so there is no reason to pay for
        # (or add a second window of exposure from) a repeated DPAPI call.
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    updated = 0
    for device_id in device_ids:
        if service.nodes_db.device(device_id):
            service.configrx_db.set_credential(device_id, username, encrypted)
            updated += 1
    service.log.add(CONFIGRX_CATEGORY, f"Bulk-stored an SSH credential for {updated} device(s)")
    _audit(service, params, "credential.store", target="configrx:bulk",
           detail=f"{updated} device(s), username {username}")
    return {"ok": True, "updated": updated}


def post_configrx_device_credential(service, params, body, device_id) -> dict:
    from .. import dpapi

    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    username = str(body.get("ssh_username", "")).strip()
    password = str(body.get("ssh_password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    if not dpapi.available():
        raise ValueError(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only, so ConfigRX refuses to store an SSH password "
            "here rather than keep it in plain text.")
    # The enable secret is separate and optional, with set_credential's own
    # three-way contract: the key absent from the body leaves whatever is
    # already stored untouched, present-and-empty clears it, present-and-
    # non-empty (re)encrypts and stores it. Needed only by a vendor whose
    # login shell is not already privileged EXEC (currently just cisco-asa).
    enable_kwargs = {}
    if "enable_secret" in body:
        enable_secret = str(body.get("enable_secret") or "")
        enable_kwargs["enable_secret_enc"] = (
            dpapi.protect(enable_secret.encode("utf-8")) if enable_secret else None)
        enable_secret = None
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.configrx_db.set_credential(device_id, username, encrypted, **enable_kwargs)
    service.log.add(CONFIGRX_CATEGORY, f"Stored an SSH credential for {row['ip']}")
    _audit(service, params, "credential.store", target=f"configrx:{row['ip']}",
           detail=f"username {username}")
    return {"ok": True}


def delete_configrx_device_credential(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    service.configrx_db.clear_credential(device_id)
    service.log.add(CONFIGRX_CATEGORY, f"Cleared the stored SSH credential for {row['ip']}")
    _audit(service, params, "credential.clear", target=f"configrx:{row['ip']}")
    return {"ok": True}


def get_configrx_device_backups(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    # No "changed since previous" flag to compute here: ConfigRxDatabase.
    # add_backup only ever inserts a row when the hash differs from the
    # device's prior backup, so every stored row already IS a change —
    # an unchanged poll updates last_backup_ts/status and stores nothing.
    rows = service.configrx_db.backups_for(device_id)
    return {"backups": [_configrx_backup_json(r) for r in rows]}


def get_configrx_backup(service, params, body, backup_id) -> dict:
    """Reading a stored config is a read — the route this backs is gated
    ConfigRX read, not write, so a viewer's click on a backup answers "has
    this switch changed" instead of 403ing. A verbatim backup (captured
    with store_secrets on) is the one case that still needs guarding: a
    caller without ConfigRX write gets it through the same redaction pass
    get_configrx_diff always applies, never the stored secrets themselves."""
    row = service.configrx_db.backup(backup_id)
    if not row:
        raise ValueError("No such backup")
    content = service.configrx_db.backup_content(backup_id)
    backup_json = _configrx_backup_json(row)
    if not backup_json["redacted"] and not _may_read_secrets(service, params, "configrx"):
        content, _ = configrx_redact.redact(content or "")
        backup_json["redacted"] = True
    return {"backup": backup_json, "content": content}


def _configrx_backup_label(row) -> str:
    return f"backup #{row['id']} ({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row['ts']))})"


def get_configrx_diff(service, params, body) -> dict:
    """A unified diff between two of one device's stored backups — Tier 2:
    the hashes that would detect the change are already stored, this is
    the view that reads them. Gated exactly like get_configrx_backup
    (the single-backup CONTENT route) rather than the metadata list: a
    diff hands over the device's own configuration lines just as reading
    one backup does, so it costs the same permission.

    `from`/`to` name backup ids explicitly; omit both for the adjacent
    pair — the two most recent stored backups, ordered newest as `to` —
    which is the one-click "what changed last time" case the frontend's
    Diff button uses by default.

    Redaction is applied a SECOND time here, unconditionally, regardless
    of what each row's own `redacted` flag already says. A backup captured
    with "keep secrets in backups" (store_secrets) switched on is stored
    verbatim on purpose — that setting exists so the row can serve as an
    actual restore file — but a diff is a comparison view, not a download
    of that file, and nothing here may hand an unredacted secret to a diff
    reader even when the device's own setting would let the single-backup
    view do exactly that. Because configrx_redact.redact() maps every
    secret it recognises onto the identical literal "<redacted>" token, a
    secret that merely changed value reads as no line at all in the
    hunks — the directive is present on both sides and nothing about its
    own text differs — which is the honest answer for "did the password
    change": this diff can say a secret-bearing line is still there, not
    what it became. See configrx_redact's module docstring for the pattern
    list's own scope and limits.
    """
    device_id = _num(params, "device", None, int)
    if not device_id or not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    backups = service.configrx_db.backups_for(device_id)
    if len(backups) < 2:
        raise ValueError("At least two stored backups are needed to diff")
    from_param = _num(params, "from", None, int)
    to_param = _num(params, "to", None, int)
    if from_param is None and to_param is None:
        # backups_for is already newest-first: the adjacent pair is simply
        # its first two rows, older explaining what changed into newer.
        to_row, from_row = backups[0], backups[1]
    else:
        by_id = {b["id"]: b for b in backups}
        from_row = by_id.get(int(from_param)) if from_param is not None else None
        to_row = by_id.get(int(to_param)) if to_param is not None else None
        if not from_row or not to_row:
            raise ValueError("Both backups must belong to this device")

    from_json, to_json = _configrx_backup_json(from_row), _configrx_backup_json(to_row)
    # Fast path (TESTS: "same-hash pair returns empty diff fast-path"): two
    # rows with the same content hash cannot diff to anything, whether that
    # is one backup picked for both ends or two distinct rows that happen
    # to match (a config reverted to something backed up before). Skipping
    # redact()+unified_diff here is not just an optimisation — it also means
    # picking the same backup twice never runs a diff over its own secrets.
    if from_row["id"] == to_row["id"] or from_row["sha256"] == to_row["sha256"]:
        return {"diff": "", "additions": 0, "removals": 0,
                "from": from_json, "to": to_json, "identical": True}

    from_content = service.configrx_db.backup_content(from_row["id"]) or ""
    to_content = service.configrx_db.backup_content(to_row["id"]) or ""
    from_redacted, _ = configrx_redact.redact(from_content)
    to_redacted, _ = configrx_redact.redact(to_content)
    text, additions, removals = configrx.diff_texts(
        from_redacted, to_redacted,
        _configrx_backup_label(from_row), _configrx_backup_label(to_row))
    return {"diff": text, "additions": additions, "removals": removals,
            "from": from_json, "to": to_json, "identical": not text}


def post_configrx_device_backup(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    config = service.configrx_db.device_config(device_id)
    if not config or not config["backup_enabled"]:
        raise ValueError("Backup is not enabled for this device")
    try:
        queued = service.configrx.backup_now(device_id)
    except configrx.ConfigRxWorker.NotRunning as exc:
        raise ValueError(str(exc))
    return {"ok": True, "queued": queued}


def post_configrx_worker(service, params, body) -> dict:
    action = str(body.get("action", "")).lower()
    if action == "start":
        service.configrx_settings["enabled"] = True
        service.configrx_db.save_settings({"enabled": True})
        service.configrx.start(service.configrx_settings)
    elif action == "stop":
        service.configrx_settings["enabled"] = False
        service.configrx_db.save_settings({"enabled": False})
        service.configrx.stop()
    # `enabled` is served from /api/config, which the browser refetches only
    # when config_version moves: without this bump the settings dialog kept
    # showing the collector as running after the strip had stopped it.
    service.bump_config()
    return {"running": service.configrx.running,
            "status": service.configrx.status_text()}


# ------------------------------------------------------------- ssh host keys
# The remembered host key for a device, and forgetting it. Both live under
# /api/ssh/ rather than /api/configrx/ because the key is shared: the SSH
# terminal stores and checks the same row. Reading one is a ConfigRX read (it
# is shown in ConfigRX's device dialog); forgetting one is an `ssh` WRITE,
# because it is the act that lets the next connection to that device accept
# whatever key it is offered.
#
# There is no HTTP route for trusting a NEW key: that decision is only ever
# taken with the offered key in hand, over the terminal's own socket, so
# there is no endpoint here through which a key could be trusted blind.

def _ssh_device_host(service, device_id):
    """(device row, ip, port) for a device, or ValueError. The port is
    ConfigRX's stored SSH port, since that is the port this app connects on
    and the store is keyed by (host, port)."""
    device = service.nodes_db.device(device_id)
    if not device:
        raise ValueError("No such device")
    config = service.configrx_db.device_config(device_id)
    port = int(config["ssh_port"]) if config and config["ssh_port"] else 22
    return device, device["ip"], port


def _host_key_json(row) -> dict:
    return {
        "host": row["host"], "port": row["port"], "key_type": row["key_type"],
        "fingerprint": row["fingerprint"], "first_seen_ts": row["first_seen_ts"],
        "last_seen_ts": row["last_seen_ts"], "trusted_by": row["trusted_by"] or "",
    }


def get_ssh_device_hostkey(service, params, body, device_id) -> dict:
    _device, host, port = _ssh_device_host(service, device_id)
    row = service.configrx_db.host_key(host, port)
    return {"host_key": _host_key_json(row) if row else None}


def delete_ssh_device_hostkey(service, params, body, device_id) -> dict:
    _device, host, port = _ssh_device_host(service, device_id)
    removed = service.configrx_db.forget_host_key(host, port)
    if removed:
        service.log.add(CONFIGRX_CATEGORY,
                        f"Forgot the stored SSH host key for {host}",
                        detail=f"The next connection to {host} port {port} will store"
                               f" whatever key it is offered.")
    return {"ok": True, "removed": 1 if removed else 0}


# --------------------------------------------------------------------- auth

def _client(params) -> str:
    return params.get("_client", "")


# At most this many password verifications at once. Each one is a scrypt
# at N=2^17 — about 128 MiB and half a second — on an endpoint that needs
# no session, so unbounded concurrency was both a memory DoS (30 parallel
# attempts is ~4 GB) and the reason the throttle's sleep did not bite: the
# server is threaded, so twelve simultaneous guesses each slept five
# seconds in parallel and the effective rate was one attempt per 0.9 s
# rather than one per five.
_LOGIN_SLOTS = threading.Semaphore(4)

_dummy_hash_value: str | None = None
_dummy_hash_lock = threading.Lock()


def _dummy_hash() -> str:
    """A real hash of a random string, built with the parameters in force
    now.

    The point of hashing when the account does not exist is that the time
    taken says nothing about whether it does. The hardcoded string this
    replaces named N=2^14 while stored hashes use 2^17, so a missing
    account answered about nine times faster — measured 0.055 s against
    0.48 s — and the endpoint was a username oracle. Derived from
    hash_password so it cannot drift from the real cost again, including
    onto the PBKDF2 fallback where scrypt is unavailable.
    """
    global _dummy_hash_value
    with _dummy_hash_lock:
        if _dummy_hash_value is None:
            from ..auth import hash_password
            _dummy_hash_value = hash_password(secrets.token_urlsafe(32))
        return _dummy_hash_value


def post_login(service, params, body) -> dict:
    """Verify a password. Deliberately slow to fail, and vague about why."""
    from ..auth import (AuthError, LockedOut, check_username, needs_rehash,
                        hash_password, verify_password)
    from .service import LdapUnavailable

    password = str(body.get("password", ""))
    client = _client(params)

    # Validated before it is used as a throttle key or written anywhere.
    # An unvalidated name reached both: a 200 KB username produced a 200 KB
    # event, which is a cheap way to push every other event out of the
    # 3,000-entry ring. Every name that is not a username shares one key
    # and one log line, so trying millions of them costs one entry.
    try:
        username = check_username(str(body.get("username", "")))
    except AuthError:
        username = ""
    label = username or "(not a username)"

    # Checked before the semaphore and before any hashing: a locked-out
    # caller must not be able to hold a verification slot or spend a
    # half-second of scrypt.
    remaining = service.throttle.lockout_remaining(username, client)
    if remaining > 0:
        service.log.add(ERROR_CATEGORY,
                        f"Refused sign-in for {label} from {client}: too many "
                        f"failures, locked for another {remaining / 60:.0f} min")
        _audit(service, dict(params, _username=label), "signin.locked_out",
               target=label, detail=f"locked for another {remaining:.0f}s")
        raise LockedOut(f"Too many failed sign-ins. Try again in "
                        f"{max(1, round(remaining / 60))} minute(s).")

    with _LOGIN_SLOTS:
        delay = service.throttle.delay_for(username, client)
        if delay:
            time.sleep(min(delay, 5))

        row = service.app_db.user(username) if username else None
        stored = row["password"] if row else None

        # Hash something even when the account does not exist, so the time
        # taken cannot be used to discover which usernames are real. This
        # only distinguishes "no such account" from "an account exists" —
        # it says nothing about whether that account is local or LDAP, so
        # it stays exactly as it was for both kinds of account.
        if stored is None:
            verify_password(password, _dummy_hash())
            service.throttle.record_failure(username, client)
            service.log.add(ERROR_CATEGORY,
                            f"Failed sign-in for {label} from {client}")
            _audit(service, dict(params, _username=label), "signin.failed",
                   target=label, detail="no such account")
            raise PermissionError("Wrong username or password")

        auth_source = row["auth_source"]

        if auth_source == "ldap":
            # An LDAP-mapped account (Tier 1 #10): the directory verifies
            # the password, not the (empty, never-consulted) local hash. If
            # the feature is switched off this account simply cannot sign
            # in — it never falls back to checking an empty local hash,
            # which verify_password already refuses outright regardless
            # (see its own `if not stored` guard), but failing here first
            # gives a clearer audit trail than "wrong password" would.
            if not service.settings.get("ldap_enabled"):
                service.throttle.record_failure(username, client)
                service.log.add(
                    ERROR_CATEGORY,
                    f"Failed sign-in for {row['username']} from {client}: "
                    f"directory sign-in is switched off")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="ldap disabled")
                raise PermissionError("Wrong username or password")
            try:
                bound = service.authenticate_ldap(row["username"], password)
            except LdapUnavailable as exc:
                # Fails closed, and says so honestly rather than as a 500:
                # this is the one login outcome that is not about the
                # credential at all, so it gets its own message and its own
                # audit action rather than being folded into signin.failed.
                service.log.add(
                    ERROR_CATEGORY,
                    f"LDAP directory unreachable while signing in "
                    f"{row['username']} from {client}: {exc}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.ldap_unreachable", target=row["username"],
                       detail=str(exc)[:200])
                raise PermissionError(
                    "Could not reach the directory service. Try again "
                    "shortly, or contact an administrator.") from exc
            if not bound:
                service.throttle.record_failure(username, client)
                service.log.add(ERROR_CATEGORY,
                                f"Failed sign-in for {row['username']} from {client}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="ldap bind refused")
                raise PermissionError("Wrong username or password")
        elif not verify_password(password, stored):
            service.throttle.record_failure(username, client)
            service.log.add(ERROR_CATEGORY,
                            f"Failed sign-in for {row['username']} from {client}")
            _audit(service, dict(params, _username=row["username"]),
                   "signin.failed", target=row["username"],
                   detail="wrong password")
            raise PermissionError("Wrong username or password")

    service.throttle.clear(username)
    service.app_db.touch_login(row["username"])

    # Upgrade the stored hash quietly, now that we hold the password. Local
    # accounts only: an LDAP account's stored hash is the empty string it
    # was created with and is never meant to become anything else —
    # needs_rehash("") would otherwise say True (an unrecognised scheme
    # "needs" upgrading) and this would happily hash the directory
    # password into a local hash nothing ever checks.
    if auth_source == "local" and needs_rehash(stored):
        service.app_db.set_password(row["username"], hash_password(password),
                                must_change=bool(row["must_change"]))

    # The real User-Agent header, not a body field. The session list claims
    # to show what signed in; it used to show whatever the caller put in a
    # body key called "_agent", markup and all.
    token = service.sessions.create(row["username"], client,
                                    str(params.get("_agent", "")))
    service.log.add(SYSTEM_CATEGORY, f"{row['username']} signed in from {client}")
    _audit(service, dict(params, _username=row["username"]), "signin.ok",
           target=row["username"], detail=str(params.get("_agent", ""))[:120])
    return {"token": token, "username": row["username"],
            "must_change": bool(row["must_change"])}


def post_logout(service, params, body) -> dict:
    token = params.get("_token", "")
    session = service.sessions.get(token)
    if session:
        service.log.add(SYSTEM_CATEGORY, f"{session['username']} signed out")
        _audit(service, dict(params, _username=session["username"]),
               "signout", target=session["username"])
    service.sessions.destroy(token)
    return {"ok": True}


def post_heartbeat(service, params, body) -> dict:
    """Confirms a person is present, or — in kiosk mode — that a wall
    display is allowed to stay signed in without one.

    server.py touches the session for every other POST before dispatch; this
    route is the one exception, so that the kiosk case can be REFUSED without
    extending anything. The rule: a heartbeat carrying ``{"kiosk": true}``
    is honoured only for an account with no write grant on any module. A
    read-only wall account stays signed in until the absolute ceiling
    (session_max_hours); an administrator who adds ?kiosk=1 keeps the idle
    sign-out, and the reply says so in words the kiosk bar shows. Enforced
    here rather than in the browser because the idle policy is a security
    control, and a client-side exception to a security control is not one.
    """
    kiosk = bool(isinstance(body, dict) and body.get("kiosk"))
    minutes = service.sessions.idle_seconds // 60
    if kiosk:
        granted = service.app_db.permissions_for(params.get("_username", ""))
        if any(_permissions.allows(level, _permissions.WRITE) for level in granted.values()):
            return {"ok": False, "kiosk": False, "idle_timeout_minutes": minutes,
                    "reason": "Kiosk mode keeps only a read-only account signed in; "
                              "this account can write, so the idle sign-out applies."}
    service.sessions.touch(params.get("_token", ""))
    return {"ok": True, "kiosk": kiosk, "idle_timeout_minutes": minutes}


def _first_run(service) -> bool:
    """Whether this is a fresh install nobody has signed in to yet.

    The seeded admin/admin account exists, is the only account, still owes
    its password change and has never signed in. The sign-in page says so,
    because a first-run administrator otherwise faces a blank form with no
    hint that a default account exists at all. It is deliberately not a
    password check — that would be a full scrypt on every unauthenticated
    request — and it goes false the moment anyone signs in."""
    from ..auth import DEFAULT_USER
    if service.app_db.user_count() != 1:
        return False
    row = service.app_db.user(DEFAULT_USER)
    return bool(row is not None and row["must_change"] and row["last_login"] is None)


def get_session(service, params, body) -> dict:
    # The version goes to the sign-in page as well as to a signed-in one: it
    # is the first thing asked for when someone reports a problem, and the
    # page that shows it to an operator who cannot get in yet is the page
    # they are looking at. It is not a secret — the login page is served
    # before any session exists, and so is every asset the version is
    # stamped on.
    from .. import __version__
    session = service.sessions.get(params.get("_token", ""))
    if not session:
        return {"authenticated": False, "first_run": _first_run(service),
                "version": __version__}
    row = service.app_db.user(session["username"])
    idle_remaining = service.sessions.idle_seconds - (time.time() - session["last_seen"])
    return {
        "authenticated": True,
        "username": session["username"],
        "version": __version__,
        "must_change": bool(row["must_change"]) if row else False,
        "idle_timeout_minutes": service.sessions.idle_seconds // 60,
        "idle_seconds_remaining": max(0, round(idle_remaining)),
    }


def get_users(service, params, body) -> dict:
    return {
        "users": [
            {"username": row["username"], "created": row["created_ts"],
             "updated": row["updated_ts"], "last_login": row["last_login"],
             "must_change": bool(row["must_change"]),
             "auth_source": row["auth_source"],
             "permissions": service.app_db.permissions_for(row["username"])}
            for row in service.app_db.users()
        ],
        "sessions": service.sessions.active(),
        "modules": list(_permissions.MODULES),
    }


def post_user(service, params, body) -> dict:
    from ..auth import AuthError, check_password_quality, check_username, hash_password

    try:
        username = check_username(str(body.get("username", "")))
    except AuthError as exc:
        raise ValueError(str(exc)) from exc

    auth_source = str(body.get("auth_source", "local") or "local").strip().lower()
    if auth_source not in ("local", "ldap"):
        raise ValueError("auth_source must be 'local' or 'ldap'")

    if service.app_db.user(username):
        raise ValueError(f"There is already an account called {username}")

    if auth_source == "ldap":
        # No local password hash is stored at all — the directory is the
        # only place this account's credential lives (post_login's ldap
        # branch never consults it), so there is nothing here for a
        # database compromise to steal for this account. must_change is
        # meaningless without a local password to change, so it starts
        # False rather than locking the account behind a change it has no
        # route to make (post_password refuses a password change for an
        # ldap account outright — see there).
        service.app_db.add_user(username, "", must_change=False, auth_source="ldap")
    else:
        password = str(body.get("password", ""))
        try:
            check_password_quality(password, username)
        except AuthError as exc:
            raise ValueError(str(exc)) from exc
        service.app_db.add_user(username, hash_password(password), must_change=True,
                                auth_source="local")

    grants = body.get("grants") or {}
    if grants:
        service.app_db.set_permissions(username, grants)
    service.bump_config()
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {username} ({auth_source}) created by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "user.create", target=username,
           detail=f"auth_source={auth_source}; " +
                  (", ".join(f"{m}:{lvl}" for m, lvl in sorted(grants.items()))
                   or "no grants"))
    return {"username": username, "auth_source": auth_source}


def _last_admin_guard(service, target: str, keeps_admin: bool) -> None:
    """Refuse a change that would leave the install with no LOCAL
    administrator.

    Deleting the last *account* was already refused; losing the last
    administrator is the same trap by a different route — an install with
    no admin has no way back into its own user management short of editing
    app.db by hand. Extended for LDAP accounts (Tier 1 #10): an
    administrator that exists only in the directory is no fallback at all
    if the directory is down or unreachable, so at least one *local*
    admin:write account must always remain — an ldap admin does not count
    toward keeping this guard satisfied, only toward the plain "some admin
    exists" check `usernames_with` would otherwise imply.
    """
    if keeps_admin:
        return
    admins = service.app_db.usernames_with("admin", _permissions.WRITE)

    def is_local(name: str) -> bool:
        row = service.app_db.user(name)
        return row is not None and row["auth_source"] == "local"

    others_local = [name for name in admins
                    if name.lower() != target.lower() and is_local(name)]
    if others_local:
        return
    if any(name.lower() == target.lower() for name in admins):
        raise ValueError(
            f"Removing administrator access from {target} would leave no "
            f"local administrator account — if the directory becomes "
            f"unreachable there would be no way back into user management "
            f"at all. Give another local account administrator access "
            f"first.")


def post_user_permissions(service, params, body) -> dict:
    username = str(body.get("username", "")).strip()
    if not username:
        raise ValueError("Which account?")
    if not service.app_db.user(username):
        raise ValueError(f"No account called {username}")
    me = params.get("_username", "")
    # Nobody edits their own grants. An administrator who wants a different
    # set asks another administrator for it, which is what makes the grid a
    # record of a decision rather than of a self-service action — and it
    # closes the "grant yourself every module" step the review found.
    if username.lower() == me.lower():
        raise ValueError(
            "You cannot change your own permissions. Ask another "
            "administrator to make the change.")
    grants = body.get("grants") or {}
    _last_admin_guard(service, username,
                      grants.get("admin") == _permissions.WRITE)
    service.app_db.set_permissions(username, grants)
    service.bump_config()
    service.log.add(SYSTEM_CATEGORY,
                    f"Permissions for {username} changed by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "user.permissions", target=username,
           detail=", ".join(f"{m}:{lvl}" for m, lvl in sorted(grants.items()))
                  or "no grants")
    return {"username": username, "permissions": service.app_db.permissions_for(username)}


def delete_user(service, params, body, username: str = "") -> dict:
    # The client sends it in the body; the query string is a convenience for
    # anyone driving the API by hand.
    target = str(body.get("username", "") or params.get("username", "")
                 or username).strip()
    me = params.get("_username", "")
    if not target:
        raise ValueError("Which account?")

    if target.lower() == me.lower():
        raise ValueError("You cannot delete the account you are signed in with")
    if not service.app_db.user(target):
        raise ValueError(f"No account called {target}")
    if service.app_db.user_count() <= 1:
        raise ValueError("That is the only account; there would be no way back in")
    _last_admin_guard(service, target, keeps_admin=False)

    service.app_db.remove_user(target)

    service.bump_config()
    ended = service.sessions.destroy_user(target)
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {target} removed by {me}; {ended} session(s) ended")
    _audit(service, params, "user.delete", target=target,
           detail=f"{ended} session(s) ended")
    return {"removed": target}


def post_password(service, params, body) -> dict:
    """Change a password: your own with the current one, or anyone's as a reset."""
    from ..auth import (AuthError, check_password_quality, hash_password,
                        verify_password)

    me = params.get("_username", "")
    target = str(body.get("username", "") or me)
    new = str(body.get("new_password", ""))
    resetting = target.lower() != me.lower()

    row = service.app_db.user(target)
    if not row:
        raise ValueError(f"No account called {target}")

    if row["auth_source"] == "ldap":
        # There is no local password for this account at all — post_login's
        # ldap branch never looks at `row["password"]` (kept as "" since
        # creation), so setting one here would do nothing but sit unused
        # and misleadingly suggest a local fallback exists when it does
        # not. The directory is the only place this account's password is
        # ever changed.
        raise ValueError(
            f"{target} signs in through the directory (LDAP); there is no "
            f"local password to change here.")

    if not resetting:
        # Changing your own password needs the current one, so a walk-up at an
        # unlocked screen cannot lock the real owner out.
        if not verify_password(str(body.get("current_password", "")), row["password"]):
            raise PermissionError("That is not the current password")

    try:
        check_password_quality(new, target)
    except AuthError as exc:
        raise ValueError(str(exc)) from exc

    if verify_password(new, row["password"]):
        raise ValueError("That is already the password")

    service.app_db.set_password(target, hash_password(new), must_change=resetting)
    ended = service.sessions.destroy_user(target)
    service.log.add(SYSTEM_CATEGORY,
                    f"Password for {target} changed by {me}; "
                    f"{ended} session(s) ended")
    _audit(service, params, "password.reset" if resetting else "password.change",
           target=target, detail=f"{ended} session(s) ended")
    return {"username": target, "sessions_ended": ended, "reset": resetting}


# ------------------------------------------------------------- API tokens
#
# A token (Tier 1 #10) belongs to an account and carries exactly that
# account's grants — there is no separate permission model to keep in sync
# with permissions.py, and nothing about how a request is authorized
# changes once it is past authentication (see server.py's Bearer handling).
# All three routes are administrator-only, the same gate account creation,
# deletion and permission changes already sit behind, rather than
# self-service for one's own account: a token is a durable, unattended
# credential with no idle timeout, and deciding that one should exist for a
# given account is exactly the kind of decision this application already
# treats as an administrative act rather than something any signed-in
# account does to itself — the same reasoning post_user_permissions'
# "nobody edits their own grants" already rests on. An account cannot even
# see its own permission grid change without another administrator's
# say-so; it should not be able to hand itself a credential that outlives
# every session outright, either.

def get_tokens(service, params, body) -> dict:
    """Metadata for every token — never the token itself, which existed
    only in the response that created it. `username` names the account
    whose grants the token authenticates with; a caller wanting "my
    account's tokens" filters this client-side, the same way the accounts
    grid itself is one list rather than one route per account."""
    return {
        "tokens": [
            {"id": row["id"], "username": row["username"], "label": row["label"],
             "created": row["created_ts"], "created_by": row["created_by"],
             "expires": row["expires_ts"], "last_used": row["last_used_ts"]}
            for row in service.app_db.api_tokens()
        ],
    }


def post_token(service, params, body) -> dict:
    """Issue a token for an existing account. The plaintext token is
    returned in THIS response only — never again, anywhere, including this
    same account's own future GET /api/tokens — because only its SHA-256 is
    kept (see auth.hash_api_token)."""
    from .. import auth

    username = str(body.get("username", "")).strip()
    if not username:
        raise ValueError("Which account is this token for?")
    if not service.app_db.user(username):
        raise ValueError(f"No account called {username}")

    label = str(body.get("label", "")).strip()
    if not label:
        raise ValueError("Give this token a label — what it is for, or what "
                         "will use it — so it can be told apart on the list "
                         "and in the audit log later.")
    if len(label) > 120:
        raise ValueError("That label is too long (120 characters max)")

    expires_ts = None
    expires_days = body.get("expires_days")
    if expires_days not in (None, "", 0):
        try:
            days = float(expires_days)
        except (TypeError, ValueError):
            raise ValueError("expires_days must be a number")
        if days <= 0:
            raise ValueError("expires_days must be positive, or omitted for no expiry")
        expires_ts = time.time() + days * 86400

    raw_token = auth.generate_api_token()
    token_id = service.app_db.add_api_token(
        username, label, auth.hash_api_token(raw_token),
        created_by=params.get("_username", ""), expires_ts=expires_ts)

    service.log.add(SYSTEM_CATEGORY,
                    f"API token '{label}' issued for {username} by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "token.issue", target=username,
           detail=f"id={token_id}; label={label}"
                  + (f"; expires in {expires_days}d" if expires_ts else "; no expiry"))
    # `token` appears in exactly one response body, ever — this one. Every
    # other route that touches tokens (get_tokens, the audit log, the event
    # log line above) carries only what post_token returns besides it.
    return {"id": token_id, "token": raw_token, "username": username,
            "label": label, "expires": expires_ts}


def delete_token(service, params, body) -> dict:
    """Revoke a token by id, immediately: the row is removed outright, so
    the very next request it would have authenticated is refused like any
    other unrecognised credential — there is no grace period and nothing
    left for a compromised token to still do."""
    token_id = body.get("id")
    try:
        token_id = int(token_id)
    except (TypeError, ValueError):
        raise ValueError("id must be a token id")

    row = service.app_db.revoke_api_token(token_id)
    if row is None:
        raise ValueError(f"No token with id {token_id}")

    service.log.add(SYSTEM_CATEGORY,
                    f"API token '{row['label']}' for {row['username']} "
                    f"revoked by {params.get('_username', 'someone')}")
    _audit(service, params, "token.revoke", target=row["username"],
           detail=f"id={token_id}; label={row['label']}")
    return {"revoked": token_id}


# ---------------------------------------------------------------- LDAP test
#
# A dry-run bind, so an administrator configuring the directory finds out
# whether ldap_url/ldap_bind_dn_template/ldap_allow_cleartext actually work
# before flipping ldap_enabled on for a real account — the same "test
# before you trust it" shape post_alerts_smtp_test and post_snmp_test
# already give their own modules. Never creates a session and never
# consults or changes any stored account; it is purely a bind attempt
# against either the saved settings or the overrides in the body, so the
# settings dialog can be tested before Apply is even pressed.

def post_ldap_test(service, params, body) -> dict:
    from .. import ldapclient

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password:
        raise ValueError("A username and password are needed to test a bind")

    url = str(body.get("url", "") or service.settings.get("ldap_url", ""))
    template = str(body.get("bind_dn_template", "")
                   or service.settings.get("ldap_bind_dn_template", ""))
    allow_cleartext = bool(body.get("allow_cleartext",
                                    service.settings.get("ldap_allow_cleartext", False)))
    timeout = float(service.settings.get("ldap_timeout_s", 10.0) or 10.0)

    try:
        dn = ldapclient.render_bind_dn(template, username)
        ldapclient.simple_bind(url, dn, password, timeout=timeout,
                               allow_cleartext=allow_cleartext)
        ok, message = True, f"Bind succeeded as {dn}"
    except ldapclient.LDAPInvalidCredentials:
        ok, message = False, "The directory rejected that username or password"
    except ldapclient.LDAPReferralError:
        ok, message = False, ("The directory returned a referral, which this "
                              "minimal client cannot follow")
    except ldapclient.LDAPBindError as exc:
        ok, message = False, str(exc)
    except (ldapclient.LDAPConnectError, ldapclient.LDAPProtocolError,
            ldapclient.LDAPConfigError) as exc:
        ok, message = False, str(exc)

    # No password, either way — only whether the test was run and against
    # what result.
    _audit(service, params, "ldap.test", target=username,
           detail=f"ok={ok}: {message}"[:400])
    return {"ok": ok, "message": message}


# ---------------------------------------------------------------------------
# Everything below this line is the browser front end's own additions
# (workstream E). They are appended rather than filed beside their relatives
# so the front-end work and the module work never touch the same hunk.
# ---------------------------------------------------------------------------


# `GET /api/alerts` caps its answer (300 by default, 2,000 hard) and the list
# said "300 shown" with no total, so an operator ticking select-all
# acknowledged 300 of however many there really were. This gives the same
# filters an honest denominator.
#
# alerts.db has no filtered COUNT of its own, and alertsdb.py belongs to
# another workstream, so the count is taken by asking for ids up to a cap and
# saying so when the cap is what answered: "300 of 5,000+ shown" is honest,
# "300 shown" was not. If a `count_alerts` ever lands on the database object
# this uses it instead, and the cap stops applying.
ALERT_TOTAL_CAP = 5000


def get_alerts_total(service, params, body) -> dict:
    """How many alerts match the filters the list is showing."""
    filters = _alert_filters(params)
    counter = getattr(service.alerts_db, "count_alerts", None)
    if callable(counter):
        return {"total": int(counter(**filters)), "capped": False,
                "cap": None}
    rows = service.alerts_db.alerts(limit=ALERT_TOTAL_CAP + 1, **filters)
    total = len(rows)
    capped = total > ALERT_TOTAL_CAP
    return {"total": ALERT_TOTAL_CAP if capped else total,
            "capped": capped, "cap": ALERT_TOTAL_CAP}


# Six features across four tabs store a secret, and every one of them goes
# through Windows DPAPI: on Linux the credential fields render in full, the
# operator types a password, and the save comes back 400. IPAM's DHCP form is
# the worst of it — it renders completely, with Windows-only help text, on a
# host where `ipam_dhcp.IS_WINDOWS` is False and nothing can ever work.
#
# This says so once, up front, so the front end can gate a form instead of
# letting somebody fill it in and be refused. It is deliberately a route of
# its own rather than another key on /api/state: the answer cannot change
# while the process is running, so it is fetched once at start-up and never
# polled. Nothing here is a secret — it is which of this host's features can
# work at all — so read on any module is enough.
def get_platform(service, params, body) -> dict:
    """What this host can and cannot do, for the forms that depend on it."""
    from .. import dpapi
    from .. import ipam_dhcp

    powershell = False
    if ipam_dhcp.IS_WINDOWS:
        try:
            ipam_dhcp._powershell_binary()
            powershell = True
        except Exception:                                     # noqa: BLE001
            powershell = False

    return {
        "platform": {
            "is_windows": bool(dpapi.IS_WINDOWS),
            "powershell": powershell,
            # dpapi.available() is the same call every credential route
            # already makes before it accepts a POST: true unconditionally
            # on Windows, true off Windows once secretstore.configured() has
            # a passphrase (NETPATH_SECRET_PASSPHRASE_FILE or
            # NETPATH_SECRET_PASSPHRASE — see CREDENTIAL-SECURITY.md §10).
            # This used to be hard-coded False here, which is the "gap this
            # workstream did not close" that document called out by name:
            # a configured Linux host accepted a credential posted to the
            # API directly while its own browser form stayed greyed out.
            "secret_store": bool(dpapi.available()),
            "credential_store": ("Windows DPAPI" if dpapi.IS_WINDOWS
                                 else ("Portable secret store" if dpapi.available()
                                       else None)),
        },
    }


# --------------------------------------------------------------- dashboard
#
# The Dashboard was a 385-byte placeholder and `login.js` makes it the
# landing page after every sign-in, so the screen every shift starts on said
# "nothing here yet". These two endpoints answer the questions a tile grid
# asks; everything else the grid needs is already on /api/state, which every
# tab polls anyway.
#
# Permission-gated the way get_state is: never refused outright (the tab is
# always reachable), but a section the signed-in account cannot read is
# absent rather than empty, so the front end can leave the tile out instead
# of drawing a zero that is not true.

# The metric keys the "worst" lists are built from. Named here rather than in
# the front end because they are the poller's vocabulary (nodepoll.py:1281,
# :1284 and nodeoids.py's per-vendor tables), not the browser's.
DASHBOARD_METRICS = (
    ("rtt", "ping_rtt_ms", "Slowest to answer", "ms", False),
    ("loss", "ping_loss_pct", "Worst packet loss", "%", False),
    ("cpu", "cpu_pct", "Highest CPU", "%", False),
)

DASHBOARD_OFFENDER_N = 10


def _dash_can(service, params, module: str) -> bool:
    granted = service.app_db.permissions_for(params.get("_username", ""))
    return _permissions.allows(granted.get(module), _permissions.READ)


def get_dashboard(service, params, body) -> dict:
    """The cross-module numbers the tile grid shows, in one round trip."""
    result: dict = {}

    if _dash_can(service, params, "nodes"):
        poller = service.node_poller
        # pool_state() separates busy from queued; the old gauge added them
        # together against the pool size and read "48 of 32 busy".
        pool = poller.pool_state() if hasattr(poller, "pool_state") else {}
        result["fleet"] = {
            "counts": service.nodes_db.device_counts(),
            "running": poller.running,
            "pool": pool,
        }

    if _dash_can(service, params, "alerts"):
        summary = service.alerts_db.open_summary()
        # One severity-1 outage must never be hidden behind forty severity-6
        # notices, so the tile is coloured by the worst open severity and
        # broken down by severity rather than shown as one total. There is no
        # per-severity COUNT on alerts.db and alertsdb.py belongs to another
        # workstream, so the breakdown is counted from the open rows up to a
        # bound and says when the bound is what answered.
        by_severity: dict[str, int] = {}
        rows = service.alerts_db.alerts(state="unresolved",
                                        limit=ALERT_TOTAL_CAP + 1)
        for row in rows[:ALERT_TOTAL_CAP]:
            key = str(row["severity"])
            by_severity[key] = by_severity.get(key, 0) + 1
        result["alerts"] = {
            "open": summary.get("open", 0),
            "acked": summary.get("acked", 0),
            "worst": summary.get("worst"),
            "by_severity": by_severity,
            "counted_capped": len(rows) > ALERT_TOTAL_CAP,
            "engine_running": service.alert_engine.running,
            "counters": service.alert_engine.counters,
        }

    # Every background process, each by the noun its own tab uses for it.
    # This tile used to list three of the eight and call them all
    # "collectors".
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
        # Headroom, not raw sizes: "which database is closest to its cap" is
        # the question, and it is answered worst-first.
        settings = service.settings or {}
        stores = []
        # Only the seven databases that actually have a cap on the Settings
        # tab; app.db, wireless.db and configrx.db have none, so they are
        # reported as size without a fraction rather than as 0% used.
        for label, db, cap_key in (
                ("NetPath", service.db, "max_trace_db_mb"),
                ("NetFlow", service.flow_db, "max_flow_db_mb"),
                ("Syslog", service.syslog_db, "max_syslog_db_mb"),
                ("Traps", service.snmp_db, "max_snmp_db_mb"),
                ("IPAM", service.ipam_db, "max_ipam_db_mb"),
                ("Nodes", service.nodes_db, "max_nodes_db_mb"),
                ("Alerts", service.alerts_db, "max_alerts_db_mb"),
                ("Wireless", service.wireless_db, None),
                ("ConfigRX", service.configrx_db, None),
                ("Application", service.app_db, None)):
            try:
                used = int(db.size_bytes())
            except Exception:                                 # noqa: BLE001
                continue
            cap_mb = settings.get(cap_key) if cap_key else None
            cap = int(cap_mb) * 1024 * 1024 if cap_mb else None
            stores.append({
                "label": label, "bytes": used, "cap_bytes": cap,
                "used_fraction": (used / cap) if cap else None,
            })
        stores.sort(key=lambda s: (s["used_fraction"] is None,
                                   -(s["used_fraction"] or 0)))
        result["storage"] = stores

    return {"dashboard": result}


def get_dashboard_offenders(service, params, body) -> dict:
    """Six short "worst ten" lists, each row linking to its device.

    One query per list rather than one per device: `count_events_by_device`
    and `top_metric` exist for exactly this.
    """
    if not _dash_can(service, params, "nodes"):
        raise PermissionError("Reading devices is not permitted")

    window_s = _num(params, "window_s", 86400.0) or 86400.0
    since = time.time() - float(window_s)
    n = int(_num(params, "n", DASHBOARD_OFFENDER_N, int) or DASHBOARD_OFFENDER_N)
    n = max(1, min(n, 50))

    def _rows(rows, value_key, unit):
        out = []
        for row in rows[:n]:
            out.append({"device_id": row["device_id"],
                        "name": row["name"] or row["ip"],
                        "ip": row["ip"],
                        "value": row[value_key],
                        "unit": unit})
        return out

    lists = []
    events = service.nodes_db.count_events_by_device(since)
    lists.append({"key": "events", "title": "Most device events (24 h)",
                  "unit": "", "rows": _rows(events, "n", "")})

    # Interface flaps are device events too, and they are the ones an
    # operator chases; kept as their own list rather than folded into the
    # count above, which would hide a flapping port behind a noisy device.
    flaps = service.nodes_db.count_events_by_device(
        since, kinds=["interface_down", "interface_up", "interface_flapping"])
    lists.append({"key": "interface_events", "title": "Most interface events (24 h)",
                  "unit": "", "rows": _rows(flaps, "n", "")})

    if _dash_can(service, params, "alerts"):
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
        lists.append({"key": "alerts", "title": "Most alerts (24 h)",
                      "unit": "", "rows": ranked})

    for key, metric, title, unit, ascending in DASHBOARD_METRICS:
        rows = service.nodes_db.top_metric(metric, n, ascending=ascending)
        lists.append({"key": key, "title": title, "unit": unit,
                      "rows": _rows(rows, "last_value", unit)})

    return {"window_s": window_s, "lists": lists}


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Two fields the database and the write paths already carry but the existing
# serializers do not return yet, so a form has no way to show what is
# currently set. `_device_json` and `_rule_json` live in modules another
# workstream owns; rather than reach into them, these two small routes hand
# the front end the missing values, and both disappear the moment the
# serializers carry them (the front end merges whatever it is given).


def get_nodes_device_upstream(service, params, body, device_id) -> dict:
    """The device this one hangs off, and the devices it could hang off.

    `PUT /api/nodes/devices/<id>` has accepted `upstream_id` since the
    topology rollup landed — an outage on a core switch raises one alert
    instead of five hundred — but nothing in the UI could set it, and
    `_device_json` does not return it, so a form had nothing to show.
    """
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    keys = row.keys()
    upstream = row["upstream_id"] if "upstream_id" in keys else None
    # Everything except this device: the server refuses self and unknown ids
    # anyway (_clean_upstream_id), and offering them would only produce an
    # error the operator could have been spared.
    candidates = [
        {"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"]}
        for d in service.nodes_db.devices()
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
        }
    return {"rules": extras}

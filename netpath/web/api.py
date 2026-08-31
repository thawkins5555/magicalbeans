"""JSON endpoints.

Each handler takes the service, the parsed query string and the decoded body,
and returns something json-serialisable. The HTTP plumbing is in server.py so
this file stays about the data.
"""

from __future__ import annotations

import ipaddress
import json
import math
import time

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
from .. import permissions as _permissions

MIN_BLOCK_PX = 3


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
_STATE_MODULE_KEYS = {
    "netflow": ("flow_settings", "dimensions", "collector"),
    "syslog": ("syslog_settings", "syslog"),
    "snmp": ("snmp_settings", "trap_kinds", "snmp"),
    "ipam": ("ipam_settings", "ipam"),
    "nodes": ("nodes_settings", "nodes"),
    "alerts": ("alerts_settings", "alerts"),
    "wireless": ("wireless_settings", "wireless"),
    "configrx": ("configrx_settings", "configrx"),
    "settings": ("storage",),
}


def get_state(service, params, body) -> dict:
    from .. import __version__
    from ..selfupdate import INSTALLED_AT_KEY, INSTALLED_COMMIT_KEY

    names = service.hostname_stats()
    session = service.sessions.get(params.get("_token", ""))
    idle_remaining = (service.sessions.idle_seconds - (time.time() - session["last_seen"])
                      if session else None)
    granted = service.app_db.permissions_for(params.get("_username", ""))
    result = {
        "version": __version__,
        "permissions": granted,
        "update": {
            "installed_commit": service.app_db.meta(INSTALLED_COMMIT_KEY),
            "installed_at": service.app_db.meta(INSTALLED_AT_KEY),
        },
        "session": {
            "username": session["username"] if session else "",
            "must_change": bool(
                (service.app_db.user(session["username"]) or {})["must_change"])
            if session and service.app_db.user(session["username"]) else False,
            "idle_timeout_minutes": service.sessions.idle_seconds // 60,
            "idle_seconds_remaining":
                max(0, round(idle_remaining)) if idle_remaining is not None else None,
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
            "open_conflicts": len(service.ipam_db.conflicts()),
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
        },
        "wireless": {
            "running": service.wireless.running,
            "status": service.wireless.status_text(),
            "counters": service.wireless.counters,
            "ap_counts": service.wireless_db.ap_counts(),
            "controller_count": len(service.wireless_db.controllers()),
        },
        "configrx": {
            "running": service.configrx.running,
            "status": service.configrx.status_text(),
            "counters": service.configrx.counters,
        },
        "storage": {
            "app_path": service.app_db.path,
            "trace_path": service.db.path,
            "flow_path": service.flow_db.path,
            "syslog_path": service.syslog_db.path,
            "snmp_path": service.snmp_db.path,
            "ipam_path": service.ipam_db.path,
            "nodes_path": service.nodes_db.path,
            "alerts_path": service.alerts_db.path,
            "wireless_path": service.wireless_db.path,
            "configrx_path": service.configrx_db.path,
            "app_bytes": service.app_db.size_bytes(),
            "trace_bytes": service.db.size_bytes(),
            "flow_bytes": service.flow_db.size_bytes(),
            "syslog_bytes": service.syslog_db.size_bytes(),
            "snmp_bytes": service.snmp_db.size_bytes(),
            "ipam_bytes": service.ipam_db.size_bytes(),
            "nodes_bytes": service.nodes_db.size_bytes(),
            "alerts_bytes": service.alerts_db.size_bytes(),
            "wireless_bytes": service.wireless_db.size_bytes(),
            "configrx_bytes": service.configrx_db.size_bytes(),
        },
    }
    for module, keys in _STATE_MODULE_KEYS.items():
        if not _permissions.allows(granted.get(module), _permissions.READ):
            for key in keys:
                result.pop(key, None)
    if not _permissions.allows(granted.get("settings"), _permissions.READ):
        # "settings" itself stays present even without Settings access —
        # every module's own refresh cadence (nodes_refresh_s and so on)
        # and cross-cutting config (DNS/ASN) live in it, and every tab
        # needs to read those regardless of its own module's grant. Only
        # the web-listener detail (bind address, port, and — in
        # particular — the TLS cert/key file paths) is Settings-specific
        # server internals with no reason to reach a user without
        # Settings access, so it alone is stripped out here rather than
        # the whole key.
        result["settings"] = {k: v for k, v in result["settings"].items()
                              if k not in ("web_host", "web_port", "web_cert", "web_key")}
    return result


# ------------------------------------------------------------------ netpath

def _target_json(service, row) -> dict:
    last = service.db.last_trace(row["id"])
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
    return {"targets": [_target_json(service, row) for row in service.db.targets()]}


def post_target(service, params, body) -> dict:
    defaults = service.settings
    host = str(body.get("host", "")).strip()
    if not host:
        raise ValueError("A destination host or address is required")
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


def _topology_json(service, topo, refusal, target_id: int | None = None) -> dict:
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
        })
    edges = [
        {"src": f"{e.src[0]}|{e.src[1] or ''}",
         "dst": f"{e.dst[0]}|{e.dst[1] or ''}",
         "share": topo.share(e.traces)}
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
        asn_data = service.app_db.asn_info(ips)
        topo = build_topology(rows, dest_ip=service.db.destination_ip(target_id),
                              hostnames=names, asn_data=asn_data)
        keys = trace.keys()
        code = trace["icmp_code"] if "icmp_code" in keys else None
        payload = _topology_json(service, topo, (code, trace["icmp_from"]
                                                 if "icmp_from" in keys else None),
                                 target_id)
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
    asn_data = service.app_db.asn_info(ips)
    topo = build_topology(rows, dest_ip=service.db.destination_ip(target_id),
                          hostnames=names, asn_data=asn_data)

    code = address = None
    for trace in reversed(service.db.traces_between(target_id, t0, t1)):
        keys = trace.keys()
        if "icmp_code" in keys and trace["icmp_code"]:
            code, address = trace["icmp_code"], trace["icmp_from"]
            break
    payload = _topology_json(service, topo, (code, address), target_id)
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

    times, series, bucket_s = service.flow_db.series(
        t0, t1, dimension, filters, bucket, limit=8)
    top_rows = service.flow_db.top(t0, t1, dimension, filters, top_n)
    totals = service.flow_db.totals(t0, t1, filters)

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


def get_flow_records(service, params, body) -> dict:
    t0, t1 = _window(params)
    filters = _flow_filters(params)
    order = params.get("order", "bytes")
    rows = service.flow_db.flows(t0, t1, filters, limit=250, order=order)

    resolve_ports = bool(service.flow_settings.get("resolve_ports", True))
    names = {}
    if service.flow_settings.get("resolve_addresses"):
        addresses = {r["src_ip"] for r in rows} | {r["dst_ip"] for r in rows}
        names = {ip: name for ip, name
                 in service.app_db.hostnames(addresses).items() if name}
    interfaces = service.flow_db.interface_names()
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
        })
    return {"records": records}


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


# -------------------------------------------------------------------- debug

def get_debug(service, params, body) -> dict:
    since = int(_num(params, "since", 0, int) or 0)
    state = service.monitor.worker_state()
    schedule = service.monitor.next_runs()
    now = time.time()

    workers = []
    running = queued = 0
    for target in service.db.targets():
        last = service.db.last_trace(target["id"])
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

    events = [
        {"seq": e.seq, "ts": e.ts, "clock": e.clock, "category": e.category,
         "target": e.target, "message": e.message, "detail": e.detail}
        for e in service.log.since(since)
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
        subnets_by_id = {s["id"]: s for s in service.ipam_db.subnets()}
        servers_by_id = {s["id"]: s for s in service.ipam_db.dhcp_servers()}
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
        devices_by_id = {d["id"]: d for d in service.nodes_db.devices()}
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

def post_settings(service, params, body) -> dict:
    scope = str(body.get("scope", "global"))
    values = body.get("values") or {}
    if scope == "netpath":
        return {"settings": service.apply_netpath_settings(values)}
    if scope == "netflow":
        return {"flow_settings": service.apply_netflow_settings(values)}
    if scope == "syslog":
        return {"syslog_settings": service.apply_syslog_settings(values)}
    if scope == "snmp":
        return {"snmp_settings": service.apply_snmp_settings(values)}
    if scope == "ipam":
        return {"ipam_settings": service.apply_ipam_settings(values)}
    if scope == "nodes":
        return {"nodes_settings": service.apply_nodes_settings(values)}
    if scope == "alerts":
        return {"alerts_settings": service.apply_alerts_settings(values)}
    if scope == "wireless":
        return {"wireless_settings": service.apply_wireless_settings(values)}
    if scope == "configrx":
        return {"configrx_settings": service.apply_configrx_settings(values)}
    return {"settings": service.apply_global_settings(values)}


def post_update(service, params, body) -> dict:
    from .. import selfupdate

    result = selfupdate.apply(service.app_db)
    if result.get("ok") and not result.get("up_to_date"):
        service.log.add(SYSTEM_CATEGORY,
                        f"Updated to commit {result['commit']}: "
                        f"{result['message']}; restarting")
    return result


def post_maintenance(service, params, body) -> dict:
    action = str(body.get("action", ""))
    if action == "redns":
        removed = service.app_db.clear_hostnames()
        return {"message": f"Cleared {removed} cached names; "
                           f"lookups restart within 15s"}
    if action == "prune_traces":
        days = float(service.settings.get("trace_retention_days", 90))
        removed = service.db.prune(days)
        return {"message": f"Deleted {removed} traces older than {days:.0f} days"}
    if action == "prune_flows":
        removed = service.flow_db.prune(0, 0)
        return {"message": f"Deleted {removed} flow records"}
    if action == "prune_syslog":
        removed = service.syslog_db.prune(0, 0)
        return {"message": f"Deleted {removed} syslog messages"}
    if action == "prune_snmp":
        removed = service.snmp_db.prune(0, 0)
        return {"message": f"Deleted {removed} stored traps"}
    if action == "prune_ipam":
        hosts = service.ipam_db.prune_hosts(0)
        conflicts = service.ipam_db.prune_conflicts(0)
        scans = service.ipam_db.prune_scans(0)
        return {"message": f"Deleted {hosts} host record(s), {conflicts} "
                           f"resolved conflict(s), {scans} scan record(s)"}
    if action == "prune_nodes":
        removed = service.nodes_db.prune(sample_days=0, event_days=0, discovery_days=0)
        return {"message": f"Deleted {removed} stored sample(s)/event(s)"}
    if action == "prune_alerts":
        removed = service.alerts_db.prune(0)
        return {"message": f"Deleted {removed} resolved alert(s)"}
    if action == "prune_configrx":
        removed = service.configrx_db.prune(0, 0)
        return {"message": f"Deleted {removed} stored config backup(s)"}
    return {"message": "Unknown action"}


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


def get_syslog_search(service, params, body) -> dict:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    limit = int(_num(params, "limit", 300, int) or 300)
    filters = _syslog_filters(params)

    started = time.time()
    rows = service.syslog_db.search(t0, t1, filters, limit=min(limit, 2000))
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

    return {
        "took_ms": round(elapsed_ms, 1),
        "fts": service.syslog_db.fts,
        "messages": [
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
        ],
    }


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


def get_snmp_traps(service, params, body) -> dict:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    limit = int(_num(params, "limit", 300, int) or 300)
    filters = _snmp_filters(params)

    started = time.time()
    rows = service.snmp_db.search(t0, t1, filters, limit=min(limit, 2000))
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
    return {"took_ms": round(elapsed_ms, 1), "traps": traps}


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
    fields = {k: v for k, v in body.items() if k in ("address", "label", "enabled")}
    service.ipam_db.update_dhcp_server(server_id, **fields)
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
    return {"ok": True}


def delete_ipam_dhcp_server_credential(service, params, body, server_id) -> dict:
    server = service.ipam_db.dhcp_server(server_id)
    if not server:
        raise ValueError("No such DHCP server")
    service.ipam_db.clear_dhcp_credential(server_id)
    service.log.add(IPAM_CATEGORY, f"Cleared the stored credential for DHCP "
                                   f"server {server['label']}")
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


def _device_json(row) -> dict:
    return {
        "id": row["id"], "ip": row["ip"], "name": row["name"],
        "group_id": row["group_id"], "device_group_id": row["device_group_id"],
        "display_name_source": row["display_name_source"],
        "enabled": bool(row["enabled"]),
        "snmp_version": row["snmp_version"], "community": row["community"],
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        # The community string is not a secret — it travels in the clear in
        # every packet the protocol defines — so it is shown as typed. Only
        # the v3 auth password is ever redacted down to has_credential.
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"],
        "snmp_retries": row["snmp_retries"],
        "ping_enabled": _tri(row["ping_enabled"]),
        "snmp_enabled": _tri(row["snmp_enabled"]),
        "oid_set": row["oid_set"],
        "sys_descr": row["sys_descr"], "sys_name": row["sys_name"],
        "sys_object_id": row["sys_object_id"], "sys_contact": row["sys_contact"],
        "sys_location": row["sys_location"], "vendor": row["vendor"],
        "status": row["status"], "ping_ok": _tri(row["ping_ok"]),
        "ping_rtt_ms": row["ping_rtt_ms"], "snmp_ok": _tri(row["snmp_ok"]),
        "snmp_error": row["snmp_error"], "consecutive_fail": row["consecutive_fail"],
        "last_poll_ts": row["last_poll_ts"], "last_up_ts": row["last_up_ts"],
        "last_down_ts": row["last_down_ts"],
        "last_uptime_ticks": row["last_uptime_ticks"],
        "last_uptime_ts": row["last_uptime_ts"], "created_ts": row["created_ts"],
    }


def _group_json(service, row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "snmp_version": row["snmp_version"],
        "community": row["community"], "v3_user": row["v3_user"],
        "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"], "snmp_retries": row["snmp_retries"],
        "ping_enabled": bool(row["ping_enabled"]), "snmp_enabled": bool(row["snmp_enabled"]),
        "oid_set": row["oid_set"], "is_default": bool(row["is_default"]),
        "created_ts": row["created_ts"],
        # The profile's own snmp_version/community/v3_* above are its
        # "primary" credential — always present, always tried first. This
        # is every ADDITIONAL credential the poller falls back to in
        # order when the primary doesn't work for a given device.
        "credentials": [_group_credential_json(r)
                        for r in service.nodes_db.group_credentials(row["id"])],
    }


def _group_credential_json(row) -> dict:
    return {
        "id": row["id"], "group_id": row["group_id"], "label": row["label"],
        "snmp_version": row["snmp_version"], "community": row["community"],
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


def _discovery_result_json(row) -> dict:
    return {"id": row["id"], "job_id": row["job_id"], "ip": row["ip"],
            "ping_ok": bool(row["ping_ok"]), "snmp_ok": bool(row["snmp_ok"]),
            "community_or_user": row["community_or_user"],
            "snmp_version": row["snmp_version"], "sys_descr": row["sys_descr"],
            "sys_name": row["sys_name"], "sys_object_id": row["sys_object_id"],
            "vendor": row["vendor"], "suggested_group_id": row["suggested_group_id"],
            "promoted_device_id": row["promoted_device_id"]}


_DEVICE_EDITABLE_BODY = ("name", "group_id", "device_group_id",
                         "display_name_source", "enabled",
                         "snmp_version", "community",
                         "v3_user", "v3_auth_proto", "poll_interval_s",
                         "snmp_timeout_s", "snmp_retries", "ping_enabled",
                         "snmp_enabled", "oid_set")
_GROUP_EDITABLE_BODY = ("name", "snmp_version", "community", "v3_user",
                        "v3_auth_proto", "poll_interval_s", "snmp_timeout_s",
                        "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set")


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


def get_nodes_devices(service, params, body) -> dict:
    group_id = params.get("group_id")
    device_group_id = params.get("device_group_id")
    status = params.get("status") or None
    text = params.get("q") or None
    # The frontend only ever sends this param when the "only offline"
    # checkbox is checked, so its mere presence is the signal — no
    # string-vs-boolean parsing of a possible "false" needed.
    exclude_up = params.get("offline_only") is not None
    rows = service.nodes_db.devices(
        group_id=int(group_id) if group_id else None,
        device_group_id=int(device_group_id) if device_group_id else None,
        status=status, text=text, exclude_up=exclude_up)
    worker_state = service.node_poller.worker_state()
    devices = []
    for row in rows:
        device = _device_json(row)
        device["polling"] = row["id"] in worker_state
        devices.append(device)
    return {"devices": devices}


def post_nodes_device(service, params, body) -> dict:
    ip = str(body.get("ip", "")).strip()
    if not ip:
        raise ValueError("An IP address is required")
    if service.nodes_db.device_by_ip(ip):
        raise ValueError(f"{ip} is already a device")
    group_id = body.get("group_id")
    device_group_id = body.get("device_group_id")
    _check_display_name_source(body)
    overrides = {k: v for k, v in body.items() if k in _DEVICE_EDITABLE_BODY
                and k not in ("name", "group_id", "device_group_id",
                              "display_name_source", "enabled")}
    device_id = service.nodes_db.add_device(
        ip, name=body.get("name") or None,
        group_id=int(group_id) if group_id else None,
        device_group_id=int(device_group_id) if device_group_id else None,
        **overrides)
    # Not an add_device parameter: like device_group_id before it,
    # add_device's **overrides filter only knows credential/polling
    # columns and would silently drop it.
    if body.get("display_name_source"):
        service.nodes_db.update_device(
            device_id, display_name_source=body["display_name_source"])
    service.log.add(NODES_CATEGORY, f"Added device {ip}")
    return {"id": device_id}


def get_nodes_device(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    device = _device_json(row)
    device["effective_config"] = {
        k: v for k, v in service.nodes_db.effective_config(row).items()
        if k != "v3_auth_pass_enc"}
    device["group_name"] = None
    if row["group_id"]:
        group = service.nodes_db.group(row["group_id"])
        device["group_name"] = group["name"] if group else None
    device["polling"] = device_id in service.node_poller.worker_state()
    return {"device": device}


def _check_display_name_source(body) -> None:
    value = body.get("display_name_source")
    if value is not None and value not in ("auto", "manual"):
        raise ValueError("display_name_source must be 'auto' or 'manual'")


def put_nodes_device(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    _check_display_name_source(body)
    fields = {k: v for k, v in body.items() if k in _DEVICE_EDITABLE_BODY}
    service.nodes_db.update_device(device_id, **fields)
    return {"ok": True}


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


def post_nodes_device_poll(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    service.node_poller.poll_now(device_id)
    return {"ok": True}


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
        version = int(config.get("snmp_version") or 1)
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        try:
            session = _Session(row["ip"], DEFAULT_SNMP_PORT, timeout_s,
                               int(config.get("snmp_retries", 2)))
            try:
                if version in (0, 1):
                    packet = build_request(version, identity or "public", PDU_GET,
                                           random.randint(1, 2 ** 16), oids)
                else:
                    engine_reply = session.request(discovery_probe())
                    auth_key = (localized_key(auth_proto, password, engine_reply.engine_id)
                               if auth_proto and password else None)
                    packet = build_v3_request(
                        random.randint(1, 2 ** 16), random.randint(1, 2 ** 16),
                        PDU_GET, oids, engine_id=engine_reply.engine_id,
                        engine_boots=engine_reply.engine_boots,
                        engine_time=engine_reply.engine_time, user=identity or "",
                        auth_proto=auth_proto, auth_key=auth_key)
                response = session.request(packet)
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
        except SnmpError as exc:
            result["snmp"]["ok"] = False
            result["snmp"]["error"] = str(exc)
        finally:
            password = None
    return result


def get_nodes_device_interfaces(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    rows = service.nodes_db.interfaces(device_id)
    return {"interfaces": [
        {"id": r["id"], "if_index": r["if_index"], "descr": r["descr"],
         "alias": r["alias"], "phys_addr": r["phys_addr"], "speed_bps": r["speed_bps"],
         "admin_status": r["admin_status"], "oper_status": r["oper_status"],
         "in_bps": r["in_bps"], "out_bps": r["out_bps"],
         "in_error_rate": r["in_error_rate"], "out_error_rate": r["out_error_rate"],
         "last_in_errors": r["last_in_errors"], "last_out_errors": r["last_out_errors"],
         "last_in_octets": r["last_in_octets"], "last_out_octets": r["last_out_octets"],
         "last_seen_ts": r["last_seen_ts"]}
        for r in rows]}


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
    points = service.nodes_db.series(device_id, int(metric_id), t0, t1)
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
    interface_events = []
    for iface in service.nodes_db.interfaces(device_id):
        for ev in service.nodes_db.interface_events(interface_id=iface["id"], since_s=since_s):
            interface_events.append({
                "id": ev["id"], "interface_id": ev["interface_id"],
                "if_index": iface["if_index"], "descr": iface["descr"],
                "ts": ev["ts"], "kind": ev["kind"], "detail": ev["detail"]})
    interface_events.sort(key=lambda e: e["ts"], reverse=True)
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
    return {"ok": True}


def delete_nodes_device_credential(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    service.nodes_db.clear_device_credential(device_id)
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
    return {"groups": [_group_json(service, r) for r in service.nodes_db.groups()]}


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
    return {"ok": True}


def delete_nodes_group_credential_secret(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    if not cred or cred["group_id"] != int(group_id):
        raise ValueError("No such credential")
    service.nodes_db.clear_group_credential_password(credential_id)
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
    overrides = {"discovery_communities": communities}
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
    return {"job": _discovery_job_json(job),
            "results": [_discovery_result_json(r) for r in results]}


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
    file capped at a few MB (max_mib_bytes)."""
    import base64
    from .. import mibparse

    filename = str(body.get("filename", "")).strip() or "uploaded.mib"
    content_b64 = body.get("content")
    if not content_b64:
        raise ValueError("content (base64-encoded MIB text) is required")
    try:
        raw = base64.b64decode(content_b64, validate=False)
    except Exception:
        raise ValueError("content is not valid base64")
    max_bytes = int(service.nodes_settings.get("max_mib_bytes", 8 * 1024 * 1024))
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
    max_bytes = int(service.nodes_settings.get("max_mib_bytes", 8 * 1024 * 1024))
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

def _alert_json(row) -> dict:
    from .. import alertmail

    severity = row["severity"]
    return {
        "id": row["id"], "rule_id": row["rule_id"], "dedup_key": row["dedup_key"],
        "entity_kind": row["entity_kind"], "entity_id": row["entity_id"],
        "entity_label": row["entity_label"], "severity": severity,
        "severity_name": alertmail.SEVERITY_NAMES[severity] if 0 <= severity <= 7
                        else str(severity),
        "message": row["message"], "detail": row["detail"], "state": row["state"],
        "count": row["count"], "opened_ts": row["opened_ts"], "last_ts": row["last_ts"],
        "acked_ts": row["acked_ts"], "acked_by": row["acked_by"],
        "ack_note": row["ack_note"], "resolved_ts": row["resolved_ts"],
        "resolved_by": row["resolved_by"],
    }


def _rule_json(row) -> dict:
    return {
        "id": row["id"], "key": row["key"], "name": row["name"], "kind": row["kind"],
        "source_kind": row["source_kind"], "severity": row["severity"],
        "enabled": bool(row["enabled"]), "is_builtin": bool(row["is_builtin"]),
        "device_filter": row["device_filter"], "threshold": row["threshold"],
        "clear_threshold": row["clear_threshold"], "for_polls": row["for_polls"],
        "template_id": row["template_id"], "created_ts": row["created_ts"],
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


def get_alerts(service, params, body) -> dict:
    state = params.get("state") or None
    severity = params.get("severity")
    rule_id = params.get("rule_id")
    device_text = params.get("device") or None
    text = params.get("q") or None
    t0 = _num(params, "t0", None)
    t1 = _num(params, "t1", None)
    limit = int(_num(params, "limit", 300, int) or 300)
    rows = service.alerts_db.alerts(
        state=state, severity=int(severity) if severity else None,
        rule_id=int(rule_id) if rule_id else None, device_text=device_text,
        text=text, t0=t0, t1=t1, limit=min(limit, 2000))
    rule_names = {r["id"]: r["name"] for r in service.alerts_db.rules()}
    alerts = []
    for row in rows:
        alert = _alert_json(row)
        alert["rule_name"] = rule_names.get(row["rule_id"], "")
        alerts.append(alert)
    return {"alerts": alerts}


def get_alert(service, params, body, alert_id) -> dict:
    row = service.alerts_db.alert(alert_id)
    if not row:
        raise ValueError("No such alert")
    alert = _alert_json(row)
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
    return {"ok": True}


def post_alert_resolve(service, params, body, alert_id) -> dict:
    if not service.alerts_db.alert(alert_id):
        raise ValueError("No such alert")
    service.alerts_db.resolve(alert_id, params.get("_username", ""))
    return {"ok": True}


def post_alerts_ack_all(service, params, body) -> dict:
    n = service.alerts_db.acknowledge_all(params.get("_username", ""))
    return {"acknowledged": n}


def _bulk_alert_ids(body) -> list[int]:
    ids = body.get("alert_ids") or []
    if not ids:
        raise ValueError("alert_ids is required")
    return [int(i) for i in ids]


def post_alerts_bulk_resolve(service, params, body) -> dict:
    alert_ids = _bulk_alert_ids(body)
    n = service.alerts_db.resolve_many(alert_ids, params.get("_username", ""))
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
    if kind not in ("device_event", "interface_event", "threshold", "trap",
                    "syslog", "ipam"):
        raise ValueError("Unrecognized rule kind")
    if service.alerts_db.rule_by_key(key):
        raise ValueError(f"A rule with key '{key}' already exists")
    fields = {k: v for k, v in body.items() if k in
             ("severity", "enabled", "device_filter", "threshold",
              "clear_threshold", "for_polls", "template_id")}
    rule_id = service.alerts_db.add_rule(key, name, kind, source_kind, **fields)
    service.log.add(ALERTS_CATEGORY, f"Added alert rule {name}")
    return {"id": rule_id}


def put_alerts_rule(service, params, body, rule_id) -> dict:
    row = service.alerts_db.rule(rule_id)
    if not row:
        raise ValueError("No such rule")
    allowed_keys = ("name", "severity", "enabled", "device_filter", "threshold",
                    "clear_threshold", "for_polls", "template_id")
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
        fake_alert = {"entity_label": "sample-device (10.20.3.5)",
                     "entity_id": "10.20.3.5", "message": "This is a sample alert.",
                     "detail": "", "severity": 4, "count": 1,
                     "opened_ts": now, "last_ts": now}
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
    return {"ok": True}


def delete_alerts_smtp_credential(service, params, body) -> dict:
    service.alerts_db.clear_smtp_credential()
    service.log.add(ALERTS_CATEGORY, "Cleared the stored SMTP credential")
    return {"ok": True}


def post_alerts_smtp_test(service, params, body) -> dict:
    """Sends a real test email, using in-progress-edit SMTP settings from
    the body when present, else the saved ones — the same "test what's
    typed before saving" idiom as IPAM's DHCP test and the SNMP Trap/
    Syslog "send test" buttons."""
    from .. import alertmail, dpapi

    to_addr = str(body.get("to", "")).strip()
    if not to_addr:
        raise ValueError("A recipient address is required")
    settings = dict(service.alerts_settings)
    for key in ("smtp_host", "smtp_port", "smtp_security", "smtp_verify_cert",
               "smtp_username", "smtp_from", "smtp_from_name", "smtp_timeout_s"):
        if key in body:
            settings[key] = body[key]
    password = body.get("password")
    if password is None:
        blob = service.alerts_db.smtp_password_enc()
        if blob:
            try:
                password = dpapi.unprotect(blob).decode("utf-8")
            except Exception:
                password = None
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
    return {"running": service.alert_engine.running,
            "status": service.alert_engine.status_text()}


# ---------------------------------------------------------------- wireless

def _controller_json(row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "ip": row["ip"],
        "enabled": bool(row["enabled"]),
        "snmp_version": row["snmp_version"], "community": row["community"],
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        # Same has_credential convention as Nodes' device v3 password —
        # the encrypted blob itself is never sent to the browser.
        "has_credential": bool(row["v3_auth_pass_enc"]),
        "last_poll_ts": row["last_poll_ts"],
        "last_poll_ok": _tri(row["last_poll_ok"]),
        "last_poll_error": row["last_poll_error"],
        "created_ts": row["created_ts"],
    }


def _radio_json(row) -> dict:
    return {
        "radio_id": row["radio_id"], "channel": row["channel"],
        "operating_power_dbm": row["operating_power_dbm"],
        "station_count": row["station_count"],
    }


def _ap_json(service, row) -> dict:
    radios = [_radio_json(r) for r in service.wireless_db.radios_for(row["id"])]
    # The at-a-glance table shows one tx-power figure per AP; a real AP
    # has one radio per band, so this is the strongest of them rather
    # than an arbitrary "first" pick.
    powers = [r["operating_power_dbm"] for r in radios if r["operating_power_dbm"] is not None]
    return {
        "id": row["id"], "controller_id": row["controller_id"],
        "wtp_id": row["wtp_id"], "vdom": row["vdom"], "name": row["name"],
        "status": row["status"], "model": row["model"],
        "mac_address": row["mac_address"], "station_count": row["station_count"],
        "tx_power_dbm": max(powers) if powers else None,
        "radios": radios,
        "last_seen_ts": row["last_seen_ts"],
    }


def get_wireless_overview(service, params, body) -> dict:
    return {
        "controllers": [_controller_json(r) for r in service.wireless_db.controllers()],
        "ap_counts": service.wireless_db.ap_counts(),
        "poller": {
            "running": service.wireless.running,
            "status": service.wireless.status_text(),
            "counters": service.wireless.counters,
        },
    }


def get_wireless_controllers(service, params, body) -> dict:
    return {"controllers": [_controller_json(r) for r in service.wireless_db.controllers()]}


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
    if not service.wireless_db.controller(controller_id):
        raise ValueError("No such controller")
    fields = {k: v for k, v in body.items() if k in _CONTROLLER_EDITABLE_BODY}
    service.wireless_db.update_controller(controller_id, **fields)
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
    return {"ok": True}


def delete_wireless_controller_credential(service, params, body, controller_id) -> dict:
    row = service.wireless_db.controller(controller_id)
    if not row:
        raise ValueError("No such controller")
    service.wireless_db.set_credential(controller_id, None)
    service.log.add(WIRELESS_CATEGORY, f"Cleared the stored SNMPv3 credential for {row['name']}")
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
    return {"aps": result}


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
    return {"running": service.wireless.running,
            "status": service.wireless.status_text()}


# ----------------------------------------------------------------- configrx

def _configrx_device_json(service, device_row) -> dict:
    config = service.configrx_db.device_config(device_row["id"])
    return {
        "id": device_row["id"], "ip": device_row["ip"],
        "name": device_row["name"] or device_row["sys_name"] or device_row["ip"],
        "vendor": device_row["vendor"],
        "backup_enabled": bool(config["backup_enabled"]) if config else False,
        "ssh_port": config["ssh_port"] if config else 22,
        "ssh_username": (config["ssh_username"] if config else "") or "",
        # Same has_credential convention as every other stored password in
        # this app — the encrypted blob itself never reaches the browser.
        "has_credential": bool(config["ssh_password_enc"]) if config else False,
        "vendor_override": (config["vendor_override"] if config else "") or "",
        "last_backup_ts": config["last_backup_ts"] if config else None,
        "last_backup_status": config["last_backup_status"] if config else None,
        "last_backup_error": config["last_backup_error"] if config else None,
    }


def _configrx_backup_json(row) -> dict:
    return {"id": row["id"], "device_id": row["device_id"], "ts": row["ts"],
            "sha256": row["sha256"], "size_bytes": row["size_bytes"]}


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
    devices = [_configrx_device_json(service, r) for r in rows]
    if params.get("enabled_only") is not None:
        devices = [d for d in devices if d["backup_enabled"]]
    return {"devices": devices}


def get_configrx_device(service, params, body, device_id) -> dict:
    device = service.nodes_db.device(device_id)
    if not device:
        raise ValueError("No such device")
    return {"device": _configrx_device_json(service, device)}


def post_configrx_device_config(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    fields = {k: v for k, v in body.items()
             if k in ("backup_enabled", "ssh_port", "ssh_username", "vendor_override")}
    service.configrx_db.update_device_config(device_id, **fields)
    return {"ok": True}


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
    try:
        encrypted = dpapi.protect(password.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        password = None
    service.configrx_db.set_credential(device_id, username, encrypted)
    service.log.add(CONFIGRX_CATEGORY, f"Stored an SSH credential for {row['ip']}")
    return {"ok": True}


def delete_configrx_device_credential(service, params, body, device_id) -> dict:
    row = service.nodes_db.device(device_id)
    if not row:
        raise ValueError("No such device")
    service.configrx_db.clear_credential(device_id)
    service.log.add(CONFIGRX_CATEGORY, f"Cleared the stored SSH credential for {row['ip']}")
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
    row = service.configrx_db.backup(backup_id)
    if not row:
        raise ValueError("No such backup")
    content = service.configrx_db.backup_content(backup_id)
    return {"backup": _configrx_backup_json(row), "content": content}


def post_configrx_device_backup(service, params, body, device_id) -> dict:
    if not service.nodes_db.device(device_id):
        raise ValueError("No such device")
    config = service.configrx_db.device_config(device_id)
    if not config or not config["backup_enabled"]:
        raise ValueError("Backup is not enabled for this device")
    service.configrx.backup_now(device_id)
    return {"ok": True}


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
    return {"running": service.configrx.running,
            "status": service.configrx.status_text()}


# --------------------------------------------------------------------- auth

def _client(params) -> str:
    return params.get("_client", "")


def post_login(service, params, body) -> dict:
    """Verify a password. Deliberately slow to fail, and vague about why."""
    from ..auth import needs_rehash, hash_password, verify_password

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    client = _client(params)

    delay = service.throttle.delay_for(username, client)
    if delay:
        time.sleep(min(delay, 5))

    row = service.app_db.user(username) if username else None
    stored = row["password"] if row else None

    # Hash something even when the account does not exist, so the time taken
    # cannot be used to discover which usernames are real.
    if stored is None:
        verify_password(password, "scrypt$16384$8$1$" + "A" * 24 + "$" + "A" * 44)
        service.throttle.record_failure(username or "?", client)
        service.log.add(ERROR_CATEGORY, f"Failed sign-in for "
                                        f"{username or '(blank)'} from {client}")
        raise PermissionError("Wrong username or password")

    if not verify_password(password, stored):
        service.throttle.record_failure(username, client)
        service.log.add(ERROR_CATEGORY,
                        f"Failed sign-in for {row['username']} from {client}")
        raise PermissionError("Wrong username or password")

    service.throttle.clear(username, client)
    service.app_db.touch_login(row["username"])

    # Upgrade the stored hash quietly, now that we hold the password.
    if needs_rehash(stored):
        service.app_db.set_password(row["username"], hash_password(password),
                                must_change=bool(row["must_change"]))

    token = service.sessions.create(row["username"], client,
                                    str(body.get("_agent", "")))
    service.log.add(SYSTEM_CATEGORY, f"{row['username']} signed in from {client}")
    return {"token": token, "username": row["username"],
            "must_change": bool(row["must_change"])}


def post_logout(service, params, body) -> dict:
    token = params.get("_token", "")
    session = service.sessions.get(token)
    if session:
        service.log.add(SYSTEM_CATEGORY, f"{session['username']} signed out")
    service.sessions.destroy(token)
    return {"ok": True}


def post_heartbeat(service, params, body) -> dict:
    """Confirms a person is present. server.py has already touched the
    session for any POST by the time this runs; the only job left is to hand
    back a fresh countdown so the client's warning banner resets."""
    return {"ok": True, "idle_timeout_minutes": service.sessions.idle_seconds // 60}


def get_session(service, params, body) -> dict:
    session = service.sessions.get(params.get("_token", ""))
    if not session:
        return {"authenticated": False}
    row = service.app_db.user(session["username"])
    idle_remaining = service.sessions.idle_seconds - (time.time() - session["last_seen"])
    return {
        "authenticated": True,
        "username": session["username"],
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
        password = str(body.get("password", ""))
        check_password_quality(password, username)
    except AuthError as exc:
        raise ValueError(str(exc)) from exc

    if service.app_db.user(username):
        raise ValueError(f"There is already an account called {username}")

    service.app_db.add_user(username, hash_password(password), must_change=True)
    grants = body.get("grants") or {}
    if grants:
        service.app_db.set_permissions(username, grants)
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {username} created by "
                    f"{params.get('_username', 'someone')}")
    return {"username": username}


def post_user_permissions(service, params, body) -> dict:
    username = str(body.get("username", "")).strip()
    if not username:
        raise ValueError("Which account?")
    if not service.app_db.user(username):
        raise ValueError(f"No account called {username}")
    grants = body.get("grants") or {}
    service.app_db.set_permissions(username, grants)
    service.log.add(SYSTEM_CATEGORY,
                    f"Permissions for {username} changed by "
                    f"{params.get('_username', 'someone')}")
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

    service.app_db.remove_user(target)
    ended = service.sessions.destroy_user(target)
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {target} removed by {me}; {ended} session(s) ended")
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
    return {"username": target, "sessions_ended": ended, "reset": resetting}

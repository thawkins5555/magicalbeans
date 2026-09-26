"""Handlers: NetFlow overview, records and settings."""

from __future__ import annotations

import math
import time

from ... import namelookup
from ...services import format_bytes, format_packets, format_rate, port_name, protocol_name

from ._shared import _csv_response, _csv_time, _num, _window


# ------------------------------------------------------------------ netflow

def _flow_filters(params) -> dict:
    exporter = params.get("exporter") or None
    direction = str(params.get("direction") or "both").lower()
    if direction not in ("in", "out", "both"):
        direction = "both"
    iface = _num(params, "iface", None, int)
    if iface is not None and not 0 <= iface <= 4294967295:
        iface = None
    return {
        "src_ip": params.get("src", ""),
        "dst_ip": params.get("dst", ""),
        "port": params.get("port") or None,
        "protocol": _num(params, "protocol", None, int),
        "exporter": exporter,
        "iface": iface,
        # A direction only means something scoped to one exporter's own
        # interface numbering; without one chosen it is forced back to
        # "both" here, so every downstream reader agrees it is a no-op
        # rather than each having to re-derive the same rule.
        "direction": direction if exporter else "both",
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
        return namelookup.resolve_name(
            service.nodes_db, service.app_db, text) or text
    if dimension in ("Source AS", "Destination AS"):
        return f"AS{text}"
    if names and dimension in ADDRESS_DIMENSIONS:
        # Named where a name exists, address where it does not, so an internal
        # host with no PTR record still reads sensibly beside a named one.
        return ARROW.join(names.get(part.strip(), part.strip())
                          for part in text.split(ARROW))
    return text


# flowdb.overview allocates one float per bucket per series, so the bucket
# count — not the span — decides what a chart request costs in memory. A
# span past the ladder's last rung, or a configured bucket_seconds far too
# small for the window (a ten-second bucket over a year is 3.15 million of
# them), is bounded by widening the bucket until the count fits rather than
# narrowing the window the operator asked for — the same thing
# analysis.build_timeline does for its own MAX_BUCKETS.
FLOW_MAX_BUCKETS = 5000


def _flow_bucket(service, span: float) -> float:
    configured = int(service.flow_settings.get("bucket_seconds", 0) or 0)
    if configured:
        bucket = float(configured)
    else:
        bucket = 21600.0
        for limit, step in [(900, 10), (7200, 60), (43200, 300),
                            (172800, 900), (1209600, 3600)]:
            if span <= limit:
                bucket = float(step)
                break
    bucket = max(bucket, 1.0)
    if span / bucket > FLOW_MAX_BUCKETS:
        bucket = math.ceil(span / FLOW_MAX_BUCKETS)
    return float(bucket)


def _flow_coverage(service) -> dict:
    """flow_db.coverage(), through service.cached_poll when the service has
    one -- the same 10s cache /api/state's own coverage reads share, so an
    overview poll never pays for a second scan of MIN/MAX(ts_end) a moment
    after /api/state already ran one. A duck-typed test service that carries
    no cached_poll gets the plain, uncached call instead."""
    cached_poll = getattr(service, "cached_poll", None)
    if cached_poll is None:
        return service.flow_db.coverage()
    return cached_poll("flow_coverage", 10.0, service.flow_db.coverage)


def _exporter_rows(service) -> list[dict]:
    """The overview's exporter dropdown list, named the way the Exporter
    column and the chart label already are (Symptom 1 in the plan)."""
    rows = service.flow_db.exporters()
    names = namelookup.resolve_names(
        service.nodes_db, service.app_db, [row["address"] for row in rows])
    return [{"address": row["address"], "name": names.get(row["address"]),
             "version": row["version"], "flows": row["flows"],
             "last_seen": row["last_seen"]}
            for row in rows]


def get_flow_overview(service, params, body) -> dict:
    t0, t1 = _window(params)
    span = t1 - t0
    dimension = params.get("dimension", "Application")
    filters = _flow_filters(params)
    bucket = _flow_bucket(service, span)
    top_n = int(service.flow_settings.get("top_n", 10))

    # `info` is filled in by flowdb.overview with what actually answered the
    # window (records_only/tier/summaries_from/widened), since only it knows
    # whether a rollup tier or the raw table did the work.
    info: dict = {}
    # One aggregate pass over the window feeds the chart, the top-N bars and
    # the totals line together, rather than a scan each.
    times, series, bucket_s, top_rows, totals = service.flow_db.overview(
        t0, t1, dimension, filters, bucket, series_limit=8, top_limit=top_n,
        info=info)

    names = _address_names(service, dimension,
                           list(series) + [row["key"] for row in top_rows])
    total_bytes = totals["bytes"] or 0
    # A5: the same coverage() /api/state polls, so records_from never
    # disagrees with what the status strip says raw history reaches.
    coverage = _flow_coverage(service)

    # times[0], not the t0 asked for: flowdb snaps the window start down to a
    # bucket boundary so a rollup bucket lands wholly inside one slot, and the
    # chart's own axis has to agree with the values drawn on it.
    return {
        "t0": times[0] if times else t0,
        "t1": t1, "bucket_s": bucket_s, "dimension": dimension,
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
                 "packets_text": format_packets(row["packets"] or 0),
                 "flows": row["flows"],
                 "share": (row["bytes"] or 0) / total_bytes if total_bytes else 0}
                for row in top_rows],
        "totals": {
            "bytes": totals["bytes"], "packets": totals["packets"],
            "flows": totals["flows"],
            "bytes_text": format_bytes(totals["bytes"]),
            "rate_text": format_rate(totals["bytes"], span),
            "packets_text": format_packets(totals["packets"]),
        },
        "exporters": _exporter_rows(service),
        # Honest coverage: whether this answer only reached as far back as
        # raw retention allows, and where the summaries would have reached
        # instead -- the root cause the plan starts from.
        "records_only": bool(info.get("records_only")),
        "records_from": coverage.get("raw_oldest"),
        "summaries_from": info.get("summaries_from"),
        "widened": bool(info.get("widened")),
        "breakdown_from": info.get("breakdown_from"),
    }


# The screen asks for the top 250 records by whichever order is selected
# (nf-order in index.html); FLOW_EXPORT_CAP is the taller export ceiling —
# past what one export click should hand back, still far short of buffering
# a million rows.
FLOW_SCREEN_LIMIT = 250
FLOW_EXPORT_CAP = 20000


def _flow_records_rows(service, params, limit: int) -> tuple[list[dict], bool, bool]:
    """The row-producing half of get_flow_records, factored out so the
    export handler below can ask for FLOW_EXPORT_CAP rows through the
    identical filter/window/order path the screen uses for its 250 —
    same params, same permission gate, just a taller limit.

    The third result is flowdb's scan bound: whether the window reaches
    further back than the ordering looked."""
    t0, t1 = _window(params)
    filters = _flow_filters(params)
    order = params.get("order", "bytes")
    rows, bounded = service.flow_db.flows(t0, t1, filters, limit=limit + 1,
                                          order=order)
    truncated = len(rows) > limit
    rows = rows[:limit]

    resolve_ports = bool(service.flow_settings.get("resolve_ports", True))
    names = {}
    if service.flow_settings.get("resolve_addresses"):
        addresses = {r["src_ip"] for r in rows} | {r["dst_ip"] for r in rows}
        names = {ip: name for ip, name
                 in service.app_db.hostnames(addresses).items() if name}
    interfaces = service.flow_db.interface_names()
    # Resolved through the shared batched helper rather than one query per
    # address, so the Exporter column agrees with Syslog's Host column and
    # Alerts' Object column about what a device is called: SNMP sysName,
    # then a manual name that is not just the address, then the reverse-DNS
    # cache.
    exporter_names = namelookup.resolve_names(
        service.nodes_db, service.app_db,
        {r["exporter"] for r in rows if r["exporter"]})
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
            "ts_start": row["ts_start"],
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
    return records, truncated, bounded


def get_flow_records(service, params, body) -> dict:
    records, _truncated, bounded = _flow_records_rows(
        service, params, FLOW_SCREEN_LIMIT)
    return {"records": records, "scan_bounded": bounded}


def get_flow_records_export(service, params, body) -> dict:
    records, truncated, _bounded = _flow_records_rows(
        service, params, FLOW_EXPORT_CAP)
    header = ["start", "end", "ts", "src_ip", "src_name", "src_port", "dst_ip",
             "dst_name", "dst_port", "protocol", "bytes", "packets", "in_if",
             "out_if", "exporter", "exporter_name"]
    csv_rows = [[_csv_time(r.get("ts_start")), _csv_time(r.get("ts"))] +
                [r.get(key) for key in header[2:]] for r in records]
    return _csv_response("netflow", header, csv_rows, truncated=truncated,
                         cap=FLOW_EXPORT_CAP)


# ----------------------------------------------------------- exporters view

# The rates /api/netflow/exporters reports are over the last five minutes,
# the same window "active" state is judged on, so a rate the operator sees
# is a rate an "active" exporter earned it in.
EXPORTER_RATE_WINDOW_S = 300.0
# decoder.missing is itself bounded to 256 entries; this is a generous cap
# on the call rather than a real limit, just enough to see all of them.
MISSING_TEMPLATES_ALL = 1024


def get_flow_exporters(service, params, body) -> dict:
    now = time.time()
    rows = service.flow_db.exporters()
    addresses = [row["address"] for row in rows]
    names = namelookup.resolve_names(service.nodes_db, service.app_db, addresses)
    rates = service.flow_db.exporter_totals(now - EXPORTER_RATE_WINDOW_S, now)

    iface_counts: dict[str, set] = {}
    for row in service.flow_db.interface_totals(now - 3600, now):
        iface_counts.setdefault(row["exporter"], set()).add(row["iface"])

    seq_stats = service.collector.decoder.sequence_gaps()
    missing_counts: dict[str, int] = {}
    for entry in service.collector.decoder.missing_templates(MISSING_TEMPLATES_ALL):
        missing_counts[entry["exporter"]] = missing_counts.get(entry["exporter"], 0) + 1

    exporters = []
    for row in rows:
        address = row["address"]
        rate = rates.get(address) or {}
        rate_bytes = rate.get("bytes", 0) or 0
        last_seen = row["last_seen"] or 0
        age = now - last_seen if last_seen else None
        if age is None:
            state = "silent"
        elif age < 300:
            state = "active"
        elif age < 3600:
            state = "idle"
        else:
            state = "silent"
        gap = seq_stats.get(address) or {}
        exporters.append({
            "address": address,
            "name": names.get(address),
            "version": row["version"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "state": state,
            "flows_per_s": (rate.get("flows", 0) or 0) / EXPORTER_RATE_WINDOW_S,
            "bits_per_s": rate_bytes * 8 / EXPORTER_RATE_WINDOW_S,
            "rate_text": format_rate(rate_bytes, EXPORTER_RATE_WINDOW_S),
            "packets": row["packets"],
            "flows": row["flows"],
            "sampling": row["sampling"],
            "interfaces": len(iface_counts.get(address, ())),
            "seq_missed": gap.get("missed", 0),
            "seq_gaps": gap.get("gaps", 0),
            "seq_resets": gap.get("resets", 0),
            "seq_last": gap.get("last"),
            "missing_templates": missing_counts.get(address, 0),
        })
    exporters.sort(key=lambda e: (e["name"] or "", e["address"]))
    return {"exporters": exporters}


# ---------------------------------------------------------- interfaces view

def _flow_interface_label(setting_names: dict, exporter: str, if_index: int,
                          device_ifaces: dict) -> str:
    """interface_names setting -> Nodes alias/descr/name -> the bare index."""
    key = f"{exporter}:{if_index}"
    if key in setting_names:
        return setting_names[key]
    row = device_ifaces.get(if_index)
    if row is not None:
        if row["alias"]:
            return row["alias"]
        if row["descr"]:
            return row["descr"]
        if row["name"]:
            return row["name"]
    return str(if_index)


def get_flow_interfaces(service, params, body) -> dict:
    t0, t1 = _window(params)
    span = max(t1 - t0, 1.0)
    exporter = params.get("exporter") or None
    rows = service.flow_db.interface_totals(t0, t1, exporter=exporter)

    addresses = {row["exporter"] for row in rows}
    exporter_names = namelookup.resolve_names(service.nodes_db, service.app_db, addresses)
    devices = (service.nodes_db.devices_by_addresses(addresses)
              if service.nodes_db is not None and addresses else {})
    # {address: {if_index: interfaces row}}, one nodes_db.interfaces() call
    # per device found rather than per interface row.
    device_ifaces = {address: {r["if_index"]: r
                               for r in service.nodes_db.interfaces(device["id"])}
                     for address, device in devices.items()}
    setting_names = service.flow_db.interface_names()

    by_iface: dict[tuple[str, int], dict] = {}
    for row in rows:
        entry = by_iface.setdefault((row["exporter"], row["iface"]), {
            "in_bytes": 0, "out_bytes": 0, "in_flows": 0, "out_flows": 0})
        if row["dir"] == "in":
            entry["in_bytes"] += row["bytes"] or 0
            entry["in_flows"] += row["flows"] or 0
        elif row["dir"] == "out":
            entry["out_bytes"] += row["bytes"] or 0
            entry["out_flows"] += row["flows"] or 0

    interfaces = []
    for (address, if_index), entry in by_iface.items():
        ifaces = device_ifaces.get(address, {})
        node_row = ifaces.get(if_index)
        speed_bps = node_row["speed_bps"] if node_row is not None else None
        in_bps = entry["in_bytes"] * 8 / span
        out_bps = entry["out_bytes"] * 8 / span
        interfaces.append({
            "exporter": address,
            "exporter_name": exporter_names.get(address),
            "if_index": if_index,
            "name": _flow_interface_label(setting_names, address, if_index, ifaces),
            "speed_bps": speed_bps,
            "in_bytes": entry["in_bytes"], "out_bytes": entry["out_bytes"],
            "in_bps": in_bps, "out_bps": out_bps,
            "in_util": (in_bps / speed_bps) if speed_bps else None,
            "out_util": (out_bps / speed_bps) if speed_bps else None,
            "in_flows": entry["in_flows"], "out_flows": entry["out_flows"],
            "in_text": format_rate(entry["in_bytes"], span),
            "out_text": format_rate(entry["out_bytes"], span),
        })
    interfaces.sort(key=lambda r: (max(r["in_util"] or 0, r["out_util"] or 0),
                                   max(r["in_bps"], r["out_bps"])), reverse=True)
    return {"t0": t0, "t1": t1, "interfaces": interfaces}


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

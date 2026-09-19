"""Handlers: NetPath targets, traces and topology."""

from __future__ import annotations

import ipaddress
import math
import urllib.parse

from ...analysis import MAX_BUCKETS, availability, build_timeline, build_topology
from ... import namelookup
from ...tracer import unreachable_text
from ... import db as netpathdb
from ... import httpcheck

from ._shared import MIN_BLOCK_PX, _audit, _audit_diff, _num, _pick, _window


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


def _validate_target_url(url: str) -> str:
    """The destination's web page URL: HTTPS only, with a host, and bounded."""
    url = str(url or "").strip()
    if not url:
        return ""
    if len(url) > httpcheck.URL_MAX:
        raise ValueError(f"https_url must be {httpcheck.URL_MAX} characters "
                         f"or fewer")
    if not httpcheck.is_https_url(url):
        raise ValueError("https_url must start with https:// — a web page "
                         "check verifies a certificate, so a plain http:// "
                         "address cannot be checked")
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise ValueError("https_url needs a host, e.g. https://switch.example/")
    # A credential in the URL leaks via http.client's error, which gets stored, served, and logged.
    if parsed.username or parsed.password:
        raise ValueError("https_url must not contain a username or password")
    return url


def _target_json(service, row, last=None, https=None) -> dict:
    keys = row.keys()
    url = str(row["https_url"] or "") if "https_url" in keys else ""
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
        "https_url": url,
        "https_insecure": (bool(row["https_insecure"])
                           if "https_insecure" in keys else False),
        # "none" covers both no URL configured and a URL not yet checked.
        "https_state": ("none" if not url or https is None
                        else ("up" if https["ok"] else "down")),
        "https_status_code": https["status_code"] if https else None,
        "https_latency_ms": https["latency_ms"] if https else None,
        "https_error": (https["error"] or "") if https else "",
        "https_last_ts": https["ts"] if https else None,
    }


def get_targets(service, params, body) -> dict:
    rows = service.db.targets()
    ids = [row["id"] for row in rows]
    last_traces = service.db.last_traces(ids)
    last_https = service.db.last_https_checks(ids)
    return {"targets": [_target_json(service, row, last_traces.get(row["id"]),
                                     last_https.get(row["id"]))
                        for row in rows]}


# Bounds a NetPath target's numeric fields may not exceed. db.py's own
# MIN_*/MAX_* constants are referenced rather than re-typed, so this 400 and
# db.py's _clamp_target_fields backstop can never disagree about what "in
# range" means. Each field reaches a subprocess argument, expected_budget's
# arithmetic, or monitor.py's scheduler — an interval_s at or below zero is
# a spawn storm against one destination.
_TARGET_FIELD_RANGES = {
    "interval_s": (int, netpathdb.MIN_INTERVAL_S, netpathdb.MAX_INTERVAL_S),
    "max_hops": (int, netpathdb.MIN_MAX_HOPS, netpathdb.MAX_MAX_HOPS),
    "probes": (int, netpathdb.MIN_PROBES, netpathdb.MAX_PROBES),
    "timeout_s": (float, netpathdb.MIN_TIMEOUT_S, netpathdb.MAX_TIMEOUT_S),
    # These two reach neither a subprocess nor a loop bound, only a
    # comparison in monitor.classify() — bounded to what is merely sane
    # (non-negative; a percentage), not a mechanism-driven ceiling.
    "warn_rtt_ms": (float, 0.0, None),
    "warn_loss": (float, 0.0, 100.0),
}


def _validate_target_fields(fields: dict) -> dict:
    """Casts and range-checks whichever of _TARGET_FIELD_RANGES' keys are
    present in `fields`, returning a new dict (everything else passed
    through unchanged). Rejects with a clear 400 naming the field and both
    bounds — the visible half of the same check db.py's _clamp_target_fields
    makes silently as a backstop for any other caller; a client submitting
    interval_s=0 should be told why, not have it quietly rewritten to 5 with
    no explanation anywhere in the response.
    """
    out = dict(fields)
    for key, (kind, low, high) in _TARGET_FIELD_RANGES.items():
        if key not in out:
            continue
        try:
            value = kind(out[key])
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if value < low or (high is not None and value > high):
            range_text = (f"between {low} and {high}" if high is not None
                         else f"at least {low}")
            raise ValueError(f"{key} must be {range_text}")
        out[key] = value
    return out


def post_target(service, params, body) -> dict:
    defaults = service.settings
    host = str(body.get("host", "")).strip()
    if not host:
        raise ValueError("A destination host or address is required")
    host = _validate_target_host(host)
    fields = _validate_target_fields({
        "interval_s": body.get("interval_s", defaults["default_interval_s"]),
        "max_hops": body.get("max_hops", defaults["default_max_hops"]),
        "probes": body.get("probes", defaults["default_probes"]),
        "warn_rtt_ms": body.get("warn_rtt_ms", defaults["default_warn_rtt_ms"]),
        "warn_loss": body.get("warn_loss", defaults["default_warn_loss"]),
        "timeout_s": body.get("timeout_s", defaults["default_timeout_s"]),
    })
    https_url = _validate_target_url(body.get("https_url", ""))
    target_id = service.db.add_target(
        host=host, label=str(body.get("label") or host).strip(), **fields)
    if https_url or body.get("https_insecure"):
        service.db.update_target(
            target_id, https_url=https_url,
            https_insecure=1 if body.get("https_insecure") else 0)
    service.monitor.trace_now(target_id)
    _audit(service, params, "target.create", target=str(target_id),
          detail=f"host={host}")
    return {"id": target_id}


def put_target(service, params, body, target_id: int) -> dict:
    # Fetched before anything changes — the only way to name what actually
    # changed afterward; update_target itself never reads the row it is
    # about to overwrite.
    before = service.db.target(target_id)
    fields = _pick(body, {"host", "label", "interval_s", "max_hops", "probes",
                          "warn_rtt_ms", "warn_loss", "timeout_s", "enabled",
                          "https_url", "https_insecure"})
    if "https_url" in fields:
        fields["https_url"] = _validate_target_url(fields["https_url"])
    if "https_insecure" in fields:
        fields["https_insecure"] = 1 if fields["https_insecure"] else 0
    # The same check the add route makes: without it, a destination could be
    # added with a host that resolves and then edited to anything at all,
    # leaving the traceroute thread failing every interval against a name
    # that cannot exist.
    if "host" in fields:
        # str() first, the way the add route does it: `ip_address(123)` is a
        # perfectly valid address object, so an integer would be stored as
        # 0.0.0.123, and a null would raise AttributeError as a 500 rather
        # than a refusal.
        fields["host"] = _validate_target_host(str(fields["host"] or "").strip())
    fields = _validate_target_fields(fields)
    service.db.update_target(target_id, **fields)
    if "hop_probe_enabled" in body:
        service.set_hop_probe_enabled(target_id, bool(body["hop_probe_enabled"]))
    if before is not None and fields:
        detail = _audit_diff(before, fields) or "no change"
        _audit(service, params, "target.update", target=str(target_id), detail=detail)
    return {"ok": True}


def delete_target(service, params, body, target_id: int) -> dict:
    # Fetched before the delete — afterward there is nothing left to name
    # this by at all.
    before = service.db.target(target_id)
    service.db.remove_target(target_id)
    if before is not None:
        _audit(service, params, "target.delete", target=str(target_id),
              detail=f"host={before['host']}")
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


def get_netpath_https(service, params, body) -> dict:
    """Web-page availability over the window, bucketed like the timeline."""
    target_id = int(params.get("target", 0))
    target = service.db.target(target_id)
    if target is None:
        return {"buckets": [], "summary": {}}
    keys = target.keys()
    url = str(target["https_url"] or "") if "https_url" in keys else ""
    t0, t1 = _window(params)
    if not url:
        return {"t0": t0, "t1": t1, "url": "", "buckets": [],
                "summary": {"state": "none", "checks": 0}}

    bucket_s, per_block = _block_size(service, target, t1 - t0,
                                      _num(params, "width", 1200))
    bucket_s = max(float(bucket_s), 1e-3)
    start = math.floor(t0 / bucket_s) * bucket_s
    count = max(1, int(math.ceil((t1 - start) / bucket_s)))
    if count > MAX_BUCKETS:
        bucket_s = max((t1 - t0) / (MAX_BUCKETS - 1), 1e-3)
        start = math.floor(t0 / bucket_s) * bucket_s
        count = max(1, min(MAX_BUCKETS,
                           int(math.ceil((t1 - start) / bucket_s))))

    totals = [0] * count
    passed = [0] * count
    latencies: list[list[float]] = [[] for _ in range(count)]
    errors = [""] * count
    codes: list[int | None] = [None] * count
    rows = service.db.https_checks_between(target_id, start, t1)
    for row in rows:
        index = int((row["ts"] - start) / bucket_s)
        if index < 0 or index >= count:
            continue
        totals[index] += 1
        if row["ok"]:
            passed[index] += 1
        elif not errors[index]:
            errors[index] = row["error"] or ""
            codes[index] = row["status_code"]
        if row["latency_ms"] is not None:
            latencies[index].append(float(row["latency_ms"]))

    buckets = []
    for index in range(count):
        total = totals[index]
        times = latencies[index]
        buckets.append({
            "t0": start + index * bucket_s,
            "t1": start + (index + 1) * bucket_s,
            "total": total,
            "ok": passed[index],
            "ok_pct": (100.0 * passed[index] / total) if total else None,
            "avg_latency_ms": (sum(times) / len(times)) if times else None,
            "last_error": errors[index],
            "status_code": codes[index],
        })

    checks = sum(totals)
    every = [value for group in latencies for value in group]
    last = rows[-1] if rows else None
    return {
        "t0": t0,
        "t1": t1,
        "url": url,
        "bucket_s": bucket_s,
        "polls_per_block": per_block,
        "buckets": buckets,
        "summary": {
            "state": "none" if last is None else ("up" if last["ok"] else "down"),
            "checks": checks,
            "ok_pct": (100.0 * sum(passed) / checks) if checks else 0.0,
            "avg_latency_ms": (sum(every) / len(every)) if every else None,
            "last_error": (last["error"] or "") if last is not None else "",
            "last_status_code": last["status_code"] if last is not None else None,
            "last_ts": last["ts"] if last is not None else None,
        },
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
        # Which TTLs hit MAX_HOP_FANOUT and had a trace's own edge-pairing
        # bounded there — see analysis.py's own comment above that constant.
        # Sorted so the wire shape is stable regardless of set iteration
        # order; empty (not omitted) when nothing was truncated, so a caller
        # can check "is this list non-empty" without a .get() default.
        "truncated_ttls": sorted(topo.truncated_ttls),
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
        from_nodes = namelookup.fill_from_nodes(service.nodes_db, names, ips)
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
    # renamed. See namelookup.fill_from_nodes for the precedence.
    from_nodes = namelookup.fill_from_nodes(service.nodes_db, names, ips)
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

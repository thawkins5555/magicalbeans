"""Handlers: syslog search, export and settings."""

from __future__ import annotations

import time

from ... import namelookup
from ...syslogparse import facility_name, severity_name

from ._shared import EXPORT_ROW_CAP, SEARCH_ROW_CAP, _csv_response, _csv_time, _hist_window, _num, _page


# ------------------------------------------------------------------- syslog

# One id_chunks chunk from each lookup. Raising it is safe -- syslogdb's
# host clause chunks whatever it is given.
SYSLOG_HOST_IP_CAP = 500


def _syslog_filters(service, params) -> dict:
    filters = {
        "text": params.get("q", ""),
        "severity": params.get("severity") or None,
        "facility": params.get("facility") or None,
        "source": params.get("source", ""),
        "host": params.get("host", ""),
        "app": params.get("app", ""),
    }
    # The Host column often shows a name resolved from Nodes or DNS that was
    # never stored on the row, so the stored host alone cannot answer a search
    # for it. Resolve the fragment to the addresses it could mean and let
    # syslogdb match those too.
    host = filters["host"].strip()
    if host:
        filters["host_ips"] = _syslog_host_ips(service, host)
    # The free-text Search box hits the same gap: any word typed there might
    # be the device name the Host column shows rather than anything the row
    # has stored. Resolve each term long enough to be worth a lookup and let
    # syslogdb match a hit by source address too.
    text_ips = {}
    for term in filters["text"].split():
        fragment = term[:-1] if term.endswith("*") and len(term) > 1 else term
        if len(fragment) >= 3:
            ips = _syslog_host_ips(service, fragment)
            if ips:
                text_ips[term] = ips
    if text_ips:
        filters["text_ips"] = text_ips
    return filters


# Both lookups are leading-% LIKE scans no index can serve, and the Syslog
# tab re-runs its search every couple of seconds while Live is on. Keyed by
# fragment (the Host box, and now every free-text term worth resolving) and
# capped at 8 entries so a page of scrolling searches cannot grow this
# without bound.
_HOST_IP_MEMO: dict = {}
_HOST_IP_MEMO_TTL_S = 5.0
_HOST_IP_MEMO_CAP = 8


def _syslog_host_ips(service, host: str) -> list:
    now = time.time()
    cached = _HOST_IP_MEMO.get(host)
    if cached is not None and now - cached[0] < _HOST_IP_MEMO_TTL_S:
        return list(cached[1])
    ips = set(service.nodes_db.device_ips_by_name(host, SYSLOG_HOST_IP_CAP))
    for row in service.app_db.search_hostnames(host, SYSLOG_HOST_IP_CAP):
        ips.add(row["ip"])
    resolved = sorted(ips)[:SYSLOG_HOST_IP_CAP]
    if host not in _HOST_IP_MEMO and len(_HOST_IP_MEMO) >= _HOST_IP_MEMO_CAP:
        oldest = min(_HOST_IP_MEMO, key=lambda key: _HOST_IP_MEMO[key][0])
        del _HOST_IP_MEMO[oldest]
    _HOST_IP_MEMO[host] = (now, tuple(resolved))
    return resolved


def get_syslog_overview(service, params, body) -> dict:
    """Histogram plus the context the page needs; deliberately cheap."""
    t0, t1, bucket = _hist_window(params)
    filters = _syslog_filters(service, params)

    buckets = service.syslog_db.histogram(t0, t1, bucket, filters)
    stats = service.cached_poll("syslog_stats", 10.0,
                                service.syslog_db.stats)
    # A full-table scan; shared by every open tab. Same 10s TTL as `stats`
    # above (syslog_refresh_s's own default).
    sources = service.cached_poll("syslog_recent_sources", 10.0,
                                  service.syslog_db.sources)
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": buckets,
        "stats": stats,
        "sources": [{"source": row["source"], "count": row["n"],
                     "last_seen": row["last_seen"]}
                    for row in sources],
    }


def _syslog_search_rows(service, params, cap: int, *,
                        use_request_limit: bool = True
                        ) -> tuple[list[dict], bool, float, int, bool]:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    filters = _syslog_filters(service, params)

    started = time.time()
    # The screen's request carries a `limit` this bounds against `cap`. The
    # export handler passes use_request_limit=False instead: the export
    # buttons send no limit at all, so nothing here could tell "the caller
    # wants only 300 rows" from "the caller sent nothing and 300 is the
    # screen's default" — and an export always wants every matching row up
    # to the export ceiling.
    if use_request_limit:
        effective = _page(params, 300, cap)[0]
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

    # The message supplies a host only when the device self-reports one;
    # fill the gap from the Nodes SNMP identity or the DNS cache, Nodes
    # first since it is a locally-managed polled identity rather than a PTR
    # record. Unlike the Source column's resolved name above this always
    # runs: it fills in what the Host column means, rather than being an
    # opt-in display toggle.
    resolved_hosts = {}
    need = {row["source"] for row in rows
            if not row["host"] or row["host"] == row["source"]}
    for ip in need:
        name = namelookup.resolve_name(service.nodes_db, service.app_db, ip)
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
    header = ["time", "id", "ts", "source", "source_name", "host", "app", "procid",
             "msgid", "severity_name", "facility_name", "message"]
    csv_rows = [[_csv_time(m.get("ts"))] + [m.get(key) for key in header[1:]]
               for m in messages]
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

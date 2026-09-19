"""Handlers: SNMP trap search, export and settings."""

from __future__ import annotations

import json
import time

from ...syslogparse import severity_name
from ...trapdecode import GENERIC_NAMES, VERSION_NAMES, enc_octets, format_ticks

from ._shared import EXPORT_ROW_CAP, SEARCH_ROW_CAP, _csv_response, _csv_time, _hist_window, _may_read_secrets, _num, _page


# --------------------------------------------------------------------- snmp

def _snmp_filters(service, params) -> dict:
    filters = {
        "text": params.get("q", ""),
        "severity": params.get("severity") or None,
        "version": params.get("version") or None,
        "kind": params.get("kind", ""),
        "source": params.get("source", ""),
        "oid": params.get("oid", ""),
        "community": params.get("community", ""),
    }
    if not _may_read_secrets(service, params, "snmp"):
        # A caller who may not see the value can't filter on it either --
        # ignored the same as if it were never given.
        filters["community"] = ""
    return filters


def get_snmp_overview(service, params, body) -> dict:
    """Histogram plus the context the page needs; deliberately cheap."""
    t0, t1, bucket = _hist_window(params)
    filters = _snmp_filters(service, params)

    buckets = service.snmp_db.histogram(
        t0, t1, bucket, filters, reveal=_may_read_secrets(service, params, "snmp"))
    stats = service.cached_poll("trap_stats", 10.0,
                                service.snmp_db.stats)
    # Each a full-table scan; shared by every open tab rather than run per
    # request. Same 10s TTL as `stats` above (snmp_refresh_s's own default).
    sources = service.cached_poll("trap_recent_sources", 10.0,
                                  service.snmp_db.recent_sources)
    kinds = service.cached_poll("trap_kind_counts", 10.0, service.snmp_db.kinds)
    return {
        "t0": t0, "t1": t1, "bucket_s": bucket,
        "buckets": buckets,
        "stats": stats,
        "sources": [{"source": row["source"], "count": row["n"],
                     "last_seen": row["last_seen"]}
                    for row in sources],
        "kinds": [{"kind": row["trap_kind"], "count": row["n"]}
                  for row in kinds],
    }


# EXPORT_ROW_CAP is defined once, alongside SEARCH_ROW_CAP above (both
# capped lists — syslog and SNMP traps — share it).
def _snmp_trap_rows(service, params, cap: int, *,
                    use_request_limit: bool = True
                    ) -> tuple[list[dict], bool, float]:
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 86400)
    reveal = _may_read_secrets(service, params, "snmp")
    filters = _snmp_filters(service, params)

    started = time.time()
    # Same use_request_limit reasoning as _syslog_search_rows above: the
    # export path cannot tell an explicit small limit from the screen's
    # own on-screen default arriving unasked, so export ignores the
    # request's limit entirely and always asks for the full cap.
    if use_request_limit:
        effective = _page(params, 300, cap)[0]
    else:
        effective = cap
    rows = service.snmp_db.search(t0, t1, filters, limit=effective + 1, reveal=reveal)
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
            # The sending device's own trap community (its USM user name for
            # v3), so the same rule _community_fields applies to a device's
            # stored community applies here: shown to callers who could
            # change it anyway, a has_community boolean for everyone else.
            # Omitted rather than blanked, like _community_fields, to not read as "carried none".
            **({"community": row["community"] or ""} if reveal else {}),
            "has_community": bool(row["community"]),
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
    header = ["time", "id", "ts", "source", "source_name", "version_name",
             "trap_name", "trap_oid", "trap_kind", "severity_name", "community",
             "agent_addr", "is_inform"]

    # A blank cell would say "carried none" instead of "not shown".
    def _cell(trap, key):
        if key == "time":
            return _csv_time(trap.get("ts"))
        if key == "community" and "community" not in trap:
            return "not shown" if trap.get("has_community") else ""
        return trap.get(key)

    csv_rows = [[_cell(t, key) for key in header] for t in traps]
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
    from ...trapdecode import build_v1_trap, build_v2c_trap

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

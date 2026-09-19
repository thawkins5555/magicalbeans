"""Handlers: the Debug page's worker and queue diagnostics."""

from __future__ import annotations

import time

from ...tracer import expected_budget
from ... import permissions as _permissions
from ..service import STORES, db_for

from ._shared import _num, request_permissions


# -------------------------------------------------------------------- debug


# Which module's grant an event category belongs to. eventlog.CATEGORIES is
# a display taxonomy, not an authorization one, so the mapping is written
# out rather than assumed. The three naming no module go to `settings`:
# `system` carries sign-in history and account changes, `error` every
# module's failure detail, `dns` the addresses the resolver is working
# through.
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


def _debug_can(granted, module: str) -> bool:
    return _permissions.allows(granted.get(module), _permissions.READ)


def _debug_netpath_workers(service, params, granted, now) -> tuple:
    """One row per NetPath destination — its trace and its web page check
    on the same row — plus the running/queued counts."""
    if not _debug_can(granted, "netpath"):
        return [], 0, 0
    state = service.monitor.worker_state()
    schedule = service.monitor.next_runs()
    workers = []
    running = queued = 0
    targets = service.db.targets()
    last_traces = service.db.last_traces([target["id"] for target in targets])
    last_https = service.db.last_https_checks([t["id"] for t in targets])
    https_state = service.https_checker.worker_state()
    https_schedule = service.https_checker.next_runs()
    for target in targets:
        last = last_traces.get(target["id"])
        work = state.get(target["id"])
        keys = target.keys()
        timeout_s = float(target["timeout_s"]) if "timeout_s" in keys else 2.0
        check = last_https.get(target["id"])
        url = str(target["https_url"] or "") if "https_url" in keys else ""
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
            "https": {
                "url": url,
                "state": ("none" if not url or check is None
                          else ("up" if check["ok"] else "down")),
                "checking": target["id"] in https_state,
                "elapsed": (now - (https_state[target["id"]]["started"] or now)
                            if target["id"] in https_state else None),
                "next_run": https_schedule.get(target["id"]),
                "last_run": check["ts"] if check else None,
                "status_code": check["status_code"] if check else None,
                "latency_ms": check["latency_ms"] if check else None,
                "error": (check["error"] or "") if check else "",
            },
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
    return workers, running, queued


def _debug_events(service, params, granted, since) -> tuple:
    """The event batch and the cursor that goes with it. One stream carries
    every module's events, so each category is filtered by the module it
    belongs to rather than by `debug: read` alone."""
    visible = {category for category, module in _EVENT_CATEGORY_MODULE.items()
               if _debug_can(granted, module)}
    # One lock hold for the batch and the cursor that goes with it.
    raw, last_seq = service.log.since_with_seq(since)
    events = [
        {"seq": e.seq, "ts": e.ts, "clock": e.clock, "category": e.category,
         "target": e.target, "message": e.message, "detail": e.detail}
        for e in raw if e.category in visible
    ]
    return events, last_seq


def _debug_dns_workers(service, params, granted, now) -> list:
    """One row per address currently out for a reverse lookup, under
    `settings` — the module _EVENT_CATEGORY_MODULE gives the dns category."""
    dns_state = service.resolver.worker_state() if _debug_can(granted, "settings") else {}
    return sorted(
        [{"ip": ip, "elapsed": now - info["started"]}
         for ip, info in dns_state.items() if info["started"]],
        key=lambda row: row["elapsed"], reverse=True)


def _debug_ipam_workers(service, params, granted, now) -> list:
    """One row per subnet being scanned and one per DHCP server being
    polled: one worker, so one shared table."""
    ipam_state = service.ipam.state() if _debug_can(granted, "ipam") else {}
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
    return ipam_workers


def _debug_node_workers(service, params, granted, now) -> list:
    """One row per device being polled or queued — the NetPath `workers`
    shape without its per-target budget/schedule columns."""
    node_state = service.node_poller.worker_state() if _debug_can(granted, "nodes") else {}
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
    return node_workers


def _debug_discovery_scans(service, params, granted, now) -> list:
    """One row per sweeping discovery scan — the worker-table shape plus
    the probed/found counters a bounded sweep has."""
    see_nodes = _debug_can(granted, "nodes")
    discovery_scans = []
    for job in (service.nodes_db.discovery_jobs(20) if see_nodes else []):
        if job["state"] != "running":
            continue
        discovery_scans.append({
            "label": f"{job['target']} ({job['kind']})",
            "probed": job["probed"], "total": job["total"],
            "responded": job["responded"], "identified": job["identified"],
            "elapsed": now - job["started_ts"],
        })
    discovery_scans.sort(key=lambda row: row["elapsed"], reverse=True)
    return discovery_scans


def _debug_summary(service, params, granted, sections) -> dict:
    """The "is everything running" header, counted from the assembled
    sections."""
    from ...ipam_scan import ping_mode_summary
    ping_mode = ping_mode_summary()
    see_netpath = _debug_can(granted, "netpath")
    return {
        # None, not False/0: an account without `netpath` sees nothing, not a false "stopped".
        "scheduler": service.monitor.running if see_netpath else None,
        "workers_busy": sections["running"],
        "workers_total": service.monitor.workers if see_netpath else None,
        "queued": sections["queued"],
        "resolver": bool(service.resolver._thread
                         and service.resolver._thread.is_alive()),
        "dns_pending": len(sections["dns_workers"]),
        "collector": service.collector.running,
        "packets": service.collector.counters["packets"],
        "ipam": service.ipam.running,
        "ipam_active": len(sections["ipam_workers"]),
        "nodes": service.node_poller.running,
        "nodes_active": len(sections["node_workers"]),
        "discovery_active": len(sections["discovery_scans"]),
        "buffered": len(service.log.all()),
        # Same fact the startup log line states once, kept visible here.
        "ping_path": ping_mode["path"],
        "ping_kind": ping_mode["kind"],
        "ping_mode_env": ping_mode["mode_env"],
    }


def get_debug(service, params, body) -> dict:
    since = int(_num(params, "since", 0, int) or 0)
    now = time.time()

    # Every section below names something from another module, so `debug:
    # read` alone must not read any of them. A section the account cannot
    # read comes back empty rather than as a 403, as get_state does.
    granted = request_permissions(service, params)

    workers, running, queued = _debug_netpath_workers(service, params, granted, now)
    events, last_seq = _debug_events(service, params, granted, since)
    sections = {
        "running": running,
        "queued": queued,
        "dns_workers": _debug_dns_workers(service, params, granted, now),
        "ipam_workers": _debug_ipam_workers(service, params, granted, now),
        "node_workers": _debug_node_workers(service, params, granted, now),
        "discovery_scans": _debug_discovery_scans(service, params, granted, now),
    }

    return {
        "workers": workers,
        "dns_workers": sections["dns_workers"],
        "ipam_workers": sections["ipam_workers"],
        "node_workers": sections["node_workers"],
        # polls/ok/timeout/auth_fail/unsupported/errors/overruns — already
        # computed on every poll, previously never surfaced anywhere.
        "node_counters": (service.node_poller.counters
                          if _debug_can(granted, "nodes") else {}),
        "discovery_scans": sections["discovery_scans"],
        "events": events,
        "last_seq": last_seq,
        "log_epoch": service.log.epoch,
        "capacity": service.log.capacity,
        # A full load gets every target the log knows; a delta stays a delta.
        "targets": (service.log.targets() if since == 0
                    else sorted({e["target"] for e in events if e["target"]})),
        # Every read in this application takes its store's write lock, so
        # `wait_s` here is time the web tier spent queued behind the poller
        # and the collectors on a file WAL would have let it read anyway.
        # Cumulative since start; a rate is two snapshots subtracted.
        "store_locks": _store_locks(service),
        # Per-route request latency, keyed by route pattern rather than by
        # path. The server has always measured this and always thrown it
        # away; it is kept now because it is the only number that says which
        # endpoint is actually slow.
        "routes": _route_latency(service),
        "summary": _debug_summary(service, params, granted, sections),
    }


def _store_locks(service) -> dict:
    """Lock wait and hold per database file, worst waiter first."""
    rows = {}
    for store in STORES:
        db = db_for(service, store)
        stats = getattr(db, "lock_stats", None)
        if db is None or not callable(stats):
            continue
        measured = stats()
        if measured:
            rows[store.name] = {"label": store.label, **measured}
    return dict(sorted(rows.items(),
                       key=lambda kv: kv[1].get("wait_s", 0.0), reverse=True))


def _route_latency(service) -> dict:
    r"""Per-route timing off the access log, slowest total first.

    Bounded by the route table, not by the fleet: one key per pattern, so a
    thousand devices are still one `/api/nodes/devices/(\d+)` row.
    """
    access = getattr(service, "access_log", None) or getattr(service, "access", None)
    snapshot = access.snapshot() if access is not None else {}
    routes = snapshot.get("routes") or {}
    return dict(sorted(routes.items(),
                       key=lambda kv: kv[1].get("total_ms", 0.0), reverse=True))


def post_debug_clear(service, params, body) -> dict:
    service.log.clear()
    return {"last_seq": service.log.last_seq}

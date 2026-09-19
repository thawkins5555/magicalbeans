"""Handlers: Nodes devices, discovery, addresses and bulk import."""

from __future__ import annotations

import csv
import io
import ipaddress
import sqlite3
import re
import time

from ... import alertsdb
from ... import namelookup
from ...eventlog import NODES as NODES_CATEGORY
from ... import trapdecode
from ... import nodeoids
from ... import configrx_redact
from ... import configrx_stanza
from ... import webrelay
from ... import enterprises, mibcatalog, vendorid
from ... import nodepoll
from ... import nodesdb
from ... import permissions as _permissions

from ._shared import Conflict, NotFound, _audit, _audit_diff, _blank_device_override_is_inherit, _bulk_device_ids, _clean_priv_proto, _clean_web_fields, _community_fields, _csv_response, _device_display_name, _devices_for_rows, _discovery_duplicate, _discovery_identification, _fleet_counts, _group_credential_json, _maintenance_json, _matched_device_names, _may_read_secrets, _neighbor_local_port_labeler, _num, _page, _pick, _planned_scope, _refuse_orphaned_v3_secret, _require, _series_bucket_s, _tri, _v3_level_fields, _window, request_permissions


# -------------------------------------------------------------------- nodes


# The community string travels in the clear in every packet the protocol
# defines, so it is not a secret in the sense a password is — and it is
# still the only access control on many industrial devices, where the v2c
# community is what a PLC or RTU checks before answering, and sometimes
# before accepting a write. Handing every community in the estate to every
# read-only Nodes account is a lateral-movement gift regardless of what the
# wire already leaks. The value is shown to callers who could change it
# anyway (module WRITE); everyone else gets `has_community`, the same
# reduction `v3_auth_pass_enc` already gets.
# Every store column whose value IS a secret — not a boolean about one. A
# serialiser that names one owes the caller a `reveal` decision
# (_may_read_secrets); the encrypted blobs never leave the process at all.
# Deliberately NOT here: has_* booleans, `username`/`ssh_username`, and
# compliance's `pattern`, which _compliance_rule_json gates for itself.
SECRET_COLUMNS = frozenset({
    "community", "community_or_user", "password", "password_enc",
    "token_hash", "v3_auth_pass_enc", "v3_priv_pass_enc", "auth_pass_enc",
    "ssh_password_enc", "enable_secret_enc",
})


def _device_json(row, reveal: bool = False) -> dict:
    overrides = nodesdb.override_fields(row)
    return {
        "id": row["id"], "ip": row["ip"], "name": row["name"],
        "group_id": row["group_id"], "device_group_id": row["device_group_id"],
        "display_name_source": row["display_name_source"],
        "enabled": bool(row["enabled"]),
        "override_fields": list(overrides), "override_count": len(overrides),
        "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        **_v3_level_fields(row),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"],
        "snmp_retries": row["snmp_retries"],
        "ping_enabled": _tri(row["ping_enabled"]),
        "snmp_enabled": _tri(row["snmp_enabled"]),
        "oid_set": row["oid_set"], "mib_file_id": row["mib_file_id"],
        "mib_file_auto": bool(row["mib_file_auto"]) if "mib_file_auto" in row.keys() else False,
        "ping_count": row["ping_count"], "ping_timeout_ms": row["ping_timeout_ms"],
        "unreachable_ping_only": row["unreachable_ping_only"],
        "mac_table_interval_s": row["mac_table_interval_s"],
        # The same inherit-via-NULL override columns mac_table_interval_s
        # models, read defensively for a row fetched before the migration
        # that added them has run.
        "lldp_interval_s": (row["lldp_interval_s"] if "lldp_interval_s" in row.keys() else None),
        # Per-port VLAN membership walk interval, inheritable and defensively
        # keyed the same way lldp_interval_s immediately above is -- added in
        # the same migration, read the same way for a row from before it ran.
        "vlan_interval_s": (row["vlan_interval_s"] if "vlan_interval_s" in row.keys() else None),
        # ARP-cache walk interval: the same inherit-via-NULL override as the
        # three above, defensively keyed for the same reason, and the one
        # whose _merge_config fallback is 0 rather than an hour (see there).
        "arp_table_interval_s": (row["arp_table_interval_s"] if "arp_table_interval_s" in row.keys() else None),
        "poe_enabled": (_tri(row["poe_enabled"]) if "poe_enabled" in row.keys() else None),
        "stp_enabled": (_tri(row["stp_enabled"]) if "stp_enabled" in row.keys() else None),
        # The capability probe's verdict — True/False once probed, None
        # until the first poll gets to it — and, once stp_capable is true,
        # the bridge-wide state the device pane's BRIDGE & RF subtab reads.
        # Per-port PoE power and STP state live on the interfaces rows
        # instead (see get_nodes_device_interfaces); the topology-change
        # COUNT is a metric with history (see get_nodes_device_metrics), not a column
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
        # The device's own default-route next hop(s) — see nodepoll.
        # _refresh_default_gateway — comma-joined when more than one, "" when
        # unset or the last read found none.
        "default_gateway": ((row["default_gateway"] or "")
                            if "default_gateway" in row.keys() else ""),
        # sw_image_file is Cisco's boot image path, not a version.
        "sw_version": (row["sw_version"] if "sw_version" in row.keys() else None),
        "fw_version": (row["fw_version"] if "fw_version" in row.keys() else None),
        "sw_image": (row["sw_image"] if "sw_image" in row.keys() else None),
        "sw_image_file": (row["sw_image_file"] if "sw_image_file" in row.keys() else None),
        "sw_source": (row["sw_source"] if "sw_source" in row.keys() else None),
        "fw_source": (row["fw_source"] if "fw_source" in row.keys() else None),
        "status": row["status"], "ping_ok": _tri(row["ping_ok"]),
        "ping_rtt_ms": row["ping_rtt_ms"], "snmp_ok": _tri(row["snmp_ok"]),
        "snmp_error": row["snmp_error"], "consecutive_fail": row["consecutive_fail"],
        "last_poll_ts": row["last_poll_ts"], "last_up_ts": row["last_up_ts"],
        "last_down_ts": row["last_down_ts"],
        "last_uptime_ticks": row["last_uptime_ticks"],
        "last_uptime_ts": row["last_uptime_ts"], "created_ts": row["created_ts"],
        "status_since_ts": _status_since(row),
        "sys_uptime_s": _sys_uptime_s(row),
        # Web-interface fields for the WEB relay, keyed defensively for a
        # pre-migration row. `web_port_effective` is resolved here so the
        # form can show a placeholder without repeating the 80/443 rule.
        "web_scheme": (row["web_scheme"] if "web_scheme" in row.keys() else None),
        "web_port": (row["web_port"] if "web_port" in row.keys() else None),
        "web_port_effective": _web_port_effective(row),
    }


def _web_port_effective(row) -> int:
    """The port the relay dials for this device. Resolved by webrelay, the
    module that actually dials it, so the form's placeholder and the
    relay's destination cannot disagree."""
    return webrelay.device_web_target(row)[2]


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
        **_v3_level_fields(row),
        "poll_interval_s": row["poll_interval_s"],
        "snmp_timeout_s": row["snmp_timeout_s"], "snmp_retries": row["snmp_retries"],
        "ping_enabled": bool(row["ping_enabled"]), "snmp_enabled": bool(row["snmp_enabled"]),
        "oid_set": row["oid_set"], "mib_file_id": row["mib_file_id"],
        "ping_count": row["ping_count"], "ping_timeout_ms": row["ping_timeout_ms"],
        "unreachable_ping_only": row["unreachable_ping_only"],
        "mac_table_interval_s": row["mac_table_interval_s"],
        # Per-port VLAN membership walk interval, the group/profile side of
        # the same override device rows expose (see _device_json) — a
        # profile's own value here is what an inheriting device's blank
        # override falls back to (nodesdb._merge_config), so the front end
        # needs it to show what "inherit" actually means, the same reason
        # mac_table_interval_s is already here.
        "vlan_interval_s": (row["vlan_interval_s"] if "vlan_interval_s" in row.keys() else None),
        # ARP-cache walk interval, for the same "show what inherit means"
        # reason as vlan_interval_s immediately above.
        "arp_table_interval_s": (row["arp_table_interval_s"] if "arp_table_interval_s" in row.keys() else None),
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


def _discovery_result_json(row, installed=None, devices_by_ip=None,
                           index=None, reveal: bool = False) -> dict:
    """`installed` is the set of MIB filenames present, and `devices_by_ip`
    an ip -> device row map, each passed by the caller once per listing so
    neither the MIB hint nor the already-added check is a query per row.
    `promoted_device_id` alone missed an address added to Nodes some other
    way — by hand, or from an earlier scan — so `devices_by_ip` is checked
    too; either source wins because promote() always reuses that same row.

    `index` adds the duplicate verdict, on the probed address alone.

    `community_or_user` is the credential that actually answered this
    address, so it follows _community_fields' rule rather than riding out
    with the rest of the row: omitted (not blanked, which would read as
    "the scan found none") for a caller without Nodes write, which gets
    `has_community_or_user` instead."""
    existing = devices_by_ip.get(row["ip"]) if devices_by_ip else None
    existing_id = existing["id"] if existing else row["promoted_device_id"]
    existing_name = _device_display_name(existing) if existing else None
    return {"id": row["id"], "job_id": row["job_id"], "ip": row["ip"],
            "ping_ok": bool(row["ping_ok"]), "snmp_ok": bool(row["snmp_ok"]),
            "has_community_or_user": bool(row["community_or_user"]),
            **({"community_or_user": row["community_or_user"]} if reveal else {}),
            "snmp_version": row["snmp_version"], "sys_descr": row["sys_descr"],
            "sys_name": row["sys_name"], "sys_object_id": row["sys_object_id"],
            "vendor": row["vendor"], "suggested_group_id": row["suggested_group_id"],
            "promoted_device_id": row["promoted_device_id"],
            "existing_device_id": existing_id,
            "existing_device_name": existing_name,
            **_discovery_duplicate(row, index),
            **_discovery_identification(row, installed)}


_DEVICE_EDITABLE_BODY = ("name", "group_id", "device_group_id",
                         "display_name_source", "enabled",
                         "snmp_version", "community",
                         "v3_user", "v3_auth_proto", "v3_priv_proto", "poll_interval_s",
                         "snmp_timeout_s", "snmp_retries", "ping_enabled",
                         "snmp_enabled", "oid_set", "mib_file_id",
                         "ping_count", "ping_timeout_ms", "unreachable_ping_only",
                         "vendor_oid", "location_oid", "mac_table_interval_s",
                         "vlan_interval_s", "arp_table_interval_s",
                         "vendor_override", "upstream_id",
                         # Per-device, never inherited (nodesdb._DEVICE_ONLY_COLUMNS)
                         # — absent from _GROUP_EDITABLE_BODY below on purpose.
                         "web_scheme", "web_port")


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
    # The per-method timeline kinds are left out: an outage already counts
    # once as `down`, and counting its snmp_down/ping_down too would triple
    # every bar (and spend the read's row limit three times as fast).
    events = service.nodes_db.device_events(
        since_s=max(0.0, time.time() - t0),
        exclude_kinds=tuple(nodesdb.TIMELINE_ONLY_EVENT_KINDS))
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
        "device_counts": _fleet_counts(service)[0],
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
        "overrides_only": params.get("overrides_only") is not None,
    }


def _maintenance_only_ids(service, params):
    """The device ids to restrict the list to when `maintenance_only` is
    present, or None when it is not.

    Server-side, because the list is paged at DEVICE_LIST_DEFAULT_LIMIT: a
    page filtered after the fact would hand back fewer rows than it asked
    for and a `total` that did not describe them. The ids come from
    alerts.db, which nodesdb cannot join against — two files — so they are
    read here and passed down as an id clause.
    """
    if params.get("maintenance_only") is None:
        return None
    # Windows count here as well as in the Dashboard figure: "in maintenance"
    # has to mean the same thing in the filter as in the number that links to
    # it, or the count and the list it opens disagree.
    ids, group_ids = _planned_scope(service)
    if not ids and not group_ids:
        return []
    return sorted(service.nodes_db.device_ids(only_ids=ids,
                                              device_group_ids=group_ids))


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
    # Its OWN field, never folded into muted_until: maintenance mode has no
    # until_ts, and anything rendering muted_until prints "muted until <a
    # date>" — an operator handed a date that never arrives waits for it.
    maintenance = service.alerts_db.maintenance_device_ids()
    # A count, not a list: the row only has room for "2 alerts muted".
    rule_muted_counts: dict[int, int] = {}
    for entity_id in service.alerts_db.muted_entity_ids(alertsdb.DEVICE_RULE_KIND):
        pair = alertsdb.split_device_rule(entity_id)
        if pair is not None:
            rule_muted_counts[pair[0]] = rule_muted_counts.get(pair[0], 0) + 1
    # A device merged into another keeps the address it was entered under as
    # an alias, and the list is where an operator looks for that address —
    # so the whole set rides along, in one read for the page rather than one
    # per row.
    aliases = service.nodes_db.addresses_for_devices(row["id"] for row in rows)
    reveal = _may_read_secrets(service, params, "nodes")
    devices = []
    for row in rows:
        device = _device_json(row, reveal)
        device["polling"] = row["id"] in worker_state
        device["muted_until"] = muted.get(str(row["id"]))
        device["rule_muted_count"] = rule_muted_counts.get(row["id"], 0)
        maint_row = maintenance.get(str(row["id"]))
        device["maintenance"] = _maintenance_json(maint_row) if maint_row else None
        device["addresses"] = _device_addresses_json(
            row, aliases.get(row["id"], ()))
        devices.append(device)
    return devices


_DEVICE_INDEX_FIELDS = ("id", "ip", "name", "sys_name", "display_name_source",
                        "device_group_id", "status")


def _device_index_rows_json(service, params, rows) -> list[dict]:
    """The seven columns a device lookup table needs, and nothing else —
    no per-row mute/maintenance/alias reads, no sys_descr, no credential
    fields for _may_read_secrets to decide about."""
    return [{field: row[field] for field in _DEVICE_INDEX_FIELDS} for row in rows]


# Paging here is opt-in, not the default: a caller that sends neither
# `limit` nor `offset` still gets the whole fleet back, because nothing here
# can be sure it is the only caller (test_frontend_contracts.py and tests/ui/
# pin the no-params shape). nodes.js is the caller on the paged form, and
# DEVICE_LIST_DEFAULT_LIMIT is its page size.
DEVICE_LIST_DEFAULT_LIMIT = 500
DEVICE_LIST_MAX_LIMIT = 2000


def get_nodes_devices(service, params, body) -> dict:
    filters = _device_filters(params)
    only_ids = _maintenance_only_ids(service, params)
    if only_ids is not None:
        # Nothing is in maintenance mode: answered here rather than by
        # nodesdb, whose id clause has no valid SQL for an empty set.
        if not only_ids:
            return {"devices": [], "total": 0}
        filters["only_ids"] = only_ids
    total = service.nodes_db.devices_count(**filters)
    # `fields=index` is app.js's shared ip->device / id->device cache, which
    # reads seven columns and was being handed the whole 25-column row for
    # every device in the fleet, every thirty seconds, per open tab. Paging
    # is unchanged; only the projection differs.
    to_json = (_device_index_rows_json if params.get("fields") == "index"
               else _device_rows_json)
    if params.get("limit") is None and params.get("offset") is None:
        rows = service.nodes_db.devices(**filters)
        return {"devices": to_json(service, params, rows), "total": total}
    limit, offset = _page(params, DEVICE_LIST_DEFAULT_LIMIT, DEVICE_LIST_MAX_LIMIT)
    rows = service.nodes_db.devices(limit=limit, offset=offset, **filters)
    return {"devices": to_json(service, params, rows),
            "total": total, "limit": limit, "offset": offset}


_DEVICE_CSV_HEADER = ["id", "name", "ip", "status", "group_id", "device_group_id",
                     "vendor", "sys_descr", "sys_name", "polling", "muted_until",
                     "maintenance_since", "poll_interval_s", "last_poll_ts",
                     "override_count", "addresses",
                     "sw_version", "sw_image", "sw_image_file", "fw_version",
                     "uptime_s"]


def get_nodes_devices_export(service, params, body) -> dict:
    """The Devices table's current filter, unpaged and uncapped: a CSV
    export exists to leave with everything that matched, not one page of
    it, and nodes_db.devices() already has no limit of its own to lift."""
    filters = _device_filters(params)
    only_ids = _maintenance_only_ids(service, params)
    if only_ids is not None:
        if not only_ids:
            return _csv_response("devices", _DEVICE_CSV_HEADER, [])
        filters["only_ids"] = only_ids
    rows = service.nodes_db.devices(**filters)
    devices = _device_rows_json(service, params, rows)
    header = _DEVICE_CSV_HEADER
    csv_rows = [[d.get("id"), _device_display_name(d), d.get("ip"), d.get("status"),
                d.get("group_id"), d.get("device_group_id"), d.get("vendor"),
                d.get("sys_descr"), d.get("sys_name"), d.get("polling"),
                d.get("muted_until"),
                (d.get("maintenance") or {}).get("started_ts"),
                d.get("poll_interval_s"), d.get("last_poll_ts"),
                d.get("override_count"),
                ", ".join(a["ip"] for a in d.get("addresses") or ()),
                d.get("sw_version"), d.get("sw_image"), d.get("sw_image_file"),
                d.get("fw_version"), d.get("sys_uptime_s")]
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
    rows = service.nodes_db.mac_locations(mac)
    devices = _devices_for_rows(service, rows)
    locations = [_mac_location_json(row, devices[row["device_id"]])
                for row in rows if row["device_id"] in devices]
    # How many devices are actually walking their forwarding tables, so the
    # frontend can say "nothing has been learned yet" rather than "not
    # found" when the feature is simply switched off everywhere. One query,
    # not effective_config() per device — this runs on a keystroke.
    return {"mac": mac, "locations": locations,
            "enabled_devices": service.nodes_db.mac_walk_enabled_count(),
            "retention_days": float(
                service.nodes_settings.get("mac_table_retention_days", 7))}


def get_nodes_arp_search(service, params, body) -> dict:
    """Where an IP or a MAC appears in the stored ARP caches — the other
    half of the MAC search above. The forwarding table says which PORT a
    MAC is on; the ARP cache says which IP that MAC holds (or which MAC
    an IP resolves to), on which routed interface of which router. An
    operator with only an address in hand joins the two here: ARP gives
    the MAC, then the MAC search gives the port.

    The needle is whatever was typed; nodesdb.arp_locations decides
    whether it is a MAC prefix, an address prefix or both (a colon-hex
    prefix is either), and answers [] for anything it refuses, so this
    never has to second-guess it. Every (device, interface) hit comes
    back rather than one picked here, for the reason the MAC search gives.
    """
    needle = (params.get("q") or "").strip()
    rows = service.nodes_db.arp_locations(needle)
    devices = _devices_for_rows(service, rows)
    locations = []
    for row in rows:
        device = devices.get(row["device_id"])
        if device is None:
            continue
        locations.append(_arp_json(
            row, device_name=namelookup.device_name(device),
            if_descr=row["if_descr"] or f"Interface {row['if_index']}"))
    # Chain to the switch port only for rows matched by address: a MAC
    # needle's ports are already the MAC group's answer.
    lowered = needle.lower()
    ports = []
    macs, ips_for_mac = [], {}
    for row in rows:
        mac, ip = row["mac"], row["ip"]
        if not mac or not str(ip or "").lower().startswith(lowered):
            continue
        if mac not in ips_for_mac:
            if len(macs) >= 8:
                continue
            ips_for_mac[mac] = []
            macs.append(mac)
        # A MAC that answers to more than one matched address (a router with
        # secondaries, say) names all of them, not just the first row seen —
        # capped at four so a busy MAC does not turn one port row into a
        # paragraph.
        ip_list = ips_for_mac[mac]
        if ip not in ip_list and len(ip_list) < 4:
            ip_list.append(ip)
    port_rows = service.nodes_db.mac_locations_for(macs) if macs else []
    if port_rows:
        port_devices = _devices_for_rows(service, port_rows)
        for row in port_rows:
            device = port_devices.get(row["device_id"])
            if device is None:
                continue
            ports.append({**_mac_location_json(row, device),
                          "ip": ", ".join(ips_for_mac.get(row["mac"], []))})
    # How many devices walk their ARP cache at all — off is the shipped
    # default here, so "not found" and "nobody is collecting this" are
    # different sentences far more often than for the MAC table. One
    # query, for the reason mac_walk_enabled_count gives.
    return {"needle": needle, "locations": locations, "ports": ports,
            "enabled_devices": service.nodes_db.arp_walk_enabled_count(),
            "retention_days": float(
                service.nodes_settings.get("mac_table_retention_days", 7))}


def _mac_location_json(row, device) -> dict:
    """One mac_locations/mac_locations_for row as the MAC search and the
    ARP-chained port group both spell it — one shape, so the two cannot
    drift on a field name."""
    return {
        "device_id": row["device_id"],
        "device_name": namelookup.device_name(device),
        "if_index": row["if_index"],
        "if_descr": row["if_descr"] or f"Interface {row['if_index']}",
        "mac": row["mac"], "vlan": row["vlan"], "seen_ts": row["seen_ts"],
        "first_seen_ts": row["first_seen_ts"],
        "present": bool(row["present"]),
        "uplink": bool(row["uplink"]), "uplink_to": row["uplink_to"],
    }


def _arp_json(row, **extra) -> dict:
    """One arp_entries row as every ARP route spells it, plus whatever the
    route knows that the row does not — the detail pane's local_port, the
    search's device_name and if_descr. One shape, so the two cannot drift
    on a field name."""
    return {
        "device_id": row["device_id"], "if_index": row["if_index"],
        **extra,
        "ip": row["ip"], "mac": row["mac"], "entry_type": row["entry_type"],
        "seen_ts": row["seen_ts"], "first_seen_ts": row["first_seen_ts"],
        "present": bool(row["present"]),
    }


def get_nodes_device_arp(service, params, body, device_id) -> dict:
    """One device's whole stored ARP cache, present and stale alike, for
    the detail pane's ARP subtab — the neighbours read's shape, with the
    same local-port labeller so a row names "Vlan10" rather than "if 7".

    `enabled` and `interval_s` say whether this device walks its cache at
    all, resolved through effective_config: the browser holds the device's
    own override and its profile's value separately and cannot tell "blank
    here, 900 on the profile" from "blank everywhere", so an empty table
    would read the same whether the walk is off or simply has not run
    yet. The server knows; it says."""
    row = _require(service.nodes_db.device(device_id), "device")
    interval = int(service.nodes_db.effective_config(row).get("arp_table_interval_s") or 0)
    label = _neighbor_local_port_labeler(service)
    return {"entries": [_arp_json(r, local_port=label(device_id, r["if_index"]))
                        for r in service.nodes_db.arp_entries_for(device_id)],
            "enabled": interval > 0, "interval_s": interval}


def get_nodes_device_arp_export(service, params, body, device_id) -> dict:
    """One device's ARP table, exported — bounded by that one cache, the
    same way the neighbours export beside it is bounded by port count.
    A core router's cache runs to tens of thousands of rows, which is
    still one device's table and well inside what a CSV download is for."""
    entries = get_nodes_device_arp(service, params, body, device_id)["entries"]
    header = ["if_index", "local_port", "ip", "mac", "entry_type", "present",
              "seen_ts", "first_seen_ts"]
    csv_rows = [[e.get(key) for key in header] for e in entries]
    return _csv_response("arp-table", header, csv_rows)


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
        "matched_device_ip": row["matched_device_ip"] if "matched_device_ip" in keys else None,
        "resolved_name": None,
        "resolved_source": "",
    }


def _resolve_neighbor_names(service, neighbors: list[dict]) -> None:
    """Names every neighbour row with the chain Reports and the mapper use:
    a row _NEIGHBOR_MATCH_SQL already matched gets its matched_device_name
    replaced by the chain's name; a row it left unmatched is looked up by
    address (nodesdb.neighbour_device_matches, shared with the mapper) and,
    failing that, named from the reverse-DNS cache -- the Syslog Host
    column's own order."""
    if service.nodes_db is None:
        return

    ip_matches = service.nodes_db.neighbour_device_matches(
        neighbors, nodepoll.neighbor_ip_candidates)
    for index, device in ip_matches.items():
        neighbor = neighbors[index]
        neighbor["matched_device_id"] = device["id"]
        neighbor["matched_device_ip"] = device["ip"]
        neighbor["resolved_source"] = "nodes"

    names = _matched_device_names(
        service, (n.get("matched_device_id") for n in neighbors))
    for neighbor in neighbors:
        device_id = neighbor.get("matched_device_id")
        if device_id in names:
            name = names[device_id]
            neighbor["matched_device_name"] = name
            if neighbor.get("resolved_source") == "nodes":
                neighbor["resolved_name"] = name

    unresolved_ips: set = set()
    for neighbor in neighbors:
        if neighbor.get("matched_device_id") is None:
            unresolved_ips.update(nodepoll.neighbor_ip_candidates(neighbor))
    if not unresolved_ips:
        return
    names = service.app_db.hostnames(sorted(unresolved_ips))
    for neighbor in neighbors:
        if neighbor.get("matched_device_id") is not None:
            continue
        for ip in nodepoll.neighbor_ip_candidates(neighbor):
            if names.get(ip):
                neighbor["resolved_name"] = names[ip]
                neighbor["resolved_source"] = "dns"
                break


def get_nodes_device_neighbors(service, params, body, device_id) -> dict:
    """The LLDP/CDP neighbours seen on one device's own ports — protocol,
    local/remote port, the remote sysName, and the best-effort device match
    nodesdb.neighbours_of already computes — for the detail pane's
    Neighbours section. Present and stale rows both come back (see
    replace_neighbors' ageing scheme); the client marks a stale one rather
    than this route filtering it out, the same choice get_nodes_device_
    events makes for interface events."""
    _require(service.nodes_db.device(device_id), "device")
    rows = service.nodes_db.neighbours_of(device_id)
    label = _neighbor_local_port_labeler(service)
    neighbors = [_neighbor_json(r, label(device_id, r["if_index"])) for r in rows]
    _resolve_neighbor_names(service, neighbors)
    return {"neighbors": neighbors}


def get_nodes_device_neighbors_export(service, params, body, device_id) -> dict:
    """One device's own Neighbours table, exported — bounded by its own
    port count like the interfaces export beside it, so there is no export
    ceiling to lift here either."""
    neighbors = get_nodes_device_neighbors(service, params, body, device_id)["neighbors"]
    header = ["if_index", "local_port", "protocol", "chassis_id", "sys_name",
             "port_id", "platform", "remote_address", "matched_device_id",
             "matched_device_name", "matched_device_ip", "present", "seen_ts",
             "first_seen_ts", "resolved_name", "resolved_source"]
    csv_rows = [[n.get(key) for key in header] for n in neighbors]
    return _csv_response("neighbours", header, csv_rows)


# ------------------------------------------------------ upstream suggestions
#
# The neighbour-match join above is a best-effort guess, and only an
# operator-confirmed devices.upstream_id may drive ROLLED_UP_BY's
# downstream-outage suppression (see alertrules.py). These two routes are how
# an operator confirms one at fleet scale: a read route listing the
# suggestions with their evidence, and a write route applying a reviewed
# batch. Nothing here ever applies a suggestion by itself.
UPSTREAM_SUGGESTIONS_DEFAULT_LIMIT = 500
UPSTREAM_SUGGESTIONS_MAX_LIMIT = 2000


def _upstream_suggestion_json(service, label, suggestion: dict,
                              rows: dict | None = None) -> dict:
    # `rows` is the page's device rows read in one devices_by_ids, the way
    # the port labels beside them are already batched; without it this was a
    # device() — one nodes.db lock — per suggestion, up to the page cap.
    device = (rows.get(suggestion["device_id"]) if rows is not None
              else service.nodes_db.device(suggestion["device_id"]))
    candidates = []
    for candidate in suggestion["candidates"]:
        candidates.append({
            "matched_device_id": candidate["matched_device_id"],
            "matched_device_name": candidate["matched_device_name"],
            "match_kind": candidate["match_kind"],
            "protocols": candidate["protocols"],
            "local_if_index": candidate["if_index"],
            "local_port": label(suggestion["device_id"], candidate["if_index"]),
            "present": candidate["present"],
            "stale": not candidate["present"],
            "seen_ts": candidate["seen_ts"],
            "first_seen_ts": candidate["first_seen_ts"],
            "confidence": candidate["confidence"],
            "confidence_rank": candidate["confidence_rank"],
        })
    return {
        "device_id": suggestion["device_id"],
        "device_name": namelookup.device_name(device) if device else None,
        "device_ip": device["ip"] if device else None,
        "ambiguous": suggestion["ambiguous"],
        "candidates": candidates,
    }


def _suggestion_device_rows(service, suggestions) -> dict:
    return {d["id"]: d for d in service.nodes_db.devices_by_ids(
        {s["device_id"] for s in suggestions})}


def get_nodes_upstream_suggestions(service, params, body) -> dict:
    """Candidate devices.upstream_id assignments for an operator to review
    and accept — one entry per device with no upstream_id yet whose own
    LLDP/CDP neighbour rows matched at least one other enabled device (see
    nodesdb.upstream_suggestions for the evidence and confidence each
    candidate carries). A device with more than one plausible match comes
    back with `ambiguous: true` and every candidate listed, rather than
    this route picking one for the operator.

    Paged the same way get_nodes_devices is: no `limit`/`offset` in the
    query gets everything (there is nothing yet pinned against a no-params
    shape here the way get_nodes_devices' docstring worries about, but the
    two routes are kept symmetric on principle), and `limit`/`offset` page
    the device list — there can be hundreds of these at fleet scale.
    """
    total = service.nodes_db.upstream_suggestions_count()
    label = _neighbor_local_port_labeler(service)
    if params.get("limit") is None and params.get("offset") is None:
        suggestions = service.nodes_db.upstream_suggestions()
        rows = _suggestion_device_rows(service, suggestions)
        return {"suggestions": [_upstream_suggestion_json(service, label, s, rows)
                                for s in suggestions],
                "total": total}
    limit, offset = _page(params, UPSTREAM_SUGGESTIONS_DEFAULT_LIMIT,
                          UPSTREAM_SUGGESTIONS_MAX_LIMIT)
    suggestions = service.nodes_db.upstream_suggestions(limit=limit, offset=offset)
    rows = _suggestion_device_rows(service, suggestions)
    return {"suggestions": [_upstream_suggestion_json(service, label, s, rows)
                            for s in suggestions],
            "total": total, "limit": limit, "offset": offset}


UPSTREAM_APPLY_MAX_ASSIGNMENTS = 2000


def _upstream_assignment_pairs(body) -> dict:
    """body["assignments"]: [{"device_id", "upstream_id"}, ...] -> a dict
    keyed by device_id, values not yet validated. A device_id repeated in
    the same batch collapses to its LAST entry — the same "last one wins"
    a form re-submitting the same row would produce — rather than being
    treated as a conflict the operator has to know to avoid."""
    raw = body.get("assignments")
    if not isinstance(raw, list) or not raw:
        raise ValueError("assignments is required")
    if len(raw) > UPSTREAM_APPLY_MAX_ASSIGNMENTS:
        raise ValueError(
            f"at most {UPSTREAM_APPLY_MAX_ASSIGNMENTS} assignments at once")
    pairs = {}
    for entry in raw:
        if not isinstance(entry, dict) or "device_id" not in entry:
            raise ValueError("each assignment needs a device_id")
        try:
            device_id = int(entry["device_id"])
        except (TypeError, ValueError):
            raise ValueError("device_id must be a device id") from None
        pairs[device_id] = entry.get("upstream_id")
    return pairs


def _find_upstream_cycle(service, overrides: dict, rows: dict | None = None) -> list | None:
    """Whether `overrides` (device_id -> new, already-cleaned upstream_id),
    applied on top of what is on file for every OTHER device, would create
    a cycle reachable from any device this batch touches. Returns the
    cycle's device ids, nearest-first, or None.

    _clean_upstream_id already refuses a single device pointed at itself;
    what it cannot see is a batch where device A's upstream becomes B and,
    in the SAME batch, B's becomes A — each pair valid alone, only the two
    together forming a cycle. Walking every touched device's own upstream
    chain under the proposed values (falling back to the stored value for
    a device the batch does not mention) catches that. This only runs
    against an operator-submitted batch, not the alert engine's hot path
    upstream_chain protects with its own max_depth=8, so it can afford to
    walk as far as the whole fleet before concluding there is no cycle,
    rather than risk missing one longer than eight levels the way that
    cap would.
    """
    rows = rows or {}

    def upstream_of(device_id):
        if device_id in overrides:
            return overrides[device_id]
        row = rows.get(device_id)
        if row is None:
            row = service.nodes_db.device(device_id)
        return int(row["upstream_id"]) if row and row["upstream_id"] is not None else None

    ceiling = service.nodes_db.device_count() + 1
    for start in overrides:
        chain = [start]
        seen = {start}
        current = start
        for _ in range(ceiling):
            parent = upstream_of(current)
            if parent is None:
                break
            if parent in seen:
                return chain[chain.index(parent):]
            chain.append(parent)
            seen.add(parent)
            current = parent
    return None


def post_nodes_upstream_suggestions_apply(service, params, body) -> dict:
    """The write side of the upstream-suggestions review flow: a batch of
    {"device_id", "upstream_id"} pairs an operator has looked at and
    accepted (upstream_id may be null/0/"" to mean "leave unset" — see
    _clean_upstream_id), applied together in one transaction.

    Nothing here ever chooses a suggestion on its own — there is no
    "high confidence means apply it for me" path anywhere in this route,
    on purpose. alertrules.py's ROLLED_UP_BY comment is explicit that
    driving alert suppression off an unconfirmed neighbour match is the
    one failure mode this application must not have; the operator's
    review, not this route, is what turns a guess into something
    alertrules.py may trust.

    Every pair is validated exactly as a single PUT .../devices/<id> would
    (_clean_upstream_id: the device and its proposed upstream both exist,
    neither points a device at itself), and then the WHOLE batch's
    resulting graph is checked for a cycle no individual pair could show
    (_find_upstream_cycle) — a batch that would create one is refused
    outright, naming the devices involved, rather than applying the
    assignments that happen not to be part of it.
    """
    pairs = _upstream_assignment_pairs(body)
    # Every device this batch names, and every device it points at, in one
    # read: the batch cap is 2,000 assignments and each one used to cost
    # three single-row queries, each taking the nodes.db write lock.
    wanted = set(pairs)
    for value in pairs.values():
        if value not in (None, "", 0, "0"):
            try:
                wanted.add(int(value))
            except (TypeError, ValueError):
                pass
    rows = {d["id"]: d for d in service.nodes_db.devices_by_ids(wanted)}
    for device_id in pairs:
        if device_id not in rows:
            # A body field, not the addressed resource: 400, like the profile
            # and group references bulk update refuses.
            raise ValueError(f"No such device {device_id}")
    cleaned = {device_id: _clean_upstream_id(service, device_id, upstream_id, rows)
              for device_id, upstream_id in pairs.items()}
    cycle = _find_upstream_cycle(service, cleaned, rows)
    if cycle:
        raise ValueError(
            "This would create an upstream cycle through device(s): "
            + " -> ".join(str(device_id) for device_id in cycle))
    service.nodes_db.set_upstream_ids(cleaned)
    service.log.add(NODES_CATEGORY,
                    f"Applied {len(cleaned)} upstream suggestion(s)")
    return {"ok": True, "updated": len(cleaned)}


def _duplicate_conflict(service, ip: str) -> Conflict | None:
    """A 409, not a 400, for an address that's already a known alias:
    adding a router's second address as a second device is the mistake
    this release exists to stop, but it's occasionally what an operator
    means, so the payload names the device and the caller may say `force`.
    A collision with a device's own primary IP stays a plain 400 — the
    UNIQUE index would refuse it regardless of `force`.
    """
    if service.nodes_db.device_by_ip(ip):
        raise ValueError(f"{ip} is already a device")
    owner = service.nodes_db.device_id_for_address(ip, configured=True)
    device = service.nodes_db.device(owner) if owner else None
    if device is None:
        return None
    reason = (f"{ip} is another address of "
              f"{_device_display_name(device)} ({device['ip']})")
    return Conflict(reason, {"duplicate_of": {
        "device_id": device["id"], "device_name": _device_display_name(device),
        "device_ip": device["ip"], "reason": reason}})


def post_nodes_device(service, params, body) -> dict:
    ip = _device_address(body)
    conflict = _duplicate_conflict(service, ip)
    if conflict is not None and not body.get("force"):
        raise conflict
    group_id = body.get("group_id")
    device_group_id = body.get("device_group_id")
    _check_display_name_source(body)
    # The same two fields put_nodes_device handles specially, validated
    # before the insert so a refused value does not leave a half-configured
    # device behind (0 is never a device id, and a device cannot be its own
    # upstream before it exists).
    upstream_id = (_clean_upstream_id(service, 0, body["upstream_id"])
                   if "upstream_id" in body else None)
    vendor_override = str(body.get("vendor_override") or "").strip()
    if len(vendor_override) > 64:
        raise ValueError("A vendor name is at most 64 characters")
    overrides = {k: v for k, v in body.items() if k in _DEVICE_EDITABLE_BODY
                and k not in ("name", "group_id", "device_group_id",
                              "display_name_source", "enabled",
                              "vendor_override", "upstream_id")}
    # Validated before the insert, like upstream_id above and for the same
    # reason: a refused value must not leave a half-configured device behind.
    _clean_web_fields(overrides)
    _clean_priv_proto(overrides)
    _blank_device_override_is_inherit(overrides)
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
    detail_parts = []
    if group_id:
        detail_parts.append(f"group_id={group_id}")
    if device_group_id:
        detail_parts.append(f"device_group_id={device_group_id}")
    if vendor_override:
        detail_parts.append(f"vendor_override={vendor_override}")
    _audit(service, params, "device.create", target=f"device:{ip}",
          detail=", ".join(detail_parts))
    return {"id": device_id}


# ------------------------------------------- addresses, duplicates, merge


def _address_json(row) -> dict:
    keys = row.keys()
    return {"ip": row["ip"], "source": row["source"], "seen_ts": row["seen_ts"],
            "if_index": row["if_index"] if "if_index" in keys else None,
            "netmask": row["netmask"] if "netmask" in keys else None}


def _interface_label(names, if_index) -> str:
    """The Addresses subtab's "interface" column: an alias's descr, falling
    back to its name, or "" once the interface is gone or if_index unknown."""
    if not names or if_index is None:
        return ""
    iface = names.get(if_index)
    if iface is None:
        return ""
    return iface["descr"] or iface["name"] or ""


def _device_addresses_json(row, aliases, names=None) -> list[dict]:
    """The device's primary address first, then every learned alias — the
    primary isn't stored in device_addresses, so it's added here. The alias
    rows are passed in rather than read here, so a whole page of devices can
    be answered from one nodes_db.addresses_for_devices() read. `names` is
    {if_index: interfaces row}, for the "interface" column — omitted where a
    caller has no reason to pay for the interfaces read."""
    addresses = [{"ip": row["ip"], "source": "primary", "seen_ts": None,
                  "if_index": None, "netmask": None, "primary": True,
                  "interface": ""}]
    for alias in aliases:
        addr = _address_json(alias)
        addresses.append({**addr, "primary": False,
                          "interface": _interface_label(names, addr["if_index"])})
    return addresses


def get_nodes_device_addresses(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    names = service.nodes_db.interface_labels(device_id)
    return {"addresses": _device_addresses_json(
        row, service.nodes_db.device_addresses(device_id), names)}


# The same ceiling shape DEVICE_LIST_MAX_LIMIT uses. The pair count is
# O(devices squared) on a fleet with repeated sys_names, which is the very
# case this feature exists to find, so an unclamped limit is a fleet-sized
# body built under the nodes.db lock.
DUPLICATES_MAX_LIMIT = 2000


def get_nodes_duplicates(service, params, body) -> dict:
    """Pairs that look like one device entered twice. Fetched on demand
    from the Duplicates button, not the Devices page's refresh tick — it's
    three self-joins over the fleet."""
    limit, _offset = _page(params, 200, DUPLICATES_MAX_LIMIT)
    candidates = service.nodes_db.duplicate_candidates(limit)
    rows = {d["id"]: d for d in service.nodes_db.devices_by_ids(
        {pair["a_id"] for pair in candidates}
        | {pair["b_id"] for pair in candidates})}
    pairs = []
    for pair in candidates:
        a = rows.get(pair["a_id"])
        b = rows.get(pair["b_id"])
        if a is None or b is None:
            continue
        pairs.append({
            **pair,
            "a_name": _device_display_name(a), "a_ip": a["ip"],
            "b_name": _device_display_name(b), "b_ip": b["ip"],
        })
    return {"duplicates": pairs}


def _merge_targets(service, body, device_id):
    loser = _require(service.nodes_db.device(device_id), "device")
    try:
        winner_id = int(body.get("into") or 0)
    except (TypeError, ValueError):
        raise ValueError("into must be a device id") from None
    if not winner_id:
        raise ValueError("into is required")
    winner = _require(service.nodes_db.device(winner_id), "device")
    if winner["id"] == loser["id"]:
        raise ValueError("A device cannot be merged into itself")
    return loser, winner


def post_nodes_device_merge(service, params, body, device_id) -> dict:
    """Fold one device row into another, across all four databases.
    `preview: true` counts what would move and writes nothing, since a
    merge can't be undone. Execute order mirrors delete_nodes_device's
    (ConfigRX/Alerts/Mapper, then Nodes) so a crash mid-way leaves a nodes
    row still owning what hasn't moved, not orphaned rows."""
    loser, winner = _merge_targets(service, body, device_id)
    plan = service.nodes_db.merge_plan(loser["id"], winner["id"])
    if body.get("preview"):
        return {"preview": True, "plan": plan,
                "loser": {"id": loser["id"], "name": _device_display_name(loser),
                          "ip": loser["ip"]},
                "winner": {"id": winner["id"], "name": _device_display_name(winner),
                           "ip": winner["ip"]}}
    service.configrx_db.reassign_device(loser["id"], winner["id"])
    service.alerts_db.merge_device(loser["id"], winner["id"],
                                   params.get("_username", ""))
    service.mapper_db.reassign_device(loser["id"], winner["id"])
    service.nodes_db.merge_devices(loser["id"], winner["id"])
    service.log.add(NODES_CATEGORY,
                    f"Merged {loser['ip']} into {_device_display_name(winner)}")
    _audit(service, params, "device.merge", target=f"device:{winner['ip']}",
          detail=f"merged device:{loser['ip']} (id {loser['id']}) into id {winner['id']}")
    return {"ok": True, "device_id": winner["id"], "plan": plan}


def _effective_config_json(service, row, reveal: bool) -> dict:
    """The device's effective_config as the API shows it: both stored
    blobs withheld (has_credential/has_priv_credential say whether they
    exist), the community only for a caller who may read secrets, and the
    USM level the poll actually goes out at AFTER the profile merge — the
    row-level security_level in _device_json is null for a device that
    does not override its version, which is most of them."""
    from ...nodepoll import security_level

    effective = service.nodes_db.effective_config(row)
    shown = {k: v for k, v in effective.items()
             if k not in ("v3_auth_pass_enc", "v3_priv_pass_enc")
             and (reveal or k != "community")}
    shown["security_level"] = security_level(effective) or None
    shown["has_credential"] = bool(effective.get("v3_auth_pass_enc"))
    shown["has_priv_credential"] = bool(effective.get("v3_priv_pass_enc"))
    return shown


def get_nodes_device(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    reveal = _may_read_secrets(service, params, "nodes")
    device = _device_json(row, reveal)
    # ConfigRX fallback for a Layer-2 switch whose route tables never
    # answer over SNMP (nodepoll._refresh_default_gateway leaves the column
    # empty): its `ip default-gateway`/default static route, parsed off its
    # latest backup (configrx._config_gateway). SNMP always wins when set.
    if device["default_gateway"]:
        device["default_gateway_source"] = "snmp"
    else:
        rx_config = service.configrx_db.device_config(device_id)
        fallback = ((rx_config["config_gateway"] or "")
                    if rx_config is not None and "config_gateway" in rx_config.keys()
                    else "")
        device["default_gateway_source"] = "configrx" if fallback else ""
        if fallback:
            device["default_gateway"] = fallback
    # effective_config resolves the profile's own community into the
    # device's, so it carries one too and follows the same rule.
    device["effective_config"] = _effective_config_json(service, row, reveal)
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
    # Beside muted_until, never inside it — see _device_rows_json. A device
    # can be muted AND in maintenance at once, and both lines render.
    maint_row = service.alerts_db.open_maintenance(device_id)
    device["maintenance"] = _maintenance_json(maint_row) if maint_row else None
    # Named rather than counted: the one place with room to say which.
    rule_mutes = []
    for entity_id, until_ts in service.alerts_db.muted_entity_ids(
            alertsdb.DEVICE_RULE_KIND).items():
        pair = alertsdb.split_device_rule(entity_id)
        if pair is not None and pair[0] == device_id:
            rule_mutes.append({"rule_key": pair[1], "until_ts": until_ts})
    device["rule_mutes"] = sorted(rule_mutes, key=lambda m: m["rule_key"])
    # Rides in the device JSON rather than behind its own fetch: the
    # ADDRESSES subtab is one short list the detail pane already has a
    # round trip for, and a second request per device selection to carry
    # three rows is a request nobody needs.
    names = service.nodes_db.interface_labels(device_id)
    device["addresses"] = _device_addresses_json(
        row, service.nodes_db.device_addresses(device_id), names)
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
        # The enterprise arc this device's sysObjectID sits under, or None.
        # vendor_source/vendor_confidence cannot tell a real but unnamed arc
        # apart from a generic net-snmp sysObjectID with no arc at all, and
        # only the second can never receive VENDOR_HEALTH (keyed by arc) —
        # so a device pane can say why the health section is empty instead
        # of showing a blank that reads as a fault.
        "vendor_arc": row["vendor_arc"] if "vendor_arc" in keys else None,
        "learnable": learnable, "learn_reason": learn_reason,
    }


def _check_display_name_source(body) -> None:
    value = body.get("display_name_source")
    if value is not None and value not in ("auto", "manual"):
        raise ValueError("display_name_source must be 'auto' or 'manual'")


def _clean_upstream_id(service, device_id, value, rows: dict | None = None):
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
    # `rows` is a batch caller's pre-read device map; falling back to
    # device() keeps the single-device PUT path unchanged.
    if rows is None or upstream not in rows:
        if not service.nodes_db.device(upstream):
            raise ValueError("No such upstream device")
    return upstream


def _device_address(body) -> str:
    """The address a device is being added at, or a readable refusal.

    Devices are keyed by address and nothing here resolves names — the poller
    speaks SNMP and ICMP straight to what is stored — so a hostname is not a
    device address, and neither is `999.999.1.oops`. Accepting one would
    store an unpollable row that looks exactly like a device merely down,
    forever — the worst way to be told about a typo.

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
    # Captured for the audit diff below — this existence check discarded
    # the row entirely before now, though it was already the "before" side
    # of every field this route can change.
    before = _require(service.nodes_db.device(device_id), "device")
    _check_display_name_source(body)
    fields = _pick(body, _DEVICE_EDITABLE_BODY)
    _clean_web_fields(fields)
    _clean_priv_proto(fields)
    _blank_device_override_is_inherit(fields)
    if "v3_auth_proto" in fields and not fields["v3_auth_proto"]:
        # Against the profile the device is in AFTER this write — the same
        # PUT can move it — since a NULL protocol is that profile's.
        target = fields.get("group_id", before["group_id"])
        group = service.nodes_db.group(target) if target else None
        _refuse_orphaned_v3_secret(
            fields, before, inherited=group["v3_auth_proto"] if group else None)
    if "upstream_id" in fields:
        fields["upstream_id"] = _clean_upstream_id(
            service, device_id, fields["upstream_id"])
    result = {"ok": True}
    if "vendor_override" in fields:
        # Not a plain column write: setting a vendor by hand also teaches the
        # fleet (when the sysObjectID is specific enough) and clearing it
        # re-decides the row, both of which nodesdb.set_vendor_override owns.
        # Audited on its own line rather than folded into the generic diff.
        value = fields.pop("vendor_override")
        value = str(value or "").strip()
        if len(value) > 64:
            raise ValueError("A vendor name is at most 64 characters")
        result["vendor"] = service.nodes_db.set_vendor_override(
            device_id, value or None, params.get("_username", ""))
        _audit(service, params, "device.update", target=f"device:{before['ip']}",
              detail=f"vendor_override: {before['vendor_override'] or ''!r} -> {value!r}")
    if fields:
        service.nodes_db.update_device(device_id, **fields)
        detail = _audit_diff(before, fields)
        if detail:
            _audit(service, params, "device.update", target=f"device:{before['ip']}",
                  detail=detail)
    return result


def delete_nodes_device(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    # Alerts first, ConfigRX second, Nodes last. Three databases, so this
    # cannot be one transaction and one order has to be wrong on a crash;
    # the question is which residue is survivable. Nodes-first would leave configrx.db
    # holding this device_id's ssh_password_enc and enable_secret_enc keyed
    # on an id nothing owns — and devices.id is INTEGER PRIMARY KEY without
    # AUTOINCREMENT, so SQLite reissues the freed rowid and the next device
    # added would silently inherit those credentials. This order fails the
    # other way: a nodes row outliving its ConfigRX config, deletable again.
    # Alerts goes ahead of both on exactly that reasoning: an open
    # maintenance period or a mute keyed on this id would be inherited whole
    # by whichever device SQLite next hands the freed rowid to, which would
    # then arrive silenced with nothing on screen saying why.
    service.alerts_db.forget_device(device_id)
    service.configrx_db.forget_device(device_id)
    service.mapper_db.forget_device(device_id)
    # History (up to millions of rows) is purged in background batches by the DevicePurger.
    queued = service.nodes_db.request_device_removal([device_id])
    service.device_purger.wake()
    service.log.add(NODES_CATEGORY, f"Removed device {row['ip']}")
    _audit(service, params, "device.delete", target=f"device:{row['ip']}")
    return {"ok": True, "queued": queued}


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
    # The fields changed, not one line per device: a batch of hundreds would
    # blow the 512-char detail clip instantly. "Was device N touched by this
    # bulk op" is an accepted gap — there is no per-device target this can
    # carry without a many-to-many audit-target table.
    _audit(service, params, "device.bulk_update", target=f"{len(device_ids)} devices",
          detail=", ".join(fields))
    return {"ok": True, "updated": len(device_ids)}


def post_nodes_devices_bulk_delete(service, params, body) -> dict:
    device_ids = _bulk_device_ids(body)
    # Alerts then ConfigRX, for the inheritance reasons spelled out in
    # delete_nodes_device.
    for device_id in device_ids:
        service.alerts_db.forget_device(device_id)
        service.configrx_db.forget_device(device_id)
        service.mapper_db.forget_device(device_id)
    # One transaction, then the purge runs in the background — see delete_nodes_device.
    removed = service.nodes_db.request_device_removal(device_ids)
    service.device_purger.wake()
    service.log.add(NODES_CATEGORY, f"Bulk-removed {removed} device(s)")
    _audit(service, params, "device.bulk_delete", target=f"{len(device_ids)} devices")
    return {"ok": True, "removed": removed, "queued": removed}


def get_nodes_purges(service, params, body) -> dict:
    """How much of the deleted devices' history is still being removed."""
    return service.nodes_db.purge_status()


# ------------------------------------------------------------ bulk import
#
# Onboarding a fleet one POST at a time is minutes of round trips before
# anything has been polled once. This route accepts the same fields the
# single POST accepts (see _DEVICE_EDITABLE_BODY), as a JSON array or as
# pasted CSV with a header row, validates every row before writing anything,
# and inserts whatever validated in one transaction — a conflict partway
# through cannot leave the fleet half-imported while the per-row disposition
# list below says otherwise.
#
# Accepted CSV columns (case-insensitive, spaces or underscores either
# way): address (or ip, required), name, group (or group_id — a polling
# profile, by name or numeric id), device_group (or device_group_id — by
# name or numeric id), snmp_version, community, v3_user, v3_auth_proto,
# poll_interval_s, snmp_timeout_s, snmp_retries, ping_enabled,
# snmp_enabled, vendor_override, display_name_source, web_scheme,
# web_port. An unrecognised
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
                          "mac_table_interval_s", "arp_table_interval_s")
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


def _drop_profile_matching_credential(service, group_id, overrides) -> None:
    """A CSV row that names a profile and pastes that profile's own
    community/version is not carrying an override — it is restating the
    profile's credential. Same rule as discovery promote(): drop both
    columns when they equal the named profile's primary credential or one
    of its alternates, so a bulk import under "Site B" does not pin
    Site B's community on every row."""
    if "community" not in overrides and "snmp_version" not in overrides:
        return
    group_row = service.nodes_db.group(group_id) if group_id else None
    if group_row is None:
        return
    community = overrides.get("community", group_row["community"])
    snmp_version = overrides.get("snmp_version", group_row["snmp_version"])
    known = [group_row] + list(service.nodes_db.group_credentials(group_id))
    if any(g["community"] == community and g["snmp_version"] == snmp_version
           for g in known):
        overrides.pop("community", None)
        overrides.pop("snmp_version", None)


def post_nodes_devices_bulk_import(service, params, body) -> dict:
    rows = _parse_bulk_import_rows(body)
    if not rows:
        raise ValueError("No rows to import")
    if len(rows) > BULK_IMPORT_MAX_ROWS:
        raise ValueError(f"At most {BULK_IMPORT_MAX_ROWS:,} rows at a time")

    groups = service.nodes_db.groups()
    device_groups = service.nodes_db.device_groups()
    devices_by_ip = {d["ip"]: d for d in service.nodes_db.devices()}
    existing_ips = set(devices_by_ip)
    # A router's second L3 address, from a spreadsheet listing interfaces
    # not devices — reported as `duplicate` like the primary-IP case, and
    # imported anyway when `force`.
    alias_owners = {} if body.get("force") else service.nodes_db.address_owners(configured=True)
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
            duplicate.append({"row": i, "ip": ip, "reason": f"{ip} is already a device",
                              "device_id": (devices_by_ip[ip]["id"]
                                            if ip in devices_by_ip else None),
                              "device_name": (_device_display_name(devices_by_ip[ip])
                                              if ip in devices_by_ip else None)})
            continue
        owner = service.nodes_db.device(alias_owners[ip]) if ip in alias_owners else None
        if owner is not None:
            duplicate.append({
                "row": i, "ip": ip, "device_id": owner["id"],
                "device_name": _device_display_name(owner),
                "reason": f"{ip} is another address of "
                          f"{_device_display_name(owner)} ({owner['ip']})"})
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
            # After the loop, not inside it: the refusal must be the same
            # sentence the single-device form gives.
            _clean_web_fields(overrides)
            _clean_priv_proto(overrides)
            _drop_profile_matching_credential(service, group_id, overrides)
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
        # device, batched: a first poll and, where SNMP is enabled, a vendor
        # identification walk. Best effort — a poller that cannot queue one
        # does not undo an insert that has already committed.
        for device_id in device_ids:
            try:
                service.node_poller.poll_now(device_id)
                device_row = service.nodes_db.device(device_id)
                if device_row is not None and service.nodes_db.effective_config(
                        device_row).get("snmp_enabled", True):
                    service.node_poller.start_identify(device_id, trigger="bulk-import")
            except Exception:                                     # noqa: BLE001
                pass

    _audit(service, params, "device.bulk_import",
          detail=f"created={len(created)}, duplicate={len(duplicate)}, "
                 f"invalid={len(invalid)}")
    return {"ok": True, "total": len(rows), "created": created,
            "duplicate": duplicate, "invalid": invalid}


def post_nodes_device_poll(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    # queued=False means a poll for this device was already in flight, so
    # this click started nothing. The button says so rather than reporting
    # "Polled" off the other poll's completion.
    return {"ok": True, "queued": bool(service.node_poller.poll_now(device_id, walks=True))}


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
        (queued if service.node_poller.poll_now(device_id, walks=True) else busy).append(device_id)
    if queued:
        service.log.add(NODES_CATEGORY, f"Poll now requested for {len(queued)} device(s)")
    return {"ok": True, "queued": queued, "already_polling": busy, "missing": missing}


def post_nodes_device_focus(service, params, body, device_id) -> dict:
    """The browser renews this every refresh tick while the device is
    selected on the Nodes tab; the short TTL means fast polling lapses on
    its own when the tab is left or the browser closes — deselection
    never needs its own request."""
    _require(service.nodes_db.device(device_id), "device")
    interval = float(service.nodes_settings.get("focus_poll_interval_s", 3))
    service.node_poller.set_focus(device_id, ttl_s=15, interval_s=interval)
    return {"ok": True, "interval_s": interval}


def get_nodes_device_dom(service, params, body, device_id, if_index) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    sensors = service.node_poller.read_dom(int(device_id), int(if_index))
    return {"sensors": sensors}


def get_nodes_device_hardware(service, params, body, device_id) -> dict:
    """Whole-device counterpart of get_nodes_device_dom: the device
    dialog's HARDWARE SENSORS section, not one interface's DOM table."""
    _require(service.nodes_db.device(device_id), "device")
    return service.node_poller.read_hardware(int(device_id))


_SENSOR_FAMILY_KINDS = {"temp_sensor_c": "temperature", "temp_sensor_state": "temperature",
                        "psu_state": "psu", "stack_power_port": "stack_power",
                        "fan_state": "fan"}
_PSU_STATE_WORDS = {0: "ok", 1: "degraded", 2: "failed / no input",
                    3: "not present (removed or no input)"}
_TEMP_STATE_WORDS = {0: "normal", 1: "warning", 2: "critical", 3: "shutdown"}
_STACK_POWER_STATE_WORDS = {0: "ok", 2: "cable down"}
_FAN_STATE_WORDS = {0: "ok", 1: "degraded", 2: "failed", 3: "not present"}


def get_nodes_device_sensors(service, params, body, device_id) -> dict:
    """The per-sensor temperature and power-supply rows the poller stored
    (temp_sensor_c.<i>, temp_sensor_state.<i>, psu_state.<i>) joined to the
    limits the device published for them -- stored data only, no SNMP."""
    _require(service.nodes_db.device(device_id), "device")
    limits = service.nodes_db.interface_thresholds(int(device_id))
    by_key: dict[tuple, dict] = {}
    for row in service.nodes_db.metrics(int(device_id)):
        root, _, suffix = str(row["key"]).partition(".")
        kind = _SENSOR_FAMILY_KINDS.get(root)
        if kind is None or not suffix.isdigit():
            continue
        index = int(suffix)
        entry = by_key.setdefault((kind, index), {
            "kind": kind, "index": index, "name": row["label"] or f"sensor {index}",
            "value": None, "unit": "", "state": None, "state_text": "",
            "high_warn": None, "high_alarm": None, "limit_source": "", "last_ts": None})
        entry["last_ts"] = max(entry["last_ts"] or 0, row["last_ts"] or 0) or None
        value = row["last_value"]
        if root == "temp_sensor_c":
            entry["value"], entry["unit"] = value, row["unit"] or "\u00b0C"
            limit = limits.get((index, "temp_sensor_c"))
            if limit is not None:
                entry["high_warn"], entry["high_alarm"] = limit["high_warn"], limit["high_alarm"]
                entry["limit_source"] = limit["source"]
        else:
            words = (_PSU_STATE_WORDS if root == "psu_state" else
                     _STACK_POWER_STATE_WORDS if root == "stack_power_port" else
                     _FAN_STATE_WORDS if root == "fan_state" else
                     _TEMP_STATE_WORDS)
            entry["state"] = None if value is None else int(value)
            entry["state_text"] = words.get(entry["state"], str(value) if value is not None else "")
    sensors = sorted(by_key.values(), key=lambda e: (e["kind"], e["index"]))
    return {"sensors": sensors,
            "covered": any(e["kind"] == "temperature" and (e["high_warn"] is not None
                                                             or e["high_alarm"] is not None
                                                             or e["state"] is not None)
                           for e in sensors)}


# metric root -> the rules a Sensor Snapshot baseline on it can resolve.
_BASELINE_RULE_KEYS = {
    "psu_state": ("psu_warning", "psu_failed"),
    "stack_power_port": ("stack_power_cable_down",),
    "fan_state": ("fan_warning", "fan_failed"),
}


def post_nodes_device_sensor_snapshot(service, params, body, device_id) -> dict:
    """Accepts every current psu_state/stack_power_port/fan_state reading as
    this device's baseline and resolves whatever is open on those rules for
    it (see alertengine._evaluate_thresholds for the baseline-skip half)."""
    device_id = int(device_id)
    device = _require(service.nodes_db.device(device_id), "device")
    now = time.time()
    rows = [{"metric_key": row["key"], "value": row["last_value"], "ts": now}
           for row in service.nodes_db.metrics(device_id)
           if row["last_value"] is not None
           and str(row["key"]).partition(".")[0] in _BASELINE_RULE_KEYS]
    service.nodes_db.replace_sensor_baselines(device_id, rows)
    for row in rows:
        root, _, suffix = row["metric_key"].partition(".")
        for rule_key in _BASELINE_RULE_KEYS[root]:
            resolved = service.alerts_db.resolve_by_dedup(
                f"{rule_key}:sensor:{device_id}:{suffix}", by="")
            if resolved is not None:
                service.alerts_db.add_rollup_note(resolved["id"], "Sensor snapshot")
    _audit(service, params, "device.sensor_snapshot", target=f"device:{device['ip']}",
          detail=f"count={len(rows)}")
    return {"count": len(rows), "ts": now}


def get_nodes_device_sensor_snapshot(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    return service.nodes_db.sensor_baseline_meta(int(device_id))


_STACK_POWER_SWITCH_LABEL_RE = re.compile(r"^Switch (?P<switch>\S+)$")
_STACK_POWER_MODE_WORDS = {1: "power sharing", 2: "redundant",
                           3: "power sharing (strict)", 4: "redundant (strict)"}
_STACK_POWER_TOPOLOGY_WORDS = {1: "ring", 2: "star"}


def _stack_power_numkey(value):
    """Numeric-first sort key: a stack/switch/port number in this feature
    is always the raw digits nodepoll wrote, but falls back gracefully if a
    label ever fails to parse."""
    try:
        return (0, int(value))
    except (TypeError, ValueError):
        return (1, str(value))


def get_nodes_device_stack_power(service, params, body, device_id) -> dict:
    """CISCO-STACKWISE-MIB rows nodepoll._poll_stack_power stored -- stored
    data only, no SNMP. A port's name, switch number and neighbour switch
    are each their own fact (stack_power_port_admin's label, and the
    stack_power_port_switch/_neighbour metrics) rather than parsed out of
    stack_power_port.<idx>'s friendly label, which stays free to read
    however reads best in an alert. Only the switch-info rows below still
    read their switch number off a label ("Switch N") -- that one is not a
    compound value, so there is nothing to parse apart.
    """
    _require(service.nodes_db.device(device_id), "device")
    rows = {str(row["key"]): row for row in service.nodes_db.metrics(int(device_id))}
    present = any(key.startswith("stack_power_") for key in rows)

    stacks = []
    for key, row in rows.items():
        if not key.startswith("stack_power_stack_type."):
            continue
        n = key.split(".", 1)[1]
        mode_row = rows.get(f"stack_power_stack_mode.{n}")
        members_row = rows.get(f"stack_power_stack_members.{n}")
        mode = int(mode_row["last_value"]) if mode_row and mode_row["last_value"] is not None else None
        topology = int(row["last_value"]) if row["last_value"] is not None else None
        stacks.append({
            "number": int(n) if n.isdigit() else n,
            "name": row["label"] or f"power stack {n}",
            "mode": mode, "mode_text": _STACK_POWER_MODE_WORDS.get(mode, ""),
            "topology": _STACK_POWER_TOPOLOGY_WORDS.get(topology, ""),
            "members": (int(members_row["last_value"])
                       if members_row and members_row["last_value"] is not None else None),
        })
    stacks.sort(key=lambda s: _stack_power_numkey(s["number"]))

    switches = []
    for key, row in rows.items():
        if not key.startswith("stack_power_budget_w."):
            continue
        ent = key.split(".", 1)[1]
        m = _STACK_POWER_SWITCH_LABEL_RE.match(row["label"] or "")
        switch = m.group("switch") if m else ent
        committed_row = rows.get(f"stack_power_committed_w.{ent}")
        allocated_row = rows.get(f"stack_power_allocated_w.{ent}")
        switches.append({
            "switch": int(switch) if switch.isdigit() else switch,
            "budget_w": row["last_value"],
            "committed_w": committed_row["last_value"] if committed_row else None,
            "allocated_w": allocated_row["last_value"] if allocated_row else None,
        })
    switches.sort(key=lambda s: _stack_power_numkey(s["switch"]))

    ports = []
    for key, row in rows.items():
        if not key.startswith("stack_power_port."):
            continue
        idx = key.split(".", 1)[1]
        admin_row = rows.get(f"stack_power_port_admin.{idx}")
        switch_row = rows.get(f"stack_power_port_switch.{idx}")
        neighbour_row = rows.get(f"stack_power_port_neighbour.{idx}")
        limit_row = rows.get(f"stack_power_port_limit_a.{idx}")
        # admin_row's label is the raw cswStackPowerPortName (nodepoll's own
        # doing) -- the friendly `row["label"]` stays reserved for the alert.
        name = (admin_row["label"] if admin_row else None) or (row["label"] or "")
        switch = (int(switch_row["last_value"])
                 if switch_row and switch_row["last_value"] is not None else None)
        neighbour = (int(neighbour_row["last_value"])
                    if neighbour_row and neighbour_row["last_value"] is not None else 0)
        admin = (int(admin_row["last_value"])
                if admin_row and admin_row["last_value"] is not None else None)
        state = int(row["last_value"]) if row["last_value"] is not None else None
        if admin == 2:
            state_text = "disabled"
        elif state == 2:
            state_text = "cable down"
        else:
            state_text = "ok" if state == 0 else ""
        ports.append({
            "switch": switch, "name": name, "neighbour_switch": neighbour,
            "admin_text": {1: "enabled", 2: "disabled"}.get(admin, ""),
            # No raw link column is stored separately from `state` -- see
            # nodepoll._poll_stack_power's docstring for why state alone
            # (0 up-or-disabled, 2 down) is the only fact a disabled port
            # ever publishes here.
            "link_text": "" if admin == 2 else ("down" if state == 2 else "up"),
            "state": state, "state_text": state_text,
            "limit_a": limit_row["last_value"] if limit_row else None,
            "last_ts": row["last_ts"],
        })
    ports.sort(key=lambda p: (_stack_power_numkey(p["switch"]), p["name"]))

    return {"present": present, "stacks": stacks, "switches": switches, "ports": ports}


def get_nodes_device_dom_all(service, params, body, device_id) -> dict:
    """Every port's DOM/SFP reading in one call, for the device dialog's
    DOM / SFP SENSORS section -- read_dom() above stays the interface
    dialog's own one-port read."""
    _require(service.nodes_db.device(device_id), "device")
    sensors = service.node_poller.read_dom_all(int(device_id))
    return {"sensors": sensors}


def get_nodes_device_mac_table(service, params, body, device_id, if_index) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    device_id, if_index = int(device_id), int(if_index)
    if params.get("stored"):
        # The port dialog's first paint: whatever the last walk stored, with
        # no SNMP of its own, so it renders before the live read below even
        # starts. `walked` distinguishes "this device has never had a MAC
        # walk" from "walked, nothing learned on this port".
        rows = service.nodes_db.mac_entries_for(device_id, if_index)
        macs = [{"mac": row["mac"], "vlan": row["vlan"], "seen_ts": row["seen_ts"],
                "present": row["present"]} for row in rows]
        return {"macs": macs, "supported": True, "source": "stored",
                "walked": service.nodes_db.has_mac_entries(device_id)}
    macs = service.node_poller.read_mac_table(device_id, if_index)
    return {"macs": macs, "supported": macs is not None}


def get_nodes_device_interface_config(service, params, body, device_id, if_index) -> dict:
    """This port's own stanza from the device's latest ConfigRX backup.
    Gated on nodes read AND configrx read (checked here, like
    get_dashboard_offenders' _dash_can); redacted like get_configrx_backup
    for a caller without configrx write."""
    device_id, if_index = int(device_id), int(if_index)
    if not _permissions.allows(
            request_permissions(service, params).get("nodes"), _permissions.READ):
        raise _permissions.Forbidden("Reading devices is not permitted")
    _require(service.nodes_db.device(device_id), "device")
    backups = service.configrx_db.backups_for(device_id, limit=1)
    if not backups:
        return {"backup_id": None, "ts": None, "text": None, "searched": [], "headers": 0}
    backup = backups[0]
    content = service.configrx_db.backup_content(backup["id"]) or ""
    if not _may_read_secrets(service, params, "configrx"):
        content, _ = configrx_redact.redact(content)
    iface = service.nodes_db.interface_row(device_id, if_index)
    names = [iface["name"] if iface else None,
            iface["descr"] if iface else None]
    searched = [n for n in names if n]
    text = configrx_stanza.interface_stanza(content, searched)
    headers = configrx_stanza.count_interface_headers(content)
    return {"backup_id": backup["id"], "ts": backup["ts"], "text": text,
            "searched": searched, "headers": headers}


# Bumped by every handler below that edits the MIB corpus in a way
# mib_generation() cannot see — an in-place rename moves neither the
# highest object id nor either count. A plain module counter is enough:
# it only has to be comparable within one process, exactly as
# nodesdb.config_generation() argues for itself.
_OID_NAMES_EPOCH = 0


def _invalidate_oid_names() -> None:
    """Call after editing a MIB object in place; see _oid_name_table."""
    global _OID_NAMES_EPOCH
    _OID_NAMES_EPOCH += 1


def _oid_name_table(service) -> dict:
    """OID -> name, from every uploaded MIB plus the built-in well-known
    table the Trap page already decodes with. One table, so uploading a MIB
    improves the OID browser the same moment it improves trap decoding.

    Rebuilt only when the MIB corpus has actually moved. This inverts every
    object of every installed MIB, and the shipped catalog's PowerNet-MIB
    is ~2.7 MiB on its own — a cost the OID browser and the trap decoder
    were each paying per request. `nodes_db.mib_generation()` is one
    indexed query (highest object id, object count, file count) and is the
    same signal nodepoll already keeps its own MIB index against; the local
    epoch covers the one edit that tuple cannot see, a rename through
    PUT .../mibs/<file>/objects/<id>. A catalog install lands on a
    background thread and changes the counts, so it needs no bump of its
    own.

    Held on the Service rather than in a module global, so two Services in
    one process — which is every test run — cannot be served each other's
    MIBs.
    """
    key = (service.nodes_db.mib_generation(), _OID_NAMES_EPOCH)
    cached = getattr(service, "_api_oid_names", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    names = dict(trapdecode.WELL_KNOWN)
    # all_known_oids() is name -> OID (it feeds mibparse.resolve's `known`
    # dict); the browser needs the inverse.
    for name, oid in service.nodes_db.all_known_oids().items():
        if oid:
            names[oid] = name
    # Read-only to every caller (_decode_oid only ever looks things up).
    service._api_oid_names = (key, names)
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
    device = _require(service.nodes_db.device(device_id), "device")
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
    _require(service.nodes_db.device(device_id), "device")
    return {"walk": service.node_poller.start_oid_walk(int(device_id))}


def get_nodes_device_oid_walk(service, params, body, device_id) -> dict:
    """Progress, or the finished walk. `download` asks for the file text:
    once handed over, the rows are dropped, since a walk exists to be
    downloaded once.

    Dropped only for a caller who could start another one. Watching a walk
    is a read, but forgetting it is not: without the write check any
    `nodes: read` account could delete a finished walk out from under the
    engineer who ran it, and re-running it needs `nodes: write`."""
    _require(service.nodes_db.device(device_id), "device")
    status = service.node_poller.oid_walk_status(
        int(device_id), with_rows=params.get("download") is not None)
    if status is None:
        return {"walk": None}
    if params.get("download") is None or status["state"] != "done":
        status.pop("walk", None)
        return {"walk": status}
    rows = status.pop("walk", [])
    text = _oid_walk_text(service, status, rows)
    if _may_read_secrets(service, params, "nodes"):
        service.node_poller.forget_oid_walk(int(device_id))
    return {"walk": status, "text": text,
            "filename": _oid_walk_filename(status)}


def delete_nodes_device_oid_walk(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    return {"cancelled": service.node_poller.cancel_oid_walk(int(device_id))}


def post_nodes_device_identify(service, params, body, device_id) -> dict:
    """Re-identify: start the bounded vendor walk now, or report the one
    already running. A job, not a synchronous answer — the walk is up to
    20 s, the page refreshes every few seconds, and bulk cannot wait."""
    _require(service.nodes_db.device(device_id), "device")
    return {"job": service.node_poller.start_identify(int(device_id), trigger="manual")}


def get_nodes_device_identify(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    return {"job": service.node_poller.identify_status(int(device_id)),
            "result": {"vendor": row["vendor"], "vendor_detected": row["vendor_detected"],
                       "vendor_source": row["vendor_source"] or "",
                       "vendor_confidence": (row["vendor_confidence"] or ""
                                             if "vendor_confidence" in row.keys() else ""),
                       **_identification_json(service, row)}}


def delete_nodes_device_identify(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
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


_TEST_WALK_MAX_ROWS = 512
_TEST_WALK_BUDGET_S = 6.0


def _test_ifindex_walk(service, exchange, version: int) -> dict:
    """A real ifIndex walk for the Test button, reported rather than raised.

    The same shape NodePoller._walk_column_detail walks with — GETBULK on
    v2c/v3 at the configured repetition count, halved on tooBig and falling
    back to GETNEXT, varbinds accepted until one leaves the subtree — but
    bounded to a few seconds in front of a waiting human, and answering
    "what happened" instead of a table. The three numbers that name the
    fault a scalar GET cannot see: how many repetitions the agent actually
    accepted, the error-status it answered (a PAN-OS agent says genErr or
    noSuchName for a subtree it will not serve), and how far the walk got
    before the clock ran out.
    """
    from ...nodeoids import IF_TABLE
    from ...nodepoll import _oid_key
    from ...snmppoll import ERROR_STATUS, PDU_GETBULK, PDU_GETNEXT, SnmpError

    base = IF_TABLE["if_index"]
    settings = service.nodes_db.settings()
    configured = int(settings.get("snmp_bulk_max_repetitions", 40) or 0)
    use_bulk = version != 0 and configured > 0
    repetitions = configured if use_bulk else 0
    started = time.time()
    deadline = started + _TEST_WALK_BUDGET_S
    current = base
    rows = requests = 0
    error_status = 0
    stopped = "reached the end of the ifIndex column"
    while True:
        if rows >= _TEST_WALK_MAX_ROWS:
            stopped = f"stopped at this test's {_TEST_WALK_MAX_ROWS}-row limit"
            break
        if time.time() > deadline:
            stopped = f"still going after {_TEST_WALK_BUDGET_S:.0f}s"
            break
        try:
            requests += 1
            response = exchange(PDU_GETBULK if use_bulk else PDU_GETNEXT,
                                [current], repetitions)
        except SnmpError as exc:
            stopped = f"{exc} after {rows} row(s)"
            break
        if use_bulk and response.error_status == 1:      # tooBig
            if repetitions <= 1:
                use_bulk = False
                repetitions = 0
            else:
                repetitions = max(1, repetitions // 2)
            continue
        if response.error_status:
            error_status = response.error_status
            stopped = (f"the device answered "
                       f"{ERROR_STATUS.get(error_status, 'an unknown error')}"
                       f"({error_status})")
            break
        if not response.varbinds:
            stopped = "the device returned nothing"
            break
        done = False
        for vb in response.varbinds:
            oid = vb["oid"]
            if not oid or not oid.startswith(base + "."):
                done = True
                break
            if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                done = True
                break
            if _oid_key(oid) <= _oid_key(current):
                stopped = f"the device answered with a non-increasing OID ({oid})"
                done = True
                break
            rows += 1
            current = oid
        if done:
            break
    return {"rows": rows, "requests": requests,
            "max_repetitions": repetitions if use_bulk else 0,
            "bulk": use_bulk, "error_status": error_status,
            "error_status_name": ERROR_STATUS.get(error_status, "") if error_status else "",
            "stopped": stopped,
            "summary": (f"{rows} interface(s) in {requests} request(s), "
                        + (f"GETBULK x{repetitions}" if use_bulk else "GETNEXT")
                        + f" — {stopped}"),
            "ms": (time.time() - started) * 1000.0}


def _test_ping(ip: str, timeout_s: float) -> dict:
    """The ping half of post_nodes_device_test."""
    from ...ipam_scan import ping_once

    ping = {"ok": None, "rtt_ms": None}
    started = time.time()
    ping_ok = ping_once(ip, timeout_ms=int(timeout_s * 1000))
    ping["ok"] = ping_ok
    if ping_ok:
        ping["rtt_ms"] = (time.time() - started) * 1000.0
    return ping


def _test_engine_discovery(session, row, phases: list, snmp: dict) -> tuple:
    """SNMPv3 engine discovery, its own phase of post_nodes_device_test: a
    timeout here is a different fault from a timeout on the signed request —
    no signed request was ever sent, so the username and password were never
    tested at all. Returns (engine_id, boots, engine_time); raises SnmpError
    on failure, having already recorded the engine phase either way."""
    from ...nodepoll import discover_engine
    from ...snmppoll import SnmpError

    started = time.time()
    try:
        engine = discover_engine(session, row["ip"])
    except SnmpError as exc:
        snmp["engine"] = {"ok": False, "id": None, "boots": None,
                          "time": None, "resynced": False,
                          "ms": (time.time() - started) * 1000.0}
        raise SnmpError(
            f"SNMPv3 engine discovery failed: {exc} — the "
            f"unauthenticated discovery probe (RFC 3414 §4) got "
            f"no usable answer, so no signed request was sent "
            f"and the username and password were never tested")
    finally:
        phases.append({"name": "engine discovery",
                       "ms": (time.time() - started) * 1000.0})
    engine_id, boots, engine_time = engine
    snmp["engine"] = {"ok": True, "id": engine_id.hex(), "boots": boots,
                      "time": engine_time, "resynced": False,
                      "ms": phases[-1]["ms"]}
    return engine


def _test_auth_failure_detail(exc) -> dict:
    """The `snmp` fields an _AuthFailure in post_nodes_device_test sets: say
    WHICH usmStats counter the agent named, by its type-carried name rather
    than a substring of the message, and what that means for the password.
    wrongDigests and unknownUserNames are the credential being wrong;
    notInTimeWindows is the clock, which the poller resyncs and retries on
    every poll and which is normally transient — a Test must not call that a
    failure when the poll recovers from it silently, so `auth.ok` is null
    there, not false."""
    from ...nodepoll import USM_STATS

    name = exc.usm_name
    oid = next((o for o, (n, _) in USM_STATS.items() if n == name), None)
    explanation = USM_STATS[oid][1] if oid else ""
    detail = {
        "ok": False, "error": str(exc),
        "report": {
            "name": name or None, "oid": oid,
            "detail": explanation or ("the device answered with a "
                                      "Report-PDU naming no usmStats "
                                      "counter this poller knows")}}
    if name in ("wrongDigests", "unknownUserNames"):
        detail["auth"] = {"ok": False, "detail": explanation}
    elif name == "decryptionErrors":
        # The signature verified — USM checks it before it decrypts — so
        # auth is proven and it is the PRIVACY password that is wrong. Said
        # in its own words, or a wrong privacy password reads exactly like a
        # wrong auth one.
        detail["auth"] = {"ok": True, "detail": (
            "the signature verified, so the authentication password "
            "is right; the device could not decrypt the request, so "
            "the privacy password or protocol is wrong")}
    elif name == "notInTimeWindows":
        detail["auth"] = {"ok": None, "detail": (
            "the device rejected the engine time twice, so the "
            "password was never checked; the poller resyncs and "
            "retries on this and it is normally transient — run "
            "the test again")}
    else:
        detail["auth"] = {"ok": None, "detail": "not proven either way: "
                          + (explanation or "the device answered with "
                                            "a Report-PDU")}
    return detail


def post_nodes_device_test(service, params, body, device_id) -> dict:
    """Ping + SNMP against the in-progress-edit config carried in the
    body, falling back to the saved one for anything not overridden — the
    same "test what's typed before saving" idiom as IPAM's DHCP test.
    Builds the SNMP request directly with snmppoll and nodepoll's module-
    level v3_exchange rather than going through NodePoller/credential_for(),
    so a typed-but-unsaved v3 password is used once, in memory, and never
    touches DPAPI — the same "usable without ever being persisted on a
    non-Windows box" property CREDENTIAL-SECURITY.md documents for every
    other credential form.

    The SNMPv3 half answers in fields, not one string, because one string
    is what an operator spent days on: "engine resync required — check the
    username and auth password" for every Report-PDU whatever it named, and
    "authorization error" for a credential the device had just verified.
    `engine` is what discovery learned (and whether a Report re-taught it),
    `auth` whether the signature was accepted, `report` the usmStats counter
    a refusing agent named, `refused_oid`/`hint` the object and the advice
    for an authorizationError — the same words the poll writes to the
    device row, from the same functions, so the two never disagree."""
    import random
    from ... import nodeoids
    from ...nodepoll import (
        DEFAULT_SNMP_PORT, _AuthFailure, _Session,
        access_denied_advice, access_denied_headline, credential_for,
        refused_oid, v3_exchange)
    from ...snmppoll import (ERROR_STATUS, PDU_GET, SnmpAccessDenied, SnmpDowngrade,
                            SnmpError, build_request)

    row = _require(service.nodes_db.device(device_id), "device")
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
    # The privacy pair follows the auth pair's rule exactly, including for
    # the protocol: typed wins, the resolved config is the fallback, and a
    # null or blank protocol is "(profile)" — the edit form posts every
    # override key on every Test, null for each left at "(profile)", the
    # same body Save sends. Reading present-but-null as "no privacy" tested
    # a device inheriting an authPriv profile at authNoPriv, and against
    # the PAN-OS box this release exists for the Test button answered
    # unsupportedSecLevels with advice to set a privacy password that was
    # already set, while the scheduled poll succeeded. Only the PASSWORD
    # has a "present-but-empty means test without one" reading, because
    # that is the one field the form cannot say "inherit" for.
    priv_fields = {"v3_priv_proto": body.get("v3_priv_proto")
                   or config.get("v3_priv_proto")}
    _clean_priv_proto(priv_fields)
    priv_proto = priv_fields["v3_priv_proto"]
    priv_password = body.get("v3_priv_pass")
    if identity is None or (password is None and "v3_auth_pass" not in body) \
            or (priv_password is None and "v3_priv_pass" not in body):
        try:
            stored = credential_for(config)
            stored_identity, stored_proto, stored_password = (
                stored.identity, stored.auth_proto, stored.auth_password)
        except SnmpError as exc:
            # The STORED credential is itself refused — a v1/v2c community
            # carrying a comma, saved before nodesdb.clean_community existed
            # to refuse it. Polling says so in words on the device row; the
            # Test button is where an operator goes to find out why, and
            # this call sits outside the try below, so without this arm it
            # answered a bare 500 with the explanation in a traceback in the
            # log. ValueError is the shape server.py turns into a 400
            # carrying the message.
            raise ValueError(str(exc))
        identity = identity if identity is not None else stored_identity
        auth_proto = auth_proto or stored_proto
        if password is None and "v3_auth_pass" not in body:
            password = stored_password
        if priv_password is None and "v3_priv_pass" not in body:
            priv_password = stored.priv_password
        stored = None
    if not priv_proto:
        priv_password = None

    result = {"ping": {"ok": None, "rtt_ms": None}, "snmp": {"ok": None, "error": None}}
    timeout_s = float(config.get("snmp_timeout_s", 3.0))
    if config.get("ping_enabled"):
        result["ping"] = _test_ping(row["ip"], timeout_s)

    if config.get("snmp_enabled"):
        version = int(config.get("snmp_version", 1))
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        # Per-phase timings, appended as each phase finishes. Six scalars in
        # one GET is the one thing every device answers, so a test made of
        # nothing else reported OK against every fault a real poll trips
        # over: a table walk that times out part way, an agent that answers
        # an error-status for the ifTable, one that refuses GETBULK, and a
        # community that is dropped without a word. The walk below is the
        # poll's own first walk, so the test now fails where the poll does.
        snmp = result["snmp"]
        phases = snmp["phases"] = []
        # Every diagnostic key is present from the start, None until the
        # phase that answers it has run, so a reader never has to ask
        # whether a missing key means "not v3" or "did not get that far".
        # The level is derived the way the poller's security_level derives
        # it — a protocol AND a password sign the request — from the
        # typed-or-stored pair resolved above, since the typed password is
        # exactly the one credential_for cannot see.
        signed = bool(version >= 3 and auth_proto and password)
        encrypted = bool(signed and priv_proto and priv_password)
        level = (("authPriv" if encrypted else "authNoPriv" if signed
                  else "noAuthNoPriv") if version >= 3 else "")
        snmp["security_level"] = level or None
        for key in ("engine", "auth", "report", "error_status",
                    "error_status_name", "refused_oid", "hint"):
            snmp[key] = None
        # What the message names the credential as, without ever printing
        # it: the version and identity the test actually used, which may
        # both be the form's rather than the saved row's.
        label_config = dict(config, snmp_version=version)
        label_config["v3_user" if version >= 3 else "community"] = identity
        session = None
        # The (engine id, boots, time) the next signed request is built
        # with. A one-element list because `learned` — how v3_exchange
        # hands back what a Report re-taught it — has to replace it from
        # inside a closure, and the payload reports the resync rather than
        # hiding it, which is the whole difference from the copy this
        # handler used to carry.
        engine = [None]

        def learned(engine_id: bytes, boots: int, engine_time: int) -> None:
            resynced = engine[0] is not None
            engine[0] = (engine_id, boots, engine_time)
            snmp["engine"].update(id=engine_id.hex(), boots=boots,
                                  time=engine_time, resynced=resynced)

        try:
            session = _Session(row["ip"], DEFAULT_SNMP_PORT, timeout_s,
                               int(config.get("snmp_retries", 2)))
            if version >= 3:
                # Discovery is its own phase, because a timeout here is a
                # different fault from a timeout on the signed request: no
                # signed request was ever sent, so the username and the
                # password were never tested at all.
                engine[0] = _test_engine_discovery(session, row, phases, snmp)

            def exchange(pdu_tag, request_oids, max_repetitions=0):
                """One round trip on the shared session, either framing.
                The v3 framing is the poller's own v3_exchange — the resync
                on a first Report included, so a device whose clock has
                drifted passes the Test the same way it passes the poll."""
                if version in (0, 1):
                    request_id = random.randint(1, 2 ** 16)
                    packet = build_request(version, identity or "public", pdu_tag,
                                           request_id, request_oids,
                                           max_repetitions=max_repetitions)
                    return session.request(packet, expect_request_id=request_id)
                return v3_exchange(
                    session, pdu_tag, request_oids, identity=identity,
                    auth_proto=auth_proto, password=password, engine=engine[0],
                    max_repetitions=max_repetitions or 10, ip=row["ip"],
                    learned=learned, priv_proto=priv_proto,
                    priv_password=priv_password,
                    verify_replies=bool(service.nodes_settings.get(
                        "v3_verify_replies", True)))

            started = time.time()
            try:
                response = exchange(PDU_GET, oids)
            finally:
                phases.append({"name": "scalars",
                               "ms": (time.time() - started) * 1000.0})
            if version >= 3:
                # Any non-Report reply to a signed request is USM saying
                # the signature verified; an unsigned request proves
                # nothing about the password either way, and says so
                # rather than claiming an authentication that never ran.
                snmp["auth"] = (
                    {"ok": True, "detail": (
                        "the device verified the signature, decrypted the "
                        "request and answered encrypted; the reply's own "
                        "signature verified here (authPriv)" if encrypted else
                        "the device verified the signature and answered; "
                        "the reply's own signature verified here (authNoPriv)")}
                    if signed else
                    {"ok": None, "detail": "the request was not signed "
                                           "(noAuthNoPriv), so there was nothing "
                                           "to authenticate"})
            snmp["error_status"] = response.error_status
            snmp["error_status_name"] = (
                ERROR_STATUS.get(response.error_status, "") if response.error_status else "")
            if response.error_status == 16:
                # The message authenticated and the object was refused. The
                # headline goes in `error` and the advice in `hint`; joined
                # with ". " they are nodepoll.access_denied_reason verbatim,
                # the text the poll writes to the device row — split only so
                # the dialog can put the advice on a line of its own.
                snmp["refused_oid"] = refused_oid(response, oids) or None
                snmp["hint"] = access_denied_advice(label_config, level)
                raise SnmpAccessDenied(access_denied_headline(response, oids))
            values = {vb["oid"]: vb["value"] for vb in response.varbinds
                     if vb["type"] not in ("noSuchObject", "noSuchInstance")}
            snmp["ok"] = True
            snmp["sys_descr"] = values.get(nodeoids.SYSTEM_SCALARS["sys_descr"])
            snmp["sys_name"] = values.get(nodeoids.SYSTEM_SCALARS["sys_name"])
            snmp["sys_uptime"] = values.get(nodeoids.SYSTEM_SCALARS["sys_uptime"])
            walk = _test_ifindex_walk(service, exchange, version)
            snmp["walk"] = walk
            phases.append({"name": "ifIndex walk", "ms": walk.pop("ms"),
                           "detail": walk["summary"]})
        except _AuthFailure as exc:
            snmp.update(_test_auth_failure_detail(exc))
        except SnmpDowngrade as exc:
            # The device answered, but below the level it was asked at,
            # and the reply was refused unread. Not an auth failure — the
            # password was never contradicted — and said so, with the
            # setting that accepts such replies named in the error itself.
            snmp["ok"] = False
            snmp["error"] = str(exc)
            snmp["auth"] = {"ok": None, "detail": (
                "not proven either way: the reply carried no signature, so "
                "there was nothing to verify — refused as a downgrade")}
        except (SnmpError, OSError) as exc:
            # SnmpAccessDenied lands here too, with the headline as the
            # error and refused_oid/hint already filled in above. OSError:
            # _Session's socket() itself failed (descriptor exhaustion);
            # the same readable answer as a protocol failure.
            snmp["ok"] = False
            snmp["error"] = str(exc)
        finally:
            password = None
            priv_password = None
            if session is not None:
                # Every datagram this test sent and threw away: from the
                # wrong peer, undecodable, or answering a request id we
                # were not waiting on. A timeout with drops is a different
                # fault from a timeout without — the first is something
                # answering that should not be, the second is nothing
                # answering at all — and the count was read by nothing.
                result["snmp"]["dropped"] = session.dropped
                session.close()
    return result


def get_nodes_device_interfaces(service, params, body, device_id) -> dict:
    device = _require(service.nodes_db.device(device_id), "device")
    rows = service.nodes_db.interfaces(device_id)
    # The open port dialog refreshes one row every five seconds and was
    # re-fetching the whole table — a quarter of a megabyte on a 500-port
    # switch — to read it. Same shape, one interface.
    if_index = _num(params, "if_index", None, int)
    if if_index is not None:
        rows = [r for r in rows if r["if_index"] == if_index]
    keys = rows[0].keys() if rows else ()
    # Why this list stops where it does, when the poller's per-poll cap is
    # what stopped it. It rides with the interfaces rather than with the
    # device's own JSON because it is a fact about this table, and the pane
    # showing the table is the one place it answers a question somebody is
    # asking.
    note = (device["interfaces_note"] or ""
            if "interfaces_note" in device.keys() else "")
    priority = service.nodes_db.priority_if_indexes(device_id)
    # poe_admin/poe_detect_status/poe_power_mw/stp_state/media are read
    # defensively like every other column a migration added: a row fetched
    # before the ALTER TABLE has run on this database will not have them.
    return {"note": note, "interfaces": [
        {"id": r["id"], "if_index": r["if_index"], "descr": r["descr"],
         "name": r["name"] if "name" in r.keys() else None,
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
         "stp_state": (r["stp_state"] if "stp_state" in keys else None),
         "stp_blocking_vlans": (r["stp_blocking_vlans"] if "stp_blocking_vlans" in keys else None),
         "stp_vlan_count": (r["stp_vlan_count"] if "stp_vlan_count" in keys else None),
         "media": (r["media"] if "media" in keys else None),
         "optic_mode": (r["optic_mode"] if "optic_mode" in keys else None),
         "priority": r["if_index"] in priority}
        for r in rows]}


def put_nodes_interface_priority(service, params, body, device_id, if_index) -> dict:
    device = _require(service.nodes_db.device(device_id), "device")
    if_index = int(if_index)
    if not service.nodes_db.interface_exists(device_id, if_index):
        raise NotFound("No such interface")
    on = bool(body.get("priority"))
    service.nodes_db.set_interface_priority(device_id, if_index, on)
    _audit(service, params, "interface.priority",
          target=f"device:{device['ip']} if:{if_index}",
          detail=f"priority {'set' if on else 'cleared'}")
    return {"device_id": int(device_id), "if_index": if_index, "priority": on}


def get_nodes_device_interfaces_export(service, params, body, device_id) -> dict:
    """One device's port table. Bounded by its own port count — a device
    with thousands of interfaces is not a case this network has — so
    there is no export ceiling to lift here, only the same rows the JSON
    handler above already reads."""
    interfaces = get_nodes_device_interfaces(service, params, body, device_id)["interfaces"]
    header = ["if_index", "descr", "name", "alias", "phys_addr", "speed_bps",
             "admin_status", "oper_status", "in_bps", "out_bps",
             "in_error_rate", "out_error_rate", "last_in_errors", "last_out_errors",
             "last_seen_ts", "poe_admin", "poe_detect_status", "poe_power_mw",
             "stp_state", "stp_blocking_vlans", "stp_vlan_count",
             "media", "optic_mode", "Priority"]
    csv_rows = [[i.get(key) for key in header[:-1]] +
                ["yes" if i.get("priority") else "no"] for i in interfaces]
    return _csv_response("interfaces", header, csv_rows)


def get_nodes_device_metrics(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    key = params.get("key")
    if key:
        row = service.nodes_db.metric_by_key(device_id, key)
        rows = [row] if row else []
    else:
        rows = service.nodes_db.metrics(device_id)
    return {"metrics": [
        {"id": r["id"], "key": r["key"], "label": r["label"], "unit": r["unit"],
         "kind": r["kind"], "last_value": r["last_value"], "last_ts": r["last_ts"]}
        for r in rows]}


def get_nodes_device_series(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
    metric_id = params.get("metric_id")
    if not metric_id:
        raise ValueError("metric_id is required")
    t0, t1 = _window(params)
    bucket_s = _series_bucket_s(params, t0, t1)
    points = service.nodes_db.series(device_id, int(metric_id), t0, t1, bucket_s=bucket_s)
    return {"t0": t0, "t1": t1, "points": points}

"""Handlers: additional per-device SNMP credentials."""

from __future__ import annotations

import functools
import ipaddress
import json

from ...eventlog import NODES as NODES_CATEGORY
from ... import mibcatalog
from ... import nodediscover
from ... import nodepoll
from ... import nodesdb

from ._shared import NotFound, _audit, _bulk_ids, _clean_priv_proto, _clear_credential, _device_index, _discovery_job_json, _may_read_secrets, _page, _pick, _refuse_orphaned_v3_secret, _require, _store_v3_credential
from .nodes import _discovery_result_json, _invalidate_oid_names


# ---------------------------------------------------- additional credentials
#
# A profile's own snmp_version/community/v3_* columns (above) are its
# always-present "primary" credential. These endpoints manage the ADDITIONAL
# credentials in its group_credentials table — alternates the poller tries,
# in order, for a device that does not answer the primary.

_GROUP_CREDENTIAL_EDITABLE = ("label", "snmp_version", "community", "v3_user",
                              "v3_auth_proto", "v3_priv_proto")


def post_nodes_group_credentials(service, params, body, group_id) -> dict:
    row = _require(service.nodes_db.group(group_id), "polling profile")
    fields = _pick(body, _GROUP_CREDENTIAL_EDITABLE)
    _clean_priv_proto(fields)
    credential_id = service.nodes_db.add_group_credential(group_id, **fields)
    service.log.add(NODES_CATEGORY,
                    f"Added an additional SNMP credential to profile {row['name']}")
    return {"id": credential_id}


def put_nodes_group_credential(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    cred = _require(cred if cred and cred["group_id"] == int(group_id) else None,
                    "credential")
    fields = _pick(body, _GROUP_CREDENTIAL_EDITABLE)
    _clean_priv_proto(fields)
    _refuse_orphaned_v3_secret(fields, cred)
    service.nodes_db.update_group_credential(credential_id, **fields)
    return {"ok": True}


def delete_nodes_group_credential_row(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    cred = _require(cred if cred and cred["group_id"] == int(group_id) else None,
                    "credential")
    service.nodes_db.remove_group_credential(credential_id)
    return {"ok": True}


def post_nodes_group_credential_secret(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    cred = _require(cred if cred and cred["group_id"] == int(group_id) else None,
                    "credential")
    return _store_v3_credential(
        service, params, body, priv_stored=bool(cred["v3_priv_pass_enc"]),
        store=functools.partial(service.nodes_db.set_group_credential_password,
                                credential_id),
        category=NODES_CATEGORY,
        message=("Stored an SNMPv3 credential for an additional "
                 f"credential on profile {cred['label'] or credential_id}"),
        target=f"profile-credential:{cred['label'] or credential_id}",
        unavailable=(
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only."))


def delete_nodes_group_credential_secret(service, params, body, group_id, credential_id) -> dict:
    cred = service.nodes_db.group_credential(credential_id)
    cred = _require(cred if cred and cred["group_id"] == int(group_id) else None,
                    "credential")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.nodes_db.clear_group_credential_password,
                                credential_id),
        category=NODES_CATEGORY,
        target=f"profile-credential:{cred['label'] or credential_id}")


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


# Per-scan timing and concurrency overrides from the Start-discovery
# dialog — they live only in the job's own settings, never in stored
# settings. `high` is None except for the worker count, a thread count that
# needs a real ceiling.
_DISCOVERY_SCAN_OVERRIDES = (
    ("snmp_timeout_s", "discovery_snmp_timeout_s", float, 0, None),
    ("ping_timeout_s", "discovery_ping_timeout_s", float, 0, None),
    ("snmp_retries", "discovery_snmp_retries", int, 0, None),
    ("ping_retries", "discovery_ping_retries", int, 0, None),
    ("workers", "discovery_workers", int, 1, nodediscover.MAX_DISCOVERY_WORKERS),
)


def _discovery_scan_overrides(body) -> dict:
    """The five timing values, validated and keyed as the dialog sends them
    — the shape stored on the job, so a rescan replays them through the
    same validation a fresh start goes through."""
    scan = {}
    for body_key, _override_key, cast, low, high in _DISCOVERY_SCAN_OVERRIDES:
        value = body.get(body_key)
        if value is not None and str(value) != "":
            value = cast(value)
            if value < low:
                raise ValueError(f"{body_key} cannot be less than {low}"
                                 if low else f"{body_key} cannot be negative")
            if high is not None and value > high:
                raise ValueError(f"{body_key} cannot be more than {high}")
            scan[body_key] = value
    return scan


def _start_discovery_job(service, kind, target, group_id,
                         allow_ping_only, scan,
                         refuse_if_target_running: bool = False) -> int:
    """Everything a discovery start is past reading the request: the profile
    turned into the communities the sweep may try, the global settings a job
    cannot see on its own, and the row that remembers both inputs. Shared
    with the rescan route so a replayed sweep can never drift from a fresh
    one — the rescan carries no logic of its own."""
    _require(service.nodes_db.group(group_id), "polling profile")
    communities = _discovery_communities_for_group(service, group_id)
    if not communities and not allow_ping_only:
        raise ValueError(
            "This profile has no v1/v2c communities for discovery to try. "
            "Pick a profile with one, or allow ping-only devices.")
    # The never-scan list and the probe rate are global settings the
    # discovery job cannot see on its own, so they are carried in with the
    # per-job overrides. Not settable from the request body: a scan does not
    # get to choose how gentle it is with a plant segment.
    overrides = {
        "discovery_communities": communities,
        "never_scan_cidrs": service.settings.get("never_scan_cidrs", ""),
    }
    for body_key, override_key, _cast, _low, _high in _DISCOVERY_SCAN_OVERRIDES:
        if body_key in scan:
            overrides[override_key] = scan[body_key]
    job_id = service.node_poller.start_discovery(
        kind, target, overrides=overrides, allow_ping_only=allow_ping_only,
        group_id=group_id, scan_overrides=scan,
        refuse_if_target_running=refuse_if_target_running)
    service.log.add(NODES_CATEGORY, f"Started {kind} discovery of {target}")
    return job_id


def post_nodes_discovery(service, params, body) -> dict:
    target = str(body.get("target", "")).strip()
    if not target:
        raise ValueError("A target is required")
    kind, target = _discovery_kind_for(target)
    group_id = body.get("group_id")
    if not group_id:
        raise ValueError("A polling profile is required")
    job_id = _start_discovery_job(
        service, kind, target, group_id,
        bool(body.get("allow_ping_only")), _discovery_scan_overrides(body))
    return {"id": job_id}


def post_nodes_discovery_rescan(service, params, body, job_id) -> dict:
    """Re-runs a finished sweep as a NEW job carrying the profile and timing
    the original ran with. Never in place: a DiscoveryJob's thread cannot be
    restarted, a second sweep writing into the same row would double-list
    every address the first one found, and the run being repeated is the
    audit trail the repeat is being compared against.

    A row started before the profile was stored on it cannot be replayed at
    all. Rather than guess one, the answer says so and the browser opens the
    Start dialog with the target filled in."""
    job = _require(service.nodes_db.discovery_job(job_id), "discovery job")
    if service.node_poller.discovery_running(job_id):
        raise ValueError(
            "This scan is still running — wait for it to finish, or cancel "
            "it, before running it again.")
    target = job["target"]
    keys = job.keys()
    group_id = job["group_id"] if "group_id" in keys else None
    if not group_id or service.nodes_db.group(group_id) is None:
        return {"needs_profile": True, "target": target,
                "allow_ping_only": bool(job["allow_ping_only"])}
    raw = job["overrides_json"] if "overrides_json" in keys else None
    try:
        stored = json.loads(raw) if raw else {}
    except ValueError:
        stored = {}
    if not isinstance(stored, dict):
        stored = {}   # only reachable from a hand-edited row; run at the defaults
    # A double-click on Re-discover, or a second operator on the same row,
    # would otherwise put two sweeps of the same /24 on the wire at once. The
    # poller answers it and starts the sweep under one lock, because asking
    # here and starting afterwards is a window two requests fit through. A
    # row left 'running' by a process that died is not a sweep anybody is
    # waiting for and does not wedge the button: what is refused is a job
    # this poller is actually running.
    try:
        new_id = _start_discovery_job(
            service, job["kind"], target, group_id,
            bool(job["allow_ping_only"]), _discovery_scan_overrides(stored),
            refuse_if_target_running=True)
    except nodepoll.DiscoveryBusy:
        raise ValueError(
            f"A scan of {target} is already running — wait for it to "
            "finish before starting another.") from None
    return {"id": new_id, "rescan_of": job_id}


def get_nodes_discovery(service, params, body) -> dict:
    limit, _offset = _page(params, 50, 500)
    return {"jobs": [_discovery_job_json(r) for r in service.nodes_db.discovery_jobs(limit)]}


def get_nodes_discovery_job(service, params, body, job_id) -> dict:
    job = _require(service.nodes_db.discovery_job(job_id), "discovery job")
    results = service.nodes_db.discovery_results(job_id)
    installed = {mib["filename"] for mib in service.nodes_db.mib_files()}
    # One pass over the fleet rather than a device_by_ip() per row — a scan
    # of a /22 can carry over a thousand results.
    index = _device_index(service)
    devices_by_ip = index["by_ip"]
    reveal = _may_read_secrets(service, params, "nodes")
    rows_json = [_discovery_result_json(row, installed, devices_by_ip, index, reveal)
                for row in sorted(results, key=lambda r: r["id"])]
    return {"job": _discovery_job_json(job), "results": rows_json}


def delete_nodes_discovery_job(service, params, body, job_id) -> dict:
    """DELETE on a running scan cancels it (the row stays, so its partial
    results can still be reviewed); DELETE on any finished/cancelled/
    errored scan removes it — and its results — from the list for good."""
    _require(service.nodes_db.discovery_job(job_id), "discovery job")
    if service.node_poller.discovery_running(job_id):
        service.node_poller.cancel_discovery(job_id)
        return {"ok": True, "cancelled": True}
    service.nodes_db.remove_discovery_job(job_id)
    return {"ok": True, "removed": True}


def post_nodes_discovery_promote(service, params, body, job_id) -> dict:
    """`result_ids` promote normally; `force_result_ids` (or legacy
    `force: true`) add those rows as their own device instead."""
    _require(service.nodes_db.discovery_job(job_id), "discovery job")
    legacy_force = bool(body.get("force"))
    result_ids = _bulk_ids(body, "result_ids", noun="discovery results", required=False)
    force_result_ids = _bulk_ids(body, "force_result_ids", noun="discovery results",
                                 required=False)
    if not result_ids and not force_result_ids:
        raise ValueError("No results selected")
    combined = []
    for result_id in result_ids + force_result_ids:
        if result_id not in combined:
            combined.append(result_id)
    device_ids = service.node_poller.promote(
        job_id, combined, force=legacy_force, force_ids=force_result_ids)
    service.log.add(NODES_CATEGORY,
                    f"Promoted {len(device_ids)} device(s) from discovery job #{job_id}")
    return {"device_ids": device_ids}


def post_nodes_discovery_reviewed(service, params, body, job_id) -> dict:
    """The approve/deny dialog for this job was answered (or dismissed) —
    either way it must never pop again, whatever was or wasn't added."""
    _require(service.nodes_db.discovery_job(job_id), "discovery job")
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
    from ... import mibparse
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
    afterwards, which makes upload order irrelevant."""
    import base64
    from ... import mibcatalog, mibparse

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
        _audit(service, params, "mib.upload", target=filename,
              detail=f"loaded={len(loaded)}, skipped={len(skipped)}")
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
    _audit(service, params, "mib.upload", target=filename,
          detail=f"module={result['module'] or 'unknown'}")
    return result


def post_nodes_mibs_resolve_all(service, params, body) -> dict:
    """Re-resolve every stored MIB against every other, to a fixpoint —
    the one button that fixes a list of files uploaded in the wrong order
    without an admin having to guess which one to press Resolve on."""
    from ... import mibparse

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
    from ... import mibcatalog

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
    row = _require(service.nodes_db.mib_file(mib_file_id), "MIB file")
    objects = service.nodes_db.mib_objects(mib_file_id)
    return {"file": _mib_file_json(row),
            "objects": [_mib_object_json(r) for r in objects]}


def delete_nodes_mib(service, params, body, mib_file_id) -> dict:
    row = _require(service.nodes_db.mib_file(mib_file_id), "MIB file")
    service.nodes_db.remove_mib_file(mib_file_id)
    service._snmp_settings_with_mibs()
    service.log.add(NODES_CATEGORY, f"Removed MIB {row['filename']}")
    _audit(service, params, "mib.delete", target=row["filename"])
    return {"ok": True}


def post_nodes_mib_resolve(service, params, body, mib_file_id) -> dict:
    """Re-parses the file's own stored text from scratch (mib_objects only
    keeps the final oid or NULL, not the parent/last_arc an unresolved
    object needs to retry) and resolves again against everything
    currently known — this is the whole "upload CISCO-SMI after
    CISCO-PROCESS-MIB, then hit resolve" story."""
    from ... import mibparse

    row = _require(service.nodes_db.mib_file(mib_file_id), "MIB file")
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


def _clean_oid(value) -> str:
    """A dotted numeric OID, or ValueError.

    isascii() as well as isdigit(), and no sign accepted, because the BER
    encoder this eventually reaches shifts each arc right seven bits at a
    time: a negative arc never terminates that loop, and str.isdigit() is
    True for superscript and Arabic-Indic digits that int() rejects. Either
    would land here as a stored OID the poller then reads on every poll.
    """
    oid = str(value or "").strip().strip(".")
    parts = oid.split(".") if oid else []
    if not parts or not all(part.isascii() and part.isdigit() for part in parts):
        raise ValueError("An OID must be numeric, like 1.3.6.1.2.1.1")
    return oid


def put_nodes_mib_object(service, params, body, mib_file_id, obj_id) -> dict:
    objects = {r["id"]: r for r in service.nodes_db.mib_objects(mib_file_id)}
    if obj_id not in objects:
        raise NotFound("No such MIB object")
    fields = _pick(body, ("name", "oid", "description", "syntax", "enums"))
    if "oid" in fields:
        fields["oid"] = _clean_oid(fields["oid"])
    service.nodes_db.update_mib_object(obj_id, **fields)
    # A rename or a re-pointed OID changes what the table says without
    # changing any of the three numbers mib_generation() counts.
    _invalidate_oid_names()
    service._snmp_settings_with_mibs()
    return {"ok": True}

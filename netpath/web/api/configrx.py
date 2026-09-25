"""Handlers: ConfigRX backups, search, compliance and SSH host keys."""

from __future__ import annotations

import functools
import json
import time

from ... import namelookup
from ...eventlog import CONFIGRX as CONFIGRX_CATEGORY
from ... import configrx
from ... import configrx_compliance
from ... import configrx_redact
from ... import nodesdb

from ._shared import NotFound, _UNSET, _audit, _audit_diff, _bulk_device_ids, _bulk_ids, _clear_credential, _encrypt_secret, _id_list, _may_read_secrets, _num, _page, _pick, _require, _ssh_device_host


# ----------------------------------------------------------------- configrx

def _configrx_device_json(service, device_row, worker_state=None,
                          config=_UNSET, global_has_cred=_UNSET) -> dict:
    # `config` pre-read by a list caller that fetched every row in one query
    # (all_device_configs); _UNSET rather than None so "this device has no
    # config row" stays distinguishable from "nobody looked it up yet".
    if config is _UNSET:
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
    own_credential = bool(config["ssh_password_enc"]) if config else False
    if global_has_cred is _UNSET:
        glob = service.configrx_db.global_credential()
        global_has_cred = bool(glob and glob["password_enc"])
    credential_source = "stored" if own_credential else ("global" if global_has_cred else "")
    return {
        "id": device_row["id"], "ip": device_row["ip"],
        "name": name,
        "vendor": device_row["vendor"],
        # The vendor this device would ACTUALLY back up as, resolved the same
        # way configrx._backup_device resolves it: the explicit override, then
        # what SNMP detected — not the displayed vendor, which a custom vendor
        # OID may have replaced with free text.
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
        "has_credential": own_credential,
        "credential_source": credential_source,
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
    row = _require(service.configrx_db.backup(backup_id), "backup")
    removed = service.configrx_db.delete_backup(backup_id)
    if removed:
        service.log.add(CONFIGRX_CATEGORY,
                        f"Deleted a stored config backup for device {row['device_id']}")
        # There is no restore-to-device capability here, so a deleted
        # backup's config content is gone for good — which makes "who deleted
        # it" worth recording. device.ip over the bare id, matching every
        # other device-scoped audit target, falling back to the id on a row
        # whose device has since been removed.
        device = service.nodes_db.device(row["device_id"])
        target = f"device:{device['ip']}" if device else f"device:{row['device_id']}"
        _audit(service, params, "configrx.backup_delete", target=target,
              detail=f"backup #{backup_id}")
    return {"ok": True, "removed": 1 if removed else 0}


def post_configrx_backups_bulk_delete(service, params, body) -> dict:
    removed = service.configrx_db.delete_backups(
        _bulk_ids(body, "backup_ids", noun="backups"))
    service.log.add(CONFIGRX_CATEGORY, f"Deleted {removed} stored config backup(s)")
    _audit(service, params, "configrx.backup_bulk_delete", target=f"{removed} backups")
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
    # One read for the whole list, the shape get_configrx_overview already
    # uses: a device_config() per device was one configrx.db lock
    # acquisition per device on every refresh tick.
    configs = {c["device_id"]: c for c in service.configrx_db.all_device_configs()}
    glob = service.configrx_db.global_credential()
    global_has_cred = bool(glob and glob["password_enc"])
    devices = [_configrx_device_json(service, r, worker_state,
                                     configs.get(r["id"]), global_has_cred)
               for r in rows]
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
    device = _require(service.nodes_db.device(device_id), "device")
    return {"device": _configrx_device_json(
        service, device, service.configrx.worker_state())}


def post_configrx_device_config(service, params, body, device_id) -> dict:
    device = _require(service.nodes_db.device(device_id), "device")
    fields = _pick(body, ("backup_enabled", "ssh_port", "ssh_username",
                          "vendor_override", "store_secrets"))
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
        # device:{ip}, not a bare device_id — the same target shape every
        # other device-scoped audit line in this file uses.
        _audit(service, params,
               "configrx.store_secrets", target=f"device:{device['ip']}",
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
    fields = _pick(body, ("backup_enabled", "ssh_port", "vendor_override",
                          "ssh_username"))
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
    configs = {c["device_id"]: c for c in service.configrx_db.all_device_configs()}
    queued, busy, missing, not_enabled = [], [], [], []
    for device_id in device_ids:
        if device_id not in existing:
            missing.append(device_id)
            continue
        config = configs.get(device_id)
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


def post_configrx_credential(service, params, body) -> dict:
    """Stores the single global ConfigRX account, used for a backup when a
    device carries no ssh_username/ssh_password of its own."""
    username = str(body.get("ssh_username", "")).strip()
    password = str(body.get("ssh_password", ""))
    if not username:
        raise ValueError("A username is required")
    if password:
        try:
            encrypted = _encrypt_secret(password, (
                "This machine cannot encrypt a stored credential — DPAPI is "
                "Windows-only, so ConfigRX refuses to store an SSH password "
                "here rather than keep it in plain text."))
        finally:
            password = None
    else:
        # Username-only update: keep the stored password, refusing only
        # when there is none to keep.
        existing = service.configrx_db.global_credential()
        if not existing or not existing["password_enc"]:
            raise ValueError("A username and password are both required")
        encrypted = bytes(existing["password_enc"])
    service.configrx_db.set_global_credential(username, encrypted)
    service.log.add(CONFIGRX_CATEGORY, "Stored the global ConfigRX SSH account")
    _audit(service, params, "credential.store", target="configrx:global",
           detail=f"username {username}")
    # Served from /api/config (configrx_global_credential) — refetched only
    # when config_version moves, the same reason post_configrx_worker bumps it.
    service.bump_config()
    return {"ok": True}


def delete_configrx_credential(service, params, body) -> dict:
    result = _clear_credential(
        service, params,
        clear=service.configrx_db.clear_global_credential,
        category=CONFIGRX_CATEGORY,
        message="Cleared the global ConfigRX SSH account",
        target="configrx:global")
    service.bump_config()
    return result


def post_configrx_devices_bulk_credential(service, params, body) -> dict:
    device_ids = _bulk_device_ids(body)
    username = str(body.get("ssh_username", "")).strip()
    password = str(body.get("ssh_password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    try:
        # Encrypted once, not once per device: it is the same plaintext going
        # to every selected device, so there is no reason to pay for (or add a
        # second window of exposure from) a repeated encrypt call.
        encrypted = _encrypt_secret(password, (
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only, so ConfigRX refuses to store an SSH password "
            "here rather than keep it in plain text."))
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
    row = _require(service.nodes_db.device(device_id), "device")
    username = str(body.get("ssh_username", "")).strip()
    password = str(body.get("ssh_password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    unavailable = (
        "This machine cannot encrypt a stored credential — DPAPI is "
        "Windows-only, so ConfigRX refuses to store an SSH password "
        "here rather than keep it in plain text.")
    # The enable secret is separate and optional, with set_credential's own
    # three-way contract: the key absent from the body leaves whatever is
    # already stored untouched, present-and-empty clears it, present-and-
    # non-empty (re)encrypts and stores it. Needed only by a vendor whose
    # login shell may not already be privileged EXEC (configrx.VENDORS'
    # enable_command entries: Cisco IOS/IOS-XE, NX-OS, IOS-XR, SG/CBS, ASA,
    # and Rockwell Stratix).
    enable_kwargs = {}
    if "enable_secret" in body:
        enable_secret = str(body.get("enable_secret") or "")
        enable_kwargs["enable_secret_enc"] = (
            _encrypt_secret(enable_secret, unavailable) if enable_secret else None)
        enable_secret = None
    try:
        encrypted = _encrypt_secret(password, unavailable)
    finally:
        password = None
    service.configrx_db.set_credential(device_id, username, encrypted, **enable_kwargs)
    service.log.add(CONFIGRX_CATEGORY, f"Stored an SSH credential for {row['ip']}")
    _audit(service, params, "credential.store", target=f"configrx:{row['ip']}",
           detail=f"username {username}")
    return {"ok": True}


def delete_configrx_device_credential(service, params, body, device_id) -> dict:
    row = _require(service.nodes_db.device(device_id), "device")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.configrx_db.clear_credential, device_id),
        category=CONFIGRX_CATEGORY,
        message=f"Cleared the stored SSH credential for {row['ip']}",
        target=f"configrx:{row['ip']}")


def delete_configrx_device_enable_secret(service, params, body, device_id) -> dict:
    """The SSH username/password are untouched — only ConfigRxDatabase.
    clear_enable_secret runs, for the device that turned out not to need
    one. Clearing the whole credential (above) still clears both, per this
    release's security review; this is the narrower operation that was
    missing beside it."""
    row = _require(service.nodes_db.device(device_id), "device")
    service.configrx_db.clear_enable_secret(device_id)
    service.log.add(CONFIGRX_CATEGORY, f"Cleared the stored enable secret for {row['ip']}")
    _audit(service, params, "credential.clear", target=f"configrx:{row['ip']}",
           detail="enable secret only")
    return {"ok": True}


def get_configrx_device_backups(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
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
    row = _require(service.configrx_db.backup(backup_id), "backup")
    content = service.configrx_db.backup_content(backup_id)
    backup_json = _configrx_backup_json(row)
    # Redact on the way out for anyone without ConfigRX write, whatever the
    # stored flag says. The flag means "we ran the redactor", not "the
    # redactor found and removed something" — a vendor no pattern matches is
    # stored verbatim and still stamped redacted=True, so trusting it would
    # serve a RADIUS key or an IKE pre-shared key in full to a caller holding
    # only ConfigRX read. Redaction is idempotent, so re-running it here
    # costs one pass and takes the flag out of the trust boundary.
    if not _may_read_secrets(service, params, "configrx"):
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

    That same property (secret changes are invisible to the redacted diff)
    means an empty `diff` is ambiguous on its own: it is the honest answer
    both for "nothing changed" and for "only a secret's value changed" —
    and those are very different things for an operator to be told. Both
    backups' own `sha256` (of the stored bytes, never redacted) still
    tells the two apart even when their redacted bodies render identically,
    so `redacted_only_change` is set whenever the visible diff is
    empty but the underlying backups are not actually the same — a rotated
    enable secret or a changed SNMP community are exactly this case, and
    without this flag they render as a clean, reassuring empty diff, which
    is the one place this feature must not be silent. `identical` means
    what it says now: the two backups genuinely are the same, not merely
    "nothing visible differs".
    """
    device_id = _num(params, "device", None, int)
    if not device_id or not service.nodes_db.device(device_id):
        raise NotFound("No such device")
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
    # Two rows with the same content hash cannot diff to anything, whether
    # that is one backup picked for both ends or a config reverted to
    # something backed up before. Not just an optimisation: skipping
    # redact()+unified_diff means picking the same backup twice never runs a
    # diff over its own secrets.
    if from_row["id"] == to_row["id"] or from_row["sha256"] == to_row["sha256"]:
        return {"diff": "", "additions": 0, "removals": 0,
                "from": from_json, "to": to_json, "identical": True,
                "redacted_only_change": False}

    from_content = service.configrx_db.backup_content(from_row["id"]) or ""
    to_content = service.configrx_db.backup_content(to_row["id"]) or ""
    from_redacted, _ = configrx_redact.redact(from_content)
    to_redacted, _ = configrx_redact.redact(to_content)
    text, additions, removals = configrx.diff_texts(
        from_redacted, to_redacted,
        _configrx_backup_label(from_row), _configrx_backup_label(to_row))
    # The fast path above caught the equal-hash case, so these two rows are
    # never identical: an empty `text` means the stored bytes differ entirely
    # inside material configrx_redact.redact() maps onto the same literal
    # token on both sides, so nothing about the difference survives into the
    # rendered diff.
    return {"diff": text, "additions": additions, "removals": removals,
            "from": from_json, "to": to_json, "identical": False,
            "redacted_only_change": not text}


def post_configrx_device_backup(service, params, body, device_id) -> dict:
    _require(service.nodes_db.device(device_id), "device")
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


# ------------------------------------------------------- search + compliance
#
# netpath/configrx_compliance.py: cross-device config search, and the
# compliance rule sets that turn a repeated search into a standing pass/fail
# column. That module redacts and bounds everything that needs it, so these
# routes are the thin dispatch on top — neither result carries an unredacted
# secret, so both read as ("configrx", R); rule-set/rule CRUD changes
# monitoring policy, so ("configrx", W).

def _configrx_search_json(service, result: dict) -> dict:
    """search()'s raw {device_id, line_no, line} rows, with each match's
    device name/ip hydrated in from one batch fetch rather than a
    nodes_db.device() call per match."""
    device_ids = {m["device_id"] for m in result["matches"]}
    devices = {row["id"]: row for row in service.nodes_db.devices_by_ids(device_ids)}
    matches = []
    for m in result["matches"]:
        device = devices.get(m["device_id"])
        matches.append({
            "device_id": m["device_id"],
            "device_name": namelookup.device_name(device) if device else None,
            "device_ip": device["ip"] if device else None,
            "line_no": m["line_no"], "line": m["line"],
        })
    return {"matches": matches, "truncated": result["truncated"], "indexed": result["indexed"]}


CONFIGRX_SEARCH_MAX_LIMIT = 2000


def get_configrx_search(service, params, body) -> dict:
    """One query against every device's latest redacted capture — see
    configrx_compliance.search. `mode=regex` runs a bounded regular expression
    (configrx_compliance.UnsafeRegex, a ValueError subclass, reaches server.py's
    ordinary ValueError->400 handling unchanged, so a refused pattern comes
    back as a plain 400 naming what was wrong with it, not a 500)."""
    query = str(params.get("query", "")).strip()
    if not query:
        raise ValueError("query is required")
    mode = str(params.get("mode") or "text")
    device_ids = _id_list(params.get("device"))
    limit, _offset = _page(params, configrx_compliance.DEFAULT_LIMIT,
                           CONFIGRX_SEARCH_MAX_LIMIT)
    result = configrx_compliance.search(service.configrx_db, query, mode=mode,
                                    device_ids=device_ids, limit=limit)
    return _configrx_search_json(service, result)


def get_configrx_rule_sets(service, params, body) -> dict:
    enabled_only = str(params.get("enabled_only", "")).strip().lower() in ("1", "true", "yes")
    return {"rule_sets": [dict(r) for r in
                          service.configrx_db.rule_sets(enabled_only=enabled_only)]}


def post_configrx_rule_set(service, params, body) -> dict:
    name = str(body.get("name", "")).strip()
    if not name:
        raise ValueError("A name is required")
    device_group_id = body.get("device_group_id")
    rule_set_id = configrx_compliance.add_rule_set(
        service.configrx_db, name, int(device_group_id) if device_group_id else None)
    service.log.add(CONFIGRX_CATEGORY, f"Added ConfigRX rule set {name}")
    _audit(service, params, "configrx.rule_set.create", target=name)
    return {"id": rule_set_id}


def get_configrx_rule_set(service, params, body, rule_set_id) -> dict:
    row = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    return {"rule_set": dict(row)}


def put_configrx_rule_set(service, params, body, rule_set_id) -> dict:
    # Fetched before the update — update_rule_set itself never reads the
    # row it is about to change.
    before = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    fields = _pick(body, ("name", "device_group_id", "enabled"))
    service.configrx_db.update_rule_set(rule_set_id, **fields)
    detail = _audit_diff(before, fields)
    if detail:
        _audit(service, params, "configrx.rule_set.update", target=before["name"],
              detail=detail)
    return {"ok": True}


def delete_configrx_rule_set(service, params, body, rule_set_id) -> dict:
    row = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    service.configrx_db.delete_rule_set(rule_set_id)
    service.log.add(CONFIGRX_CATEGORY, f"Removed ConfigRX rule set {row['name']}")
    _audit(service, params, "configrx.rule_set.delete", target=row["name"])
    return {"ok": True}


def _compliance_rule_json(row, reveal: bool) -> dict:
    # A rule's pattern is not text that MIGHT contain a secret the way a
    # backup line is: the Add-rule dialog says outright that a rule can check
    # a secret's actual value, so the pattern can simply BE the community
    # string or password. That puts it behind ConfigRX write, not this
    # route's plain read. There is no partial redaction to fall back on —
    # the whole pattern IS the value — so a caller without write gets every
    # other field plus an explicit `pattern_hidden` flag rather than a
    # pattern that silently reads as empty.
    fields = dict(row)
    if not reveal:
        fields["pattern"] = None
        fields["pattern_hidden"] = True
    return fields


def get_configrx_rule_set_rules(service, params, body, rule_set_id) -> dict:
    _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    reveal = _may_read_secrets(service, params, "configrx")
    return {"rules": [_compliance_rule_json(r, reveal) for r in service.configrx_db.rules_for(rule_set_id)]}


def post_configrx_rule_set_rule(service, params, body, rule_set_id) -> dict:
    row = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    description = str(body.get("description", "")).strip()
    kind = str(body.get("kind", ""))
    pattern = str(body.get("pattern", ""))
    ordinal = int(body.get("ordinal", 0) or 0)
    # configrx_compliance.add_rule raises ValueError for a bad kind or an
    # empty description, and configrx_compliance.UnsafeRegex (itself a
    # ValueError) for a pattern unsafe to ever run — all three reach
    # server.py's ordinary ValueError->400 handling unchanged.
    rule_id = configrx_compliance.add_rule(
        service.configrx_db, rule_set_id, description, kind, pattern, ordinal)
    _audit(service, params, "configrx.rule.create", target=row["name"],
          detail=f"{kind}: {description}")
    return {"id": rule_id}


def delete_configrx_rule_set_rule(service, params, body, rule_set_id, rule_id) -> dict:
    rule_set = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    rule = _require(next((r for r in service.configrx_db.rules_for(rule_set_id)
                          if r["id"] == int(rule_id)), None), "rule")
    service.configrx_db.delete_rule(rule_id)
    _audit(service, params, "configrx.rule.delete", target=rule_set["name"],
          detail=rule["description"])
    return {"ok": True}


def post_configrx_rule_set_evaluate(service, params, body, rule_set_id) -> dict:
    """The manual "re-evaluate now" action — automatic evaluation already
    happens on every new capture and on ConfigRxWorker's own hourly sweep,
    so this exists for an operator who just edited a rule set and does not
    want to wait for either."""
    row = _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    count = configrx_compliance.evaluate_all(
        service.configrx_db, service.nodes_db, rule_set_id=rule_set_id)
    _audit(service, params, "configrx.rule_set.evaluate", target=row["name"],
          detail=f"{count} device(s) evaluated")
    return {"evaluated": count}


def _compliance_result_json(row) -> dict:
    try:
        failed_rules = json.loads(row["failed_rules"]) if row["failed_rules"] else []
    except (TypeError, ValueError):
        failed_rules = []
    return {"device_id": row["device_id"], "rule_set_id": row["rule_set_id"],
           "status": row["status"], "failed_rules": failed_rules,
           "backup_id": row["backup_id"], "evaluated_ts": row["evaluated_ts"]}


def get_configrx_rule_set_results(service, params, body, rule_set_id) -> dict:
    """Every device's latest result for one rule set — the column a
    2,000-row device list reads, one query rather than one per device."""
    _require(service.configrx_db.rule_set(rule_set_id), "rule set")
    rows = service.configrx_db.compliance_results_for_rule_set(rule_set_id)
    return {"results": [_compliance_result_json(r) for r in rows]}


def get_configrx_device_compliance(service, params, body, device_id) -> dict:
    """The per-device tab equivalent of the route above: every rule set's
    latest result for one device."""
    _require(service.nodes_db.device(device_id), "device")
    rows = service.configrx_db.compliance_results_for_device(device_id)
    return {"results": [_compliance_result_json(r) for r in rows]}


# ------------------------------------------------------------- ssh host keys


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

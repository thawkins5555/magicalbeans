"""Handlers: application settings, storage usage and sign-in (AAA)."""

from __future__ import annotations

import time

from ... import alertsdb
from ...eventlog import SYSTEM as SYSTEM_CATEGORY
from ... import configrx_compliance
from ... import webrelay
from ... import nodesdb
from ... import db as netpathdb
from ... import permissions as _permissions
from ... import appdb as _appdb

from ._shared import Accepted, _audit, _encrypt_secret, _is_admin, _num, _page, _visible_settings, request_permissions


# ----------------------------------------------------------------- settings

# Every settings scope a module owns, and the key POST /api/settings answers
# with: {scope: response key}. The route table derives the permission from
# THIS table (server._settings_requirement) rather than from
# permissions.MODULES — a module in MODULES with no entry here (`debug` was
# one) was authorized against itself and then fell through to the global
# writer, which is how a debug:write account rewrote the listener's bind
# address, TLS paths and the DNS server. Anything not named here is the
# Settings module's, by construction.
SETTINGS_SCOPES = {
    "netpath": "settings",
    "netflow": "flow_settings",
    "syslog": "syslog_settings",
    "snmp": "snmp_settings",
    "ipam": "ipam_settings",
    "nodes": "nodes_settings",
    "alerts": "alerts_settings",
    "wireless": "wireless_settings",
    "configrx": "configrx_settings",
    "mapper": "mapper_settings",
}


# Global settings that are not an operator's to change even with Settings
# write. Turning self-update on decides whether this host replaces its own
# code from the internet; the ldap_* keys decide who may sign in at all and
# where a password gets sent; session_* decides how long every account's
# sign-in lasts (applied immediately, not at the next restart); web_* decides
# which certificate the listener presents and where it binds. Each is an
# administrator's call in the same sense creating an account is.
# SETTINGS_ONLY_KEYS below only hides them from a reader — this is what
# stops a settings:write grant, deliberately weaker than admin, writing
# them.
ADMIN_ONLY_SETTINGS = ("updates_enabled", "ldap_enabled", "ldap_url",
                      "ldap_bind_dn_template", "ldap_allow_cleartext",
                      "ldap_timeout_s",
                      # TACACS+: the same "who may sign in at all" call as
                      # the ldap_* keys above.
                      "tacacs_enabled", "tacacs_servers", "tacacs_timeout_s",
                      "tacacs_auto_create", "tacacs_default_role",
                      # The write-only field a client posts; the stored
                      # tacacs_secret_enc blob is never client-settable.
                      "tacacs_secret",
                      "session_idle_minutes", "session_max_hours",
                      "web_host", "web_port", "web_cert", "web_key",
                      # Same kind of decision as where the listener binds.
                      "web_relay_port_range")


def _may_change_admin_settings(service, params) -> bool:
    """Whether this caller may change ADMIN_ONLY_SETTINGS. Its own function
    so there is exactly one place the answer is decided."""
    return _is_admin(service, params)


# Mirrors the min/max on each of these inputs in index.html: the Settings
# page refuses an out-of-range number before posting, but an API client can
# skip the browser. None as a high means the field is open-ended (a database
# cap has a floor, never a ceiling).
_GLOBAL_SETTINGS_RANGES = {
    "dns_workers": (1, 32),
    "dns_timeout_s": (0.5, 30),
    "tacacs_timeout_s": (1, 60),
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
    "debug_log_capacity": (1000, 50000),
    "max_trace_db_mb": (16, None),
    # The age cap beside the size cap. The maintenance pass calls prune()
    # every interval, so a 0 posted straight to the API (the Settings page's
    # input says min="1", but a client can skip the browser) would compute a
    # cutoff of "now" and silently delete every trace, over and over.
    "trace_retention_days": (1, 3650),
    # The two rollup retentions, netflow-scope, mirroring netflow.js's own
    # min=0 on them. 0 is a real choice there — keep no summaries at this
    # tier — but a negative puts _prune_rollup's cutoff in the future, which
    # deletes every rollup row on every sweep and leaves the tier's floor
    # ahead of now, silently taking it out of service while compaction goes
    # on writing to it.
    "rollup_minute_days": (0, 3650),
    "rollup_retention_days": (0, 3650),
    "app_db_warn_mib": (16, None),
    "max_flow_db_mb": (16, None),
    "max_snmp_db_mb": (16, None),
    "max_syslog_db_mb": (16, None),
    "max_ipam_db_mb": (16, None),
    "max_wireless_db_mb": (16, None),
    "max_nodes_db_mb": (16, None),
    "max_nodes_series_db_mb": (16, None),
    "max_alerts_db_mb": (16, None),
    # Bounded well below 100: a free-space floor at or near the whole volume
    # is an alert that can never clear.
    "disk_free_warn_pct": (1, 90),
    "disk_free_critical_pct": (1, 90),
    "session_idle_minutes": (1, 1440),
    "session_max_hours": (1, 168),
    # These five are netpath-scope, not global, but land in the same flat
    # dict because _check_settings_ranges only cares whether a key is
    # PRESENT, never which scope it came from. trace_workers is a
    # ThreadPoolExecutor size; the rest are what a new target is created
    # from. Referencing db.py's MIN_*/MAX_* rather than repeating the
    # numbers, so this cannot drift from what add_target enforces.
    "trace_workers": (netpathdb.MIN_TRACE_WORKERS, netpathdb.MAX_TRACE_WORKERS),
    "default_interval_s": (netpathdb.MIN_INTERVAL_S, netpathdb.MAX_INTERVAL_S),
    "default_max_hops": (netpathdb.MIN_MAX_HOPS, netpathdb.MAX_MAX_HOPS),
    "default_probes": (netpathdb.MIN_PROBES, netpathdb.MAX_PROBES),
    "default_timeout_s": (netpathdb.MIN_TIMEOUT_S, netpathdb.MAX_TIMEOUT_S),
}


# The one key two scopes disagree about. 0 is a real choice for a flow
# rollup tier ("keep no summaries here"), but nodes' rollup_retention_days
# bounds samples_hourly, where nodesseriesdb.prune reads 0 as "matches every
# existing row" -- a year of metric history gone on the next sweep. The
# browser has always sent min=1 for it; this is the same floor for a client
# that skips the browser.
_SCOPE_SETTINGS_RANGES = {
    "nodes": {"rollup_retention_days": (1, 3650),
              "interface_sample_retention_days": (1, 3650),
              "interface_rollup_retention_days": (1, 3650)},
    # -1 deletes every ap_samples/radio_samples row on the next sweep
    # (prune_history reads it as "everything is older than this"); 0
    # writes a row every poll instead of every history_sample_s.
    "wireless": {"history_days": (1, 3650), "history_sample_s": (60, 86400),
                 "ap_web_port": (1, 65535)},
}


def _check_settings_ranges(values: dict, scope: str = "") -> None:
    overrides = _SCOPE_SETTINGS_RANGES.get(scope, {})
    for key, (low, high) in {**_GLOBAL_SETTINGS_RANGES, **overrides}.items():
        if key not in values:
            continue
        value = values[key]
        if value < low or (high is not None and value > high):
            range_text = (f"between {low} and {high}" if high is not None
                         else f"at least {low}")
            raise ValueError(f"{key} must be {range_text}")


def _scope_defaults(scope: str) -> dict:
    """The defaults dict whose value types a scope's settings must match."""
    from ... import (alertsdb, appdb, configrxdb, db, flowdb, ipamdb, mapperdb,
                    nodesdb, snmptrapdb, syslogdb, wirelessdb)
    return {
        "netpath": db.NETPATH_DEFAULTS, "netflow": flowdb.DEFAULTS,
        "syslog": syslogdb.DEFAULTS, "snmp": snmptrapdb.DEFAULTS,
        "ipam": ipamdb.DEFAULTS, "nodes": nodesdb.DEFAULTS,
        "alerts": alertsdb.DEFAULTS, "wireless": wirelessdb.DEFAULTS,
        "configrx": configrxdb.DEFAULTS, "mapper": mapperdb.DEFAULTS,
    }.get(scope, appdb.GLOBAL_DEFAULTS)


# Mirrors index.html's own min/max on the MAPPER settings dialog's VLAN
# collapse threshold, the same way _GLOBAL_SETTINGS_RANGES mirrors the
# global Settings page's inputs -- kept apart from that dict because it is
# not a global setting, and _check_settings_ranges only ever checks
# _GLOBAL_SETTINGS_RANGES regardless of scope. map_style has no numeric
# range to speak of (it is one of mapperdb.MAP_STYLES), so it gets its own
# membership check rather than being forced into a (low, high) shape that
# does not fit it.
def _check_mapper_settings(service, values: dict) -> None:
    from ... import mapperdb

    if "vlan_collapse_threshold" in values:
        threshold = values["vlan_collapse_threshold"]
        if threshold < 1 or threshold > 30:
            raise ValueError("vlan_collapse_threshold must be between 1 and 30")
    # max_strand_vlans is mapper.render_plan's genuine cap (mirrors
    # index.html's own "Never draw more than N strands" input, min 1 max
    # 200) — validated at all once it actually means that, so a stray huge
    # or zero/negative value can no longer reach render_plan and produce
    # nonsense strand counts or a divide-by-zero-shaped span.
    if "max_strand_vlans" in values:
        max_strands = values["max_strand_vlans"]
        if max_strands < 1 or max_strands > 200:
            raise ValueError("max_strand_vlans must be between 1 and 200")
    # Below 0.5 (index.html's own floor for the same field) a strand's
    # width -- and, per render_plan's symmetric spacing, every OTHER
    # strand's offset from the link's centre line, since offsets are
    # multiples of width_min*2 -- collapses toward zero, drawing every
    # strand of a multi-VLAN link on top of the same line.
    if "link_width_min" in values:
        width_min = values["link_width_min"]
        if width_min < 0.5:
            raise ValueError("link_width_min must be at least 0.5")
    if "link_width_max" in values:
        width_max = values["link_width_max"]
        if width_max < 1:
            raise ValueError("link_width_max must be at least 1")
    # Cross-field checks below read whichever side of a pair THIS request
    # does not mention from the currently-applied settings (post_settings
    # calls this before apply_settings merges/saves, so mapper_settings is
    # still last request's values) -- a request naming only one of a pair
    # is exactly how an operator moving one slider at a time would call
    # this, and it must be checked against what the other one actually is,
    # not skipped for want of both being named in the same body.
    if "vlan_collapse_threshold" in values or "max_strand_vlans" in values:
        threshold = values.get(
            "vlan_collapse_threshold", service.mapper_settings.get(
                "vlan_collapse_threshold", mapperdb.DEFAULTS["vlan_collapse_threshold"]))
        max_strands = values.get(
            "max_strand_vlans", service.mapper_settings.get(
                "max_strand_vlans", mapperdb.DEFAULTS["max_strand_vlans"]))
        # <=, not <: at max_strand_vlans == vlan_collapse_threshold, render_
        # plan's span (max_strands - threshold) is 0, and a link exactly at
        # the threshold already takes the collapsed branch (count < threshold
        # is false there) -- so it draws at width_max instead of the width_min
        # the strand mode one VLAN fewer would have used, the exact
        # discontinuity this finding reproduced.
        if max_strands <= threshold:
            raise ValueError(
                "max_strand_vlans must be greater than vlan_collapse_threshold "
                f"({threshold}), or a link exactly at the threshold draws at "
                "the maximum width instead of the minimum")
    if "link_width_min" in values or "link_width_max" in values:
        width_min = values.get(
            "link_width_min", service.mapper_settings.get(
                "link_width_min", mapperdb.DEFAULTS["link_width_min"]))
        width_max = values.get(
            "link_width_max", service.mapper_settings.get(
                "link_width_max", mapperdb.DEFAULTS["link_width_max"]))
        if width_max < width_min:
            raise ValueError("link_width_max must be at least link_width_min")
    if "map_style" in values and values["map_style"] not in mapperdb.MAP_STYLES:
        raise ValueError(f"Unknown map_style: {values['map_style']!r}")


def _check_configrx_settings(values: dict) -> None:
    """`ignore_line_patterns` is one regex per line, validated with the
    same bounded-regex compiler compliance rules use, so a pattern that
    could run away on a real capture is refused here rather than producing
    bad diffs later."""
    from ... import configrx_compliance

    if "ignore_line_patterns" not in values:
        return
    for line in str(values["ignore_line_patterns"]).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            configrx_compliance.compile_bounded(line)
        except configrx_compliance.UnsafeRegex as exc:
            raise ValueError(f"Line ignore pattern {line!r} is invalid: {exc}") from exc


def _check_netflow_settings(values: dict) -> None:
    """A port or interface name is shown in every viewer's flow table, so
    the markup characters are refused here as well as escaped there."""
    for key in ("custom_ports", "interface_names"):
        text = str(values.get(key, ""))
        if "<" in text or ">" in text:
            raise ValueError(f"{key}: a name cannot contain < or >")
    # Same bound as the other rollup-retention day settings (0 keeps no
    # interface-scope summaries at all, a negative would put prune()'s
    # cutoff in the future and delete every one of them on the next sweep).
    if "rollup_interface_days" in values:
        days = values["rollup_interface_days"]
        if not (0 <= days <= 3650):
            raise ValueError("rollup_interface_days must be between 0 and 3650")


def _check_tacacs_settings(values: dict) -> None:
    """`tacacs_servers` parses (a clear error naming the bad entry rather
    than a client-side surprise on first sign-in) and `tacacs_default_role`
    is one of permissions.role_grants' names, whichever of the two the
    caller actually posted."""
    from ... import tacacsclient

    if "tacacs_servers" in values and str(values["tacacs_servers"]).strip():
        try:
            tacacsclient.parse_servers(values["tacacs_servers"])
        except tacacsclient.TacacsConfigError as exc:
            raise ValueError(f"tacacs_servers: {exc}") from exc
    if "tacacs_default_role" in values:
        if values["tacacs_default_role"] not in _permissions.AUTO_CREATE_ROLES:
            raise ValueError(
                "tacacs_default_role must be viewer or operator")


def _check_disk_free_settings(service, values: dict) -> None:
    """The critical free-space floor has to sit below the warning one.

    Posted the other way round, every volume alert opens at critical the
    moment it opens at all, and the warning band it is meant to escalate
    from can never be reached. Either key can arrive on its own, so the one
    that is not in the body is read from what is stored, the way
    _check_mapper_settings pairs its two.
    """
    if not ({"disk_free_warn_pct", "disk_free_critical_pct"} & set(values)):
        return
    warn = float(values.get("disk_free_warn_pct",
                            service.settings.get("disk_free_warn_pct", 10)))
    critical = float(values.get("disk_free_critical_pct",
                                service.settings.get("disk_free_critical_pct", 5)))
    if critical >= warn:
        raise ValueError(
            f"disk_free_critical_pct ({critical:g}) must be below "
            f"disk_free_warn_pct ({warn:g})")


def post_settings(service, params, body) -> dict:
    from ...sqlitebase import coerce_settings

    scope = str(body.get("scope", "global"))
    values = body.get("values") or {}
    if not isinstance(values, dict):
        raise ValueError("values must be an object")
    granted = request_permissions(service, params)
    # Only the keys this scope would actually write. A per-module scope
    # discards anything outside its own defaults below, so a netpath-scope
    # POST carrying web_cert never sets web_cert — and refusing the whole
    # request because the key was *mentioned* would turn a harmlessly ignored
    # field into a 403. Filtering by the scope's own defaults still refuses
    # the write that would really land.
    scope_keys = _scope_defaults(scope)
    # The ciphertext column is derived from "tacacs_secret" below, never
    # taken from a client as-is.
    values.pop("tacacs_secret_enc", None)
    touched = [key for key in ADMIN_ONLY_SETTINGS
               if key in values and (key in scope_keys
                                     or (key == "tacacs_secret" and scope == "global"))]
    if touched and not _may_change_admin_settings(service, params):
        raise _permissions.Forbidden(
            f"Changing {', '.join(touched)} needs administrator access")
    # Read before coerce_settings drops it (it is not a key of GLOBAL_DEFAULTS
    # under this name): blank or absent means keep the currently stored
    # secret, so only a genuinely non-empty value gets encrypted below.
    raw_tacacs_secret = values.get("tacacs_secret") if scope == "global" else None
    # Typed before anything is written: apply_settings saves first and the
    # loaders hand back whatever was stored, so a null or "abc" for a
    # numeric key would persist and then raise from every subsequent start's
    # int() until the database was edited by hand.
    values = coerce_settings(_scope_defaults(scope), values, strict=True)
    _check_settings_ranges(values, scope)
    _check_disk_free_settings(service, values)
    if "web_relay_port_range" in values:
        # Typed here, not at the next relay: an unparseable range would
        # otherwise store happily and surface as a failed WEB click later.
        webrelay.parse_port_range(values["web_relay_port_range"])
    if scope == "mapper":
        _check_mapper_settings(service, values)
    if scope == "configrx":
        _check_configrx_settings(values)
    if scope == "netflow":
        _check_netflow_settings(values)
    if scope == "global":
        _check_tacacs_settings(values)
        if raw_tacacs_secret:
            import base64

            encrypted = _encrypt_secret(str(raw_tacacs_secret), (
                "This machine cannot encrypt a stored credential — DPAPI is "
                "Windows-only. See CREDENTIAL-SECURITY.md for the portable "
                "secret store this platform needs instead; nothing will be "
                "saved here until then."))
            values["tacacs_secret_enc"] = base64.b64encode(encrypted).decode("ascii")
    # The keys, never the values: a settings value can be a credential-
    # adjacent path or a hostname, and an audit trail is a record of what
    # was touched, not a second copy of the configuration.
    _audit(service, params, "settings.change", target=scope,
           detail=", ".join(sorted(str(k) for k in values)) or "nothing")
    key = SETTINGS_SCOPES.get(scope)
    if key is None:
        applied = service.apply_global_settings(values)
        return {"settings": _visible_settings(applied, granted)}
    if scope == "netpath":
        # NetPath's apply returns the merged settings dict, which carries the
        # global keys too; every other scope returns only its own module's.
        applied = service.apply_netpath_settings(values)
        return {key: _visible_settings(applied, granted)}
    return {key: service.apply_settings(scope, values)}


def post_update(service, params, body) -> dict:
    from ... import selfupdate

    # Refused here as well as inside apply(): this is the one that produces
    # a 403 rather than a JSON error, so an operator sees a refusal rather
    # than a failed update, and nothing reaches the network at all.
    if not selfupdate.updates_enabled(service.app_db):
        raise _permissions.Forbidden(selfupdate.UPDATES_DISABLED_MESSAGE)
    _audit(service, params, "update.requested")
    db_path = getattr(service.app_db, "path", "")
    username = str(params.get("_username", ""))
    client = str(params.get("_client", ""))

    def before_quiesce(sha, message):
        # The last moment app.db is open: the record of who replaced this
        # host's code used to be written after the teardown, and lost.
        service.log.add(SYSTEM_CATEGORY, f"Updated to {sha[:10]}; restarting")
        service.app_db.audit(username, client, "update.installed",
                             target=sha[:10])

    def on_result(result):
        if result.get("ok"):
            return
        if result.get("quiesced"):
            from ...appdb import write_audit
            write_audit(db_path, username, client, "update.refused",
                        detail=str(result.get("error", "")))
        else:
            service.app_db.audit(username, client, "update.refused",
                                 detail=str(result.get("error", "")))

    # The status, not the outcome: the install outlives any request deadline.
    return Accepted(selfupdate.start_job(service.app_db, before_quiesce,
                                         on_result))


def get_update_status(service, params, body) -> dict:
    """Where the update job got to. Polled by the Settings dialog once a
    second, and read again by a browser that reloaded mid-update."""
    from ... import selfupdate

    return selfupdate.status()


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
        # The rollups too: "delete all flow records" that left the charts
        # full of data would not be what the button says.
        removed = service.flow_db.prune(0, 0, minute_days=0, rollup_days=0)
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

    Two shapes behind one route, told apart by whether `t0`/`t1` is
    present. Settings > Audit always sends both (see auditFetchPage() in
    settings.js), so that means the filtered, keyset-paginated search
    below via audit_query(). Neither present means the older "since a
    cursor" poll a few tests still use directly — `since` the last id
    already seen, `limit` how many rows at most — via audit_events().
    """
    if "t0" in params or "t1" in params:
        return _get_audit_search(service, params)
    since = int(_num(params, "since", 0, int) or 0)
    limit, _offset = _page(params, 500, _appdb.AUDIT_MAX_LIMIT)
    rows = service.app_db.audit_events(since, limit)
    return {
        "events": [{"id": row["id"], "ts": row["ts"],
                    "username": row["username"], "client": row["client"],
                    "action": row["action"], "target": row["target"],
                    "detail": row["detail"]} for row in rows],
        "last_id": rows[-1]["id"] if rows else since,
        "max_id": service.app_db.audit_last_id(),
        "limit": limit,
    }


def _get_audit_search(service, params) -> dict:
    """audit_query(), filtered and paged for the Settings > Audit subtab.
    One row past `limit` is fetched (audit_query's own contract) so
    `truncated` can be told from "that was all of it" without a second
    query, the same trick the syslog search route uses.

    usernames/actions are the filter dropdowns' options, rebuilt from this
    same request rather than a separate one — cheap (DISTINCT over an
    indexed column, see ix_audit_username/ix_audit_action) next to the
    query this already ran, and it means the dropdowns can never disagree
    with the rows just returned.
    """
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - 2592000)
    limit, _offset = _page(params, 200, _appdb.AUDIT_MAX_LIMIT)
    before_id = _num(params, "before_id", None, int)
    rows = service.app_db.audit_query(
        t0, t1, username=params.get("username") or "",
        action=params.get("action") or "", target=params.get("target") or "",
        q=params.get("q") or "", before_id=before_id, limit=limit)
    truncated = len(rows) > limit
    rows = rows[:limit]
    return {
        "rows": [{"id": row["id"], "ts": row["ts"], "username": row["username"],
                  "client": row["client"], "action": row["action"],
                  "target": row["target"], "detail": row["detail"]}
                 for row in rows],
        "truncated": truncated,
        "usernames": service.app_db.audit_usernames(),
        "actions": service.app_db.audit_action_names(),
    }

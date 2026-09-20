"""Shared CSV, request-scoped and cross-section helpers every route module uses."""

from __future__ import annotations

import json
import math
import time

from ... import csvout
from ...analysis import clamp_window
from ... import namelookup
from ...flowdb import DIMENSIONS
from ...eventlog import CATEGORIES
from ...syslogparse import FACILITIES, SEVERITIES
from ... import trapdecode
from ... import configrx
from ... import dbreport
from ... import webrelay
from ... import mibcatalog, vendorid
from ... import nodepoll
from ... import permissions as _permissions
from ..service import STORES, db_for, disk_space


MIN_BLOCK_PX = 3

# "no argument given", distinct from an argument that is None.
_UNSET = object()


# ---------------------------------------------------------------------- CSV
#
# csv_cell/csv_text themselves live in netpath/csvout.py now (F2), so
# reportsched's emailed CSV attachment shares the exact same formula-safe
# formatting without importing this route module. Aliased here under its
# old name so every _csv_text call site below is unchanged.
# Exports answer as JSON (server.py has no Content-Disposition path); the
# browser saves the `text` field itself.
_csv_text = csvout.csv_text


def _csv_filename(module: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    return f"sappiwhere-{module}-{stamp}.csv"


def _csv_time(ts) -> str:
    """A local-time reading alongside the epoch column every export keeps,
    so a spreadsheet opened straight from the download already reads as a
    clock time instead of a raw float."""
    if ts is None:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _csv_response(module: str, header: list[str], rows, *, truncated: bool = False,
                  cap: int | None = None) -> dict:
    """The one shape every export handler below returns. `cap` is the
    export ceiling that applied (None when the underlying query has none —
    devices, interfaces and wireless APs are none of them capped even on
    screen, so their export is not capped either);
    `truncated` is whether the result actually hit it, the same "there is
    more than this" signal the search screens already use for SEARCH_ROW_CAP."""
    rows = list(rows)
    return {"csv": _csv_text(header, rows), "filename": _csv_filename(module),
            "count": len(rows), "truncated": truncated, "cap": cap}


class Conflict(ValueError):
    """A 400's refusal with the evidence attached, so the browser can offer
    "add anyway" — a ValueError subclass so a generic handler still reports
    it sensibly; server.py turns it into a 409 with `payload`."""

    def __init__(self, message: str, payload: dict | None = None):
        super().__init__(message)
        self.payload = payload or {}


class NotFound(ValueError):
    """"That row is not here" — server.py turns it into a 404."""


def _audit(service, params, action: str, target: str = "",
           detail: str = "") -> None:
    """One line in the on-disk audit trail (appdb.audit).

    Written alongside the event-log line most of these actions already
    produce, not instead of it: the ring is for watching the application
    work and is gone on the next restart, this is the record that answers
    "who changed that" a month later.

    Covers authentication, authorization, credential and destructive-
    administration actions, plus the configuration changes an operator has
    to answer for after the fact: NetPath destinations, devices and their
    bulk operations, device groups, polling profiles, MIBs, alert rule
    definitions, IPAM subnets and ConfigRX backup deletion. "Who changed the
    CPU threshold from 90 to 99 last March" is a compliance question on a
    site under an ISO or food-safety regime. Still not a second copy of
    the event log: this is the durable record, that is the live ring.
    """
    service.app_db.audit(params.get("_username", ""), params.get("_client", ""),
                         action, target, detail)


# Never shown with either value in an audit diff — the SNMP community
# string is credential-adjacent, same as every secret this file already
# redacts before it reaches a log line or an export; naming a field as
# merely "changed" here is still enough to answer "was this touched".
_AUDIT_REDACTED_FIELDS = ("community",)


def _audit_diff(before, fields: dict) -> str:
    """"field: old -> new" for every key in `fields` that actually differs
    from `before`'s own value, joined with "; " — the shape an audit line
    for an update route wants (put_nodes_device, put_nodes_group, and
    friends). `before` is a row (or anything supporting `row[key]`); a
    field in _AUDIT_REDACTED_FIELDS is named as changed, never with
    either value. Empty when nothing in `fields` actually changed.
    """
    parts = []
    for key, value in fields.items():
        if before[key] == value:
            continue
        if key in _AUDIT_REDACTED_FIELDS:
            parts.append(f"{key}: changed")
        else:
            parts.append(f"{key}: {before[key]} -> {value}")
    return "; ".join(parts)


def _num(params, key, default=None, cast=float):
    value = params.get(key)
    if value in (None, ""):
        return default
    try:
        return cast(value)
    except (TypeError, ValueError):
        return default


def _page(params, default, cap) -> tuple[int, int]:
    """The (limit, offset) every paginated list route reads from the query
    string, clamped: limit into [1, cap], offset at 0 or above. SQLite reads
    a negative LIMIT as "no limit", so an unclamped ?limit=-1 returns the
    whole table instead of a page."""
    limit = max(1, min(int(_num(params, "limit", default, int) or default), cap))
    offset = max(0, int(_num(params, "offset", 0, int) or 0))
    return limit, offset


def _require(row, what: str):
    """`row` back, or NotFound("No such <what>"), which server.py answers
    404 for."""
    if not row:
        raise NotFound(f"No such {what}")
    return row


class Accepted(dict):
    """A dict server.py answers 202 for instead of 200 — work started, not
    finished; ordinary otherwise, so callers need nothing special."""

    http_status = 202


def _pick(body: dict, allowed) -> dict:
    """Only the keys of `body` an update route is allowed to write. The
    allow-list is the boundary: anything not named here never reaches a
    database column, whatever the caller sent."""
    return {k: v for k, v in body.items() if k in allowed}


def _encrypt_secret(secret: str, unavailable: str) -> bytes:
    """A secret encrypted for storage, or ValueError.

    `unavailable` is the caller's own "this machine cannot store one"
    message, worded for the field the operator is actually looking at.
    The plaintext is dropped from this frame before returning either way:
    with neither DPAPI nor a configured passphrase store, nothing here
    writes a plaintext password or a weaker cipher instead.
    """
    from ... import dpapi

    if not dpapi.available():
        raise ValueError(unavailable)
    try:
        return dpapi.protect(secret.encode("utf-8"))
    except dpapi.DpapiUnavailable as exc:
        raise ValueError(str(exc))
    finally:
        secret = None


# The other spellings of the one cipher, mapped to the name it is stored
# and shown under. "AES128" is net-snmp's and snmpcrypt takes it so a name
# copied from an agent's own configuration works; "AES-128" is how PAN-OS
# and most vendor UIs print it. Mapped BEFORE the membership check below,
# not after, because a spelling that passed validation and was stored
# verbatim was a one-click loss: the form's select has only "AES", so an
# "AES128" row showed "(none)", and the next Save posted a blank protocol
# and dropped the privacy blob with it. tests/test_frontend_contracts.py
# pins the stored names to the select's options for the same reason.
_PRIV_PROTO_ALIASES = {"AES128": "AES", "AES-128": "AES"}


def _clean_priv_proto(fields: dict) -> None:
    """Validates `v3_priv_proto` in place, if present: blank means none
    (nodesdb drops the privacy blob with it), anything else must be a
    protocol snmpcrypt speaks, stored under its one canonical name.
    Refused by name rather than stored and refused at poll time, because
    "DES" typed here and "unsupported" on the device row an hour later is
    the kind of distance an operator should not have to close."""
    from ... import snmpcrypt

    if "v3_priv_proto" not in fields:
        return
    proto = str(fields["v3_priv_proto"] or "").strip().upper()
    proto = _PRIV_PROTO_ALIASES.get(proto, proto)
    if proto and proto not in snmpcrypt.PRIV_PROTOCOLS:
        raise ValueError(
            f"The privacy protocol must be AES (AES-128-CFB); {proto!r} is "
            f"not supported — DES is not offered, and AES-192/256 need a key "
            f"extension no RFC defines")
    fields["v3_priv_proto"] = proto or None


def _blank_device_override_is_inherit(fields: dict) -> None:
    """On a device row a blank `v3_user` or `v3_auth_proto` is stored as
    NULL — "the profile's" — never as the empty string. The edit form
    already posts null for a field left at "(profile)", so this only
    changes what an API caller sending "" gets: effective_config resolves
    a NULL column to the profile's and keeps "" as a value, so "" with the
    device's own stored password was a row that said has_credential: true
    and derived noAuthNoPriv, refused before every poll. The community is
    not here: nodesdb.clean_community owns it, and a blank one is hidden-
    not-cleared for an account that cannot read secrets (deviceOverrides
    in nodes.js says why)."""
    for key in ("v3_user", "v3_auth_proto"):
        if key in fields and isinstance(fields[key], str) and not fields[key].strip():
            fields[key] = None


def _refuse_orphaned_v3_secret(fields: dict, row, inherited=None) -> None:
    """Refuses a write that blanks `v3_auth_proto` while the row still
    holds an SNMPv3 password. security_level needs the protocol AND the
    password to sign, so the row would derive noAuthNoPriv and every poll
    would be refused before it was sent — with the JSON still saying
    has_credential: true, a credential that exists and can never work.
    `inherited` is what a blank resolves to on a device row — the
    profile's protocol — where NULL means "the profile's", a working
    state as long as the profile has one; a profile or additional
    credential has nothing to inherit from and passes None. The form
    offers no blank protocol, so this is reachable by API alone, and
    refusing it is cheaper than a stored secret nobody can use."""
    if "v3_auth_proto" not in fields:
        return
    if str(fields["v3_auth_proto"] or "").strip():
        return
    if str(inherited or "").strip():
        return
    if row["v3_auth_pass_enc"] or row["v3_priv_pass_enc"]:
        raise ValueError(
            "An SNMPv3 password is stored for this credential, and it cannot "
            "be used without an auth protocol. Keep the auth protocol, or "
            "clear the stored credential first.")


# The wireless poller speaks authNoPriv at most (fortipoll's docstring), so
# a privacy field for a controller is refused — on every route that could
# carry one. The credential POST refused it from the start; the controller
# add and edit routes allow-list-dropped the same two keys and answered
# {"ok": true}, which is the "stored and never sent" this sentence exists
# to prevent, worn as a success.
_PRIVACY_UNSUPPORTED = (
    "A privacy password is not supported for this credential: only "
    "Nodes devices and polling profiles can be polled at authPriv. "
    "Leave the privacy fields empty, or give this user an authNoPriv "
    "view on the device.")


def _refuse_controller_privacy(body: dict) -> None:
    """ValueError for a controller body carrying a privacy protocol or
    password — a value, not the key: the Nodes form always posts the key
    as null, and null is nothing to refuse."""
    if body.get("v3_priv_proto") or body.get("v3_priv_pass"):
        raise ValueError(_PRIVACY_UNSUPPORTED)


def _v3_fields(body: dict, *, allow_priv: bool) -> tuple[str, str, str, str | None, str | None]:
    """(user, auth_proto, password, priv_proto, priv_password) from an
    SNMPv3 credential body — the first three required, since a v3
    credential is meaningless without them; the privacy pair optional. A
    privacy password needs a protocol beside it, since without one it
    cannot be used. A protocol WITHOUT a password is accepted, on purpose:
    that is the form's "stored — leave blank to keep", an operator
    re-typing the auth password without losing the privacy one, and the
    store's COALESCE keeps the old blob. On a row with no privacy blob the
    same body stores the protocol alone and derives authNoPriv, which
    _store_v3_credential reports as a warning rather than refuses, because
    refusing it would break the re-type. A caller that cannot poll at
    authPriv passes allow_priv=False and a typed privacy password is
    refused in words — the wireless poller — rather than stored and
    ignored."""
    user = str(body.get("v3_user", "")).strip()
    password = str(body.get("v3_auth_pass", ""))
    auth_proto = str(body.get("v3_auth_proto", "")).strip()
    if not user or not password or not auth_proto:
        raise ValueError("A username, auth protocol, and password are all required")
    priv_password = str(body.get("v3_priv_pass", "") or "")
    fields = {"v3_priv_proto": body.get("v3_priv_proto")}
    _clean_priv_proto(fields)
    priv_proto = fields["v3_priv_proto"]
    if not allow_priv and (priv_password or priv_proto):
        raise ValueError(_PRIVACY_UNSUPPORTED)
    if priv_password and not priv_proto:
        raise ValueError("A privacy protocol (AES) is required with a privacy password")
    return user, auth_proto, password, priv_proto, (priv_password or None)


def _store_v3_credential(service, params, body, *, store, category, message,
                         target, unavailable, allow_priv: bool = True,
                         priv_stored: bool = False) -> dict:
    """Store one SNMPv3 credential: validate the body, encrypt the password
    (and the privacy password, if one was typed), hand them to `store`,
    then log and audit it.

    `store` is the caller's own database call, `unavailable` its own wording
    for a host that cannot encrypt. Neither password leaves this frame.
    With allow_priv, `store` takes (user, auth_proto, encrypted, priv_proto,
    priv_encrypted) — priv_encrypted None meaning "leave the stored one",
    the form's "blank to keep"; without it, the three-argument shape the
    wireless controller store has always had, and a privacy field in the
    body is a ValueError before anything is encrypted.

    `priv_stored` is whether the row already holds a privacy blob. A
    protocol with no typed privacy password is "keep the stored one" when
    there is one; when there is not, the row ends up at authNoPriv with a
    protocol that promises more, and the answer carries a `warning` saying
    so — the one case where "blank keeps" keeps nothing.
    """
    user, auth_proto, password, priv_proto, priv_password = _v3_fields(
        body, allow_priv=allow_priv)
    priv_encrypted = None
    try:
        encrypted = _encrypt_secret(password, unavailable)
        if priv_password:
            priv_encrypted = _encrypt_secret(priv_password, unavailable)
    finally:
        password = None
        priv_password = None
    if allow_priv:
        store(user, auth_proto, encrypted, priv_proto, priv_encrypted)
    else:
        store(user, auth_proto, encrypted)
    service.log.add(category, message)
    # The audit names what THIS call stored, not the row's resulting level:
    # a blank privacy field keeps whatever privacy password was already
    # there, and only the row knows whether that is anything.
    _audit(service, params, "credential.store", target=target,
           detail=f"SNMPv3 user {user}"
                  + (f" with a {priv_proto} privacy password (authPriv)"
                     if priv_encrypted else ""))
    result = {"ok": True}
    if priv_proto and not priv_encrypted and not priv_stored:
        result["warning"] = (
            f"Stored the auth password only: {priv_proto} is set as the "
            "privacy protocol but no privacy password was typed and none "
            "was stored, so this credential is authNoPriv until one is.")
    return result


def _clear_credential(service, params, *, clear, category, message=None,
                      target=None) -> dict:
    """Drop one stored credential via the caller's own `clear` call, then
    log and audit it. `message`/`target` are omitted by the routes that
    write only one of the two records today."""
    clear()
    if target is not None:
        _audit(service, params, "credential.clear", target=target)
    if message:
        service.log.add(category, message)
    return {"ok": True}


def _window(params, default_span_s: float = 3600.0) -> tuple[float, float]:
    """The (t0, t1) every windowed route reads from the query string.

    Runs through analysis.clamp_window, the same rule the NetPath side
    applies. It matters because `_num(..., float)` happily parses "inf",
    "nan" and "1e18", and a t1 <= t0 check catches neither: a span of 1e18
    seconds reaches flowdb.overview, which sizes its per-series lists from
    (t1 - t0) / bucket_s — an allocation bounded only by the machine's
    memory, on the request thread of a host that is also polling devices and
    receiving flows. clamp_window bounds the magnitude, the ordering and the
    span, and returns a sane pair for input that is not a
    finite number at all."""
    t1 = _num(params, "t1", time.time())
    t0 = _num(params, "t0", t1 - default_span_s)
    if t1 <= t0:
        t1 = t0 + 60
    return clamp_window(t0, t1)


# The histogram stores allocate one dict per bucket BEFORE they run any
# query, so the bucket count — not the span — decides what an overview
# request costs in memory. Bounded the way _flow_bucket bounds the same
# hazard: widen the bucket until the count fits rather than narrow the
# window the caller asked for. Two slots are held back from the cap because
# each store floors its first bucket to a boundary below t0 and adds a
# trailing partial one.
HIST_MAX_BUCKETS = 5000


def _hist_window(params, default_span_s: float = 86400.0,
                 default_bucket_s: float = 3600.0) -> tuple[float, float, float]:
    """The (t0, t1, bucket_s) the three overview histograms read from the
    query string: the window through _window, then a bucket no smaller than
    the stores' own 60 s floor and no smaller than HIST_MAX_BUCKETS allows."""
    t0, t1 = _window(params, default_span_s)
    bucket = _num(params, "bucket", default_bucket_s)
    if bucket is None or not math.isfinite(bucket):
        bucket = default_bucket_s
    bucket = max(float(bucket), 60.0)
    if (t1 - t0) / bucket > HIST_MAX_BUCKETS - 2:
        bucket = float(math.ceil((t1 - t0) / (HIST_MAX_BUCKETS - 2)))
    return t0, t1, bucket


def _id_list(raw) -> list[int] | None:
    """A comma-separated `device_ids=1,2,3` query param -> [1, 2, 3], or
    None when the param was not given at all — distinct from an explicit
    empty list, which a caller cannot actually send through a query string
    the same way a POST body could, so None is the only "not specified"
    a GET route here needs to recognise."""
    if raw in (None, ""):
        return None
    out = []
    for piece in str(raw).split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            out.append(int(piece))
        except ValueError:
            raise ValueError(f"device_ids must be a comma-separated list of ids, not {piece!r}")
    # Same reader as every POST body's list, so a GET obeys the bulk cap too.
    return _bulk_ids({"device_ids": out}, "device_ids", required=False)


# ------------------------------------------------------------------ general

# get_state is one omnibus endpoint every open tab polls, so it is never
# permission-gated as a whole; each per-module section is dropped from the
# response instead when the signed-in account cannot read that module.
#
# The payload is two routes. /api/config changes only when an operator
# changes something — settings blocks, grants, constant vocabularies — and
# carries `config_version`; /api/state changes on its own — running flags,
# counters, clocks — and repeats the version so the browser knows when to
# fetch the other half. Both maps below drop a module's keys for an account
# that cannot read it.
_CONFIG_MODULE_KEYS = {
    "netflow": ("flow_settings", "dimensions"),
    "syslog": ("syslog_settings",),
    "snmp": ("snmp_settings", "trap_kinds"),
    "ipam": ("ipam_settings",),
    "nodes": ("nodes_settings",),
    "alerts": ("alerts_settings",),
    "wireless": ("wireless_settings",),
    "configrx": ("configrx_settings", "configrx_vendors"),
    "mapper": ("mapper_settings",),
}
_STATE_MODULE_KEYS = {
    "netflow": ("collector",),
    "syslog": ("syslog",),
    "snmp": ("snmp",),
    "ipam": ("ipam",),
    "nodes": ("nodes",),
    "alerts": ("alerts",),
    "wireless": ("wireless",),
    "configrx": ("configrx",),
    "settings": ("storage",),
}

# Global settings only a Settings reader may see. "settings" itself stays in
# every response — every module's refresh cadence lives in it — but these
# keys are server internals: where the listener binds and which TLS material
# it loads, how long a sign-in lasts, which resolver the nslookup
# subprocesses are pointed at, and the directory's address, bind DN template
# (which names the plant's LDAP tree structure) and cleartext opt-out.
SETTINGS_ONLY_KEYS = ("web_host", "web_port", "web_cert", "web_key",
                      "web_relay_port_range",
                      "session_idle_minutes", "session_max_hours",
                      "dns_server", "asn_server",
                      "ldap_url", "ldap_bind_dn_template",
                      "ldap_allow_cleartext", "ldap_timeout_s",
                      "tacacs_servers", "tacacs_timeout_s",
                      "tacacs_auto_create", "tacacs_default_role",
                      "tacacs_secret_enc")


def _visible_settings(settings: dict, granted: dict) -> dict:
    """`settings` as this caller may see it. One rule for both the endpoint
    that reads the settings and the one that writes them: if they disagreed,
    post_settings echoing the unfiltered dict would hand back exactly what
    SETTINGS_ONLY_KEYS exists to withhold."""
    if _permissions.allows(granted.get("settings"), _permissions.READ):
        visible = dict(settings)
        # Whether a secret is stored, never the ciphertext -- the same
        # "has_credential" idiom other stored credentials use, none of
        # which return their encrypted blob to any reader either.
        visible["tacacs_secret_set"] = bool(visible.pop("tacacs_secret_enc", ""))
        return visible
    return {k: v for k, v in settings.items() if k not in SETTINGS_ONLY_KEYS}


# ------------------------------------------------ per-request memoisation
#
# `app_db.user()` is read by the must-change gate on every /api/* request,
# `app_db.permissions_for()` by the dispatch gate whenever a route has a
# requirement, and then AGAIN by the handler itself on most gated routes.
# Two to four queries per request, each under app.db's single write lock,
# for two answers that cannot change while the request is in flight.
#
# The scope is one request and nothing longer. functools.lru_cache — or any
# other process-lifetime memo — is deliberately NOT used here: a permission
# revoked or a password reset while a tab is open has to be refused on the
# very next request, which is the guarantee the dispatch gate documents,
# and a process-lifetime cache would keep the revoked grant working. Within
# a single request the value genuinely cannot move: no route revokes its
# own caller's grants (post_user_permissions refuses a self-edit outright)
# and post_password reads the row it is about to overwrite, not after.


def _request_cache(params) -> dict | None:
    """The scratch dict `server.Handler._dispatch` resets for each request.

    None when a handler runs outside the HTTP server — a test calling it
    directly, a script — and every helper below then simply reads through
    to app.db, which is exactly the behaviour this memo replaces.
    """
    cache = params.get("_cache")
    return cache if isinstance(cache, dict) else None


def request_permissions(service, params, username=None) -> dict:
    """{module: level} for the account this request runs as.

    Keyed on the username, so a route that also inspects some OTHER account
    — the user grid, a grant edit — can never be handed this request's
    answer for it. Returns a copy: the memo outlives the call and
    get_config puts what it returns straight into a response body.
    """
    if username is None:
        username = params.get("_username", "")
    username = str(username or "")
    cache = _request_cache(params)
    if cache is None:
        return service.app_db.permissions_for(username)
    # NOCASE in the table, so the key is folded the same way.
    key = ("permissions", username.lower())
    if key not in cache:
        cache[key] = service.app_db.permissions_for(username)
    return dict(cache[key])


def request_user(service, params, username=None):
    """The `users` row for the account this request runs as, or None.

    Same per-request scope, same keying and the same reason for both as
    request_permissions. `not in` rather than a truthiness test, because a
    username with no account caches a perfectly good None.
    """
    if username is None:
        username = params.get("_username", "")
    username = str(username or "")
    cache = _request_cache(params)
    if cache is None:
        return service.app_db.user(username)
    key = ("user", username.lower())
    if key not in cache:
        cache[key] = service.app_db.user(username)
    # sqlite3.Row is read-only, so this one needs no defensive copy.
    return cache[key]


def _drop_unreadable(result: dict, granted: dict, module_keys: dict) -> None:
    for module, keys in module_keys.items():
        if not _permissions.allows(granted.get(module), _permissions.READ):
            for key in keys:
                result.pop(key, None)


def _alerts_settings_json(service, params) -> dict:
    """The Alerts settings block as this caller may see it.

    For Slack, Teams and PagerDuty the incoming-webhook URL *is* the bearer
    credential, and `webhook_headers` is where an Authorization header goes,
    so both follow _community_fields' rule rather than travelling in the
    clear to every `alerts: read` account: the values for a caller who could
    change them anyway, a boolean for everyone else. A copy, because the
    dict here is the live one service.alerts_settings hands out."""
    settings = service.alerts_settings
    flags = {"has_webhook_url": bool(settings.get("webhook_url")),
             "has_webhook_headers": bool(settings.get("webhook_headers"))}
    if _may_read_secrets(service, params, "alerts"):
        return {**settings, **flags}
    return {**settings, **flags, "webhook_url": "", "webhook_headers": []}


def _snmp_settings_json(service, params) -> dict:
    """The SNMP trap settings block, following _alerts_settings_json's rule:
    accepted-communities values for a caller who could change them, a has_
    flag for everyone else."""
    settings = service.snmp_settings
    flags = {"has_accepted_communities": bool(settings.get("accepted_communities"))}
    if _may_read_secrets(service, params, "snmp"):
        return {**settings, **flags}
    return {**settings, **flags, "accepted_communities": ""}


def get_config(service, params, body) -> dict:
    """Everything the browser needs that only an operator can change.

    Fetched once at start-up and again whenever /api/state reports a new
    `config_version`. Never polled on its own: nothing in here moves by
    itself. Not gated as a whole, like /api/state — a module's block is
    dropped for an account that cannot read it."""
    from ... import __version__
    from ...selfupdate import (INSTALLED_AT_KEY, INSTALLED_COMMIT_KEY,
                              INSTALLED_TAG_KEY, updates_enabled)
    granted = request_permissions(service, params)
    result = {
        "config_version": service.config_version,
        "version": __version__,
        "permissions": granted,
        "update": {
            "installed_commit": service.app_db.meta(INSTALLED_COMMIT_KEY),
            "installed_tag": service.app_db.meta(INSTALLED_TAG_KEY),
            "installed_at": service.app_db.meta(INSTALLED_AT_KEY),
            # So the Settings page can say why the button does nothing,
            # rather than showing one that always fails.
            "enabled": updates_enabled(service.app_db),
        },
        "settings": service.settings,
        "flow_settings": service.flow_settings,
        "dimensions": list(DIMENSIONS),
        "categories": CATEGORIES,
        "severities": SEVERITIES,
        "facilities": FACILITIES,
        "syslog_settings": service.syslog_settings,
        "snmp_settings": _snmp_settings_json(service, params),
        "trap_kinds": list(trapdecode.KINDS),
        "ipam_settings": service.ipam_settings,
        "nodes_settings": service.nodes_settings,
        "alerts_settings": _alerts_settings_json(service, params),
        "wireless_settings": service.wireless_settings,
        "configrx_settings": service.configrx_settings,
        "mapper_settings": service.mapper_settings,
        # The vendor override <select> is built from this, not a JS copy of
        # configrx.VENDORS — label and key only, nothing a client
        # could use to influence what a backup sends over SSH. Order matches
        # the table's own (Python dicts keep insertion order).
        "configrx_vendors": [{"key": key, "label": vendor.label}
                             for key, vendor in configrx.VENDORS.items()],
    }
    _drop_unreadable(result, granted, _CONFIG_MODULE_KEYS)
    # "settings" itself stays present even without Settings access — every
    # module's own refresh cadence (nodes_refresh_s and so on) lives in it,
    # and every tab needs to read those regardless of its own module's
    # grant. Only the keys in SETTINGS_ONLY_KEYS are stripped.
    result["settings"] = _visible_settings(result["settings"], granted)
    return result


# What app.js's state tick uses, so N tabs in one window cost one compute
# instead of N. Deliberately not longer: a single tab must lose no
# freshness at all, and at this TTL its own next poll always misses.
STATE_COUNTS_TTL_S = 2.0


def _state_counts(service) -> dict:
    """The fleet-wide tallies behind /api/state's tab badges: seven queries
    across four stores, each one taking that store's single write lock.

    Split out so the whole set is one `cached_poll` entry rather than seven
    unconditional round trips per tab per tick. Every value here is a
    COUNT(*) over the whole fleet — nothing in it can be usefully fresher
    than the poll cadence itself.

    Returns plain scalars and flat dicts of scalars only, which is what
    makes the caller's shallow copy of the two nested dicts a full one.
    """
    # One lookup, not two: open_worst and unresolved_count below both read
    # off this same summary rather than each running their own query.
    summary = service.alerts_db.open_summary()
    return {
        "open_conflicts": service.ipam_db.conflict_count(),
        "device_count": service.nodes_db.device_count(),
        "device_counts": _fleet_counts(service)[0],
        "open_count": service.alerts_db.open_count(),
        # The badge on the tab is coloured by this. A count alone said
        # "there are alerts" in the same amber whether the worst of them
        # was a notice or a device being down.
        "open_worst": summary["worst"],
        # open_count above is state='open' only, but the Alerts list's own
        # default State filter is "unresolved" — state IN ('open', 'acked')
        # — so a tab badge built from open_count alone starts undercounting
        # the moment anyone acknowledges anything.
        "unresolved_count": summary["open"] + summary["acked"],
        "ap_counts": service.wireless_db.ap_counts(),
        "controller_count": service.wireless_db.controller_count(),
    }


def get_state(service, params, body) -> dict:
    """What changes on its own: every worker's running flag, status line
    and counters, the counts the tab badges show, the session clocks. Polled
    every two seconds by every open tab, so what it costs matters: the
    figures that cannot usefully change at that rate are served from a
    short cache (Service.cached_poll), and every count is a COUNT(*)."""
    session = service.sessions.get(params.get("_token", ""))
    idle_remaining = (service.sessions.idle_seconds - (time.time() - session["last_seen"])
                      if session else None)
    # The absolute ceiling is the other way a session ends, and staying at
    # the keyboard does not move it. Server-authoritative like the idle
    # figure, so a browser clock that disagrees cannot make the countdown
    # lie.
    max_remaining = (service.sessions.max_seconds - (time.time() - session["created"])
                     if session else None)
    granted = request_permissions(service, params)
    # session["username"] is what _route put in params["_username"], so
    # this is the same row the must-change gate already read.
    account = request_user(service, params, session["username"]) if session else None
    names = service.cached_poll("hostname_stats", 10, service.hostname_stats)
    # Every fleet-wide count below in one cached compute, shared by every
    # tab polling in the same window.
    #
    # `cached_poll` hands the SAME object back to every caller inside the
    # TTL, and `_drop_unreadable` at the end of this function MUTATES what
    # it is given. That is safe here for one reason: it pops TOP-LEVEL keys
    # off `result`, and `result` is a fresh dict literal on every request,
    # so the cached object is never the thing passed to it. The two nested
    # dicts are copied out below all the same, so that no shared structure
    # reaches a response at all and a later pop one level down could not
    # turn one account's redaction into everybody's.
    # tests/test_state_cache.py polls this route as two accounts with
    # different grants and asserts neither ever sees the other's.
    counts = service.cached_poll("state_counts", STATE_COUNTS_TTL_S,
                                 lambda: _state_counts(service))
    result = {
        "config_version": service.config_version,
        "session": {
            "username": session["username"] if session else "",
            "must_change": bool(account["must_change"]) if account else False,
            "idle_timeout_minutes": service.sessions.idle_seconds // 60,
            "idle_seconds_remaining":
                max(0, round(idle_remaining)) if idle_remaining is not None else None,
            "max_seconds_remaining":
                max(0, round(max_remaining)) if max_remaining is not None else None,
            "theme": account["theme"] if account and account["theme"] in THEMES else "",
        },
        "uptime_s": time.time() - service.started_at,
        "collector": {
            "running": service.collector.running,
            "status": service.collector.status_text(),
            "counters": service.collector.counters,
            "decoder": service.collector.decoder.stats,
            # A5: how far back each tier reaches, cached — this is polled
            # every 2s by every open tab and coverage() reads the raw table.
            "coverage": service.cached_poll(
                "flow_coverage", 10.0, service.flow_db.coverage),
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
            "open_conflicts": counts["open_conflicts"],
        },
        "nodes": {
            "running": service.node_poller.running,
            "status": service.node_poller.status_text(),
            "counters": service.node_poller.counters,
            "device_count": counts["device_count"],
            "device_counts": dict(counts["device_counts"]),
            # Also exposed at /api/nodes/purges for anything asking about a delete alone.
            "purges": service.cached_poll("nodes_purges", 3,
                                          service.nodes_db.purge_status),
        },
        "alerts": {
            "running": service.alert_engine.running,
            "status": service.alert_engine.status_text(),
            "counters": service.alert_engine.counters,
            "open_count": counts["open_count"],
            "open_worst": counts["open_worst"],
            "unresolved_count": counts["unresolved_count"],
        },
        "wireless": {
            "running": service.wireless.running,
            "status": service.wireless.status_text(),
            "counters": service.wireless.counters,
            "ap_counts": dict(counts["ap_counts"]),
            "controller_count": counts["controller_count"],
        },
        "configrx": {
            "running": service.configrx.running,
            "status": service.configrx.status_text(),
            "counters": service.configrx.counters,
            # Which paramiko this process actually loaded, and what it can and
            # does offer — visible before a handshake fails rather than only
            # in the error text of one that already did.
            "ssh": configrx.ssh_algorithm_status(),
        },
        "storage": service.cached_poll("storage", 10, lambda: _storage(service)),
    }
    _drop_unreadable(result, granted, _STATE_MODULE_KEYS)
    return result


def _storage(service) -> dict:
    stores = [(store.name, db_for(service, store)) for store in STORES]
    stores = [(name, db) for name, db in stores if db is not None]
    result = {f"{name}_path": db.path for name, db in stores}
    result.update({f"{name}_bytes": db.size_bytes() for name, db in stores})
    # How far back each file still reaches, so trimming reads as lost
    # history, not just bytes. None for the two with no history and for an
    # empty store.
    result.update({f"{name}_oldest_ts": db.oldest_ts() for name, db in stores})
    # The volume itself, beside the files on it: a cap governs one database,
    # and nothing on this page ever said how much room the disk had left for
    # all of them. Named without the _bytes suffix on purpose — the total
    # on the Settings page is the sum of every *_bytes key, and free space
    # is not one of the files.
    free, total = disk_space(service)
    if total:
        result["disk_free"] = free
        result["disk_total"] = total
    # What the retention asks for, beside how far back the file reaches. A
    # settings read, not a query, so it stays on the /api/state path.
    nodes_settings = getattr(service, "nodes_settings", None) or {}
    result["nodes_series_rollup_days"] = float(
        nodes_settings.get("rollup_retention_days", 400) or 0)
    # app.db carries the audit trail, which no sweep may trim, so it gets a
    # warning where every other store gets a cap.
    warn_mib = int(service.settings.get("app_db_warn_mib") or 0)
    app_bytes = result.get("app_bytes")
    if warn_mib and app_bytes and app_bytes > warn_mib * 1024 * 1024:
        result["app_db_warning"] = (
            f"app.db is {app_bytes / (1024 * 1024):.0f} MiB, past the "
            f"{warn_mib} MiB app_db_warn_mib mark — its audit trail is never "
            f"trimmed; archive the file or raise the threshold")
    return result


def get_db_report(service, params, body) -> dict:
    """Where the bytes in each database are, per table. Its own route, cached
    five minutes: COUNT(*) over every table in thirteen files is seconds."""
    return {"stores": service.cached_poll(
        "db_report", 300, lambda: dbreport.report(_report_paths(service)))}


def _report_paths(service) -> dict:
    paths = {}
    for store in STORES:
        db = db_for(service, store)
        if db is not None:
            paths[store.name] = db.path
    return paths


def _is_admin(service, params) -> bool:
    granted = request_permissions(service, params)
    return _permissions.allows(granted.get("admin"), _permissions.WRITE)


# The most rows a search returns whatever limit is asked for. Was an inline
# 2000 in two handlers; named so the response can say so and the page can
# read "300 of 4,120 shown" instead of "300 shown".
SEARCH_ROW_CAP = 2000

# The on-screen search stays capped at SEARCH_ROW_CAP — a "do not try to
# render this many table rows" limit, not a data limit. An export exists to
# leave with more than a screen can hold, so the syslog, SNMP trap, IPAM
# hosts and DHCP lease exports get this taller ceiling instead.
EXPORT_ROW_CAP = 20000
def _tri(value):
    """None/0/1 -> None/False/True. A device's own override columns are
    NULL when "inherit from the group", which a blind bool() would
    collapse into False — indistinguishable from an explicit off."""
    return None if value is None else bool(value)


def _community_fields(row, reveal: bool) -> dict:
    community = row["community"]
    fields = {"has_community": bool(community)}
    if reveal:
        fields["community"] = community
    return fields


def _may_read_secrets(service, params, module: str) -> bool:
    granted = request_permissions(service, params)
    return _permissions.allows(granted.get(module), _permissions.WRITE)


def _v3_level_fields(row) -> dict:
    """The privacy protocol, whether a privacy password is stored (a
    boolean, the same reduction the auth password gets — the blob itself
    is never returned), and the security level DERIVED from the row the
    way the poller derives it (nodepoll.security_level): authPriv when
    both pairs are stored, authNoPriv with the auth pair, noAuthNoPriv
    with neither, null for a v1/v2c row or a device row that does not
    override the version. Read defensively for a row fetched before the
    5.8.0 migration has run."""
    from ...nodepoll import security_level

    keys = row.keys()
    priv_proto = row["v3_priv_proto"] if "v3_priv_proto" in keys else None
    priv_blob = row["v3_priv_pass_enc"] if "v3_priv_pass_enc" in keys else None
    version = row["snmp_version"] if "snmp_version" in keys else None
    level = None
    if version is not None and int(version) == 3:
        level = security_level({
            "snmp_version": 3, "v3_auth_proto": row["v3_auth_proto"],
            "v3_auth_pass_enc": row["v3_auth_pass_enc"],
            "v3_priv_proto": priv_proto, "v3_priv_pass_enc": priv_blob})
    return {"v3_priv_proto": priv_proto,
            "has_priv_credential": bool(priv_blob),
            "security_level": level}


def _clean_web_fields(fields: dict) -> None:
    """Validates `web_scheme`/`web_port` in place, if present. Blank clears
    either one, since a form that could set but never unset them would
    strand a device on a port that has since moved.
    """
    if "web_scheme" in fields:
        scheme = str(fields["web_scheme"] or "").strip().lower()
        if scheme and scheme not in webrelay.WEB_SCHEMES:
            raise ValueError("The web scheme must be http or https.")
        fields["web_scheme"] = scheme or None
    if "web_port" in fields:
        value = fields["web_port"]
        if value in (None, "", 0, "0"):
            fields["web_port"] = None
        else:
            try:
                port = int(value)
            except (TypeError, ValueError):
                raise ValueError(
                    "The web port must be a number from 1 to 65535.") from None
            if not 1 <= port <= 65535:
                raise ValueError("The web port must be a number from 1 to 65535.")
            fields["web_port"] = port


def _group_credential_json(row, reveal: bool = False) -> dict:
    return {
        "id": row["id"], "group_id": row["group_id"], "label": row["label"],
        "snmp_version": row["snmp_version"],
        **_community_fields(row, reveal),
        "v3_user": row["v3_user"], "v3_auth_proto": row["v3_auth_proto"],
        "has_credential": bool(row["v3_auth_pass_enc"]),
        **_v3_level_fields(row),
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


def _device_display_name(row) -> str:
    """nodes.js's displayName() precedence: manual name if pinned to it,
    else the SNMP hostname, else the manual name anyway, else the IP."""
    return ((row["name"] if row["display_name_source"] == "manual" else None)
            or row["sys_name"] or row["name"] or row["ip"])


def _device_index(service) -> dict:
    """One pass over the fleet, built once per discovery listing, that
    every result row is tested against. `by_address` covers a device's
    primary IP plus every alias its own address table reported;
    `by_identity` is a hint only, not an answer — two switches from the
    same carton share it honestly.

    Deliberately NOT memoised against `nodes_db.config_generation()`, which
    is the obvious thing to reach for and is wrong here. That counter moves
    for writes a PERSON made — add, edit, promote, merge, delete — and
    deliberately does not move for what the poller and the discovery sweep
    learn on their own: `record_device_addresses` and `seed_identity` both
    leave it alone, by design, because they are observations rather than
    settings. Those two are precisely what `by_address` and `by_identity`
    are built from, so a cache keyed on the generation serves a listing
    that cannot see the alias or the hostname just learned — which is a
    duplicate flagged as new, and a device added twice.
    tests/test_device_identity.py's "sysName plus sysObjectID alone is only
    a medium hint" is that failure, and it fails within milliseconds of the
    write, so no TTL short enough to be safe would ever hit.

    Caching this wants a generation counter that observations bump too,
    which belongs in nodesdb rather than here.
    """
    devices = service.nodes_db.devices()
    by_id = {row["id"]: row for row in devices}
    by_address = {row["ip"]: row for row in devices}
    for address, device_id in service.nodes_db.address_owners(configured=True).items():
        if address not in by_address and device_id in by_id:
            by_address[address] = by_id[device_id]
    return {"by_id": by_id, "by_ip": {row["ip"]: row for row in devices},
            "by_address": by_address,
            "by_identity": service.nodes_db.devices_by_identity()}


def _discovery_duplicate(row, index) -> dict:
    """Which device, if any, this result looks like, and how sure. High
    means the probed address is already on an existing device's own
    interfaces, which nothing else can honestly explain; medium means only
    sysName+sysObjectID match — a reason to look, not a verdict. Only high
    changes what promote() does."""
    if not index:
        return {}
    ip = row["ip"]
    device = index["by_address"].get(ip)
    if device is not None:
        name = _device_display_name(device)
        return {"duplicate_of_device_id": device["id"],
                "duplicate_of_device_name": name,
                "duplicate_confidence": "high",
                "duplicate_reason": f"already added as {name}: {ip} is on its interfaces"}
    key = ((row["sys_name"] or "").lower(), row["sys_object_id"] or "")
    device = index["by_identity"].get(key) if all(key) else None
    if device is not None:
        return {"duplicate_of_device_id": device["id"],
                "duplicate_of_device_name": _device_display_name(device),
                "duplicate_confidence": "medium",
                "duplicate_reason": "same sysName and sysObjectID"}
    return {}


def _discovery_identification(row, installed=None) -> dict:
    """What the sweep's arc hop found for a result, or blanks for a row
    written before 4.32."""
    keys = row.keys()
    arcs = []
    if "arcs" in keys and row["arcs"]:
        try:
            arcs = [int(a) for a in json.loads(row["arcs"])]
        except (TypeError, ValueError):
            arcs = []
    bundle_key = (row["suggest_bundle"] if "suggest_bundle" in keys else None) or None
    bundle = mibcatalog.bundle(bundle_key) if bundle_key else None
    bundle_installed = bool(bundle) and installed is not None and \
        all(fn in installed for fn, _url in bundle.files)
    return {
        "vendor_source": (row["vendor_source"] if "vendor_source" in keys else "") or "",
        "vendor_confidence": (row["vendor_confidence"]
                              if "vendor_confidence" in keys else "") or "",
        "arcs": arcs,
        "arc_names": [vendorid.arc_name(a) for a in arcs],
        "suggest_bundle": bundle_key,
        "suggest_bundle_installed": bundle_installed,
    }
_GROUP_EDITABLE_BODY = ("name", "snmp_version", "community", "v3_user",
                        "v3_auth_proto", "v3_priv_proto", "poll_interval_s",
                        "snmp_timeout_s",
                        "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                        "mib_file_id", "ping_count", "ping_timeout_ms",
                        "unreachable_ping_only", "vendor_oid", "location_oid",
                        "mac_table_interval_s", "vlan_interval_s",
                        "arp_table_interval_s")


def _planned_scope(service) -> tuple[set[int], set[int]]:
    """Device ids and group ids covered by maintenance mode or an active
    window. A mute is not planned — that device is still down, only quiet."""
    ids = {int(i) for i in service.alerts_db.maintenance_device_ids()}
    group_ids: set[int] = set()
    for row in service.alerts_db.active_windows():
        if row["scope_kind"] == "group":
            if row["scope_group_id"] is not None:
                group_ids.add(int(row["scope_group_id"]))
            continue
        try:
            ids.update(int(i) for i in json.loads(row["scope_device_ids"] or "[]"))
        except (TypeError, ValueError):
            continue
    return ids, group_ids


def _planned_down(service) -> set[int]:
    """Those of them that are actually down, which is what the fleet counts
    move out of `down`."""
    ids, group_ids = _planned_scope(service)
    if not ids and not group_ids:
        return set()
    return service.nodes_db.device_ids(status="down", only_ids=ids,
                                       device_group_ids=group_ids)


def _fleet_counts(service) -> tuple[dict, set[int]]:
    """device_counts() with planned outages moved from `down` to `maintenance`.

    `down` is re-counted with the planned ids excluded rather than having
    len(planned) subtracted from it: subtraction spans two reads a poll can
    land between, and it is a second definition of the same number that only
    agrees with the clause below while everything else is correct.
    """
    counts = service.nodes_db.device_counts()
    planned = _planned_down(service)
    counts["maintenance"] = len(planned)
    if planned:
        counts["down"] = service.nodes_db.devices_count(status="down",
                                                        exclude_ids=planned)
    return counts, planned


def _devices_for_rows(service, rows) -> dict:
    """The device row behind each search hit, by id, in one read. The two
    searches above run on a keystroke and answer up to their row limit,
    and a device() per hit made one keystroke cost a query per row — two
    hundred and one for a short address prefix. devices_by_ids is the
    same read chunked to the bind-parameter limit, so this is one or two
    statements whatever the hit count."""
    return {d["id"]: d for d in service.nodes_db.devices_by_ids(
        row["device_id"] for row in rows)}


def _neighbor_local_port_labeler(service, prefetch_ids=None):
    """A (device_id, if_index) -> label closure for LLDP/CDP rows, backed by
    one interfaces() read per device it is actually asked about rather than
    the whole fleet's — a neighbours read only ever touches the handful of
    devices that reported a neighbour, not the thousands that did not.
    Falls back to "if <N>" for a port whose interface row has not been
    polled yet (or was deleted since), which is still a legible label.

    `prefetch_ids` lets a caller that already knows the whole set (a map
    GET) fill the cache in one bounded read instead of one per device."""
    cache: dict[int, dict[int, str]] = {}
    if prefetch_ids:
        # Seeded empty: a device with no interfaces must read as "answered
        # nothing", not fall through and get queried again per neighbour row.
        for device_id in prefetch_ids:
            cache.setdefault(int(device_id), {})
        for row in service.nodes_db.interface_port_labels_for_devices(prefetch_ids):
            cache.setdefault(row["device_id"], {})[row["if_index"]] = (
                row["name"] or row["descr"] or row["alias"] or "")

    def label(device_id, if_index):
        if if_index is None:
            return ""
        ports = cache.get(device_id)
        if ports is None:
            ports = {i["if_index"]: (i["name"] or i["descr"] or i["alias"] or "")
                     for i in service.nodes_db.interface_port_labels(device_id)}
            cache[device_id] = ports
        return ports.get(if_index) or f"if {if_index}"
    return label


def _mapper_port_index(service, device_ids):
    """A (device_id, port_text) -> if_index resolver for
    mapper.assemble_links's `port_index` kwarg. One prefetch read, keyed on
    each on-map device's own interface name/descr reduced through
    nodepoll._canonical_if_name -- the same reduction a neighbour-reported
    port string (`row["port_id"]`/`row["port_descr"]`) is put through before
    the lookup, so "Te1/1/1" and "TenGigabitEthernet1/1/1" resolve to the
    same port."""
    index: dict[int, dict[str, int]] = {}
    for row in service.nodes_db.interface_port_labels_for_devices(device_ids):
        by_name = index.setdefault(row["device_id"], {})
        for text in (row["name"], row["descr"]):
            if text:
                key = nodepoll._canonical_if_name(text)
                # A second, different if_index for the same canonical key on
                # this device is ambiguous: mark it so the resolver returns
                # None and the row falls back to matched_if_index instead.
                if key in by_name and by_name[key] != row["if_index"]:
                    by_name[key] = None
                elif key not in by_name:
                    by_name[key] = row["if_index"]

    def port_index(device_id, port_text):
        if not port_text:
            return None
        return index.get(device_id, {}).get(nodepoll._canonical_if_name(port_text))
    return port_index


def _matched_device_names(service, device_ids) -> dict:
    """{device_id: display name} for matched devices, one batched read."""
    ids = {d for d in device_ids if d is not None}
    if not ids or service.nodes_db is None:
        return {}
    devices = service.nodes_db.devices_by_ids(ids)
    return namelookup.display_names(service.nodes_db, service.app_db, devices)


# The 16 MB body cap leaves room for well over a million integers, and an
# id list that long is a mistake or an attack rather than a fleet. This is
# the ceiling on that, deliberately far above any list the interface can
# produce: the SQLite parameter limit (SQLITE_MAX_VARIABLE_NUMBER, 999 on
# builds older than 3.32) is handled by chunking in nodesdb._id_chunks, not
# by capping the request, so this never refuses an ordinary select-all.
BULK_DEVICE_ID_MAX = 50000


def _bulk_ids(body, key, cap=BULK_DEVICE_ID_MAX, *, required=True,
              noun="devices") -> list[int]:
    """The one reader for every `body[key]` list of row ids: one cap, one
    refusal wording, one int coercion. `required` is each route's own."""
    ids = body.get(key) or []
    if not ids:
        if required:
            raise ValueError(f"{key} is required")
        return []
    if len(ids) > cap:
        raise ValueError(
            f"Too many {noun} in one request: {len(ids)}, limit is "
            f"{cap}. Send them in batches.")
    try:
        return [int(i) for i in ids]
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a list of ids") from None


def _bulk_device_ids(body) -> list[int]:
    return _bulk_ids(body, "device_ids")


def _series_bucket_s(params, t0: float, t1: float) -> float:
    """The bucket width a series route applies to a resolved [t0, t1]: 0
    (raw) unless `bucket_s` asks for wider, floored at 0 and capped at half
    the window so a caller cannot ask for one bucket covering the whole
    span. Shared by get_nodes_device_series and the batch route below."""
    bucket_s = _num(params, "bucket_s", 0)
    if bucket_s < 0:
        bucket_s = 0
    return min(bucket_s, (t1 - t0) / 2)


def _alert_filters(params) -> dict:
    severity = params.get("severity")
    rule_id = params.get("rule_id")
    return {
        "state": params.get("state") or None,
        "severity": int(severity) if severity else None,
        "rule_id": int(rule_id) if rule_id else None,
        "device_text": params.get("device") or None,
        "text": params.get("q") or None,
        "t0": _num(params, "t0", None),
        "t1": _num(params, "t1", None),
    }
#
# The third silencing mechanism, and the only indefinite one. Devices only,
# with no entity_kind parameter at all: advertising a kind the handler then
# refuses is worse than not offering one, and unlike alert_mutes this table
# has no column pretending otherwise.


def _maintenance_json(row) -> dict:
    return {"device_id": row["device_id"], "started_ts": row["started_ts"],
            "ended_ts": row["ended_ts"], "started_by": row["started_by"],
            "ended_by": row["ended_by"], "reason": row["reason"]}
# The remembered host key for a device, and forgetting it. Both live under
# /api/ssh/ because the key is shared: the terminal stores and checks the
# same row. Reading one is a ConfigRX read (it is shown in ConfigRX's device
# dialog); forgetting one is an `ssh` WRITE, since it is what lets the next
# connection accept whatever key it is offered. There is no route for
# trusting a NEW key — that decision is only ever taken with the offered key
# in hand, over the terminal's own socket.

def _ssh_device_host(service, device_id):
    """(device row, ip, port) for a device, or ValueError. The port is
    ConfigRX's stored SSH port, since that is the port this app connects on
    and the store is keyed by (host, port)."""
    device = _require(service.nodes_db.device(device_id), "device")
    config = service.configrx_db.device_config(device_id)
    port = int(config["ssh_port"]) if config and config["ssh_port"] else 22
    return device, device["ip"], port


# Must mirror app.js's THEMES (and boot.js's copy) exactly, or a theme
# rejected here silently reverts to dark instead of saving.
THEMES = ("dark", "light", "contrast", "midnight", "nord", "solarized", "slate", "neon")


# An honest denominator for the same filters `GET /api/alerts` applies, so
# an operator ticking select-all knows how many rows that really is. Where
# the database offers a filtered `count_alerts` this uses it; otherwise it
# asks for ids up to a cap and says when the cap is what answered — "300 of
# 5,000+ shown" is honest, "300 shown" is not.
ALERT_TOTAL_CAP = 5000


def _device_event_json(row) -> dict:
    """One device_events row as get_nodes_device_events spells it — reused
    by the fleet-wide route beside it, so the two cannot drift."""
    return {"id": row["id"], "ts": row["ts"], "kind": row["kind"],
            "detail": row["detail"]}

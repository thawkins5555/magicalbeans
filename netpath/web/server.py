"""The web server.

Standard library only: `http.server` with a threading mixin, plus `ssl` when a
certificate is configured. That keeps the deployment to "install PySide6 or
don't" rather than pulling a web framework and its dependency tree onto a
machine whose job is watching the network.

Every route carries a (module, level) permission and needs a signed-in
session — a browser's `sw_session` cookie, or (Tier 1 #10) an
`Authorization: Bearer <token>` API token, checked the same place and
against the same permission gates; see `permissions.py` and the ROUTES
table below. A token never mints a cookie session and is exempt from the
idle timeout that a cookie session is subject to — see `_route`'s handling
of the two. Without `--cert` this is plain HTTP, so the session cookie,
every credential typed into the interface and every bearer token sent
cross the network in the clear — bind to 127.0.0.1, or give it a
certificate.
"""

from __future__ import annotations

import json
import gzip
import hashlib
import mimetypes
import os
import re
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from collections import OrderedDict, deque

from . import api
from . import wsock
from .. import auth
from .. import permissions
from .service import Service

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Content types by extension, written down rather than asked of
# `mimetypes.guess_type`. That function consults the Windows registry, where
# .js has been known to resolve to text/plain — and every response here
# carries `X-Content-Type-Options: nosniff`, under which a script served as
# text/plain is refused outright and the application does not load. The
# charset is stated for every text type so a browser never has to guess it.
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".woff2": "font/woff2",
}

# What gets gzip-compressed on the way out. Text of every kind and the two
# structured formats; never an image (other than SVG, which is text) or
# anything already compressed. Below GZIP_MIN_BYTES the gzip header costs
# more than it saves.
COMPRESSIBLE_PREFIXES = ("text/", "application/json", "application/javascript",
                         "image/svg+xml")
GZIP_MIN_BYTES = 1024
GZIP_LEVEL = 6


def content_type_for(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in MIME_TYPES:
        return MIME_TYPES[ext]
    guessed, _ = mimetypes.guess_type(path)
    return guessed or "application/octet-stream"


def is_compressible(content_type: str) -> bool:
    return content_type.startswith(COMPRESSIBLE_PREFIXES)


class StaticCache:
    """The files under static/, read once and served from memory.

    Each entry holds the bytes, a gzip of them, a content-hash ETag and the
    file's mtime and size. Before this every request for a script re-read the
    file from disk (283 KB for the terminal emulator) and, on a match, sent a
    304 whose ETag was `mtime-size` — so identical files across two deploys
    revalidated as different, and a same-second rewrite of the same length
    aliased as the same. A hash is right in both directions.

    Loaded by WebServer.start(), which is also what restart() goes through,
    so a listener re-bound in-process for a port change gets a fresh map. A
    self-update never serves from a stale map: it swaps the whole package
    with the listener down and always ends in execv or _exit (selfupdate.py).

    The one live case is a developer editing a file while the server runs.
    `get()` stats the file (one stat, where the old path did a stat AND a
    read) and reloads the entry if the mtime or size moved, so an edit shows
    on the next request exactly as it did before. A file that is not in the
    map yet — added after start — is loaded on first request.
    """

    def __init__(self, root: str):
        self.root = root
        self._entries: dict[str, dict] = {}
        self._lock = threading.Lock()

    def load(self) -> None:
        entries = {}
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                full = os.path.join(dirpath, name)
                try:
                    entries[full] = self._read(full)
                except OSError:
                    continue
        with self._lock:
            self._entries = entries

    @staticmethod
    def _read(full: str) -> dict:
        stat = os.stat(full)
        with open(full, "rb") as handle:
            body = handle.read()
        content_type = content_type_for(full)
        gzipped = (gzip.compress(body, GZIP_LEVEL)
                   if is_compressible(content_type) and len(body) >= GZIP_MIN_BYTES
                   else None)
        return {
            "body": body,
            "gzip": gzipped,
            "etag": '"' + hashlib.sha256(body).hexdigest()[:32] + '"',
            "content_type": content_type,
            "mtime": stat.st_mtime,
            "size": stat.st_size,
        }

    def get(self, full: str) -> dict | None:
        try:
            stat = os.stat(full)
        except OSError:
            return None
        with self._lock:
            entry = self._entries.get(full)
        if entry and entry["mtime"] == stat.st_mtime and entry["size"] == stat.st_size:
            return entry
        try:
            entry = self._read(full)
        except OSError:
            return None
        with self._lock:
            self._entries[full] = entry
        return entry


STATIC_CACHE = StaticCache(STATIC_DIR)

R, W = permissions.READ, permissions.WRITE


def _password_requirement(params, body):
    """Changing your own password is always allowed (per-route None); only
    resetting a *different* account's needs the same administrator gate
    user management itself sits behind — mirrors post_password's own
    `resetting = target.lower() != me.lower()` check, since the route
    table can't see into the request body on its own.

    Administrator rather than Settings write since 4.37: resetting someone
    else's password is taking their account, and that belongs with creating
    and deleting accounts, not with changing a refresh interval."""
    me = params.get("_username", "")
    target = str(body.get("username", "") or me)
    return ("admin", W) if target.lower() != me.lower() else None


def _settings_requirement(params, body):
    """post_settings is one generic dispatcher for every module's own
    settings (body['scope']); the module that gates it is whichever one the
    scope names, not a fixed tag — 'global' (or anything unrecognized)
    falls to the Settings module itself.

    Derived from post_settings' own dispatch table, not from
    permissions.MODULES: a module listed there with no branch in
    post_settings was authorized against itself and then fell through to
    the global writer. `debug` was exactly that, so a debug:write account
    could rewrite the listener's bind address, port, TLS certificate and
    key paths, the DNS server the nslookup subprocesses use, and the
    session lifetimes. Reading the requirement from the table that decides
    what actually happens keeps the two from drifting apart again."""
    scope = str(body.get("scope", "global"))
    module = scope if scope in api.SETTINGS_SCOPES else "settings"
    return (module, W)


# (method, compiled path, handler, permission). permission is one of:
# None (no gate — auth alone is enough), a (module, level) pair, or a
# `fn(params, body) -> (module, level) | None` for the handful of routes
# whose requirement depends on the request itself. A trailing regex group
# is passed to the handler.
ROUTES = [
    ("POST", r"^/api/login$", api.post_login, None),
    ("POST", r"^/api/logout$", api.post_logout, None),
    ("POST", r"^/api/heartbeat$", api.post_heartbeat, None),
    ("GET", r"^/api/session$", api.get_session, None),
    # Accounts and their grants are the `admin` capability's, not
    # Settings'. Settings write used to be all of this as well: an account
    # granted it to change a retention cap could grant itself every module,
    # reset anyone's password and trigger the self-update.
    ("GET", r"^/api/users$", api.get_users, ("admin", W)),
    ("POST", r"^/api/users$", api.post_user, ("admin", W)),
    ("DELETE", r"^/api/users$", api.delete_user, ("admin", W)),
    ("POST", r"^/api/users/permissions$", api.post_user_permissions, ("admin", W)),
    ("POST", r"^/api/password$", api.post_password, _password_requirement),
    # API tokens (Tier 1 #10): a service-account credential, not a person's
    # — issuing or revoking one is exactly as administrative an act as
    # creating or deleting the account it authenticates as, so it sits
    # behind the same `admin` gate as the routes above rather than being
    # self-service. See api.post_token's docstring for the fuller reasoning.
    ("GET", r"^/api/tokens$", api.get_tokens, ("admin", R)),
    ("POST", r"^/api/tokens$", api.post_token, ("admin", W)),
    ("DELETE", r"^/api/tokens$", api.delete_token, ("admin", W)),
    # A dry-run bind against the configured (or about-to-be-saved) LDAP
    # settings — same shape as the SMTP test route below, and gated the
    # same way the settings that configure it are (ADMIN_ONLY_SETTINGS).
    ("POST", r"^/api/settings/ldap-test$", api.post_ldap_test, ("admin", W)),
    ("GET", r"^/api/state$", api.get_state, None),
    ("GET", r"^/api/config$", api.get_config, None),
    ("GET", r"^/api/netpath/targets$", api.get_targets, ("netpath", R)),
    ("POST", r"^/api/netpath/targets$", api.post_target, ("netpath", W)),
    ("PUT", r"^/api/netpath/targets/(\d+)$", api.put_target, ("netpath", W)),
    ("DELETE", r"^/api/netpath/targets/(\d+)$", api.delete_target, ("netpath", W)),
    ("POST", r"^/api/netpath/targets/(\d+)/trace$", api.trace_now, ("netpath", W)),
    ("GET", r"^/api/netpath/timeline$", api.get_timeline, ("netpath", R)),
    ("GET", r"^/api/netpath/topology$", api.get_topology, ("netpath", R)),
    ("GET", r"^/api/netflow/overview$", api.get_flow_overview, ("netflow", R)),
    ("GET", r"^/api/netflow/records$", api.get_flow_records, ("netflow", R)),
    ("GET", r"^/api/netflow/records/export\.csv$", api.get_flow_records_export, ("netflow", R)),
    ("POST", r"^/api/netflow/collector$", api.post_collector, ("netflow", W)),
    ("POST", r"^/api/netflow/testpacket$", api.post_test_packet, ("netflow", W)),
    ("GET", r"^/api/snmp/overview$", api.get_snmp_overview, ("snmp", R)),
    ("GET", r"^/api/snmp/traps$", api.get_snmp_traps, ("snmp", R)),
    ("GET", r"^/api/snmp/traps/export\.csv$", api.get_snmp_traps_export, ("snmp", R)),
    ("POST", r"^/api/snmp/collector$", api.post_snmp_collector, ("snmp", W)),
    ("POST", r"^/api/snmp/test$", api.post_snmp_test, ("snmp", W)),
    ("GET", r"^/api/syslog/overview$", api.get_syslog_overview, ("syslog", R)),
    ("GET", r"^/api/syslog/search$", api.get_syslog_search, ("syslog", R)),
    ("GET", r"^/api/syslog/search/export\.csv$", api.get_syslog_search_export, ("syslog", R)),
    ("POST", r"^/api/syslog/collector$", api.post_syslog_collector, ("syslog", W)),
    ("POST", r"^/api/syslog/test$", api.post_syslog_test, ("syslog", W)),
    ("GET", r"^/api/ipam/search$", api.get_ipam_search, ("ipam", R)),
    ("GET", r"^/api/ipam/subnets$", api.get_ipam_subnets, ("ipam", R)),
    ("POST", r"^/api/ipam/subnets$", api.post_ipam_subnet, ("ipam", W)),
    ("PUT", r"^/api/ipam/subnets/(\d+)$", api.put_ipam_subnet, ("ipam", W)),
    ("DELETE", r"^/api/ipam/subnets/(\d+)$", api.delete_ipam_subnet, ("ipam", W)),
    ("POST", r"^/api/ipam/subnets/(\d+)/scan$", api.post_ipam_subnet_scan, ("ipam", W)),
    ("POST", r"^/api/ipam/subnets/(\d+)/clear$", api.post_ipam_subnet_clear, ("ipam", W)),
    ("GET", r"^/api/ipam/hosts$", api.get_ipam_hosts, ("ipam", R)),
    ("GET", r"^/api/ipam/hosts/export\.csv$", api.get_ipam_hosts_export, ("ipam", R)),
    ("GET", r"^/api/ipam/conflicts$", api.get_ipam_conflicts, ("ipam", R)),
    ("POST", r"^/api/ipam/conflicts/(\d+)/resolve$", api.post_ipam_conflict_resolve, ("ipam", W)),
    ("GET", r"^/api/ipam/dhcp/servers$", api.get_ipam_dhcp_servers, ("ipam", R)),
    ("POST", r"^/api/ipam/dhcp/servers$", api.post_ipam_dhcp_server, ("ipam", W)),
    ("PUT", r"^/api/ipam/dhcp/servers/(\d+)$", api.put_ipam_dhcp_server, ("ipam", W)),
    ("DELETE", r"^/api/ipam/dhcp/servers/(\d+)$", api.delete_ipam_dhcp_server, ("ipam", W)),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/poll$", api.post_ipam_dhcp_server_poll, ("ipam", W)),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/test$", api.post_ipam_dhcp_server_test, ("ipam", W)),
    ("POST", r"^/api/ipam/dhcp/servers/(\d+)/credential$", api.post_ipam_dhcp_server_credential, ("ipam", W)),
    ("DELETE", r"^/api/ipam/dhcp/servers/(\d+)/credential$", api.delete_ipam_dhcp_server_credential, ("ipam", W)),
    ("GET", r"^/api/ipam/dhcp/scopes$", api.get_ipam_dhcp_scopes, ("ipam", R)),
    ("GET", r"^/api/ipam/dhcp/leases$", api.get_ipam_dhcp_leases, ("ipam", R)),
    ("GET", r"^/api/ipam/dhcp/leases/export\.csv$",
     api.get_ipam_dhcp_leases_export, ("ipam", R)),
    ("GET", r"^/api/ipam/dhcp/scope-history$", api.get_ipam_dhcp_scope_history, ("ipam", R)),
    ("GET", r"^/api/nodes/overview$", api.get_nodes_overview, ("nodes", R)),
    ("GET", r"^/api/nodes/mac-search$", api.get_nodes_mac_search, ("nodes", R)),
    # The L2 topology view (Tier 1 #5's UI half): the fleet-wide link graph,
    # and its own CSV export — matched before the "export.csv" suffix could
    # ever be confused with a device id, the same ordering rule the devices
    # export above already follows.
    ("GET", r"^/api/nodes/topology$", api.get_nodes_topology, ("nodes", R)),
    ("GET", r"^/api/nodes/topology/export\.csv$", api.get_nodes_topology_export, ("nodes", R)),
    ("GET", r"^/api/nodes/devices$", api.get_nodes_devices, ("nodes", R)),
    # Same filters as the list above, exported as CSV: matched before the
    # `(\d+)$` device route below on purpose, though \d+ would never match
    # the literal "export.csv" anyway.
    ("GET", r"^/api/nodes/devices/export\.csv$", api.get_nodes_devices_export, ("nodes", R)),
    ("POST", r"^/api/nodes/devices$", api.post_nodes_device, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-import$", api.post_nodes_devices_bulk_import, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-update$", api.post_nodes_devices_bulk_update, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-delete$", api.post_nodes_devices_bulk_delete, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)$", api.get_nodes_device, ("nodes", R)),
    ("PUT", r"^/api/nodes/devices/(\d+)$", api.put_nodes_device, ("nodes", W)),
    ("DELETE", r"^/api/nodes/devices/(\d+)$", api.delete_nodes_device, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-poll$", api.post_nodes_devices_bulk_poll, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-identify$", api.post_nodes_devices_bulk_identify, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/(\d+)/poll$", api.post_nodes_device_poll, ("nodes", W)),
    # Focus sets a three-second poll interval on a device. That is traffic
    # this application decides to send, at twenty times the normal rate, at
    # a box that may be a PLC — a write, not a read, whatever the browser
    # happens to call it while a row is selected.
    ("POST", r"^/api/nodes/devices/(\d+)/focus$", api.post_nodes_device_focus, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)/interfaces/(\d+)/dom$", api.get_nodes_device_dom, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/interfaces/(\d+)/mac-table$", api.get_nodes_device_mac_table, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/oids$", api.get_nodes_device_oids, ("nodes", R)),
    # A whole-device walk is a live SNMP job, not a read of stored data, so
    # starting and cancelling one need write access; watching it does not.
    ("POST", r"^/api/nodes/devices/(\d+)/oid-walk$", api.post_nodes_device_oid_walk, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)/oid-walk$", api.get_nodes_device_oid_walk, ("nodes", R)),
    ("DELETE", r"^/api/nodes/devices/(\d+)/oid-walk$", api.delete_nodes_device_oid_walk, ("nodes", W)),
    # Vendor identification: starting or cancelling the walk is a live SNMP
    # job, so it needs write access; reading the verdict does not.
    ("POST", r"^/api/nodes/devices/(\d+)/identify$", api.post_nodes_device_identify, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)/identify$", api.get_nodes_device_identify, ("nodes", R)),
    ("DELETE", r"^/api/nodes/devices/(\d+)/identify$", api.delete_nodes_device_identify, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/(\d+)/test$", api.post_nodes_device_test, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)/interfaces$", api.get_nodes_device_interfaces, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/interfaces/export\.csv$",
     api.get_nodes_device_interfaces_export, ("nodes", R)),
    # The device detail pane's Neighbours section (Tier 1 #5's UI half):
    # one device's own LLDP/CDP rows, present and stale alike.
    ("GET", r"^/api/nodes/devices/(\d+)/neighbors$", api.get_nodes_device_neighbors, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/neighbors/export\.csv$",
     api.get_nodes_device_neighbors_export, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/metrics$", api.get_nodes_device_metrics, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/series$", api.get_nodes_device_series, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/events$", api.get_nodes_device_events, ("nodes", R)),
    ("GET", r"^/api/nodes/devices/(\d+)/timeline$", api.get_nodes_device_timeline, ("nodes", R)),
    ("POST", r"^/api/nodes/devices/(\d+)/credential$", api.post_nodes_device_credential, ("nodes", W)),
    ("DELETE", r"^/api/nodes/devices/(\d+)/credential$", api.delete_nodes_device_credential, ("nodes", W)),
    ("GET", r"^/api/nodes/device-groups$", api.get_nodes_device_groups, ("nodes", R)),
    ("POST", r"^/api/nodes/device-groups$", api.post_nodes_device_group, ("nodes", W)),
    ("PUT", r"^/api/nodes/device-groups/(\d+)$", api.put_nodes_device_group, ("nodes", W)),
    ("DELETE", r"^/api/nodes/device-groups/(\d+)$", api.delete_nodes_device_group, ("nodes", W)),
    ("GET", r"^/api/nodes/groups$", api.get_nodes_groups, ("nodes", R)),
    ("POST", r"^/api/nodes/groups$", api.post_nodes_group, ("nodes", W)),
    ("PUT", r"^/api/nodes/groups/(\d+)$", api.put_nodes_group, ("nodes", W)),
    ("DELETE", r"^/api/nodes/groups/(\d+)$", api.delete_nodes_group, ("nodes", W)),
    ("POST", r"^/api/nodes/groups/(\d+)/default$", api.post_nodes_group_default, ("nodes", W)),
    ("POST", r"^/api/nodes/groups/(\d+)/credential$", api.post_nodes_group_credential, ("nodes", W)),
    ("DELETE", r"^/api/nodes/groups/(\d+)/credential$", api.delete_nodes_group_credential, ("nodes", W)),
    ("POST", r"^/api/nodes/groups/(\d+)/credentials$", api.post_nodes_group_credentials, ("nodes", W)),
    ("PUT", r"^/api/nodes/groups/(\d+)/credentials/(\d+)$", api.put_nodes_group_credential, ("nodes", W)),
    ("DELETE", r"^/api/nodes/groups/(\d+)/credentials/(\d+)$", api.delete_nodes_group_credential_row, ("nodes", W)),
    ("POST", r"^/api/nodes/groups/(\d+)/credentials/(\d+)/secret$", api.post_nodes_group_credential_secret, ("nodes", W)),
    ("DELETE", r"^/api/nodes/groups/(\d+)/credentials/(\d+)/secret$", api.delete_nodes_group_credential_secret, ("nodes", W)),
    ("POST", r"^/api/nodes/discovery$", api.post_nodes_discovery, ("nodes", W)),
    ("GET", r"^/api/nodes/discovery$", api.get_nodes_discovery, ("nodes", R)),
    ("GET", r"^/api/nodes/discovery/(\d+)$", api.get_nodes_discovery_job, ("nodes", R)),
    ("DELETE", r"^/api/nodes/discovery/(\d+)$", api.delete_nodes_discovery_job, ("nodes", W)),
    ("POST", r"^/api/nodes/discovery/(\d+)/promote$", api.post_nodes_discovery_promote, ("nodes", W)),
    ("POST", r"^/api/nodes/discovery/(\d+)/reviewed$", api.post_nodes_discovery_reviewed, ("nodes", W)),
    ("POST", r"^/api/nodes/collector$", api.post_nodes_collector, ("nodes", W)),
    ("GET", r"^/api/nodes/mibs$", api.get_nodes_mibs, ("nodes", R)),
    ("POST", r"^/api/nodes/mibs$", api.post_nodes_mib, ("nodes", W)),
    ("POST", r"^/api/nodes/mibs/resolve-all$", api.post_nodes_mibs_resolve_all, ("nodes", W)),
    ("GET", r"^/api/nodes/mib-catalog$", api.get_nodes_mib_catalog, ("nodes", R)),
    ("GET", r"^/api/nodes/mib-catalog/status$", api.get_nodes_mib_catalog_status, ("nodes", R)),
    ("POST", r"^/api/nodes/mib-catalog/([\w-]+)/install$", api.post_nodes_mib_catalog_install, ("nodes", W)),
    ("GET", r"^/api/nodes/mibs/(\d+)$", api.get_nodes_mib, ("nodes", R)),
    ("DELETE", r"^/api/nodes/mibs/(\d+)$", api.delete_nodes_mib, ("nodes", W)),
    ("POST", r"^/api/nodes/mibs/(\d+)/resolve$", api.post_nodes_mib_resolve, ("nodes", W)),
    ("PUT", r"^/api/nodes/mibs/(\d+)/objects/(\d+)$", api.put_nodes_mib_object, ("nodes", W)),
    ("GET", r"^/api/alerts/overview$", api.get_alerts_overview, ("alerts", R)),
    ("GET", r"^/api/alerts$", api.get_alerts, ("alerts", R)),
    ("GET", r"^/api/alerts/export\.csv$", api.get_alerts_export, ("alerts", R)),
    ("GET", r"^/api/alerts/mutes$", api.get_alerts_mutes, ("alerts", R)),
    ("POST", r"^/api/alerts/mute$", api.post_alerts_mute, ("alerts", W)),
    ("DELETE", r"^/api/alerts/mute$", api.delete_alerts_mute, ("alerts", W)),
    ("POST", r"^/api/alerts/bulk-mute$", api.post_alerts_bulk_mute, ("alerts", W)),
    ("GET", r"^/api/alerts/windows$", api.get_alerts_windows, ("alerts", R)),
    ("POST", r"^/api/alerts/windows$", api.post_alerts_window, ("alerts", W)),
    ("PUT", r"^/api/alerts/windows/(\d+)$", api.put_alerts_window, ("alerts", W)),
    ("DELETE", r"^/api/alerts/windows/(\d+)$", api.delete_alerts_window, ("alerts", W)),
    ("POST", r"^/api/alerts/windows/(\d+)/end$", api.post_alerts_window_end, ("alerts", W)),
    ("GET", r"^/api/alerts/(\d+)$", api.get_alert, ("alerts", R)),
    ("POST", r"^/api/alerts/(\d+)/ack$", api.post_alert_ack, ("alerts", W)),
    ("POST", r"^/api/alerts/(\d+)/unack$", api.post_alert_unack, ("alerts", W)),
    ("POST", r"^/api/alerts/(\d+)/resolve$", api.post_alert_resolve, ("alerts", W)),
    ("POST", r"^/api/alerts/ack-all$", api.post_alerts_ack_all, ("alerts", W)),
    ("POST", r"^/api/alerts/bulk-ack$", api.post_alerts_bulk_ack, ("alerts", W)),
    ("POST", r"^/api/alerts/bulk-unack$", api.post_alerts_bulk_unack, ("alerts", W)),
    ("POST", r"^/api/alerts/bulk-resolve$", api.post_alerts_bulk_resolve, ("alerts", W)),
    ("GET", r"^/api/alerts/rules$", api.get_alerts_rules, ("alerts", R)),
    ("POST", r"^/api/alerts/rules$", api.post_alerts_rule, ("alerts", W)),
    ("PUT", r"^/api/alerts/rules/(\d+)$", api.put_alerts_rule, ("alerts", W)),
    ("DELETE", r"^/api/alerts/rules/(\d+)$", api.delete_alerts_rule, ("alerts", W)),
    ("GET", r"^/api/alerts/templates$", api.get_alerts_templates, ("alerts", R)),
    ("POST", r"^/api/alerts/templates$", api.post_alerts_template, ("alerts", W)),
    ("PUT", r"^/api/alerts/templates/(\d+)$", api.put_alerts_template, ("alerts", W)),
    ("POST", r"^/api/alerts/templates/(\d+)/reset$", api.post_alerts_template_reset, ("alerts", W)),
    ("POST", r"^/api/alerts/templates/(\d+)/preview$", api.post_alerts_template_preview, ("alerts", R)),
    ("DELETE", r"^/api/alerts/templates/(\d+)$", api.delete_alerts_template, ("alerts", W)),
    ("POST", r"^/api/alerts/smtp/credential$", api.post_alerts_smtp_credential, ("alerts", W)),
    ("DELETE", r"^/api/alerts/smtp/credential$", api.delete_alerts_smtp_credential, ("alerts", W)),
    ("POST", r"^/api/alerts/smtp/test$", api.post_alerts_smtp_test, ("alerts", W)),
    ("POST", r"^/api/alerts/engine$", api.post_alerts_engine, ("alerts", W)),
    ("GET", r"^/api/wireless/overview$", api.get_wireless_overview, ("wireless", R)),
    ("GET", r"^/api/wireless/controllers$", api.get_wireless_controllers, ("wireless", R)),
    ("POST", r"^/api/wireless/controllers$", api.post_wireless_controller, ("wireless", W)),
    ("PUT", r"^/api/wireless/controllers/(\d+)$", api.put_wireless_controller, ("wireless", W)),
    ("DELETE", r"^/api/wireless/controllers/(\d+)$", api.delete_wireless_controller, ("wireless", W)),
    ("POST", r"^/api/wireless/controllers/(\d+)/credential$", api.post_wireless_controller_credential, ("wireless", W)),
    ("DELETE", r"^/api/wireless/controllers/(\d+)/credential$", api.delete_wireless_controller_credential, ("wireless", W)),
    ("POST", r"^/api/wireless/controllers/(\d+)/poll$", api.post_wireless_controller_poll, ("wireless", W)),
    ("GET", r"^/api/wireless/aps$", api.get_wireless_aps, ("wireless", R)),
    ("GET", r"^/api/wireless/aps/export\.csv$", api.get_wireless_aps_export, ("wireless", R)),
    ("POST", r"^/api/wireless/aps/(\d+)/service$", api.post_wireless_ap_service, ("wireless", W)),
    ("DELETE", r"^/api/wireless/aps/(\d+)$", api.delete_wireless_ap, ("wireless", W)),
    ("POST", r"^/api/wireless/collector$", api.post_wireless_collector, ("wireless", W)),
    ("POST", r"^/api/ipam/worker$", api.post_ipam_worker, ("ipam", W)),
    ("GET", r"^/api/configrx/overview$", api.get_configrx_overview, ("configrx", R)),
    ("GET", r"^/api/configrx/devices$", api.get_configrx_devices, ("configrx", R)),
    ("POST", r"^/api/configrx/devices/bulk-config$", api.post_configrx_devices_bulk_config, ("configrx", W)),
    ("POST", r"^/api/configrx/devices/bulk-credential$", api.post_configrx_devices_bulk_credential, ("configrx", W)),
    ("POST", r"^/api/configrx/devices/bulk-backup$", api.post_configrx_devices_bulk_backup, ("configrx", W)),
    ("GET", r"^/api/configrx/devices/(\d+)$", api.get_configrx_device, ("configrx", R)),
    ("POST", r"^/api/configrx/devices/(\d+)/config$", api.post_configrx_device_config, ("configrx", W)),
    ("POST", r"^/api/configrx/devices/(\d+)/credential$", api.post_configrx_device_credential, ("configrx", W)),
    ("DELETE", r"^/api/configrx/devices/(\d+)/credential$", api.delete_configrx_device_credential, ("configrx", W)),
    ("GET", r"^/api/configrx/devices/(\d+)/backups$", api.get_configrx_device_backups, ("configrx", R)),
    ("POST", r"^/api/configrx/devices/(\d+)/backup$", api.post_configrx_device_backup, ("configrx", W)),
    # The backup's CONTENT, not its metadata: reading a stored config is a
    # read, the same as the listing beside it (dates, sizes, hashes,
    # whether it was redacted) — a read-only operator needs both to answer
    # "has this switch changed". get_configrx_backup itself is what still
    # guards a verbatim (store_secrets) capture: a caller without ConfigRX
    # write gets it redacted rather than 403ing outright.
    ("GET", r"^/api/configrx/backups/(\d+)$", api.get_configrx_backup, ("configrx", R)),
    # A diff hands over the device's own configuration lines exactly as
    # reading one backup's content does (see get_configrx_backup's own
    # comment above), so it is gated the same way — matched before the
    # "(\d+)" backup route above could ever apply, though "diff" would
    # never match \d+ anyway.
    ("GET", r"^/api/configrx/diff$", api.get_configrx_diff, ("configrx", W)),
    ("POST", r"^/api/configrx/backups/bulk-delete$",
     api.post_configrx_backups_bulk_delete, ("configrx", W)),
    ("DELETE", r"^/api/configrx/backups/(\d+)$", api.delete_configrx_backup, ("configrx", W)),
    ("POST", r"^/api/configrx/worker$", api.post_configrx_worker, ("configrx", W)),
    # The remembered SSH host key for a device: shown and forgotten in
    # ConfigRX's device dialog, so both routes are ConfigRX's. Forgetting is
    # what lets the next connection accept a new key, and configrx write
    # already decides which port and which credential that connection uses —
    # it is the permission that already says which box is trusted, so it is
    # the right holder of "start over with this device's key". Trusting a new
    # key from inside the terminal stays ("ssh", W).
    ("GET", r"^/api/ssh/devices/(\d+)/hostkey$", api.get_ssh_device_hostkey, ("configrx", R)),
    ("DELETE", r"^/api/ssh/devices/(\d+)/hostkey$", api.delete_ssh_device_hostkey, ("configrx", W)),
    # The terminal window. Read is meaningless for a shell — you either get
    # to type on the device or you do not — so both routes want write, and
    # the socket is the one hijacking route in the table (see _route).
    ("GET", r"^/api/ssh/devices/(\d+)$", api.get_ssh_device, ("ssh", W)),
    ("GET", r"^/api/ssh/devices/(\d+)/socket$", api.ws_ssh_device, ("ssh", W)),
    # The on-disk audit trail. Administrator-only, and there is deliberately
    # no route that writes to or deletes from it.
    ("GET", r"^/api/audit$", api.get_audit, ("admin", R)),
    ("GET", r"^/api/debug$", api.get_debug, ("debug", R)),
    ("POST", r"^/api/debug/clear$", api.post_debug_clear, ("debug", W)),
    ("POST", r"^/api/settings$", api.post_settings, _settings_requirement),
    # Maintenance deletes retention data outright and self-update replaces
    # this host's own code: both are administrator acts, not settings.
    ("POST", r"^/api/maintenance$", api.post_maintenance, ("admin", W)),
    ("POST", r"^/api/update$", api.post_update, ("admin", W)),
    # Front-end additions (workstream E), appended so they never share
    # a hunk with the module routes above. `/api/alerts/total` cannot
    # collide with `/api/alerts/(\d+)`, which only matches digits.
    ("GET", r"^/api/alerts/total$", api.get_alerts_total, ("alerts", R)),
    # Which of this host's features can work at all. No gate beyond a
    # session: it is a property of the machine, not of any module.
    ("GET", r"^/api/platform$", api.get_platform, None),
    # The Dashboard aggregates whatever the account can already read,
    # so like /api/state it is not gated as a whole — each section is
    # dropped inside the handler instead. The offenders list is device
    # data and is gated on Nodes read.
    ("GET", r"^/api/dashboard$", api.get_dashboard, None),
    ("GET", r"^/api/dashboard/offenders$", api.get_dashboard_offenders,
     ("nodes", R)),
    # Two fields the write paths accept and the read serializers do not
    # return yet, so the forms that set them can show what is set.
    ("GET", r"^/api/nodes/devices/(\d+)/upstream$",
     api.get_nodes_device_upstream, ("nodes", R)),
    ("GET", r"^/api/alerts/rules/extras$", api.get_alerts_rule_extras,
     ("alerts", R)),
]

COMPILED = [(method, re.compile(pattern), handler, requirement)
            for method, pattern, handler, requirement in ROUTES]

# Reachable without a session: the sign-in page and what it needs to render.
# tokens.css is the stylesheet app.css reads its colours from; the sign-in
# page links both, before there is a session to be gated on.
PUBLIC_PATHS = {"/login", "/login.html", "/login.js", "/tokens.css", "/app.css", "/boot.js",
                "/favicon.ico", "/favicon.svg"}
PUBLIC_API = {"/api/login", "/api/session"}

# What an account whose password must still be changed may reach. Everything
# else under /api/ is refused until it has been: the seeded admin/admin
# account is a way in, not an account, and the flag saying so was enforced
# only by the bundled UI (app.js) — anything talking to the API directly was
# exempt, so a fresh install was owned by whoever reached the port first.
# Static files are untouched: the browser has to be able to load the app in
# order to show the change-password dialog at all.
MUST_CHANGE_API = {"/api/session", "/api/logout", "/api/state", "/api/config",
                   "/api/heartbeat", "/api/password"}

SESSION_COOKIE = "sw_session"

# `Authorization: Bearer <token>` — an API token (Tier 1 #10), checked
# wherever the session cookie above is checked, in `_route` below. Case-
# insensitive per RFC 9110 §11.1 (the scheme name, not the token itself).
BEARER_RE = re.compile(r"^Bearer\s+(\S+)$", re.IGNORECASE)


class LengthRequired(ValueError):
    """A body this server will not read: chunked rather than measured. Its
    own type so _route can answer 411 instead of the 400 every other bad
    body gets."""


# How many source addresses the access log remembers at once. `recent` has
# always been a bounded deque; `clients` was a plain dict with nothing
# removing entries, so every address that ever made a request stayed for
# the life of the process along with its user-agent string — every
# port-scanner source, every health-check probe, every DHCP-reassigned
# laptop. A thousand is far more than any real operator population and
# still a bounded amount of memory and of work for the console, which
# re-sorts this dict once a second.
MAX_TRACKED_CLIENTS = 1000


class AccessLog:
    """Recent requests and per-client totals, for the service console.

    Bounded in both directions: this is a live view, not an audit trail —
    that is what appdb's `audit` table is for, and unlike this it is never
    trimmed. Static files are counted but kept out of the recent list,
    which would otherwise be nothing but the five scripts every page load
    fetches.
    """

    def __init__(self, capacity: int = 400,
                 max_clients: int = MAX_TRACKED_CLIENTS):
        self._lock = threading.Lock()
        self.recent: deque = deque(maxlen=capacity)
        # Ordered by least-recently-seen, so eviction drops the address
        # that has been quiet longest rather than an arbitrary one.
        self.clients: "OrderedDict[str, dict]" = OrderedDict()
        self.max_clients = max_clients
        self.total = 0
        self.errors = 0
        self.active = 0
        self.peak_active = 0
        self.started_at = time.time()

    def record(self, client: str, method: str, path: str, status: int,
               ms: float, agent: str) -> None:
        with self._lock:
            self.total += 1
            if status >= 400:
                self.errors += 1
            entry = {"ts": time.time(), "client": client, "method": method,
                     "path": path, "status": status, "ms": ms}
            if not path.startswith(("/app.", "/netpath.js", "/netflow.js",
                                    "/snmp.js", "/syslog.js", "/debug.js",
                                    "/settings.js", "/ssh.js", "/ssh.css",
                                    "/vendor/")):
                self.recent.appendleft(entry)
            info = self.clients.setdefault(client, {
                "requests": 0, "first_seen": time.time(), "last_seen": 0.0,
                "agent": agent, "errors": 0})
            info["requests"] += 1
            info["last_seen"] = time.time()
            if agent:
                info["agent"] = agent
            if status >= 400:
                info["errors"] += 1
            self.clients.move_to_end(client)
            while len(self.clients) > self.max_clients:
                self.clients.popitem(last=False)

    def opened(self) -> None:
        with self._lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)

    def closed(self) -> None:
        with self._lock:
            self.active = max(0, self.active - 1)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total": self.total, "errors": self.errors,
                "active": self.active, "peak_active": self.peak_active,
                "recent": list(self.recent),
                "clients": {name: dict(info) for name, info in self.clients.items()},
            }

    def clear(self) -> None:
        with self._lock:
            self.recent.clear()
            self.clients.clear()
            self.total = self.errors = 0


class Handler(BaseHTTPRequestHandler):
    server_version = "SappiWhere"
    sys_version = ""
    # HTTP/1.1, for keep-alive. The default here is HTTP/1.0, under which
    # every response closed the connection and a page load opened one TCP
    # (or TLS) connection per script — around twenty. Three things in this
    # file leaned on that and are unaffected: the WebSocket handshake writes
    # its own 101 status line (wsock.py) and sets close_connection; _body
    # refuses Transfer-Encoding outright, so a chunked request is still
    # 411 and never misread; and every response leaves through _send with a
    # Content-Length, or is a 304 with no body — the two things a persistent
    # connection needs to know where one response ends. What changes is the
    # resource profile: a browser holds a handful of idle connections per
    # tab, each on a daemon thread, until `timeout` below closes them.
    protocol_version = "HTTP/1.1"
    service: Service = None      # set on the server instance
    access: AccessLog = None

    # socketserver only calls settimeout() when this is not None, so without
    # it a half-open connection sat in readline() forever holding its
    # thread — one slow-loris socket per thread, with no cap on either.
    # Thirty seconds is far longer than any legitimate client needs to
    # finish sending a request. The terminal's WebSocket replaces this with
    # its own timeout the moment it takes the socket over (wsock.WebSocket),
    # so a quiet shell is not affected.
    timeout = 30

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt, *args):
        return  # the event log is the log; stderr noise helps nobody

    def send_response(self, code, message=None):
        """The base class's, without the `Server` header.

        "SappiWhere" on every response tells an unauthenticated scanner
        which product — and so which version-specific weaknesses — to try,
        and buys nothing: no client here reads it.
        """
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def setup(self):
        super().setup()
        if self.access:
            self.access.opened()

    def finish(self):
        try:
            super().finish()
        finally:
            if self.access:
                self.access.closed()

    def _accepts_gzip(self) -> bool:
        """Whether the client asked for gzip, per Accept-Encoding.

        Token-wise rather than a substring test, so `gzip;q=0` — a client
        saying it must NOT receive gzip — is honoured, and `x-gzip` is not
        mistaken for a request for it."""
        header = self.headers.get("Accept-Encoding") or ""
        for part in header.split(","):
            token, _, params = part.strip().partition(";")
            if token.strip().lower() != "gzip":
                continue
            q = 1.0
            for param in params.split(";"):
                name, _, value = param.strip().partition("=")
                if name.strip().lower() == "q":
                    try:
                        q = float(value)
                    except ValueError:
                        q = 0.0
            return q > 0
        return False

    def _send(self, code: int, body: bytes, content_type: str,
              extra_headers: dict | None = None,
              gzipped: bytes | None = None) -> None:
        """Every response leaves through here — that is what makes the
        security headers below a guarantee rather than a convention, and it
        is where compression is negotiated once for all of them.

        `gzipped` is a caller that already holds the compressed form (the
        static cache); anything else compressible above GZIP_MIN_BYTES is
        compressed here per response, which for the 10 KB JSON polls is
        cheaper than the bytes it saves many times over. A 304 carries no
        body, no length and no type — but it does carry every security
        header, which the hand-written 304 this replaces did not: revalidation
        is the steady state for every script and stylesheet, so those were
        the headers most responses were missing.
        """
        headers = dict(extra_headers or {})
        self._drain_request_body()
        self._status = code
        self.send_response(code)
        if code != 304:
            compressible = is_compressible(content_type)
            if compressible:
                # The representation depends on the request header, and any
                # cache between here and the browser has to know that.
                headers.setdefault("Vary", "Accept-Encoding")
            if (compressible and body and len(body) >= GZIP_MIN_BYTES
                    and "Content-Encoding" not in headers and self._accepts_gzip()):
                body = gzipped if gzipped is not None else gzip.compress(body, GZIP_LEVEL)
                headers["Content-Encoding"] = "gzip"
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        # No external resources are loaded, so this can be strict.
        # `connect-src 'self'` is what the terminal window's WebSocket needs
        # and all it needs: current browsers count a same-origin ws:// (or
        # wss://) URL as 'self', while the bare scheme-sources `ws: wss:`
        # this used to carry matched *any* host, which would let every page
        # in the product open a socket anywhere. `frame-ancestors 'none'`
        # keeps the terminal — Trust button and all — out of anyone's
        # iframe. `form-action 'self'` is what stops injected markup from
        # posting an operator's typing off-site, and `base-uri 'none'`
        # stops an injected <base> from repointing every relative URL on
        # the page. Inline styles stay allowed for the terminal emulator,
        # which injects its own <style>.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline';"
                         " connect-src 'self'; frame-ancestors 'none';"
                         " base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Only under TLS: sent over plain HTTP it is ignored by browsers,
        # and sending it from a host that is later served without a
        # certificate would lock the interface out of every browser that
        # remembered it.
        if getattr(self.server, "is_tls", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and code != 304:
            self.wfile.write(body)

    def _json(self, payload, code: int = 200, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        headers = {"Cache-Control": "no-store"}
        headers.update(extra_headers or {})
        self._send(code, body, "application/json; charset=utf-8", headers)

    # Every request body this app takes is JSON, and every one of them is
    # small — a device, a rule, a settings block. Anything past this is
    # refused before a byte is read, rather than being pulled into memory
    # first: a single mistyped Content-Length used to be a 128 MiB
    # allocation, and that was the general limit for every route.
    MAX_BODY_BYTES = 16 * 1024 * 1024

    # The exception, and the only one: a MIB upload carries a base64-encoded
    # archive, whose ceiling is the operator's own max_mib_bundle_bytes
    # setting (64 MB by default, ~85 MB once encoded). Raising the limit for
    # exactly these paths keeps the general cap tight without breaking a
    # documented setting.
    LARGE_BODY_PATHS = ("/api/nodes/mibs",)

    def _body_limit(self, path: str) -> int:
        if not path.startswith(self.LARGE_BODY_PATHS):
            return self.MAX_BODY_BYTES
        try:
            budget = int(self.service.nodes_settings.get(
                "max_mib_bundle_bytes", 0))
        except (AttributeError, TypeError, ValueError):
            budget = 0
        # base64 is four bytes per three, plus the JSON envelope around it.
        return max(self.MAX_BODY_BYTES, (budget * 4) // 3 + 65536)

    def _drain_request_body(self) -> None:
        """Consume a request body the handler never read, before answering.

        A refusal that comes before the handler — not signed in, must change
        password, wrong content type, wrong origin — used to respond with the
        POST body still sitting unread in the socket. Under HTTP/1.0 the
        close threw it away. Under a persistent connection it is the first
        bytes of the next request, and that request fails to parse. Small
        bodies are read and dropped so the connection stays usable; anything
        larger, or chunked, closes the connection instead, which is also
        what the 411 for chunked bodies needs."""
        if getattr(self, "_body_consumed", False):
            return
        self._body_consumed = True
        if (self.headers.get("Transfer-Encoding") or "").strip():
            self.close_connection = True
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return
        if length <= 0:
            return
        if length > self.MAX_BODY_BYTES:
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except OSError:
            self.close_connection = True

    def _body(self, limit: int | None = None) -> dict:
        # Chunked bodies were read as Content-Length 0, i.e. as an empty
        # body, and the request then ran with default arguments — POST
        # /api/settings with no body resolves to apply_global_settings({}).
        # Harmless as deployed (HTTP/1.0, no keep-alive) and a hole the
        # moment a reverse proxy forwards a chunked request, so it is
        # refused outright rather than silently reinterpreted.
        if (self.headers.get("Transfer-Encoding") or "").strip():
            raise LengthRequired(
                "This server reads Content-Length only; send the body with a "
                "length rather than chunked")
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            self._body_consumed = True
            return {}
        cap = self.MAX_BODY_BYTES if limit is None else limit
        if length > cap:
            # Left unread on purpose: _send will close the connection rather
            # than read a body this size.
            raise ValueError(
                f"Request body of {length:,} bytes exceeds the "
                f"{cap:,} byte limit")
        raw = self.rfile.read(length)
        self._body_consumed = True
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        if not isinstance(body, dict):
            return {}
        # Underscore-prefixed keys are this layer's, not the caller's — the
        # same rule the query string has always had. Only the body was
        # exempt, and post_login read `_agent` out of it, so the session
        # list showed whatever the client claimed instead of its real
        # User-Agent (arbitrary markup included).
        return {k: v for k, v in body.items() if not str(k).startswith("_")}

    # -------------------------------------------------------------- routing

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # ------------------------------------------------------------ sessions

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def _set_session_cookie(self, token: str, clear: bool = False) -> dict:
        """HttpOnly so script cannot read it, SameSite=Strict so it is not sent
        on a cross-site request, Secure only under TLS because a Secure cookie
        is dropped outright over plain HTTP."""
        attributes = [f"{SESSION_COOKIE}={'' if clear else token}",
                      "Path=/", "HttpOnly", "SameSite=Strict"]
        if getattr(self.server, "is_tls", False):
            attributes.append("Secure")
        attributes.append("Max-Age=0" if clear else "Max-Age=%d"
                          % self.service.sessions.max_seconds)
        return {"Set-Cookie": "; ".join(attributes)}

    def _dispatch(self, method: str) -> None:
        # One Handler instance serves every request on a persistent
        # connection, so per-request state is reset here, not in __init__.
        self._body_consumed = False
        started = time.perf_counter()
        try:
            self._route(method)
        finally:
            if self.access:
                self.access.record(
                    self.client_address[0], method, urlparse(self.path).path,
                    getattr(self, "_status", 0),
                    (time.perf_counter() - started) * 1000,
                    self.headers.get("User-Agent", "")[:120])

    def _origin_matches(self, origin: str) -> bool:
        """Whether `origin` is this server's own origin — scheme, host and
        port, all three.

        Comparing the netloc alone accepted `https://host:8443` against a
        plain-HTTP listener on that host and port, and vice versa. The hole
        is narrow (a page at `http://host:8443` cannot exist while
        `https://host:8443` is what is listening) but an origin is defined
        as the triple and there is no reason to compare two thirds of it.
        The scheme comes from whether a certificate is configured, which is
        the same thing the cookie's `Secure` flag is decided by.
        """
        parsed = urlparse(origin)
        expected_scheme = "https" if getattr(self.server, "is_tls", False) else "http"
        host = (self.headers.get("Host") or "").strip().lower()
        return (parsed.scheme.lower() == expected_scheme
                and parsed.netloc.lower() == host)

    def _same_origin(self, require_origin: bool = False) -> bool:
        """Whether a request came from this server's own pages.

        One rule, used by both the state-changing methods and the
        terminal's WebSocket upgrade, with `require_origin` the single
        difference between them. A browser always sends `Origin` on an
        upgrade, so the socket refuses a missing one. It does NOT always
        send it on a same-origin fetch, and nothing outside a browser sends
        it at all — the demo harness and every script that drives this API
        through http.client included — so for POST/PUT/DELETE an absent
        `Origin` is allowed. That is not a hole: the attack this closes is a
        page on another origin using the operator's cookie, and a browser
        doing that always labels it. `Sec-Fetch-Site` is checked the same
        way: honoured when the browser sends it, absent otherwise.

        `SameSite=Strict` on the cookie is not enough on its own, because
        "site" is registrable-domain-scoped: another port on this host or a
        sibling subdomain is the same site, and over plain HTTP a network
        attacker can put a page on one.
        """
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            if require_origin:
                return False
        elif not self._origin_matches(origin):
            return False
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        return True

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # Query parameters starting with an underscore are ours, not the
        # caller's; strip anything that arrives claiming to be one.
        params = {k: v for k, v in params.items() if not k.startswith("_")}

        token = self._cookie(SESSION_COOKIE)
        session = self.service.sessions.get(token) if token else None
        params["_client"] = self.client_address[0]
        params["_agent"] = self.headers.get("User-Agent", "")
        authenticated = False
        if session:
            params["_token"] = token
            params["_username"] = session["username"]
            authenticated = True
            # A write is something a person chose to do — add a target, change
            # a setting, send a test packet — as opposed to the state poll
            # every open tab makes on its own every couple of seconds. Only
            # the former counts as presence for the idle timeout; otherwise a
            # tab left open in the background would never time out.
            # /api/heartbeat decides for itself: a kiosk heartbeat from an
            # account that can write is refused WITHOUT extending the
            # session (api.post_heartbeat), which this blanket touch would
            # have made impossible.
            if method in ("POST", "PUT", "DELETE") and path != "/api/heartbeat":
                self.service.sessions.touch(token)
        else:
            # No cookie session: an API token (Tier 1 #10) may still
            # authenticate this request, checked against `Authorization`
            # rather than `Cookie`. Deliberately never sets params["_token"]
            # — that key is the SessionStore's, and a token has no entry
            # there to touch, get or extend. That single omission is what
            # makes "no idle timeout for a token" and "a token cannot mint
            # a browser session" true without any further special-casing
            # below: sessions.touch("") and sessions.get("") are both
            # no-ops (see auth.SessionStore), and no Set-Cookie is ever
            # produced from anywhere but the login route's own response
            # handling further down.
            match = BEARER_RE.match((self.headers.get("Authorization") or "").strip())
            if match:
                username = self.service.authenticate_api_token(
                    match.group(1), self.client_address[0])
                if username:
                    params["_username"] = username
                    authenticated = True

        if not authenticated and path not in PUBLIC_PATHS and path not in PUBLIC_API:
            if path.startswith("/api/"):
                self._json({"error": "Not signed in", "authenticated": False}, 401)
            else:
                # The query string survives the bounce so /?kiosk=1 comes
                # back as a kiosk after sign-in (login.js hands it back).
                query = urlparse(self.path).query
                self._send(302, b"", "text/plain",
                           {"Location": "/login" + ("?" + query if query else "")})
            return

        # The flag on the account, not on the session: a reset takes effect
        # for a session that is already open, and the check costs one indexed
        # lookup on a table with one row per operator. Applies to a token-
        # authenticated request exactly the same as a browser one — an
        # account that owes a password change is not fully trusted yet,
        # whichever door it came in by.
        if authenticated and path.startswith("/api/") and path not in MUST_CHANGE_API:
            row = self.service.app_db.user(params.get("_username", ""))
            if row is not None and row["must_change"]:
                self._json({"error": "password change required"}, 403)
                return

        # A cross-site form can send a POST but cannot set this content type
        # without a preflight the browser will refuse. With SameSite=Strict on
        # the cookie that is belt and braces, but both are cheap.
        if method in ("POST", "PUT", "DELETE"):
            content_type = (self.headers.get("Content-Type") or "").split(";")[0]
            if content_type.strip() != "application/json":
                self._json({"error": "Requests must be application/json"}, 415)
                return
            if not self._same_origin():
                self._json({"error": "Cross-origin request refused"}, 403)
                return

        for route_method, pattern, handler, requirement in COMPILED:
            if route_method != method:
                continue
            match = pattern.match(path)
            if not match:
                continue
            try:
                body = (self._body(self._body_limit(path))
                        if method in ("POST", "PUT", "DELETE") else {})
                need = requirement(params, body) if callable(requirement) else requirement
                if need is not None:
                    module, level = need
                    granted = self.service.app_db.permissions_for(
                        params.get("_username", "")).get(module)
                    if not permissions.allows(granted, level):
                        self._json({"error": f"No {level} access to {module}"}, 403)
                        return
                # Every route but one captures a row id; the MIB catalog
                # captures a bundle key, which is a name. Digits still
                # arrive as ints so no handler signature changes.
                args = [int(group) if group.isdigit() else group
                        for group in match.groups()]

                # A hijacking handler (the terminal's WebSocket) takes the
                # connection over and holds it for the life of the session.
                # The upgrade is answered here, not in the handler, so that
                # everything a refusal depends on stays on this side of the
                # 101: the handler is handed a socket that is already
                # established. It runs after exactly the same
                # cookie/session/permission tail as every other route, which
                # is the whole reason it is a route rather than a special
                # case earlier in the dispatch. There is no keep-alive to
                # unwind afterwards (HTTP/1.0), so the connection simply
                # closes.
                if getattr(handler, "hijack", False):
                    self.close_connection = True
                    # Origin, checked here rather than in wsock: this is the
                    # CSRF gate for a route that has none of the usual ones.
                    # An upgrade is a GET, so the JSON content-type check
                    # above never sees it, and the session cookie is
                    # SameSite=*Strict* — which is site-scoped, not
                    # origin-scoped, so another port on this host or a
                    # sibling subdomain is "same site" and its page could
                    # otherwise open this socket with the operator's cookie
                    # and drive a shell. A browser always sends Origin on an
                    # upgrade, so a missing one is refused too (hence
                    # require_origin); it is a check about who is asking,
                    # which is this layer's business, not the framing's.
                    # Same helper as the POST/PUT/DELETE rule above, so the
                    # two cannot drift — and it compares the scheme as well
                    # as the netloc, which this check used not to.
                    if not self._same_origin(require_origin=True):
                        self._json({"error": "Cross-origin WebSocket refused"}, 403)
                        return
                    try:
                        websocket = wsock.accept(self)
                    except wsock.WebSocketError as exc:
                        # Refused before anything was written, so this is
                        # still an ordinary HTTP response.
                        self._send(400, str(exc).encode("utf-8"),
                                   "text/plain; charset=utf-8")
                        return
                    # Only now: a refused upgrade is not a 101 in the log.
                    self._status = 101
                    try:
                        handler(websocket, self.service, params, *args)
                    except Exception:
                        traceback.print_exc()
                    return

                result = handler(self.service, params, body, *args)

                headers = None
                if path == "/api/login":
                    headers = self._set_session_cookie(result.pop("token"))
                elif path == "/api/logout":
                    headers = self._set_session_cookie("", clear=True)
                self._json(result, extra_headers=headers)
            except LengthRequired as exc:
                self._json({"error": str(exc)}, 411)
            except auth.LockedOut as exc:
                # Before the ValueError arm below: LockedOut is an AuthError,
                # not a ValueError, but keeping it here says plainly that
                # "stop" and "wrong password" are different answers.
                self._json({"error": str(exc)}, 429)
            except permissions.Forbidden as exc:
                # Before the PermissionError arm below, which this subclasses:
                # "you may not do that" leaves the session alone, where 401
                # tells the browser to go to the sign-in page and loses the
                # refusal on the way.
                self._json({"error": str(exc)}, 403)
            except PermissionError as exc:
                self._json({"error": str(exc)}, 401)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
            except Exception as exc:
                traceback.print_exc()
                self._json({"error": "Internal Server Error"}, 500)
            return

        if path.startswith("/api/"):
            self._json({"error": "No such endpoint"}, 404)
            return
        self._static(path)

    def _static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        if path == "/login":
            path = "/login.html"
        # Resolve inside the static directory and refuse anything that
        # escapes. commonpath rather than startswith: the directory name is
        # a prefix of its own siblings' names ("static_notes"), and a prefix
        # test would have let one of those through.
        candidate = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        try:
            inside = os.path.commonpath([STATIC_DIR, candidate]) == STATIC_DIR
        except ValueError:
            inside = False
        entry = STATIC_CACHE.get(candidate) if inside and os.path.isfile(candidate) else None
        if entry is None:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return

        # An update replaces the files underneath a browser that already has
        # the old ones. The shell is never cached so a reload always picks up
        # new script tags, and the scripts carry a validator so the browser
        # can tell stale from current instead of guessing. `no-cache` (not
        # `immutable`): the URLs are fixed names, so the browser must ask;
        # what changed is that asking is now answered from memory with a
        # content hash, and the answer carries the same headers as a 200.
        if candidate.endswith(".html"):
            cache = {"Cache-Control": "no-store"}
        else:
            cache = {"Cache-Control": "no-cache", "ETag": entry["etag"]}
            if self._etag_matches(entry["etag"]):
                self._send(304, b"", entry["content_type"], cache)
                return
        self._send(200, entry["body"], entry["content_type"], cache,
                   gzipped=entry["gzip"])

    def _etag_matches(self, etag: str) -> bool:
        """If-None-Match, read as the header it is: a list, possibly weak-
        prefixed, possibly `*` — not a single string compared whole."""
        header = self.headers.get("If-None-Match")
        if not header:
            return False
        for candidate in header.split(","):
            candidate = candidate.strip()
            if candidate == "*":
                return True
            if candidate.startswith("W/"):
                candidate = candidate[2:]
            if candidate == etag:
                return True
        return False


class WebServer:
    def __init__(self, service: Service, host: str = "0.0.0.0", port: int = 8443,
                 certfile: str | None = None, keyfile: str | None = None):
        self.service = service
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.access = AccessLog()
        self.error: str | None = None

    @property
    def scheme(self) -> str:
        return "https" if self.certfile else "http"

    @property
    def url(self) -> str:
        shown = "localhost" if self.host in ("0.0.0.0", "") else self.host
        return f"{self.scheme}://{shown}:{self.port}/"

    @property
    def running(self) -> bool:
        return self.httpd is not None

    def start(self, block: bool = True) -> bool:
        """Bring the listener up. Returns False and sets `error` if it cannot."""
        self.error = None
        # Read once per listener, so restart() (a port or certificate change,
        # in-process) serves whatever is on disk now.
        STATIC_CACHE.load()
        handler = type("BoundHandler", (Handler,),
                       {"service": self.service, "access": self.access})
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
            self.httpd.daemon_threads = True

            self.httpd.is_tls = bool(self.certfile)
            if self.certfile:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.certfile, self.keyfile or self.certfile)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.httpd.socket = context.wrap_socket(self.httpd.socket,
                                                        server_side=True)
        except (OSError, ssl.SSLError) as exc:
            hint = ""
            if getattr(exc, "errno", None) in (48, 98, 10048):
                hint = " — another process already holds this port"
            elif getattr(exc, "errno", None) in (13, 1):
                hint = " — ports below 1024 need administrator rights"
            self.error = f"Could not bind {self.host}:{self.port}: {exc}{hint}"
            self.httpd = None
            return False

        self.access.started_at = time.time()
        if block:
            self.httpd.serve_forever()
        else:
            self._thread = threading.Thread(target=self.httpd.serve_forever,
                                            name="sappiwhere-web", daemon=True)
            self._thread.start()
        return True

    def restart(self, host: str | None = None, port: int | None = None,
                certfile: str | None = None, keyfile: str | None = None) -> bool:
        self.stop()
        if host is not None:
            self.host = host
        if port is not None:
            self.port = int(port)
        if certfile is not None:
            self.certfile = certfile or None
        if keyfile is not None:
            self.keyfile = keyfile or None
        return self.start(block=False)

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

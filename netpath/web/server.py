"""The web server.

Standard library only: `http.server` with a threading mixin, plus `ssl` when a
certificate is configured. That keeps the deployment to "install PySide6 or
don't" rather than pulling a web framework and its dependency tree onto a
machine whose job is watching the network.

There is no authentication yet. Bind to an interface you trust, or to
127.0.0.1 and reach it through something that does authenticate, until the
TACACS work lands.
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from collections import deque

from . import api
from . import wsock
from .. import permissions
from .service import Service

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

R, W = permissions.READ, permissions.WRITE


def _password_requirement(params, body):
    """Changing your own password is always allowed (per-route None); only
    resetting a *different* account's needs the same Settings-write gate
    user management itself sits behind — mirrors post_password's own
    `resetting = target.lower() != me.lower()` check, since the route
    table can't see into the request body on its own."""
    me = params.get("_username", "")
    target = str(body.get("username", "") or me)
    return ("settings", W) if target.lower() != me.lower() else None


def _settings_requirement(params, body):
    """post_settings is one generic dispatcher for every module's own
    settings (body['scope']); the module that gates it is whichever one
    the scope names, not a fixed tag — 'global' (or anything unrecognized)
    falls to the Settings module itself."""
    scope = str(body.get("scope", "global"))
    module = scope if scope in permissions.MODULES else "settings"
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
    ("GET", r"^/api/users$", api.get_users, ("settings", W)),
    ("POST", r"^/api/users$", api.post_user, ("settings", W)),
    ("DELETE", r"^/api/users$", api.delete_user, ("settings", W)),
    ("POST", r"^/api/users/permissions$", api.post_user_permissions, ("settings", W)),
    ("POST", r"^/api/password$", api.post_password, _password_requirement),
    ("GET", r"^/api/state$", api.get_state, None),
    ("GET", r"^/api/netpath/targets$", api.get_targets, ("netpath", R)),
    ("POST", r"^/api/netpath/targets$", api.post_target, ("netpath", W)),
    ("PUT", r"^/api/netpath/targets/(\d+)$", api.put_target, ("netpath", W)),
    ("DELETE", r"^/api/netpath/targets/(\d+)$", api.delete_target, ("netpath", W)),
    ("POST", r"^/api/netpath/targets/(\d+)/trace$", api.trace_now, ("netpath", W)),
    ("GET", r"^/api/netpath/timeline$", api.get_timeline, ("netpath", R)),
    ("GET", r"^/api/netpath/topology$", api.get_topology, ("netpath", R)),
    ("GET", r"^/api/netflow/overview$", api.get_flow_overview, ("netflow", R)),
    ("GET", r"^/api/netflow/records$", api.get_flow_records, ("netflow", R)),
    ("POST", r"^/api/netflow/collector$", api.post_collector, ("netflow", W)),
    ("POST", r"^/api/netflow/testpacket$", api.post_test_packet, ("netflow", W)),
    ("GET", r"^/api/snmp/overview$", api.get_snmp_overview, ("snmp", R)),
    ("GET", r"^/api/snmp/traps$", api.get_snmp_traps, ("snmp", R)),
    ("POST", r"^/api/snmp/collector$", api.post_snmp_collector, ("snmp", W)),
    ("POST", r"^/api/snmp/test$", api.post_snmp_test, ("snmp", W)),
    ("GET", r"^/api/syslog/overview$", api.get_syslog_overview, ("syslog", R)),
    ("GET", r"^/api/syslog/search$", api.get_syslog_search, ("syslog", R)),
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
    ("GET", r"^/api/ipam/dhcp/scope-history$", api.get_ipam_dhcp_scope_history, ("ipam", R)),
    ("GET", r"^/api/nodes/overview$", api.get_nodes_overview, ("nodes", R)),
    ("GET", r"^/api/nodes/mac-search$", api.get_nodes_mac_search, ("nodes", R)),
    ("GET", r"^/api/nodes/devices$", api.get_nodes_devices, ("nodes", R)),
    ("POST", r"^/api/nodes/devices$", api.post_nodes_device, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-update$", api.post_nodes_devices_bulk_update, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-delete$", api.post_nodes_devices_bulk_delete, ("nodes", W)),
    ("GET", r"^/api/nodes/devices/(\d+)$", api.get_nodes_device, ("nodes", R)),
    ("PUT", r"^/api/nodes/devices/(\d+)$", api.put_nodes_device, ("nodes", W)),
    ("DELETE", r"^/api/nodes/devices/(\d+)$", api.delete_nodes_device, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-poll$", api.post_nodes_devices_bulk_poll, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/bulk-identify$", api.post_nodes_devices_bulk_identify, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/(\d+)/poll$", api.post_nodes_device_poll, ("nodes", W)),
    ("POST", r"^/api/nodes/devices/(\d+)/focus$", api.post_nodes_device_focus, ("nodes", R)),
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
    ("GET", r"^/api/alerts/mutes$", api.get_alerts_mutes, ("alerts", R)),
    ("POST", r"^/api/alerts/mute$", api.post_alerts_mute, ("alerts", W)),
    ("DELETE", r"^/api/alerts/mute$", api.delete_alerts_mute, ("alerts", W)),
    ("GET", r"^/api/alerts/(\d+)$", api.get_alert, ("alerts", R)),
    ("POST", r"^/api/alerts/(\d+)/ack$", api.post_alert_ack, ("alerts", W)),
    ("POST", r"^/api/alerts/(\d+)/resolve$", api.post_alert_resolve, ("alerts", W)),
    ("POST", r"^/api/alerts/ack-all$", api.post_alerts_ack_all, ("alerts", W)),
    ("POST", r"^/api/alerts/bulk-ack$", api.post_alerts_bulk_ack, ("alerts", W)),
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
    ("POST", r"^/api/wireless/aps/(\d+)/service$", api.post_wireless_ap_service, ("wireless", W)),
    ("DELETE", r"^/api/wireless/aps/(\d+)$", api.delete_wireless_ap, ("wireless", W)),
    ("POST", r"^/api/wireless/collector$", api.post_wireless_collector, ("wireless", W)),
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
    ("GET", r"^/api/configrx/backups/(\d+)$", api.get_configrx_backup, ("configrx", R)),
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
    ("GET", r"^/api/debug$", api.get_debug, ("debug", R)),
    ("POST", r"^/api/debug/clear$", api.post_debug_clear, ("debug", W)),
    ("POST", r"^/api/settings$", api.post_settings, _settings_requirement),
    ("POST", r"^/api/maintenance$", api.post_maintenance, ("settings", W)),
    ("POST", r"^/api/update$", api.post_update, ("settings", W)),
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
]

COMPILED = [(method, re.compile(pattern), handler, requirement)
            for method, pattern, handler, requirement in ROUTES]

# Reachable without a session: the sign-in page and what it needs to render.
PUBLIC_PATHS = {"/login", "/login.html", "/login.js", "/app.css", "/favicon.ico"}
PUBLIC_API = {"/api/login", "/api/session"}

SESSION_COOKIE = "sw_session"


class AccessLog:
    """Recent requests and per-client totals, for the service console.

    Bounded: this is a live view, not an audit trail. Static files are counted
    but kept out of the recent list, which would otherwise be nothing but the
    five scripts every page load fetches.
    """

    def __init__(self, capacity: int = 400):
        self._lock = threading.Lock()
        self.recent: deque = deque(maxlen=capacity)
        self.clients: dict[str, dict] = {}
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
    service: Service = None      # set on the server instance
    access: AccessLog = None

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt, *args):
        return  # the event log is the log; stderr noise helps nobody

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

    def _send(self, code: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self._status = code
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # No external resources are loaded, so this can be strict.
        # `connect-src 'self'` is what the terminal window's WebSocket needs
        # and all it needs: current browsers count a same-origin ws:// (or
        # wss://) URL as 'self', while the bare scheme-sources `ws: wss:`
        # this used to carry matched *any* host, which would let every page
        # in the product open a socket anywhere. `frame-ancestors 'none'`
        # keeps the terminal — Trust button and all — out of anyone's
        # iframe. Inline styles stay allowed for the terminal emulator,
        # which injects its own <style>.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline';"
                         " connect-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        headers = {"Cache-Control": "no-store"}
        headers.update(extra_headers or {})
        self._send(code, body, "application/json; charset=utf-8", headers)

    # Every request body this app takes is JSON, and the largest legitimate
    # one by far is a base64-encoded MIB zip (max_mib_bundle_bytes, 64 MB by
    # default, ~85 MB once encoded). Anything past this is refused before a
    # byte is read, rather than being pulled into memory first — otherwise a
    # single mistyped Content-Length is an out-of-memory kill.
    MAX_BODY_BYTES = 128 * 1024 * 1024

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        if length > self.MAX_BODY_BYTES:
            raise ValueError(
                f"Request body of {length:,} bytes exceeds the "
                f"{self.MAX_BODY_BYTES:,} byte limit")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

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
        if session:
            params["_token"] = token
            params["_username"] = session["username"]
            # A write is something a person chose to do — add a target, change
            # a setting, send a test packet — as opposed to the state poll
            # every open tab makes on its own every couple of seconds. Only
            # the former counts as presence for the idle timeout; otherwise a
            # tab left open in the background would never time out.
            if method in ("POST", "PUT", "DELETE"):
                self.service.sessions.touch(token)

        if not session and path not in PUBLIC_PATHS and path not in PUBLIC_API:
            if path.startswith("/api/"):
                self._json({"error": "Not signed in", "authenticated": False}, 401)
            else:
                self._send(302, b"", "text/plain", {"Location": "/login"})
            return

        # A cross-site form can send a POST but cannot set this content type
        # without a preflight the browser will refuse. With SameSite=Strict on
        # the cookie that is belt and braces, but both are cheap.
        if method in ("POST", "PUT", "DELETE"):
            content_type = (self.headers.get("Content-Type") or "").split(";")[0]
            if content_type.strip() != "application/json":
                self._json({"error": "Requests must be application/json"}, 415)
                return

        for route_method, pattern, handler, requirement in COMPILED:
            if route_method != method:
                continue
            match = pattern.match(path)
            if not match:
                continue
            try:
                body = self._body() if method in ("POST", "PUT", "DELETE") else {}
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
                    # upgrade, so a missing one is refused too; it is a check
                    # about who is asking, which is this layer's business,
                    # not the framing's.
                    origin = (self.headers.get("Origin") or "").strip()
                    host = (self.headers.get("Host") or "").strip().lower()
                    if not origin or urlparse(origin).netloc.lower() != host:
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
        # Resolve inside the static directory and refuse anything that escapes.
        candidate = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        if not candidate.startswith(STATIC_DIR) or not os.path.isfile(candidate):
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        content_type, _ = mimetypes.guess_type(candidate)
        stat = os.stat(candidate)
        etag = f'"{int(stat.st_mtime)}-{stat.st_size}"'

        # An update replaces the files underneath a browser that already has
        # the old ones. The shell is never cached so a reload always picks up
        # new script tags, and the scripts carry a validator so the browser can
        # tell stale from current instead of guessing.
        if candidate.endswith(".html"):
            cache = {"Cache-Control": "no-store"}
        else:
            cache = {"Cache-Control": "no-cache", "ETag": etag}
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self._status = 304
                return

        with open(candidate, "rb") as handle:
            body = handle.read()
        self._send(200, body, content_type or "application/octet-stream", cache)


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

"""The application without a user interface.

The databases, the trace scheduler, the reverse-DNS resolver, the collectors,
the pollers and the event log all live here. The web server is a front end
over this.
"""

from __future__ import annotations

import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ..alertengine import AlertEngine
from ..alertsdb import AlertsDatabase
from ..auth import (DEFAULT_PASSWORD, DEFAULT_USER, LoginThrottle,
                    SessionStore, hash_password)
from ..appdb import AppDatabase, migrate_from
from ..collector import Collector
from ..configrx import ConfigRxWorker
from ..configrxdb import ConfigRxDatabase
from ..db import Database, FORCED_PRUNE_BUDGET_S, TRIM_BUDGET_S
from ..eventlog import ERROR, NODES, SYSTEM, EventLog
from ..flowdb import ROLLUP_TIERS, FlowDatabase
from ..fortipoll import WirelessPoller
from .. import ipam_scan
from ..ipamdb import IpamDatabase
from ..ipam_worker import IpamWorker
from ..mapperdb import MapperDatabase
from ..mibparse import known_oids_for, load_into, resolve_all
from ..monitor import AsnResolver, HopProber, Monitor, Resolver
from ..nodepoll import NodePoller
from .. import permissions
from ..nodesdb import NodesDatabase
from ..services import format_bytes
from ..snmptrapd import TrapCollector
from ..snmptrapdb import SnmpTrapDatabase
from ..sshterm import SshSessionRegistry
from ..syslogd import SyslogCollector
from ..syslogdb import SyslogDatabase
from ..webrelay import WebRelayRegistry
from ..wirelessdb import WirelessDatabase

MAINTENANCE_INTERVAL_S = 900

# When a capped database is close enough to its cap to be worth an alert,
# and when that stops being true. Trimming keeps a busy store just under its
# cap for ever, so the clear band sits below the raise band: without it the
# alert would open and close on alternate sweeps for a store doing exactly
# what the cap tells it to.
DB_CAP_WARN_SHARE = 0.85
DB_CAP_HIGH_SHARE = 0.95
DB_CAP_CLEAR_SHARE = 0.80

# How far free space has to recover above disk_free_warn_pct before the
# volume alert clears. A WAL grows between prunes and shrinks after them, so
# a volume sitting on the threshold would flap the alert every sweep.
DISK_FREE_CLEAR_MARGIN_PCT = 2.0


@dataclass(frozen=True)
class Store:
    """One database this application opens.

    `name` is the prefix its keys carry in /api/state's storage block and
    the entity_id its size alert uses, so each file gets an alert of its
    own. `attr` is where it hangs off the Service. `cap_key` is the
    max_*_db_mb setting that trims it, or None for a store that is
    deliberately uncapped.
    """

    name: str
    label: str
    attr: str
    cap_key: str | None


# Every database, in the order the Settings page lists them. One table
# because there were two hand-written ones — the storage block's and the
# Dashboard headroom tile's — and mapper.db was added to one and missed in
# the other, so two views of the same question disagreed about how many
# databases exist. The maintenance sweep's size alerts read it too, so all
# three can only be wrong together.
STORES = (
    Store("app", "Application", "app_db", None),
    Store("trace", "NetPath", "db", "max_trace_db_mb"),
    Store("flow", "NetFlow", "flow_db", "max_flow_db_mb"),
    Store("snmp", "Traps", "snmp_db", "max_snmp_db_mb"),
    Store("syslog", "Syslog", "syslog_db", "max_syslog_db_mb"),
    Store("ipam", "IPAM", "ipam_db", "max_ipam_db_mb"),
    Store("nodes", "Nodes", "nodes_db", "max_nodes_db_mb"),
    Store("nodes_series", "Nodes metrics", "nodes_db.series_db",
          "max_nodes_series_db_mb"),
    Store("nodes_mibs", "Nodes MIBs", "nodes_db.mib_db", None),
    Store("alerts", "Alerts", "alerts_db", "max_alerts_db_mb"),
    Store("wireless", "Wireless", "wireless_db", None),
    Store("configrx", "ConfigRX", "configrx_db", None),
    Store("mapper", "Mapper", "mapper_db", None),
)


def db_for(service, store: Store):
    """The database object `store` names, or None where this service has not
    opened it — a partially built service still answers rather than raising,
    the same way the Dashboard's collector list treats a worker that is not
    there."""
    obj = service
    for part in store.attr.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def disk_space(service) -> tuple[int, int]:
    """Free and total bytes on the volume the data files sit on, (0, 0) when
    that cannot be read.

    Asked of the application file's own directory: every store is opened
    beside it in every shipped layout, and a cap only ever governs one file
    — nothing else in the product notices the disk under them filling up.
    """
    db = db_for(service, STORES[0])
    if db is None:
        return 0, 0
    try:
        usage = shutil.disk_usage(Path(db.path).parent)
    except OSError:
        return 0, 0
    return usage.free, usage.total


# The flow rollups get their own timer rather than riding the maintenance
# sweep: at a quarter-hour cadence the unsummarised tail of raw flows would be
# a quarter of an hour of them, which at a busy exporter's volume is the very
# scan the rollups exist to avoid. With this and flowdb's seal lag the tail is
# about three minutes wherever a pass can build every bucket that has sealed
# since the last one. Where it cannot, the watermark still advances as far as
# the pass got, so the tail is bounded by how fast the store can summarise
# rather than growing by a bucket a minute for ever.
ROLLUP_INTERVAL_S = 60

# What each tier is called where an operator reads about it.
ROLLUP_TIER_NAMES = {60: "minute", 3600: "hourly"}


def _restart(worker, settings, enabled_default) -> None:
    """Stop a collector/worker and start it again only if its settings say
    it is enabled. `enabled_default` is what an absent "enabled" key means
    for this scope — the three event collectors treat it as off, the
    pollers as on."""
    worker.stop()
    if settings.get("enabled", enabled_default):
        worker.start(settings)


def _apply_netflow(service, settings) -> None:
    # Interface and port name tables are rebuilt before the collector comes
    # back up, so the first flow it decodes already resolves against them.
    service._apply_interface_names()
    service._apply_port_names()
    _restart(service.collector, settings, None)


def _apply_syslog(service, settings) -> None:
    _restart(service.syslog, settings, None)


def _apply_snmp(service, settings) -> None:
    _restart(service.snmp, settings, None)


def _apply_wireless(service, settings) -> None:
    _restart(service.wireless, settings, True)


def _apply_configrx(service, settings) -> None:
    _restart(service.configrx, settings, True)


def _apply_ipam(service, settings) -> None:
    # Started or stopped by `enabled`, never bounced: the DHCP poller reads
    # its own settings each cycle, so a live one needs no restart.
    if settings.get("enabled", True):
        service.ipam.start()
    else:
        service.ipam.stop()


def _apply_nodes(service, settings) -> None:
    service.node_poller.reconfigure(settings)


def _apply_alerts(service, settings) -> None:
    service.alert_engine.reconfigure(settings)


def _apply_mapper(service, settings) -> None:
    """No-op: MAPPER has no background worker to restart or reconfigure —
    it reads nodesdb live on every request instead of polling anything of
    its own (see mapperdb's module docstring). The settings save this is
    called from is itself the whole effect; this function exists only so
    `apply_settings` below has the same four-tuple shape for every scope,
    rather than `post_settings` needing a special case that skips calling
    an apply function for exactly one module."""


# scope -> (settings attribute, database attribute, event-log line, effect).
# `netpath` and `global` are not here: both write self.settings rather than
# a module's own dict and have their own methods.
_MODULE_SCOPES = {
    "netflow": ("flow_settings", "flow_db", "NetFlow settings applied", _apply_netflow),
    "syslog": ("syslog_settings", "syslog_db", "Syslog settings applied", _apply_syslog),
    "snmp": ("snmp_settings", "snmp_db", "SNMP trap settings applied", _apply_snmp),
    "wireless": ("wireless_settings", "wireless_db", "Wireless settings applied",
                 _apply_wireless),
    "configrx": ("configrx_settings", "configrx_db", "ConfigRX settings applied",
                 _apply_configrx),
    "ipam": ("ipam_settings", "ipam_db", "IPAM settings applied", _apply_ipam),
    "nodes": ("nodes_settings", "nodes_db", "Nodes settings applied", _apply_nodes),
    "alerts": ("alerts_settings", "alerts_db", "Alerts settings applied", _apply_alerts),
    # Settings-only module: this same generic merge/save/apply_fn/log/
    # bump_config path (see apply_settings below) already supports one —
    # the shape does not assume every scope restarts a worker, only that
    # apply_fn does *something* with the merged settings, and "nothing" is
    # a valid something. That is what keeps post_settings from needing a
    # bespoke branch for mapper: it dispatches through this table exactly
    # like every module with a worker does.
    "mapper": ("mapper_settings", "mapper_db", "Mapper settings applied", _apply_mapper),
}

# The scopes whose effect is run off the request thread, by the serial
# executor Service owns. Exactly the five that bounce a worker: every one of
# them ends in _restart(), whose stop() joins each of the worker's threads for
# up to two seconds, and syslogd.stop() joins every connected TCP client on
# top of that. A syslog save with a couple of devices holding TCP sessions
# open therefore held the HTTP response open for more than four seconds while
# the browser sat on a spinner, for work the operator had already been told
# was saved.
#
# The other four are deliberately not here, because none of them joins
# anything: nodes hot-swaps the poller's pool (nodepoll.reconfigure), alerts
# only start/stops, ipam start/stops a worker that re-reads its own settings
# each cycle, and mapper has no worker at all. Running those inline keeps
# them synchronous with the response — /api/state and the IPAM start/stop
# control read them back immediately — and costs nothing.
_DEFERRED_SCOPES = frozenset({"netflow", "syslog", "snmp", "wireless", "configrx"})

# How long shutdown() waits for a queued restart to finish before closing the
# databases underneath it. A restart is bounded by its joins — a couple of
# seconds per worker thread, plus one per connected syslog TCP client, of
# which there can be up to max_tcp_clients — so this is generous rather than
# tight: the point is that the wait ends at all if a worker thread wedges.
RESTART_DRAIN_TIMEOUT_S = 30.0


class LdapUnavailable(Exception):
    """The directory could not be used at all — unreachable, timed out, or
    misconfigured (an unset or malformed ldap_url/bind_dn_template) —
    which is a fact about the service, not about the credential typed in.
    api.post_login answers this with a distinct message and logs it apart
    from a plain wrong-password refusal, and never lets it become an
    unhandled 500 (see the `except Exception` arm server._route already
    has for that; this is caught explicitly instead, before it gets there).
    """


class Service:
    def __init__(self, db_path: str, flow_db_path: str, syslog_db_path: str,
                 app_db_path: str, ipam_db_path: str, snmp_db_path: str,
                 nodes_db_path: str, alerts_db_path: str,
                 wireless_db_path: str, configrx_db_path: str):
        self.log = EventLog()
        self.app_db = AppDatabase(app_db_path)
        # Before the trace database is opened for normal use: on an install
        # that predates app.db this lifts the settings, accounts and name cache
        # out of netpath.db and then drops them from it.
        migrate_from(self.app_db, db_path, log=self.log)
        # Only now are the accounts final: what an upgrade owes them (write on
        # every module for an install that predates the permission table, and
        # `ssh` for the accounts that already hold write on everything else)
        # is granted here rather than in AppDatabase.__init__, which runs
        # before the migration above.
        self.app_db.backfill_permissions()

        self.db = Database(db_path)
        self.flow_db = FlowDatabase(flow_db_path)
        self.syslog_db = SyslogDatabase(syslog_db_path, log=self.log)
        self.ipam_db = IpamDatabase(ipam_db_path)
        self.snmp_db = SnmpTrapDatabase(snmp_db_path)
        self.nodes_db = NodesDatabase(nodes_db_path)
        self.alerts_db = AlertsDatabase(alerts_db_path)
        self.wireless_db = WirelessDatabase(wireless_db_path)
        self.configrx_db = ConfigRxDatabase(configrx_db_path)
        # No mapper_db_path constructor parameter: Service.__init__ is called
        # positionally by every test in tests/, by demo/ and by __main__.py's
        # own path-resolution helpers (flow_path_for and friends), all sized
        # to the ten arguments above. Adding an eleventh would break every one
        # of those call sites for a store that needs no CLI override of its
        # own (mapper.db holds only manually-placed map bookkeeping, nothing
        # an operator would ever want on a different disk or volume than the
        # rest). So its path is derived instead, the same directory
        # configrx_db_path already resolved to.
        self.mapper_db = MapperDatabase(
            str(Path(configrx_db_path).parent / "mapper.db"))
        # Global keys and NetPath keys, merged for reading. Each store filters
        # this dict down to what it owns when it is written back.
        self.settings = {**self.app_db.settings(), **self.db.settings()}
        self.flow_settings = self.flow_db.settings()
        self.syslog_settings = self.syslog_db.settings()
        self.ipam_settings = self.ipam_db.settings()
        self.snmp_settings = self.snmp_db.settings()
        self.nodes_settings = self.nodes_db.settings()
        # The one in-flight MIB catalog install, if any. The lock makes
        # "is one already running?" and "claim it" one step — the web server
        # is threaded, so two clicks land on two threads.
        self._mib_job = None
        self._mib_lock = threading.Lock()
        self.alerts_settings = self.alerts_db.settings()
        self.wireless_settings = self.wireless_db.settings()
        self.configrx_settings = self.configrx_db.settings()
        self.mapper_settings = self.mapper_db.settings()

        # Where a settings save's worker restart actually runs (see
        # _DEFERRED_SCOPES and apply_settings). One thread, so restarts stay
        # in the order they were asked for and two saves can never overlap
        # one worker's stop and start — that pair is not re-entrant, and a
        # second stop() landing between the first one's stop and its start
        # would leave the collector down with its stored settings claiming
        # it is up. The thread is created on the first save, not here: an
        # install nobody opens Settings on never grows one.
        self._restart_pool = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="settings-restart")
        # Counts what is queued *and* what is running, so await_restarts can
        # tell "the queue is empty" from "the queue is empty because the one
        # restart is still inside worker.stop()".
        self._restarts_idle = threading.Condition()
        self._restarts_pending = 0
        self._restarts_closed = False

        self.hop_prober = HopProber(self.db, log=self.log)
        self.monitor = Monitor(
            self.db,
            workers=int(self.settings["trace_workers"]),
            log=self.log,
            on_complete=self._on_trace_complete,
        )
        self.resolver = Resolver(
            self.db,
            self.app_db,
            workers=int(self.settings["dns_workers"]),
            timeout_s=float(self.settings["dns_timeout_s"]),
            cache_ttl_s=float(self.settings["dns_cache_days"]) * 86400,
            log=self.log,
            extra_ips=self._extra_resolve_targets,
            server=str(self.settings.get("dns_server", "")),
            use_nslookup=bool(self.settings.get("dns_use_nslookup", True)),
            ipam_db=self.ipam_db,
        )
        self.asn_resolver = AsnResolver(
            self.db,
            self.app_db,
            timeout_s=float(self.settings.get("dns_timeout_s", 3.0)),
            cache_ttl_s=float(self.settings.get("asn_cache_days", 30)) * 86400,
            server=str(self.settings.get("asn_server", "")),
            log=self.log,
        )
        self.collector = Collector(self.flow_db, log=self.log)
        self.syslog = SyslogCollector(self.syslog_db, log=self.log)
        self.snmp = TrapCollector(self.snmp_db, log=self.log, nodes_db=self.nodes_db)
        self.ipam = IpamWorker(self.ipam_db, log=self.log,
                               global_settings=lambda: self.settings)
        self.node_poller = NodePoller(self.nodes_db, log=self.log)
        self.wireless = WirelessPoller(self.wireless_db, log=self.log)
        # Reads Nodes' device list for IP/vendor, so constructed after nodes_db.
        self.configrx = ConfigRxWorker(self.configrx_db, self.nodes_db, log=self.log)
        # Depends on nodes_db/snmp_db/syslog_db/ipam_db/wireless_db, so
        # constructed last.
        self.alert_engine = AlertEngine(
            self.alerts_db, nodes_db=self.nodes_db, snmp_db=self.snmp_db,
            syslog_db=self.syslog_db, ipam_db=self.ipam_db, app_db=self.app_db,
            wireless_db=self.wireless_db, netpath_db=self.db, log=self.log)
        # Wired after construction because the engine is built last, after
        # everything it reads from; the poller guards every use, so it runs
        # standalone (tests, scripts) with this left unset.
        self.node_poller.alert_engine = self.alert_engine

        self.sessions = SessionStore(
            idle_minutes=int(self.settings.get("session_idle_minutes", 10)),
            max_hours=int(self.settings.get("session_max_hours", 12)))
        self.throttle = LoginThrottle()
        # After sessions (a terminal belongs to a signed-in user) and after
        # configrx_db (it is where the device's SSH credential and host key
        # live). Holds no thread of its own until a session opens.
        self.ssh_sessions = SshSessionRegistry(self)
        # The WEB button's TCP relays, ordered the same way: after sessions
        # (a tunnel belongs to a signed-in user) and after nodes_db (the
        # target comes from the device row).
        self.web_relays = WebRelayRegistry(self)
        self._ensure_default_user()

        self._stop = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self._rollup_thread: threading.Thread | None = None
        self._nodes_split_thread: threading.Thread | None = None
        # The maintenance thread waits on the first between ticks, so
        # request_maintenance() wakes it at once; the second marks that
        # pass done.
        self._maintenance_request = threading.Event()
        self._maintenance_done = threading.Event()
        # Held for the body of run_maintenance: shutdown() below must not
        # close a database out from under a sweep in flight.
        self._maintenance_lock = threading.Lock()
        # One thread rebuilds rollup buckets at a time. The 60-second timer
        # and the maintenance sweep's backfill both do, and two of them
        # rebuilding the same bucket at once is how a dimension's rows came
        # to be paired with a span row built from a different set of flows.
        self._rollup_lock = threading.Lock()
        self.started_at = time.time()
        # Bumped by every write to something /api/config carries. The
        # browser refetches /api/config only when this number moves.
        # Monotonic within a process; a restart starting again from 1 is
        # fine, because the client compares for inequality, not order.
        self.config_version = 1
        # Per-poll figures that are expensive to compute and cannot usefully
        # change faster than an operator can read them: storage sizes (30
        # stat() calls) and the reverse-DNS cache fill (three queries).
        self._poll_cache: dict[str, tuple[float, object]] = {}

    def _ensure_default_user(self) -> None:
        """Create admin/admin on a fresh install, flagged to be changed.

        The account exists so there is a way in; the flag exists so the first
        thing anyone does is replace it.
        """
        if self.app_db.user_count():
            return
        self.app_db.add_user(DEFAULT_USER, hash_password(DEFAULT_PASSWORD),
                             must_change=True)
        # There is no one else yet to grant this account access, so it
        # starts with everything — the same grant an upgrading install's
        # existing accounts are backfilled to.
        self.app_db.set_permissions(
            DEFAULT_USER, {m: permissions.WRITE for m in permissions.MODULES})
        self.log.add(SYSTEM, f"Created the default {DEFAULT_USER} account. "
                             f"Change its password before this is reachable "
                             f"by anyone else.")

    # --------------------------------------------------------- authentication

    def authenticate_ldap(self, username: str, password: str) -> bool:
        """True if `username`/`password` verifies against the configured
        directory; False for a definite bad-credential answer (wrong
        password, or a referral this minimal client cannot follow — see
        ldapclient's module docstring). Raises LdapUnavailable when the
        directory itself could not be used at all (unreachable, timed out,
        or misconfigured), so the caller (api.post_login) can log and
        answer that case distinctly from "wrong password" — the two need
        very different next steps from whoever is failing to sign in, and
        conflating them is what turns a network blip into "is my password
        no longer valid?" support tickets.
        """
        from .. import ldapclient

        # Defence in depth; ldapclient.simple_bind refuses this too. A
        # non-empty DN with an empty password is a legal LDAP "unauthenticated
        # bind" (RFC 4513 §5.1.2), which many directories answer with
        # success rather than invalidCredentials, so it cannot be left to the
        # directory to reject.
        if password == "":
            return False

        try:
            dn = ldapclient.render_bind_dn(
                str(self.settings.get("ldap_bind_dn_template", "")), username)
            ldapclient.simple_bind(
                str(self.settings.get("ldap_url", "")), dn, password,
                timeout=float(self.settings.get("ldap_timeout_s", 10.0) or 10.0),
                allow_cleartext=bool(self.settings.get("ldap_allow_cleartext", False)))
            return True
        except ldapclient.LDAPInvalidCredentials:
            return False
        except ldapclient.LDAPReferralError:
            return False
        except ldapclient.LDAPBindError:
            # No such object, unwilling to perform, and the like: not a
            # credential the directory accepted, but also not a connectivity
            # problem — answered the same as a wrong password.
            return False
        except (ldapclient.LDAPConnectError, ldapclient.LDAPProtocolError,
                ldapclient.LDAPConfigError) as exc:
            raise LdapUnavailable(str(exc)) from exc

    def authenticate_api_token(self, raw_token: str, client: str = "") -> str | None:
        """The username an API token authenticates as, or None if it does
        not authenticate a request at all (unknown, or expired).

        Checked wherever the session cookie is checked (server.py's Bearer
        handling), but this is deliberately NOT a SessionStore entry: there
        is no idle timeout here and never will be — that is the entire
        point of a token an unattended script can hold — and nothing here
        touches auth.SessionStore at all.
        """
        from .. import auth

        token_hash = auth.hash_api_token(raw_token)
        row = self.app_db.api_token_by_hash(token_hash)
        if row is None:
            return None
        # Defence in depth over the indexed SQL equality match above: an
        # explicit constant-time comparison of the exact bytes matched. The
        # token's 256 bits of entropy is what actually protects it, which is
        # why the indexed lookup is fine in the first place.
        from .. import ldapclient
        if not ldapclient.constant_time_hash_eq(row["token_hash"], token_hash):
            return None
        if row["expires_ts"] is not None and time.time() > row["expires_ts"]:
            self.app_db.audit(row["username"], client, "token.expired_use",
                              target=str(row["id"]),
                              detail=f"label={row['label']}")
            return None
        self.app_db.touch_api_token(row["id"], row["last_used_ts"])
        return row["username"]

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        self.monitor.start()
        self.hop_prober.start()
        if self.settings.get("dns_enabled", True):
            self.resolver.start()
        if self.settings.get("asn_enabled", True):
            self.asn_resolver.start()
        if self.flow_settings.get("enabled", True):
            self.collector.start(self.flow_settings)
        if self.syslog_settings.get("enabled", True):
            self.syslog.start(self.syslog_settings)
        if self.snmp_settings.get("enabled", True):
            self.snmp.start(self.snmp_settings)
        self._seed_default_mibs()
        self._snmp_settings_with_mibs()
        if self.ipam_settings.get("enabled", True):
            self.ipam.start()
        if self.nodes_settings.get("enabled", True):
            self.node_poller.start(self.nodes_settings)
        if self.alerts_settings.get("enabled", True):
            self.alert_engine.start()
        if self.wireless_settings.get("enabled", True):
            self.wireless.start(self.wireless_settings)
        if self.configrx_settings.get("enabled", True):
            self.configrx.start(self.configrx_settings)

        # After the collectors are up: an index refill is background work and
        # must not delay the service being reachable.
        self.syslog_db.start_index_backfill()
        if not self.syslog_db.index_ready:
            _, total = self.syslog_db.index_progress
            self.log.add(SYSTEM, f"Rebuilding the syslog search index over "
                                 f"{total:,} stored messages so that searches "
                                 f"match anywhere in a word. Searching still "
                                 f"works meanwhile, by scanning.")

        self._apply_interface_names()
        self._apply_port_names()

        # Nodes and Wireless polling both call ipam_scan.ping_many(); with
        # no ICMP socket available (Windows, or Linux without CAP_NET_RAW or
        # a ping_group_range grant) that falls back to one `ping` subprocess
        # per probe, which turns a fleet-sized poll cycle from under a minute
        # into minutes. Said once here, since nothing else tells the operator
        # why the cycle got slow.
        ping_mode = ipam_scan.ping_mode_summary()
        if ping_mode["path"] == "socket":
            self.log.add(SYSTEM, f"ICMP ping using an unprivileged {ping_mode['kind']} "
                                 f"socket — no subprocess spawned per probe.")
        elif ping_mode["mode_env"] == "subprocess":
            self.log.add(SYSTEM, "ICMP ping: subprocess path forced by "
                                 "NETPATH_PING_MODE=subprocess.")
        elif ping_mode["error"]:
            self.log.add(SYSTEM, f"ICMP ping: {ping_mode['error']}")
        else:
            self.log.add(SYSTEM, "ICMP ping: no ICMP socket available here "
                                 "(Windows, or Linux without CAP_NET_RAW or a "
                                 "ping_group_range grant) — falling back to one "
                                 "`ping` subprocess per probe. That cost scales with "
                                 "fleet size; widening ping_interval_s on Nodes/"
                                 "Wireless polling profiles reduces how often it "
                                 "is paid.")

        self._stop.clear()
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop, name="netpath-maintenance", daemon=True)
        self._maintenance_thread.start()
        self._rollup_thread = threading.Thread(
            target=self._rollup_loop, name="netpath-flow-rollup", daemon=True)
        self._rollup_thread.start()
        self._start_nodes_split()
        self.log.add(SYSTEM, "Service started")

    def _start_nodes_split(self) -> None:
        """Phase 2 of the 5.0.0 nodes.db split, on its own thread: the
        hourly rollups can be hundreds of megabytes and nothing, least of
        all the web server, should wait on them."""
        if not self.nodes_db.split_pending():
            return
        self.log.add(SYSTEM, "Nodes: moving the metric history into "
                             "nodes_series.db in the background. Charts and "
                             "polling work throughout.")
        min_hour = time.time() - float(
            self.nodes_settings.get("rollup_retention_days", 400)) * 86400
        self._nodes_split_thread = threading.Thread(
            target=self._run_nodes_split, args=(min_hour,),
            name="netpath-nodes-split", daemon=True)
        self._nodes_split_thread.start()

    def _run_nodes_split(self, min_hour: float) -> None:
        try:
            self.nodes_db.continue_split(
                self._stop, min_hour,
                lambda text: self.log.add(SYSTEM, text))
        except Exception as exc:                              # noqa: BLE001
            self.log.add(SYSTEM, f"Nodes: the background history move failed "
                                 f"({exc}); it retries on the next start.")

    def shutdown(self) -> None:
        self._stop.set()
        # The maintenance thread waits on this, not on _stop, so it has to
        # be set too or the join below waits out the whole tick.
        self._maintenance_request.set()
        # Before the databases close: holds an ATTACH on nodes.db.
        if self._nodes_split_thread is not None:
            self._nodes_split_thread.join(timeout=10.0)
            self._nodes_split_thread = None
        # A sweep could still be running when the databases close below —
        # join the maintenance thread, then hold the lock run_maintenance
        # holds for the whole close sequence.
        if self._maintenance_thread is not None:
            self._maintenance_thread.join(timeout=10.0)
            self._maintenance_thread = None
        if self._rollup_thread is not None:
            self._rollup_thread.join(timeout=10.0)
            self._rollup_thread = None
        # Before the databases close: a deferred restart starts a collector
        # that writes to them, so one still in flight here would find its
        # store closed underneath it. Draining first means the stop/start
        # this method does below is also the last word on every worker,
        # rather than racing a queued start that would bring one back up
        # after shutdown had stopped it.
        self._drain_restarts()
        with self._maintenance_lock:
            # Interactive SSH sessions first: they are the only thing here a
            # person is watching, and each one writes a closing device event,
            # so they must end while the databases are still open.
            self.ssh_sessions.shutdown()
            # And the relays, same reason: each writes a closing device
            # event, so they must end while the databases are still open.
            self.web_relays.shutdown()
            self.monitor.shutdown()   # waits briefly for running traces to land
            self.hop_prober.shutdown()
            self.resolver.shutdown()
            self.asn_resolver.shutdown()
            self.collector.stop()
            self.syslog.stop()
            self.snmp.stop()
            self.ipam.shutdown()
            # Alerts reads Nodes' own data, so stop the reader before the writer.
            self.alert_engine.stop()
            self.node_poller.shutdown()   # waits briefly for running polls to land
            self.wireless.shutdown()      # waits briefly for a running poll to land
            self.configrx.stop()
            self.db.close()
            self.flow_db.close()
            self.syslog_db.close()
            self.snmp_db.close()
            self.ipam_db.close()
            self.nodes_db.close()
            self.alerts_db.close()
            self.wireless_db.close()
            self.configrx_db.close()
            # No worker reads or writes this one (see _apply_mapper), but
            # the connection itself still wants a clean close like every
            # other store here — otherwise a temp-dir test teardown on
            # Windows can find the file still held open.
            self.mapper_db.close()
            self.app_db.close()

    # ------------------------------------------------------------- settings

    def bump_config(self) -> None:
        """Say that something /api/config carries has changed."""
        self.config_version += 1

    def cached_poll(self, key: str, ttl_s: float, compute):
        """`compute()` at most once per `ttl_s`, shared by every open tab.

        /api/state ran ten databases' size_bytes() (three stat() calls each)
        and the hostname cache's three queries on every 2-second poll of
        every tab. Neither figure means anything at that resolution."""
        now = time.time()
        hit = self._poll_cache.get(key)
        if hit and now - hit[0] < ttl_s:
            return hit[1]
        value = compute()
        self._poll_cache[key] = (now, value)
        return value

    def apply_global_settings(self, values: dict) -> dict:
        self.settings.update(values)
        self.app_db.save_settings(self.settings)
        self.sessions.configure(
            int(self.settings.get("session_idle_minutes", 10)),
            int(self.settings.get("session_max_hours", 12)))
        self.resolver.configure(self.settings["dns_workers"],
                                self.settings["dns_timeout_s"],
                                float(self.settings["dns_cache_days"]) * 86400,
                                server=str(self.settings.get("dns_server", "")),
                                use_nslookup=bool(
                                    self.settings.get("dns_use_nslookup", True)))
        if self.settings.get("dns_enabled", True):
            self.resolver.start()
        else:
            self.resolver.stop()
        self.asn_resolver.configure(
            self.asn_resolver.workers,
            float(self.settings.get("dns_timeout_s", 3.0)),
            float(self.settings.get("asn_cache_days", 30)) * 86400,
            server=str(self.settings.get("asn_server", "")))
        if self.settings.get("asn_enabled", True):
            self.asn_resolver.start()
        else:
            self.asn_resolver.stop()
        self.log.add(SYSTEM, "Global settings applied")
        # Asked for, not run here: this is an HTTP thread, and the sweep it
        # wants is the whole 13-store prune and trim.
        self.request_maintenance()
        self.bump_config()
        return self.settings

    def apply_netpath_settings(self, values: dict) -> dict:
        # Only the keys netpath.db owns. self.settings holds the global and
        # the NetPath keys in one dict, so an unfiltered update() would let a
        # netpath:write account inject web_host, web_cert or
        # session_idle_minutes into the settings every other part of the app
        # reads.
        from ..db import APP_DEFAULTS as NETPATH_KEYS
        self.settings.update({k: v for k, v in values.items() if k in NETPATH_KEYS})
        self.db.save_settings(self.settings)
        self.monitor.set_workers(int(self.settings["trace_workers"]))
        self.log.add(SYSTEM, "NetPath settings applied")
        self.bump_config()
        return self.settings

    def apply_settings(self, scope: str, values: dict) -> dict:
        """One module's settings saved and applied: merge, persist, restart
        or reconfigure whatever the scope owns, log it, and bump /api/config.
        Returns the scope's live settings dict. KeyError for a scope that is
        not a module — `global` and `netpath` have their own methods.

        Everything the HTTP response answers for happens here, on the request
        thread: the merge, the write to the module's database, the event-log
        line and the config bump. So a 200 still means "this is stored", and
        a reader that comes back on the strength of it sees the new values.

        What does *not* happen here, for the five scopes in _DEFERRED_SCOPES,
        is the worker restart — that is handed to the serial executor and the
        response goes out immediately. The transition is not hidden from the
        operator: /api/state reports each worker's `running` flag and its
        status_text() on the poll the Settings and Dashboard pages already
        make, so the collector is seen going down and coming back with no
        frontend change at all.
        """
        settings_attr, db_attr, label, apply_fn = _MODULE_SCOPES[scope]
        settings = getattr(self, settings_attr)
        settings.update(values)
        db = getattr(self, db_attr)
        db.save_settings(settings)
        # Read the stored values back over the live dict. A store may bound
        # what it accepts (nodesdb clamps the worker counts, db.py clamps
        # trace_workers), and it clamps a copy — so without this the database
        # holds the bounded number while this dict, which is what apply_fn
        # hands the worker AND what /api/state serves the settings form,
        # keeps whatever was posted. The clamp would then protect the file
        # and nothing else.
        settings.update(db.settings())
        if scope in _DEFERRED_SCOPES:
            self._queue_restart(scope, apply_fn, settings)
        else:
            apply_fn(self, settings)
        self.log.add(SYSTEM, label)
        self.bump_config()
        return settings

    # -------------------------------------------------- deferred restarts

    def _queue_restart(self, scope: str, apply_fn, settings: dict) -> None:
        """Hand one scope's effect to the restart executor.

        `settings` is the module's live dict, not a copy, and deliberately:
        a restart that has been waiting behind another one should bring the
        worker up on what is stored now, not on what was stored when it was
        queued. Two saves in quick succession therefore converge on the
        second one's settings instead of the first restart resurrecting a
        collector the second save had just disabled.
        """
        with self._restarts_idle:
            if not self._restarts_closed:
                self._restarts_pending += 1
                # Submitted under the same lock that shutdown() sets the
                # closed flag with, so the pool cannot be shut down between
                # the check and the submit.
                self._restart_pool.submit(self._run_restart, scope, apply_fn,
                                          settings)
                return
        # Only after shutdown() has drained and closed the executor. Dropping
        # the effect would silently ignore a save, so it runs inline — what
        # this did before the executor existed. The latency that costs does
        # not matter to a service that is already going away.
        self._apply_restart(scope, apply_fn, settings)

    def _run_restart(self, scope: str, apply_fn, settings: dict) -> None:
        """The executor thread's whole job: one effect, then the bookkeeping
        await_restarts waits on. The decrement is in a finally so that a
        failure no exception guard anticipated still leaves the count honest
        rather than wedging every later await_restarts on a restart that is
        not running."""
        try:
            self._apply_restart(scope, apply_fn, settings)
        finally:
            with self._restarts_idle:
                self._restarts_pending -= 1
                if self._restarts_pending == 0:
                    self._restarts_idle.notify_all()

    def _apply_restart(self, scope: str, apply_fn, settings: dict) -> None:
        """One scope's effect with its failure caught and logged.

        A restart that raises — a port that will not bind now that another
        process holds it, a driver that throws on start — must not end the
        executor thread. There is only one, and every later settings save
        queues behind it, so losing it would mean no module's settings ever
        took effect again until the service was restarted.
        """
        try:
            apply_fn(self, settings)
        except Exception as exc:
            self.log.add(ERROR, f"{scope} settings were saved, but applying "
                                f"them failed: {exc}", target=scope,
                         detail=traceback.format_exc())

    def await_restarts(self, timeout: float = 10.0) -> bool:
        """Block until no deferred restart is queued or running.

        True when it went quiet, False when `timeout` ran out first — the
        caller decides what that means. shutdown() uses it so a restart
        cannot outlive the service; a test uses it instead of sleeping, so
        it asserts on a worker that has actually been brought back up rather
        than on whether a chosen interval was long enough.
        """
        with self._restarts_idle:
            return self._restarts_idle.wait_for(
                lambda: self._restarts_pending == 0, timeout)

    def _drain_restarts(self) -> None:
        """Stop accepting restarts and wait for the queued ones, on the way
        down. Idempotent, because shutdown() is: a second call finds the
        executor already closed and nothing pending."""
        with self._restarts_idle:
            self._restarts_closed = True
        if not self.await_restarts(RESTART_DRAIN_TIMEOUT_S):
            # Said rather than swallowed: a restart still running past this
            # point is about to meet a closed database, and the traceback
            # that produces is much harder to read than this line.
            self.log.add(ERROR, f"A settings restart was still running after "
                                f"{RESTART_DRAIN_TIMEOUT_S:.0f}s; shutting "
                                f"down without waiting for it")
        # wait=False because the drain above is the wait, with a bound on it:
        # a worker thread wedged past the timeout must not hang the shutdown
        # here too. cancel_futures is belt and braces — nothing can have been
        # queued since the flag went up, since _queue_restart sets the count
        # and submits under the same lock the flag is set under.
        self._restart_pool.shutdown(wait=False, cancel_futures=True)

    def _trim_db(self, key: str, db, label: str, noun: str, **kwargs) -> None:
        """Trim one database to its `max_*_db_mb` setting, if that setting is
        set at all — 0 means no cap, and no trim call. Extra kwargs go
        straight to trim_to_size (the trace database passes its budget)."""
        cap = int(self.settings.get(key, 0)) * 1024 * 1024
        if not cap:
            return
        removed = db.trim_to_size(cap, **kwargs)
        if removed:
            self.log.add(SYSTEM, f"{label} over its {cap // 1048576} MB cap: "
                                 f"removed {removed} {noun}")

    # -------------------------------------------------------- MIB catalog

    def mib_install_status(self) -> dict | None:
        """The most recent bundle install, or None if none has been started.

        One job at a time by design: two installs racing would interleave
        their fixpoint resolves over the same tables for no benefit, and an
        operator installing two bundles back to back is better served by the
        second one being refused with a clear reason than by both half-landing.
        """
        job = self._mib_job
        return job.json() if job else None

    def install_mib_bundle(self, key: str) -> dict:
        from .. import mibcatalog

        bundle = mibcatalog.bundle(key)
        if bundle is None:
            raise ValueError(f"No such MIB bundle: {key}")
        with self._mib_lock:
            running = self._mib_job
            if running is not None and running.state == "running":
                raise ValueError(f"An install of {running.key} is still running")
            job = mibcatalog.InstallJob(key, len(bundle.files))
            self._mib_job = job
        thread = threading.Thread(target=self._run_mib_install,
                                  args=(bundle, job), daemon=True,
                                  name=f"mib-install-{key}")
        thread.start()
        return job.json()

    def _run_mib_install(self, bundle, job) -> None:
        from .. import mibcatalog

        max_bytes = int(self.nodes_settings.get("max_mib_bytes", 8 * 1024 * 1024))
        budget = int(self.nodes_settings.get("max_mib_bundle_bytes",
                                             64 * 1024 * 1024))
        timeout = float(self.nodes_settings.get("mib_download_timeout_s", 30.0))
        existing = {row["filename"] for row in self.nodes_db.mib_files()}
        spent = 0
        try:
            for filename, url in bundle.files:
                job.current = filename
                if filename in existing:
                    # Re-installing must not double a file: the operator's
                    # own edits live on those rows, and a second copy would
                    # define every name twice in all_known_oids().
                    job.skipped.append(filename)
                    job.completed += 1
                    continue
                text = mibcatalog.fetch_file(url, timeout, max_bytes)
                spent += len(text)
                if spent > budget:
                    raise mibcatalog.DownloadError(
                        f"This bundle exceeds the {budget:,} byte total limit "
                        f"after {len(job.installed)} file(s)")
                # Resolve properly at the end; getting each file merely stored
                # first is what lets the fixpoint see the whole bundle at once.
                load_into(self.nodes_db, filename, text,
                          known_oids_for(self.nodes_db), max_bytes)
                existing.add(filename)
                job.installed.append(filename)
                job.completed += 1
            summary = resolve_all(self.nodes_db, max_bytes)
            job.resolved_count = summary["resolved_count"]
            job.object_count = summary["object_count"]
            self._snmp_settings_with_mibs()
            job.state = "done"
            job.current = ""
            self.log.add(NODES,
                         f"Installed MIB bundle {bundle.name}: "
                         f"{len(job.installed)} file(s) added, "
                         f"{len(job.skipped)} already present; "
                         f"{summary['resolved_count']}/{summary['object_count']} "
                         f"object(s) resolved overall")
        except Exception as error:               # noqa: BLE001 - shown verbatim
            job.state = "error"
            job.error = str(error) or type(error).__name__
            self.log.add(NODES,
                         f"MIB bundle {bundle.name} failed at "
                         f"{job.current or 'startup'}: {job.error}")
        finally:
            job.finished_ts = time.time()

    def _seed_default_mibs(self) -> None:
        """Load the MIB files bundled under netpath/mibs/ through the same
        parse/resolve/store path a real upload uses, so a fresh install
        starts with a browsable IF-MIB and enterprise-root arcs instead of
        an empty MIB list. Tracked by filename in the "seeded_mib_files"
        setting rather than by checking mib_files() for that name: an
        admin who deletes a bundled MIB removes its mib_files() row, so
        presence there can't tell "never seeded" from "deleted on purpose"
        — only the persistent seeded-list can, and only it must, or the
        next restart would silently bring a deleted MIB back."""
        mibs_dir = Path(__file__).resolve().parent.parent / "mibs"
        if not mibs_dir.is_dir():
            return
        already = {name for name in
                   str(self.nodes_settings.get("seeded_mib_files", "")).split(",")
                   if name}
        max_bytes = int(self.nodes_settings.get("max_mib_bytes", 8 * 1024 * 1024))
        seeded = False
        for path in sorted(mibs_dir.glob("*.mib")):
            if path.name in already:
                continue
            text = path.read_text(encoding="utf-8")
            known = known_oids_for(self.nodes_db)
            load_into(self.nodes_db, path.name, text, known, max_bytes)
            already.add(path.name)
            seeded = True
        if seeded:
            # The bundled set is a dependency graph, not a list: Q-BRIDGE-MIB
            # hangs off P-BRIDGE-MIB, ENTITY-SENSOR-MIB off ENTITY-MIB, so one
            # sweep in filename order can leave a file half-resolved.
            summary = resolve_all(self.nodes_db, max_bytes)
            self.nodes_settings["seeded_mib_files"] = ",".join(sorted(already))
            self.nodes_db.save_settings(self.nodes_settings)
            self._snmp_settings_with_mibs()
            self.log.add(SYSTEM,
                         f"Seeded bundled MIBs: {summary['resolved_count']}/"
                         f"{summary['object_count']} object(s) resolved across "
                         f"{summary['files']} file(s)")

    def _snmp_settings_with_mibs(self) -> None:
        """MIB-derived OID names apply to both what Nodes polls and what the
        SNMP Trap page displays, so a name learned from an uploaded MIB is
        merged into the trap decoder's own oid_names setting rather than
        living only in Nodes' database. Merged into the live decoder only —
        never written back into snmp_db's own stored setting — so the SNMP
        Trap module's own Settings dialog still shows and edits exactly
        what an admin typed there, and deleting a MIB in Nodes stops
        contributing names on the next call without touching anything the
        admin owns."""
        extra = self.nodes_db.oid_name_lines()
        if not extra:
            return
        merged = (self.snmp_settings.get("oid_names", "") + "\n" + extra).strip()
        self.snmp.decoder.configure({**self.snmp_settings, "oid_names": merged})

    def _apply_port_names(self) -> None:
        from ..services import parse_custom_ports, set_custom_ports
        set_custom_ports(parse_custom_ports(
            self.flow_settings.get("custom_ports", "")))

    def _apply_interface_names(self) -> None:
        mapping = {}
        for line in str(self.flow_settings.get("interface_names", "")).splitlines():
            if "=" not in line or ":" not in line:
                continue
            left, name = line.split("=", 1)
            exporter, _, index = left.rpartition(":")
            try:
                mapping[(exporter.strip(), int(index))] = name.strip()
            except ValueError:
                continue
        if mapping:
            self.flow_db.set_interface_names(mapping)

    def save_listener_settings(self, values: dict) -> None:
        """Used by the console and the command line, which set only web_* keys."""
        self.settings.update(values)
        self.app_db.save_settings(self.settings)
        self.bump_config()

    def hostname_stats(self) -> dict:
        """Cache fill from app.db, pending count from the hop table."""
        stats = self.app_db.cache_stats()
        seen = self.db.distinct_hop_ips()
        stats["pending"] = len(self.app_db.unknown_ips(seen))
        return stats

    def ipam_search(self, query: str, limit: int = 50) -> list[dict]:
        """Every host IPAM knows anything about whose IP, MAC, hostname or
        (for a lease) description contains `query` — the complement to
        browsing by subnet: "what's the IP for printer-3rd-floor" or
        "who is aa:bb:cc:dd:ee:ff" rather than "what's on 10.20.3.0/24".

        Three independent sources, since none alone is complete: hosts
        SappiWhere's own sweep discovered, DHCP-reported leases and
        reservations, and the shared reverse-DNS cache built from PTR
        lookups. A result outside every subnet configured here isn't a
        bug — DHCP polling reads a server's scopes independently of what
        subnets IPAM has been told to sweep, so a lease can exist for a
        range nothing here is watching; the `sources` entry always says
        which of the three found it.
        """
        results: dict[str, dict] = {}
        placed: set[str] = set()   # already has subnet/alive from its own sweep row

        def entry(ip: str) -> dict:
            return results.setdefault(ip, {
                "ip": ip, "hostname": None, "mac": None,
                "sources": [], "subnet": None, "alive": None,
            })

        for row in self.ipam_db.search_hosts(query, limit):
            found = entry(row["ip"])
            found["mac"] = found["mac"] or row["mac"]
            found["alive"] = bool(row["alive"])
            found["subnet"] = row["subnet_cidr"]
            found["sources"].append("discovered by SappiWhere's own sweep")
            placed.add(row["ip"])

        for row in self.ipam_db.search_dhcp(query, limit):
            found = entry(row["ip"])
            found["hostname"] = found["hostname"] or row["hostname"]
            found["mac"] = found["mac"] or row["mac"]
            kind = "DHCP reservation" if row["is_reservation"] else "DHCP lease"
            server = row["server_label"] or "DHCP server"
            found["sources"].append(f"{kind} ({server})")

        for row in self.app_db.search_hostnames(query, limit):
            found = entry(row["ip"])
            found["hostname"] = found["hostname"] or row["hostname"]
            found["sources"].append("reverse DNS")

        # Fill in subnet/alive for anything not already placed above — a
        # DHCP- or DNS-only match whose address happens to also be a
        # currently discovered host.
        missing = set(results) - placed
        if missing:
            host_rows = {row["ip"]: row for row in self.ipam_db.hosts()}
            for ip in missing:
                host = host_rows.get(ip)
                if not host:
                    continue
                found = results[ip]
                found["alive"] = bool(host["alive"])
                found["mac"] = found["mac"] or host["mac"]
                if host["subnet_id"] is not None:
                    subnet = self.ipam_db.subnet(host["subnet_id"])
                    found["subnet"] = subnet["cidr"] if subnet else None

        query_lower = query.lower()

        def sort_key(e: dict):
            name = (e["hostname"] or "").lower()
            return (not name.startswith(query_lower),
                   query_lower not in e["ip"],
                   name or e["ip"])

        return sorted(results.values(), key=sort_key)[:limit]

    def _on_trace_complete(self, target_id: int) -> None:
        """Monitor's completion hook: hand the freshly-traced hop set to the
        continuous prober, which only acts on it if that target opted in."""
        try:
            self.hop_prober.refresh_hops(target_id)
        except Exception:
            pass

    def set_hop_probe_enabled(self, target_id: int, enabled: bool) -> None:
        self.db.update_target(target_id, hop_probe_enabled=1 if enabled else 0)
        self.hop_prober.set_enabled(target_id, enabled)

    # ---------------------------------------------------------- maintenance

    def _extra_resolve_targets(self) -> list:
        """Addresses worth naming beyond NetPath's own hops, for the shared
        resolver: flow endpoints, syslog sources, and IPAM's discovered
        hosts, each gated by its own module's resolve setting."""
        addresses = []
        if self.flow_db.settings().get("resolve_addresses"):
            addresses.extend(self.flow_db.recent_endpoints())
        if self.syslog_settings.get("resolve_sources"):
            addresses.extend(row["source"] for row
                             in self.syslog_db.sources(limit=100))
        if self.snmp_settings.get("resolve_sources"):
            addresses.extend(row["source"] for row
                             in self.snmp_db.recent_sources(limit=100))
        if self.ipam_settings.get("resolve_hosts", True):
            addresses.extend(row["ip"] for row in self.ipam_db.hosts()
                             if row["alive"])
        if self.nodes_settings.get("resolve_addresses", True):
            addresses.extend(row["ip"] for row in self.nodes_db.devices())
        return addresses

    def _maintenance_loop(self) -> None:
        while not self._stop.is_set():
            requested = self._maintenance_request.wait(60)
            self._maintenance_request.clear()
            if self._stop.is_set():
                break
            try:
                self.run_maintenance(force=requested)
            except Exception:
                import traceback
                traceback.print_exc()
            finally:
                if requested and not self._maintenance_request.is_set():
                    self._maintenance_done.set()

    def compact_flow_rollups(self) -> int:
        """Summarise sealed flow buckets into both tiers.

        The minute tier first: the hourly one is built from it wherever it
        covers a whole hour.
        """
        written = 0
        with self._rollup_lock:
            for tier in ROLLUP_TIERS:
                written += self.flow_db.compact_rollup(tier)
        return written

    def _rollup_loop(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(ROLLUP_INTERVAL_S):
                break
            try:
                self.compact_flow_rollups()
            except Exception:
                import traceback
                traceback.print_exc()

    def request_maintenance(self) -> None:
        """Ask for a forced sweep and return; the sweep runs on the
        maintenance thread, which this wakes, rather than blocking the HTTP
        thread for up to a minute on a large install."""
        self._maintenance_done.clear()
        self._maintenance_request.set()

    _last_maintenance = 0.0

    def run_maintenance(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_maintenance < MAINTENANCE_INTERVAL_S:
            return

        # A forced call (a settings save, on an HTTP thread) waits for
        # whatever sweep is already running rather than racing it; a
        # periodic call from the timer thread just skips this tick if one is
        # already in flight, the same as the interval check above.
        if force:
            self._maintenance_lock.acquire()
        elif not self._maintenance_lock.acquire(blocking=False):
            return
        try:
            self._last_maintenance = now
            self._run_maintenance_body(force=force)
        finally:
            self._maintenance_lock.release()

    def _stopping(self) -> bool:
        """Shutdown is waiting on the lock this sweep holds. The rest of the
        pass runs at the next start rather than making the stop wait for
        it."""
        return self._stop.is_set()

    def _run_maintenance_body(self, force: bool = False) -> None:
        # A forced pass gets a short budget on netpath.db (the only store
        # here with per-hop rows at fleet volume) so a burst of settings
        # saves can't stall on a backlog; it still does enough retention
        # work that saves can't outrun what retention enforces.
        prune_budget = FORCED_PRUNE_BUDGET_S if force else TRIM_BUDGET_S
        self.db.prune(float(self.settings.get("trace_retention_days", 90)),
                      budget_s=prune_budget)
        self._trim_db("max_trace_db_mb", self.db, "Trace database",
                      "oldest traces", budget_s=prune_budget)
        # Before the prune, not after: the backfill summarises raw flows, and
        # pruning first would delete a bucket before it had been summarised.
        # A chart wider than a quarter of an hour reads the rollups rather
        # than the raw rows. Forward compaction is not repeated here — the
        # 60-second timer has already done it, and a second pass over the
        # same buckets doubles a sweep's rollup load for nothing.
        with self._rollup_lock:
            for tier in ROLLUP_TIERS:
                written, done = self.flow_db.backfill_rollup(tier)
                if done:
                    self.log.add(SYSTEM,
                                 f"NetFlow: summarised the stored history "
                                 f"into the {ROLLUP_TIER_NAMES[tier]} rollups "
                                 f"({written} row(s) on this pass)")
        self.flow_db.drop_legacy_indexes()
        self.flow_db.prune(
            float(self.flow_settings.get("retention_days", 14)),
            int(self.flow_settings.get("max_flows", 5_000_000)),
            minute_days=float(self.flow_settings.get("rollup_minute_days", 2)),
            rollup_days=float(self.flow_settings.get("rollup_retention_days", 90)))
        # Last of the flow stages, for the reason compaction runs before the
        # prune: the size cap deletes the same oldest raw rows the backfill
        # is still summarising, and running it first meant a store already at
        # its cap gave them up on every sweep while the backfill advanced one
        # bucket. The promise that a 30-day chart outlives a fortnight of raw
        # retention only holds if the rows are summarised before they go.
        self._trim_db("max_flow_db_mb", self.flow_db, "Flow database",
                      "oldest flow records")

        self.syslog_db.prune(
            float(self.syslog_settings.get("retention_days", 30)),
            int(self.syslog_settings.get("max_rows", 20_000_000)))
        self.snmp_db.prune(
            float(self.snmp_settings.get("retention_days", 90)),
            int(self.snmp_settings.get("max_rows", 5_000_000)))
        self.app_db.prune_hostnames(
            max(float(self.settings.get("dns_cache_days", 7)) * 4, 30))
        self.app_db.prune_asn_cache(
            max(float(self.settings.get("asn_cache_days", 30)) * 4, 90))

        self.ipam_db.prune_hosts(
            float(self.ipam_settings.get("host_retention_days", 30)))
        self.ipam_db.prune_conflicts(
            float(self.ipam_settings.get("conflict_retention_days", 90)))
        self.ipam_db.prune_scans(
            float(self.ipam_settings.get("scan_history_days", 30)))
        self.ipam_db.prune_scope_history(
            float(self.ipam_settings.get("dhcp_history_days", 35)))

        self._trim_db("max_syslog_db_mb", self.syslog_db, "Syslog database",
                      "oldest messages")
        self._trim_db("max_snmp_db_mb", self.snmp_db, "SNMP trap database",
                      "oldest traps")

        if self._stopping():
            return

        self.wireless_db.prune_ap_events()

        removed = self.configrx_db.prune(
            float(self.configrx_settings.get("retention_days", 90)),
            int(self.configrx_settings.get("retention_count_per_device", 30)))
        if removed:
            self.log.add(SYSTEM, f"ConfigRX: removed {removed} old backup(s) "
                                 f"past retention")

        self._trim_db("max_ipam_db_mb", self.ipam_db, "IPAM database",
                      "oldest scan records")

        if self._stopping():
            return

        # Before the prune, not after: compact_rollup summarises complete
        # hours of raw samples into samples_hourly, and pruning first would
        # delete an hour before it had been summarised. A chart wider than
        # three days reads only the rollups.
        written = self.nodes_db.compact_rollup()
        if written:
            self.log.add(SYSTEM, f"Nodes: summarised {written} metric-hour(s) "
                                 f"into the hourly rollups")
        self.nodes_db.prune(
            sample_days=float(self.nodes_settings.get("sample_retention_days", 3)),
            rollup_days=float(self.nodes_settings.get("rollup_retention_days", 400)),
            event_days=float(self.nodes_settings.get("event_retention_days", 180)),
            discovery_days=float(self.nodes_settings.get("discovery_retention_days", 30)),
            max_samples_per_metric=int(
                self.nodes_settings.get("sample_row_cap_per_metric", 0)))
        # Forwarding-table entries nothing has refreshed for a while. A
        # switch taken out of the walk schedule would otherwise keep
        # answering MAC searches from a table nobody has confirmed since,
        # sending someone to a port the address left months ago.
        self.nodes_db.prune_mac_entries(
            float(self.nodes_settings.get("mac_table_retention_days", 7)) * 86400)
        # LLDP/CDP neighbour rows nothing has refreshed in as long — the
        # same present=0-then-age-out shape mac_entries uses, so the same
        # retention setting governs both rather than adding a second knob for
        # the same "device stopped being walked" problem.
        self.nodes_db.prune_neighbors(
            float(self.nodes_settings.get("mac_table_retention_days", 7)) * 86400)
        # VLAN membership (Q-BRIDGE/VTP) and the two per-port VLAN tables age
        # out on the same clock as neighbours and the MAC table: all three
        # are "device stopped answering this walk", the same failure mode
        # mac_table_retention_days already governs, so a fourth (or sixth)
        # setting for the identical question would just be one more knob an
        # operator has to know exists.
        self.nodes_db.prune_vlans(
            float(self.nodes_settings.get("mac_table_retention_days", 7)) * 86400)
        self.nodes_db.prune_vlan_ports(
            float(self.nodes_settings.get("mac_table_retention_days", 7)) * 86400)
        self.nodes_db.prune_port_vlans(
            float(self.nodes_settings.get("mac_table_retention_days", 7)) * 86400)
        self._trim_db("max_nodes_db_mb", self.nodes_db, "Nodes database",
                      "oldest events")
        # Own cap since 5.0.0: growth lives here, not in the inventory file.
        # Two stages, so the noun names both: raw samples go first, hourly
        # rollups only once raw is at its floor.
        self._trim_db("max_nodes_series_db_mb", self.nodes_db.series_db,
                      "Nodes metric history",
                      "oldest samples and hourly rollups")

        if self._stopping():
            return

        self.alerts_db.prune(
            float(self.alerts_settings.get("retention_days", 180)))
        self._trim_db("max_alerts_db_mb", self.alerts_db, "Alerts database",
                      "oldest resolved alerts")

        self._sample_storage_alerts()
        self._optimize_stores()

    def _optimize_stores(self) -> None:
        """Refresh every store's query-planner statistics.

        Last in the sweep, after the prunes and trims have changed the table
        sizes the planner is about to be told about, and cheap enough at this
        cadence that it needs no budget of its own -- PRAGMA optimize does
        nothing at all for a table whose statistics are still current.
        """
        for store in STORES:
            if self._stopping():
                return
            db = db_for(self, store)
            optimize = getattr(db, "optimize", None)
            if callable(optimize):
                optimize()

    def _sample_storage_alerts(self) -> None:
        """Alert on a database close to its cap, and on the volume under
        them all running low.

        At the end of the sweep rather than on a clock of its own, because
        the trims above have just run: the size read here is what is left
        after retention did everything it could, which is the only figure
        worth waking anyone for. Driven from STORES so it cannot disagree
        with the Settings page or the Dashboard about which databases exist
        or what caps them, and the store name is the entity_id so each
        database opens an alert of its own instead of one that flaps between
        them.
        """
        engine = getattr(self, "alert_engine", None)
        raise_it = getattr(engine, "system_occurrence", None)
        clear_it = getattr(engine, "clear_system_occurrence", None)
        if raise_it is None or clear_it is None:
            return

        def still_open(rule_key: str, entity_id: str) -> bool:
            # alertrules.dedup_key's key for the occurrence system_occurrence
            # builds, which is the one clear_system_occurrence resolves.
            return self.alerts_db.open_by_dedup(
                f"{rule_key}:system:{entity_id}") is not None

        for store in STORES:
            if not store.cap_key:
                continue
            db = db_for(self, store)
            cap = int(self.settings.get(store.cap_key, 0) or 0) * 1024 * 1024
            if db is None or not cap:
                continue
            try:
                used = int(db.size_bytes())
            except Exception:                                 # noqa: BLE001
                continue
            share = used / cap
            if share < DB_CAP_CLEAR_SHARE:
                clear_it("db_near_cap", store.name)
                continue
            # An alert already open is re-raised in the hold band rather than
            # left alone: the rule's auto-resolve measures from last_ts and
            # only a raise moves it, so a store trimmed from 90% to 83% would
            # be closed by that backstop half an hour later and the effective
            # clear would be "below 85% for two sweeps", not below 80%.
            if (share < DB_CAP_WARN_SHARE
                    and not still_open("db_near_cap", store.name)):
                continue
            # The percentage is in the message as well as in `severity`
            # because AlertEngine._apply opens the row at the RULE's
            # severity: what separates a store at 97% of its cap from one at
            # 86% on the Alerts page is the wording, not the colour.
            raise_it(
                "db_near_cap", store.name, f"{store.label} database",
                severity=2 if share >= DB_CAP_HIGH_SHARE else 3,
                extra={"store": store.name, "path": db.path,
                       "bytes": used, "cap_bytes": cap,
                       "used_pct": round(share * 100, 1),
                       "setting": store.cap_key},
                message=(f"{store.label} is at {share * 100:.0f}% of its "
                         f"{cap // 1048576} MB cap "
                         f"({format_bytes(used)} in {db.path}). Its oldest "
                         f"records are deleted once it reaches that cap. "
                         f"Raise {store.cap_key} in Settings → Data & "
                         f"Retention to keep more history."))

        free, total = disk_space(self)
        if not total:
            return
        free_pct = free / total * 100.0
        warn = float(self.settings.get("disk_free_warn_pct", 10) or 0)
        critical = float(self.settings.get("disk_free_critical_pct", 5) or 0)
        folder = str(Path(self.app_db.path).parent)
        if not warn or free_pct >= warn + DISK_FREE_CLEAR_MARGIN_PCT:
            clear_it("disk_space_low", "data")
            return
        # The databases' hold band, on the volume: raised below `warn`,
        # cleared only once free space is a margin above it again.
        if free_pct >= warn and not still_open("disk_space_low", "data"):
            return
        raise_it(
            "disk_space_low", "data", folder,
            severity=2 if free_pct < critical else 3,
            extra={"path": folder, "free_bytes": free, "total_bytes": total,
                   "free_pct": round(free_pct, 1),
                   "setting": "disk_free_warn_pct"},
            message=(f"{folder} has {format_bytes(free)} free of "
                     f"{format_bytes(total)} ({free_pct:.0f}%). Every "
                     f"database in it stops being written the moment the "
                     f"volume fills, whatever the size caps say. Warns below "
                     f"{warn:.0f}% (disk_free_warn_pct in Settings → Data & "
                     f"Retention)."))

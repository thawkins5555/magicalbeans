"""The application without a user interface.

Everything that was previously owned by the Qt main window — the databases, the
trace scheduler, the reverse-DNS resolver, the flow collector and the event log
— lives here instead. The desktop window and the web server are both just
front ends over this.
"""

from __future__ import annotations

import threading
import time

from ..auth import (DEFAULT_PASSWORD, DEFAULT_USER, LoginThrottle,
                    SessionStore, hash_password)
from ..appdb import AppDatabase, migrate_from
from ..collector import Collector
from ..db import Database
from ..eventlog import SYSTEM, EventLog
from ..flowdb import FlowDatabase
from ..ipamdb import IpamDatabase
from ..ipam_worker import IpamWorker
from ..monitor import AsnResolver, HopProber, Monitor, Resolver
from ..syslogd import SyslogCollector
from ..syslogdb import SyslogDatabase

MAINTENANCE_INTERVAL_S = 900


class Service:
    def __init__(self, db_path: str, flow_db_path: str, syslog_db_path: str,
                 app_db_path: str, ipam_db_path: str):
        self.log = EventLog()
        self.app_db = AppDatabase(app_db_path)
        # Before the trace database is opened for normal use: on an install
        # that predates app.db this lifts the settings, accounts and name cache
        # out of netpath.db and then drops them from it.
        migrate_from(self.app_db, db_path, log=self.log)

        self.db = Database(db_path)
        self.flow_db = FlowDatabase(flow_db_path)
        self.syslog_db = SyslogDatabase(syslog_db_path)
        self.ipam_db = IpamDatabase(ipam_db_path)
        # Global keys and NetPath keys, merged for reading. Each store filters
        # this dict down to what it owns when it is written back.
        self.settings = {**self.app_db.settings(), **self.db.settings()}
        self.flow_settings = self.flow_db.settings()
        self.syslog_settings = self.syslog_db.settings()
        self.ipam_settings = self.ipam_db.settings()

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
        self.ipam = IpamWorker(self.ipam_db, log=self.log)

        self.sessions = SessionStore(
            idle_minutes=int(self.settings.get("session_idle_minutes", 10)),
            max_hours=int(self.settings.get("session_max_hours", 12)))
        self.throttle = LoginThrottle()
        self._ensure_default_user()

        self._stop = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self.started_at = time.time()

    def _ensure_default_user(self) -> None:
        """Create admin/admin on a fresh install, flagged to be changed.

        The account exists so there is a way in; the flag exists so the first
        thing anyone does is replace it.
        """
        if self.app_db.user_count():
            return
        self.app_db.add_user(DEFAULT_USER, hash_password(DEFAULT_PASSWORD),
                             must_change=True)
        self.log.add(SYSTEM, f"Created the default {DEFAULT_USER} account. "
                             f"Change its password before this is reachable "
                             f"by anyone else.")

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
        if self.ipam_settings.get("enabled", True):
            self.ipam.start()

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
        self._stop.clear()
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop, name="netpath-maintenance", daemon=True)
        self._maintenance_thread.start()
        self.log.add(SYSTEM, "Service started")

    def shutdown(self) -> None:
        self._stop.set()
        self.monitor.shutdown()   # waits briefly for running traces to land
        self.hop_prober.shutdown()
        self.resolver.shutdown()
        self.asn_resolver.shutdown()
        self.collector.stop()
        self.syslog.stop()
        self.ipam.shutdown()
        self.db.close()
        self.flow_db.close()
        self.syslog_db.close()
        self.ipam_db.close()
        self.app_db.close()

    # ------------------------------------------------------------- settings

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
        self.run_maintenance(force=True)
        return self.settings

    def apply_netpath_settings(self, values: dict) -> dict:
        self.settings.update(values)
        self.db.save_settings(self.settings)
        self.monitor.set_workers(int(self.settings["trace_workers"]))
        self.log.add(SYSTEM, "NetPath settings applied")
        return self.settings

    def apply_netflow_settings(self, values: dict) -> dict:
        self.flow_settings.update(values)
        self.flow_db.save_settings(self.flow_settings)
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
        self.collector.stop()
        if self.flow_settings.get("enabled"):
            self.collector.start(self.flow_settings)
        self.log.add(SYSTEM, "NetFlow settings applied")
        return self.flow_settings

    def apply_syslog_settings(self, values: dict) -> dict:
        self.syslog_settings.update(values)
        self.syslog_db.save_settings(self.syslog_settings)
        self.syslog.stop()
        if self.syslog_settings.get("enabled"):
            self.syslog.start(self.syslog_settings)
        self.log.add(SYSTEM, "Syslog settings applied")
        return self.syslog_settings

    def apply_ipam_settings(self, values: dict) -> dict:
        self.ipam_settings.update(values)
        self.ipam_db.save_settings(self.ipam_settings)
        if self.ipam_settings.get("enabled", True):
            self.ipam.start()
        else:
            self.ipam.stop()
        self.log.add(SYSTEM, "IPAM settings applied")
        return self.ipam_settings

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
        if self.ipam_settings.get("resolve_hosts", True):
            addresses.extend(row["ip"] for row in self.ipam_db.hosts()
                             if row["alive"])
        return addresses

    def _maintenance_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(60)
            if self._stop.is_set():
                break
            try:
                self.run_maintenance()
            except Exception:
                import traceback
                traceback.print_exc()

    _last_maintenance = 0.0

    def run_maintenance(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_maintenance < MAINTENANCE_INTERVAL_S:
            return
        self._last_maintenance = now

        cap = int(self.settings.get("max_trace_db_mb", 0)) * 1024 * 1024
        if cap:
            removed = self.db.trim_to_size(cap)
            if removed:
                self.log.add(SYSTEM, f"Trace database over its "
                                     f"{cap // 1048576} MB cap: removed "
                                     f"{removed} oldest traces")

        cap = int(self.settings.get("max_flow_db_mb", 0)) * 1024 * 1024
        if cap:
            removed = self.flow_db.trim_to_size(cap)
            if removed:
                self.log.add(SYSTEM, f"Flow database over its "
                                     f"{cap // 1048576} MB cap: removed "
                                     f"{removed} oldest flow records")

        self.flow_db.prune(float(self.flow_settings.get("retention_days", 14)),
                           int(self.flow_settings.get("max_flows", 5_000_000)))

        self.syslog_db.prune(
            float(self.syslog_settings.get("retention_days", 30)),
            int(self.syslog_settings.get("max_rows", 20_000_000)))
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

        cap = int(self.settings.get("max_syslog_db_mb", 0)) * 1024 * 1024
        if cap:
            removed = self.syslog_db.trim_to_size(cap)
            if removed:
                self.log.add(SYSTEM, f"Syslog database over its "
                                     f"{cap // 1048576} MB cap: removed "
                                     f"{removed} oldest messages")

        cap = int(self.settings.get("max_ipam_db_mb", 0)) * 1024 * 1024
        if cap:
            removed = self.ipam_db.trim_to_size(cap)
            if removed:
                self.log.add(SYSTEM, f"IPAM database over its "
                                     f"{cap // 1048576} MB cap: removed "
                                     f"{removed} oldest scan records")

"""Runs subnet scans and DHCP polls on a schedule, and does the conflict
checking that only makes sense with both kinds of result in hand.

Each subnet and each DHCP server gets its own next-due time and its own
in-flight guard, so a slow scan of one subnet does not delay another, and a
DHCP server that has stopped answering does not block the ones that haven't.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .eventlog import ERROR, IPAM, NullLog, SYSTEM
from .ipam_dhcp import poll as dhcp_poll
from .ipam_scan import SubnetTooLarge, normalize_mac, read_arp_table, sweep, usable_addresses
from .ipamdb import IpamDatabase, scope_size

# How many subnet scans may run at once. Each one calls sweep(), which builds
# its own ThreadPoolExecutor of `ping_workers` (64) threads and runs one
# `ping` subprocess per address, so the number that matters is this times
# ping_workers: 4 x 64 = 256 concurrent pings, on a box that is also polling
# a fleet. Before, every enabled subnet got its own bare thread with nothing
# limiting how many ran together -- 50 subnets meant 50 scan threads, 3,200
# pool threads and up to 3,200 concurrent ping processes.
#
# Overridable per install through the IPAM settings key of the same name;
# `settings.get` keeps working on a database that has no such key.
DEFAULT_MAX_CONCURRENT_SCANS = 4

# The window the first scan of each subnet is spread across, in seconds.
# `_next_scan` starts empty, so on the first tick after start-up every
# enabled subnet was due at once -- and because they then all share one
# scan_interval_minutes they stayed in lockstep for the life of the process.
# Five minutes is short enough that an operator watching a fresh install
# sees every subnet scanned promptly, and long enough that fifty of them do
# not arrive together.
FIRST_SCAN_SPREAD_S = 300.0


def credential_for_server(server) -> tuple[str | None, str | None]:
    """Decrypt a DHCP server's stored credential, if it has one.

    Returns (None, None) when the server has no username, meaning the ambient
    or Credential Manager path applies. Decryption happens here, immediately
    before the one call that needs it — nothing decrypted is cached, so the
    plaintext password's lifetime in this process is as short as the call
    that uses it.
    """
    username = server["username"]
    if not username:
        return None, None
    if server["password_enc"] is None:
        return username, None
    from . import dpapi
    password = dpapi.unprotect(bytes(server["password_enc"])).decode("utf-8")
    return username, password


class IpamWorker:
    def __init__(self, db: IpamDatabase, log=None, global_settings=None):
        self.db = db
        self.log = log or NullLog()
        # Called for the application-wide settings: never_scan_cidrs lives
        # there rather than in the IPAM module's own table, because which
        # networks nothing here may probe is a fact about the plant, and
        # Nodes discovery honours the same list. A worker built without it
        # simply has no deny list.
        self._global_settings = global_settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._next_scan: dict[int, float] = {}
        self._next_dhcp_poll: dict[int, float] = {}
        self._scanning: set[int] = set()
        self._polling: set[int] = set()
        # Subnets handed to the scan pool but not yet started. Without this,
        # a scan waiting for a pool slot is in neither _scanning nor the
        # queue's view, so the next tick would hand it in again.
        self._queued: set[int] = set()
        self._scan_pool: ThreadPoolExecutor | None = None
        self._scan_pool_size = 0
        # False until the first tick has spread the subnets' first scans
        # across FIRST_SCAN_SPREAD_S.
        self._staggered = False
        # When each currently-running scan or poll began, for the Debug page.
        # Only holds entries for ids presently in _scanning/_polling — an id
        # leaving one of those sets removes its entry here in the same
        # locked block, so the two can never disagree about what's running.
        self._scan_started: dict[int, float] = {}
        self._poll_started: dict[int, float] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ipam-worker", daemon=True)
        self._thread.start()
        self.log.add(SYSTEM, "IPAM worker started")

    def stop(self) -> None:
        if self.running:
            self.log.add(SYSTEM, "IPAM worker stopped")
        self._stop.set()
        with self._lock:
            pool, self._scan_pool = self._scan_pool, None
            self._scan_pool_size = 0
        if pool is not None:
            # Not waited on: a sweep in flight can take minutes, and stop()
            # is called from the UI thread and from shutdown. cancel_futures
            # matches every other pool-owning worker's stop() (see
            # monitor.py's Monitor.shutdown()): without it, a scan that was
            # only queued — never started — still runs after stop() returns
            # and then fails writing to a database this same stop() may have
            # just closed underneath it.
            pool.shutdown(wait=False, cancel_futures=True)

    def shutdown(self) -> None:
        self.stop()

    def state(self) -> dict:
        with self._lock:
            return {"scanning": sorted(self._scanning), "polling": sorted(self._polling),
                    "scan_started": dict(self._scan_started),
                    "poll_started": dict(self._poll_started)}

    # -------------------------------------------------------------- schedule

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                import traceback
                traceback.print_exc()
            self._stop.wait(5)

    def _tick(self) -> None:
        settings = self.db.settings()
        if not settings.get("enabled", True):
            return
        now = time.time()

        subnets = [s for s in self.db.subnets() if s["enabled"]]
        if not self._staggered:
            self._stagger_first_scans(subnets, settings, now)
        for subnet in subnets:
            if now >= self._next_scan.get(subnet["id"], 0):
                self._schedule_scan(subnet["id"], settings)

        for server in self.db.dhcp_servers():
            if not server["enabled"]:
                continue
            if now >= self._next_dhcp_poll.get(server["id"], 0) and server["id"] not in self._polling:
                self._schedule_dhcp_poll(server["id"], settings)

    def _stagger_first_scans(self, subnets: list, settings: dict,
                             now: float) -> None:
        """Give each subnet its own first due time, spread evenly across
        FIRST_SCAN_SPREAD_S (or the scan interval, whichever is shorter).

        Runs once. A subnet added later has no entry and so is still due
        immediately, which is what an operator who just added one expects.
        """
        self._staggered = True
        interval_s = float(settings.get("scan_interval_minutes", 60)) * 60
        spread = min(FIRST_SCAN_SPREAD_S, max(interval_s, 0.0))
        count = len(subnets)
        if count < 2 or spread <= 0:
            return
        for position, subnet in enumerate(subnets):
            self._next_scan.setdefault(subnet["id"],
                                       now + spread * position / count)

    def _pool(self, settings: dict) -> ThreadPoolExecutor:
        """The shared scan pool, rebuilt if its configured size changed.
        Caller must not hold the lock."""
        size = max(1, int(settings.get("max_concurrent_scans",
                                       DEFAULT_MAX_CONCURRENT_SCANS)))
        with self._lock:
            if self._scan_pool is not None and self._scan_pool_size == size:
                return self._scan_pool
            old_pool, self._scan_pool = self._scan_pool, ThreadPoolExecutor(
                max_workers=size, thread_name_prefix="ipam-scan")
            self._scan_pool_size = size
            pool = self._scan_pool
        if old_pool is not None:
            old_pool.shutdown(wait=False)
        return pool

    def scan_now(self, subnet_id: int) -> None:
        self._schedule_scan(subnet_id, self.db.settings())

    def poll_dhcp_now(self, server_id: int) -> None:
        self._schedule_dhcp_poll(server_id, self.db.settings())

    def _schedule_scan(self, subnet_id: int, settings: dict) -> None:
        """Hand one subnet to the shared scan pool, at most once at a time.

        A bulk "scan all subnets" from the API arrives here too, so the cap
        applies to it as well: the scans queue instead of fanning out.
        """
        with self._lock:
            if subnet_id in self._scanning or subnet_id in self._queued:
                return
            self._queued.add(subnet_id)
        self._next_scan[subnet_id] = time.time() + \
            float(settings.get("scan_interval_minutes", 60)) * 60
        try:
            self._pool(settings).submit(self._run_scan, subnet_id, settings)
        except RuntimeError:        # the pool was shut down under us
            with self._lock:
                self._queued.discard(subnet_id)

    def _schedule_dhcp_poll(self, server_id: int, settings: dict) -> None:
        self._next_dhcp_poll[server_id] = time.time() + \
            float(settings.get("dhcp_poll_interval_minutes", 15)) * 60
        threading.Thread(target=self._run_dhcp_poll, args=(server_id, settings),
                         name=f"ipam-dhcp-{server_id}", daemon=True).start()

    # ------------------------------------------------------------ subnet scan

    def _never_scan(self) -> tuple:
        """The networks no scan from here may probe, from the global settings.

        Failing to read them is not a reason to skip a scan, but it is a
        reason to say so: an empty list means every address is probed, which
        is what the setting exists to prevent.
        """
        if self._global_settings is None:
            return ()
        try:
            raw = self._global_settings().get("never_scan_cidrs", "")
        except Exception as exc:
            self.log.add(ERROR, f"IPAM could not read never_scan_cidrs: {exc}")
            return ()
        return tuple(part.strip() for part in
                     str(raw or "").replace(",", " ").split() if part.strip())

    def _run_scan(self, subnet_id: int, settings: dict) -> None:
        with self._lock:
            self._queued.discard(subnet_id)
            if subnet_id in self._scanning:
                return
            self._scanning.add(subnet_id)
            self._scan_started[subnet_id] = time.time()
        try:
            self._scan(subnet_id, settings)
        finally:
            with self._lock:
                self._scanning.discard(subnet_id)
                self._scan_started.pop(subnet_id, None)

    def _scan(self, subnet_id: int, settings: dict) -> None:
        subnet = self.db.subnet(subnet_id)
        if not subnet:
            return

        max_addresses = int(settings.get("max_scan_addresses", 1024))
        try:
            addresses = usable_addresses(subnet["cidr"], max_addresses)
        except (SubnetTooLarge, ValueError) as exc:
            self.log.add(ERROR, f"IPAM scan of {subnet['cidr']} skipped: {exc}")
            return

        scan_id = self.db.start_scan(subnet_id, len(addresses))
        self.log.add(IPAM, f"Scanning {subnet['label']} ({subnet['cidr']}, "
                           f"{len(addresses)} addresses)", target=subnet["label"])

        alive_count, new_conflicts, error = 0, 0, None
        try:
            alive_map = sweep(addresses, timeout_ms=int(settings.get("ping_timeout_ms", 800)),
                              workers=int(settings.get("ping_workers", 64)),
                              never_scan=self._never_scan())
            net = ipaddress.ip_network(subnet["cidr"], strict=False)
            arp = {ip: mac for ip, mac in read_arp_table().items()
                  if ipaddress.ip_address(ip) in net}

            # A window inside which a DHCP lease's MAC is still worth trusting
            # for the cross-check below. Older than this, a mismatch is just
            # as likely to mean the DHCP server hasn't reclaimed the lease yet
            # as it is to mean a real conflict, so it is left alone rather
            # than flagged.
            dhcp_freshness_s = max(
                float(settings.get("dhcp_poll_interval_minutes", 15)) * 60 * 3, 3600)
            dhcp_cutoff = time.time() - dhcp_freshness_s

            for ip in addresses:
                is_alive = bool(alive_map.get(ip))
                mac = normalize_mac(arp.get(ip)) if ip in arp else None
                if is_alive:
                    alive_count += 1
                previous = self.db.record_host(ip, subnet_id, is_alive, mac)
                if not mac:
                    continue

                if previous and previous["mac"] and previous["mac"] != mac:
                    if self.db.record_conflict(ip, previous["mac"], mac, "scan"):
                        new_conflicts += 1
                        self.log.add(
                            IPAM, f"Possible IP conflict: {ip} has answered as "
                                 f"both {previous['mac']} and {mac}", target=ip)

                lease = self.db.dhcp_lease_for_ip(ip)
                if lease and lease["mac"] and lease["polled_ts"] >= dhcp_cutoff:
                    lease_mac = normalize_mac(lease["mac"])
                    if lease_mac and lease_mac != mac:
                        if self.db.record_conflict(ip, lease_mac, mac, "scan_dhcp"):
                            new_conflicts += 1
                            self.log.add(
                                IPAM, f"{ip} answered on the wire as {mac}, but "
                                     f"the DHCP server's lease record says "
                                     f"{lease_mac}", target=ip)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            error = str(exc)

        self.db.finish_scan(scan_id, alive_count, new_conflicts, error=error)
        self.log.add(IPAM, f"Scan of {subnet['label']} finished: {alive_count}/"
                           f"{len(addresses)} answered, {new_conflicts} new "
                           f"conflict(s)", target=subnet["label"])

    # -------------------------------------------------------------- dhcp poll

    def _run_dhcp_poll(self, server_id: int, settings: dict) -> None:
        with self._lock:
            if server_id in self._polling:
                return
            self._polling.add(server_id)
            self._poll_started[server_id] = time.time()
        try:
            self._poll(server_id, settings)
        finally:
            with self._lock:
                self._polling.discard(server_id)
                self._poll_started.pop(server_id, None)

    def _poll(self, server_id: int, settings: dict) -> None:
        server = self.db.dhcp_server(server_id)
        if not server:
            return
        self.log.add(IPAM, f"Polling DHCP server {server['label']}",
                     target=server["address"])
        try:
            username, password = credential_for_server(server)
            snapshot = dhcp_poll(server["address"],
                                 timeout_s=float(settings.get("dhcp_timeout_s", 30)),
                                 username=username, password=password)
        except Exception as exc:
            self.db.set_dhcp_poll_result(server_id, ok=False, error=str(exc))
            self.log.add(ERROR, f"DHCP poll of {server['label']} failed: {exc}",
                         target=server["address"])
            return
        finally:
            username = password = None

        self.db.replace_dhcp_scopes(server_id, snapshot.scopes)
        self.db.replace_dhcp_leases(server_id, snapshot.leases)
        self._record_scope_history(server_id)
        self.db.set_dhcp_poll_result(server_id, ok=True)
        self.log.add(IPAM, f"Polled {server['label']}: {len(snapshot.scopes)} "
                           f"scope(s), {len(snapshot.leases)} lease(s)",
                     target=server["address"])

    def _record_scope_history(self, server_id: int) -> None:
        """One leased/reserved/total snapshot per scope, so the DHCP page can
        chart usage over time. Reads back what was just written rather than
        the raw poll snapshot, so this always agrees with what the API's own
        usage figures are computed from."""
        try:
            scopes = self.db.dhcp_scopes(server_id)
            leases = self.db.dhcp_leases(server_id)
            by_scope: dict[str, list] = {}
            for lease in leases:
                by_scope.setdefault(lease["scope_id"], []).append(lease)
            for scope in scopes:
                scope_leases = by_scope.get(scope["scope_id"], [])
                reserved = sum(1 for row in scope_leases if row["is_reservation"])
                leased = len(scope_leases) - reserved
                total = scope_size(scope["start_ip"], scope["end_ip"])
                self.db.record_scope_usage(server_id, scope["scope_id"],
                                           leased, reserved, total)
        except Exception:
            import traceback
            traceback.print_exc()

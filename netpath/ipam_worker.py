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

from .eventlog import ERROR, IPAM, NullLog, SYSTEM
from .ipam_dhcp import DhcpUnavailable
from .ipam_dhcp import poll as dhcp_poll
from .ipam_scan import SubnetTooLarge, normalize_mac, read_arp_table, sweep, usable_addresses
from .ipamdb import IpamDatabase


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
    def __init__(self, db: IpamDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._next_scan: dict[int, float] = {}
        self._next_dhcp_poll: dict[int, float] = {}
        self._scanning: set[int] = set()
        self._polling: set[int] = set()
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

        for subnet in self.db.subnets():
            if not subnet["enabled"]:
                continue
            if now >= self._next_scan.get(subnet["id"], 0) and subnet["id"] not in self._scanning:
                self._schedule_scan(subnet["id"], settings)

        for server in self.db.dhcp_servers():
            if not server["enabled"]:
                continue
            if now >= self._next_dhcp_poll.get(server["id"], 0) and server["id"] not in self._polling:
                self._schedule_dhcp_poll(server["id"], settings)

    def scan_now(self, subnet_id: int) -> None:
        self._schedule_scan(subnet_id, self.db.settings())

    def poll_dhcp_now(self, server_id: int) -> None:
        self._schedule_dhcp_poll(server_id, self.db.settings())

    def _schedule_scan(self, subnet_id: int, settings: dict) -> None:
        self._next_scan[subnet_id] = time.time() + \
            float(settings.get("scan_interval_minutes", 60)) * 60
        threading.Thread(target=self._run_scan, args=(subnet_id, settings),
                         name=f"ipam-scan-{subnet_id}", daemon=True).start()

    def _schedule_dhcp_poll(self, server_id: int, settings: dict) -> None:
        self._next_dhcp_poll[server_id] = time.time() + \
            float(settings.get("dhcp_poll_interval_minutes", 15)) * 60
        threading.Thread(target=self._run_dhcp_poll, args=(server_id, settings),
                         name=f"ipam-dhcp-{server_id}", daemon=True).start()

    # ------------------------------------------------------------ subnet scan

    def _run_scan(self, subnet_id: int, settings: dict) -> None:
        with self._lock:
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
                              workers=int(settings.get("ping_workers", 64)))
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
        except (DhcpUnavailable, Exception) as exc:
            self.db.set_dhcp_poll_result(server_id, ok=False, error=str(exc))
            self.log.add(ERROR, f"DHCP poll of {server['label']} failed: {exc}",
                         target=server["address"])
            return
        finally:
            username = password = None

        self.db.replace_dhcp_scopes(server_id, snapshot.scopes)
        self.db.replace_dhcp_leases(server_id, snapshot.leases)
        self.db.set_dhcp_poll_result(server_id, ok=True)
        self.log.add(IPAM, f"Polled {server['label']}: {len(snapshot.scopes)} "
                           f"scope(s), {len(snapshot.leases)} lease(s)",
                     target=server["address"])

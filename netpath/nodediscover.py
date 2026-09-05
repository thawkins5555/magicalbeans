"""Per-device and per-subnet discovery: a ping sweep (reused from
ipam_scan.py, not reimplemented) followed by best-effort SNMP v1/v2c
identification of whatever responded.

DiscoveryJob runs on its own daemon thread, one per active job — this
mirrors IpamWorker's per-job-thread shape, not Monitor's pool, because a
discovery sweep is a one-shot bounded task, not a recurring per-target
schedule. NodePoller (nodepoll.py) owns a dict of active jobs and starts
one per API call.

SNMPv3 identification is deliberately out of scope: v3 requires a known
username to even attempt authentication, which a blind sweep does not
have — a v3 device is added manually, with its real credentials, once an
admin already knows it is there (from this module's ping-only result, or
simply from knowing the network).
"""

from __future__ import annotations

import json
import random
import sqlite3
import threading
import time
import traceback

from . import mibcatalog, nodeoids, vendorid
from .eventlog import ERROR, NODES, NullLog
from .ipam_scan import (DEFAULT_PROBES_PER_SECOND, SubnetTooLarge,
                        is_never_scanned, parse_never_scan, sweep,
                        usable_addresses)
from .nodeoids import DEFAULT_SNMP_PORT
from .nodesdb import NodesDatabase
from .snmppoll import PDU_GET, PDU_GETNEXT, SnmpError, V2C, build_request, decode_response



def _candidate_communities(text: str | None) -> list[str]:
    """No fallback guess: the list comes from the chosen polling profile's
    own v1/v2c credentials, and an empty list (a v3-only profile) simply
    means no SNMP identification is attempted — the sweep still runs and
    reports ping-only results. The API layer refuses that combination up
    front unless the job explicitly allows ping-only devices."""
    return [c.strip() for c in (text or "").split(",") if c.strip()]


def _snmp_identify(ip: str, version: int, community: str, timeout_s: float,
                   oids: list[str], pdu: int = PDU_GET):
    """One single-shot GET (or GETNEXT), no retry (the caller already loops
    over several community/version combinations, so a slow retry-per-guess
    would make a subnet sweep take far too long). Returns a Response or
    raises SnmpError."""
    # nodepoll._Session rather than a bare socket: it accepts a datagram
    # only from the address asked and only with the request id sent. The
    # bare socket took the first datagram that arrived, from anyone, as
    # this host's identity. retries=0 keeps the single attempt; the import
    # is local because nodepoll imports this module.
    from .nodepoll import _Session
    session = _Session(ip, DEFAULT_SNMP_PORT, timeout_s, 0)
    try:
        request_id = random.randint(1, 2 ** 16)
        packet = build_request(version, community, pdu, request_id, oids)
        return session.request(packet, expect_request_id=request_id)
    finally:
        session.close()


def _snmp_getnext_one(ip: str, version: int, community: str, timeout_s: float,
                      retries: int, oid: str):
    """One GETNEXT for the arc hop, with the sweep's own retry rule:
    (oid, type, value), or None when the agent signalled the end — an
    empty reply, endOfMibView/noSuchObject/noSuchInstance, or a non-zero
    error-status (a v1 agent's noSuchName past its last object). Raises
    SnmpError only when every attempt went unanswered, so the hop can say
    'timeout' and keep the arcs it already found."""
    last_error = None
    for _attempt in range(1 + max(0, int(retries))):
        try:
            response = _snmp_identify(ip, version, community, timeout_s, [oid],
                                      pdu=PDU_GETNEXT)
        except SnmpError as exc:
            last_error = exc
            continue
        if getattr(response, "error_status", 0) or not response.varbinds:
            return None
        vb = response.varbinds[0]
        if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
            return None
        return vb["oid"], vb["type"], vb["value"]
    raise last_error or SnmpError(f"no reply from {ip}")


class DiscoveryJob:
    def __init__(self, db: NodesDatabase, job_id: int, kind: str, target: str,
                settings: dict, log=None):
        self.db = db
        self.job_id = job_id
        self.kind = kind
        self.target = target
        self.settings = settings
        self.log = log or NullLog()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run_safe,
                                        name=f"discovery-{job_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def cancel(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    # ------------------------------------------------------------------

    def _run_safe(self) -> None:
        try:
            self._run()
        except SubnetTooLarge as exc:
            # Refused before a single packet was sent — nothing to
            # unwind, just record why.
            self.db.update_discovery_job(self.job_id, state="error",
                                         error=str(exc), finished_ts=time.time())
        except Exception as exc:
            # "Cannot operate on a closed database" while _stop is set (job
            # was cancel()led by NodePoller.stop()/shutdown()) means this
            # job ran past shutdown()'s drain window (bounded by
            # NodePoller._discovery_budget_s, not unlimited) and the
            # database closed under it -- an accepted, bounded consequence
            # of stopping promptly, not a bug. It does not get the
            # traceback below, which would read exactly like a crash in a
            # log an operator checks right after a service stop, and it
            # does not attempt the update_discovery_job call below either,
            # which would raise the identical way. The same exception for
            # any OTHER reason, or NOT during a stop, is still a real bug
            # and still gets the full treatment.
            if isinstance(exc, sqlite3.ProgrammingError) and self._stop.is_set():
                self.log.add(NODES, f"Discovery job #{self.job_id} stopped "
                                    f"when the service shut down; its state "
                                    f"was not saved")
                return
            # A discovery thread must never die quietly, mirroring the
            # same discipline NodePoller._run_one uses for poll workers.
            self.log.add(ERROR, f"Discovery job #{self.job_id} failed",
                         detail=traceback.format_exc())
            traceback.print_exc()
            try:
                self.db.update_discovery_job(
                    self.job_id, state="error",
                    error="internal error — see the event log", finished_ts=time.time())
            except Exception:
                pass  # best-effort; the failure itself is already logged above

    def _run(self) -> None:
        max_addresses = int(self.settings.get("max_scan_addresses", 1024))
        if self.kind == "subnet":
            addresses = usable_addresses(self.target, max_addresses)
        else:
            addresses = [self.target]
        self.db.update_discovery_job(self.job_id, total=len(addresses))

        communities = _candidate_communities(self.settings.get("discovery_communities"))
        # Per-scan overrides (the Start-discovery dialog) fall back to the
        # module defaults; they exist only in this job's settings dict and
        # never touch stored settings.
        default_timeout = float(self.settings.get("default_snmp_timeout_s", 3.0))
        snmp_timeout_s = float(
            self.settings.get("discovery_snmp_timeout_s") or default_timeout)
        ping_timeout_s = float(
            self.settings.get("discovery_ping_timeout_s") or default_timeout)
        snmp_retries = max(0, int(self.settings.get("discovery_snmp_retries") or 0))
        ping_retries = max(0, int(self.settings.get("discovery_ping_retries") or 0))
        groups = self.db.groups()

        # One bulk ping pass first, then SNMP per address — mirrors
        # ipam_scan.scan_subnet's own shape rather than interleaving. Extra
        # ping passes (per-scan retries) only revisit the addresses that
        # have not answered yet.
        # Pacing and the deny list, both from settings so a site can be
        # gentler than the default without a code change. `never_scan_cidrs`
        # is the list of networks this application must never put a probe
        # into at all — a plant segment full of PLCs whose stacks predate
        # the idea of an unsolicited packet.
        probes_per_second = float(self.settings.get(
            "discovery_probes_per_second") or DEFAULT_PROBES_PER_SECOND)
        never_scan = parse_never_scan(self.settings.get("never_scan_cidrs", ""))
        blocked = [ip for ip in addresses if is_never_scanned(ip, never_scan)]
        if blocked and len(blocked) == len(addresses):
            self.db.update_discovery_job(
                self.job_id, state="error", finished_ts=time.time(),
                error=f"Every address in {self.target} is inside the "
                      f"never-scan list, so nothing was probed.")
            return
        if blocked:
            self.log.add(NODES, f"Discovery of {self.target} skipped "
                                f"{len(blocked)} address(es) on the never-scan "
                                f"list")

        alive = sweep(addresses, timeout_ms=int(ping_timeout_s * 1000),
                      probes_per_second=probes_per_second,
                      never_scan=never_scan)
        for _ in range(ping_retries):
            if self._stop.is_set():
                break
            silent = [ip for ip in addresses if not alive.get(ip)]
            if not silent:
                break
            alive.update({ip: ok for ip, ok in
                          sweep(silent, timeout_ms=int(ping_timeout_s * 1000),
                                probes_per_second=probes_per_second,
                                never_scan=never_scan).items()
                          if ok})

        # The SNMP half is paced too, and by the same figure. A sweep that
        # walks away from ICMP at 200/s and then fires several community
        # guesses per responding address as fast as it can is still the
        # burst this exists to prevent — a PLC that survived the ping is
        # exactly the device most likely to fall over on the probes.
        snmp_interval = (1.0 / probes_per_second
                         if probes_per_second > 0 else 0.0)
        next_probe = time.monotonic()

        probed = responded = identified = 0
        for ip in addresses:
            if self._stop.is_set():
                self.db.update_discovery_job(self.job_id, state="cancelled",
                                             finished_ts=time.time())
                return
            probed += 1
            ping_ok = bool(alive.get(ip, False))
            if ping_ok:
                responded += 1

            # A device worth discovering might be SNMP-only with ICMP
            # filtered, so a single-device job always tries SNMP even on a
            # failed ping; a subnet sweep only bothers with addresses that
            # answered, or a /24 sweep would spend most of its time
            # probing SNMP against hundreds of genuinely dead addresses.
            result = {"ip": ip, "ping_ok": 1 if ping_ok else 0, "snmp_ok": 0}
            # An address on the never-scan list is still reported, so a
            # bounded sweep accounts for every address it was asked about;
            # it simply never had a packet sent to it. The one log line
            # above says how many those were.
            if is_never_scanned(ip, never_scan):
                pass
            elif ping_ok or self.kind == "device":
                if snmp_interval:
                    delay = next_probe - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    next_probe = time.monotonic() + snmp_interval
                identity = self._try_snmp(ip, communities, snmp_timeout_s,
                                          snmp_retries)
                if identity is not None:
                    identified += 1
                    result.update(identity)
                    result["snmp_ok"] = 1
                    result["suggested_group_id"] = nodeoids.suggest_group(
                        identity.get("sys_descr", ""), identity.get("sys_object_id", ""),
                        groups)
            self.db.add_discovery_result(self.job_id, **result)
            self.db.update_discovery_job(self.job_id, probed=probed,
                                         responded=responded, identified=identified)

        # A cancel that lands while the final (or only) address is being
        # probed exits the loop normally — the top-of-loop check never
        # sees it — so the flag decides the terminal state, not the loop.
        state = "cancelled" if self._stop.is_set() else "done"
        self.db.update_discovery_job(self.job_id, state=state,
                                     finished_ts=time.time())

    def _try_snmp(self, ip: str, communities: list[str], timeout_s: float,
                  retries: int = 0):
        """Default is still one shot per version/community combination (a
        retry per guess makes a subnet sweep crawl); extra attempts happen
        only when the Start-discovery dialog asked for them for this one
        scan."""
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        for version in (V2C, 0):   # try v2c first, fall back to v1
            for community in communities:
                response = None
                for _attempt in range(1 + retries):
                    if self._stop.is_set():
                        return None
                    try:
                        response = _snmp_identify(ip, version, community,
                                                  timeout_s, oids)
                        break
                    except SnmpError:
                        continue
                if response is None:
                    continue
                values = {vb["oid"]: vb["value"] for vb in response.varbinds
                         if vb["type"] not in ("noSuchObject", "noSuchInstance")}
                if not values:
                    continue
                sys_descr = values.get(nodeoids.SYSTEM_SCALARS["sys_descr"]) or ""
                sys_name = values.get(nodeoids.SYSTEM_SCALARS["sys_name"]) or ""
                sys_object_id = values.get(nodeoids.SYSTEM_SCALARS["sys_object_id"]) or ""
                result = {
                    "community_or_user": community,
                    "snmp_version": version,
                    "sys_descr": sys_descr,
                    "sys_name": sys_name,
                    "sys_object_id": sys_object_id,
                }
                result.update(self._identify_vendor(
                    ip, version, community, timeout_s, retries,
                    sys_object_id, sys_descr))
                return result
        return None

    def _identify_vendor(self, ip: str, version: int, community: str,
                         timeout_s: float, retries: int, sys_object_id: str,
                         sys_descr: str) -> dict:
        """The vendor half of a discovery result: the enterprise-arc hop
        ((arcs + 1) GETNEXTs, typically three to eight) and vendorid's
        decision over sysObjectID, the arcs and sysDescr. No MIB scoring here
        — that needs the poller's index and happens on the device's first
        poll after promotion. A hop that times out keeps the arcs it found;
        an address that answered the identity GET is never lost to the hop.

        Switched off by the discovery_arc_hop setting, in which case the
        result is exactly 4.31's: identify_vendor over sysObjectID/sysDescr,
        with nothing walked."""
        hop = None
        if self.settings.get("discovery_arc_hop", True):
            hop = vendorid.hop_enterprise_arcs(
                lambda oid: _snmp_getnext_one(ip, version, community, timeout_s,
                                              retries, oid))
        learned = self.db.learned_vendor(sys_object_id) \
            if hasattr(self.db, "learned_vendor") else ""
        decision = vendorid.decide(
            sys_object_id, sys_descr, hop.arcs if hop else [], [],
            learned=learned, catalog_arcs=mibcatalog.ARC_KEYS)
        evidence = vendorid.evidence(
            sys_object_id, "discovery", hop, {}, {}, [], decision, {},
            catalog_arcs=mibcatalog.ARC_KEYS)
        return {
            "vendor": decision.vendor,
            "vendor_source": decision.source,
            "vendor_confidence": decision.confidence,
            "suggest_bundle": decision.suggest_bundle,
            "arcs": json.dumps(hop.arcs if hop else []),
            "vendor_evidence": json.dumps(evidence),
        }

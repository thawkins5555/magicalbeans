from __future__ import annotations

import math
import random
import sqlite3
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from ..eventlog import ERROR, NODES, NullLog
from ..nodediscover import DiscoveryJob
from ..nodesdb import NodesDatabase, is_cisco
from ..worker import Worker, ago
from .discovery_mixin import DiscoveryMixin
from .poll_mixin import PollMixin
from .identify_mixin import VendorIdentifyMixin
from .environment_mixin import EnvironmentMixin
from .vendor_sensor_psu_mixin import VendorSensorPsuMixin
from .arp_mixin import ArpMixin
from .lldp_cdp_mixin import LldpCdpMixin
from .vlan_mixin import VlanMixin
from ._consts import _DEFAULT_POLL_COST, _POLL_COST_ALPHA, _POLL_COST_CEILING_S, _STAGGER_MIN_FRACTION, _STARTUP_SPREAD_S
from ._session import EngineCache, snmp_version_of


class NodePoller(Worker, DiscoveryMixin, PollMixin, VendorIdentifyMixin, EnvironmentMixin, VendorSensorPsuMixin, ArpMixin, LldpCdpMixin, VlanMixin):
    STOPPED_TEXT = "Poller stopped"
    THREAD_NAME = "node-poller"

    def __init__(self, db: NodesDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        self._init_threading()
        self._init_schedule_caches()
        self._init_discovery_state()
        self._init_sensor_caches()
        self._init_snmp_tuning()
        self._init_autoscale()
        self._init_credential_state()
        self.counters = {"polls": 0, "ok": 0, "timeout": 0, "auth_fail": 0,
                         # denied: the agent accepted the credential and
                         # refused the object (authorizationError) — counted
                         # apart from auth_fail because it is the opposite
                         # finding about the password.
                         "unsupported": 0, "denied": 0,
                         # downgraded: the device answered, below the level
                         # it was asked at, and the reply was refused unread
                         # — its own count because it is neither an auth
                         # failure (nothing contradicted the password) nor
                         # an error (nothing failed on this end).
                         "downgraded": 0,
                         "errors": 0, "overruns": 0, "snmp_backoff": 0,
                         "mac_walks": 0, "identifications": 0,
                         # lldp_walks counts completed LLDP/CDP walks;
                         # poe_polls/stp_polls/rf_polls count poll-cycle
                         # reads that produced data (a device whose
                         # capability probe was negative never bumps them).
                         "lldp_walks": 0, "poe_polls": 0, "stp_polls": 0,
                         "rf_polls": 0,
                         # vlan_walks: completed per-port VLAN membership
                         # walks, lldp_walks' own counter.
                         "vlan_walks": 0,
                         # arp_walks: completed ARP-cache walks that stored
                         # something — a device answering neither table
                         # does not count, the same way mac_walks does not
                         # count a switch that answered no forwarding table.
                         "arp_walks": 0}

    def _init_threading(self) -> None:
        """Executor/lock/stop-event plumbing."""
        # v3_verify_replies, read once per poll in _poll_device (settings()
        # is a query, and a walk is hundreds of exchanges) and carried here
        # for every v3 exchange that poll makes. True until a poll has read
        # the setting, because verified is the shipped default.
        self._verify_replies = True
        self._executor: ThreadPoolExecutor | None = None
        # Pools _apply_pool_size has swapped out and left to drain. They
        # still hold worker threads, so they still count towards capacity.
        self._draining: list[ThreadPoolExecutor] = []
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def _init_schedule_caches(self) -> None:
        """Per-device poll/walk scheduling state -- next-run and
        last-ping times, and the per-topic (MAC/LLDP/VLAN/ARP) walk
        cadence caches and their in-flight sets."""
        self._queued: dict[int, float] = {}
        self._started: dict[int, float] = {}
        self._next_run: dict[int, float] = {}
        self._staggered: set[int] = set()
        # device_id -> when it was last pinged, so ping_interval_s can
        # decouple ICMP probing from the SNMP poll cadence.
        self._last_ping: dict[int, float] = {}
        # device_id -> when its forwarding table was last walked, and which
        # walks are in flight. Its own cadence, well away from the poll
        # cycle: a switch's FDB is hundreds to thousands of rows and is
        # walked at most once per mac_table_interval_s, opt-in per profile.
        self._next_mac_walk: dict[int, float] = {}
        self._mac_running: set[int] = set()
        # device_id -> when its LLDP/CDP neighbour table was last walked, and
        # which walks are in flight. The topology walk's own cadence
        # (lldp_interval_s), mirroring _next_mac_walk/_mac_running exactly —
        # see _maybe_walk_lldp.
        self._next_lldp_walk: dict[int, float] = {}
        self._lldp_running: set[int] = set()
        # device_id -> when its per-port VLAN membership was last walked,
        # and which walks are in flight — _next_lldp_walk/_lldp_running's
        # own shape, its own cadence (vlan_interval_s), see _maybe_walk_vlans.
        self._next_vlan_walk: dict[int, float] = {}
        self._vlan_running: set[int] = set()
        # device_id -> when its ARP cache was last walked, and which walks
        # are in flight — _next_mac_walk/_mac_running's own shape, its own
        # cadence (arp_table_interval_s, shipped 0), see _maybe_walk_arp_table.
        self._next_arp_walk: dict[int, float] = {}
        self._arp_running: set[int] = set()
        # Devices whose last ARP walk stored nothing (answered neither
        # table, or was cut short), so that fact is logged once when it
        # becomes true and once when it stops being true — not on every
        # interval. The setting is opt-in, and an operator who turns it on
        # for a profile of L2-only switches would otherwise get one
        # "answers no ARP table" line per switch per cycle for as long as
        # it stayed on. See _run_arp_table.
        self._arp_unanswered: set[int] = set()

    def _init_discovery_state(self) -> None:
        """Engine cache, discovery/vendor-id job tables, and the
        cached merged per-device configs."""
        self._engines = EngineCache()
        self._discovery_jobs: dict[int, DiscoveryJob] = {}
        # Held across a whole discovery start — the "is one already running"
        # question, the job row, and the thread — so two HTTP threads asking
        # it at once cannot both be told no one is scanning this target.
        # Reentrant because the answer is also read on its own below.
        self._discovery_lock = threading.RLock()
        # device_id -> the whole-device OID walk running or last finished for
        # it. In memory and one-at-a-time per device, the same shape as
        # _discovery_jobs above: a walk result is transient, downloaded once
        # and then dropped.
        self._oid_walks: dict[int, "_OidWalkJob"] = {}
        # device_id -> its running or last vendor identification job, and
        # the MIB corpus index the fingerprint scores against, rebuilt only
        # when nodesdb.mib_generation() says the corpus changed.
        self._vendor_ids: dict[int, "_VendorIdJob"] = {}
        self._mib_index: tuple | None = None       # (generation, MibIndex)
        self._last_completed: float = 0.0
        # The merged per-device configs the scheduling pass reads, and the
        # nodesdb config generation and wall time they were built at.
        self._configs: dict | None = None
        self._configs_generation: int = -1
        self._configs_loaded: float = 0.0
        # db.settings(), held the same way _configs is -- see _cached_settings.
        self._settings_state: tuple[int, float, dict] | None = None
        # device_id -> when its ipAddrTable was last read. See
        # _refresh_addresses: once an hour, not once a poll.
        self._addresses_read: dict[int, float] = {}

    def _init_sensor_caches(self) -> None:
        """Environmental/PoE/vendor-sensor probe-once-remember caches."""
        # device_id -> when its ENTITY-SENSOR-MIB table was last walked.
        # See _poll_environment/_SENSOR_REFRESH_S: a fixed cadence, in
        # memory only, the same shape _addresses_read already uses for a
        # walk that answers something that does not change between one
        # poll and the next.
        self._sensor_read: dict[int, float] = {}
        # device_id -> when its entSensorThresholdTable was last walked. A
        # separate stamp from _sensor_read above because it runs an order of
        # magnitude less often: a DOM reading moves every poll, but the
        # limits a transceiver publishes change only when somebody pulls the
        # optic out. See _SENSOR_THRESHOLD_REFRESH_S.
        self._sensor_threshold_read: dict[int, float] = {}
        # device_id -> when the vendor temperature table was last walked
        # (_poll_vendor_sensors); PSU state is not gated by it.
        self._vendor_sensor_read: dict[int, float] = {}
        # (device_id, PsuTable.state) -> static PSU columns, _SENSOR_REFRESH_S TTL.
        self._vendor_psu_static: dict[tuple, dict] = {}
        # (device_id, PsuTable.state) -> indices the last COMPLETE walk
        # returned. See _mark_vendor_rows_absent.
        self._vendor_psu_seen: dict[tuple[int, str], set[str]] = {}
        # device_id -> last CISCO-STACKWISE-MIB walk time / capable flag (1/0/absent=unknown).
        self._stack_power_read: dict[int, float] = {}
        self._stack_power_capable: dict[int, int] = {}
        # device_id -> when the vendor table's own published thresholds
        # were last walked. See _SENSOR_THRESHOLD_REFRESH_S.
        self._vendor_sensor_threshold_read: dict[int, float] = {}
        # device_id -> when ifMauType was last walked/whether it answered,
        # probe-once-remember'd at the same _SENSOR_REPROBE_S cadence.
        self._mau_read: dict[int, float] = {}
        self._mau_capable: dict[int, bool] = {}
        # device_id -> when the ENTITY-MIB cage scan was last tried/whether
        # entPhysicalClass answered, probe-once-remember like _mau_read.
        self._cage_read: dict[int, float] = {}
        self._cage_capable: dict[int, bool] = {}
        # device_id -> when the per-VLAN STP pass (_cisco_vlan_stp) is next
        # due, and which walks are in flight -- _next_vlan_walk/_vlan_running's
        # own shape, off the poll pool on its own cadence (see
        # _maybe_walk_stp_vlan) instead of every single poll.
        self._next_stp_vlan_walk: dict[int, float] = {}
        self._stp_vlan_running: set[int] = set()
        # device_id -> per-VLAN STP detail, shape in _run_stp_vlan_pass.
        self._stp_vlan_cache: dict[int, dict] = {}
        # device_id -> whether a per-VLAN STP attempt has ever been made in
        # this process's lifetime, so _poll_stp runs it inline once (a
        # device's first sighting, mirroring the old probe-once latches)
        # rather than waiting a whole cadence for the first answer.
        self._stp_vlan_seen: set[int] = set()
        # device_id -> the last (dot1dStpTopChanges, dot1dStpTimeSinceChange)
        # pair _poll_stp read, so a topology change wakes the per-VLAN walk
        # immediately instead of waiting for its cadence.
        self._stp_topology_seen: dict[int, tuple] = {}
        self._stp_capable_reprobe: dict[int, float] = {}
        self._stp_flap_kick: dict[int, float] = {}
        # device_id -> {"map", "ts"}: dot1dBasePortIfIndex is a static
        # table, cached rather than re-walked every poll. See
        # _cached_bridge_port_map.
        self._bridge_port_map_cache: dict[int, dict] = {}
        # device_id -> {"map", "ts"}: bundle member -> Port-channel ifIndex,
        # the same static-table cadence as _bridge_port_map_cache. See
        # _cached_agg_map.
        self._agg_map_cache: dict[int, dict] = {}
        # device_id -> when UCD-SNMP was last tried/whether it answered,
        # probe-once-remember'd like _mau_read/_mau_capable.
        self._ucd_read: dict[int, float] = {}
        self._ucd_capable: dict[int, bool] = {}
        # device_id -> when a sensor-diagnostic event was last written for
        # it. See _log_sensor_diag.
        self._sensor_diag_ts: dict[int, float] = {}
        # (device_id, cause) -> when a media (SFP/DOM) diagnostic event was
        # last written for it. See _log_media_diag.
        self._media_diag_ts: dict[tuple[int, str], float] = {}

    def _init_snmp_tuning(self) -> None:
        """Per-device GETBULK/GET sizing memory and pool-saturation state."""
        # device_id -> the GETBULK repetition count that last worked for it.
        # A device that answers "tooBig" is retried at half as many rows, and
        # remembering that means the next walk starts where the last one
        # ended up rather than re-learning the same limit every time.
        self._bulk_repetitions: dict[int, int] = {}
        # device_id -> the GET varbind count that last worked for it — the
        # same idea as the line above, in the other direction: an agent
        # that answered "tooBig" to a 25-varbind GET is asked 12 next time.
        self._get_batch: dict[int, int] = {}
        # Forwarding-table walks run here, not on the poll pool: one walk is
        # hundreds to thousands of rows, and parking poll workers on them is
        # what made the pool saturate.
        self._mac_executor: ThreadPoolExecutor | None = None
        # When the pool first looked saturated, and whether that has been
        # reported. See _note_saturation.
        self._saturated_since: float | None = None
        self._saturation_reported = False
        # device_id -> an EWMA of how long its polls actually take. _run_one
        # already had both ends of that; this keeps the difference.
        # device_id -> how many consecutive cycles have skipped this
        # device's SNMP phase while it is down. See _snmp_backoff_due.
        self._snmp_backoff: dict[int, int] = {}
        self._poll_cost: dict[int, float] = {}
        self._poll_cost_mean: float = _DEFAULT_POLL_COST

    def _init_autoscale(self) -> None:
        """Cached settings and autoscaler working state."""
        # Cached at start()/reconfigure() rather than read per pass:
        # test_scheduler pins a steady pass at five SQL statements and
        # asserts it never reads the settings table.
        self._autoscale = {"auto": False, "min": 1, "max": 1, "headroom": 1.5}
        # The two walk limits, cached the same way and for the same reason:
        # a full poll of a switch makes about thirty column walks and each
        # read the settings table twice, on the shared nodes-db lock, for
        # constants. None until start()/reconfigure() has run, so a poller
        # driven directly (a script, a test) still reads the live value.
        self._walk_settings: dict | None = None
        self._manual_workers = 16
        # None = no ceiling computed yet, which is what _note_saturation
        # reads to behave exactly as it did before autoscaling existed.
        self._autoscale_ceiling: int | None = None
        self._autoscale_at: float = 0.0
        self._autoscale_resized_at: float = 0.0
        self._autoscale_demand: float = 0.0        # rolling max this window
        self._autoscale_want: int = 0              # last target computed
        self._autoscale_shrink_votes: int = 0
        self._autoscale_sat_since: float | None = None

    def _init_credential_state(self) -> None:
        """Alert engine hook, credential-candidate memory, and the
        per-device verdict sets the events block in _poll_device reads."""
        # Set by the application once the alert engine exists, so the poller
        # can raise a system alert about itself. Left None (and every use
        # guarded) so the poller runs standalone in tests and scripts.
        self.alert_engine = None
        # device_id -> index into db.credential_candidates(device) that last
        # worked, so a multi-credential profile costs an extra request only
        # on a device's first poll or after its cached credential stops
        # working. In memory and process-lifetime only, like EngineCache.
        self._credentials: dict[int, int] = {}
        # device_id -> when an on-demand credential probe last failed for it,
        # so a device that is simply down does not re-sweep its profile's
        # candidates on every dialog a human opens. See working_config().
        self._credential_probe_failed: dict[int, float] = {}
        # device_id -> (walked_at, sysDescr, sysUpTime ticks, chassis index | None)
        self._sw_walk_state: dict[int, tuple[float, str, int | None, int | None]] = {}
        # device_id set: devices whose SNMP is currently failing on
        # AUTHENTICATION. auth_fail is recorded on entering the set and
        # auth_ok only on leaving it, which is what makes both transitions --
        # see _poll_device for why the device row cannot answer that. In
        # memory and process-lifetime only, like _credentials above.
        self._auth_failing: set[int] = set()
        # The same shape for a device whose agent accepted the credential
        # and refused the object (SnmpAccessDenied): entering records
        # access_denied, leaving on a successful poll records access_ok.
        # In memory for the same reason _auth_failing is — see the events
        # block in _poll_device.
        self._access_denied: set[int] = set()
        # And once more for a device whose replies are refused as a
        # downgrade (SnmpDowngrade: answering, but below the level asked):
        # entering records snmp_downgrade, leaving on a poll whose reply
        # verified records snmp_verified.
        self._downgraded: set[int] = set()
        # Devices whose per-method lane events have been confirmed to exist
        # (or seeded) since this process started — see the events block in
        # _poll_device and nodesdb.has_method_events. One query per device
        # per process, then never again.
        self._method_seeded: set[int] = set()
        # device_id -> consecutive qualifying SNMP-failing polls (ping OK,
        # not an auth failure, not unsupported), gating the `snmp_error`
        # device event behind `snmp_fail_alert_after` — see _poll_device.
        # In memory and process-lifetime only, like _auth_failing above.
        self._snmp_failing_count: dict[int, int] = {}
        # (device_id, expires_ts, interval_s): the device currently selected
        # in a browser polls at interval_s until expires_ts. Renewed by the
        # frontend every refresh tick while selected, so it self-expires
        # when the tab is left or the browser closes — no cleanup path.
        self._focus: tuple[int, float, float] | None = None

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        settings = settings if settings is not None else self.db.settings()
        self._read_pool_settings(settings)
        self._executor = ThreadPoolExecutor(max_workers=self._initial_pool_size())
        self._mac_executor = ThreadPoolExecutor(
            max_workers=self._mac_walk_workers(settings),
            thread_name_prefix="mac-walk")
        self._spawn()

    def _read_pool_settings(self, settings: dict) -> None:
        """Cache the pool settings on the poller.

        Read here and not in the scheduling pass on purpose:
        tests/test_scheduler.py pins a steady pass at five SQL statements
        regardless of fleet size and asserts it never reads the settings
        table. reconfigure() runs on every Nodes settings save, so this
        cache cannot go stale.
        """
        # Bounded here as well as in nodesdb.save_settings, because this is
        # the point of USE and it is handed a dict rather than reading the
        # file: a caller with an unclamped dict must not be able to size the
        # pool past the ceiling the store would have enforced.
        cap = NodesDatabase.MAX_POLL_WORKERS
        floor = max(1, min(cap, int(settings.get(
            "poll_workers_min", settings.get("poll_workers", 16)) or 1)))
        ceiling = max(floor, min(cap, int(settings.get("poll_workers_max", 128)
                                          or floor)))
        self._autoscale = {
            "auto": bool(settings.get("poll_workers_auto", True)),
            "min": floor,
            "max": ceiling,
            "headroom": max(1.0, float(settings.get("poll_pool_headroom", 1.5) or 1.5)),
        }
        self._autoscale_ceiling = ceiling if self._autoscale["auto"] else None
        self._manual_workers = max(1, min(cap, int(
            settings.get("poll_workers", 16) or 1)))
        self._walk_settings = {
            "max_rows": int(settings.get("snmp_walk_max_rows", 16384) or 16384),
            "max_repetitions": int(
                settings.get("snmp_bulk_max_repetitions", 40) or 0),
        }

    def _walk_limits(self) -> tuple[int, int]:
        """(snmp_walk_max_rows, snmp_bulk_max_repetitions) for a walk about
        to start — from the cache _read_pool_settings fills, or from the
        settings table when there is none yet."""
        cached = self._walk_settings
        if cached is not None:
            return cached["max_rows"], cached["max_repetitions"]
        settings = self.db.settings()
        return (int(settings.get("snmp_walk_max_rows", 16384) or 16384),
                int(settings.get("snmp_bulk_max_repetitions", 40) or 0))

    def _cached_settings(self) -> dict:
        """db.settings(), rebuilt on the same trigger _configs uses. Read
        into a local like _walk_limits: begin_stop() can clear this mid-poll."""
        state = self._settings_state
        now = time.time()
        generation = self.db.config_generation()
        if state is None or generation != state[0] or now - state[1] > self._CONFIG_REFRESH_S:
            state = (generation, now, self.db.settings())
            self._settings_state = state
        return state[2]

    def _mac_walk_workers(self, settings: dict) -> int:
        return max(1, min(32, int(settings.get("mac_walk_workers",
                                               self._MAC_WALK_WORKERS) or 1)))

    def _apply_mac_pool_size(self, settings: dict) -> None:
        """Resize the walk pool on a settings save as well as at start().

        Read only in start() before this, so the new mac_walk_workers control
        did nothing at all until the poller was disabled and re-enabled --
        a setting that silently ignores you is worse than no setting.
        """
        want = self._mac_walk_workers(settings)
        current = getattr(self._mac_executor, "_max_workers", None)
        if self._mac_executor is None or current == want:
            return
        previous, self._mac_executor = self._mac_executor, ThreadPoolExecutor(
            max_workers=want, thread_name_prefix="mac-walk")
        previous.shutdown(wait=False)

    def _initial_pool_size(self) -> int:
        """Where the pool starts. With auto off that is poll_workers, exactly
        as before. With auto on it is the floor -- which on an upgraded
        install IS the operator's existing poll_workers, seeded by nodesdb's
        migration, so no fleet ever starts with fewer threads than it had."""
        if not self._autoscale["auto"]:
            return self._manual_workers
        return max(self._autoscale["min"],
                   min(self._autoscale["max"], self._manual_workers))

    def reconfigure(self, settings: dict) -> None:
        """Hot pool resize, matching Monitor.set_workers: build a new
        executor, swap it in, let the old one drain in-flight work rather
        than cancelling it. Starts/stops the loop only if `enabled`
        actually changed."""
        if settings.get("enabled", True):
            if not self.running:
                self.start(settings)
                return
            self._read_pool_settings(settings)
            self._apply_mac_pool_size(settings)
            workers = self._initial_pool_size()
            if self._autoscale["auto"]:
                # Auto keeps whatever size it has arrived at, only pulled
                # back inside the operator's new bounds. Snapping to the
                # floor on every unrelated settings save would throw away
                # everything the controller had learned.
                current = getattr(self._executor, "_max_workers", workers)
                workers = max(self._autoscale["min"],
                              min(self._autoscale["max"], current))
            if self._executor is not None and self._executor._max_workers == workers:
                return
            self._apply_pool_size(workers)
        elif self.running:
            self.stop()

    _MAC_WALK_WORKERS = 4

    def stop(self) -> None:
        """Fast: cancels queued work and returns without waiting for a poll
        already running to finish. Used for a hot restart (start() calls
        this first) and for an operator disabling Nodes polling from
        Settings on an HTTP thread, neither of which should block on the
        network — shutdown() below is the version that waits."""
        self.begin_stop()
        self._join()

    def begin_stop(self) -> None:
        self._stop.set()
        # Dropped here so _walk_limits/_cached_settings re-read live settings
        # instead of a stale cache while whatever is still draining finishes.
        self._walk_settings = None
        self._settings_state = None
        for job in list(self._discovery_jobs.values()):
            job.cancel()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._mac_executor:
            self._mac_executor.shutdown(wait=False, cancel_futures=True)
            self._mac_executor = None
        with self._lock:
            for pool in self._draining:
                pool.shutdown(wait=False, cancel_futures=True)
            self._draining.clear()
            # A cancelled future never reaches _run_one/_run_*_table's own
            # clear; _started is untouched since drain() still needs it.
            self._queued.clear()
            self._mac_running.clear()
            self._vlan_running.clear()
            self._arp_running.clear()
            self._lldp_running.clear()
            self._stp_vlan_running.clear()

    finish_stop = Worker._finish_stop_draining

    def _inflight_ids(self) -> set[int]:
        with self._lock:
            return set(self._queued) | set(self._started)

    def _running_discovery_jobs(self) -> list:
        """stop() already calls job.cancel() on each of these; a running job
        stops submitting addresses and drains what's in flight in parallel,
        landing within about one address's worth of work (see
        _discovery_budget_s) rather than finishing its whole sweep, which
        can be a subnet's worth of addresses and far too long to wait out
        here."""
        return [job for job in list(self._discovery_jobs.values()) if job.running]

    def drain(self, timeout_s: float) -> bool:
        """Wait for in-flight polls and discovery jobs to finish. True if
        they all did. The same shape as Monitor.drain (netpath/monitor.py)
        for the trace scheduler this class was copied from."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self._inflight_ids() and not self._running_discovery_jobs():
                return True
            time.sleep(0.05)
        return not self._inflight_ids() and not self._running_discovery_jobs()

    def _discovery_budget_s(self, job) -> float:
        """One address's worst case for a running discovery job, from its
        own settings dict -- not a model of the whole sweep (see
        _running_discovery_jobs), and still per-address, not per-worker: the
        pool's drain waits for all of them together, so the slowest single
        address is what bounds it. Two SNMP versions tried, a handful of
        community guesses each, plus the vendor arc hop
        (hop_enterprise_arcs: "typically three to eight" GETNEXTs, no
        retry of its own) are approximated as ten SNMP round trips rather
        than counted exactly -- a generous approximation, the same shape
        as a per-device poll's own budget below; DiscoveryJob._run_safe's
        guard (netpath/nodediscover.py) is the backstop for whatever this
        misses."""
        settings = job.settings
        default_timeout = float(settings.get("default_snmp_timeout_s", 3.0))
        snmp_timeout_s = float(settings.get("discovery_snmp_timeout_s") or default_timeout)
        ping_timeout_s = float(settings.get("discovery_ping_timeout_s") or default_timeout)
        snmp_retries = max(0, int(settings.get("discovery_snmp_retries") or 0))
        ping_retries = max(0, int(settings.get("discovery_ping_retries") or 0))
        return (ping_timeout_s * (1 + ping_retries)
               + snmp_timeout_s * (1 + snmp_retries) * 10)

    # A full poll's fixed part: the ping sweep (if enabled) plus a handful
    # of SNMP round trips that always happen (scalars, ifTable, ifXTable) —
    # not a page-by-page model of a GETBULK walk against a very-high-port-
    # count chassis, which _inflight_budget_s cannot see coming. _run_one's
    # guard is the backstop for whatever this approximation misses, exactly
    # as expected_budget's own docstring in tracer.py says of a trace.
    _SNMP_ROUND_TRIPS = 4

    def _inflight_budget_s(self, ceiling_s: float = 30.0) -> float:
        """The longest a currently in-flight poll could still legitimately
        run, per its own device's configured ping/SNMP timeouts and
        retries — the drain window shutdown() should honour before giving
        up on it. Capped so one misconfigured device cannot hang shutdown
        indefinitely. Mirrors Monitor._inflight_budget_s for the trace
        scheduler this class was copied from."""
        worst = 0.0
        for device_id in self._inflight_ids():
            try:
                device = self.db.device(device_id)
                if device is None:
                    continue
                config = self.db.effective_config(device)
            except Exception:
                continue
            budget = 0.0
            if config.get("ping_enabled"):
                budget += (int(config.get("ping_count", 3) or 1)
                          * (int(config.get("ping_timeout_ms", 1000) or 1000) / 1000))
            timeout_s = float(config.get("snmp_timeout_s", 3.0))
            retries = int(config.get("snmp_retries", 2))
            budget += timeout_s * (retries + 1) * self._SNMP_ROUND_TRIPS
            try:
                if len(self.db.credential_candidates(device)) > 1:
                    budget += self._PROBE_BUDGET_S
            except Exception:
                pass
            worst = max(worst, budget)
        for job in self._running_discovery_jobs():
            try:
                worst = max(worst, self._discovery_budget_s(job))
            except Exception:
                continue
        return min(worst, ceiling_s)

    def shutdown(self, drain_s: float = 0.0) -> None:
        """Same as stop(), but waits for whatever was already running to
        finish (or to hit its own worst-case budget) before returning, so
        the databases Service.shutdown() closes right after this are not
        closed under a poll still writing its result. See _run_one's
        except clause for the backstop when a poll still overruns even
        this."""
        self.stop()
        self.drain(max(drain_s, self._inflight_budget_s()))

    def _pool_capacity(self) -> int:
        """Worker threads that could be running a poll right now.

        The live pool plus every pool left draining: shutdown(wait=False)
        does not cancel, so a shrink from 128 to 80 leaves up to 128
        old-pool polls in flight, and counting only the live pool reported
        them as "120 busy ... of 80 worker(s)". A drained pool is dropped
        here, the only place that list is pruned.
        """
        with self._lock:
            draining = list(self._draining)
        alive = 0
        for pool in draining:
            live = sum(1 for thread in getattr(pool, "_threads", ())
                       if thread.is_alive())
            if live:
                alive += live
            else:
                with self._lock:
                    if pool in self._draining:
                        self._draining.remove(pool)
        workers = getattr(self._executor, "_max_workers", 0) if self._executor else 0
        return workers + alive

    def pool_state(self) -> dict:
        """How much of the poll pool is in use right now.

        Queued and running are counted separately: together against the
        pool size they produced gauges reading "48 of 32 busy".
        """
        with self._lock:
            busy = len(self._started)
            queued = len(self._queued)
        workers = self._pool_capacity()
        return {"busy": busy, "queued": queued, "workers": workers,
                "saturated": bool(workers and busy >= workers and queued),
                # Added beside the original four, never in place of them.
                "auto": bool(self._autoscale["auto"]),
                "floor": int(self._autoscale["min"]),
                "ceiling": int(self._autoscale["max"]),
                "demand": round(self._autoscale_want, 1)}

    # How many cycles in a row a down device may skip SNMP. Two skips then
    # one attempt is the ~3x cap: enough to take most of the cost out of a
    # site outage, short enough that a device whose SNMP recovers before its
    # ping does is still found within about three intervals.
    _SNMP_BACKOFF_SKIPS = 2

    def _snmp_backoff_due(self, device_id: int) -> bool:
        """Whether this cycle skips SNMP for a device that is down.

        Counts cycles rather than keeping a wall-clock next-run stamp, on
        purpose. _last_ping/ping_interval_s is a wall clock because it
        answers an operator's separate question ("ping less often than you
        poll"); reusing it here would let that setting silently change how
        SNMP backs off. A skip count is its own thing.
        """
        skipped = self._snmp_backoff.get(device_id, 0)
        if skipped >= self._SNMP_BACKOFF_SKIPS:
            self._snmp_backoff[device_id] = 0
            return False
        self._snmp_backoff[device_id] = skipped + 1
        return True

    def _record_poll_cost(self, device_id: int, elapsed: float) -> None:
        """Fold one poll's wall time into this device's mean, and the fleet's.

        Weighted rather than averaged because the pool has to be sized for
        what polls cost NOW: a device that just went down costs thirty times
        what it did an hour ago, and an average would take an hour to say so.
        """
        if elapsed < 0 or elapsed > _POLL_COST_CEILING_S:
            # A clock step, or a poll that outlived a shutdown drain. Either
            # way it describes the machine, not the device.
            return
        previous = self._poll_cost.get(device_id)
        cost = elapsed if previous is None else (
            _POLL_COST_ALPHA * elapsed + (1 - _POLL_COST_ALPHA) * previous)
        self._poll_cost[device_id] = cost
        self._poll_cost_mean = (
            _POLL_COST_ALPHA * cost + (1 - _POLL_COST_ALPHA) * self._poll_cost_mean)

    def _running_text(self) -> str:
        n = self.db.device_count()
        pool = self.pool_state()
        # The phrase "N busy and N queued of N worker(s)" is asserted
        # verbatim by tests/test_poll_write_path.py. Additions go after it.
        auto = (f" · auto {pool['floor']}-{pool['ceiling']}"
                if pool["auto"] else "")
        return (f"Polling {n} device(s) · {pool['busy']} busy and "
                f"{pool['queued']} queued of {pool['workers']} worker(s)"
                f"{auto} · last poll {ago(self._last_completed)}")

    def worker_state(self) -> dict:
        with self._lock:
            return {device_id: {"queued": self._queued.get(device_id),
                                "started": self._started.get(device_id)}
                    for device_id in set(self._queued) | set(self._started)}

    def next_runs(self) -> dict[int, float]:
        return dict(self._next_run)

    def poll_now(self, device_id: int, walks: bool = False) -> bool:
        """Submits this device to the worker pool now, ahead of its interval.
        True when it was queued, False when a poll for it was already queued
        or running — a click during an in-flight poll starts no second poll (the walks still run)."""
        # Also doubles as "try the sensor walk again": dropping the cadence
        # stamp skips both _SENSOR_REFRESH_S and the hourly reprobe window.
        self._sensor_read.pop(device_id, None)
        self._sensor_threshold_read.pop(device_id, None)
        self._vendor_sensor_read.pop(device_id, None)
        self._vendor_sensor_threshold_read.pop(device_id, None)
        self._mau_read.pop(device_id, None)
        self._cage_read.pop(device_id, None)
        self._ucd_read.pop(device_id, None)
        self._ucd_capable.pop(device_id, None)
        self._forget_vendor_psu_static(device_id)
        self._stack_power_read.pop(device_id, None)
        # And "start from nothing": an explicit retry is the one place a
        # per-device cache is discarded on request. The operator is asking
        # for the attempt the scheduler would make with no history — the
        # same one the Test button makes, which holds no cache — so the
        # cached SNMPv3 engine goes too. Had it always, the 5.8.1 field
        # report (three firewalls polled with a stale engine until the
        # service restarted) would have been self-diagnosing: the click
        # would have polled where the scheduler failed, instead of failing
        # identically. Before _submit, so a worker that starts on this
        # click cannot read the old entry first. The scheduler's own polls
        # keep the cache; _v3_exchange's timeout rule covers them.
        self._engines.invalidate(device_id)
        if walks:
            self._walk_now(device_id)
        return self._submit(device_id)

    def _queue_walk(self, device_id: int, interval: float, running: set,
                    next_walk: dict, run_fn, now: float) -> bool:
        """Queues one walk on `self._mac_executor` if its interval is on and
        no walk for this device is already in `running`. True when queued,
        False when the interval is off, the device is already in flight, or
        the submit itself failed (the in-flight mark is then undone)."""
        if interval <= 0:
            return False
        with self._lock:
            if device_id in running:
                return False
            running.add(device_id)
        next_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(run_fn, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                running.discard(device_id)
            return False
        return True

    # Same in-flight guard/executor as the scheduled MAC/LLDP/VLAN/ARP walks.
    def _walk_now(self, device_id: int) -> None:
        device = self.db.device(device_id)
        if device is None:
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        config = self.db.effective_config(device)
        if not config.get("snmp_enabled", True):
            return
        now = time.time()
        for interval_key, running, next_walk, run_fn in (
            ("mac_table_interval_s", self._mac_running,
             self._next_mac_walk, self._run_mac_table),
            ("lldp_interval_s", self._lldp_running,
             self._next_lldp_walk, self._run_lldp_table),
            ("vlan_interval_s", self._vlan_running,
             self._next_vlan_walk, self._run_vlan_table),
            ("arp_table_interval_s", self._arp_running,
             self._next_arp_walk, self._run_arp_table),
            (self._stp_vlan_cadence_s, self._stp_vlan_running,
             self._next_stp_vlan_walk, self._run_stp_vlan_walk_job),
        ):
            # A callable interval_key is the per-VLAN STP pass' own cadence
            # (never "off" the way a raw config lookup can be) rather than
            # a setting to read directly.
            interval = (interval_key(config) if callable(interval_key)
                       else float(config.get(interval_key) or 0))
            self._queue_walk(device_id, interval, running, next_walk, run_fn, now)

    def walk_vlans_now(self) -> dict:
        """The fleet-wide VLAN scan button: queues a VLAN walk for every
        enabled device with the walk on, reachable and not already walking.
        A device stays in `_vlan_running` from queue to finish, so a second
        click before the first round completes re-queues nothing pending."""
        if self._mac_executor is None:
            return {"running": False, "queued": 0, "already_running": 0, "skipped": 0}
        now = time.time()
        configs = self.db.effective_configs()
        queued = already_running = skipped = 0
        for row in self.db.schedule_rows():
            config = configs.get(row["id"])
            interval = float(config.get("vlan_interval_s") or 0) if config else 0
            if (config is None or interval <= 0
                    or not config.get("snmp_enabled", True)
                    or row["status"] == "down" or row["consecutive_fail"]):
                skipped += 1
                continue
            if self._queue_walk(row["id"], interval, self._vlan_running,
                                self._next_vlan_walk, self._run_vlan_table, now):
                queued += 1
            else:
                already_running += 1
        return {"running": True, "queued": queued,
               "already_running": already_running, "skipped": skipped}

    def set_focus(self, device_id: int, ttl_s: float, interval_s: float) -> None:
        """The device a browser has selected polls at interval_s until the
        TTL lapses. interval_s <= 0 (the setting's off switch) clears any
        focus instead. Pulls the device's next run forward so the first
        fast poll lands promptly rather than after the profile interval."""
        if interval_s <= 0:
            self._focus = None
            return
        now = time.time()
        self._focus = (device_id, now + ttl_s, interval_s)
        due = self._next_run.get(device_id)
        if due is not None and due > now + interval_s:
            self._next_run[device_id] = now + interval_s

    # ------------------------------------------------------------------ loop

    # A backstop behind the generation counter: a config change made
    # outside this process (a second copy of the app on the same file)
    # would not bump it, so the merged configs are rebuilt at least this
    # often regardless.
    _CONFIG_REFRESH_S = 60.0

    def _loop(self) -> None:
        """The scheduling thread. Every pass is guarded: this thread dying
        silently — which one transient database error was enough to do —
        stopped all polling with `poller.error` still None and the status
        strip still reading "Polling N devices". Now the failure is
        recorded, shown, and the thread keeps going."""
        while not self._stop.is_set():
            try:
                self._schedule_pass()
                if self.error:
                    self.log.add(NODES, "Polling scheduling recovered")
                    self.error = None
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                self.error = f"Poller scheduling failed: {message}"
                self._bump("errors")
                self.log.add(ERROR, self.error, detail=traceback.format_exc())
            self._stop.wait(1.0)

    def _schedule_pass(self) -> None:
        """One pass over the fleet: whose turn is it to be polled.

        Reads six columns per enabled device and nothing else. The merged
        per-device config — which used to be recomputed here once per
        device per second, four settings reads and a group read each — is
        held between passes and rebuilt only when nodesdb's config
        generation moves or the backstop expires.
        """
        now = time.time()
        generation = self.db.config_generation()
        if (self._configs is None or generation != self._configs_generation
                or now - self._configs_loaded > self._CONFIG_REFRESH_S):
            self._configs = self.db.effective_configs()
            self._configs_generation = generation
            self._configs_loaded = now
            self._forget_devices(set(self._configs))
        self._note_saturation(now)
        focus = self._focus
        # Little's Law, accumulated in the loop that is already running:
        # a device polled every `interval` seconds, each poll costing
        # `cost` seconds of a worker, occupies cost/interval of one worker
        # continuously. Summed over the fleet that is how many workers the
        # configured cadence actually requires. No extra query, no extra
        # iteration -- both terms are already in hand here.
        demand = 0.0
        for device in self.db.schedule_rows():
            device_id = device["id"]
            config = self._configs.get(device_id)
            if config is None:
                # Added since the last rebuild; it is picked up on the next
                # pass, because add_device bumped the generation.
                continue
            interval = config["poll_interval_s"]
            # The device selected in a browser polls faster (SNMP
            # devices only — a fast ping-only cadence shows nothing
            # new) until its focus TTL lapses.
            focused = (focus is not None and device_id == focus[0]
                       and now < focus[1] and config.get("snmp_enabled", True))
            if focused:
                interval = min(interval, focus[2])
            due = self._next_run.get(device_id)
            if due is None:
                last = device["last_poll_ts"]
                due = (last + interval) if last else now
                if last and now >= due:
                    due = now + random.uniform(0, min(interval, _STARTUP_SPREAD_S))
                self._next_run[device_id] = due
            elif due - now > interval:
                due = now + interval   # backward clock step
                self._next_run[device_id] = due
            if now >= due:
                pending = device_id in self._started or device_id in self._queued
                # Focus is left exact: it exists to make the selected device
                # feel live. A pending device is left alone too: pulling it
                # earlier while its last poll is still queued only logs an
                # overrun. The phase break waits for the first reschedule
                # that is neither.
                if focused or pending or device_id in self._staggered:
                    self._next_run[device_id] = now + interval
                else:
                    self._staggered.add(device_id)
                    self._next_run[device_id] = now + interval * random.uniform(
                        _STAGGER_MIN_FRACTION, 1.0)
                if pending:
                    # A poll slower than the fast focus cadence is
                    # expected, not an overrun worth logging — only
                    # blowing the device's own profile interval is.
                    if not (focused and interval < config["poll_interval_s"]):
                        self._record_overrun(device, now, config)
                else:
                    self._submit(device_id)
            demand += (self._poll_cost.get(device_id, self._poll_cost_mean)
                       / max(interval, 1.0))
            self._maybe_walk_mac_table(device, config, now)
            self._maybe_walk_lldp(device, config, now)
            self._maybe_walk_vlans(device, config, now)
            self._maybe_walk_arp_table(device, config, now)
            self._maybe_walk_stp_vlan(device, config, now)
        self._autoscale_pass(now, demand)

    # How long the pool has to look saturated before it is worth telling
    # somebody. A burst at the top of a poll cycle is normal; five minutes
    # of it means the pool is genuinely too small for the fleet.
    _SATURATION_S = 300.0

    # How often the pool's size is reconsidered, and how rarely it is
    # actually changed. The two are deliberately different numbers.
    #
    # Evaluating often is free -- it is arithmetic over dicts already in
    # hand -- and evaluating rarely would mean a site outage waited out the
    # interval before anyone noticed the fleet had got expensive.
    #
    # RESIZING often is not free. reconfigure() builds a whole new
    # ThreadPoolExecutor and calls shutdown(wait=False) on the old one,
    # which does not cancel running futures; the executor also keeps a
    # module-global entry per worker thread and an atexit handler. Once a
    # minute means at most one abandoned pool draining at a time. Seconds
    # apart would mean a heap of them.
    _AUTOSCALE_INTERVAL_S = 15.0
    _AUTOSCALE_COOLDOWN_S = 60.0
    # A target within this fraction of the current size is not worth a new
    # pool: 16 -> 17 is noise, not a decision.
    _AUTOSCALE_DEADBAND = 0.10
    _AUTOSCALE_DEADBAND_FLOOR = 2
    # Consecutive evaluations that must agree before shrinking. Growing
    # answers a fleet being polled late, which an operator can see; shrinking
    # answers nothing urgent at all, and every shrink abandons a pool.
    _AUTOSCALE_SHRINK_VOTES = 4
    # Saturation this long with the model still not asking for more means the
    # cost estimates are behind the truth -- the first seconds of an outage,
    # before any expensive poll has completed to move an EWMA. Push up anyway.
    _AUTOSCALE_RATCHET_S = 60.0

    def _autoscale_pass(self, now: float, demand: float) -> None:
        """Size the poll pool from what the fleet actually costs.

        Called once a second with this pass's demand figure; keeps the
        rolling maximum and acts on it at most every _AUTOSCALE_INTERVAL_S,
        resizing at most every _AUTOSCALE_COOLDOWN_S.

        The maximum rather than the latest sample: demand dips for a pass
        that happens to fall between due times, and sizing off a trough is
        how a pool ends up too small a second later.
        """
        settings = self._autoscale
        if not settings["auto"] or self._executor is None:
            # Nothing accumulates while auto is off, or the max since start
            # would be waiting for whoever switches it on later.
            self._autoscale_demand = 0.0
            self._autoscale_sat_since = None
            return
        if demand > self._autoscale_demand:
            self._autoscale_demand = demand

        # Saturation is sampled on EVERY pass, not at the evaluation instants
        # below, and any unsaturated pass resets the clock. Devices due on the
        # same pass are still submitted together (the stagger thins bursts, it
        # does not remove them), so saturation arrives in bursts; sampling only
        # every 15 s can land inside burst after burst and read that as
        # continuous, ratcheting the pool up against a model that was right.
        # It would then shrink on the votes, re-lock, and ratchet again --
        # an abandoned executor every couple of minutes, for ever.
        pool = self.pool_state()
        if pool["saturated"]:
            if self._autoscale_sat_since is None:
                self._autoscale_sat_since = now
        else:
            self._autoscale_sat_since = None

        if now - self._autoscale_at < self._AUTOSCALE_INTERVAL_S:
            return
        self._autoscale_at = now

        floor, ceiling = int(settings["min"]), int(settings["max"])
        current = getattr(self._executor, "_max_workers", floor)
        want = math.ceil(self._autoscale_demand * float(settings["headroom"]))
        self._autoscale_demand = 0.0

        # The corrective term, and the only one. Overruns are not usable
        # here: _record_overrun returns early for a device that is down or
        # failing, so the overrun counter goes quiet during exactly the
        # outage that makes the fleet expensive. Measured on a 300-device
        # fleet at half the workers it needed, the counter read zero while
        # 182 devices sat queued and p95 lateness was already 8.95 s on a
        # 15 s interval. Saturation is the signal that moves when it should.
        if (self._autoscale_sat_since is not None
                and now - self._autoscale_sat_since >= self._AUTOSCALE_RATCHET_S
                and want <= current):
            # Saturated without a break for a full minute while the model
            # still asks for no more: the cost estimates are behind the
            # truth, which is the first seconds of an outage before any
            # expensive poll has completed to move an EWMA. Push up anyway.
            want = current + max(1, current // 4)

        want = max(floor, min(ceiling, want))
        self._autoscale_want = want
        self._autoscale_ceiling = ceiling
        if want == current:
            self._autoscale_shrink_votes = 0
            return

        deadband = max(self._AUTOSCALE_DEADBAND_FLOOR,
                       int(current * self._AUTOSCALE_DEADBAND))
        if abs(want - current) < deadband and want > floor and want < ceiling:
            self._autoscale_shrink_votes = 0
            return

        if want < current:
            # Shrinking buys nothing an operator can see and costs an
            # abandoned pool, so it has to be asked for repeatedly.
            self._autoscale_shrink_votes += 1
            if self._autoscale_shrink_votes < self._AUTOSCALE_SHRINK_VOTES:
                return
            want = max(want, current - max(1, current // 4))
        else:
            self._autoscale_shrink_votes = 0
            want = min(want, max(current * 2, current + 1))

        if now - self._autoscale_resized_at < self._AUTOSCALE_COOLDOWN_S:
            return
        self._autoscale_shrink_votes = 0
        self._autoscale_resized_at = now
        self._apply_pool_size(want)
        self.log.add(NODES, f"Poll pool resized from {current} to {want} worker(s) "
                            f"(floor {floor}, ceiling {ceiling})")

    def _apply_pool_size(self, workers: int) -> None:
        """Swap in a pool of this size and let the old one drain.

        shutdown(wait=False) rather than cancel: a poll in flight is talking
        to a device and holds no lock this cares about, so letting it finish
        costs nothing, where cancelling it would leave a device unpolled for
        an interval and its result unrecorded.
        """
        workers = max(1, int(workers))
        previous, self._executor = self._executor, ThreadPoolExecutor(
            max_workers=workers)
        if previous is not None:
            previous.shutdown(wait=False)
            with self._lock:
                self._draining.append(previous)

    def _note_saturation(self, now: float) -> None:
        """Raise (and clear) a system alert when every poll worker is busy
        and devices are still waiting.

        Without it, a fleet that had outgrown poll_workers looked like a
        fleet of slow devices. The alert names the number to raise.
        """
        pool = self.pool_state()
        engine = self.alert_engine
        # With the pool sizing itself, saturation below the ceiling is the
        # controller's job and not news: it corrects within fifteen seconds,
        # and an alert about something the application is already fixing is
        # the kind of noise that teaches operators to stop reading alerts.
        # Only the ceiling being reached means a human has to do something.
        #
        # _autoscale_ceiling is None until the autoscaler has run, which is
        # also the case for a poller whose start() never ran -- that is how
        # tests/test_poll_write_path.py drives this method, and None keeps
        # the pre-autoscaling behaviour exactly.
        ceiling = self._autoscale_ceiling
        below_ceiling = ceiling is not None and pool["workers"] < ceiling
        if not pool["saturated"] or below_ceiling:
            if self._saturation_reported:
                clear = getattr(engine, "clear_system_occurrence", None)
                if clear is not None:
                    clear("poll_pool_saturated", "poller")
            self._saturated_since = None
            self._saturation_reported = False
            return
        if self._saturated_since is None:
            self._saturated_since = now
            return
        if self._saturation_reported or now - self._saturated_since < self._SATURATION_S:
            return
        self._saturation_reported = True
        raise_it = getattr(engine, "system_occurrence", None)
        if raise_it is None:
            return
        minutes = (now - self._saturated_since) / 60.0
        raise_it(
            "poll_pool_saturated", "poller", "Polling pool", severity=3,
            extra={"busy": pool["busy"], "queued": pool["queued"],
                   "workers": pool["workers"],
                   "saturated_minutes": round(minutes, 1),
                   # The evidence behind the number, so the alert says why
                   # the ceiling is where it is as well as that it was hit.
                   "auto": pool["auto"], "floor": pool["floor"],
                   "ceiling": pool["ceiling"], "demand": pool["demand"]},
            message=(
                f"The poll pool has been at its ceiling of {pool['workers']} "
                f"workers with {pool['queued']} device(s) waiting for "
                f"{minutes:.0f} minutes. Devices are being polled later than "
                f"their interval. Raise Nodes → Settings → Most poll worker "
                f"threads, lengthen the polling interval, or split the fleet "
                f"across instances."
                if ceiling is not None else
                f"Every one of the {pool['workers']} poll workers has "
                f"been busy with {pool['queued']} device(s) waiting for "
                f"{minutes:.0f} minutes. Devices are being polled later "
                f"than their interval. Raise Nodes → Settings → Poll worker "
                f"threads, or lengthen the polling interval."))

    def _forget_devices(self, keep: set) -> None:
        """Drop the per-device state of devices that no longer exist.

        Every one of these is keyed by device id and kept for the process
        lifetime, so without this a long-running install accumulates an
        entry per device ever deleted.
        """
        # list(cache) first: workers insert into _poll_cost and _snmp_backoff
        # from _run_one and _poll_device while this runs, and iterating one
        # live would raise "dictionary changed size during iteration" and
        # cost a scheduling pass.
        for cache in (self._next_run, self._last_ping, self._next_mac_walk,
                      self._next_lldp_walk, self._next_vlan_walk,
                      self._next_arp_walk, self._next_stp_vlan_walk,
                      self._stp_vlan_cache, self._stp_topology_seen,
                      self._stp_capable_reprobe, self._stp_flap_kick,
                      self._bridge_port_map_cache, self._agg_map_cache,
                      self._credentials, self._credential_probe_failed,
                      self._addresses_read, self._bulk_repetitions,
                      self._sensor_read, self._sensor_threshold_read,
                      self._vendor_sensor_read, self._vendor_sensor_threshold_read,
                      self._mau_read, self._mau_capable,
                      self._cage_read, self._cage_capable,
                      self._ucd_read, self._ucd_capable,
                      self._stack_power_read, self._stack_power_capable,
                      self._sensor_diag_ts, self._snmp_backoff,
                      self._snmp_failing_count, self._get_batch,
                      self._poll_cost, self._sw_walk_state):
            for device_id in [k for k in list(cache) if k not in keep]:
                cache.pop(device_id, None)
        # Tuple-keyed, so not in the loop above.
        for cache_key in [k for k in list(self._vendor_psu_static)
                          if k[0] not in keep]:
            self._vendor_psu_static.pop(cache_key, None)
        for cache_key in [k for k in list(self._vendor_psu_seen)
                          if k[0] not in keep]:
            self._vendor_psu_seen.pop(cache_key, None)
        for cache_key in [k for k in list(self._media_diag_ts)
                          if k[0] not in keep]:
            self._media_diag_ts.pop(cache_key, None)
        # Sets rather than dicts, so not in the loop above: the "logged
        # once" memory for a device that answers no ARP table, the stagger,
        # and the four per-device verdicts whose whole purpose is to make
        # the next poll's transition (auth_ok, access_ok, snmp_verified)
        # once rather than every cycle.
        for members in (self._arp_unanswered, self._staggered,
                        self._auth_failing, self._access_denied,
                        self._downgraded, self._method_seeded,
                        self._stp_vlan_seen):
            members.difference_update(
                [k for k in list(members) if k not in keep])
        with self._lock:
            for jobs in (self._oid_walks, self._vendor_ids):
                for device_id in [k for k in jobs if k not in keep]:
                    if not jobs[device_id].running:
                        jobs.pop(device_id, None)
        # Not keyed by device id at all: a finished sweep keeps its whole
        # settings dict, one _owners entry per address swept and a dead
        # Thread for the life of the process, and drain() walks the dict
        # every 50 ms. Running ones stay, the way a running walk job does.
        with self._discovery_lock:
            for job_id in [k for k, job in list(self._discovery_jobs.items())
                           if not job.running]:
                self._discovery_jobs.pop(job_id, None)
        self._engines.forget(keep)

    def _maybe_walk_mac_table(self, device, config: dict, now: float) -> None:
        """Queue a forwarding-table walk when this device's own interval has
        come round. Off (0) unless a profile or a device asks for it, so an
        upgrade adds no SNMP load anywhere until somebody opts in.

        Not started while the device is failing or SNMP-disabled: a walk of
        hundreds of OIDs against a box that is not answering is the poll
        overrun problem all over again, at ten times the size.
        """
        interval = float(config.get("mac_table_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_mac_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every opted-in switch at once.
            self._next_mac_walk[device_id] = now + random.uniform(0, interval)
            return
        if due - now > interval:
            due = self._next_mac_walk[device_id] = now + interval   # backward clock step
        if now < due:
            return
        with self._lock:
            if device_id in self._mac_running:
                return
            self._mac_running.add(device_id)
        self._next_mac_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_mac_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._mac_running.discard(device_id)

    def _maybe_walk_lldp(self, device, config: dict, now: float) -> None:
        """Queue an LLDP/CDP neighbour walk when this device's own interval
        has come round — _maybe_walk_mac_table's own scheduling, applied to
        lldp_interval_s instead of mac_table_interval_s, and sharing its
        executor: both are the same shape of thing (a whole-device table
        walk of hundreds of rows, off the poll pool), so there is no reason
        for a second thread pool to size separately."""
        interval = float(config.get("lldp_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_lldp_walk.get(device_id)
        if due is None:
            self._next_lldp_walk[device_id] = now + random.uniform(0, interval)
            return
        if due - now > interval:
            due = self._next_lldp_walk[device_id] = now + interval
        if now < due:
            return
        with self._lock:
            if device_id in self._lldp_running:
                return
            self._lldp_running.add(device_id)
        self._next_lldp_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_lldp_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._lldp_running.discard(device_id)

    def _maybe_walk_vlans(self, device, config: dict, now: float) -> None:
        """Queue a per-port VLAN membership walk when this device's own
        interval has come round — _maybe_walk_lldp's own scheduling, applied
        to vlan_interval_s instead of lldp_interval_s, sharing the same
        executor for the same reason: another whole-device table walk of
        hundreds of rows, off the poll pool."""
        interval = float(config.get("vlan_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_vlan_walk.get(device_id)
        if due is None:
            self._next_vlan_walk[device_id] = now + random.uniform(0, interval)
            return
        if due - now > interval:
            due = self._next_vlan_walk[device_id] = now + interval
        if now < due:
            return
        with self._lock:
            if device_id in self._vlan_running:
                return
            self._vlan_running.add(device_id)
        self._next_vlan_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_vlan_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._vlan_running.discard(device_id)

    def _maybe_walk_arp_table(self, device, config: dict, now: float) -> None:
        """Queue an ARP-cache walk when this device's own interval has come
        round — _maybe_walk_mac_table's own scheduling, applied to
        arp_table_interval_s, on the same executor for the same reason as
        the LLDP and VLAN walks: a whole-device table walk of hundreds to
        thousands of rows, off the poll pool, so a slow router's cache can
        never delay the sixty-second cycle. Off (0) unless a profile or a
        device asks for it — and here 0 really is the shipped value (see
        _merge_config), so an upgrade queues nothing anywhere.

        Not started while the device is failing or SNMP-disabled, for the
        reason _maybe_walk_mac_table gives, only more so: an ARP cache is
        the largest table this poller ever walks."""
        interval = float(config.get("arp_table_interval_s") or 0)
        if interval <= 0 or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        device_id = device["id"]
        due = self._next_arp_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every opted-in router at once.
            self._next_arp_walk[device_id] = now + random.uniform(0, interval)
            return
        if due - now > interval:
            due = self._next_arp_walk[device_id] = now + interval
        if now < due:
            return
        with self._lock:
            if device_id in self._arp_running:
                return
            self._arp_running.add(device_id)
        self._next_arp_walk[device_id] = now + interval
        try:
            self._mac_executor.submit(self._run_arp_table, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._arp_running.discard(device_id)

    def _maybe_walk_stp_vlan(self, device, config: dict, now: float) -> None:
        """Queue the Cisco per-VLAN STP walk (_cisco_vlan_stp) when this
        device's own cadence (_stp_vlan_cadence_s) has come round --
        _maybe_walk_vlans' own scheduling. _poll_stp still runs this pass
        inline on a device's first sighting and on a topology-change
        trigger (see _stp_topology_changed); this cadence only covers the
        routine refresh in between, off the poll pool.

        The _loop caller hands this schedule_rows()' narrow row (id, name,
        ip, status, consecutive_fail, last_poll_ts only -- no vendor, no
        stp_capable), so vendor/stp_capable are checked against a full row
        fetched only once due, not on every second-by-second scheduling
        pass; every other gate here uses only config, which is always the
        full merged one regardless of which row shape was handed in.
        """
        if not config.get("stp_enabled", True) or not config.get("snmp_enabled", True):
            return
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        if snmp_version_of(config) == 3 or not config.get("community"):
            return
        device_id = device["id"]
        interval = self._stp_vlan_cadence_s(config)
        due = self._next_stp_vlan_walk.get(device_id)
        if due is None:
            # First seen: spread the first walk over one interval so a
            # restart does not walk every capable switch at once.
            self._next_stp_vlan_walk[device_id] = now + random.uniform(0, interval)
            return
        if due - now > interval:
            due = self._next_stp_vlan_walk[device_id] = now + interval   # backward clock step
        if now < due:
            return
        self._next_stp_vlan_walk[device_id] = now + interval
        full = device if "stp_capable" in device.keys() else self.db.device(device_id)
        # stp_capable=0 means this device answers no dot1dStp at all -- not
        # a bridge, so it can never be a PVST+ one either; skip it the same
        # way _poll_stp's own early return does.
        if full is None or full["stp_capable"] == 0 or not is_cisco(full):
            return
        with self._lock:
            if device_id in self._stp_vlan_running:
                return
            self._stp_vlan_running.add(device_id)
        try:
            self._mac_executor.submit(self._run_stp_vlan_walk_job, device_id)
        except (RuntimeError, AttributeError):
            with self._lock:
                self._stp_vlan_running.discard(device_id)

    def _submit(self, device_id: int) -> bool:
        """True when this call put the device on the pool; False when it was
        already queued or running, or the pool has shut down."""
        with self._lock:
            if device_id in self._queued or device_id in self._started:
                return False
            self._queued[device_id] = time.time()
        try:
            self._executor.submit(self._run_one, device_id)
        except (RuntimeError, AttributeError):
            # The pool has shut down, or there is none (the scheduler being
            # exercised without one). Either way the device is not queued.
            with self._lock:
                self._queued.pop(device_id, None)
            return False
        return True

    def _record_overrun(self, device, now, config: dict | None = None) -> None:
        """Record that a poll was still running as the next one fell due.

        Not recorded while the device is not answering: a poll that spends
        its whole budget in timeouts and retries is the configured timeout
        doing exactly what it was told to, and the outage itself is already
        reported by device_down. status == "down" catches a formally down
        device; consecutive_fail > 0 catches the two or three polls before
        that, which is when the first overrun would otherwise fire — an
        overrun leads the outage, it does not follow it. Suppressed at
        source rather than filtered later, so no event row and no Debug
        line are written either (wirelessdb.out_of_service is the same
        shape).
        """
        if device["status"] == "down" or device["consecutive_fail"]:
            return
        self._bump("overruns")
        running_for = now - self._started.get(device["id"], now)
        if config is None:
            config = self.db.effective_config(device)
        interval = config["poll_interval_s"]
        self.log.add(ERROR, f"Poll overrun for {device['name'] or device['ip']}: "
                            f"still running after {running_for:.0f}s, interval is "
                            f"{interval}s — lengthen the interval or shorten the "
                            f"timeout.", target=device["ip"])
        self.db.record_device_event(device["id"], "poll_overrun",
                                    f"running {running_for:.0f}s")

    def _run_one(self, device_id: int) -> None:
        """Wrapped entirely in except Exception (a scheduler thread must
        never die quietly); finally always clears _queued/_started for
        this id regardless of outcome."""
        with self._lock:
            self._queued.pop(device_id, None)
            self._started[device_id] = time.time()
        try:
            device = self.db.device(device_id)
            if device is None or not device["enabled"]:
                return
            config = self.db.effective_config(device)
            self._bump("polls")
            self._poll_device(device, config)
        except Exception as exc:
            self._bump("errors")
            # Two shapes that are not bugs and so get no traceback:
            # "Cannot operate on a closed database" while _stop is set (this
            # poll ran past shutdown()'s drain window), and a foreign key
            # failure with the device now gone (deleted mid-poll). The same
            # exceptions for any other reason still get the full treatment.
            device_gone = False
            if isinstance(exc, sqlite3.IntegrityError):
                try:
                    device_gone = self.db.device(device_id) is None
                except Exception:
                    pass  # can't tell any more; falls through to the loud path
            if isinstance(exc, sqlite3.ProgrammingError) and self._stop.is_set():
                self.log.add(NODES, f"Poll of device #{device_id} finished after "
                                    f"the poller stopped; its result was not saved")
            elif device_gone:
                self.log.add(NODES, f"Device #{device_id} was deleted while its "
                                    f"poll was running; the result was not saved")
            else:
                self.log.add(ERROR, f"Node poll worker error for device #{device_id}",
                             detail=traceback.format_exc())
                traceback.print_exc()
        finally:
            finished = time.time()
            with self._lock:
                started = self._started.pop(device_id, None)
                self._last_completed = finished
            if started is not None:
                self._record_poll_cost(device_id, finished - started)


# EnvironmentMixin._scaled_sensor_value/_sensor_precision are
# @staticmethod and reference the bare name NodePoller (moved
# verbatim), which only exists once this class is built -- bound in
# here rather than imported there, to avoid importing this module
# from environment_mixin.py.
from . import environment_mixin as _environment_mixin
_environment_mixin.NodePoller = NodePoller

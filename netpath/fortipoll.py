"""WirelessPoller: polls each configured FortiGate Wireless Controller for
its managed APs over SNMP.

Reuses the Nodes poller's SNMP plumbing: `nodepoll._Session`,
`nodepoll.EngineCache` (keyed here by controller id), `credential_for()`
and `snmppoll`'s wire-format functions. v1/v2c/v3 at noAuthNoPriv or
authNoPriv: Nodes gained authPriv in 5.8.0 and this poller did not — the
controller form has no privacy field, and the API refuses a privacy
password for a controller in words rather than dropping it — because no
FortiGate deployment has asked for it and a half-wired level is worse
than an absent one. A signed reply's digest IS verified here since 5.8.0,
the same way Nodes verifies it.

Table walking uses GETBULK on v2c/v3 (5.49.0) and GETNEXT on v1, the same
split nodepoll's own walk makes, over the same wire-format functions --
a large FortiGate's per-AP/per-radio columns made this the same
request-count problem nodepoll's walk already solved.
"""

from __future__ import annotations

import random
import re
import sqlite3
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import nodeoids as oids
from .eventlog import ERROR, NullLog, WIRELESS
from .nodeoids import oid_key
from .nodepoll import EngineCache, _AuthFailure, _Session, credential_for, snmp_version_of, v3_exchange
from .snmppoll import PDU_GETBULK, PDU_GETNEXT, SnmpError, SnmpTimeout, build_request
from .wirelessdb import WirelessDatabase
from .worker import Worker

# Only decides whether a string is already in dotted form; it is not a
# validator for whether the address is routable.
_DOTTED_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Bounds on the per-AP ping sweep. The module's whole design is "talk to the
# controller, not to every AP", so measuring per-AP latency is the one place
# that reaches further — and it must not be able to stretch a poll cycle on a
# controller carrying a hundred radios.
PING_TIMEOUT_MS = 700
PING_BUDGET_S = 20.0

SNMP_PORT = 161

# Like nodepoll's _STARTUP_SPREAD_S: breaks the phase lock of controllers seeded due at 0 together.
POLL_SPREAD_S = 30.0

# nodepoll's own shipped default (snmp_bulk_max_repetitions) -- there is no
# per-controller equivalent setting here, so one constant serves every walk.
BULK_MAX_REPETITIONS = 40

# Same interval identify_mixin.py's _IDENTIFY_RETRY_S uses for its own
# bounded re-probe: a controller latched to GETNEXT-only is tried with
# GETBULK again this often, in case whatever refused or dropped it changed.
BULK_RETRY_S = 3600.0

# Same cap _walk_column has always enforced, now on rows rather than
# requests: one GETBULK response can carry many rows.
_WALK_MAX_ROWS = 4096


class WirelessPoller(Worker):
    STOPPED_TEXT = "Poller stopped"
    THREAD_NAME = "wireless-poller"

    def __init__(self, db: WirelessDatabase, log=None):
        self.db = db
        self.log = log or NullLog()
        self._engines = EngineCache()
        # controller id -> learned GETBULK max_repetitions, 0 = GETNEXT only
        # (a controller that ever answers tooBig at repetitions=1). Mirrors
        # nodepoll's own _bulk_repetitions.
        self._bulk_repetitions: dict[int, int] = {}
        # controller id -> when a 0 verdict above was last recorded, for the
        # hourly re-probe in _bulk_settings.
        self._bulk_last_probe: dict[int, float] = {}
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._queued: set[int] = set()
        # controller_id -> its Future while queued/running -- see begin_stop.
        self._queued_futures: dict[int, "Future"] = {}
        self._next_run: dict[int, float] = {}
        self._lock = threading.Lock()
        # db.settings(), rebuilt when db._settings_generation moves (see
        # _cached_settings) instead of read 3x per controller poll.
        self._settings_state: tuple[int, dict] | None = None
        self.counters = {"polls": 0, "ok": 0, "errors": 0}

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        self._next_run.clear()
        # Always the store's own read, not the `settings` argument: that can
        # be the Service's live dict, updated before it is saved/clamped.
        self._settings_state = (self.db._settings_generation, self.db.settings())
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._spawn()

    def _cached_settings(self) -> dict:
        """Rebuilt when db._settings_generation moves. Read into a local
        first: begin_stop() can clear this mid-poll from another thread."""
        state = self._settings_state
        generation = self.db._settings_generation
        if state is None or generation != state[0]:
            state = (generation, self.db.settings())
            self._settings_state = state
        return state[1]

    def stop(self) -> None:
        """Fast: cancels queued work and returns without waiting for a poll
        already running to finish. Used for a hot restart (start() calls
        this first) and for an operator disabling wireless polling from
        Settings on an HTTP thread — shutdown() below is the version that
        waits, the same split netpath/nodepoll.py's NodePoller makes."""
        self.begin_stop()
        self._join()

    def _inflight_ids(self) -> set[int]:
        with self._lock:
            return set(self._queued)

    def drain(self, timeout_s: float) -> bool:
        """Wait for in-flight polls to finish. True if they all did."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not self._inflight_ids():
                return True
            time.sleep(0.05)
        return not self._inflight_ids()

    # A controller that is not answering fails its first GETNEXT and
    # _poll_controller returns there (the walks share one outer try/except),
    # so a dead controller costs one timeout×(retries+1), not ten. A large
    # healthy controller's successful walk time is not bounded by a timeout
    # at all; _run_one's guard is the backstop for that.
    _SNMP_FAILURE_BUDGET_S = 3.0 * (2 + 1)   # _walk_column's _Session(..., 3.0, 2)

    def _inflight_budget_s(self, ceiling_s: float = 30.0) -> float:
        if not self._inflight_ids():
            return 0.0
        return min(PING_BUDGET_S + self._SNMP_FAILURE_BUDGET_S, ceiling_s)

    def shutdown(self, drain_s: float = 0.0) -> None:
        """Same as stop(), but waits for whatever was already running to
        finish (or hit its own worst-case budget) before returning, so the
        database Service.shutdown() closes right after this is not closed
        under a poll still writing its result."""
        self.stop()
        self.drain(max(drain_s, self._inflight_budget_s()))

    def begin_stop(self) -> None:
        self._stop.set()
        # Dropped so a poll still draining reads live settings, not a stale cache.
        self._settings_state = None
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
            with self._lock:
                # A cancelled future never reaches _run_one's own discard;
                # a still-running one is left alone for drain().
                for controller_id, future in list(self._queued_futures.items()):
                    if future.cancelled():
                        self._queued.discard(controller_id)
                        self._queued_futures.pop(controller_id, None)

    finish_stop = Worker._finish_stop_draining

    def poll_now(self, controller_id: int) -> None:
        with self._lock:
            if controller_id in self._queued or not self._executor:
                return
            self._queued.add(controller_id)
        try:
            future = self._executor.submit(self._run_one, controller_id)
        except RuntimeError:
            with self._lock:
                self._queued.discard(controller_id)
            return
        with self._lock:
            self._queued_futures[controller_id] = future

    def _loop(self) -> None:
        """Guarded like NodePoller._loop: one database error must not
        kill this thread silently."""
        while not self._stop.is_set():
            try:
                self._schedule_pass()
                if self.error:
                    self.log.add(WIRELESS, "Wireless polling scheduling recovered")
                    self.error = None
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                new_error = f"Wireless poller scheduling failed: {message}"
                if new_error != self.error:
                    self.log.add(ERROR, new_error, detail=traceback.format_exc())
                self.error = new_error
                self._bump("errors")
            self._stop.wait(1.0)

    def _first_due(self, last_poll_ts, now: float, interval: float) -> float:
        """A controller's first due time this process; jittered to break phase lock on restart."""
        if not last_poll_ts:
            return now
        jitter = random.uniform(0.0, min(POLL_SPREAD_S, interval))
        return max(last_poll_ts + interval, now + jitter)

    def _schedule_pass(self) -> None:
        settings = self.db.settings()
        if not settings.get("enabled", True):
            return
        interval = max(10, int(settings.get("poll_interval_s", 60)))
        now = time.time()
        controllers = self.db.controllers()
        for controller in controllers:
            controller_id = controller["id"]
            if not controller["enabled"]:
                self._next_run.pop(controller_id, None)
                continue
            due = self._next_run.get(controller_id)
            if due is None:
                due = self._next_run[controller_id] = self._first_due(
                    controller["last_poll_ts"], now, interval)
            elif due - now > interval:
                due = self._next_run[controller_id] = now + interval   # backward clock step
            if now >= due:
                self._next_run[controller_id] = now + interval
                self.poll_now(controller_id)
        # A deleted controller never appears in the loop above, so without
        # this its _next_run entry and v3 engine state are kept forever.
        live = {c["id"] for c in controllers}
        for gone in [cid for cid in self._next_run if cid not in live]:
            self._next_run.pop(gone, None)
        self._engines.forget(live)
        # A reused controller id must not inherit a stale GETBULK verdict.
        for gone in [cid for cid in self._bulk_repetitions if cid not in live]:
            self._bulk_repetitions.pop(gone, None)
            self._bulk_last_probe.pop(gone, None)

    def _run_one(self, controller_id: int) -> None:
        try:
            controller = self.db.controller(controller_id)
            if controller is None:
                return
            self._bump("polls")
            self._poll_controller(controller)
            self._bump("ok")
        except Exception as exc:
            self._bump("errors")
            # Two shapes that are not bugs and so get no traceback: "Cannot
            # operate on a closed database" while _stop is set (this poll ran
            # past shutdown()'s drain window), and a foreign key failure with
            # the controller now gone (deleted mid-poll). The same exceptions
            # for any other reason still get the full treatment.
            controller_gone = False
            if isinstance(exc, sqlite3.IntegrityError):
                try:
                    controller_gone = self.db.controller(controller_id) is None
                except Exception:
                    pass  # can't tell any more; falls through to the loud path
            if isinstance(exc, sqlite3.ProgrammingError) and self._stop.is_set():
                self.log.add(WIRELESS, f"Poll of controller {controller_id} finished "
                                       f"after the poller stopped; its result was "
                                       f"not saved")
            elif controller_gone:
                self.log.add(WIRELESS, f"Controller {controller_id} was deleted "
                                       f"while its poll was running; the result "
                                       f"was not saved")
            else:
                traceback.print_exc()
                self.log.add(ERROR, f"Wireless poll of controller {controller_id} failed",
                            detail=traceback.format_exc())
        finally:
            with self._lock:
                self._queued.discard(controller_id)
                self._queued_futures.pop(controller_id, None)

    # --------------------------------------------------------------- polling

    def _ping_ap(self, ip: str, status: str, ping_deadline: float = float("inf")) -> float | None:
        """Round-trip to one AP, or None.

        None means "no reading", which the column shows as blank: an AP that
        does not answer ICMP is not an AP with a 0 ms response, and storing 0
        would sort it to the top of the fastest devices. An offline AP is not
        probed at all — the controller has already said it is gone, and
        waiting out a timeout per absent AP is what would make the sweep slow.

        ping_deadline is the caller's, not self's: two controllers polled
        concurrently on the pool must not share one deadline.
        """
        if not ip or status != "online":
            return None
        if time.time() > ping_deadline:
            return None
        started = time.perf_counter()   # time.time() ticks at 15.6 ms on Windows, quantising a LAN round trip
        try:
            from .ipam_scan import ping_once
            ok = ping_once(ip, timeout_ms=PING_TIMEOUT_MS)
        except Exception:
            return None
        return (time.perf_counter() - started) * 1000.0 if ok else None

    def _poll_controller(self, controller) -> None:
        config = dict(controller)
        # Local to this poll, not self: controllers are polled concurrently
        # on the pool, and a shared attribute here would let one
        # controller's poll silently answer with another's setting.
        verify_replies = bool(self._cached_settings().get("v3_verify_replies", True))
        # One budget for the whole controller's sweep, so a rack of
        # unreachable APs cannot add a timeout each to the cycle.
        ping_deadline = time.time() + PING_BUDGET_S
        try:
            names = self._walk_column(controller, config, oids.WTP_CONFIG_NAME, verify_replies)
            macs = self._walk_column(controller, config, oids.WTP_SESSION_MAC, verify_replies)
            ips = self._walk_column(controller, config, oids.WTP_SESSION_IP, verify_replies)
            states = self._walk_column(
                controller, config, oids.WTP_SESSION_CONNECTION_STATE, verify_replies)
            models = self._walk_column(controller, config, oids.WTP_SESSION_MODEL, verify_replies)
            stations = self._walk_column(
                controller, config, oids.WTP_SESSION_STATION_COUNT, verify_replies)
            uptimes = self._walk_column(controller, config, oids.WTP_SESSION_UPTIME, verify_replies)
            session_uptimes = self._walk_column(
                controller, config, oids.WTP_SESSION_SESSION_UPTIME, verify_replies)
            profiles = self._walk_column(
                controller, config, oids.WTP_SESSION_PROFILE, verify_replies)
            modes = self._walk_column(controller, config, oids.WTP_RADIO_MODE, verify_replies)
            bssids = self._walk_column(controller, config, oids.WTP_RADIO_BSSID, verify_replies)
            channels = self._walk_column(controller, config, oids.WTP_RADIO_CHANNEL, verify_replies)
            powers = self._walk_column(
                controller, config, oids.WTP_RADIO_OPERATING_POWER, verify_replies)
            radio_stations = self._walk_column(
                controller, config, oids.WTP_RADIO_STATION_COUNT, verify_replies)
            widths = self._walk_column(
                controller, config, oids.WTP_PROFILE_RADIO_CHANNEL_WIDTH, verify_replies)
        except SnmpError as exc:
            self.db.record_poll(controller["id"], ok=False, error=str(exc))
            self.log.add(ERROR, f"Wireless controller {controller['name']} unreachable",
                        detail=str(exc))
            return

        # WTP_SESSION_* suffixes are "<vdomIndex>.<wtpIdLength>.<wtpId chars...>"
        # (WtpId is a string-valued table index, encoded the same way any
        # DisplayString index is in SNMP's OID-suffix convention); WTP_CONFIG_NAME
        # shares that same (vdom, wtpId) key. WTP_RADIO_* adds one more
        # trailing arc for the radio id.
        width_by_profile = _channel_widths(widths)
        now = time.time()
        seen: set[tuple[str, str]] = set()
        # This sweep's history samples, one executemany each at the end (record_samples).
        history_sample_s = float(self._cached_settings().get("history_sample_s", 300))
        ap_sample_rows: list[tuple] = []
        radio_sample_rows: list[tuple] = []
        for suffix, mac in macs.items():
            vdom_wtp = _split_vdom_wtp(suffix)
            if vdom_wtp is None:
                continue
            vdom, wtp_id = vdom_wtp
            seen.add((vdom, wtp_id))
            state_num = states.get(suffix)
            status = oids.CONNECTION_STATE.get(
                int(state_num) if state_num is not None else -1, "other")
            ip = _format_ip(ips.get(suffix))
            name = names.get(suffix) or wtp_id
            profile = str(profiles.get(suffix) or "")
            uptime_ticks = _as_int(uptimes.get(suffix))
            ap_id = self.db.upsert_ap(
                controller["id"], wtp_id, vdom,
                name=name,
                status=status,
                model=models.get(suffix) or "",
                mac_address=_format_mac(mac),
                ip=ip,
                response_ms=self._ping_ap(ip, status, ping_deadline),
                station_count=_as_int(stations.get(suffix)),
                profile=profile,
                # No reading, no timestamp: the two are only true together.
                uptime_ticks=uptime_ticks,
                uptime_ts=now if uptime_ticks is not None else None,
                session_uptime_ticks=_as_int(session_uptimes.get(suffix)))
            radios = []
            prefix = suffix + "."
            # Keyed off the mode column rather than the channel column: a
            # disabled or monitor-mode radio reports a mode but may report no
            # channel at all, and dropping it entirely is what made a
            # FAP-231F look like it had two radios when it has three.
            radio_suffixes = sorted(
                set(modes) | set(channels) | set(powers) | set(radio_stations))
            for radio_suffix in radio_suffixes:
                if not radio_suffix.startswith(prefix):
                    continue
                radio_id = radio_suffix[len(prefix):]
                channel = channels.get(radio_suffix)
                mode_num = modes.get(radio_suffix)
                radios.append({
                    "radio_id": radio_id,
                    "channel": str(channel) if channel is not None else None,
                    "mode": oids.RADIO_MODE.get(
                        int(mode_num) if mode_num is not None else -1, "other"),
                    "operating_power_dbm": _as_int(powers.get(radio_suffix)),
                    "station_count": _as_int(radio_stations.get(radio_suffix)),
                    "bssid": _format_mac(bssids.get(radio_suffix)) or None,
                    # Profile-radio table is keyed by profile name, so every AP on it reads the same row.
                    "channel_width": width_by_profile.get((vdom, profile, radio_id)),
                })
            self.db.replace_radios(ap_id, radios, controller_id=controller["id"],
                                   wtp_id=wtp_id, vdom=vdom, name=name)
            self._append_history(ap_id, status, _as_int(stations.get(suffix)),
                                 radios, now, ap_sample_rows, radio_sample_rows,
                                 history_sample_s)

        if ap_sample_rows or radio_sample_rows:
            self.db.record_samples(ap_sample_rows, radio_sample_rows)
        self.db.record_poll(controller["id"], ok=True)
        stale_after_polls = int(self._cached_settings().get("stale_after_polls", 5))
        removed = self.db.prune_stale(controller["id"], seen, stale_after_polls)
        for ap in removed:
            # prune_stale has already recorded the ap_removed row the
            # Alerts engine drains; this is the same fact in the event log,
            # where an operator watching the Debug feed will see it.
            self.log.add(WIRELESS,
                        f"AP {ap['name']} removed from {controller['name']}",
                        target=controller["ip"],
                        detail=f"wtp id   {ap['wtp_id']}\n"
                               f"vdom     {ap['vdom'] or '-'}\n"
                               f"missed   {ap['missed_polls']} consecutive poll(s)")

    def _append_history(self, ap_id, status, station_count, radios, now,
                        ap_sample_rows: list[tuple], radio_sample_rows: list[tuple],
                        history_sample_s: float = 300.0) -> None:
        """Appends one ap_samples row and one radio_samples row per radio, unless
        this AP's last sample is younger than history_sample_s."""
        last = self.db.last_sample_ts(ap_id)
        if last is not None and (now - last) < history_sample_s:
            return
        ap_sample_rows.append((ap_id, now, 1 if status == "online" else 0, station_count))
        for radio in radios:
            radio_sample_rows.append((
                ap_id, radio["radio_id"], now, radio.get("station_count"),
                radio.get("channel"), radio.get("operating_power_dbm")))

    # ------------------------------------------------------------ SNMP layer

    def _bulk_settings(self, controller, config: dict) -> tuple[bool, int]:
        """(use GETBULK, repetitions) for a walk of this controller -- the
        same per-controller memory nodepoll's own _bulk_settings keeps, so
        a controller that answered tooBig (or refused GETBULK outright) is
        not re-asked with it on every column of every poll; a GETNEXT-only
        verdict is retried with GETBULK again after BULK_RETRY_S."""
        if int(config.get("snmp_version") or 0) == 0:
            return False, 0
        controller_id = controller["id"]
        learned = self._bulk_repetitions.get(controller_id)
        if learned == 0:
            last_probe = self._bulk_last_probe.get(controller_id)
            if last_probe is None or time.time() - last_probe < BULK_RETRY_S:
                return False, 0
        return True, (learned or BULK_MAX_REPETITIONS)

    def _remember_repetitions(self, controller, repetitions: int, *,
                              use_bulk: bool = True) -> None:
        controller_id = controller["id"]
        self._bulk_repetitions[controller_id] = (
            max(1, int(repetitions)) if use_bulk else 0)
        if not use_bulk:
            self._bulk_last_probe[controller_id] = time.time()

    def forget_bulk_verdict(self, controller_id: int) -> None:
        """Clears a controller's learned GETBULK verdict, so an operator's
        Poll Now after fixing a path re-probes at once rather than waiting
        for the hourly retry."""
        self._bulk_repetitions.pop(controller_id, None)
        self._bulk_last_probe.pop(controller_id, None)

    def _walk_column(self, controller, config: dict, base_oid: str,
                     verify_replies: bool = True) -> dict[str, object]:
        values: dict[str, object] = {}
        current = base_oid
        controller_id = controller["id"]
        use_bulk, max_repetitions = self._bulk_settings(controller, config)
        # Only this walk's very first, never-tried request gets the timeout downgrade below.
        untried_first_request = use_bulk and controller_id not in self._bulk_repetitions
        # One socket for the whole walk, not one per row.
        session = _Session(controller["ip"], SNMP_PORT, 3.0, 2)
        hit_cap = False
        try:
            while True:
                pdu_tag = PDU_GETBULK if use_bulk else PDU_GETNEXT
                try:
                    response = self._snmp_walk_request(
                        controller, config, current, session, pdu_tag,
                        max_repetitions, verify_replies)
                except SnmpTimeout:
                    if not untried_first_request:
                        raise
                    # A large GETBULK reply can exceed path MTU on a tunnelled link.
                    use_bulk = False
                    response = self._snmp_walk_request(
                        controller, config, current, session, PDU_GETNEXT,
                        0, verify_replies)
                    self._remember_repetitions(controller, 0, use_bulk=False)
                untried_first_request = False
                if use_bulk and response.error_status == 1:   # tooBig
                    if max_repetitions <= 1:
                        use_bulk = False
                        self._remember_repetitions(controller, 0, use_bulk=False)
                    else:
                        max_repetitions = max(1, max_repetitions // 2)
                        self._remember_repetitions(controller, max_repetitions)
                    continue
                if use_bulk and response.error_status and not values:
                    # Any other error status (genErr etc.) before any row came back -- GETBULK is refused outright.
                    use_bulk = False
                    self._remember_repetitions(controller, 0, use_bulk=False)
                    continue
                if not response.varbinds:
                    break
                stop = False
                # GETBULK answers many rows per response, GETNEXT one -- both walk this same loop.
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base_oid or oid.startswith(base_oid + ".")):
                        stop = True
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                        stop = True
                        break
                    if oid_key(oid) <= oid_key(current):
                        # A stuck or malicious agent that never answers a later OID would spin forever otherwise.
                        stop = True
                        break
                    values[oid[len(base_oid) + 1:]] = vb["value"]
                    current = oid
                    if len(values) >= _WALK_MAX_ROWS:
                        hit_cap = True
                        stop = True
                        break
                if stop:
                    break
        finally:
            session.close()
        if hit_cap:
            self.log.add(WIRELESS, f"Table walk of {base_oid} on {controller['ip']} "
                                   f"stopped at the {_WALK_MAX_ROWS}-row cap",
                         target=controller["ip"])
        return values

    def _snmp_walk_request(self, controller, config: dict, oid: str,
                           session: "_Session", pdu_tag: int, max_repetitions: int,
                           verify_replies: bool = True):
        """One GETNEXT/GETBULK round trip on a session the caller owns
        (opened and closed once for the whole walk in _walk_column, not once
        per row). non_repeaters is always 0: every walk here is over a
        single column. `max_repetitions` is ignored by build_request/
        v3_exchange for a GETNEXT pdu_tag, so a v1 caller passes it unused."""
        version = snmp_version_of(config)
        if version in (0, 1):
            identity = credential_for(config).identity
            request_id = session.next_request_id()
            packet = build_request(version, identity or "public", pdu_tag,
                                   request_id, [oid], max_repetitions=max_repetitions)
            # The id filter is what makes a late reply to the previous
            # request a dropped datagram rather than this one's answer.
            return session.request(packet, expect_request_id=request_id)
        # Shared with NodePoller (engineTime, Report retry, msgID). The
        # priv args below are always None: controllers has no priv columns.
        credential = credential_for(config)
        controller_id = controller["id"]

        def learned(engine_id: bytes, boots: int, engine_time: int) -> None:
            self._engines.set(controller_id, engine_id, boots, engine_time)

        try:
            return v3_exchange(
                session, pdu_tag, [oid], identity=credential.identity,
                auth_proto=credential.auth_proto, password=credential.auth_password,
                engine=self._engines.current(controller_id),
                max_repetitions=max_repetitions,
                ip=controller["ip"], learned=learned,
                priv_proto=credential.priv_proto, priv_password=credential.priv_password,
                verify_replies=verify_replies)
        except _AuthFailure:
            self._engines.invalidate(controller_id)
            raise


def _split_vdom_name(suffix: str) -> tuple[str, str, str] | None:
    """'<vdomIndex>.<len>.<char>...[.<rest>]' -> (vdom, name, rest); name is WtpId or profile name."""
    parts = suffix.split(".")
    if len(parts) < 2:
        return None
    vdom = parts[0]
    try:
        length = int(parts[1])
        chars = parts[2:2 + length]
        if len(chars) != length:
            return None
        name = "".join(chr(int(c)) for c in chars)
    except (ValueError, IndexError):
        return None
    return vdom, name, ".".join(parts[2 + length:])


def _split_vdom_wtp(suffix: str) -> tuple[str, str] | None:
    parsed = _split_vdom_name(suffix)
    return None if parsed is None else (parsed[0], parsed[1])


def _channel_widths(values: dict[str, object]) -> dict[tuple[str, str, str], str]:
    """fgWcWtpProfileRadioChannelWidth keyed by (vdom, profile, radio id)."""
    widths: dict[tuple[str, str, str], str] = {}
    for suffix, value in values.items():
        parsed = _split_vdom_name(suffix)
        if parsed is None or not parsed[2]:
            continue
        vdom, profile, radio_id = parsed
        width = oids.CHANNEL_WIDTH.get(_as_int(value))
        if width:
            widths[(vdom, profile, radio_id)] = width
    return widths


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_ip(value) -> str:
    """fgWcWtpSessionWtpIpAddress is an InetAddress — four raw bytes for IPv4,
    sixteen for IPv6 — but by the time it reaches here snmppoll has already
    turned the octets into text: a non-printable string comes back as
    space-separated hex ("7F 00 00 01"), not as bytes. So the hex form is the
    normal case, and the dotted form (which some FortiOS builds send, and
    which the IpAddress type decodes to directly) is accepted as well.

    Anything that is neither becomes blank rather than a mangled address — a
    six-byte MAC, for instance, must not be stored as an IP and pinged.
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value or "").strip()
        if not text:
            return ""
        if _DOTTED_RE.match(text):
            return text
        groups = text.replace(":", " ").split()
        try:
            raw = bytes(int(g, 16) for g in groups if len(g) <= 2)
        except ValueError:
            return ""
        if len(raw) != len(groups):
            return ""
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
    return ""


def _format_mac(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return ":".join(f"{b:02x}" for b in value)
    return str(value or "")

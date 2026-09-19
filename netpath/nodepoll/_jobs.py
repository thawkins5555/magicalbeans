from __future__ import annotations

import threading
import time
import traceback
from .. import mibcatalog, nodeoids, vendorid
from ..eventlog import ERROR
from ..snmppoll import SnmpError, SnmpTimeout




class _OidWalkJob:
    """A whole-device SNMP walk, run on its own thread.

    Its own thread rather than the poll pool: a full walk of a core switch
    is tens of thousands of GETNEXTs and minutes of wall time, and parking
    one of four poll workers on it for that long would stall the devices
    behind it. Exactly one runs per device at a time — a second request
    while one is running is refused politely, the way backup_now does.
    """

    def __init__(self, poller, device_id: int, base: str, max_rows: int,
                 budget_s: float):
        self.poller = poller
        self.device_id = device_id
        self.base = base
        self.max_rows = max_rows
        self.budget_s = budget_s
        self.rows: list[dict] = []
        self.state = "starting"      # starting|running|done|failed
        self.stopped = ""
        self.error = ""
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.device_label = ""
        self._count = 0              # read without the lock by status()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "running")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"oid-walk-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self, with_rows: bool = False) -> dict:
        elapsed = (self.finished_ts or time.time()) - self.started_ts
        result = {"device_id": self.device_id, "state": self.state,
                  "rows": self._count, "elapsed": elapsed,
                  "stopped": self.stopped, "error": self.error,
                  "base": self.base, "started_ts": self.started_ts,
                  "complete": self.stopped == "end of subtree",
                  "device_label": self.device_label}
        if with_rows:
            result["walk"] = list(self.rows)
        return result

    def _run(self) -> None:
        try:
            device = self.poller.db.device(self.device_id)
            if device is None:
                raise ValueError("No such device")
            self.device_label = device["sys_name"] or device["name"] or device["ip"]
            config = self.poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")
            self.state = "running"

            # Progress only: _walk_from owns the list and hands it back
            # whole below, so a status() mid-walk reports a count without
            # racing a list another thread is appending to.
            def note(_row):
                self._count += 1

            rows, stopped = self.poller._walk_from(
                device, config, self.base, self.max_rows, self.budget_s,
                cancelled=self._cancel.is_set, on_row=note)
            self.rows = rows
            self._count = len(rows)
            self.stopped = stopped
            self.state = "done"
        except Exception as exc:                      # a job thread must not die quietly
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            self.poller.log.add(
                ERROR, f"OID walk failed for device #{self.device_id}: {self.error}",
                detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()


class _VendorIdJob:
    """One device's vendor identification, on its own thread.

    Off the poll pool for the same reason _OidWalkJob is: the bounded walk
    is up to a few hundred requests and ~20 s by budget, but a device that
    stops answering half way through pays its timeout per request on top,
    and on a 60 s profile that is an overrun parked on one of the pool's
    workers. Concurrency is capped by NodePoller._maybe_identify instead.
    """

    def __init__(self, poller, device_id: int, trigger: str):
        self.poller = poller
        self.device_id = device_id
        self.trigger = trigger
        self.state = "starting"          # starting|hopping|walking|done|failed
        self.started_ts = time.time()
        self.finished_ts: float | None = None
        self.requests = 0
        self.objects = 0
        self.arcs: list[int] = []
        self.error = ""
        self.decision = None
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.state in ("starting", "hopping", "walking")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"vendor-id-{self.device_id}", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def status(self) -> dict:
        return {"device_id": self.device_id, "state": self.state, "trigger": self.trigger,
                "elapsed": (self.finished_ts or time.time()) - self.started_ts,
                "requests": self.requests, "objects": self.objects,
                "arcs_found": list(self.arcs), "error": self.error,
                "decision": self.decision.json() if self.decision else None}

    def _run(self) -> None:
        poller = self.poller
        db = poller.db
        settings = db.settings()
        hop = None
        rows_by_arc: dict[int, list[str]] = {}
        capped: dict[int, bool] = {}
        candidates: list = []
        walk_info: dict = {}
        error = ""
        device = db.device(self.device_id)
        sys_object_id = (device["sys_object_id"] if device else "") or ""
        previous_attempts = 0
        try:
            if device is None:
                raise ValueError("No such device")
            evidence_before = vendorid._evidence_dict(device)
            if evidence_before.get("error"):
                previous_attempts = int(evidence_before.get("attempts") or 0)
            config = poller.working_config(device)
            if not config.get("snmp_enabled", True):
                raise ValueError("SNMP is disabled for this device")

            # The hop keeps the device's own retries: a missed hop loses an
            # arc. The walk below goes without them.
            self.state = "hopping"

            def getnext(oid):
                if self._cancel.is_set():
                    raise SnmpError("cancelled")
                self.requests += 1
                return poller._getnext_one(device, config, oid)

            hop = vendorid.hop_enterprise_arcs(getnext)
            self.arcs = list(hop.arcs)
            if hop.stopped == "timeout" and not hop.arcs:
                # The hop swallows a timeout on purpose so a partial answer
                # survives — but no answer at all is not an identification,
                # it is a device that did not reply. Recorded as an error so
                # the bounded retries apply instead of this counting as done.
                raise SnmpTimeout(f"no reply from {device['ip']} during the "
                                  f"identification walk")

            self.state = "walking"
            max_objects = int(settings.get("vendor_walk_max_objects", 500) or 500)
            budget_s = float(settings.get("vendor_walk_budget_s", 20.0) or 20.0)
            walk_config = {**config, "snmp_retries": 0}
            deadline = time.time() + budget_s
            walk_started = time.time()
            walk_requests = 0
            stopped = "complete"
            for arc in hop.arcs:
                remaining = max_objects - self.objects
                remaining_s = deadline - time.time()
                if remaining <= 0 or remaining_s <= 0:
                    stopped = ("stopped at the %d-object limit" % max_objects
                               if remaining <= 0 else "stopped after %.0fs" % budget_s)
                    break
                if self._cancel.is_set():
                    stopped = "cancelled"
                    break
                generic = arc in vendorid.GENERIC_ARCS
                per_arc = 20 if generic else min(vendorid.PER_ARC_OBJECTS, remaining)
                per_arc_s = min(vendorid.PER_ARC_BUDGET_S, remaining_s)

                def note(_row):
                    self.objects += 1

                rows, why = poller._walk_from(
                    device, walk_config, f"{nodeoids.ENTERPRISES}.{arc}",
                    max_rows=per_arc, budget_s=per_arc_s,
                    cancelled=self._cancel.is_set, on_row=note)
                walk_requests += len(rows) + 1
                rows_by_arc[arc] = [row["oid"] for row in rows]
                capped[arc] = len(rows) >= per_arc or why.startswith("stopped")
            self.requests += walk_requests
            if self._cancel.is_set():
                # What was gathered is kept and shown, but a cancelled walk
                # is not a verdict: it is recorded as incomplete, so the
                # dialog says so and the bounded retries still apply.
                error = "cancelled"
            walk_info = {"objects": sum(len(v) for v in rows_by_arc.values()),
                         "requests": walk_requests,
                         "elapsed_s": round(time.time() - walk_started, 2),
                         "stopped": stopped}
            candidates = vendorid.fingerprint(rows_by_arc, poller._mib_index_cached())
        except Exception as exc:              # a job thread must not die quietly
            error = ("cancelled" if self._cancel.is_set()
                     else (str(exc) or exc.__class__.__name__))
            if not isinstance(exc, (SnmpError, ValueError)):
                poller.log.add(ERROR, f"Vendor identification failed for device "
                                      f"#{self.device_id}: {error}",
                               detail=traceback.format_exc())
        try:
            device = db.device(self.device_id)
            if device is None:
                self.state = "failed"
                return
            decision = vendorid.decide(
                sys_object_id, device["sys_descr"] or "", hop.arcs if hop else [],
                candidates, manual=device["vendor_override"] or "",
                learned=db.learned_vendor(sys_object_id),
                catalog_arcs=mibcatalog.ARC_KEYS)
            self.decision = decision
            evidence = vendorid.evidence(
                sys_object_id, self.trigger, hop, rows_by_arc, capped, candidates,
                decision, walk_info, catalog_arcs=mibcatalog.ARC_KEYS, error=error,
                attempts=previous_attempts + 1)
            db.record_identification(self.device_id, decision, evidence, sys_object_id)
            poller._apply_identification(self.device_id, decision, error)
            self.error = error
            self.state = "failed" if error else "done"
        except Exception as exc:
            self.error = str(exc) or exc.__class__.__name__
            self.state = "failed"
            poller.log.add(ERROR, f"Vendor identification could not be recorded for "
                                  f"device #{self.device_id}: {self.error}",
                           detail=traceback.format_exc())
        finally:
            self.finished_ts = time.time()
            poller._bump("identifications")


class DiscoveryBusy(RuntimeError):
    """A sweep of this target is already on the wire. Raised by
    start_discovery(refuse_if_target_running=True) rather than answered as a
    return value, so a caller cannot mistake a refusal for a job id."""

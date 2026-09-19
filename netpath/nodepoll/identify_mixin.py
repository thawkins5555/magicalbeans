from __future__ import annotations

import time
from .. import nodeoids, vendorid
from ..eventlog import NODES
from ..snmppoll import PDU_GETBULK, PDU_GETNEXT, SnmpError, SnmpTimeout
from ._decode import _oid_key, interface_speed_bps
from ._jobs import _VendorIdJob
from ._session import Credential, _Session, _error_status_reason, _with_dropped, credential_for, snmp_version_of


class VendorIdentifyMixin:

    # ------------------------------------------------ vendor identification

    _IDENTIFY_RETRY_S = 3600.0
    _IDENTIFY_MAX_ATTEMPTS = 3

    def _getnext_one(self, device, config: dict, oid: str):
        """One GETNEXT for the arc hop: (oid, type, value), or None when the
        agent signalled the end. _snmp_get_next does not check error_status
        — a v1 agent answers a probe past its last object with noSuchName
        and the request OID echoed back, which would read as a loop — so the
        end conditions live here, where vendorid.hop_enterprise_arcs expects
        them."""
        response = self._snmp_get_next(device, config, oid)
        if getattr(response, "error_status", 0):
            return None
        if not response.varbinds:
            return None
        vb = response.varbinds[0]
        if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
            return None
        return vb["oid"], vb["type"], vb["value"]

    def _mib_index_cached(self):
        """The MIB corpus as vendorid wants it, rebuilt only when the corpus
        changed. Identification is rare, so even a rebuild per run would do;
        the cache is for a bulk Re-identify of a few hundred devices."""
        generation = self.db.mib_generation()
        with self._lock:
            cached = self._mib_index
            if cached is not None and cached[0] == generation:
                return cached[1]
        index = vendorid.build_mib_index(self.db.enterprise_objects(), self.db.mib_files())
        with self._lock:
            self._mib_index = (generation, index)
        return index

    def _identification_due(self, device, sys_object_id: str, now: float) -> bool:
        """Whether this device needs (another) identification walk: never
        identified, identified for a different sysObjectID, or the last run
        failed and it is time for one of the bounded retries. A device
        identified for its current sysObjectID returns False before any I/O
        — that is the "zero steady-state traffic" rule."""
        if device["identified_ts"] is None:
            return True
        if (device["identified_sys_object_id"] or "") != (sys_object_id or ""):
            return True
        evidence = vendorid._evidence_dict(device)
        if evidence.get("error"):
            attempts = int(evidence.get("attempts") or 0)
            last = float(evidence.get("ts") or 0)
            return attempts < self._IDENTIFY_MAX_ATTEMPTS and \
                now - last >= self._IDENTIFY_RETRY_S
        return False

    def _maybe_identify(self, device_id: int, identity, config: dict, settings) -> None:
        """Start the bounded identification walk for a device whose poll just
        succeeded, when it is due and there is room. Called from the poll
        worker but starts a separate thread; see _VendorIdJob."""
        if not identity or not settings.get("vendor_walk_enabled", True):
            return
        if not config.get("snmp_enabled", True):
            return
        device = self.db.device(device_id)
        if device is None:
            return
        if not self._identification_due(device, identity.get("sys_object_id") or "",
                                        time.time()):
            return
        limit = int(settings.get("vendor_walk_parallel", 4) or 4)
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return
            running = sum(1 for j in self._vendor_ids.values() if j.running)
            if running >= limit:
                return           # the next poll tries again; identified_ts stays NULL
            trigger = ("sysobjectid_changed" if device["identified_ts"] is not None
                       and not vendorid._evidence_dict(device).get("error")
                       else "first_poll")
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        job.start()

    def start_identify(self, device_id: int, trigger: str = "manual") -> dict:
        """Re-identify on demand: forget the previous verdict so the next
        poll would walk anyway, and start the walk now. Refused politely
        while one is already running for this device."""
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        if not self.db.effective_config(device).get("snmp_enabled", True):
            raise ValueError("SNMP is disabled for this device")
        with self._lock:
            job = self._vendor_ids.get(device_id)
            if job is not None and job.running:
                return job.status()
            job = _VendorIdJob(self, device_id, trigger)
            self._vendor_ids[device_id] = job
        self.db.clear_identification(device_id)
        # Sensor plausibility depends on vendor (_cisco_sensor_table_plausible),
        # so a re-identification invalidates an old "no sensors" verdict.
        self.db.set_sensor_capable(device_id, None)
        self.db.set_vendor_sensor_capable(device_id, None)
        self._sensor_read.pop(device_id, None)
        self._sensor_threshold_read.pop(device_id, None)
        self._vendor_sensor_read.pop(device_id, None)
        self._vendor_sensor_threshold_read.pop(device_id, None)
        self._forget_vendor_psu_static(device_id)
        self._stack_power_read.pop(device_id, None)
        job.start()
        return job.status()

    def identify_status(self, device_id: int) -> dict | None:
        job = self._vendor_ids.get(device_id)
        return job.status() if job else None

    def identifying(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        return job is not None and job.running

    def cancel_identify(self, device_id: int) -> bool:
        job = self._vendor_ids.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def _apply_identification(self, device_id: int, decision, error: str = "") -> None:
        """After a walk: coverage and MIB assignment against the decided arc,
        and one event saying what was decided and why."""
        device = self.db.device(device_id)
        if device is None:
            return
        identity = {"sys_object_id": device["sys_object_id"] or "",
                    "sys_descr": device["sys_descr"] or "",
                    "vendor_detected": decision.vendor, "vendor": decision.vendor,
                    "vendor_arc": decision.vendor_arc,
                    "preferred_mib_file_id": decision.mib_file_id}
        self._check_vendor_mib(device_id, device, identity)
        label = decision.vendor or "unidentified"
        text = (f"{label} via {decision.source} ({decision.confidence}): {decision.reason}"
                if decision.source else f"unidentified: {decision.reason}")
        if error:
            text += f" — walk incomplete: {error}"
        self.db.record_device_event(device_id, "identified", text)

    def _poll_custom_mib(self, device, config: dict, mib_file_id: int) -> list[tuple]:
        """A device or its polling profile can be assigned one uploaded
        MIB (nodesdb's mib_file_id override); this polls that MIB's own
        resolved *scalar* objects and reports them under its own names —
        the same best-effort shape as the UCD-SNMP-MIB block above (one
        failed GET never fails the whole poll; a device that doesn't
        answer any of this MIB's objects just contributes nothing).

        mibparse stores an OBJECT-TYPE's OID as its MIB clause names it, so
        the instance to GET is that OID plus the standard ".0" — the same
        convention nodeoids.SYSTEM_SCALARS' hand-written OIDs bake in. Table
        objects are out of scope: ".0" on a table column always misses, and
        so contributes nothing rather than raising.

        Read in batches of _CUSTOM_MIB_BATCH, halving on a tooBig(1)
        Response the way _walk_column_detail already halves a GETBULK and
        remembering the size that worked beside the walk's own learned
        repetition count. One GET of every object in the file is how this
        silently produced nothing at all: IP-MIB alone is 267 varbinds,
        most agents answer tooBig well below that, and RFC 3416 has a
        tooBig Response carry an empty varbind list — no metric, no error,
        one wasted round trip per device per poll."""
        objects = [o for o in self.db.mib_objects(mib_file_id, resolved_only=True)
                  if not o["is_notification"]]
        if not objects:
            return []
        instance_oids = [f"{o['oid']}.0" for o in objects]
        metrics = []

        def read_mib_objects():    # best-effort: this device may answer none
            values = self._custom_mib_values(device, config, instance_oids)
            for obj, instance_oid in zip(objects, instance_oids):
                vb = values.get(instance_oid)
                if not vb or vb["type"] in ("noSuchObject", "noSuchInstance"):
                    continue
                if not isinstance(vb["value"], (int, float)):
                    continue   # a string/OID-valued object isn't a chartable metric
                # Always "gauge": a Counter-typed object is charted at its
                # raw value, not a rate. A rate needs a per-metric baseline
                # (see counter_rate), which an arbitrary admin-picked MIB
                # object does not get.
                metrics.append((f"mib_{obj['name']}", obj["name"], "", "gauge", vb["value"]))

        self._best_effort(f"Custom MIB read for {device['ip']}", read_mib_objects)
        return metrics

    # The conventional safe varbind count for one GET; halved per device
    # and remembered whenever an agent answers tooBig.
    _CUSTOM_MIB_BATCH = 25

    def _custom_mib_values(self, device, config: dict,
                           instance_oids: list[str]) -> dict:
        """oid -> varbind for a whole MIB's scalars, in batches this device has been shown to cope with. One session for the whole read, like _poll_interfaces: opening one per call cost IP-MIB's 267 objects eleven ephemeral ports and twenty-two key derivations a poll."""
        device_id = device["id"]
        batch = self._get_batch.get(device_id) or self._CUSTOM_MIB_BATCH
        values: dict = {}
        index = 0
        credential = credential_for(config)
        session = self._session_for(device, config)
        try:
            while index < len(instance_oids):
                chunk = instance_oids[index:index + batch]
                response = self._snmp_get_on(session, device, config, chunk,
                                             credential=credential)
                if response.error_status == 1 and len(chunk) > 1:    # tooBig
                    batch = max(1, batch // 2)
                    self._get_batch[device_id] = batch
                    continue
                values.update({vb["oid"]: vb for vb in response.varbinds})
                index += len(chunk)
        finally:
            session.close()
        return values

    # Without a budget, a device the walk enumerated but whose
    # per-interface GETs stop answering costs N x timeout x (retries + 1) on
    # one poll worker — over an hour for a large chassis. Half the device's
    # own poll interval, with a floor so a 3-second focus poll still reads.
    _INTERFACE_BUDGET_FRACTION = 0.5
    _INTERFACE_BUDGET_FLOOR_S = 3.0
    # The same shape for a column walk that was given no deadline of its
    # own, and a ceiling on what one walk may retain: 16,384 rows of MAC
    # addresses is well under a megabyte, while 16,384 rows of 64 KB octet
    # strings is three gigabytes on one poll worker.
    _WALK_BUDGET_FRACTION = 0.5
    _WALK_BUDGET_FLOOR_S = 10.0
    _WALK_MAX_BYTES = 4 * 1024 * 1024
    _INTERFACE_GIVE_UP_TIMEOUTS = 3
    _MAX_INTERFACES = 512

    def _v1_get_dropping_unknown(self, device, config: dict, oids: list,
                                 max_drops: int = 3, *, session: _Session,
                                 credential: Credential | None = None) -> dict:
        """A GET against an SNMPv1 agent, minus the objects it does not
        implement.

        v1 has no per-varbind noSuchObject: an agent asked for one object
        it does not have answers the WHOLE request with error-status 2
        (noSuchName), error-index naming the offender, and echoes every
        varbind back as a null. The offending varbind is dropped and the
        request re-sent, up to `max_drops` times — beyond that the device
        is answering nothing useful and the interface is skipped, rather
        than the poll spending one round trip per column.
        """
        remaining = list(oids)
        for _ in range(max_drops + 1):
            if not remaining:
                return {}
            response = self._snmp_get_on(session, device, config, remaining,
                                         credential)
            if response.error_status != 2:            # noSuchName
                return {vb["oid"]: vb for vb in response.varbinds}
            index = response.error_index
            if not 1 <= index <= len(remaining):
                return {}      # the agent will not say which: nothing to drop
            remaining.pop(index - 1)
        return {}

    def _interface_varbinds(self, device, config: dict, if_index: int,
                            is_v1: bool, want_ifx: bool, *, session: _Session,
                            credential: Credential | None = None) -> tuple:
        """(oid -> varbind, whether ifXTable still answers) for one
        interface, over the session and credential _poll_interfaces holds
        for the whole read.

        On v2c and v3 the IF-MIB and ifXTable columns ride in one GET: an
        object the agent lacks comes back as a per-varbind noSuchObject and
        the rest of the reply is unharmed. On v1 they cannot — mixing one
        ifXTable OID into the request makes a v1 agent answer noSuchName
        for the whole PDU, and since only authorizationError was ever
        raised on, every interface on every v1 device came back blank: no
        counters, no speed, no link events. So on v1 the two tables are two
        requests, and an ifXTable that answers noSuchName is remembered as
        "this device has none" for the rest of the poll rather than
        re-asked once per port.
        """
        oids = [f"{oid}.{if_index}" for oid in nodeoids.IF_TABLE.values()]
        ifx_oids = [f"{oid}.{if_index}" for oid in nodeoids.IFX_TABLE.values()]
        if not is_v1:
            response = self._snmp_get_on(session, device, config,
                                         oids + ifx_oids, credential)
            return {vb["oid"]: vb for vb in response.varbinds}, want_ifx
        values = self._v1_get_dropping_unknown(device, config, oids,
                                               session=session,
                                               credential=credential)
        if not want_ifx:
            return values, False
        try:
            response = self._snmp_get_on(session, device, config, ifx_oids,
                                         credential)
        except SnmpTimeout:
            raise
        except SnmpError:
            return values, False
        if response.error_status == 2:                # no ifXTable at all
            return values, False
        values.update({vb["oid"]: vb for vb in response.varbinds})
        return values, True

    def _poll_interfaces(self, device, config: dict) -> tuple:
        """(rows, complete, reason, note) for a device's interfaces.

        `reason` is a fault the caller stores as snmp_error; `note` is the
        designed per-poll cap, which is not one — see _MAX_INTERFACES below.

        Walks the ifIndex column to discover interfaces, then reads the
        columns for each index.

        A walk that stops part way DEGRADES the interface data — complete
        is False, `reason` says what happened, and the device's own SNMP
        state is untouched. It used to fail the whole device: the ifIndex
        walk opted into raise_on_timeout, and the exception propagated out
        of _poll_device's one try to set snmp_ok = False even though the
        system scalars had already answered. On a chassis with several
        hundred interfaces behind a 3 s x 3 budget that is the whole
        reported fault — L3 confirmed, community confirmed, sysDescr
        populated, polling "failing".

        The boundary is progress, not cause: an ifIndex walk that got
        NOTHING at all still raises (see _walk_column_detail), because the
        scalars answering and then the very next request going unanswered
        is a device that has gone away mid-poll, and a device that has
        gone away must not read as healthy. One row is enough to say the
        agent is there and the credential is right.

        `complete` is what lets the caller decide whether an interface the
        walk did not produce is really gone: a walk cut short is not
        evidence of absence, and deleting on it takes the interfaces'
        link-event history with them.
        """
        interval = float(config.get("poll_interval_s") or 120)
        deadline = time.monotonic() + max(self._INTERFACE_BUDGET_FLOOR_S,
                                          self._INTERFACE_BUDGET_FRACTION * interval)
        indexes, complete, reason = self._walk_indexes(
            device, config, nodeoids.IF_TABLE["if_index"], raise_on_timeout=True)
        if not indexes:
            return [], complete, reason, ""
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        want_ifx = True
        wanted = indexes[:self._MAX_INTERFACES]
        note = ""
        if len(indexes) > self._MAX_INTERFACES:
            complete = False
            # A NOTE, deliberately not the `reason` the caller stores as
            # snmp_error: this cap is a designed limit, the same on every
            # poll, and a core switch or a firewall with per-VLAN
            # subinterfaces sits over it permanently. Reported as an SNMP
            # error it painted a red line in the device pane and wrote a
            # NODES log line every poll interval for ever, which is how a
            # real error that arrives later gets missed. It still has to
            # reach the operator — a table that stops at 512 with nothing
            # saying why is the "healthy device, no interfaces" reading
            # again in miniature — so it travels to the device row and is
            # rendered under the interface table it describes.
            note = (f"the device reported {len(indexes)} interfaces; one poll "
                    f"reads the first {self._MAX_INTERFACES}")
        rows = []
        skipped = 0
        consecutive_timeouts = 0
        abandoned = ""
        # One socket and one credential decrypt for the whole read, not
        # one of each per interface: a 512-port chassis otherwise opens
        # 512 ephemeral UDP ports and re-decrypts the stored v3 password
        # 512 times, per device, per poll.
        # Credential first: it can raise on a malformed one, and raising after
        # opening the socket leaked it.
        credential = credential_for(config)
        session = self._session_for(device, config)
        try:
            for if_index in wanted:
                if time.monotonic() > deadline:
                    abandoned = "the poll's interface budget ran out"
                    break
                if consecutive_timeouts >= self._INTERFACE_GIVE_UP_TIMEOUTS:
                    abandoned = (f"{consecutive_timeouts} interfaces in a row did "
                                 f"not answer")
                    break
                try:
                    values, want_ifx = self._interface_varbinds(
                        device, config, if_index, is_v1, want_ifx,
                        session=session, credential=credential)
                except SnmpTimeout:
                    # One interface's own GET timing out doesn't invalidate the
                    # whole poll — the device answered enough to enumerate its
                    # interfaces, so the rest are still worth collecting. Three
                    # in a row does mean the device has gone quiet.
                    skipped += 1
                    consecutive_timeouts += 1
                    continue
                except SnmpError:
                    skipped += 1
                    consecutive_timeouts = 0
                    continue
                consecutive_timeouts = 0
                # Stamped right after this interface's own GET returns, not at
                # poll start: at a 3 s focus cadence that gap is a large
                # fraction of dt. This is the timestamp counter_rate and
                # update_interface_rates use for this row.
                sample_ts = time.time()

                def _val(table, key, _values=values, _index=if_index):
                    vb = _values.get(f"{table[key]}.{_index}")
                    if not vb or vb["type"] in ("noSuchObject", "noSuchInstance",
                                                "endOfMibView", "null"):
                        return None
                    return vb["value"]

                speed = _val(nodeoids.IF_TABLE, "if_speed")
                high_speed = _val(nodeoids.IFX_TABLE, "if_high_speed")
                if_type = _val(nodeoids.IF_TABLE, "if_type")
                # ifSpeed is a Gauge32 that RFC 2863 saturates at 4294967295 for
                # any link it cannot express in 32 bits of bits/sec, which is why
                # ifHighSpeed (Mbit/s) exists. The sentinel is left as a literal
                # denominator rather than treated as "unknown": in_util/out_util
                # are clamped to [0, 100], so a row stuck with it still reports a
                # bounded number instead of losing the metric.
                speed_bps = interface_speed_bps(speed, high_speed, if_type)
                hc_in = _val(nodeoids.IFX_TABLE, "if_hc_in_octets")
                hc_out = _val(nodeoids.IFX_TABLE, "if_hc_out_octets")
                in_octets = hc_in if isinstance(hc_in, (int, float)) else _val(nodeoids.IF_TABLE, "if_in_octets")
                out_octets = hc_out if isinstance(hc_out, (int, float)) else _val(nodeoids.IF_TABLE, "if_out_octets")
                # in_octets and out_octets fall back from the 64-bit ifXTable
                # counters to the 32-bit ifTable ones independently, so the wrap
                # width has to be tracked independently too: an agent answering
                # ifHCInOctets but not ifHCOutOctets would otherwise apply a
                # width of 64 to a genuinely 32-bit counter, and counter_rate
                # would drop the sample at every wrap.
                in_octet_bits = 64 if isinstance(hc_in, (int, float)) else 32
                out_octet_bits = 64 if isinstance(hc_out, (int, float)) else 32

                admin_raw = _val(nodeoids.IF_TABLE, "if_admin_status")
                oper_raw = _val(nodeoids.IF_TABLE, "if_oper_status")
                in_errors = _val(nodeoids.IF_TABLE, "if_in_errors")
                out_errors = _val(nodeoids.IF_TABLE, "if_out_errors")
                in_discards = _val(nodeoids.IF_TABLE, "if_in_discards")
                out_discards = _val(nodeoids.IF_TABLE, "if_out_discards")
                discontinuity = _val(nodeoids.IFX_TABLE, "if_discontinuity")
                rows.append({
                    "if_index": if_index,
                    "descr": _val(nodeoids.IF_TABLE, "if_descr") or "",
                    "name": _val(nodeoids.IFX_TABLE, "if_name") or "",
                    "alias": _val(nodeoids.IFX_TABLE, "if_alias") or "",
                    "phys_addr": (_val(nodeoids.IF_TABLE, "if_phys_addr") or ""),
                    "speed_bps": speed_bps,
                    "admin_status": {1: "up", 2: "down", 3: "testing"}.get(
                        int(admin_raw), "") if admin_raw is not None else "",
                    "oper_status": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                                   5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(
                        int(oper_raw), "") if oper_raw is not None else "",
                    "in_octets": int(in_octets) if isinstance(in_octets, (int, float)) else None,
                    "out_octets": int(out_octets) if isinstance(out_octets, (int, float)) else None,
                    "in_errors": int(in_errors) if isinstance(in_errors, (int, float)) else None,
                    "out_errors": int(out_errors) if isinstance(out_errors, (int, float)) else None,
                    "in_discards": int(in_discards) if isinstance(in_discards, (int, float)) else None,
                    "out_discards": int(out_discards) if isinstance(out_discards, (int, float)) else None,
                    "discontinuity_ts": (float(discontinuity)
                                         if isinstance(discontinuity, (int, float)) else None),
                    "_in_octet_bits": in_octet_bits,
                    "_out_octet_bits": out_octet_bits,
                    "_sample_ts": sample_ts,
                })
        finally:
            credential = None
            session.close()
        if skipped or abandoned:
            complete = False
            per_interface = abandoned or f"{skipped} did not answer"
            self.log.add(NODES, f"Read {len(rows)} of {len(indexes)} interface(s) "
                                f"on {device['ip']}: {per_interface}. Interfaces "
                                f"that were not read keep their stored values.",
                        target=device["ip"])
            # Both halves, when both happened: the walk's own stop reason
            # names why the table is short, the per-interface one why the
            # rows it did enumerate are missing values.
            reason = f"{reason}; {per_interface}" if reason else per_interface
        if reason:
            self.log.add(NODES, f"Interface read on {device['ip']} is "
                                f"incomplete: {reason}", target=device["ip"])
        return rows, complete, reason, note

    def _table_walk_deadline(self, config: dict, interval_key: str) -> float:
        """Monotonic-clock budget for one table walk, off its own cadence rather than poll_interval_s (which cut an hourly walk off at 60s); falls back to poll_interval_s, so it only widens the budget."""
        interval = float(config.get(interval_key) or 0)
        if interval <= 0:
            interval = float(config.get("poll_interval_s") or 120)
        return time.monotonic() + max(self._WALK_BUDGET_FLOOR_S,
                                      self._WALK_BUDGET_FRACTION * interval)

    def _walk_column(self, device, config: dict, base_oid: str,
                     raise_on_timeout: bool = False,
                     deadline: float | None = None) -> dict[str, object]:
        """One table column's values. See _walk_column_status, which this
        wraps for the callers that do not need to know whether the walk
        finished."""
        return self._walk_column_status(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout,
                                        deadline=deadline)[0]

    def _walk_column_status(self, device, config: dict, base_oid: str,
                            raise_on_timeout: bool = False,
                            deadline: float | None = None) -> tuple:
        """(index suffix -> value, whether the walk reached the end). See
        _walk_column_detail, which this wraps for the callers that do not
        need to know WHY a walk stopped."""
        return self._walk_column_detail(device, config, base_oid,
                                        raise_on_timeout=raise_on_timeout,
                                        deadline=deadline)[:2]

    def _walk_column_detail(self, device, config: dict, base_oid: str,
                            raise_on_timeout: bool = False,
                            deadline: float | None = None) -> tuple:
        """(index suffix -> value, whether the walk reached the end, why it
        stopped when it did not).

        `complete` is False whenever the walk stopped for a reason that is
        not "the table ended": a timeout, an SNMP error, the row cap, an
        agent that answered nothing, one that answered out of order, or
        the caller's own deadline. Callers that go on to delete rows the
        walk did not produce need to know the difference — a walk cut
        short is not evidence that anything is gone.

        v2c and v3 walk with GETBULK, up to
        `settings["snmp_bulk_max_repetitions"]` rows per request; v1 has no
        GETBULK PDU and uses GETNEXT. Either way the walk runs on one shared
        `_Session`. Per response, varbinds are taken in order until the first
        that leaves the subtree, answers noSuchObject/noSuchInstance/
        endOfMibView, or is not lexicographically after the request (an agent
        echoing itself or going backwards); the next request resumes from the
        last accepted OID. A GETBULK answered `error_status == 1` (tooBig) is
        retried at half the repetitions, then falls back to GETNEXT rather
        than looping, and the fallback itself is remembered. Any OTHER
        non-zero error-status — genErr(5) and noSuchName(2) are what a
        PAN-OS agent answers a subtree it will not serve — ends the walk
        with that status named in the reason. It used to fall through to
        the non-increasing-OID guard and end the walk with nothing said at
        all, which is a device reading healthy with zero interfaces. Stops
        at the subtree end, at `settings["snmp_walk_max_rows"]`, or at
        _WALK_MAX_BYTES of retained values (either cap logged once, not per
        row) — the row cap alone does not bound memory, since one row can
        carry a 64 KB octet string that renders three bytes of `str` per
        wire byte. A caller that passes no `deadline` gets one derived
        from the device's own poll interval, the way _poll_interfaces
        derives its interface budget: without it an agent answering each
        GETBULK just inside its timeout can hold a poll worker for twenty
        minutes on one walk.

        A mid-walk SnmpTimeout means the device stopped answering, not that
        the table ended, so a caller whose result drives the device's own
        up/down status (_poll_interfaces, via _walk_indexes) passes
        raise_on_timeout=True rather than have it read as "no more rows".
        Best-effort callers leave it swallowed like any other SnmpError.
        Either way the reason names the session's `dropped` count when it
        is non-zero: replies that arrived and were rejected (wrong peer,
        undecodable, wrong request id) are a different fault from no reply
        at all, and only one of them is a firewall.
        """
        max_rows = self._walk_limits()[0]
        if deadline is None:
            interval = float(config.get("poll_interval_s") or 120)
            deadline = time.monotonic() + max(self._WALK_BUDGET_FLOOR_S,
                                              self._WALK_BUDGET_FRACTION * interval)
        # GETBULK does not exist in v1, so whether to use it is decided on
        # the configured version with 0 (v1) the only value that says no —
        # an absent version means v2c, the same default `_walk_request`,
        # `_snmp_get` and `_snmp_get_next` apply for framing. Framing
        # (build_request vs build_v3_request) is unaffected either way: v1
        # and v2c share the same community-based wire format. The
        # repetition count is the one this device last coped with.
        use_bulk, max_repetitions = self._bulk_settings(device, config)

        values: dict[str, object] = {}
        current = base_oid
        hit_cap = ""
        retained = 0
        complete = True
        reason = ""
        session = self._session_for(device, config)
        try:
            while True:
                if len(values) >= max_rows:
                    hit_cap = f"stopped at the {max_rows}-row cap"
                    complete = False
                    reason = hit_cap
                    break
                if deadline is not None and time.monotonic() > deadline:
                    # The caller's own budget, on the monotonic clock so a
                    # backward wall-clock step cannot strand it. Checked inside
                    # the walk, not only between walks: a Cisco per-VLAN
                    # sweep that checked only between VLANs could run two
                    # unbounded walks past the budget it was given.
                    complete = False
                    hit_cap = (f"stopped after {len(values)} row(s) when the "
                               f"walk's own time budget ran out")
                    reason = hit_cap
                    break
                try:
                    pdu_tag = PDU_GETBULK if use_bulk else PDU_GETNEXT
                    response = self._walk_request(
                        session, device, config, current, pdu_tag, max_repetitions)
                except SnmpTimeout as exc:
                    complete = False
                    reason = (f"{exc} (table walk cut short after "
                              f"{len(values)} row(s))")
                    if raise_on_timeout and not values:
                        # Nothing at all came back, so this is the device
                        # having stopped answering rather than a table too
                        # large to finish inside the budget. Only that
                        # reads as an SNMP failure; see _poll_interfaces.
                        raise SnmpTimeout(_with_dropped(reason, session)) from exc
                    break
                except SnmpError as exc:
                    complete = False
                    reason = f"SNMP error: {exc}"
                    break
                if use_bulk and response.error_status == 1:   # tooBig
                    if max_repetitions <= 1:
                        use_bulk = False
                        self._remember_repetitions(device, 0, use_bulk=False)
                    else:
                        max_repetitions = max(1, max_repetitions // 2)
                        self._remember_repetitions(device, max_repetitions)
                    continue
                if response.error_status:
                    if (snmp_version_of(config) == 0 and response.error_status == 2
                            and values):
                        # v1 GETNEXT past a MIB's last object answers
                        # noSuchName(2) (RFC 1157) — with rows already
                        # accepted, that IS the table end, not a refusal.
                        break
                    complete = False
                    reason = _error_status_reason(response, base_oid)
                    break
                if not response.varbinds:
                    complete = False
                    reason = "the device returned nothing"
                    break
                stop = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base_oid or oid.startswith(base_oid + ".")):
                        stop = True
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance", "endOfMibView"):
                        stop = True
                        break
                    if _oid_key(oid) <= _oid_key(current):
                        complete = False
                        reason = (f"the device answered with a non-increasing "
                                  f"OID ({oid}) — its SNMP agent is misbehaving")
                        stop = True
                        break
                    values[oid[len(base_oid) + 1:]] = vb["value"]
                    retained += len(str(vb["value"]))
                    current = oid
                    if len(values) >= max_rows:
                        hit_cap = f"stopped at the {max_rows}-row cap"
                        complete = False
                        reason = hit_cap
                        stop = True
                        break
                    if retained >= self._WALK_MAX_BYTES:
                        hit_cap = (f"stopped at the {self._WALK_MAX_BYTES}-byte "
                                   f"cap after {len(values)} row(s)")
                        complete = False
                        reason = hit_cap
                        stop = True
                        break
                if stop:
                    break
            if reason:
                reason = _with_dropped(reason, session)
        finally:
            session.close()
        if hit_cap:
            self.log.add(NODES, f"Table walk of {base_oid} on "
                                f"{device['ip']} {hit_cap}",
                         target=device["ip"])
        return values, complete, reason

    def _walk_indexes(self, device, config: dict, base_oid: str,
                      raise_on_timeout: bool = False) -> tuple:
        """(the integer indexes the column reported, whether the walk
        finished, why it stopped when it did not).

        A suffix that is not an integer is skipped, not treated as the end
        of the table: one malformed row used to truncate the list, and
        because the caller then deleted every interface it had not seen,
        one bad row took the rest of the device's ports and their link
        history with it.
        """
        indexes: list[int] = []
        values, complete, reason = self._walk_column_detail(
            device, config, base_oid, raise_on_timeout=raise_on_timeout)
        for suffix in values:
            try:
                indexes.append(int(suffix))
            except ValueError:
                continue
        return indexes, complete, reason

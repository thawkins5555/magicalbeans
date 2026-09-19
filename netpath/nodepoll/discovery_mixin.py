from __future__ import annotations

from ..nodediscover import DiscoveryJob
from ._jobs import DiscoveryBusy


class DiscoveryMixin:

    # ------------------------------------------------------------ discovery

    def start_discovery(self, kind: str, target: str,
                        overrides: dict | None = None,
                        allow_ping_only: bool = False,
                        group_id: int | None = None,
                        scan_overrides: dict | None = None,
                        refuse_if_target_running: bool = False) -> int:
        """`overrides` is what THIS run's settings are built from; `group_id`
        and `scan_overrides` are what the row keeps so Re-discover can build
        the same settings again from the profile as it stands then.

        `refuse_if_target_running` raises DiscoveryBusy instead of putting a
        second sweep of one target on the wire. The check is here, under the
        lock the start holds, and not in the caller: asked first and acted on
        afterwards it is two steps with a window between them, and the web
        server is threaded, so a double-click on Re-discover fits two
        requests through it.
        """
        settings = dict(self.db.settings())
        if overrides:
            settings.update(overrides)
        with self._discovery_lock:
            if refuse_if_target_running and self._target_running(target):
                raise DiscoveryBusy(target)
            job_id = self.db.add_discovery_job(kind, target,
                                               allow_ping_only=allow_ping_only,
                                               group_id=group_id,
                                               scan_overrides=scan_overrides)
            job = DiscoveryJob(self.db, job_id, kind, target, settings,
                               log=self.log)
            self._discovery_jobs[job_id] = job
            job.start()
        return job_id

    def _target_running(self, target: str) -> bool:
        """Whether a sweep of this target is on the wire. Callers hold
        _discovery_lock, which is also what keeps a job whose row exists but
        whose thread has not been started yet from reading as stranded."""
        with self._discovery_lock:
            return any(job.target == target and job.running
                       for job in list(self._discovery_jobs.values()))

    def cancel_discovery(self, job_id: int) -> None:
        job = self._discovery_jobs.get(job_id)
        if job is not None:
            job.cancel()

    def discovery_running(self, job_id: int) -> bool:
        # Under the start's own lock: between the job row being written and
        # its thread being started there is nothing to read is_alive() on,
        # and a row read then would answer "stranded" for a sweep that is
        # about to run.
        with self._discovery_lock:
            job = self._discovery_jobs.get(job_id)
            return job is not None and job.running

    def promote(self, job_id: int, result_ids: list[int],
                force: bool = False, force_ids=()) -> list[int]:
        """Creates a devices row per discovery result. The target profile
        is the job's own group_id when the job carries one and that
        profile still exists (a job started under a non-default profile
        lands its devices there, not in the vendor-suggested group); a job
        with no group_id (from before the rescan feature) falls back to
        the suggested group. The discovered community/version is carried
        as a per-device override only when it matches none of the target
        profile's own credentials — its primary credential or any
        additional one — so a device that a profile's existing credential
        list already covers keeps trying that shared list (and benefits
        from any future credential added to the profile) instead of being
        pinned to one override. Already-promoted
        result ids are a no-op rather than a duplicate-IP error, so a
        second promote call with an overlapping selection is always safe
        to retry. A ping-only result (no SNMP answer) is skipped outright
        unless its job was started with the allow-ping-only option — the
        checkbox state in the browser is a convenience, this is the rule.

        A result whose probed address is already a device folds onto
        it; unless forced, a result whose probed address is on an
        existing device's interfaces folds onto that device too.
        `force_ids` (or `force=True` for everything) adds those rows as
        their own device regardless, processed first so an address a
        later row would otherwise have folded onto still gets its own
        row. A promoted device writes nothing to device_addresses; its
        first poll fills the interface list.
        """
        job = self.db.discovery_job(job_id)
        allow_ping_only = bool(job and job["allow_ping_only"])
        forced = set(force_ids) | (set(result_ids) if force else set())
        ordered_ids = list(force_ids) + [rid for rid in result_ids if rid not in force_ids]
        device_ids = []
        seen_results = set()
        forced_devices: set[int] = set()
        for raw_id in ordered_ids:
            result = self.db.discovery_result(raw_id)
            is_forced = raw_id in forced
            if result is None or result["job_id"] != job_id:
                continue
            result_id = result["id"]
            if result_id in seen_results:
                continue
            seen_results.add(result_id)
            if not result["snmp_ok"] and not allow_ping_only:
                continue
            if result["promoted_device_id"]:
                device_ids.append(result["promoted_device_id"])
                continue
            existing = self.db.device_by_ip(result["ip"])
            if existing is None and not is_forced:
                owner = self.db.device_id_for_address(result["ip"], configured=True)
                if owner is not None and owner not in forced_devices:
                    existing = self.db.device(owner)
            if existing is not None:
                self.db.mark_promoted(result_id, existing["id"])
                device_ids.append(existing["id"])
                if is_forced:
                    forced_devices.add(existing["id"])
                continue
            job_group_id = job["group_id"] if job and "group_id" in job.keys() else None
            group_id = result["suggested_group_id"]
            if job_group_id and self.db.group(job_group_id) is not None:
                group_id = job_group_id
            group_row = self.db.group(group_id) if group_id else None
            overrides = {}
            if result["snmp_ok"] and result["community_or_user"]:
                known = [group_row] + list(self.db.group_credentials(group_id)) \
                       if group_row is not None else []
                matches_known = any(
                    g["community"] == result["community_or_user"]
                    and g["snmp_version"] == result["snmp_version"] for g in known)
                if not matches_known:
                    overrides["community"] = result["community_or_user"]
                    overrides["snmp_version"] = result["snmp_version"]
            elif not result["snmp_ok"]:
                # A ping-only device would otherwise sit failing SNMP on
                # every poll; it can be switched back on in its Edit form
                # once real credentials are known.
                overrides["snmp_enabled"] = 0
                overrides["ping_enabled"] = 1
            # The manual name is left as the IP (add_device's default):
            # the displayed name prefers sys_name on its own, so copying
            # sysName into the manual field would only shadow later
            # renames on the device.
            device_id = self.db.add_device(
                result["ip"], group_id=group_id, **overrides)
            if result["snmp_ok"]:
                keys = result.keys()
                self.db.seed_identity(
                    device_id, sys_descr=result["sys_descr"] or "",
                    sys_name=result["sys_name"] or "",
                    sys_object_id=result["sys_object_id"] or "",
                    vendor=result["vendor"] or "",
                    vendor_source=(result["vendor_source"] if "vendor_source" in keys else "") or "",
                    vendor_confidence=(result["vendor_confidence"]
                                       if "vendor_confidence" in keys else "") or "",
                    vendor_evidence=(result["vendor_evidence"]
                                     if "vendor_evidence" in keys else None))
            self.db.mark_promoted(result_id, device_id)
            device_ids.append(device_id)
            if is_forced:
                forced_devices.add(device_id)
        seen_devices = set()
        deduped = []
        for did in device_ids:
            if did not in seen_devices:
                seen_devices.add(did)
                deduped.append(did)
        return deduped

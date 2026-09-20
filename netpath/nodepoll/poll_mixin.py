from __future__ import annotations

import ipaddress
import time
import traceback
from .. import mibcatalog, nodeoids, nodesdb, swversion, vendorid
from ..eventlog import ERROR, NODES
from ..ipam_scan import ping_many
from ..nodesdb import NodesDatabase
from ..snmppoll import PDU_GET, Response, SnmpAccessDenied, SnmpDowngrade, SnmpError, SnmpTimeout, SnmpUnsupported, build_request
from ._decode import _DEVICE_MAX_KEYS, _INTERFACE_METRICS, _inet_address_text, _int_keyed, _interface_reassigned, counter_rate, detect_reboot, max_event_rate
from ._session import Credential, SnmpBadOid, _AuthFailure, _CREDENTIAL_VERDICTS, _Session, _assemble, _credential_contradicted, _error_specificity, access_denied_reason, credential_for, security_level, snmp_version_of, v3_exchange


class PollMixin:

    # ---------------------------------------------------------------- poll

    def _best_effort(self, label, fn, *args):
        """Run one optional read, swallowing "this device does not answer
        that" and nothing else. A credential or security-level verdict is
        not that (see _CREDENTIAL_VERDICTS): those are re-raised for the
        caller's own handler, named so the log says which read produced it.
        """
        try:
            return fn(*args)
        except _CREDENTIAL_VERDICTS as exc:
            self.log.add(NODES, f"{label}: {exc}")
            raise
        except SnmpError:
            return None

    def _poll_device(self, device, config: dict) -> None:
        device_id = device["id"]
        ip = device["ip"]
        now = time.time()

        settings = self._cached_settings()
        self._verify_replies = bool(settings.get("v3_verify_replies", True))
        ping_ok = None
        ping_rtt_ms = None
        ping_loss_pct = None
        if config.get("ping_enabled"):
            # Several probes, not one: a single probe can only ever report
            # 0% or 100% loss, which is no use for spotting a link that is
            # up but dropping a fifth of its traffic. The timeout is its own
            # setting rather than snmp_timeout_s borrowed — ICMP round trips
            # and SNMP round trips have nothing to do with each other, and
            # tying them meant raising an SNMP timeout silently slowed every
            # ping.
            interval = float(settings.get("ping_interval_s", 0) or 0)
            due = (interval <= 0
                   or (now - self._last_ping.get(device_id, 0.0)) >= interval)
            if due:
                self._last_ping[device_id] = now
                sent, received, rtt = ping_many(
                    ip, count=int(config.get("ping_count", 3) or 1),
                    timeout_ms=int(config.get("ping_timeout_ms", 1000) or 1000))
                ping_ok = received > 0
                ping_rtt_ms = rtt
                ping_loss_pct = 100.0 * (sent - received) / sent if sent else None
            else:
                # Not this device's turn to be pinged. The last known result
                # still stands: skipping a probe must not read as a failed
                # one, and record_poll overwrites both columns every time, so
                # the previous RTT has to be carried forward too or the device
                # row would blank it on every poll between pings.
                previous_ok = device["ping_ok"]
                ping_ok = None if previous_ok is None else bool(previous_ok)
                ping_rtt_ms = device["ping_rtt_ms"]

        if ping_ok:
            self._snmp_backoff.pop(device_id, None)

        snmp_ok = None
        snmp_error = ""
        # Whether SNMP failed because the device refuses something this
        # poller does not speak, rather than because it is unreachable.
        # Decided by exception type, never by a substring of the message:
        # no message this raises contains the word "unsupported".
        snmp_unsupported = False
        # Whether the agent verified the credential and then refused the
        # object under its own access control (authorizationError). Type-
        # decided like the two beside it: every message this raises
        # contains the word "auth", and so does every message that is NOT
        # this — see auth_failing below.
        snmp_denied = False
        # Whether the agent would not accept the message at all (a wrong
        # community or v3 password, an engine that will not resync).
        # Decided by exception type, never by a substring of the message:
        # the unsupportedSecLevels text contains "authPriv", and every
        # access-denied message above contains "authenticated", so "auth"
        # in the message was already raising auth_fail for faults that
        # proved the password GOOD.
        snmp_auth_failed = False
        # Whether the device answered every request, but below the level
        # it was asked at, and the reply was refused as a downgrade
        # (SnmpDowngrade). Type-decided like the three above. Not an
        # outage — the device is demonstrably answering — and not an auth
        # failure — nothing contradicted the password, there was no
        # signature to contradict it — which is why it is neither in the
        # down path nor in snmp_failing_now below. Before this flag it fell
        # into the generic arm, and with ping off a device that answered
        # every single request was marked down and mailed as one.
        snmp_downgraded = False
        identity = None
        uptime_ticks = None
        interfaces: list[dict] = []
        # Whether the interface read finished. A partial read must not
        # delete the interfaces it never reached (see replace_interfaces).
        interfaces_complete = True
        # None until an interface read actually happens, so a poll that
        # never got that far leaves the stored note alone rather than
        # blanking a truncation the stored rows still show.
        interfaces_note = None
        metrics: list[tuple] = []   # (key, label, unit, kind, value)

        # A device already down costs about thirty times one that is up, so
        # it skips the SNMP half of most cycles. Ping is NOT backed off,
        # which is what makes that safe: ping detects both the outage and the
        # recovery and _next_run is untouched, so the cadence, the timeline
        # and the up/down events are unchanged. Decided on THIS cycle's ping,
        # not device["status"], which _run_one read before the poll and so
        # describes the previous one. See INTERNALS.md.
        # ping_enabled and `is False` are both load-bearing: with ping off,
        # SNMP is the only evidence the device exists and skipping it means a
        # recovered device is never seen to recover; None is "no ping
        # evidence", and no evidence is not a failure.
        backed_off = (device["status"] == "down"
                      and config.get("ping_enabled")
                      and ping_ok is False
                      and config.get("snmp_enabled")
                      and self._snmp_backoff_due(device_id))
        if backed_off:
            # None, not False: None is this file's established "the poll did
            # not touch that method" (see the lane events below), and False
            # here would be read as a real SNMP failure by snmp_failing_now
            # once ping recovered, counting a phantom failure toward
            # snmp_fail_alert_after on every recovery. record_poll is handed
            # the previous values further down instead, so the device row
            # keeps saying what it last actually knew.
            self._bump("snmp_backoff")

        if config.get("snmp_enabled") and not backed_off:
            try:
                cred_config, identity, uptime_ticks, metrics = \
                    self._poll_snmp_scalars_with_credential(device, config)
                interfaces, interfaces_complete, interfaces_reason, interfaces_note = \
                    self._poll_interfaces(device, cred_config)
                # SNMP itself worked — the scalars answered — so snmp_ok
                # stays true and the interface read is what degraded. The
                # reason still has to reach the device row: an empty
                # interface table with no error beside it is the "healthy
                # device, zero interfaces" reading that sent operators
                # hunting the network instead of the agent.
                snmp_error = interfaces_reason
                if config.get("mib_file_id"):
                    metrics = metrics + self._poll_custom_mib(
                        device, cred_config, config["mib_file_id"])
                snmp_ok = True
            except SnmpUnsupported as exc:
                snmp_ok = False
                snmp_error = str(exc)
                snmp_unsupported = True
                self._bump("unsupported")
            except SnmpTimeout as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("timeout")
            except SnmpAccessDenied as exc:
                # Before SnmpError, which it is a subclass of: the credential
                # loop has already rotated on it (an authPriv alternate may
                # well have succeeded), so reaching here means every
                # candidate was refused this way or worse.
                snmp_ok = False
                snmp_error = str(exc)
                snmp_denied = True
                self._bump("denied")
            except _AuthFailure as exc:
                snmp_ok = False
                snmp_error = str(exc)
                snmp_auth_failed = True
                self._bump("auth_fail")
            except SnmpDowngrade as exc:
                # Before SnmpError, which it is a subclass of — the generic
                # arm is the outage path.
                snmp_ok = False
                snmp_error = str(exc)
                snmp_downgraded = True
                self._bump("downgraded")
            except SnmpError as exc:
                snmp_ok = False
                snmp_error = str(exc)
                self._bump("errors")
            except SnmpBadOid as exc:
                # An OID this poll was configured with cannot be encoded --
                # a MIB object or an override carrying an arc that is not a
                # non-negative integer, refused by enc_oid.
                snmp_ok = False
                snmp_error = (f"an OID configured for this device is not a "
                              f"valid object identifier: {exc}")
                self._bump("errors")
            except ValueError as exc:
                # Everything else; kept so a ValueError doesn't freeze the device row.
                snmp_ok = False
                snmp_error = f"the poll could not be completed: {exc}"
                self._bump("errors")

        # -------------------------------------------------------- status

        down_after = int(settings.get("down_after_failures", 3))
        # SNMP's evidence that the device is up is wider than snmp_ok. An
        # authorizationError is the agent's own verified Response — it
        # accepted the message and refused the object — and a downgrade is
        # a reply to every request that merely lacked the signature asked
        # for. Neither is silence, and "down" means silence: a device that
        # answers is not having an outage, whatever else is wrong with it.
        # An auth failure is deliberately NOT here: a Report is the agent
        # declining to say anything about the request, and the existing
        # choice that it follows ping alone stands.
        snmp_answered = bool(snmp_ok) or snmp_denied or snmp_downgraded
        if not config.get("snmp_enabled"):
            # A ping-only device by design (SNMP off entirely) is reachable
            # by ping alone, regardless of the "degrade gracefully when
            # SNMP is failing" setting below — that setting is about a
            # device that normally has SNMP on, not one configured without
            # it. Ping-only is documented as a first-class configuration.
            reachable = bool(ping_ok)
        elif not config.get("ping_enabled"):
            # Nothing is pinging it, so SNMP is the only evidence there is.
            reachable = snmp_answered
        else:
            # Both probes run, so DOWN means both failed. A device answering
            # ICMP with a broken community string is reachable and
            # misconfigured; reporting it down hides the SNMP error behind
            # an outage that isn't happening. Per device and per profile,
            # because occasionally SNMP failing really is the outage.
            ping_only_ok = bool(config.get("unreachable_ping_only", True))
            reachable = snmp_answered or (ping_only_ok and bool(ping_ok))

        # snmp_denied deliberately has NO status of its own, and does not
        # reuse "unsupported" either. "unsupported" is a verdict about the
        # poller — it cannot speak what the device requires — and lives in
        # the status vocabulary of the devices table, the timeline segments,
        # the dashboard figures, the map and the availability report; a
        # fifth value there is a vocabulary change in six files for a
        # diagnostics fix. A refused object is a verdict about the
        # device's configuration, and the device itself is demonstrably
        # reachable (its agent verified the message and answered), so it
        # counts as answered above and the status is "up" — an outage is
        # the one thing it is not — and the access_denied event below
        # carries the finding. A downgrade is filed the same way, for the
        # same reason, with snmp_downgrade as its event.
        if snmp_unsupported:
            status = "unsupported"
        elif reachable:
            status = "up"
        elif device["consecutive_fail"] + 1 >= down_after:
            status = "down"
        else:
            status = device["status"] if device["status"] in ("up", "down") else "unknown"

        # Every sample this poll produced, written in ONE transaction at the
        # end (see the T4 block below) rather than one commit each. A device
        # that goes on to be marked down still leaves the loss sample that
        # explains why: the flush is unconditional, not part of the success
        # path.
        samples: list[tuple] = []   # (key, label, unit, kind, ts, value)
        if ping_loss_pct is not None:
            samples.append(("ping_loss_pct", "Packet loss", "%", "gauge",
                            now, ping_loss_pct))
        if ping_rtt_ms is not None:
            samples.append(("ping_rtt_ms", "Ping response time", "ms", "gauge",
                            now, ping_rtt_ms))

        # T1 — the device row.
        #
        # A backed-off cycle stores what SNMP last actually reported rather
        # than the None it reasoned with above. record_poll overwrites both
        # columns on every poll, so passing None would blank them: the
        # device pane would show a down device's SNMP as unknown, and
        # prev_snmp_ok would reset, so the next real failure would record a
        # second snmp_down event for an outage already being reported. The
        # skipped-ping branch carries its previous values forward for the
        # same reason -- see ping_interval_s above.
        stored_snmp_ok, stored_snmp_error = snmp_ok, snmp_error
        if backed_off:
            was = device["snmp_ok"]
            stored_snmp_ok = None if was is None else bool(was)
            stored_snmp_error = device["snmp_error"] or ""
        previous = self.db.record_poll(
            device_id, ping_ok=ping_ok, ping_rtt_ms=ping_rtt_ms,
            snmp_ok=stored_snmp_ok, snmp_error=stored_snmp_error,
            identity=identity, uptime_ticks=uptime_ticks,
            status=status, reachable=reachable, interfaces_note=interfaces_note)
        if previous is None:
            return

        if self.counters is not None and snmp_ok:
            self._bump("ok")

        # Once, when it starts and when it stops — not every poll. A device
        # over the interface cap stays over it, and a line repeated every
        # poll interval is noise the next real one hides behind. The note
        # itself lives on the device row for as long as it is true.
        if interfaces_note is not None:
            was = previous["interfaces_note"] if "interfaces_note" in previous.keys() else ""
            if bool(interfaces_note) != bool(was):
                self.log.add(
                    NODES,
                    (f"Interface table on {device['ip']}: {interfaces_note}."
                     if interfaces_note else
                     f"Interface table on {device['ip']} is no longer "
                     f"truncated: every interface it reports is read."),
                    target=device["ip"])

        # ---------------------------------------------------------- debug
        self._log_poll_debug(device, status, now, ping_ok, ping_rtt_ms, snmp_ok,
                             snmp_error, interfaces, interfaces_complete,
                             interfaces_note, metrics)

        # -------------------------------------------------------- events

        was_status = previous["status"]
        first_poll = previous["last_poll_ts"] is None
        if status == "up" and was_status not in ("up",) and not first_poll:
            self.db.record_device_event(device_id, "up", "responding again")
        elif status == "down" and was_status != "down":
            self.db.record_device_event(device_id, "down", snmp_error or "not responding")
        elif status == "unsupported" and was_status != "unsupported":
            self.db.record_device_event(device_id, "unsupported", snmp_error)

        # access_denied: the agent accepted the credential and refused the
        # object. Recorded beside `unsupported` because it is the same
        # kind of finding — a configuration verdict, not an outage — but on
        # a transition held in memory rather than in `status`, since it has
        # no status of its own (see the status block above). Entering the
        # set records access_denied with the full explanation; a successful
        # poll afterwards records access_ok, the pair alertrules.CLEARS
        # uses to close the alert, exactly as auth_fail/auth_ok do below.
        with self._lock:
            if snmp_denied and device_id not in self._access_denied:
                self._access_denied.add(device_id)
                access_event = ("access_denied", snmp_error)
            elif snmp_ok and device_id in self._access_denied:
                self._access_denied.discard(device_id)
                access_event = ("access_ok", "")
            else:
                access_event = None
        if access_event is not None:
            self.db.record_device_event(device_id, access_event[0], access_event[1])

        # snmp_downgrade: the same shape again, for a device answering below
        # the level asked. A transition, because the device that does this
        # does it on every poll until the operator either fixes the agent or
        # turns v3_verify_replies off — and then the next poll's verified
        # reply records snmp_verified, the pair alertrules.CLEARS uses to
        # close device_downgrade. Only a poll that succeeded leaves the set:
        # every other outcome — a timeout, a Report — says nothing about
        # whether replies verify now.
        with self._lock:
            if snmp_downgraded and device_id not in self._downgraded:
                self._downgraded.add(device_id)
                downgrade_event = ("snmp_downgrade", snmp_error)
            elif snmp_ok and device_id in self._downgraded:
                self._downgraded.discard(device_id)
                downgrade_event = ("snmp_verified", "")
            else:
                downgrade_event = None
        if downgrade_event is not None:
            self.db.record_device_event(device_id, downgrade_event[0], downgrade_event[1])

        # Per-method transitions (snmp_up/snmp_down, ping_up/ping_down): the
        # status timeline's split SNMP/ping lanes are built from these, not
        # from the up/down events above, which follow `status` — effectively
        # ping alone once unreachable_ping_only lets a dead SNMP agent hide
        # behind a healthy ping. Compared against `previous` (the device row
        # from before THIS poll's own record_poll update) rather than
        # recorded on every poll, so the event log grows on a real change,
        # not once per device per interval forever. A previous value of None
        # (never observed, or the method was off) seeds the first event too,
        # the same way the very first up/down does further down — a segment
        # needs a start. `snmp_ok`/`ping_ok` of None here means this poll
        # didn't touch that method (disabled, or not this poll's turn to
        # ping — see ping_interval_s above, which carries the old value
        # forward rather than going None), so it never manufactures an event
        # out of a probe that didn't run.
        prev_snmp_ok = previous["snmp_ok"]
        prev_snmp_ok = None if prev_snmp_ok is None else bool(prev_snmp_ok)
        prev_ping_ok = previous["ping_ok"]
        prev_ping_ok = None if prev_ping_ok is None else bool(prev_ping_ok)
        # An install upgraded from before the lanes existed has device rows
        # with snmp_ok/ping_ok already populated, so the comparison above
        # would never fire until the next flap — and then only for the
        # method that flapped, leaving the other lane empty. Once per device
        # per process: if no lane event was ever recorded, forget the
        # previous values so this poll seeds both methods it observed.
        with self._lock:
            unseeded = device_id not in self._method_seeded
        if unseeded:
            if not self.db.has_method_events(device_id):
                prev_snmp_ok = prev_ping_ok = None
            with self._lock:
                self._method_seeded.add(device_id)
        if snmp_ok is not None and snmp_ok != prev_snmp_ok:
            self.db.record_device_event(
                device_id, "snmp_up" if snmp_ok else "snmp_down",
                "" if snmp_ok else snmp_error)
        if ping_ok is not None and ping_ok != prev_ping_ok:
            self.db.record_device_event(
                device_id, "ping_up" if ping_ok else "ping_down", "")

        # TRANSITIONS, like the up/down events above: an alert an operator
        # resolved by hand must not re-open because the next poll repeated
        # what the last one said. The transition is held here, in
        # _auth_failing, rather than derived from the device row's previous
        # snmp_ok/snmp_error, which cannot answer it — a device that times
        # out one poll in ten would "recover" into an auth_ok every time, and
        # a multi-credential profile re-raises whichever candidate's error
        # came last, so the recorded text alternates while nothing changed.
        # Entering the set records auth_fail, leaving it records auth_ok,
        # everything else records nothing.
        #
        # Decided by exception type (snmp_auth_failed, set only in the
        # _AuthFailure arm), never by a substring of the message. This used
        # to test for "auth" in the text, and "auth" is in nearly every
        # SNMPv3 message there is: the unsupportedSecLevels explanation says
        # "authPriv", and an authorizationError explanation says "the
        # message authenticated" — so an alert named "SNMP authentication
        # failing" was raised for the one fault that proved the password
        # correct.
        auth_failing = bool(snmp_auth_failed and snmp_ok is False)
        # What ends it is any outcome proving the credential was ACCEPTED,
        # not only a successful poll. An authorizationError is one: the
        # agent verified the message and refused the object, so the
        # password is right by the device's own word. Leaving the set only
        # on snmp_ok kept "SNMP authentication failing" open beside an
        # access_denied whose text said the message authenticated — two
        # alerts contradicting each other about one password, one of them
        # stale. unsupportedSecLevels is NOT here: USM refuses the level
        # (RFC 3414 s3.2 step 5) before it checks the digest (step 6), so
        # that Report proves nothing about the password either way, and a
        # downgrade is unsigned, so it proves nothing at all.
        credential_accepted = bool(snmp_ok) or snmp_denied
        with self._lock:
            if auth_failing and device_id not in self._auth_failing:
                self._auth_failing.add(device_id)
                auth_event = ("auth_fail", snmp_error)
            elif credential_accepted and device_id in self._auth_failing:
                self._auth_failing.discard(device_id)
                auth_event = ("auth_ok", "")
            else:
                auth_event = None
        if auth_event is not None:
            self.db.record_device_event(device_id, auth_event[0], auth_event[1])

        # A switch whose SNMP agent has died but still answers ICMP is
        # reachable and broken; `unreachable_ping_only` keeps it out of
        # device_down, so this is the event `snmp_failing_ping_ok` watches.
        #
        # Gated on `snmp_fail_alert_after` CONSECUTIVE qualifying failures,
        # not the first one — a single missed poll is not "SNMP failing",
        # and alerting on it would open snmp_failing_ping_ok on any blip.
        # Counted in memory, per device, the same shape as _auth_failing
        # above, and reset the moment SNMP succeeds again. Once the
        # threshold is reached the event keeps recording on EVERY qualifying
        # poll after that, not just the one that crossed it — the rule
        # carries `auto_resolve_after_s`, measured from the alert's last
        # occurrence, so the repeats are what keep it open while the agent
        # stays dead and their stopping is what lets it clear. A transition
        # would freeze `last_ts` and announce a false all-clear an hour
        # later.
        # A refused object is excluded the way unsupported is: "SNMP is not
        # answering" is untrue of an agent that verified the message and
        # answered it, and the access_denied event above is its report. So
        # is a downgrade, for the same reason — the agent answered every
        # request — and the snmp_downgrade event above is its report.
        snmp_failing_now = (not auth_failing and snmp_ok is False and ping_ok
                            and not snmp_unsupported and not snmp_denied
                            and not snmp_downgraded)
        with self._lock:
            if snmp_failing_now:
                fail_count = self._snmp_failing_count.get(device_id, 0) + 1
                self._snmp_failing_count[device_id] = fail_count
            else:
                # Consecutive means consecutive: any poll that does not
                # qualify — SNMP answered, ping also down (that is a device
                # outage, not a dead agent), an auth failure — starts the
                # count over rather than pausing it.
                fail_count = 0
                self._snmp_failing_count.pop(device_id, None)
        snmp_fail_alert_after = max(
            1, int(settings.get("snmp_fail_alert_after", 3) or 1))
        if snmp_failing_now and fail_count >= snmp_fail_alert_after:
            self.db.record_device_event(
                device_id, "snmp_error",
                f"SNMP is not answering but the device replies to ping: "
                f"{snmp_error}")

        # Hoisted out of the branch below: the interface block needs it too.
        # A restarted device restarted its interface counters too, and
        # counter_rate cannot tell a reset from a 32-bit wrap. One poll's
        # rates are dropped; the counters are still stored, so the next poll
        # measures against the post-reboot baseline.
        rebooted = False
        if uptime_ticks is not None:
            rebooted, note = detect_reboot(
                uptime_ticks, now, previous["last_uptime_ticks"],
                previous["last_uptime_ts"] or now)
            if rebooted:
                self.db.record_device_event(device_id, "rebooted", note)
                # A reboot can be onto different firmware; re-probe UCD-SNMP
                # support from nothing rather than trust the old verdict.
                self._ucd_read.pop(device_id, None)
                self._ucd_capable.pop(device_id, None)

        walk_pending = bool(
            snmp_ok and identity and settings.get("vendor_walk_enabled", True)
            and config.get("snmp_enabled", True)
            and self._identification_due(previous, identity.get("sys_object_id") or "", now))
        self._check_vendor_mib(device_id, previous, identity, defer_assignment=walk_pending)
        if walk_pending:
            self._maybe_identify(device_id, identity, config, settings)

        # ----------------------------------------------------- interfaces

        if interfaces:
            # T2 — the interface table. `prior` is the pre-update read
            # replace_interfaces() already did for its own comparison, so
            # the link-event loop below reuses it instead of reading the
            # table a second time; `ids` replaces one interface_id_for()
            # SELECT per port.
            result = self.db.replace_interfaces(
                device_id, interfaces, allow_delete=interfaces_complete)
            existing = result["prior"]
            interface_ids = result["ids"]
            rate_rows: list[dict] = []
            # The device-level worst case of each per-interface rate. The
            # six shipped if_*_high threshold rules all read a metric with
            # no interface suffix, and "the worst port on this box" is what
            # a device-level rule can usefully mean.
            worst: dict[str, float] = {}
            any_port_up = False
            for row in interfaces:
                if_index = row["if_index"]
                prior = existing.get(if_index)
                # This row's own GET timestamp, not the poll-start `now`:
                # the rate's dt has to match when the counters were actually
                # read (see the comment in _poll_interfaces). Metric samples
                # recorded below still use `now`, aligned with the rest of
                # this poll.
                sample_ts = row.get("_sample_ts") or now
                in_bps = out_bps = in_err_rate = out_err_rate = None
                in_disc_rate = out_disc_rate = None
                # ifCounterDiscontinuityTime: the agent saying this port's
                # counters restarted. A rate across that is fiction for
                # exactly the same reason a rate across a reboot is.
                discontinuity = row.get("discontinuity_ts")
                broke = (discontinuity is not None and prior is not None
                         and prior["discontinuity_ts"] is not None
                         and discontinuity != prior["discontinuity_ts"])
                if prior is not None and not rebooted and not broke:
                    since = prior["last_sample_ts"] or 0
                    # in_bits/out_bits track ifHCIn/OutOctets independently
                    # (see _poll_interfaces) because a device can answer
                    # one 64-bit ifXTable counter for a row without
                    # answering the other: applying one combined width to
                    # both counters would treat a genuinely 32-bit
                    # fallback as 64-bit and drop its wrapped sample.
                    in_bits = row.get("_in_octet_bits", 32)
                    out_bits = row.get("_out_octet_bits", 32)
                    in_bps = counter_rate(
                        prior["last_in_octets"], since, row.get("in_octets"),
                        sample_ts, in_bits, speed_bps=row.get("speed_bps"))
                    out_bps = counter_rate(
                        prior["last_out_octets"], since, row.get("out_octets"),
                        sample_ts, out_bits, speed_bps=row.get("speed_bps"))
                    # ifInErrors/ifOutErrors and ifInDiscards/ifOutDiscards
                    # are 32-bit counters; the rate is events per second
                    # between polls. Capped at the interface's own packet
                    # rate the same way the octet counters above are
                    # capped at its bit rate, or a 32-bit reset with no
                    # reboot/discontinuity marker reads as a wrap.
                    max_events = max_event_rate(row.get("speed_bps"))
                    in_err_rate = counter_rate(
                        prior["last_in_errors"], since, row.get("in_errors"),
                        sample_ts, 32, max_rate=max_events)
                    out_err_rate = counter_rate(
                        prior["last_out_errors"], since, row.get("out_errors"),
                        sample_ts, 32, max_rate=max_events)
                    in_disc_rate = counter_rate(
                        prior["last_in_discards"], since, row.get("in_discards"),
                        sample_ts, 32, max_rate=max_events)
                    out_disc_rate = counter_rate(
                        prior["last_out_discards"], since, row.get("out_discards"),
                        sample_ts, 32, max_rate=max_events)
                speed_bps = row.get("speed_bps")
                # counter_rate already refuses any rate implying more than
                # 1.3x speed_bps (treating that as a reset rather than a
                # real burst), so a raw util here tops out around 130%,
                # not unbounded -- still above 100%, which is not a real
                # utilization. Clamped into [0, 100] for the same reason
                # the rate itself is bounded: a number a dashboard or
                # alert rule can trust.
                in_util = (max(0.0, min(100.0, 100.0 * in_bps * 8 / speed_bps))
                           if in_bps is not None and speed_bps else None)
                out_util = (max(0.0, min(100.0, 100.0 * out_bps * 8 / speed_bps))
                            if out_bps is not None and speed_bps else None)
                rate_rows.append({
                    "if_index": if_index, "in_octets": row.get("in_octets"),
                    "out_octets": row.get("out_octets"),
                    "in_errors": row.get("in_errors"),
                    "out_errors": row.get("out_errors"),
                    "in_discards": row.get("in_discards"),
                    "out_discards": row.get("out_discards"),
                    "in_bps": in_bps, "out_bps": out_bps,
                    "in_error_rate": in_err_rate, "out_error_rate": out_err_rate,
                    "in_discard_rate": in_disc_rate,
                    "out_discard_rate": out_disc_rate,
                    "discontinuity_ts": discontinuity,
                    "ts": sample_ts})
                interface_id = interface_ids.get(if_index)
                # Suppressed only when `rebooted` AND _interface_reassigned
                # says the port at this ifIndex really changed: some
                # platforms renumber ifIndex across a reload, and comparing
                # oper_status across a renumbering fabricates a link event.
                # A reboot alone is not evidence of renumbering, though, and
                # a missed link_down is far worse than an occasional
                # fabricated one -- so the comparison still runs whenever
                # the prior and current rows agree, or cannot be told apart.
                if (interface_id is not None and prior is not None
                        and not (rebooted and _interface_reassigned(prior, row))):
                    if prior["oper_status"] and prior["oper_status"] != row.get("oper_status"):
                        kind = "link_up" if row.get("oper_status") == "up" else "link_down"
                        if row.get("oper_status") in ("up", "down"):
                            # A blocked port flapping is a different event to
                            # an ordinary one: it says the redundant path
                            # moved. Same rule, so no new alert to tune --
                            # the detail line names it.
                            blocked = (
                                "stp_state" in prior.keys()
                                and prior["stp_state"] in NodesDatabase.STP_BLOCKED_STATES)
                            self.db.record_interface_event(
                                interface_id, kind,
                                f"{row.get('descr') or if_index}: {prior['oper_status']} -> {row.get('oper_status')}"
                                + (" (spanning tree blocked)" if blocked else ""))
                if interface_id is not None:
                    label = row.get("descr") or f"if{if_index}"
                    # A down port's counters are not "zero traffic" -- they
                    # are nothing worth storing. The tuple is still emitted
                    # (never dropped) so record_metric_samples updates
                    # last_ts and clears last_value, matching its own "polled,
                    # no answer" contract; only an up port's normal None
                    # skip (a rate genuinely not computable this poll) is
                    # unchanged below.
                    port_up = row.get("oper_status") == "up"
                    if port_up:
                        any_port_up = True
                    for suffix, unit, value in _INTERFACE_METRICS(
                            in_bps, out_bps, in_err_rate, out_err_rate,
                            in_disc_rate, out_disc_rate, in_util, out_util):
                        if not port_up:
                            value = None
                        elif value is None:
                            continue
                        samples.append((f"if_{suffix}.{if_index}",
                                        f"{label} {suffix}", unit, "gauge",
                                        now, value))
                        if value is not None and suffix in _DEVICE_MAX_KEYS:
                            worst[suffix] = max(worst.get(suffix, value), value)
            for suffix, value in worst.items():
                unit, label = _DEVICE_MAX_KEYS[suffix]
                samples.append((f"if_{suffix}", label, unit, "gauge", now, value))
            if interfaces and not any_port_up:
                # Every port down: the worst-port aggregates have nothing to
                # report, but must say so rather than silently freeze at
                # whatever they last read while the device was reachable.
                for suffix, (unit, label) in _DEVICE_MAX_KEYS.items():
                    samples.append((f"if_{suffix}", label, unit, "gauge", now, None))
            # T3 — every interface's counters and rates.
            self.db.update_interface_rates(device_id, rate_rows)

        samples.extend((key, label, unit, kind, now, value)
                       for key, label, unit, kind, value in metrics)
        # T4 — every sample this poll produced, in one transaction.
        self.db.record_metric_samples(device_id, samples)

        # ---------------------------------------- PoE / STP / environment
        if snmp_ok and config.get("snmp_enabled"):
            self._poll_poe_stp_environment(device, config, cred_config, metrics, now)

    def _log_poll_debug(self, device, status, now: float, ping_ok, ping_rtt_ms,
                        snmp_ok, snmp_error: str, interfaces: list[dict],
                        interfaces_complete: bool, interfaces_note, metrics: list[tuple]) -> None:
        """A per-poll trace, the same shape monitor.py logs a trace with
        (command + raw output in `detail`), so a device silently failing
        to poll leaves a record beyond its own status/error fields."""
        detail_lines = [
            f"ping       {'n/a' if ping_ok is None else ('ok' if ping_ok else 'no reply')}"
            + (f" ({ping_rtt_ms:.0f} ms)" if ping_rtt_ms is not None else ""),
            f"snmp       {'n/a' if snmp_ok is None else ('ok' if snmp_ok else 'failed')}",
        ]
        if snmp_ok:
            detail_lines.append(f"interfaces {len(interfaces)}"
                                + ("" if interfaces_complete else " (incomplete)"))
            if interfaces_note:
                detail_lines.append(f"truncated  {interfaces_note}")
            detail_lines.append(f"metrics    {len(metrics)}")
            if snmp_error:
                detail_lines.append(f"degraded   {snmp_error}")
        elif snmp_error:
            detail_lines.append(f"error      {snmp_error}")
        detail_lines.append(f"elapsed    {time.time() - now:.2f}s")
        self.log.add(NODES, f"Polled {device['ip']}: {status}", target=device["ip"],
                    detail="\n".join(detail_lines))

    def _poll_poe_stp_environment(self, device, config: dict, cred_config: dict,
                                  metrics: list[tuple], now: float) -> None:
        """PoE, STP, environmental sensors, vendor sensors/PSU and the
        device's own addresses, run after the interface rows above are
        written, not before: PoE and STP write per-port columns keyed by
        (device_id, if_index), and a row that does not exist yet updates
        nothing. Each of the first four gets its own try, so a device that
        fails one keeps the others. Called only when snmp_ok and
        config["snmp_enabled"] -- see _poll_device."""
        device_id = device["id"]
        if config.get("poe_enabled", True):
            try:
                self._best_effort(f"PoE read for device #{device_id}",
                                  self._poll_poe,
                                  device_id, device, cred_config)
            except Exception:
                self._bump("errors")
                self.log.add(ERROR, f"PoE read failed for device #{device_id}",
                             detail=traceback.format_exc())
        if config.get("stp_enabled", True):
            try:
                self._best_effort(f"STP read for device #{device_id}",
                                  self._poll_stp,
                                  device_id, device, cred_config)
            except Exception:
                self._bump("errors")
                self.log.add(ERROR, f"STP read failed for device #{device_id}",
                             detail=traceback.format_exc())
        try:
            self._best_effort(
                f"Environmental sensor read for device #{device_id}",
                self._poll_environment,
                device_id, device, cred_config, {m[0] for m in metrics}, now)
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"Environmental sensor read failed for "
                                f"device #{device_id}",
                         detail=traceback.format_exc())
        try:
            self._best_effort(
                f"Vendor sensor/PSU read for device #{device_id}",
                self._poll_vendor_sensors,
                device_id, device, cred_config, now)
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"Vendor sensor/PSU read failed for "
                                f"device #{device_id}",
                         detail=traceback.format_exc())
        self._refresh_addresses(device, config)

    def working_config(self, device) -> dict:
        """The config an *on-demand* read should use — effective_config()
        merged with the credential this device actually answers on.

        effective_config() resolves a device's overrides over its profile's
        PRIMARY credential and nothing else. A profile can carry alternates
        (group_credentials, for a mixed-vendor subnet) and the poller caches
        whichever one works in self._credentials, so an on-demand read built
        straight from effective_config() would query a device answering on
        an alternate with the wrong community: every read a timeout, on a
        device the poller shows as up.

        One candidate (the overwhelmingly common case, and any device with
        its own credential override) costs nothing extra: it *is*
        effective_config. With alternates, the poller's cached winner is
        trusted; only a device the poller has not resolved yet is probed
        here, one cheap GET per candidate, and the winner is cached the same
        way the poll path caches it.
        """
        config = self.db.effective_config(device)
        candidates = self.db.credential_candidates(device)
        if len(candidates) <= 1:
            return config
        cached = self._credentials.get(device["id"])
        if cached is not None and cached < len(candidates):
            return {**config, **candidates[cached]}
        # A probe that just failed is not worth repeating for every read: the
        # interface dialog alone fires two (MAC table and DOM sensors), and an
        # unreachable device would pay the whole candidate sweep for each.
        failed_at = self._credential_probe_failed.get(device["id"], 0.0)
        if time.time() - failed_at < self._PROBE_RETRY_S:
            return config
        # retries=0, and a budget across the whole sweep: the probe only asks
        # "does this credential answer at all", and the real read that follows
        # still gets the device's full configured timeout and retries. With
        # them, an unreachable device with a few alternates took
        # candidates x timeout x (retries+1) — half a minute of a request a
        # human is waiting on, for a device that is simply down.
        deadline = time.time() + self._PROBE_BUDGET_S
        for index, candidate in enumerate(candidates):
            if time.time() > deadline:
                break
            trial = {**config, **candidate, "snmp_retries": 0}
            try:
                self._snmp_get(device, trial,
                               [nodeoids.SYSTEM_SCALARS["sys_object_id"]])
            except SnmpError as exc:
                if _credential_contradicted(exc):
                    break        # see _poll_snmp_scalars_with_credential
                continue
            self._credentials[device["id"]] = index
            # The winning credential is returned with the device's own retry
            # setting restored — only the probe went without them.
            return {**config, **candidate}
        self._credential_probe_failed[device["id"]] = time.time()
        return config

    def _snmp_get(self, device, config: dict, oids: list[str]) -> Response:
        """One GET round trip against a device, handling v1/v2c/v3 (at
        whichever USM level the credential implies) transparently, on a
        socket of its own. A caller making several GETs in a row should
        open one session and use _snmp_get_on instead."""
        session = self._session_for(device, config)
        try:
            return self._snmp_get_on(session, device, config, oids)
        finally:
            session.close()

    def _snmp_get_on(self, session: _Session, device, config: dict,
                     oids: list[str], credential: Credential | None = None) -> Response:
        """_snmp_get over an already-open session — the `_walk_request` /
        `_snmp_get_next` split, for GET.

        `credential` is the already-decrypted credential for `config` when
        the caller holds one for the length of its read (see
        _poll_interfaces): a v3 GET per interface otherwise re-decrypts the
        stored password blob once per port, 512 times on a full chassis.
        """
        version = snmp_version_of(config)
        if version in (0, 1):
            identity = (credential or credential_for(config)).identity
            request_id = session.next_request_id()
            packet = _assemble(build_request, version, identity or "public",
                               PDU_GET, request_id, oids)
            response = session.request(packet, request_id)
        else:
            response = self._v3_exchange(session, device, config, PDU_GET, oids,
                                         credential=credential)
        self._check_error_status(response, config, oids)
        return response

    def _v3_exchange(self, session: _Session, device, config: dict, pdu_tag: int,
                     oids: list[str], max_repetitions: int = 0,
                     credential: Credential | None = None) -> Response:
        """The poller's side of the module-level v3_exchange: the engine
        cache. Every v3 caller once went through its own copy of "build
        the message, send it, and if a Report comes back give up" — so a
        device whose engineBoots had incremented (a restart) failed every
        poll until something else invalidated the cache, and the operator
        was told only "engine resync required". The resync loop itself now
        lives in v3_exchange, shared with the Test button; what is left
        here is feeding it the cached engine parameters, keeping the ones
        a Report teaches, and dropping the entry when even the retry was
        refused — or when a request built from it drew no answer at all —
        so the next poll rediscovers from nothing.

        That last case is the one 5.8.1 added. A Report is the agent
        saying "not those parameters", and the resync loop learns from
        it; but an agent past a restart or a clock step may simply
        discard a message it will not accept, and silence teaches
        nothing. With the cache dropped only on _AuthFailure, a device
        that answered a stale engine with silence was polled with the
        same doomed request every cycle until the service was restarted
        (which is the only other thing that empties this cache). Three
        firewalls on one working profile did exactly that."""
        # Decrypted here unless the caller already holds one for the
        # length of its read; either way it is a local that is dropped in
        # the finally below, never cached on the poller.
        owned = credential is None
        credential = credential_for(config) if owned else credential
        device_id = device["id"]
        # Captured up front, not read again after the failure: the
        # question is whether the request that timed out was built from
        # a cached engine, and the cache may have been rewritten since.
        engine = self._engines.current(device_id)
        relearned = False

        def learned(engine_id: bytes, boots: int, engine_time: int) -> None:
            nonlocal relearned
            relearned = True
            self._engines.set(device_id, engine_id, boots, engine_time)

        try:
            return v3_exchange(
                session, pdu_tag, oids, identity=credential.identity,
                auth_proto=credential.auth_proto, password=credential.auth_password,
                engine=engine,
                max_repetitions=max_repetitions, ip=device["ip"], learned=learned,
                priv_proto=credential.priv_proto,
                priv_password=credential.priv_password,
                verify_replies=self._verify_replies)
        except _AuthFailure:
            self._engines.invalidate(device_id)
            raise
        except SnmpTimeout as exc:
            # Dropped after ONE timeout, not two, and only when the engine
            # that went out was cached and was NOT relearned during this
            # call. One SnmpTimeout reaching here is already retries + 1
            # unanswered datagrams (_Session.request retries; the profile
            # default snmp_retries is 2), so "consecutive" is built in one
            # layer down. The cost of dropping wrongly is one
            # unauthenticated discovery probe on the next poll of a device
            # that is already failing; the failure being cured is
            # permanent, and the churn avoided is one packet. Requiring a
            # second timeout would double the recovery latency (two poll
            # intervals) to save one datagram. The scope guard is the
            # fresh-engine rule, not a counter: an engine `learned` inside
            # this call — a discovery, or a Report's re-teach whose retry
            # then timed out — was just taught by the agent and is kept,
            # or a slow device would rediscover on every poll. An empty
            # cache has nothing to drop and must not claim it dropped one.
            if engine is None or relearned:
                raise
            self._engines.invalidate(device_id)
            engine_id, boots, engine_time = engine
            raise SnmpTimeout(
                f"{exc}; the request was built from a cached SNMPv3 engine "
                f"(boots {boots}, time {engine_time}) that an agent past a "
                f"restart or a clock step may discard without a Report, so "
                f"the cached engine was dropped and the next poll will "
                f"rediscover it") from exc
        finally:
            if owned:
                credential = None

    def _check_error_status(self, response: Response, config: dict,
                            oids: list[str]) -> None:
        """authorizationError(16) on a GET, raised with the object named and
        the credential's own explanation (access_denied_reason). Every
        other error-status is left in the Response for the caller to
        interpret, as it always was — noSuchName on one OID in a batch does
        not make the whole reply worthless. An instance method rather than
        the staticmethod it was, because a useful message needs `config`
        (which credential, at what level) and the request's OID list (what
        error-index counts into), and both callers are in _snmp_get with
        both in hand."""
        if response.error_status == 16:   # authorizationError
            raise SnmpAccessDenied(access_denied_reason(
                config, response, oids, security_level(config)))

    def _poll_snmp_scalars_with_credential(self, device, config: dict):
        """Resolves which SNMP credential actually works for this device
        this poll, then fetches the system scalars with it — one function,
        so a working credential is never fetched twice. Tries the cached
        last-known-good candidate (from self._credentials) first; on a
        cache miss, or if that candidate no longer works, walks the full
        candidate list from db.credential_candidates() in order. Every
        failure mode is credential-specific in a mixed profile — a v3
        authPriv alternate raises SnmpUnsupported on a host whose
        `cryptography` backend does not work, while a v2c alternate right
        after it works — so every SnmpError subclass is caught and the
        sweep goes on, with two exceptions.

        A failure that CONTRADICTS the credential does not rotate. A digest
        that did not verify, a reply that would not decrypt, or an unsigned
        answer to a signed request is this end refusing what came back,
        not the device refusing the request — and it is exactly what one
        forged datagram looks like. Rotating on it would let that datagram
        walk the poller off a verified v3 credential and onto the cleartext
        v1/v2c community further down the list, which is a downgrade an
        attacker can ask for. Only a refusal the DEVICE named (a Report,
        an authorizationError, a level it does not serve, silence) is
        worth trying the next candidate on.

        And once every candidate has failed, the MOST SPECIFIC error is
        re-raised, not the last. A profile whose v3 primary is refused by
        name and whose v2c alternate the device simply ignores used to
        show whichever came last — the alternate's "no reply" — and hide
        the one message that named the fault; a sweep that ends in a
        timeout after a named refusal is still that refusal. Among equals
        the later one still wins, as before.
        Returns (winning_config, identity, uptime_ticks, metrics)."""
        device_id = device["id"]
        candidates = self.db.credential_candidates(device)
        cached_index = self._credentials.get(device_id)
        order = [cached_index] if cached_index is not None and cached_index < len(candidates) else []
        order += [i for i in range(len(candidates)) if i not in order]
        # A device that is simply down does not need its whole credential
        # list re-tried on every poll: four candidates at 3 s and two
        # retries is 36 s of a worker per poll, per down device. After a
        # sweep has failed, only the last-known-good candidate (or the
        # first, if there is none) is tried until the retry window passes —
        # the same negative caching the on-demand path in working_config
        # has always had.
        failed_at = self._credential_probe_failed.get(device_id, 0.0)
        if len(order) > 1 and time.time() - failed_at < self._PROBE_RETRY_S:
            order = order[:1]
        last_error: Exception | None = None
        for index in order:
            trial_config = {**config, **candidates[index]}
            try:
                identity, uptime_ticks, metrics = self._poll_snmp_scalars(device, trial_config)
            except SnmpError as exc:
                if _credential_contradicted(exc):
                    raise
                if last_error is None or \
                        _error_specificity(exc) >= _error_specificity(last_error):
                    last_error = exc
                continue
            if cached_index is not None and index != cached_index:
                # A genuine credential change may answer UCD-SNMP differently.
                self._ucd_read.pop(device_id, None)
                self._ucd_capable.pop(device_id, None)
            self._credentials[device_id] = index
            self._credential_probe_failed.pop(device_id, None)
            return trial_config, identity, uptime_ticks, metrics
        if len(candidates) > 1:
            self._credential_probe_failed[device_id] = time.time()
        raise last_error or SnmpTimeout(f"no reply from {device['ip']}")

    def _identity_extras(self, device, config: dict, oids: list[str]) -> dict:
        """Answers to identity OIDs read in a GET of their own, best-effort.

        Separate from the scalar GET so that an object the device does not
        implement can cost nothing but this request — on SNMPv1 an
        unimplemented object in a request spoils every answer in it, and
        identity is the one thing that must not be lost that way. Failure is
        silent for the same reason the UCD-SNMP read below is: not answering
        is the normal case, not an error.
        """
        return self._identity_extras_detail(device, config, oids)[0]

    def _identity_extras_detail(self, device, config: dict,
                                oids: list[str]) -> tuple:
        """(answers, whether the GET itself got a reply); only _poll_software_version needs the distinction."""
        if not oids:
            return {}, True
        try:
            response = self._snmp_get(device, config, oids)
        except SnmpError:
            return {}, False
        return ({vb["oid"]: vb["value"] for vb in response.varbinds
                 if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                       "endOfMibView")}, True)

    _SW_WALK_MAX_AGE_S = 86400.0

    def _sw_walk_due(self, device_id: int, sys_descr: str,
                     uptime_ticks: int | None, now: float) -> bool:
        """No walk on record, stale, sysDescr changed, or rebooted since."""
        state = self._sw_walk_state.get(device_id)
        if state is None:
            return True
        walked_at, walked_descr, walked_ticks, _chassis_idx = state
        if now - walked_at >= self._SW_WALK_MAX_AGE_S:
            return True
        if sys_descr != walked_descr:
            return True
        if uptime_ticks is not None and walked_ticks is not None:
            rebooted, _note = detect_reboot(uptime_ticks, now, walked_ticks, walked_at)
            if rebooted:
                return True
        return False

    def _walk_sw_columns(self, device, config: dict, arc) -> dict:
        """{column OID: {index: value}} for the arc's SW_VERSION_COLUMNS entry."""
        (sw_column, fw_column), status_column = nodeoids.SW_VERSION_COLUMNS[arc]
        deadline = self._table_walk_deadline(config, "poll_interval_s")
        columns = {}
        for oid in (sw_column, fw_column, status_column):
            if oid:
                rows = self._walk_column(device, config, oid, deadline=deadline)
                if rows:
                    columns[oid] = rows
        return columns

    def _entity_software_walk(self, device, config: dict,
                              cached_chassis_idx: int | None) -> tuple[dict, int | None]:
        """(scalars keyed as swversion's _FIRST constants, chassis index found).
        A cached index costs one GET; otherwise entPhysicalClass is walked for
        the chassis row (class 3), else the first populated SoftwareRev row."""
        idx = cached_chassis_idx
        if idx is None:
            deadline = self._table_walk_deadline(config, "poll_interval_s")
            classes = _int_keyed(self._walk_column(
                device, config, self._ENT_PHYSICAL_CLASS, deadline=deadline))
            for suffix, value in sorted(classes.items()):
                if str(value).strip() == str(self._ENT_CLASS_CHASSIS):
                    idx = suffix
                    break
        if idx is not None:
            sw_oid = f"{nodeoids.ENT_PHYSICAL_SOFTWARE_REV}.{idx}"
            fw_oid = f"{nodeoids.ENT_PHYSICAL_FIRMWARE_REV}.{idx}"
            answers = self._identity_extras(device, config, [sw_oid, fw_oid])
            scalars = {}
            if answers.get(sw_oid):
                scalars[nodeoids.ENT_PHYSICAL_SOFTWARE_REV_FIRST] = answers[sw_oid]
            if answers.get(fw_oid):
                scalars[nodeoids.ENT_PHYSICAL_FIRMWARE_REV_FIRST] = answers[fw_oid]
            if scalars:
                return scalars, idx
        # No chassis row named (or the targeted GET answered nothing): the
        # first row of the whole software column, whatever entity it is.
        deadline = self._table_walk_deadline(config, "poll_interval_s")
        rows = _int_keyed(self._walk_column(
            device, config, nodeoids.ENT_PHYSICAL_SOFTWARE_REV, deadline=deadline))
        for suffix in sorted(rows):
            if rows[suffix]:
                return {nodeoids.ENT_PHYSICAL_SOFTWARE_REV_FIRST: rows[suffix]}, None
        return {}, None

    def _poll_software_version(self, device, config: dict, identity: dict) -> dict:
        """Version keys for the identity dict: one GET, then at most one gated
        walk (vendor column, else ENTITY-MIB chassis row). No keys at all when
        nothing new was learned, so the stored values stay."""
        arc = identity.get("vendor_arc")
        device_id = device["id"]
        oids = list(swversion.oids_for(arc))
        scalars, answered = self._identity_extras_detail(device, config, oids)
        sys_descr = identity.get("sys_descr") or ""
        info = swversion.extract(arc, sys_descr, scalars)

        now = time.time()
        uptime_ticks = identity.get("sys_uptime_ticks")
        state = self._sw_walk_state.get(device_id)
        cached_chassis_idx = state[3] if state else None
        walk_due = answered and self._sw_walk_due(device_id, sys_descr, uptime_ticks, now)
        walked = False
        columns = {}

        if not info.version and arc in nodeoids.SW_VERSION_COLUMNS and walk_due:
            columns = self._walk_sw_columns(device, config, arc)
            info = swversion.extract(arc, sys_descr, scalars, columns)
            self._sw_walk_state[device_id] = (now, sys_descr, uptime_ticks, cached_chassis_idx)
            walked = True

        if not info.version and walk_due:
            entity_scalars, chassis_idx = self._entity_software_walk(
                device, config, cached_chassis_idx)
            if entity_scalars:
                info = swversion.extract(arc, sys_descr, {**scalars, **entity_scalars},
                                         columns)
            self._sw_walk_state[device_id] = (now, sys_descr, uptime_ticks, chassis_idx)
            walked = True

        if oids and not answered and not info.source:
            return {}
        if not info.version and not walked:
            return {}
        return {"sw_version": info.version or None, "sw_image": info.image or None,
                "sw_image_file": info.image_file or None,
                "fw_version": info.firmware or None,
                "sw_source": info.source or None, "fw_source": info.fw_source or None}

    def _poll_snmp_scalars(self, device, config: dict):
        device_id = device["id"]
        oids = list(nodeoids.SYSTEM_SCALARS.values())
        # An operator-chosen OID for vendor and/or location. Both the bare and
        # the .0 instance form are asked for, because "1.3.6.1.4.1.x.y" and
        # "…y.0" are both reasonable things to type and only one of them
        # answers; whichever does is used. See nodeoids.identity_oid_variants.
        #
        # On v2c and v3 they ride in the SAME GET as the standard scalars,
        # for no extra round trip: an unimplemented object comes back as a
        # per-varbind noSuchObject and the rest of the response is unharmed.
        # SNMPv1 has no such thing — it answers noSuchName with the whole
        # varbind list echoed back as nulls, which would blank sysDescr,
        # sysObjectID, sysName and sysLocation on every v1 device with a
        # custom identity OID set. By construction at least one of the two
        # forms cannot answer, so on v1 they are read separately and
        # best-effort. Note the missing `or 1`: that fallback turns a
        # configured 0 (v1) into 1 (v2c) and would make this branch
        # unreachable for exactly the devices it protects.
        configured_version = config.get("snmp_version")
        is_v1 = configured_version is not None and int(configured_version) == 0
        custom = nodeoids.identity_oid_variants(config)
        if custom["all"] and not is_v1:
            oids += [oid for oid in custom["all"] if oid not in oids]
        # One socket from here through the UCD-SNMP read below -- the whole
        # span is in the try, not just the first GET, since an exception
        # from anything in between (a v1 identity extra, a credential
        # verdict out of _poll_software_version) leaked this socket too.
        session = self._session_for(device, config)
        try:
            response = self._snmp_get_on(session, device, config, oids)
            values = {vb["oid"]: vb["value"] for vb in response.varbinds
                      if vb["type"] not in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView")}
            if custom["all"] and is_v1:
                values.update(self._identity_extras(device, config, custom["all"]))
            identity = {
                "sys_descr": values.get(nodeoids.SYSTEM_SCALARS["sys_descr"]) or "",
                "sys_object_id": values.get(nodeoids.SYSTEM_SCALARS["sys_object_id"]) or "",
                "sys_name": values.get(nodeoids.SYSTEM_SCALARS["sys_name"]) or "",
                "sys_contact": values.get(nodeoids.SYSTEM_SCALARS["sys_contact"]) or "",
                "sys_location": values.get(nodeoids.SYSTEM_SCALARS["sys_location"]) or "",
            }
            # The zero-SNMP half of vendor identification, every poll: a manual
            # or learned vendor, a real vendor arc in sysObjectID, the walk this
            # device already had for this sysObjectID, then the sysDescr guess.
            # See vendorid.poll_decision for the order and why.
            detected, source, confidence, vendor_arc = vendorid.poll_decision(
                identity["sys_object_id"], identity["sys_descr"], device,
                self.db.learned_vendor(identity["sys_object_id"]))
            # Always stored, always what the behavioural readers use — a custom
            # vendor name replaces the display value only (see
            # nodesdb.detected_vendor).
            identity["vendor_detected"] = detected
            identity["vendor"], identity["vendor_source"] = detected, source
            identity["vendor_confidence"] = confidence
            identity["vendor_arc"] = vendor_arc

            custom_vendor = nodeoids.first_text(values, custom["vendor"])
            if custom_vendor:
                identity["vendor"] = custom_vendor
                identity["vendor_source"] = "oid"
            custom_location = nodeoids.first_text(values, custom["location"])
            if custom_location:
                identity["sys_location"] = custom_location

            uptime = values.get(nodeoids.SYSTEM_SCALARS["sys_uptime"])
            uptime_ticks = int(uptime) if isinstance(uptime, (int, float)) else None
            # _sw_walk_due tells a reboot from a re-poll with this.
            identity["sys_uptime_ticks"] = uptime_ticks

            identity.update(self._poll_software_version(device, config, identity))

            metrics = []

            def read_ucd_snmp():        # best-effort: often not present at all
                # Probe-once-remember'd like _mau_capable.
                capable = self._ucd_capable.get(device_id)
                due = (time.time() - self._ucd_read.get(device_id, 0.0)
                      >= self._SENSOR_REPROBE_S)
                if capable is False and not due:
                    return
                self._ucd_read[device_id] = time.time()
                extra_response = self._snmp_get_on(session, device, config,
                                                   list(nodeoids.UCD_SNMP.values()))
                extra = {vb["oid"]: vb["value"] for vb in extra_response.varbinds
                         if vb["type"] not in ("noSuchObject", "noSuchInstance")}
                if extra:
                    self._ucd_capable[device_id] = True
                elif capable is None:
                    self._ucd_capable[device_id] = False
                idle = extra.get(nodeoids.UCD_SNMP["cpu_raw_idle"])
                if isinstance(idle, (int, float)):
                    metrics.append(("cpu_pct", "CPU", "%", "gauge", max(0.0, 100.0 - float(idle))))
                avail = extra.get(nodeoids.UCD_SNMP["mem_avail_kb"])
                total = extra.get(nodeoids.UCD_SNMP["mem_total_kb"])
                if isinstance(avail, (int, float)) and isinstance(total, (int, float)) and total:
                    metrics.append(("mem_pct", "Memory", "%", "gauge",
                                   max(0.0, 100.0 * (1 - float(avail) / float(total)))))

            self._best_effort(f"UCD-SNMP read for {device['ip']}", read_ucd_snmp)
        finally:
            session.close()

        metrics.extend(self._poll_vendor_health(device, config, identity,
                                                already={m[0] for m in metrics}))
        # UPS-MIB: battery/output health for anything wired to a UPS that
        # answers SNMP. Not arc-gated the way _poll_vendor_health is — see
        # nodeoids.UPS_HEALTH's module comment for why — so it is read here,
        # best-effort, on every device exactly like the UCD-SNMP block
        # above rather than folded into _poll_vendor_health's per-arc loop.
        metrics.extend(self._poll_ups_health(device, config, identity,
                                             already={m[0] for m in metrics}))
        # RSSI/SNR/capacity for a PtP wireless bridge — the same
        # arc-gated, best-effort scalar shape _poll_vendor_health uses just
        # above, kept as its own method because RF is not "health" and has
        # its own OID table (nodeoids.RF_METRICS).
        metrics.extend(self._poll_rf_metrics(device, config, identity))
        return identity, uptime_ticks, metrics

    # How often a device's ipAddrTable is re-read. Its addresses change when
    # somebody reconfigures it, not between polls, and the walk exists to
    # correlate traps and syslog rather than to chart anything — so once an
    # hour, not on the poll cycle.
    _ADDRESS_REFRESH_S = 3600.0

    def _health_column(self, device, config: dict, oid: str, how: str):
        """One vendor table column, reduced to a single number.

        Best-effort throughout: a device that does not implement the column
        answers nothing and contributes nothing, exactly like the UCD-SNMP
        read above. Errors are swallowed for the same reason — not
        answering a vendor object is the normal case, not a poll failure.
        """
        try:
            values = self._walk_column(device, config, oid)
        except SnmpError:
            return None
        numbers = [float(value) for value in values.values()
                   if isinstance(value, (int, float))]
        if not numbers:
            return None
        if how == "column_max":
            return max(numbers)
        if how == "column_avg":
            return sum(numbers) / len(numbers)
        return numbers[0]

    def _cisco_memory_pct(self, device, config: dict):
        """Cisco reports memory as used and free bytes per pool rather than
        as a percentage. Pools are summed: a router with a processor pool
        and an I/O pool has one memory figure, not two."""
        try:
            used = self._walk_column(device, config, nodeoids.CISCO_MEMORY_USED)
            free = self._walk_column(device, config, nodeoids.CISCO_MEMORY_FREE)
        except SnmpError:
            return None
        used_total = sum(float(v) for v in used.values()
                         if isinstance(v, (int, float)))
        free_total = sum(float(v) for v in free.values()
                         if isinstance(v, (int, float)))
        total = used_total + free_total
        if total <= 0:
            return None
        return 100.0 * used_total / total

    def _host_resources_storage_rows(self, device, config: dict) -> tuple:
        """(types, sizes, used) — hrStorageType/Size/Used, walked ONCE and
        shared by every reader of hrStorageTable (today: disk_pct's worst
        fixed disk and mem_pct's HOST-RESOURCES fallback), so a device that
        needs both pays for this table exactly once per poll rather than
        once per kind of row somebody wants out of it. All three empty
        dicts on a device with no HOST-RESOURCES-MIB support at all, or on
        any SnmpError — best-effort, same as everything else this reads."""
        try:
            types = self._walk_column(device, config, nodeoids.HR_STORAGE_TYPE)
            if not types:
                return {}, {}, {}
            sizes = self._walk_column(device, config, nodeoids.HR_STORAGE_SIZE)
            used = self._walk_column(device, config, nodeoids.HR_STORAGE_USED)
        except SnmpError:
            return {}, {}, {}
        return types, sizes, used

    @staticmethod
    def _worst_storage_pct(types: dict, sizes: dict, used: dict,
                           wanted_type: str) -> float | None:
        """The fullest hrStorageTable row of one hrStorageType, as a
        percentage — disk_pct and mem_pct are the same computation over a
        different type. No allocation-unit scaling: a used/size ratio does
        not need it."""
        worst = None
        for index, kind in types.items():
            if str(kind).strip(".") != wanted_type:
                continue
            size = sizes.get(index)
            taken = used.get(index)
            if not isinstance(size, (int, float)) or not isinstance(taken, (int, float)):
                continue
            if size <= 0:
                continue
            pct = 100.0 * float(taken) / float(size)
            worst = pct if worst is None else max(worst, pct)
        return worst

    def _host_resources_disk_pct(self, types: dict, sizes: dict, used: dict):
        """The busiest fixed disk, as a percentage, from an already-walked
        hrStorageTable (see _host_resources_storage_rows).

        hrStorageTable also holds RAM and virtual memory rows; reporting
        those as disk would make a machine using its page cache look full.
        Only hrStorageFixedDisk rows count, and the fullest of them is what
        an operator means by "the disk is filling up"."""
        return self._worst_storage_pct(types, sizes, used,
                                       nodeoids.HR_STORAGE_FIXED_DISK)

    def _host_resources_mem_pct(self, types: dict, sizes: dict, used: dict):
        """Physical memory as a percentage, from the same already-walked
        hrStorageTable _host_resources_disk_pct reads — the HOST-RESOURCES
        fallback for mem_pct, tried only when UCD-SNMP, the Fortinet scalar
        and the Cisco memory pool all failed to answer.

        hrStorageRam only: hrStorageVirtualMemory (swap) sits under a
        different type and is never counted, because a machine with an
        ordinary swap file would otherwise read as critically low on RAM.
        """
        return self._worst_storage_pct(types, sizes, used, nodeoids.HR_STORAGE_RAM)

    def _refresh_addresses(self, device, config: dict) -> None:
        """Remember every address this device answers on.

        A switch sends its traps from a loopback and its syslog from a
        management VRF, and neither address is in the devices table, so the
        alert engine could not tell whose message it was. ipAddrTable says
        which addresses are the device's own. Walked at most once an hour
        per device — see _ADDRESS_REFRESH_S."""
        device_id = device["id"]
        now = time.time()
        if now - self._addresses_read.get(device_id, 0.0) < self._ADDRESS_REFRESH_S:
            return
        self._addresses_read[device_id] = now
        try:
            rows = self._walk_column(device, config, nodeoids.IP_ADDR_TABLE)
        except SnmpError:
            return
        # Joined on the index suffix (the address, for ipAddrTable); each
        # is its own best-effort walk so a partial answer still records.
        details = {}
        for oid, key in ((nodeoids.IP_ADDR_IFINDEX, "if_index"),
                         (nodeoids.IP_ADDR_NETMASK, "netmask")):
            try:
                extra = self._walk_column(device, config, oid)
            except SnmpError:
                continue
            for suffix, value in extra.items():
                if value is None or value == "":
                    continue
                # Must match record_device_addresses' folded lookup key.
                address = nodesdb.alias_candidate(rows.get(suffix) or suffix)
                if not address:
                    continue
                try:
                    entry = int(value) if key == "if_index" else str(value)
                except (TypeError, ValueError):
                    continue
                details.setdefault(address, {})[key] = entry
        addresses = [str(value) for value in rows.values() if value]
        self.db.record_device_addresses(device_id, addresses, nodesdb.CONFIGURED_SOURCE,
                                        details=details, complete=True)
        self._refresh_default_gateway(device, config)

    @staticmethod
    def _gateway_candidate(value) -> str:
        """A next-hop value as stored, or "" for anything that is not a
        real, non-default IP address — the same alias_candidate gate
        _refresh_addresses uses, plus an ipaddress parse so a misbehaving
        agent's OctetString or integer answer can't land in the column."""
        text = nodesdb.alias_candidate(value)
        if not text:
            return ""
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return ""
        return text

    def _refresh_default_gateway(self, device, config: dict) -> None:
        """Default-route next hop, tried in order (ipCidrRouteTable is empty
        on IOS 15.x/IOS-XE); first to answer wins, none leaves it alone."""
        device_id = device["id"]
        try:
            route_rows = self._walk_column(device, config,
                                            nodeoids.IP_CIDR_ROUTE_NEXTHOP_DEFAULT)
            walked = True
        except SnmpError:
            route_rows = {}
            walked = False
        if walked and route_rows:
            hops = {self._gateway_candidate(v) for v in route_rows.values()}
            hops.discard("")
            if hops:
                self.db.set_default_gateway(device_id, ", ".join(sorted(hops)))
                return
        try:
            inet_rows = self._walk_column(
                device, config, nodeoids.INET_CIDR_ROUTE_NEXTHOP_DEFAULT_V4)
            inet_walked = True
        except SnmpError:
            inet_rows = {}
            inet_walked = False
        if inet_walked and inet_rows:
            hops = {self._gateway_candidate(_inet_address_text(v))
                    for v in inet_rows.values()}
            hops.discard("")
            if hops:
                self.db.set_default_gateway(device_id, ", ".join(sorted(hops)))
                return
        try:
            response = self._snmp_get(device, config, [nodeoids.IP_ROUTE_NEXTHOP_DEFAULT])
        except SnmpError:
            return
        vb = next((v for v in response.varbinds
                  if v["oid"] == nodeoids.IP_ROUTE_NEXTHOP_DEFAULT), None)
        value = self._gateway_candidate(vb["value"]) if vb and vb["value"] else ""
        self.db.set_default_gateway(device_id, value)

    def _poll_vendor_health(self, device, config: dict, identity: dict,
                            already=()) -> list[tuple]:
        """CPU, memory, disk, temperature and session count for real network
        gear, keyed on the vendor arc SNMP identification worked out.

        Everything here is best-effort and additive: the thresholds are
        unchanged, so a device that starts answering cpu_pct can now open
        `cpu_high` where it previously reported nothing at all. Only the
        objects the device's own maker defines are asked for; the
        HOST-RESOURCES fallback runs only when neither the vendor table nor
        UCD-SNMP produced a figure, so a net-snmp box costs nothing extra.
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc(
                (identity or {}).get("sys_object_id") or "")
        metrics: list[tuple] = []
        # `already` is what the UCD-SNMP read produced. A vendor's own
        # object beats it — a FortiGate that also answers UCD-SNMP is still
        # better described by fgSysCpuUsage — so the vendor probes below
        # ignore it and record_metric_samples keeps the last value per key.
        # Only the generic HOST-RESOURCES fallback respects it, so a
        # net-snmp box costs no extra requests at all.
        produced: set = set()

        def add(key, label, unit, value):
            if value is None or key in produced:
                return
            produced.add(key)
            metrics.append((key, label, unit, "gauge", float(value)))

        probes = nodeoids.VENDOR_HEALTH.get(arc, ())
        scalars = [probe for probe in probes if probe[4] == "scalar"]
        if scalars:
            try:
                response = self._snmp_get(device, config,
                                          [probe[3] for probe in scalars])
                values = {vb["oid"]: vb for vb in response.varbinds}
            except SnmpError:
                values = {}
            for key, label, unit, oid, _how in scalars:
                vb = values.get(oid)
                if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                             "endOfMibView", "null") \
                        and isinstance(vb["value"], (int, float)):
                    add(key, label, unit, vb["value"])
        for key, label, unit, oid, how in probes:
            if how == "scalar" or key in produced:
                continue
            add(key, label, unit, self._health_column(device, config, oid, how))
        if arc == 9:
            add("mem_pct", "Memory", "%",
                self._cisco_memory_pct(device, config))
        known = produced | set(already)
        if "cpu_pct" not in known:
            for key, label, unit, oid, how in nodeoids.GENERIC_HEALTH:
                add(key, label, unit,
                    self._health_column(device, config, oid, how))
        # hrStorageTable answers BOTH disk_pct's and mem_pct's HOST-RESOURCES
        # fallback, so it is walked once and only when at least one of the two
        # is still missing.
        if "disk_pct" not in known or "mem_pct" not in known:
            types, sizes, used = self._host_resources_storage_rows(device, config)
            if types:
                if "disk_pct" not in known:
                    add("disk_pct", "Storage", "%",
                        self._host_resources_disk_pct(types, sizes, used))
                if "mem_pct" not in known:
                    add("mem_pct", "Memory", "%",
                        self._host_resources_mem_pct(types, sizes, used))
        return metrics

    def _poll_rf_metrics(self, device, config: dict, identity: dict) -> list[tuple]:
        """RSSI/SNR/link-capacity for a point-to-point wireless bridge,
        gated on the vendor arc this poll's identity already worked out:
        RF_METRICS has no entry for anything that is not a radio, so the
        GET below never costs a packet against a device it does not apply
        to.
        """
        arc = identity.get("vendor_arc") if identity else None
        if arc is None:
            arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
        probes = nodeoids.RF_METRICS.get(arc, ())
        if not probes:
            return []
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in probes])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            return []
        metrics = []
        for key, label, unit, oid, _how in probes:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                metrics.append((key, label, unit, "gauge", float(vb["value"])))
        if metrics:
            self._bump("rf_polls")
        return metrics

    def _poll_ups_health(self, device, config: dict, identity: dict,
                         already=()) -> list[tuple]:
        """UPS-MIB (RFC 1628) battery/output health.

        Tried on EVERY device, not gated by enterprise arc the way
        VENDOR_HEALTH is — see nodeoids.UPS_HEALTH's module comment for
        why keying this to a vendor list would not work for a UPS the way
        it does for a switch or router.

        Cost is bounded twice. Within a poll: one GET of every scalar in
        the table, and the two per-line table walks only once that GET
        shows a scalar answered. Across polls: devices.ups_capable is the
        probe-once-remember memory _poll_poe/_poll_stp use, so a confirmed
        not-a-UPS is skipped entirely rather than paying that GET forever.
        Recorded only on the FIRST probe (capable is None) — a UPS that
        times out one poll must not be relabelled incapable.
        """
        metrics: list[tuple] = []
        capable = device["ups_capable"]
        if capable == 0:
            return metrics
        scalars = [probe for probe in nodeoids.UPS_HEALTH if probe[4] == "scalar"]
        try:
            response = self._snmp_get(device, config, [probe[3] for probe in scalars])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            # No answer at all, same as every scalar coming back
            # noSuchObject — folded into the `answered = False` path below
            # (same as _poll_poe/_poll_stp do for their own tables) so an
            # outright timeout on the first-ever probe still gets recorded
            # rather than silently retried forever.
            values = {}
        answered = False
        for key, label, unit, oid, _how, scale in scalars:
            vb = values.get(oid)
            if vb and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                         "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                answered = True
                if key not in already:
                    metrics.append((key, label, unit, "gauge",
                                    float(vb["value"]) * scale))
        if not answered:
            # Nothing in the scalar batch answered: not a UPS (or a UPS
            # that does not implement UPS-MIB at all), so the two column
            # walks below are skipped rather than sent to every non-UPS
            # device in the fleet on every poll.
            if capable is None:
                self.db.set_ups_capable(device["id"], False)
            return metrics
        if capable is None:
            self.db.set_ups_capable(device["id"], True)
        for key, label, unit, oid, how, scale in nodeoids.UPS_HEALTH:
            if how == "scalar" or key in already:
                continue
            value = self._health_column(device, config, oid, how)
            if value is not None:
                metrics.append((key, label, unit, "gauge", value * scale))
        if "ups_runtime_min" not in already and \
                not any(m[0] == "ups_runtime_min" for m in metrics):
            arc = identity.get("vendor_arc") if identity else None
            if arc is None:
                arc = nodeoids.enterprise_arc((identity or {}).get("sys_object_id") or "")
            if arc == 318:   # APC / Schneider
                runtime = self._apc_runtime_fallback(device, config)
                if runtime is not None:
                    metrics.append(("ups_runtime_min", "Estimated runtime remaining",
                                    "min", "gauge", runtime))
        return metrics

    def _apc_runtime_fallback(self, device, config: dict) -> float | None:
        """APC PowerNet-MIB's upsAdvBatteryRunTimeRemaining, in TimeTicks
        (hundredths of a second), converted to minutes — read only when
        the standard upsEstimatedMinutesRemaining scalar did not answer.
        See nodeoids.APC_BATTERY_RUNTIME_TIMETICKS for why this one
        fallback, alone among everything else this module reads, is not
        cross-checked against a live unit."""
        try:
            response = self._snmp_get(
                device, config, [nodeoids.APC_BATTERY_RUNTIME_TIMETICKS])
        except SnmpError:
            return None
        for vb in response.varbinds:
            if vb["oid"] == nodeoids.APC_BATTERY_RUNTIME_TIMETICKS \
                    and vb["type"] not in ("noSuchObject", "noSuchInstance",
                                           "endOfMibView", "null") \
                    and isinstance(vb["value"], (int, float)):
                return float(vb["value"]) / 100.0 / 60.0
        return None

    def _check_vendor_mib(self, device_id: int, previous, identity: dict | None,
                          defer_assignment: bool = False) -> None:
        """Says so when a device's vendor is identified but no uploaded MIB
        describes that vendor's objects, so an admin knows there is a MIB to
        add rather than wondering why the metrics never appear.

        Coverage is re-evaluated every poll and compared against the
        persisted verdict (devices.mib_covered), with events on transitions
        only — keying off sysObjectID changes instead would make the feature
        inert for every device whose identity was already stored, and could
        neither clear on a later upload nor re-fire on a deletion.
        mib_present pairs with mib_missing in alertrules.CLEARS, so the
        upload auto-resolves the alert."""
        if not identity:
            return
        sys_object_id = identity.get("sys_object_id") or ""
        # The vendor that was *detected* (never the display value a custom
        # OID may have replaced), and the arc it was decided from: the
        # sysObjectID's own for a real vendor arc, the walk's for a
        # generic-agent device. Coverage is asked about THAT arc — a
        # net-snmp box identified as Phoenix Contact by the walk needs the
        # Phoenix MIB, and asking about arc 8072 would never say so.
        vendor = identity.get("vendor_detected") or identity.get("vendor") or ""
        vendor_arc = identity.get("vendor_arc")
        if vendor_arc is None and "vendor_arc" not in identity:
            # An older-shaped identity (tests, replays): fall back to the
            # 4.31 rule, sysObjectID's arc only.
            vendor = vendor or nodeoids.identify_vendor(
                sys_object_id, identity.get("sys_descr") or "")[0]
            vendor_arc = nodeoids.enterprise_arc(sys_object_id)
        applicable = bool(vendor) and vendor_arc is not None
        was_covered = previous["mib_covered"]      # None / 0 / 1
        if not applicable:
            # The coverage question doesn't apply (no identity yet, a
            # standard-tree sysObjectID, or no recognizable vendor); make
            # sure no stale verdict lingers from a previous identity.
            if was_covered is not None:
                self.db.set_mib_covered(device_id, None)
            return
        coverage_oid = f"{nodeoids.ENTERPRISES}.{vendor_arc}"
        covered = self.db.has_mib_covering(coverage_oid)
        # While an identification walk is still due for this device, the
        # poll path leaves assignment to it: the walk's pick is the file that
        # actually named this device's objects, and an assignment made here
        # first — by "the file with the most objects under the arc" — would
        # stand, because assignment never overrides an existing choice.
        if covered and not defer_assignment:
            self._auto_assign_mib(device_id, coverage_oid, vendor,
                                  preferred=identity.get("preferred_mib_file_id"))
        if covered and not (was_covered is None or was_covered):
            # uncovered -> covered: the MIB arrived. CLEARS resolves the
            # standing mib_missing alert off this event.
            self.db.record_device_event(
                device_id, "mib_present",
                f"An uploaded MIB now describes {vendor} objects "
                f"(enterprise arc {vendor_arc}); vendor-specific data can be decoded.")
        elif not covered and (was_covered is None or was_covered):
            # first verdict, or covered -> uncovered (a MIB was deleted).
            bundle = mibcatalog.bundle_for_arc(vendor_arc)
            hint = (f"Install the {bundle.name} bundle from the MIB catalog"
                    if bundle else f"Upload the {vendor} MIB under Nodes → Profiles & MIBs")
            self.db.record_device_event(
                device_id, "mib_missing",
                f"No uploaded MIB describes {vendor} objects (enterprise arc "
                f"{vendor_arc}). {hint} to decode this device's vendor-specific data.")
        if was_covered is None or bool(was_covered) != covered:
            self.db.set_mib_covered(device_id, covered)

    def _auto_assign_mib(self, device_id: int, sys_object_id: str,
                         vendor: str, preferred: int | None = None) -> None:
        """Point a device at its own vendor's MIB once one is present.

        Assignment happens only where the operator has expressed no
        preference — and a preference can live on the polling profile as
        well as the device: mib_file_id is an _OVERRIDE_COLUMNS entry, so a
        device-level auto-assignment layered over a group whose MIB was
        chosen by hand would BEAT that choice. Hence the effective
        (device-or-group) value is what is checked, not the device column.
        mib_file_auto marks the pick so it is not counted as an override.
        """
        device = self.db.device(device_id)
        if device is None:
            return
        if self.db.effective_config(device).get("mib_file_id") is not None:
            return
        # The fingerprint's pick — the file that actually named the most of
        # what this device answered — beats "the file with the most objects
        # under the arc", which is a guess about the device from the MIB
        # alone. Only when the preferred file still exists.
        mib_file_id = preferred if preferred and self.db.mib_file(preferred) else None
        by_evidence = mib_file_id is not None
        if mib_file_id is None:
            mib_file_id = self.db.mib_file_covering(sys_object_id)
        if mib_file_id is None:
            return
        self.db.update_device(device_id, mib_file_id=mib_file_id, mib_file_auto=1)
        mib = self.db.mib_file(mib_file_id)
        name = (mib["module"] if mib and mib["module"] else
                (mib["filename"] if mib else str(mib_file_id)))
        why = ("the identification walk matched its objects on this device"
               if by_evidence else
               f"it describes {vendor} objects (enterprise arc "
               f"{nodeoids.enterprise_arc(sys_object_id)})")
        # Recorded, not silent: this changes what gets polled every cycle, so
        # it belongs in the device's own event history where it can be seen
        # and undone rather than being discovered from new metric names.
        self.db.record_device_event(
            device_id, "mib_assigned",
            f"Assigned the {name} MIB to this device automatically: {why} "
            f"and no MIB had been chosen. Change or clear it under this "
            f"device's Custom MIB override.")

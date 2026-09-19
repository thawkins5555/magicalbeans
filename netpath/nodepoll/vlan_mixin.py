from __future__ import annotations

import time
import traceback
from .. import nodeoids
from ..eventlog import ERROR, NODES
from ..nodeoids import DEFAULT_SNMP_PORT
from ..nodesdb import detected_vendor
from ..snmppoll import PDU_GETBULK, PDU_GETNEXT, Response, SnmpError, SnmpTimeout, build_request
from ._consts import _MAX_VLANS, _VLAN_WALK_BUDGET_S
from ._decode import _decode_port_list, _decode_vlan_bitmap, _int_keyed, _oid_key
from ._jobs import _OidWalkJob
from ._session import _Session, _assemble, _credential_label, _error_status_reason, credential_for, snmp_version_of


class VlanMixin:

    # ------------------------------------------------- VLAN membership

    def read_device_vlans(self, device_id: int) -> dict | None:
        """Every VLAN this device names, which of its ports are trunk/
        access (and a trunk's native VLAN), and which VLANs actually cross
        which port — the whole-device counterpart of read_device_neighbors,
        with the same None-vs-dict contract: None means nothing answered at
        all (storage untouched by _run_vlan_table); a dict — even one whose
        lists are all empty — is a genuine "walked, and this is what came
        back", which is what lets a membership that has truly gone away age
        its stored rows out instead of sitting present forever.

        Four sources, applied in authority order:
          (a) dot1dBasePortIfIndex resolves a BRIDGE-MIB bridge port number
              to the ifIndex the rest of the app keys interfaces by (the
              same table the FDB walk resolves through _bridge_port_map).
              Absent entirely on some small switches, which is not the same
              fact as "this device has no ports": see `resolve` below for
              why the bridge port number is used as the ifIndex directly
              rather than dropping every membership the device reports.
          (b) Q-BRIDGE-MIB dot1qVlanStatic*/dot1qVlanCurrent* — the
              standards path. The current-table columns are consulted only
              where their static counterpart came back empty: a VTP/GVRP
              client legitimately carries no static configuration of its
              own.
          (c) CISCO-VTP-MIB, Cisco only (detected_vendor gate, same one
              _walk_cdp uses) — and a Cisco answer for a port SUPERSEDES
              whatever the standards path said about that same port.
              vlanTrunkPortVlansEnabled is the trunk's configured allow
              list; dot1q's own egress bitmap on classic IOS often reflects
              only VLANs with a currently active member, which is a
              narrower and more volatile fact than what is actually
              configured to cross the trunk.
          (d) mac_entries' own vlan column, for a port neither (b) nor (c)
              described at all: a VLAN whose traffic this device has
              learned on a port is evidence that VLAN crosses it, even
              though no VLAN table said so. Evidence, not configuration —
              reached only for a port with no authoritative answer, and
              never allowed to override one.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        # The budget goes INTO each walk (see _cisco_vlan_fdb's own
        # comment on why): checking only between walks would let the last
        # one of eight start after the budget was already spent.
        deadline = time.monotonic() + _VLAN_WALK_BUDGET_S
        answered = False
        complete = True

        def walk(oid: str, *, evidence: bool = True) -> dict:
            nonlocal answered, complete
            column, column_done = self._walk_column_status(
                device, config, oid, deadline=deadline)
            if column and evidence:
                answered = True
            # Every column, evidence=False included: half a bridge-port map is wrong too.
            complete = complete and column_done
            return column

        # (a) bridge port -> ifIndex. BRIDGE-MIB, not a VLAN table: it only
        # helps interpret a bridge port number the VLAN columns below might
        # report, and answering it is not itself evidence this device has
        # ANY VLAN-related MIB at all — a switch with nothing but plain
        # bridging support would otherwise flip `answered` true here and
        # get a genuine "walked, found nothing" dict below (aging every
        # stored row to present=0 and logging a 0-row walk every hour)
        # instead of the None this docstring promises for "nothing VLAN-
        # related answered". evidence=False keeps this call out of that
        # decision entirely.
        port_map = _int_keyed(walk(nodeoids.DOT1D_BASE_PORT_IFINDEX,
                                   evidence=False))

        def resolve(bridge_port: int):
            if port_map:
                return port_map.get(bridge_port)
            # dot1dBasePortIfIndex did not answer at all. Plenty of small
            # switches number their bridge ports 1:1 with ifIndex and never
            # populate this table, so treating the bridge port number as
            # the ifIndex directly recovers real data on exactly those
            # devices — a wrong guess on a device numbered differently only
            # misattributes which port a VLAN belongs to, a smaller loss
            # than dropping every membership this device reports.
            return bridge_port

        described_ports: set = set()
        port_mode: dict = {}
        port_native: dict = {}
        memberships: dict = {}   # (if_index, vlan) -> tagged
        vlan_names: dict = {}

        # (b) standards path
        static_names = walk(nodeoids.DOT1Q_VLAN_STATIC_NAME)
        egress = walk(nodeoids.DOT1Q_VLAN_STATIC_EGRESS)
        if not egress:
            egress = walk(nodeoids.DOT1Q_VLAN_CURRENT_EGRESS)
        untagged = walk(nodeoids.DOT1Q_VLAN_STATIC_UNTAGGED)
        if not untagged:
            untagged = walk(nodeoids.DOT1Q_VLAN_CURRENT_UNTAGGED)

        if static_names:
            for suffix, value in static_names.items():
                try:
                    vlan_names[int(suffix)] = str(value or "")
                except (TypeError, ValueError):
                    continue
        else:
            # No static VLAN table at all — the current-table bitmaps' own
            # suffixes are the only standards-path evidence a VLAN id
            # exists, and dot1qVlanCurrentTable has no name column to go
            # with them.
            for suffix in set(egress) | set(untagged):
                try:
                    vlan_names.setdefault(int(suffix), "")
                except (TypeError, ValueError):
                    continue

        def port_sets(column: dict) -> dict:
            out = {}
            for suffix, raw in column.items():
                try:
                    vlan = int(suffix)
                except (TypeError, ValueError):
                    continue
                ports = set()
                for bridge_port in _decode_port_list(raw):
                    if_index = resolve(bridge_port)
                    if if_index is not None:
                        ports.add(if_index)
                out[vlan] = ports
            return out

        egress_ports = port_sets(egress)
        untagged_ports = port_sets(untagged)
        # A port present in egress but not untagged is tagged; present in
        # both is untagged (dot1qPvid below is which VLAN that untagged
        # membership actually means for the port, i.e. its native VLAN).
        for vlan in set(egress_ports) | set(untagged_ports):
            eg = egress_ports.get(vlan, set())
            un = untagged_ports.get(vlan, set())
            for if_index in eg | un:
                described_ports.add(if_index)
                memberships[(if_index, vlan)] = if_index not in un

        for suffix, value in walk(nodeoids.DOT1Q_PVID).items():
            try:
                bridge_port = int(suffix)
                native = int(value)
            except (TypeError, ValueError):
                continue
            if_index = resolve(bridge_port)
            if if_index is None:
                continue
            port_native[if_index] = native
            described_ports.add(if_index)

        # (c) Cisco path — supersedes (b) per port
        if detected_vendor(device).lower() == "cisco":
            # vtpVlanEntry is indexed {managementDomainIndex, vtpVlanIndex},
            # not vtpVlanIndex alone -- a real agent answers a suffix like
            # "1.10", and int() on that raises. Same fix as _cisco_vlan_fdb's
            # suffix.split(".")[-1] below, applied to the name column that
            # copy of the logic doesn't touch.
            for suffix, value in walk(nodeoids.VTP_VLAN_NAME).items():
                vlan_id = suffix.split(".")[-1]
                if not vlan_id.isdigit():
                    continue
                vlan = int(vlan_id)
                # VLAN 1002-1005 are the legacy FDDI/token-ring defaults
                # every IOS switch names whether or not anything is
                # actually configured on them (see _cisco_vlan_fdb's
                # identical exclusion for the FDB walk). Leaving them out
                # of vlan_names keeps them out of existing_vlans below too,
                # so a default trunk doesn't grow four boilerplate VLANs on
                # top of whatever the operator actually configured.
                if 1002 <= vlan <= 1005:
                    continue
                vlan_names[vlan] = str(value or "")

            trunk_status = _int_keyed(walk(nodeoids.VTP_TRUNK_DYNAMIC_STATUS))
            trunk_native = _int_keyed(walk(nodeoids.VTP_TRUNK_NATIVE_VLAN))
            vm_vlan = _int_keyed(walk(nodeoids.CISCO_VM_VLAN))

            # vlanTrunkPortVlansEnabled* is the trunk's configured ALLOW
            # LIST, not the VLANs actually crossing it -- a trunk left at
            # IOS's default `switchport trunk allowed vlan all` answers all
            # four bitmaps fully set (every VLAN 0-4094 "allowed"), which is
            # not evidence any of those VLANs exist. The invariant this
            # walk must hold: a VLAN never appears on a link unless the
            # device itself says that VLAN exists -- vlan_names (vtpVlanName
            # above, dot1qVlanStaticName from the standards path) plus the
            # Q-BRIDGE egress/untagged bitmaps' own suffixes are that
            # evidence, so the allow-list is intersected against them below
            # rather than materialised as membership directly.
            existing_vlans = set(vlan_names) | set(egress_ports) | set(untagged_ports)

            cisco_vlans_by_port: dict = {}
            for oid, base in (
                (nodeoids.VTP_TRUNK_VLANS_ENABLED, 0),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_2K, 1024),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_3K, 2048),
                (nodeoids.VTP_TRUNK_VLANS_ENABLED_4K, 3072),
            ):
                for suffix, raw in walk(oid).items():
                    try:
                        if_index = int(suffix)
                    except (TypeError, ValueError):
                        continue
                    cisco_vlans_by_port.setdefault(if_index, set()).update(
                        _decode_vlan_bitmap(raw, base))

            cisco_ports = (set(trunk_status) | set(trunk_native)
                          | set(cisco_vlans_by_port) | set(vm_vlan))
            for if_index in cisco_ports:
                status = trunk_status.get(if_index)
                # The trunk allow-list is only meaningful for a port that is
                # actually trunking. On classic IOS, vlanTrunkPortDynamicStatus
                # carries a row for EVERY switchport -- access ports included,
                # reporting notTrunking(2) -- and such a port still answers
                # vlanTrunkPortVlansEnabled with its configured allow list
                # (default: all VLANs) and vlanTrunkPortNativeVlan (default:
                # 1). Applying those unconditionally, as this used to, threw
                # away a correctly-read access VLAN (dot1qPvid, via the
                # standards path) in favour of a fabricated ~4094-VLAN trunk
                # on every access port. So: only status == trunking(1) gets
                # the Cisco override below; anything else (notTrunking, or a
                # port this column simply never covers) keeps whatever the
                # standards path already recorded for it, and is merely
                # labelled here when IOS says outright that it is an access
                # port.
                if status != 1:
                    if status == 2:
                        port_mode[if_index] = "access"
                    # vmVlan: some Catalysts never answer dot1qPvid at all,
                    # so this is the only access-VLAN evidence they give.
                    if if_index in vm_vlan and if_index not in port_native:
                        port_native[if_index] = vm_vlan[if_index]
                        described_ports.add(if_index)
                    continue

                # Supersede: drop whatever the standards path recorded for
                # this port before writing the Cisco answer over it.
                for key in [k for k in memberships if k[0] == if_index]:
                    del memberships[key]
                described_ports.add(if_index)
                port_mode[if_index] = "trunk"
                native = trunk_native.get(if_index)
                if native is not None:
                    port_native[if_index] = native
                # Allow-list ∩ VLANs that exist -- see existing_vlans above.
                # A default `allowed vlan all` trunk's ~4094-bit allow-list
                # collapses down to the handful the device actually has.
                vlans = cisco_vlans_by_port.get(if_index, set()) & existing_vlans
                if vlans:
                    for vlan in vlans:
                        memberships[(if_index, vlan)] = not (
                            native is not None and vlan == native)
                elif native is not None and native in existing_vlans:
                    memberships[(if_index, native)] = False

        # An access port's dot1qPvid names its VLAN even where the Q-BRIDGE
        # bitmaps never cover it -- the trunk branch above already falls back
        # this way; the gap is Q-BRIDGE's, so this is not Cisco-only.
        existing_vlans = set(vlan_names) | set(egress_ports) | set(untagged_ports)
        ports_with_membership = {if_index for if_index, _ in memberships}
        for if_index, native in port_native.items():
            if if_index in ports_with_membership or native not in existing_vlans:
                continue
            memberships[(if_index, native)] = False

        if not answered:
            return None
        if not complete:
            # A truncated bitmap drops or mislabels real memberships; same verdict as the MAC/neighbour walks.
            return None

        # (d) mac_entries fallback — evidence, not configuration, only for
        # a port neither (b) nor (c) described at all.
        for row in self.db.mac_entries_for(device_id):
            if_index = row["if_index"]
            if if_index in described_ports:
                continue
            vlan_text = str(row["vlan"] or "").strip()
            if not vlan_text.isdigit():
                continue
            memberships.setdefault((if_index, int(vlan_text)), True)

        # Bound the write: the same "cap rather than fail" idiom
        # _cisco_vlan_fdb's _MAX_VLAN_CONTEXTS slice uses. Now that a Cisco
        # trunk's allow-list is intersected against VLANs the device says
        # exist (above) rather than materialised wholesale, a real device's
        # VLAN count is bounded by what it actually has configured -- a few
        # hundred at most -- so this should not bind in practice. If it
        # ever does, keep VLANs with a real port membership (actual
        # configuration/traffic) ahead of merely-named-but-unused ones, and
        # break remaining ties by id rather than truncating to the lowest
        # ids: a deployment's important VLANs are exactly as likely to be
        # numbered 1000+ as under 512, and silently dropping the
        # highest-numbered ones is the same bug this fix exists for.
        all_vlan_ids = set(vlan_names) | {vlan for _, vlan in memberships}
        vlans_with_membership = {vlan for _, vlan in memberships}
        kept_vlans = set(sorted(
            all_vlan_ids,
            key=lambda vlan: (0 if vlan in vlans_with_membership else 1, vlan),
        )[:_MAX_VLANS])

        vlans_out = [{"vlan": vlan, "name": vlan_names.get(vlan, "")}
                    for vlan in sorted(kept_vlans)]
        port_ifindexes = (set(port_mode) | set(port_native)
                         | {if_index for if_index, _ in memberships})
        ports_out = [
            {"if_index": if_index, "mode": port_mode.get(if_index, ""),
             "native_vlan": port_native.get(if_index)}
            for if_index in sorted(port_ifindexes)]
        memberships_out = [
            {"if_index": if_index, "vlan": vlan, "tagged": tagged}
            for (if_index, vlan), tagged in memberships.items()
            if vlan in kept_vlans]

        return {"vlans": vlans_out, "ports": ports_out,
                "memberships": memberships_out}

    def _run_vlan_table(self, device_id: int) -> None:
        """One scheduled per-port VLAN membership walk, mirroring
        _run_lldp_table exactly: a worker thread must never die quietly,
        and a device that answers no VLAN table at all leaves its stored
        rows alone rather than deleting them — see read_device_vlans'
        None contract."""
        try:
            result = self.read_device_vlans(device_id)
            if result is None:
                return
            self.db.replace_vlans(device_id, result["vlans"])
            self.db.replace_vlan_ports(device_id, result["ports"])
            stored = self.db.replace_port_vlans(device_id, result["memberships"])
            self._bump("vlan_walks")
            self.log.add(NODES, f"Learned {stored} VLAN membership row(s) on "
                                f"device #{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"VLAN walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._vlan_running.discard(device_id)

    # Bounds for the OID browser. Generous enough to be useful on a switch,
    # small enough that a dialog someone is sitting in front of cannot hang:
    # a full walk of a large device is tens of thousands of objects and
    # minutes of GETNEXTs, which is why this browses subtrees rather than
    # offering "walk everything".
    # Bounds on the on-demand credential probe in working_config().
    _PROBE_BUDGET_S = 8.0
    _PROBE_RETRY_S = 60.0

    _BROWSE_MAX_ROWS = 600
    _BROWSE_BUDGET_S = 20.0

    def walk_subtree(self, device_id: int, base_oid: str,
                     max_rows: int | None = None,
                     budget_s: float | None = None) -> dict | None:
        """Live on-demand GETNEXT walk of one subtree, for the OID browser.

        Same on-demand shape as read_dom()/read_mac_table(): run only while a
        human is looking at the dialog, never on the poll cycle.

        Deliberately not _walk_column(): that returns index-suffix -> value
        for one table column and caps at 512 rows, which is right for its
        callers and wrong here. A browser needs the whole OID, the SNMP type
        and the raw value of every object it passed, and it needs to say why
        it stopped — silently truncating at a cap would make a partial walk
        look like the device's complete answer.

        Returns None when the device is unknown or has SNMP disabled.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None
        base = (base_oid or "").strip().strip(".")
        # isascii() as well: str.isdigit() accepts superscript and
        # Arabic-Indic digits that int() -- and so the BER encoder -- does
        # not. See nodeoids.normalize_oid.
        if not base or not all(part.isascii() and part.isdigit()
                               for part in base.split(".")):
            raise ValueError("An OID must be numeric, like 1.3.6.1.2.1.1")

        max_rows = int(max_rows or self._BROWSE_MAX_ROWS)
        budget = float(budget_s or self._BROWSE_BUDGET_S)
        rows, stopped = self._walk_from(device, config, base, max_rows, budget)
        return {"base": base, "rows": rows, "stopped": stopped,
                "complete": stopped == "end of subtree"}

    def _bulk_settings(self, device, config: dict) -> tuple:
        """(use GETBULK, repetitions) for a walk of this device.

        The repetition count is remembered per device: an agent that
        answered "tooBig" once will answer it again, and re-learning the
        same limit at the start of every walk costs a wasted round trip
        each time.

        The GETNEXT FALLBACK is remembered the same way, as a learned count
        of 0. It was not: an agent that refuses GETBULK at any repetition
        count was recorded as "1 repetition" and so re-asked with GETBULK
        on the next column of the next poll, for ever, paying a wasted
        round trip per walk against exactly the devices least able to
        afford one.
        """
        configured = self._walk_limits()[1]
        raw_version = config.get("snmp_version")
        is_v1 = raw_version is not None and int(raw_version) == 0
        if is_v1 or configured <= 0:
            return False, 0
        learned = self._bulk_repetitions.get(device["id"])
        if learned == 0:
            return False, 0
        return True, min(configured, learned) if learned else configured

    def _remember_repetitions(self, device, repetitions: int, *,
                              use_bulk: bool = True) -> None:
        self._bulk_repetitions[device["id"]] = (
            max(1, int(repetitions)) if use_bulk else 0)

    def _walk_from(self, device, config, base: str, max_rows: int,
                   budget_s: float, cancelled=None,
                   on_row=None) -> tuple[list[dict], str]:
        """The subtree walk itself: rows collected, and why it stopped.

        Shared by walk_subtree (one subtree, in front of a waiting human)
        and the background whole-device walk, which differ only in their
        bounds and in having a cancel — not in what a walk is. `cancelled`
        is polled between requests; `on_row` sees each row as it arrives so
        a job can report progress without exposing its list.

        GETBULK on v2c and v3, over one shared socket, the same way
        _walk_column already walks a table column — a GETNEXT and a fresh
        socket per row put a fleet-wide first identification in the hours.
        """
        deadline = time.monotonic() + budget_s
        rows: list[dict] = []
        retained = 0
        stopped = "end of subtree"
        current = base
        use_bulk, repetitions = self._bulk_settings(device, config)
        session = self._session_for(device, config)
        try:
            while True:
                if cancelled is not None and cancelled():
                    stopped = f"cancelled after {len(rows)} row(s)"
                    break
                if len(rows) >= max_rows:
                    stopped = f"stopped at the {max_rows}-row limit"
                    break
                if retained >= self._WALK_MAX_BYTES:
                    stopped = (f"stopped at the {self._WALK_MAX_BYTES}-byte "
                               f"limit after {len(rows)} row(s)")
                    break
                if time.monotonic() > deadline:
                    stopped = f"stopped after {budget_s:.0f}s"
                    break
                try:
                    response = self._walk_request(
                        session, device, config, current,
                        PDU_GETBULK if use_bulk else PDU_GETNEXT, repetitions)
                except SnmpTimeout:
                    # Name what was actually tried. "The device stopped
                    # answering" alone sent an operator hunting the device
                    # when the answer was on this end — which credential we
                    # used, and against which address and port.
                    stopped = (
                        f"no reply from {device['ip']}:{DEFAULT_SNMP_PORT} "
                        f"using {_credential_label(config)}"
                        + (f" — stopped after {len(rows)} row(s)" if rows else ""))
                    break
                except SnmpError as exc:
                    stopped = f"SNMP error: {exc}"
                    break
                if use_bulk and response.error_status == 1:      # tooBig
                    if repetitions <= 1:
                        use_bulk = False
                        self._remember_repetitions(device, 0, use_bulk=False)
                    else:
                        repetitions = max(1, repetitions // 2)
                        self._remember_repetitions(device, repetitions)
                    continue
                if response.error_status:
                    stopped = _error_status_reason(response, base)
                    break
                if not response.varbinds:
                    stopped = "the device returned nothing"
                    break
                done = False
                for vb in response.varbinds:
                    oid = vb["oid"]
                    if not oid or not (oid == base or oid.startswith(base + ".")):
                        done = True          # walked out of the subtree
                        break
                    if vb["type"] in ("noSuchObject", "noSuchInstance",
                                      "endOfMibView"):
                        done = True
                        break
                    # An answer must lexicographically follow the request; a
                    # broken agent that echoes the request OID (or goes
                    # backwards) would otherwise fill the dialog with the
                    # same row until the cap or the clock stopped it,
                    # presented as the device's answer.
                    if _oid_key(oid) <= _oid_key(current):
                        stopped = ("the device answered with a non-increasing "
                                   f"OID ({oid}) — its SNMP agent is "
                                   f"misbehaving")
                        done = True
                        break
                    row = {"oid": oid, "type": vb["type"],
                           "value": vb["value"], "text": vb.get("text")}
                    rows.append(row)
                    retained += len(str(vb["value"]))
                    if on_row is not None:
                        on_row(row)
                    current = oid
                    if len(rows) >= max_rows:
                        stopped = f"stopped at the {max_rows}-row limit"
                        done = True
                        break
                    if retained >= self._WALK_MAX_BYTES:
                        # A row count alone does not bound what a walk
                        # holds: an agent answering 64 KB octet strings
                        # fills memory long before the row limit.
                        stopped = (f"stopped at the {self._WALK_MAX_BYTES}-byte "
                                   f"limit after {len(rows)} row(s)")
                        done = True
                        break
                if done:
                    break
        finally:
            session.close()
        return rows, stopped

    # The whole-device walk starts here rather than at .1: 1.3.6.1 is
    # internet(1), which is every MIB an agent can sensibly hold. Starting
    # above it would miss nothing real and starting below it invites an
    # agent to walk its own private branches forever.
    _FULL_WALK_BASE = "1.3.6.1"

    def start_oid_walk(self, device_id: int) -> dict:
        """Begin a whole-device walk in the background, or report the one
        already running for this device.

        Held in memory rather than in a table: a walk result is transient —
        it exists to be downloaded once and then thrown away — and a row
        surviving a restart would describe a job whose thread is gone.
        """
        device = self.db.device(device_id)
        if device is None:
            raise ValueError("No such device")
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and job.running:
                return job.status()
            settings = self.db.settings()
            job = _OidWalkJob(
                self, device_id,
                base=self._FULL_WALK_BASE,
                max_rows=int(settings.get("oid_walk_max_rows", 100_000)),
                budget_s=float(settings.get("oid_walk_budget_s", 600.0)))
            self._oid_walks[device_id] = job
        job.start()
        return job.status()

    def oid_walk_status(self, device_id: int, with_rows: bool = False) -> dict | None:
        job = self._oid_walks.get(device_id)
        return None if job is None else job.status(with_rows=with_rows)

    def cancel_oid_walk(self, device_id: int) -> bool:
        job = self._oid_walks.get(device_id)
        if job is None or not job.running:
            return False
        job.cancel()
        return True

    def forget_oid_walk(self, device_id: int) -> None:
        """Drop a finished walk's rows. Called once the file has been handed
        over, so a 100k-row walk does not sit in memory for the life of the
        process."""
        with self._lock:
            job = self._oid_walks.get(device_id)
            if job is not None and not job.running:
                self._oid_walks.pop(device_id, None)

    def browse_bases(self, device_id: int) -> list[dict]:
        """The subtrees the browser opens on: the two every SNMP agent
        answers, plus this device's own vendor arc where its sysObjectID
        names one. Enough to be immediately useful without walking a whole
        switch."""
        bases = [
            {"oid": nodeoids.SYSTEM_BASE, "label": "system"},
            {"oid": nodeoids.INTERFACES_BASE, "label": "interfaces"},
        ]
        device = self.db.device(device_id)
        if device is not None:
            root = nodeoids.enterprise_root(device["sys_object_id"] or "")
            if root:
                vendor = device["vendor"] or "vendor"
                bases.append({"oid": root, "label": f"{vendor} ({root})"})
        return bases

    def _snmp_get_next(self, device, config: dict, oid: str) -> Response:
        version = snmp_version_of(config)
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        session = _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)
        try:
            if version in (0, 1):
                identity = credential_for(config).identity
                request_id = session.next_request_id()
                packet = _assemble(build_request, version,
                                   identity or "public", PDU_GETNEXT,
                                   request_id, [oid])
                return session.request(packet, request_id)
            return self._v3_exchange(session, device, config, PDU_GETNEXT, [oid])
        finally:
            session.close()

    def _session_for(self, device, config: dict) -> _Session:
        """One `_Session` (one UDP socket) for a caller that makes several
        round trips of its own — `_walk_column`'s whole walk, rather than a
        fresh socket per row the way `_snmp_get_next`/`_snmp_get` do for
        their single-request callers."""
        timeout_s = float(config.get("snmp_timeout_s", 3.0))
        retries = int(config.get("snmp_retries", 2))
        return _Session(device["ip"], DEFAULT_SNMP_PORT, timeout_s, retries)

    def _walk_request(self, session: _Session, device, config: dict, oid: str,
                      pdu_tag: int, max_repetitions: int = 0) -> Response:
        """One GETNEXT/GETBULK round trip over an already-open session —
        the same v1/v2c/v3 request assembly `_snmp_get_next` uses, minus
        opening and closing a socket per call. `non_repeaters` is always 0:
        every walk here is over a single column, so there is nothing to
        exempt from repetition. Ignored by `build_request`/`build_v3_request`
        for a non-GETBULK `pdu_tag`, so a v1 caller can pass it unused."""
        version = snmp_version_of(config)
        if version in (0, 1):
            identity = credential_for(config).identity
            request_id = session.next_request_id()
            packet = _assemble(build_request, version, identity or "public",
                               pdu_tag, request_id, [oid],
                               max_repetitions=max_repetitions)
            return session.request(packet, request_id)
        return self._v3_exchange(session, device, config, pdu_tag, [oid],
                                 max_repetitions=max_repetitions)

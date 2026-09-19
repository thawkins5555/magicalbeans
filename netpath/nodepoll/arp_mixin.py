from __future__ import annotations

import ipaddress
import traceback
from .. import nodeoids
from ..eventlog import ERROR, NODES
from ..snmppoll import SnmpError
from ._decode import _octets_from_value


class ArpMixin:

    # ------------------------------------------------------------ ARP tables

    def read_device_arp_table(self, device_id: int) -> list[dict] | None:
        """Every IP-to-MAC mapping this device's ARP cache holds, and on
        which interface. The ARP counterpart of read_device_mac_table,
        with the same None-vs-empty-list contract: None means "nothing
        trustworthy came back" and storage must be left alone, an empty
        list is a genuine "the cache is empty right now" and ages every
        stored row. Each entry is {if_index, ip, mac, entry_type}, the
        MAC in the colon-hex form _fdb_entries produces (nodesdb
        normalises it on the way in).

        Two tables, walked as a FALLBACK and never merged: ipNetToMediaTable
        first, because it is what nearly every agent in the field actually
        populates, then ipNetToPhysicalTable — its IPv6-capable successor,
        and on newer gear sometimes the only one — when the first produced
        no rows at all. Not merged, because a modern agent answers both
        with the same IPv4 mappings and a merge would double-count every
        one of them; so the legacy table wins outright whenever it has
        anything to say, and a device that keeps its IPv6 neighbours only
        in the successor table loses them while it still answers the
        legacy one. That is the documented cost of never double-counting.

        The gate between the two is "produced no rows", NOT "the walk
        failed": an agent with no ipNetToMedia subtree at all answers the
        first GETNEXT with whatever object follows it, which _walk_column
        reads as a clean, complete, empty walk — exactly the case the
        fallback exists for. A walk that stopped for any OTHER reason
        (timeout, an SNMP error, the snmp_walk_max_rows cap, a
        misbehaving agent) returns None from either table rather than
        falling through, because a partial table is worse than none here:
        handing it to replace_arp_entries would mark the un-walked tail
        present=0 and quietly age out thousands of live entries every
        cycle. ARP caches are the one table this poller reads that
        actually meets the row cap on a core router, so this walker is
        deliberately MORE conservative than the MAC walker, which can
        derive "answered" from the bridge-port map and has no equivalent
        of this failure.
        """
        entries, _status, _detail = self._read_arp_table_detail(device_id)
        return entries

    # What _read_arp_table_detail's status word can be: stored/ageable
    # rows came back, the device answers neither table (a fact about the
    # box, logged once), a walk was cut short (a fact about this attempt,
    # storage left alone), or the device is not pollable at all.
    _ARP_OK, _ARP_UNANSWERED, _ARP_INCOMPLETE, _ARP_SKIPPED = (
        "ok", "unanswered", "incomplete", "skipped")

    def _read_arp_table_detail(self, device_id: int) -> tuple:
        """(entries or None, status, detail) — read_device_arp_table's
        answer plus WHY it is None when it is, so _run_arp_table can tell
        "this device does not answer" (say so once) from "this walk was cut
        short" (say why) without re-walking anything."""
        device = self.db.device(device_id)
        if device is None:
            return None, self._ARP_SKIPPED, "no such device"
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None, self._ARP_SKIPPED, "SNMP is disabled"

        entries, answered, legacy_reason = self._walk_arp_table(
            device, config, nodeoids.IP_NET_TO_MEDIA_PHYS_ADDRESS,
            nodeoids.IP_NET_TO_MEDIA_TYPE, self._arp_index_media)
        if entries is None:
            return None, self._ARP_INCOMPLETE, f"ipNetToMediaTable: {legacy_reason}"
        if answered:
            return entries, self._ARP_OK, ""
        entries, answered, modern_reason = self._walk_arp_table(
            device, config, nodeoids.IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
            nodeoids.IP_NET_TO_PHYSICAL_TYPE, self._arp_index_physical)
        if entries is None:
            return None, self._ARP_INCOMPLETE, f"ipNetToPhysicalTable: {modern_reason}"
        if answered:
            return entries, self._ARP_OK, ""
        # Neither produced a row. Each walk's own stop reason rides along
        # (empty when the subtree simply is not there), so a device that
        # timed out with nothing reads differently in the log from one that
        # cleanly has no such table — even though storage is left alone
        # either way.
        why = "; ".join(r for r in (legacy_reason, modern_reason) if r)
        return None, self._ARP_UNANSWERED, (
            "answers neither ipNetToMediaTable nor ipNetToPhysicalTable"
            + (f" ({why})" if why else ""))

    def _walk_arp_table(self, device, config: dict, phys_oid: str,
                        type_oid: str, parse_index) -> tuple:
        """One ARP table: (entries or None, whether the phys-address column
        produced any row at all, why the walk stopped when it did not
        finish).

        `entries` is None whenever the phys-address walk did not reach the
        end of its subtree — see read_device_arp_table for why a partial
        table must never be stored. "Produced any row" is judged on the
        raw walk, before invalid(2) rows and undecodable MACs are dropped,
        so a table whose every row is being deleted still counts as
        answered (an empty cache) rather than sending the caller to the
        fallback table for the same device.

        The type column is best effort: it is the same row count as the
        phys column, so a walk that finished the first will nearly always
        finish the second, and a row whose type never arrived is kept with
        entry_type '' rather than the whole table being thrown away over
        the one column that only ever removes rows.
        """
        try:
            phys, complete, reason = self._walk_column_detail(device, config, phys_oid)
        except SnmpError as exc:
            return None, False, f"SNMP error: {exc}"
        # Complete first, then empty: a timeout or an error on the very
        # first GETBULK is an empty `phys` too, and read as "this table
        # produced no rows" it sent the caller on to the successor table —
        # so a modern agent answering both would alternate sources across
        # cycles whenever the legacy walk transiently timed out, flapping
        # `present` on every IPv6-only row, and a device that merely timed
        # out twice was logged as answering neither table. Only a walk that
        # genuinely reached the end of its subtree and found nothing there
        # is the fallback's case; every other way of stopping is None, as
        # read_device_arp_table promises.
        if not complete:
            return None, bool(phys), reason
        if not phys:
            return [], False, reason
        try:
            types = self._walk_column(device, config, type_oid)
        except SnmpError:
            types = {}

        entries = []
        for suffix, raw in phys.items():
            parsed = parse_index(suffix)
            if parsed is None:
                continue
            if_index, ip = parsed
            octets = _octets_from_value(raw)
            if len(octets) != 6:
                # An incomplete entry, a DLCI, a tunnel endpoint: PhysAddress
                # is whatever the medium uses, and only six octets is a MAC
                # this app can join on. Not stored as a guess.
                continue
            type_n = types.get(suffix)
            try:
                type_n = int(type_n) if type_n is not None else None
            except (TypeError, ValueError):
                type_n = None
            if type_n == 2:
                # invalid(2): the MIB's own "this row is going away" marker,
                # and an agent may leave such rows visible for a while.
                continue
            entries.append({
                "if_index": if_index,
                "ip": ip,
                "mac": ":".join(f"{b:02x}" for b in octets),
                "entry_type": nodeoids.IP_NET_TO_MEDIA_TYPE_ENUM.get(type_n, "")
                              if type_n is not None else "",
            })
        return entries, True, ""

    @staticmethod
    def _arp_index_media(suffix: str) -> tuple[int, str] | None:
        """(ifIndex, dotted IPv4) out of an ipNetToMediaTable row suffix,
        which is ifIndex.a.b.c.d — both facts are in the index, which is
        why the net-address column is never walked."""
        parts = suffix.split(".")
        if len(parts) != 5:
            return None
        try:
            if_index = int(parts[0])
            address = ipaddress.ip_address(bytes(int(p) for p in parts[1:]))
        except ValueError:
            return None
        return if_index, str(address)

    @staticmethod
    def _arp_index_physical(suffix: str) -> tuple[int, str] | None:
        """(ifIndex, address text) out of an ipNetToPhysicalTable row
        suffix: ifIndex.addrType.addrLen.<addrLen arcs>, InetAddressType
        1 = ipv4 (4 arcs), 2 = ipv6 (16), and the zoned forms 3 = ipv4z
        (4 + a 4-arc zone) and 4 = ipv6z (16 + 4), whose zone is dropped
        because the interface the row is on already says which link it
        is. Any other type (DNS names are legal here) is skipped. An IPv6
        address is stored in its compressed lowercase form, the one form
        every later search or join can spell the same way."""
        parts = suffix.split(".")
        if len(parts) < 3:
            return None
        try:
            if_index, addr_type, addr_len = (int(parts[0]), int(parts[1]),
                                             int(parts[2]))
            arcs = [int(p) for p in parts[3:]]
        except ValueError:
            return None
        if addr_len != len(arcs):
            return None
        width = {1: 4, 2: 16, 3: 4, 4: 16}.get(addr_type)
        if width is None or addr_len < width:
            return None
        if addr_type in (1, 2) and addr_len != width:
            return None
        try:
            address = ipaddress.ip_address(bytes(arcs[:width]))
        except ValueError:
            return None
        return if_index, str(address)

    def _run_arp_table(self, device_id: int) -> None:
        """One scheduled ARP-cache walk, mirroring _run_mac_table: a worker
        thread must never die quietly, and a device whose walk stored
        nothing leaves its stored rows alone — a router that failed to
        answer once has not forgotten every host it talks to.

        What differs is that the two ways of storing nothing are told
        apart and said out loud, ONCE per transition rather than per
        interval: "answers neither table" is a fact about the box an
        operator who opted a whole profile in needs to see exactly once
        per device, and "cut short" names the reason (the row cap, most
        likely) so the fix — raise snmp_walk_max_rows, or take the device
        off the schedule — is in the same line. Recovery is logged too, so
        the log reads as a state change and not a stream."""
        try:
            entries, status, detail = self._read_arp_table_detail(device_id)
            if entries is None:
                if status == self._ARP_SKIPPED:
                    return
                if device_id not in self._arp_unanswered:
                    self._arp_unanswered.add(device_id)
                    if status == self._ARP_UNANSWERED:
                        self.log.add(NODES, f"Device #{device_id} {detail}; "
                                            f"its ARP cache is not being stored. "
                                            f"Set its ARP table interval to 0 to "
                                            f"stop asking.")
                    else:
                        self.log.add(NODES, f"ARP walk of device #{device_id} was "
                                            f"cut short and its stored table left "
                                            f"alone ({detail})")
                return
            stored = self.db.replace_arp_entries(device_id, entries)
            self._bump("arp_walks")
            if device_id in self._arp_unanswered:
                self._arp_unanswered.discard(device_id)
                self.log.add(NODES, f"Device #{device_id} answers its ARP table "
                                    f"again")
            self.log.add(NODES, f"Learned {stored} ARP entr"
                                f"{'y' if stored == 1 else 'ies'} on device "
                                f"#{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"ARP table walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._arp_running.discard(device_id)

from __future__ import annotations

import ipaddress
import traceback
from .. import nodeoids
from ..eventlog import ERROR, NODES
from ..nodesdb import detected_vendor
from ..snmppoll import SnmpError
from ._decode import _canonical_if_name, format_cdp_address


class LldpCdpMixin:

    # ------------------------------------------------- LLDP/CDP neighbours

    # LLDP-MIB columns walked for one device's remote-systems table. Each
    # entry is walked as its own column (the same one-GETBULK-walk-per-
    # column shape _fdb_entries' callers already use for the FDB), then
    # joined back together on the shared lldpRemTimeMark.lldpRemLocalPortNum.
    # lldpRemIndex suffix in _walk_lldp. A short column no longer fills a blank-field row; see read_device_neighbors for why the pass is discarded instead.
    _LLDP_COLUMNS = {
        "chassis_id_subtype": nodeoids.LLDP_REM_CHASSIS_ID_SUBTYPE,
        "chassis_id":         nodeoids.LLDP_REM_CHASSIS_ID,
        "port_id_subtype":    nodeoids.LLDP_REM_PORT_ID_SUBTYPE,
        "port_id":            nodeoids.LLDP_REM_PORT_ID,
        "port_descr":         nodeoids.LLDP_REM_PORT_DESC,
        "sys_name":           nodeoids.LLDP_REM_SYS_NAME,
        "sys_descr":          nodeoids.LLDP_REM_SYS_DESC,
    }
    _CDP_COLUMNS = {
        "device_id":   nodeoids.CDP_CACHE_DEVICE_ID,
        "device_port": nodeoids.CDP_CACHE_DEVICE_PORT,
        "platform":    nodeoids.CDP_CACHE_PLATFORM,
        "address":     nodeoids.CDP_CACHE_ADDRESS,
    }

    def read_device_neighbors(self, device_id: int) -> list[dict] | None:
        """Every LLDP neighbour this device reports, plus CDP as a
        fallback/supplement on Cisco gear (classic IOS in particular often
        speaks CDP only). The whole-device counterpart of
        read_device_mac_table, with the same None-vs-empty-list contract:
        None means neither protocol answered anything at all — storage
        must be left alone — while an empty list is a genuine "this device
        has no neighbours right now" and ages every stored row.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        deadline = self._table_walk_deadline(config, "lldp_interval_s")
        entries, lldp_answered, complete = self._walk_lldp(device, config,
                                                           deadline)
        answered = lldp_answered
        if detected_vendor(device).lower() == "cisco":
            cdp_entries, cdp_answered, cdp_complete = self._walk_cdp(
                device, config, deadline)
            entries.extend(cdp_entries)
            answered = answered or cdp_answered
            complete = complete and cdp_complete
        if not answered:
            return None
        if not complete:
            # A short column would still produce rows with that field blank; same verdict as the MAC/ARP walks — leave storage alone.
            return None
        return entries

    def _walk_lldp(self, device, config: dict,
                   deadline: float | None = None) -> tuple:
        """(neighbour rows, whether the device answered anything, whether every column walk reached the end of its subtree). See nodeoids' LLDP block for why lldpRemLocalPortNum is used directly as the local ifIndex."""
        values: dict[str, dict] = {}
        answered = False
        complete = True
        for key, oid in self._LLDP_COLUMNS.items():
            try:
                column, column_done = self._walk_column_status(
                    device, config, oid, deadline=deadline)
            except SnmpError:
                column, column_done = {}, False
            if column:
                answered = True
            complete = complete and column_done
            values[key] = column
        if not answered:
            return [], False, complete
        # lldpRemManAddrTable is walked but kept OUT of `values`/`complete`:
        # its index carries the address itself after the shared 3-arc
        # prefix (timeMark.localPort.remIndex.addrSubtype.addrLen.addr...),
        # so it cannot join the per-row suffix set above, and a device that
        # simply has no management address configured must not mark the
        # whole pass incomplete or blank every row.
        man_addrs = self._walk_lldp_man_addrs(device, config, deadline)
        port_map = self._walk_lldp_local_ports(device, config, deadline)
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 3:
                continue                          # not a real 3-arc index
            try:
                local_port = int(parts[-2])
            except ValueError:
                continue
            chassis_subtype = values["chassis_id_subtype"].get(suffix)
            entries.append({
                "if_index": port_map.get(local_port, local_port),
                "protocol": "lldp",
                "rem_index": suffix,
                "chassis_id": str(values["chassis_id"].get(suffix) or ""),
                "chassis_id_subtype": (int(chassis_subtype)
                                       if isinstance(chassis_subtype, (int, float))
                                       else None),
                "port_id": str(values["port_id"].get(suffix) or ""),
                "port_id_subtype": (int(values["port_id_subtype"].get(suffix))
                                    if isinstance(values["port_id_subtype"].get(suffix),
                                                 (int, float)) else None),
                "port_descr": str(values["port_descr"].get(suffix) or ""),
                "sys_name": str(values["sys_name"].get(suffix) or ""),
                "sys_descr": str(values["sys_descr"].get(suffix) or ""),
                "remote_address": man_addrs.get(suffix, ""),
            })
        return entries, True, complete

    def _walk_lldp_man_addrs(self, device, config: dict,
                             deadline: float | None = None) -> dict:
        """lldpRemManAddrTable, keyed back down to the plain
        timeMark.localPort.remIndex suffix _walk_lldp's rows join on.

        The table's own index is longer than that: RFC 2579's InetAddress
        convention puts the address subtype, its length and the address
        itself into the index rather than a column value —
        timeMark.localPort.remIndex.addrSubtype.addrLen.addr[.addr...].
        Only IPv4 (subtype 1, 4 octets) and IPv6 (subtype 2, 16 octets) are
        parsed; anything else (subtype 0/none-configured or an OID/DNS
        address) is skipped rather than guessed at. A remote system with
        several management addresses can report more than one row per
        neighbour — the first IPv4 wins, else the first IPv6 found."""
        try:
            column, _ = self._walk_column_status(
                device, config, nodeoids.LLDP_REM_MAN_ADDR_IF_SUBTYPE,
                deadline=deadline)
        except SnmpError:
            return {}
        by_key: dict[str, tuple[int, str]] = {}   # key -> (subtype, address)
        for suffix in column:
            parts = suffix.split(".")
            if len(parts) < 6:
                continue
            key = ".".join(parts[:3])
            try:
                addr_subtype = int(parts[3])
                addr_len = int(parts[4])
                octets = [int(p) for p in parts[5:5 + addr_len]]
            except ValueError:
                continue
            if len(octets) != addr_len:
                continue
            if addr_subtype == 1 and addr_len == 4 and all(0 <= o <= 255 for o in octets):
                address = ".".join(str(o) for o in octets)
            elif addr_subtype == 2 and addr_len == 16:
                try:
                    address = str(ipaddress.IPv6Address(bytes(octets)))
                except ValueError:
                    continue
            else:
                continue
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = (addr_subtype, address)
            elif existing[0] != 1 and addr_subtype == 1:
                by_key[key] = (addr_subtype, address)   # an IPv4 always wins
        return {key: address for key, (_, address) in by_key.items()}

    def _walk_lldp_local_ports(self, device, config: dict,
                               deadline: float | None = None) -> dict:
        """lldpLocPortNum -> ifIndex from lldpLocPortTable: an ifName/ifDescr
        match on the port id or description, else a numeric local port id
        that is a known ifIndex when the port number itself is not one.
        Unplaced ports are left out; with no stored interfaces nothing is."""
        columns = {}
        for key, oid in (("subtype", nodeoids.LLDP_LOC_PORT_ID_SUBTYPE),
                         ("port_id", nodeoids.LLDP_LOC_PORT_ID),
                         ("desc", nodeoids.LLDP_LOC_PORT_DESC)):
            try:
                columns[key], _ = self._walk_column_status(
                    device, config, oid, deadline=deadline)
            except SnmpError:
                columns[key] = {}
        if not columns["port_id"] and not columns["desc"]:
            return {}
        by_name: dict[str, int] = {}
        known: set[int] = set()
        for row in self.db.interface_port_labels(device["id"]):
            known.add(row["if_index"])
            for text in (row["name"], row["descr"]):
                canon = _canonical_if_name(text or "")
                if canon and canon not in by_name:
                    by_name[canon] = row["if_index"]
        if not known:
            return {}
        port_map: dict[int, int] = {}
        for suffix in set(columns["port_id"]) | set(columns["desc"]):
            try:
                local_port = int(suffix.split(".")[-1])
            except ValueError:
                continue
            port_id = str(columns["port_id"].get(suffix) or "").strip()
            desc = str(columns["desc"].get(suffix) or "").strip()
            subtype = columns["subtype"].get(suffix)
            target = None
            for text in (port_id, desc):
                if target is None and text:
                    target = by_name.get(_canonical_if_name(text))
            if (target is None and subtype == 7 and port_id.isdigit()
                    and local_port not in known and int(port_id) in known):
                target = int(port_id)
            if target is not None and target != local_port:
                port_map[local_port] = target
        return port_map

    def _walk_cdp(self, device, config: dict,
                  deadline: float | None = None) -> tuple:
        """(neighbour rows, whether the device answered anything, whether every column walk finished) from CISCO-CDP-MIB's cdpCacheTable."""
        values: dict[str, dict] = {}
        answered = False
        complete = True
        for key, oid in self._CDP_COLUMNS.items():
            try:
                column, column_done = self._walk_column_status(
                    device, config, oid, deadline=deadline)
            except SnmpError:
                column, column_done = {}, False
            if column:
                answered = True
            complete = complete and column_done
            values[key] = column
        if not answered:
            return [], False, complete
        suffixes: set = set()
        for column in values.values():
            suffixes.update(column)
        entries = []
        for suffix in suffixes:
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            try:
                if_index = int(parts[0])
            except ValueError:
                continue
            device_id_text = str(values["device_id"].get(suffix) or "")
            entries.append({
                "if_index": if_index,
                "protocol": "cdp",
                "rem_index": suffix,
                "chassis_id": device_id_text,
                "sys_name": device_id_text,
                "port_id": str(values["device_port"].get(suffix) or ""),
                "platform": str(values["platform"].get(suffix) or ""),
                "remote_address": format_cdp_address(values["address"].get(suffix)),
            })
        return entries, True, complete

    def _run_lldp_table(self, device_id: int) -> None:
        """One scheduled LLDP/CDP walk, mirroring _run_mac_table exactly:
        a worker thread must never die quietly, and a device that answers
        neither protocol leaves its stored neighbours alone rather than
        deleting them — see read_device_neighbors' None contract."""
        try:
            entries = self.read_device_neighbors(device_id)
            if entries is None:
                return
            stored = self.db.replace_neighbors(device_id, entries)
            self._bump("lldp_walks")
            self.log.add(NODES, f"Learned {stored} LLDP/CDP neighbour(s) on "
                                f"device #{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"LLDP/CDP walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._lldp_running.discard(device_id)

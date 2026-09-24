from __future__ import annotations

import time
import traceback
from .. import nodeoids
from ..eventlog import ERROR, NODES
from ..nodesdb import detected_vendor, is_cisco
from ._decode import _flatten_vendor_idx, _vendor_numeric, _vendor_state_value
from ._session import snmp_version_of


class VendorSensorPsuMixin:

    # ------------------------------------------------ vendor sensor/PSU tables
    #
    # nodeoids.SENSOR_TABLES/PSU_TABLES: temperature and power-supply
    # objects for every catalog vendor _poll_environment's ENTITY-SENSOR/
    # CISCO-ENTITY-SENSOR walk does not reach (see that module's own
    # comment for the resolver run this shipped against). Same probe-once-
    # remember cadence as _poll_environment (_SENSOR_REFRESH_S /
    # _SENSOR_REPROBE_S), its own latch column (vendor_sensor_capable) so a
    # device answering neither table stops being asked every poll, and its
    # own threshold cadence (_SENSOR_THRESHOLD_REFRESH_S) for the vendors
    # that publish per-sensor limits.

    def _forget_vendor_psu_static(self, device_id: int) -> None:
        """Drops this device's _vendor_psu_static/_vendor_psu_seen entries
        (tuple-keyed, so a plain .pop() cannot)."""
        for cache_key in [k for k in list(self._vendor_psu_static)
                          if k[0] == device_id]:
            self._vendor_psu_static.pop(cache_key, None)
        for cache_key in [k for k in list(self._vendor_psu_seen)
                          if k[0] == device_id]:
            self._vendor_psu_seen.pop(cache_key, None)

    def _poll_vendor_sensors(self, device_id: int, device, config: dict,
                             now: float) -> None:
        """Per-sensor temp_sensor_c.<idx>/temp_sensor_state.<idx>/
        psu_state.<idx>/fan_state.<idx> from nodeoids.SENSOR_TABLES/
        PSU_TABLES/FAN_TABLES, keyed on the device's own enterprise arc.
        fan_state reads FAN_TABLES on the same cadence as psu_state
        (due_psu), trying the FRU control table first and only falling back
        to the classic ENVMON one when the first came back empty.

        The temperature table is only tried for a device NOT already
        confirmed to answer ENTITY-SENSOR-MIB (device['sensor_capable']):
        Cisco's legacy CISCO-ENVMON-MIB table and CISCO-ENTITY-SENSOR-MIB
        index their sensors completely differently (a status-table row
        number vs. entPhysicalIndex), so a device answering both would have
        two unrelated sensors sharing one temp_sensor_c.<1> key, each poll
        overwriting the other's reading. PSU_TABLES has no such overlap —
        ENTITY-SENSOR-MIB carries no PSU state at all — so it always runs.

        Temperature keeps the _SENSOR_REFRESH_S/_SENSOR_REPROBE_S cadence;
        PSU state is read on every poll (latched-incapable devices aside).
        """
        if not config.get("snmp_enabled", True):
            return
        keys = device.keys() if hasattr(device, "keys") else device
        raw_oid = device["sys_object_id"] if "sys_object_id" in keys else ""
        arc = nodeoids.enterprise_arc(raw_oid or "")
        # Stack power support (_stack_power_capable) is independent of vendor_sensor_capable below.
        if arc == 9:
            self._poll_stack_power(device_id, device, config, now)

        capable = device["vendor_sensor_capable"]
        window = self._SENSOR_REPROBE_S if capable == 0 else self._SENSOR_REFRESH_S
        due_sensors = now - self._vendor_sensor_read.get(device_id, 0.0) >= window
        due_psu = capable != 0 or due_sensors
        if not due_sensors and not due_psu:
            return
        if due_sensors:
            self._vendor_sensor_read[device_id] = now

        sensor_table = None
        if due_sensors:
            sensor_table = nodeoids.SENSOR_TABLES.get(arc)
            read_device = getattr(self.db, "device", None)
            latest = read_device(device_id) if read_device else None
            if (latest if latest is not None else device)["sensor_capable"]:
                sensor_table = None
        psu_tables = nodeoids.PSU_TABLES.get(arc) if due_psu else None
        if psu_tables is not None and not isinstance(psu_tables, tuple):
            psu_tables = (psu_tables,)
        # Same cadence as PSU_TABLES (due_psu): fan_state is read wherever
        # psu_state is, not on its own schedule.
        fan_tables = nodeoids.FAN_TABLES.get(arc) if due_psu else None
        if sensor_table is None and not psu_tables and not fan_tables:
            if capable is None and due_sensors:
                self.db.set_vendor_sensor_capable(device_id, False)
            return

        metrics_rows = self.db.metrics(device_id)
        existing = {row["key"] for row in metrics_rows}
        # key -> stored label, for _mark_vendor_rows_absent's ABSENT row.
        existing_labels = {}
        for row in metrics_rows:
            row_keys = row.keys() if hasattr(row, "keys") else row
            existing_labels[row["key"]] = row["label"] if "label" in row_keys else row["key"]
        samples = []
        answered = False

        if sensor_table is not None:
            rows = self._vendor_sensor_rows(device, config, sensor_table)
            if rows:
                answered = True
            for idx, row in rows.items():
                if row["value"] is not None:
                    samples.append((f"temp_sensor_c.{idx}",
                                    f"{row['label']} temperature", "°C",
                                    "gauge", now, row["value"]))
                if row["state"] is not None:
                    samples.append((f"temp_sensor_state.{idx}",
                                    f"{row['label']} state", "state",
                                    "gauge", now, float(row["state"])))
            if now - self._vendor_sensor_threshold_read.get(device_id, 0.0) \
                    >= self._SENSOR_THRESHOLD_REFRESH_S:
                self._vendor_sensor_threshold_read[device_id] = now
                self._poll_vendor_sensor_thresholds(
                    device_id, device, config, sensor_table, rows, now)

        for table in psu_tables or ():
            rows, complete = self._vendor_psu_rows(device, config, table, now)
            if rows:
                answered = True
            for idx, row in rows.items():
                key = f"psu_state.{idx}"
                if row["state"] is None:
                    # Not present: a bay never seen stays silent, one seen
                    # before writes _PSU_STATE_ABSENT so psu_failed opens.
                    if key in existing:
                        samples.append((key, row["label"], "state", "gauge",
                                        now, self._PSU_STATE_ABSENT))
                    continue
                samples.append((key, row["label"], "state", "gauge", now,
                                float(row["state"])))
            self._mark_vendor_rows_absent(device_id, table.state, "psu_state",
                                          rows, complete, existing,
                                          existing_labels, samples, now)

        if fan_tables:
            primary, fallback = fan_tables
            fan_rows, fan_complete = self._vendor_psu_rows(device, config, primary, now)
            # Runs before any fallback reassigns fan_rows, so a device that
            # falls back this poll never reads as primary's tray vanishing.
            self._mark_vendor_rows_absent(device_id, primary.state, "fan_state",
                                          fan_rows, fan_complete, existing,
                                          existing_labels, samples, now)
            if not fan_rows:
                fan_rows, fan_complete = self._vendor_psu_rows(device, config, fallback, now)
                self._mark_vendor_rows_absent(device_id, fallback.state, "fan_state",
                                              fan_rows, fan_complete, existing,
                                              existing_labels, samples, now)
            if fan_rows:
                answered = True
            for idx, row in fan_rows.items():
                key = f"fan_state.{idx}"
                if row["state"] is None:
                    # Same "seen before, now silent" rule psu_state uses:
                    # only a fan tray this device has answered for before
                    # writes _PSU_STATE_ABSENT, so a chassis that never had
                    # one stays silent rather than opening fan_failed.
                    if key in existing:
                        samples.append((key, row["label"], "state", "gauge",
                                        now, self._PSU_STATE_ABSENT))
                    continue
                samples.append((key, row["label"], "state", "gauge", now,
                                float(row["state"])))

        if not capable and answered:
            self.db.set_vendor_sensor_capable(device_id, True)
        elif capable is None and not answered and due_sensors:
            self.db.set_vendor_sensor_capable(device_id, False)
        if samples:
            self.db.record_metric_samples(device_id, samples)

    def _vendor_sensor_rows(self, device, config: dict, table) -> dict:
        """idx -> {"label", "value" (already scaled, or None), "state"
        (0..3 or None), "scale"} for one nodeoids.SensorTable -- the walk
        _poll_vendor_sensors and _poll_vendor_sensor_thresholds share, so a
        published limit is only ever kept for an idx this poll actually
        read a sensor for.
        """
        rows: dict[str, dict] = {}
        values = {_flatten_vendor_idx(k): v for k, v in
                  self._walk_column(device, config, table.value).items()}
        label_override = None
        if not values and table.value_fallback:
            values = {_flatten_vendor_idx(k): v for k, v in
                      self._walk_column(device, config, table.value_fallback).items()}
            label_override = table.value_fallback_label
        names = ({_flatten_vendor_idx(k): v for k, v in
                  self._walk_column(device, config, table.name).items()}
                 if table.name else {})
        digits = ({_flatten_vendor_idx(k): v for k, v in
                   self._walk_column(device, config, table.decimal_digits).items()}
                  if table.decimal_digits else {})
        for idx, raw in values.items():
            name = names.get(idx)
            if table.name_filter and (name is None or
                    table.name_filter.lower() not in str(name).lower()):
                continue
            label = name or label_override \
                or (table.label.format(idx=idx) if table.label else f"Sensor {idx}")
            num = _vendor_numeric(raw, table.numeric_prefix)
            if num is None or num in table.skip_raw:
                continue
            scale = table.scale
            if idx in digits:
                try:
                    scale = 1.0 / (10 ** int(digits[idx]))
                except (TypeError, ValueError, ZeroDivisionError):
                    pass
            rows[idx] = {"label": str(label), "value": num * scale,
                        "state": None, "scale": scale}
        for oid, idx, label in table.extra_scalars:
            extra = self._walk_column(device, config, oid)
            raw = extra.get("0")
            if raw is None:
                continue
            num = _vendor_numeric(raw, table.numeric_prefix)
            if num is None or num in table.skip_raw:
                continue
            rows[idx] = {"label": label, "value": num * table.scale,
                        "state": None, "scale": table.scale}
        if table.state:
            states = {_flatten_vendor_idx(k): v for k, v in
                      self._walk_column(device, config, table.state).items()}
            for idx, raw in states.items():
                state = _vendor_state_value(raw, table.state_map, table.state_default)
                if state is None:
                    continue
                row = rows.get(idx)
                if row is None:
                    label = names.get(idx) or (
                        table.label.format(idx=idx) if table.label else f"Sensor {idx}")
                    row = rows[idx] = {"label": str(label), "value": None,
                                       "state": None, "scale": table.scale}
                row["state"] = state
        return rows

    def _vendor_psu_rows(self, device, config: dict, table, now: float) -> tuple:
        """({idx -> {"label", "state"}}, whether state/class/skip/name all
        walked to completion) for one nodeoids.PsuTable; an incomplete walk
        must not be read as evidence a row is gone."""
        device_id = device["id"]
        cache_key = (device_id, table.state)
        cached = self._vendor_psu_static.get(cache_key)
        if cached is not None and now - cached["ts"] < self._SENSOR_REFRESH_S:
            class_map, skip_map, names = cached["class_map"], cached["skip_map"], cached["names"]
            static_complete = True
        else:
            self._vendor_psu_static.pop(cache_key, None)
            static_complete = True
            if table.class_col:
                raw_class, class_done = self._walk_column_status(device, config, table.class_col)
                class_map = {_flatten_vendor_idx(k): v for k, v in raw_class.items()}
                static_complete = static_complete and class_done
            else:
                class_map = {}
            if table.skip_when_col:
                raw_skip, skip_done = self._walk_column_status(device, config, table.skip_when_col)
                skip_map = {_flatten_vendor_idx(k): v for k, v in raw_skip.items()}
                static_complete = static_complete and skip_done
            else:
                skip_map = {}
            if table.name:
                raw_names, names_done = self._walk_column_status(device, config, table.name)
                names = {_flatten_vendor_idx(k): v for k, v in raw_names.items()}
                static_complete = static_complete and names_done
            else:
                names = {}
            if static_complete and all(
                    m for col, m in ((table.class_col, class_map),
                                     (table.skip_when_col, skip_map),
                                     (table.name, names)) if col):
                self._vendor_psu_static[cache_key] = {
                    "class_map": class_map, "skip_map": skip_map, "names": names, "ts": now}
        rows: dict[str, dict] = {}
        raw_states, complete = self._walk_column_status(device, config, table.state)
        complete = complete and static_complete
        states = {_flatten_vendor_idx(k): v for k, v in raw_states.items()}
        for idx, raw in states.items():
            if table.class_col:
                try:
                    if int(class_map.get(idx)) not in table.class_values:
                        continue
                except (TypeError, ValueError):
                    continue
            if table.skip_when_col:
                try:
                    skip_raw = skip_map.get(idx)
                    if skip_raw is not None and int(skip_raw) in table.skip_when_values:
                        continue
                except (TypeError, ValueError):
                    pass
            label = names.get(idx) or (
                table.label.format(idx=idx) if table.label else f"PSU {idx}")
            rows[idx] = {"label": str(label),
                        "state": _vendor_state_value(raw, table.state_map, table.state_default)}
        for entry in table.extra_scalars:
            oid, idx, label = entry[:3]
            scalar_map = entry[3] if len(entry) > 3 else table.state_map
            extra = self._walk_column(device, config, oid)
            raw = extra.get("0")
            if raw is None:
                continue
            rows[idx] = {"label": label,
                        "state": _vendor_state_value(raw, scalar_map, table.state_default)}
        return rows, complete

    def _mark_vendor_rows_absent(self, device_id: int, table_state: str, family: str,
                                 rows: dict, complete: bool, existing: set,
                                 labels: dict, samples: list, now: float) -> None:
        """Marks a bay ABSENT (state gauge sample) once a COMPLETE walk of
        `table_state` no longer produces it. A walk cut short leaves the
        remembered set untouched; the set is keyed per (device_id, table_state).
        """
        seen_key = (device_id, table_state)
        if not complete:
            return
        previous = self._vendor_psu_seen.get(seen_key, set())
        for idx in sorted(previous - set(rows)):
            key = f"{family}.{idx}"
            if key in existing:
                samples.append((key, labels.get(key, key), "state", "gauge",
                                now, self._PSU_STATE_ABSENT))
        self._vendor_psu_seen[seen_key] = set(rows)

    def _poll_stack_power(self, device_id: int, device, config: dict,
                          now: float) -> None:
        """CISCO-STACKWISE-MIB (nodeoids.CSW_*) stack power cabling, arc 9
        (Cisco) only, called from _poll_vendor_sensors. Writes
        stack_power_port(_admin|_switch|_neighbour|_limit_a).<idx> (idx =
        _flatten_vendor_idx("<entPhysicalIndex>.<cswStackPowerPortIndex>")),
        stack_power_stack_*.<stack> and stack_power_*_w.<entPhysicalIndex>.
        _admin's label is the raw cswStackPowerPortName, not the friendly
        stack_power_port.<idx> label -- the API reads a port's name off it.

        Own probe-once-remember latch (_stack_power_capable/_read), separate
        from vendor_sensor_capable; retried at most once an hour
        (_SENSOR_REPROBE_S) until it answers.
        """
        capable = self._stack_power_capable.get(device_id)
        if capable != 1 and (now - self._stack_power_read.get(device_id, 0.0)
                             < self._SENSOR_REPROBE_S):
            return
        self._stack_power_read[device_id] = now

        oper = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_PORT_OPER_STATUS)
        neighbor = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_PORT_NEIGHBOR_SWITCH)
        link = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_PORT_LINK_STATUS)
        limit = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_PORT_LIMIT_A)
        port_name = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_PORT_NAME)

        switch_num = self._walk_column(device, config, nodeoids.CSW_SWITCH_NUM_CURRENT)
        budget = self._walk_column(device, config, nodeoids.CSW_SWITCH_POWER_BUDGET)
        committed = self._walk_column(device, config, nodeoids.CSW_SWITCH_POWER_COMMITED)
        allocated = self._walk_column(device, config, nodeoids.CSW_SWITCH_POWER_ALLOCATED)

        mode = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_MODE)
        members = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_NUM_MEMBERS)
        topology = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_TYPE)
        stack_name = self._walk_column(device, config, nodeoids.CSW_STACK_POWER_NAME)

        # Only the tables that yield rows count: every data stack answers
        # cswSwitchInfoTable, with or without StackPower cabling.
        answered = bool(oper or mode)
        if answered:
            self._stack_power_capable[device_id] = 1
        elif capable is None:
            self._stack_power_capable[device_id] = 0
        if not answered:
            return

        samples = []
        switch_by_ent = {suffix: _vendor_numeric(raw, False)
                         for suffix, raw in switch_num.items()}

        for suffix, admin_raw in oper.items():
            parts = suffix.split(".")
            if len(parts) != 2:
                continue
            ent, port = parts
            admin = _vendor_numeric(admin_raw, False)
            if admin is None:
                continue
            link_val = _vendor_numeric(link.get(suffix), False)
            if admin == 2:
                state = 0.0                  # administratively off, not a fault
            elif link_val == 2:
                state = 2.0                  # enabled, cable down
            elif link_val == 1:
                state = 0.0                  # enabled, up
            else:
                continue                     # link never answered -- no fact yet
            switch = switch_by_ent.get(ent)
            switch_text = str(int(switch)) if switch is not None else ent
            name = str(port_name.get(suffix) or "").strip() or f"port {port}"
            label = f"Switch {switch_text} stack power {name}"
            nbr = _vendor_numeric(neighbor.get(suffix), False)
            if nbr:                          # 0/unset -- no neighbour to name
                label += f" -> switch {int(nbr)}"
            idx = _flatten_vendor_idx(suffix)
            samples.append((f"stack_power_port.{idx}", label, "state", "gauge", now, state))
            samples.append((f"stack_power_port_admin.{idx}", name, "state",
                            "gauge", now, admin))
            if switch is not None:
                samples.append((f"stack_power_port_switch.{idx}", name, "state",
                                "gauge", now, float(switch)))
            samples.append((f"stack_power_port_neighbour.{idx}", name, "state",
                            "gauge", now, float(nbr or 0)))
            lim = _vendor_numeric(limit.get(suffix), False)
            if lim is not None:
                samples.append((f"stack_power_port_limit_a.{idx}", label, "A",
                                "gauge", now, lim))

        for suffix, raw in switch_num.items():
            switch = _vendor_numeric(raw, False)
            if switch is None:
                continue
            label = f"Switch {int(switch)}"
            for oid_map, root, unit in ((budget, "stack_power_budget_w", "W"),
                                        (committed, "stack_power_committed_w", "W"),
                                        (allocated, "stack_power_allocated_w", "W")):
                value = _vendor_numeric(oid_map.get(suffix), False)
                if value is not None:
                    samples.append((f"{root}.{suffix}", label, unit, "gauge", now, value))

        for suffix in set(topology) | set(mode) | set(members):
            label = str(stack_name.get(suffix) or "").strip() or f"power stack {suffix}"
            for oid_map, root, unit in ((topology, "stack_power_stack_type", "state"),
                                        (mode, "stack_power_stack_mode", "state"),
                                        (members, "stack_power_stack_members", "count")):
                value = _vendor_numeric(oid_map.get(suffix), False)
                if value is not None:
                    samples.append((f"{root}.{suffix}", label, unit, "gauge", now, value))

        if samples:
            self.db.record_metric_samples(device_id, samples)

    def _vendor_threshold_source(self, table) -> str:
        """A stable, human-legible source name for
        nodesdb.replace_interface_thresholds -- the OID of the table's own
        threshold column is unique enough per arc that it doubles as the
        MIB name a later diff would recognise."""
        return f"nodeoids.SENSOR_TABLES:{table.value}"

    def _poll_vendor_sensor_thresholds(self, device_id: int, device, config: dict,
                                       table, rows: dict, now: float) -> None:
        """The published high-warning/high-critical limits one
        nodeoids.SensorTable exposes, into interface_thresholds with
        metric_root='temp_sensor_c' -- the vendor-table sibling of
        _poll_published_thresholds' Cisco/Arista ENTITY-SENSOR walk.

        Only ever writes a row for an idx `rows` (this poll's reading/state
        walk) actually produced: a threshold column answering for an entity
        the value walk never reached would publish a limit for a sensor
        this poll has no reading to judge it against.
        """
        if not (table.thresholds or table.threshold_scalars) or not rows:
            return
        per_row_columns: dict[str, dict] = {}
        for band, oid in (table.thresholds or {}).items():
            for suffix, raw in self._walk_column(device, config, oid).items():
                idx = _flatten_vendor_idx(suffix)
                num = _vendor_numeric(raw, table.numeric_prefix)
                if num is None:
                    continue
                scale = rows.get(idx, {}).get("scale", table.scale)
                per_row_columns.setdefault(idx, {})[band] = num * scale
        global_columns: dict = {}
        for band, oid in (table.threshold_scalars or {}).items():
            raw = self._walk_column(device, config, oid).get("0")
            num = _vendor_numeric(raw, table.numeric_prefix)
            if num is not None:
                global_columns[band] = num * table.scale

        published = []
        for idx in rows:
            band_values = dict(global_columns)
            band_values.update(per_row_columns.get(idx, {}))
            if not band_values:
                continue
            if not self._published_band_sane("temp_sensor_c", band_values):
                self._log_sensor_diag(
                    device, f"{device['ip']} publishes temp_sensor_c limits "
                            f"for index {idx} that do not make sense "
                            f"together; they are ignored, so that sensor "
                            f"raises no threshold alerts")
                continue
            try:
                if_index = int(idx)
            except ValueError:
                continue
            published.append({"if_index": if_index, "metric_root": "temp_sensor_c",
                              "low_alarm": band_values.get("low_alarm"),
                              "low_warn": band_values.get("low_warn"),
                              "high_warn": band_values.get("high_warn"),
                              "high_alarm": band_values.get("high_alarm"),
                              "updated_ts": now})
        self.db.replace_interface_thresholds(
            device_id, self._vendor_threshold_source(table), published)

    # BRIDGE-MIB (RFC 4188) columns used by read_mac_table() to map the
    # forwarding-database entries learned on a switch port back to the
    # ifIndex the rest of the app already keys interfaces by.
    _DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
    _DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
    # Q-BRIDGE-MIB (RFC 4363) dot1qTpFdbPort. The table a VLAN-aware switch
    # actually populates, and the one most modern gear answers instead of
    # dot1dTpFdbTable. Its index is <dot1qFdbId>.<6 MAC bytes> rather than
    # the MAC alone, which is why a six-arc-only parser sees nothing here.
    _DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    # CISCO-VTP-MIB vtpVlanState: the VLAN list for the per-VLAN community
    # trick below. 1 == operational.
    _VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
    # Bounds on the Cisco per-VLAN path: a trunk-heavy switch can carry
    # hundreds of VLANs and this runs while a human waits on a dialog.
    _MAX_VLAN_CONTEXTS = 48
    _VLAN_WALK_BUDGET_S = 30.0

    @staticmethod
    def _fdb_entries(fdb_port: dict, target_ports: set, vlan: str | None,
                     vlan_indexed: bool, port_map: dict | None = None) -> list[dict]:
        """Rows of a forwarding-database column.

        Filtered to `target_ports` — one port for the interface dialog, or
        every bridge port for the whole-device walk, which also passes
        `port_map` (bridge port -> ifIndex) so each entry says which
        interface learned the address.

        Both FDB tables carry the learned MAC in the row's own OID suffix,
        so no second GET is needed for the address column. dot1dTpFdbTable
        is indexed by the MAC alone (six arcs); dot1qTpFdbTable prefixes it
        with the filtering-database id, so the MAC is always the **last
        six** arcs and anything before it is the VLAN.
        """
        entries = []
        for suffix, port in fdb_port.items():
            try:
                if int(port) not in target_ports:
                    continue
            except (TypeError, ValueError):
                continue
            parts = suffix.split(".")
            if len(parts) < 6:
                continue
            if vlan_indexed and len(parts) < 7:
                continue
            try:
                mac = ":".join(f"{int(p):02x}" for p in parts[-6:])
            except ValueError:
                continue
            entry = {
                "mac": mac,
                "vlan": (parts[0] if vlan_indexed else vlan) or "",
            }
            if port_map is not None:
                # Whole-device form: carry which interface learned it. A
                # bridge port with no ifIndex mapping is dropped rather than
                # stored against a guess.
                if_index = port_map.get(int(port))
                if if_index is None:
                    continue
                entry["if_index"] = if_index
            entries.append(entry)
        return entries

    def _bridge_ports_for(self, device, config: dict, if_index: int,
                          deadline: float | None = None):
        """(bridge ports mapping to this ifIndex, whether the device answered).

        A switch that does not answer dot1dBasePortIfIndex at all is a
        different fact from one that answers and simply has no bridge port
        for this interface, and the caller reports them differently.
        """
        base_port_if_index = self._walk_column(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
        if not base_port_if_index:
            return set(), False
        ports = set()
        for suffix, value in base_port_if_index.items():
            try:
                if int(value) == if_index:
                    ports.add(int(suffix))
            except (TypeError, ValueError):
                continue
        return ports, True

    def _cisco_vlan_fdb(self, device, config: dict, if_index: int,
                        target_ports: set):
        """Classic Cisco IOS exposes its forwarding database only inside
        per-VLAN SNMP contexts, reached by suffixing the community with
        `@<vlan>`. There is no community to suffix under v3, so that is
        skipped rather than pretended at; and the walk is bounded in both
        VLAN count and wall-clock, because this runs while a human waits on
        an interface dialog and a trunk switch can carry hundreds of VLANs.

        Returns (entries, answered). `answered` reports whether any VLAN
        context produced a bridge-port table, which is how the caller tells
        "this switch cannot tell us" from "it can, and this port has learned
        nothing" on a device whose global context answers neither.
        """
        if snmp_version_of(config) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:          # operational only
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            # VLAN 1002-1005 are the legacy FDDI/token-ring defaults every
            # IOS switch reports and none of them ever learn anything.
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        # The budget is passed INTO each walk, not only checked between
        # VLANs: checking between them let the last VLAN start two
        # unbounded walks (bridge ports, then the forwarding table) after
        # the budget was already spent, which is how a dialog a human is
        # waiting on ran for minutes.
        deadline = time.monotonic() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.monotonic() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            ports = target_ports
            if not ports:
                # On these switches dot1dBasePortIfIndex lives in the same
                # per-VLAN context as the forwarding table, so the global
                # read the caller tried first comes back empty on exactly
                # the devices this path exists for.
                ports, port_answered = self._bridge_ports_for(
                    device, scoped, if_index, deadline=deadline)
                answered = answered or port_answered
                if not ports:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
            entries.extend(self._fdb_entries(fdb_port, ports, vlan, False))
        return entries, answered

    def read_mac_table(self, device_id: int, if_index: int) -> list[dict] | None:
        """Live on-demand read of the MAC addresses learned on one switch
        port — same on-demand-while-the-dialog-is-open shape as read_dom()
        above: walked only when a human asks, never on the poll cycle.

        Three sources, because no single one covers the field: Q-BRIDGE's
        dot1qTpFdbTable first, the original BRIDGE-MIB dot1dTpFdbTable as
        fallback, and classic Cisco IOS per VLAN through the community@vlan
        convention. The first that yields anything wins — they describe the
        same port, so merging them would double-count.

        Returns None (not []) when the device answers none of them, so the
        dialog can say "no data" instead of "zero MACs learned on this
        port" — those are different facts."""
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        target_ports, answered = self._bridge_ports_for(device, config, if_index)
        # detected_vendor, not device["vendor"]: a custom vendor_oid may have
        # replaced the displayed name with whatever the device calls itself,
        # and this gate needs the identified vendor key.
        is_cisco = detected_vendor(device).lower() == "cisco"

        entries = []
        if target_ports:
            entries = self._fdb_entries(
                self._walk_column(device, config, self._DOT1Q_FDB_PORT),
                target_ports, None, True)
            if not entries:
                entries = self._fdb_entries(
                    self._walk_column(device, config, self._DOT1D_FDB_PORT),
                    target_ports, None, False)
        # Deliberately also reached when the global context answered nothing
        # at all: a classic IOS switch hides dot1dBasePortIfIndex in the same
        # per-VLAN contexts as the forwarding table, so bailing out on an
        # empty global read would skip this path on the very devices it is
        # here for.
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_fdb(
                device, config, if_index, target_ports)
            answered = answered or cisco_answered
        if not answered:
            return None

        # One MAC can legitimately appear in several VLANs; dedupe on the
        # pair rather than the address so that stays visible.
        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["mac"], e["vlan"])):
            key = (entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def read_device_mac_table(self, device_id: int) -> list[dict] | None:
        """Every MAC this switch has learned, and on which interface.

        The whole-device counterpart of read_mac_table above, and the same
        three sources in the same order — a forwarding table is a forwarding
        table whether you want one port of it or all of it. What differs is
        that this is not filtered to one port, so the bridge-port map is
        needed in full, and that this runs on the mac_table_interval_s
        schedule rather than while somebody watches a dialog.

        Returns None when the device answers no forwarding table at all,
        which the caller must not confuse with an empty one: "this switch
        cannot tell us" and "this switch has learned nothing" are different
        facts, and only the second should overwrite what we already stored.

        Also None when an FDB column walk did not finish: a truncated table is not evidence of absence, so nothing is overwritten.
        """
        device = self.db.device(device_id)
        if device is None:
            return None
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return None

        # Budget off mac_table_interval_s, not the poll interval.
        deadline = self._table_walk_deadline(config, "mac_table_interval_s")
        port_map = self._bridge_port_map(device, config, deadline=deadline)
        is_cisco = detected_vendor(device).lower() == "cisco"
        answered = bool(port_map)

        entries = []
        if port_map:
            ports = set(port_map)
            fdb, complete = self._walk_column_status(
                device, config, self._DOT1Q_FDB_PORT, deadline=deadline)
            if not complete:
                return None
            entries = self._fdb_entries(fdb, ports, None, True, port_map)
            if not entries:
                fdb, complete = self._walk_column_status(
                    device, config, self._DOT1D_FDB_PORT, deadline=deadline)
                if not complete:
                    return None
                entries = self._fdb_entries(fdb, ports, None, False, port_map)
        if not entries and is_cisco:
            entries, cisco_answered = self._cisco_vlan_device_fdb(
                device, config, port_map)
            answered = answered or cisco_answered
        if not answered:
            return None

        seen = set()
        unique = []
        for entry in sorted(entries, key=lambda e: (e["if_index"], e["mac"],
                                                    e["vlan"])):
            key = (entry["if_index"], entry["mac"], entry["vlan"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        return unique

    def _bridge_port_map(self, device, config: dict,
                         deadline: float | None = None) -> dict:
        """bridge port -> ifIndex; falls back to bridge port == ifIndex
        when dot1dBasePortIfIndex answers nothing, non-Cisco devices only
        (a Cisco device gets a per-VLAN map instead -- see _cisco_vlan_stp)
        and default-context callers only (`deadline is None`; a per-VLAN
        call already walks dot1dStpPortState per context). An incomplete
        walk returns {} rather than a partial map, so the cache above never
        remembers a truncated one."""
        base_port_if_index, complete = self._walk_column_status(
            device, config, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
        if not complete:
            return {}
        mapping = {}
        for suffix, value in base_port_if_index.items():
            try:
                mapping[int(suffix)] = int(value)
            except (TypeError, ValueError):
                continue
        if mapping or deadline is not None or is_cisco(device):
            return mapping
        port_state = self._walk_column(
            device, config, nodeoids.DOT1D_STP_PORT_STATE, deadline=deadline)
        if not port_state:
            return {}
        known = {row["if_index"] for row in self.db.interfaces(device["id"])}
        for suffix in port_state:
            try:
                bridge_port = int(suffix)
            except ValueError:
                continue
            if bridge_port in known:
                mapping[bridge_port] = bridge_port
        if mapping:
            self._log_media_diag(
                device, f"Bridge port table empty on {device['ip']}: "
                        f"assuming bridge port = ifIndex",
                "stp_bridge_port_fallback")
        return mapping

    def _cisco_vlan_device_fdb(self, device, config: dict, port_map: dict):
        """The whole device's forwarding table out of classic IOS per-VLAN
        contexts — the community@vlan path read_mac_table already needs,
        without the per-port filter. Bounded in VLAN count and wall clock
        for the same reason: a trunk switch can carry hundreds of VLANs."""
        if snmp_version_of(config) == 3:
            return [], False
        community = config.get("community")
        if not community:
            return [], False
        vlan_states = self._walk_column(device, config, self._VTP_VLAN_STATE)
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            if vlan.isdigit() and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        entries = []
        answered = False
        # See _cisco_vlan_fdb: the budget goes into the walks themselves.
        deadline = time.monotonic() + self._VLAN_WALK_BUDGET_S
        for vlan in sorted(vlans, key=int)[:self._MAX_VLAN_CONTEXTS]:
            if time.monotonic() > deadline:
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            mapping = port_map
            if not mapping:
                mapping = self._bridge_port_map(device, scoped, deadline=deadline)
                answered = answered or bool(mapping)
                if not mapping:
                    continue
            fdb_port = self._walk_column(device, scoped, self._DOT1D_FDB_PORT,
                                         deadline=deadline)
            entries.extend(self._fdb_entries(
                fdb_port, set(mapping), vlan, False, mapping))
        return entries, answered

    def _cisco_vlan_stp(self, device, config: dict,
                        start: int = 0, budget_s: float | None = None):
        """dot1dStpPortState read inside each VLAN's own `community@vlan`
        context -- classic PVST+'s real per-port state lives there, not in
        the device's default context. Each VLAN's own dot1dBasePortIfIndex
        is walked too, rather than reused from the DEFAULT context (VLAN
        1's bridge instance on IOS): a trunk that does not carry VLAN 1 is
        simply absent from that table, and reusing it drops that trunk from
        every VLAN silently -- the root cause this method exists to close.

        Walks the operational VLAN list starting at the first VLAN id >=
        `start` (wrapping to the lowest VLAN when none is), up to
        _MAX_VLAN_CONTEXTS VLANs or `budget_s` (default _VLAN_WALK_BUDGET_S).

        Returns (vlan_rows, answered, complete, next_vlan_id, vlan_total,
        next_vlan, unmapped, list_unavailable): one vlan_rows entry per VLAN
        whose own map and state walks both finished -- a complete, confirmed
        -empty map (a VTP-propagated VLAN with no local port) counts as
        answered too, with an empty ports dict and no state walk attempted;
        complete is False only on the deadline, any other failure just
        advances next_vlan_id (0 once the lap is covered, next_vlan names
        it); unmapped is the set of bridge ports seen in some VLAN's
        dot1dStpPortState but absent from THAT VLAN's own map;
        list_unavailable is True when vtpVlanState itself did not answer in
        full, in which case every other field is a no-op zero/empty value."""
        if snmp_version_of(config) == 3:
            return {}, False, True, 0, 0, None, set(), False
        community = config.get("community")
        if not community:
            return {}, False, True, 0, 0, None, set(), False
        vlan_states, list_complete = self._walk_column_status(
            device, config, self._VTP_VLAN_STATE)
        if not list_complete:
            # A genuine timeout/error/cut-short walk, not a device that
            # simply has no VTP table (that is a confirmed-empty, complete
            # answer, handled below like any other "no VLANs" case).
            return {}, False, True, 0, 0, None, set(), True
        vlans = []
        for suffix, state in vlan_states.items():
            try:
                if int(state) != 1:
                    continue
            except (TypeError, ValueError):
                continue
            vlan = suffix.split(".")[-1]
            # VLAN 1 IS the DEFAULT context on IOS (_poll_stp's merge seeds
            # it from there); asking for it again as "@1" is redundant at
            # best, and 1002-1005 are the legacy VLANs VTP always lists but
            # a real switch never actually carries traffic on.
            if vlan.isdigit() and vlan != "1" and not (1002 <= int(vlan) <= 1005):
                vlans.append(vlan)
        if not vlans:
            return {}, False, True, 0, 0, None, set(), False
        ordered = sorted(vlans, key=int)
        total = len(ordered)
        start_idx = next((i for i, v in enumerate(ordered) if int(v) >= start), 0)
        window = ordered[start_idx:start_idx + self._MAX_VLAN_CONTEXTS]
        complete = True
        budget = self._VLAN_WALK_BUDGET_S if budget_s is None else budget_s
        deadline = time.monotonic() + budget
        vlan_rows: dict[str, dict] = {}
        unmapped: set[int] = set()
        answered = False
        covered = 0
        for vlan in window:
            if time.monotonic() > deadline:
                complete = False
                break
            scoped = {**config, "community": f"{community}@{vlan}"}
            raw_map, map_done = self._walk_column_status(
                device, scoped, self._DOT1D_BASE_PORT_IF_INDEX, deadline=deadline)
            if not map_done:
                complete = False
                if time.monotonic() > deadline:
                    covered += covered == 0   # alone over budget: skip it, not the lap
                    break
                covered += 1
                continue
            mapping = {}
            for suffix, value in raw_map.items():
                try:
                    mapping[int(suffix)] = int(value)
                except (TypeError, ValueError):
                    continue
            if not mapping:
                # A complete, confirmed-empty map -- a VTP-propagated VLAN
                # with no local port on this switch -- is a real answer,
                # not a failure; there is nothing to walk dot1dStpPortState
                # for.
                vlan_rows[vlan] = {}
                answered = True
                covered += 1
                continue
            state, done = self._walk_column_status(
                device, scoped, nodeoids.DOT1D_STP_PORT_STATE, deadline=deadline)
            if not done:
                complete = False
                if time.monotonic() > deadline:
                    covered += covered == 0
                    break
                covered += 1
                continue
            answered = True
            ports = {}
            for suffix, value in state.items():
                try:
                    bridge_port = int(suffix)
                except ValueError:
                    continue
                if_index = mapping.get(bridge_port)
                if if_index is None:
                    unmapped.add(bridge_port)
                    continue
                if not isinstance(value, (int, float)):
                    continue
                state_name = nodeoids.DOT1D_STP_PORT_STATE_ENUM.get(int(value))
                if state_name is not None:
                    ports[if_index] = state_name
            vlan_rows[vlan] = ports
            covered += 1
        next_index = start_idx + covered
        if next_index >= total:
            next_vlan_id = 0
            next_vlan = ordered[0] if ordered else None
        else:
            next_vlan = ordered[next_index]
            next_vlan_id = int(next_vlan)
        return (vlan_rows, answered, complete, next_vlan_id, total, next_vlan,
                unmapped, False)

    def _run_mac_table(self, device_id: int) -> None:
        """One scheduled forwarding-table walk, on the poll pool.

        Wrapped in except Exception for the same reason _run_one is: a
        worker thread must never die quietly. A device that answers no
        forwarding table leaves what is stored alone rather than deleting
        it — a switch that failed to answer once has not forgotten every
        MAC it knows.
        """
        try:
            entries = self.read_device_mac_table(device_id)
            if entries is None:
                return
            stored = self.db.replace_mac_entries(device_id, entries)
            self._bump("mac_walks")
            self.log.add(NODES, f"Learned {stored} MAC address(es) on device "
                                f"#{device_id}")
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"MAC table walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._mac_running.discard(device_id)

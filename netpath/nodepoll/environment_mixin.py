from __future__ import annotations

import time
import traceback
from .. import nodeoids
from ..alertrules import DARK_OPTIC_DBM, is_dark_optic
from ..eventlog import ERROR, NODES
from ..nodesdb import detected_vendor
from ..snmppoll import SnmpError
from ._decode import _COPPER_MAU_ARCS, _COPPER_TEXT, _FIBER_MAU_ARCS, _SFP_METRICS, _TRANSCEIVER_TEXT, _canonical_if_name, _envmon_rows, _int_keyed, _optic_mode, _optical_direction
from ._session import snmp_version_of


class EnvironmentMixin:

    # ENTITY-MIB (RFC 6933) and ENTITY-SENSOR-MIB (RFC 3433) columns used
    # by read_dom() to find a port's transceiver sensors.
    _ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
    _ENT_PHYSICAL_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
    # entPhysicalClass/ModelName: what an entity IS, which is the only way
    # to see an SFP slot that reports no DOM at all -- a cage with nothing
    # in it has no sensor to be found by. entPhysicalVendorType would be the
    # obvious third, and is deliberately not walked: it is an OBJECT
    # IDENTIFIER, so a conforming agent answers a dotted number that no text
    # test can read, and the registered names behind those numbers
    # (`cevSFP10GLR` and its kin) run the words together, so they would not
    # match _TRANSCEIVER_TEXT even spelled out. Descr and model name carry
    # the whole job, for one fewer full walk of entPhysical per cadence.
    _ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
    _ENT_CLASS_CHASSIS = 3  # entPhysicalClass chassis(3)
    _ENT_PHYSICAL_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"
    # entPhysicalName: RFC 6933 makes it optional, so read_dom's own decode
    # (shared with _poll_environment, both pre-dating this column's use
    # here) never depended on it -- but where an agent populates it, it is
    # a nicer name than entPhysicalDescr for a whole-device sensor list,
    # which is naming dozens of rows at once rather than the one a port
    # dialog already knows the context of. See _read_entity_sensors.
    _ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
    _ENT_ALIAS_MAPPING = "1.3.6.1.2.1.47.1.3.2.1.2"
    _ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
    _ENT_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
    _ENT_SENSOR_PRECISION = "1.3.6.1.2.1.99.1.1.1.3"
    _ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
    _ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
    _ENT_SENSOR_UNITS = "1.3.6.1.2.1.99.1.1.1.6"
    _IF_INDEX_COLUMN = "1.3.6.1.2.1.2.2.1.1"

    # CISCO-ENTITY-SENSOR-MIB entSensorValueTable — what Cisco switches
    # populate INSTEAD of RFC 3433's entPhySensorTable, which is why an
    # all-Cisco fleet saw both sensor sections empty. Same index and
    # type/scale/precision/status enums, extended with specialEnum(13) and
    # dBm(14); no units-display column, so unit text comes from the type enum.
    _CISCO_SENSOR_TYPE = "1.3.6.1.4.1.9.9.91.1.1.1.1.1"
    _CISCO_SENSOR_SCALE = "1.3.6.1.4.1.9.9.91.1.1.1.1.2"
    _CISCO_SENSOR_PRECISION = "1.3.6.1.4.1.9.9.91.1.1.1.1.3"
    _CISCO_SENSOR_VALUE = "1.3.6.1.4.1.9.9.91.1.1.1.1.4"
    _CISCO_SENSOR_STATUS = "1.3.6.1.4.1.9.9.91.1.1.1.1.5"
    _CISCO_ENTERPRISE_PREFIX = "1.3.6.1.4.1.9."

    # CISCO-ENTITY-SENSOR-MIB entSensorThresholdTable — the alarm and
    # warning levels a transceiver publishes about ITSELF, indexed
    # <entPhysicalIndex>.<threshold index>. This is what makes an optic
    # power alert mean anything: an SR part's floor is not a ZR part's.
    #
    # .5 entSensorThresholdEvaluation is deliberately NOT read. It is the
    # device's own instantaneous verdict, and taking it would bypass this
    # app's hysteresis, its breach streak and for_polls all at once — the
    # three things that stop a value hovering at its limit mailing somebody
    # every poll. .6 entSensorThresholdNotificationEnable is about the
    # device's own traps, not about us.
    _CISCO_THRESHOLD_SEVERITY = "1.3.6.1.4.1.9.9.91.1.2.1.1.2"
    _CISCO_THRESHOLD_RELATION = "1.3.6.1.4.1.9.9.91.1.2.1.1.3"
    _CISCO_THRESHOLD_VALUE = "1.3.6.1.4.1.9.9.91.1.2.1.1.4"

    # entSensorThresholdSeverity -> which of this app's two bands the level
    # belongs in. other(1) is dropped: it names no band, so there is no
    # column to put it in. major(20) and critical(30) both land in the alarm
    # band -- an optic that publishes both gets the tighter of the two by the
    # duplicate rule below, which is the one that alerts first.
    _CISCO_THRESHOLD_BAND = {10: "warn", 20: "alarm", 30: "alarm"}
    # entSensorThresholdRelation -> which SIDE of the reading the level is.
    # lessThan(1)/lessOrEqual(2) are a floor, greaterThan(3)/greaterOrEqual(4)
    # a ceiling; equalTo(5) and notEqualTo(6) describe neither and are
    # dropped, since this app's evaluator only ever asks "at or past".
    _CISCO_THRESHOLD_SIDE = {1: "low", 2: "low", 3: "high", 4: "high"}
    # Every real transceiver's published dBm levels sit well inside this
    # band, and nothing a scale misread produces does -- a threshold decoded
    # a factor of a thousand out lands at -14400 or -0.0144, both outside.
    # It is the only check that can catch that failure, which is otherwise
    # invisible: -14.4 and -14400 are both "a number".
    _DBM_LIMIT_RANGE = (-60.0, 30.0)

    _SENSOR_TYPE_UNITS = {3: "V AC", 4: "V DC", 5: "A", 6: "W", 7: "Hz",
                          8: "°C", 9: "%RH", 10: "RPM", 11: "m³/min",
                          12: "", 13: "", 14: "dBm"}
    _SENSOR_STATUS = {1: "ok", 2: "unavailable", 3: "nonoperational"}
    # entPhySensorType -> a human label, for read_hardware's whole-device
    # sensor list (a port dialog's DOM table already gives its rows
    # context; a device-wide list naming dozens of unrelated probes needs
    # to say what kind each one is).
    _SENSOR_TYPE_NAMES = {1: "other", 2: "unknown", 3: "voltage",
                          4: "voltage", 5: "current", 6: "power",
                          7: "frequency", 8: "temperature", 9: "humidity",
                          10: "fan speed", 11: "airflow", 12: "other",
                          13: "state", 14: "optical power"}

    # entPhySensorType values this app turns into a device-level metric —
    # see _poll_environment; the rest of _SENSOR_TYPE_UNITS' arcs are real
    # DOM readings a transceiver has, not something a device has one true
    # value for, so they aren't promoted to a device metric here.
    _SENSOR_TYPE_TEMPERATURE = 8
    _SENSOR_TYPE_HUMIDITY = 9

    # entPhySensorType -> the per-port optic metric root. Optical power (14)
    # is absent: its key depends on the sensor's name, not its type.
    _SFP_TYPE_ROOTS = {8: "sfp_temp_c", 3: "sfp_volt", 4: "sfp_volt",
                       5: "sfp_bias_ma"}
    _SENSOR_TYPE_OPTICAL = 14
    # The one entPhysicalClass value this app has to tell apart: a
    # transceiver cage is a container(5). What is IN one is a module(9) on
    # some agents and a port(10) on others, so the contents are identified
    # by their text rather than by a class enum — see _sfp_slot_media.
    _ENT_CLASS_CONTAINER = 5
    # ENTITY-SENSOR-MIB reports current in amperes; bias is quoted in
    # milliamps everywhere an operator would read it.
    _BIAS_A_TO_MA = 1000.0

    @staticmethod
    def _scaled_sensor_value(raw, scale, precision) -> float:
        """RFC 3433's arithmetic, alone: the reading is
        raw x 10^(3*(scale-9)) with `precision` decimal places already
        folded into the integer.

        Its own function because entSensorThresholdValue is quoted in the
        SAME scale and precision as the entity's reading, and a second copy
        of three lines of exponent arithmetic is how the two would drift a
        factor of a thousand apart without anything looking wrong.

        Both come off the wire, and both are exponents: a device answering
        entPhySensorScale = 2147483647 (a legal Integer32) would have
        CPython build a multi-billion-digit integer and never return, on a
        poll worker or on the HTTP thread behind read_dom. RFC 3433 gives
        entitySensorDataScale seventeen legal values and entitySensorPrecision
        the range -8..9; anything outside either is not a reading this
        function can honour, so it is read at the MIB's own default
        (units, no folded decimals) rather than multiplied out.
        """
        scale = int(scale or 9)             # 9 = units (10^0)
        if not (NodePoller._SENSOR_SCALE_MIN <= scale
                <= NodePoller._SENSOR_SCALE_MAX):
            scale = 9
        precision = NodePoller._sensor_precision(precision)
        return raw * (10 ** (3 * (scale - 9))) / (10 ** precision)

    # RFC 3433's own ranges for entitySensorDataScale and
    # entitySensorPrecision.
    # RFC 3433 EntitySensorDataScale: yocto(1) .. units(9) .. yotta(17).
    _SENSOR_SCALE_MIN, _SENSOR_SCALE_MAX = 1, 17
    _SENSOR_PRECISION_MIN, _SENSOR_PRECISION_MAX = -8, 9

    @staticmethod
    def _sensor_precision(precision) -> int:
        value = int(precision or 0)
        if not (NodePoller._SENSOR_PRECISION_MIN <= value
                <= NodePoller._SENSOR_PRECISION_MAX):
            return 0
        return value

    def _decode_entity_sensor(self, suffix: str, raw, types: dict, scales: dict,
                              precisions: dict, statuses: dict, units: dict,
                              descrs: dict) -> dict | None:
        """One ENTITY-SENSOR-MIB row (RFC 3433) -> {"entity", "label",
        "value", "unit", "status"}, or None when `raw` is not the number
        entPhySensorValue is supposed to be (an unpopulated row, or an
        agent answering the wrong ASN.1 type for this instance).

        Shared by read_dom and _poll_environment so the scaling arithmetic
        lives in one place. Reached without entAliasMappingIdentifier, which
        maps a sensor to the port it rides on: an environmental monitor's
        probes belong to the chassis, map to nothing in that table, and
        would otherwise be invisible everywhere in this app.
        """
        if not isinstance(raw, (int, float)):
            return None
        try:
            entity = int(suffix)
        except ValueError:
            return None
        sensor_type = int(types.get(suffix) or 0)
        precision = self._sensor_precision(precisions.get(suffix))
        value = self._scaled_sensor_value(
            raw, scales.get(suffix), precisions.get(suffix))
        unit = str(units.get(suffix) or "").strip() or \
            self._SENSOR_TYPE_UNITS.get(sensor_type, "")
        return {
            "entity": entity,
            "label": str(descrs.get(suffix) or f"sensor {entity}"),
            "value": round(value, max(precision, 4)),
            "unit": unit,
            "status": self._SENSOR_STATUS.get(
                int(statuses.get(suffix) or 0), "unknown"),
        }

    def _cisco_sensor_table_plausible(self, device) -> bool:
        """Whether CISCO-ENTITY-SENSOR-MIB could answer on this device.

        The fallback walk below is gated on this so nothing but Cisco gear
        ever pays for a second table walk that could only time out: on a
        fleet of a few hundred devices an ungated fallback would be one
        wasted walk per device per sensor read, forever.
        """
        if detected_vendor(device).lower() == "cisco":
            return True
        keys = device.keys() if hasattr(device, "keys") else device
        raw = (device["sys_object_id"] if "sys_object_id" in keys else "") or ""
        return str(raw).startswith(self._CISCO_ENTERPRISE_PREFIX)

    def _walk_sensor_columns(self, device, config: dict) -> tuple[str, dict, list, bool]:
        """(source, columns, tried, complete) -- an empty result from a
        walk that merely timed out must not read as "no DOM here"."""
        tried = ["ENTITY-SENSOR-MIB"]
        source = "ENTITY-SENSOR-MIB"
        values, complete = self._walk_column_status(device, config, self._ENT_SENSOR_VALUE)
        siblings = (self._ENT_SENSOR_TYPE, self._ENT_SENSOR_SCALE,
                    self._ENT_SENSOR_PRECISION, self._ENT_SENSOR_STATUS,
                    self._ENT_SENSOR_UNITS)
        if not values and self._cisco_sensor_table_plausible(device):
            tried.append("CISCO-ENTITY-SENSOR-MIB")
            source = "CISCO-ENTITY-SENSOR-MIB"
            values, complete = self._walk_column_status(device, config, self._CISCO_SENSOR_VALUE)
            siblings = (self._CISCO_SENSOR_TYPE, self._CISCO_SENSOR_SCALE,
                        self._CISCO_SENSOR_PRECISION, self._CISCO_SENSOR_STATUS,
                        None)
        if not values:
            return "", {}, tried, complete
        type_oid, scale_oid, precision_oid, status_oid, units_oid = siblings
        cols = {
            "values": values,
            "types": self._walk_column(device, config, type_oid),
            "scales": self._walk_column(device, config, scale_oid),
            "precisions": self._walk_column(device, config, precision_oid),
            "statuses": self._walk_column(device, config, status_oid),
            "units": self._walk_column(device, config, units_oid)
                     if units_oid else {},
        }
        return source, cols, tried, complete

    def read_dom(self, device_id: int, if_index: int) -> list[dict]:
        """Live on-demand read of one interface's sensors — DOM/DDM data on
        an SFP port (light levels, bias current, supply voltage,
        temperature). Walked only while a human has the interface dialog
        open, never on the poll cycle: several table walks per call is fine
        once in a while and wasteful every interval.

        _read_entity_sensors filtered to one ifIndex, so this can never
        disagree with the whole-device list about which sensor rides on
        which port or which MIB it came from. `label` stays entPhysicalDescr
        here since a port dialog already supplies context a device-wide
        list has to spell out.

        Each row also carries `limits` — the four-band dict this port's own
        transceiver published for that reading, or None — and
        `limits_source`, the MIB it came out of. They are on the row rather
        than left to the caller because a reading and the level it is judged
        against are one fact: from 5.3.0 an optical power row with no limits
        raises no alert at all, and that is only honest if the dialog says
        so. One stored read per call, no extra walk.

        Returns [] when the device answers no sensor table or maps no
        entity to this ifIndex."""
        device = self.db.device(device_id)
        if device is None:
            return []
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return []
        limits = self.db.interface_thresholds(device_id)
        sensors = []
        for sensor in self._read_entity_sensors(device, config):
            if sensor.get("if_index") != if_index:
                continue
            sensors.append({
                "entity": sensor["entity"],
                "label": sensor.get("descr") or sensor["label"],
                "value": sensor["value"], "unit": sensor["unit"],
                "status": sensor["status"], "source": sensor.get("source", ""),
                **self._sensor_limits(limits, if_index, sensor)})
        sensors.sort(key=lambda s: s["entity"])
        return sensors

    @staticmethod
    def _sensor_limits(limits: dict, if_index, sensor: dict) -> dict:
        """{"limits": the four published bands or None, "limits_source": the
        MIB that published them} for one DOM row — the shape read_dom and
        read_dom_all both put on their rows."""
        row = limits.get((if_index, sensor.get("metric_root")))
        if row is None:
            return {"limits": None, "limits_source": ""}
        return {
            "limits": {band: row[band] for band in
                       ("low_alarm", "low_warn", "high_warn", "high_alarm")},
            "limits_source": row["source"],
        }

    def _entity_port_map(self, device, config: dict, names: dict | None = None,
                         if_by_name: dict | None = None,
                         contained_in: dict[int, int] | None = None
                         ) -> tuple[dict[int, int], int]:
        """(entPhysicalIndex -> ifIndex, how many entAliasMappingIdentifier
        rows the device answered) for every entity mapped to a port. The
        row count is only used to explain, in the Nodes event log, why
        sensors mapped to nothing.

        First pass: entAliasMappingIdentifier resolved through
        entPhysicalContainedIn — the standard, authoritative mapping.
        Second pass exists because Cisco gear often populates no alias rows
        at all: for an unmapped entity, climb its containment chain and
        match a hop's entPhysicalName (whole name or first word) against a
        stored ifDescr (`if_by_name`, canonicalised by _canonical_if_name)
        — e.g. "Te1/1/1 Transmit Power" against "TenGigabitEthernet1/1/1".
        Matched against ifDescr only, never ifAlias, since an operator-typed
        description proves nothing.

        `contained_in` is walked here when the caller has no use for it
        itself; _poll_environment passes its own so the SFP-slot scan and
        this share one walk of the column.
        """
        alias = self._walk_column(device, config, self._ENT_ALIAS_MAPPING)
        prefix = self._IF_INDEX_COLUMN + "."
        direct: dict[int, int] = {}
        for suffix, value in alias.items():
            target = str(value)
            if not target.startswith(prefix):
                continue
            try:
                entity = int(suffix.split(".")[0])
                if_index = int(target.rsplit(".", 1)[-1])
            except ValueError:
                continue
            direct[entity] = if_index
        if contained_in is None:
            contained_in, _complete = self._entity_contained_in(device, config)

        resolved: dict[int, int] = {}

        def resolve(entity: int):
            seen = 0
            chain = entity
            while chain and seen < 16:   # a real containment tree is shallow
                if chain in direct:
                    resolved[entity] = direct[chain]
                    return
                chain = contained_in.get(chain, 0)
                seen += 1

        for entity in set(direct) | set(contained_in):
            resolve(entity)
        if not names or not if_by_name:
            return resolved, len(alias)

        named = _int_keyed(names)
        for entity in sorted(set(named) | set(contained_in)):
            if entity in resolved:
                continue
            hop, seen = entity, 0
            while hop and seen < 16:
                if hop in resolved:
                    resolved[entity] = resolved[hop]
                    break
                hit = self._if_index_for_name(named.get(hop), if_by_name)
                if hit is not None:
                    resolved[entity] = hit
                    break
                hop = contained_in.get(hop, 0)
                seen += 1
        return resolved, len(alias)

    def _entity_contained_in(self, device, config: dict) -> tuple[dict[int, int], bool]:
        """(entPhysicalIndex -> the entity holding it, both ends parsed to
        int; whether the walk reached the end). Its own method because two
        passes over one device need the containment tree and neither may
        pay for a second walk of it."""
        parents: dict[int, int] = {}
        raw, complete = self._walk_column_status(
            device, config, self._ENT_PHYSICAL_CONTAINED_IN)
        for suffix, value in _int_keyed(raw).items():
            try:
                parents[suffix] = int(value)
            except (TypeError, ValueError):
                continue
        return parents, complete

    def _sfp_slot_media(self, device, config: dict, port_map: dict[int, int],
                        contained_in: dict[int, int], descrs: dict) -> tuple:
        """(media map, complete flag, class row count, cut-short diagnostics,
        optic mode map, entPhysicalModelName column): a walk cut short must
        never read as a cage that is not there. The model column is handed
        back so a caller scanning DOM-lit ports for their mode too does not
        pay for a second walk of it."""
        raw_classes, complete, class_reason = self._walk_column_detail(
            device, config, self._ENT_PHYSICAL_CLASS)
        classes = _int_keyed(raw_classes)
        reasons = [] if complete else [
            f"entPhysicalClass walk cut short ({class_reason})"]
        if not classes:
            return {}, complete, len(classes), reasons, {}, {}
        raw_models, models_done, model_reason = self._walk_column_detail(
            device, config, self._ENT_PHYSICAL_MODEL_NAME)
        complete = complete and models_done
        if not models_done:
            reasons.append(f"entPhysicalModelName walk cut short ({model_reason})")
        models = _int_keyed(raw_models)
        by_descr = _int_keyed(descrs)
        children: dict[int, list[int]] = {}
        for entity, parent in contained_in.items():
            children.setdefault(parent, []).append(entity)

        def names_transceiver(entity: int) -> bool:
            return any(_TRANSCEIVER_TEXT.search(str(column.get(entity) or ""))
                       for column in (by_descr, models))

        def names_copper(entity: int) -> bool:
            return any(_COPPER_TEXT.search(str(column.get(entity) or ""))
                       for column in (by_descr, models))

        def descendants(root: int) -> list[int]:
            found: list[int] = []
            queue, depth = list(children.get(root, ())), 0
            while queue and depth < 4:      # a cage's contents are shallow
                found.extend(queue)
                queue = [c for parent in queue for c in children.get(parent, ())]
                depth += 1
            return found

        def entity_texts(entity: int) -> tuple:
            return by_descr.get(entity), models.get(entity)

        media: dict[int, str] = {}
        mode: dict[int, str] = {}
        for entity, klass in sorted(classes.items()):
            try:
                klass = int(klass)
            except (TypeError, ValueError):
                continue
            if klass != self._ENT_CLASS_CONTAINER:
                # The cage's own text names it either way, so only something
                # OTHER than the container proves one is occupied.
                if names_transceiver(entity) and entity in port_map:
                    if_index = port_map[entity]
                    media[if_index] = (
                        "copper" if names_copper(entity) else "sfp")
                    found_mode = _optic_mode(*entity_texts(entity))
                    if found_mode:
                        mode[if_index] = found_mode
                continue
            if not names_transceiver(entity):
                continue
            # A cage rarely carries the alias row itself; the port sitting
            # in it does, which is the ifIndex the badge belongs to.
            if_index = next((port_map[e] for e in [entity] + children.get(entity, [])
                             if e in port_map), None)
            if if_index is None:
                continue
            occupants = [child for child in descendants(entity)
                        if names_transceiver(child)]
            if occupants:
                copper = names_copper(entity) or any(
                    names_copper(child) for child in occupants)
                media[if_index] = "copper" if copper else "sfp"
                occupant_texts = [text for child in occupants
                                  for text in entity_texts(child)]
                found_mode = _optic_mode(*entity_texts(entity), *occupant_texts)
                if found_mode:
                    mode[if_index] = found_mode
            else:
                media.setdefault(if_index, "sfp_empty")
        return media, complete, len(classes), reasons, mode, models

    @staticmethod
    def _if_index_for_name(name, if_by_name: dict) -> int | None:
        """The ifIndex whose canonicalised ifDescr this entPhysicalName
        names, if any: the whole name first, then its first whitespace
        token, which is the part a Cisco sensor name puts the port in."""
        raw = str(name or "").strip()
        if not raw:
            return None
        for candidate in (raw, raw.split()[0]):
            hit = if_by_name.get(_canonical_if_name(candidate))
            if hit is not None:
                return hit
        return None

    def _read_entity_sensors(self, device, config: dict) -> list[dict]:
        """Every ENTITY-SENSOR-MIB row this device answers, whatever it
        does or does not map to -- the whole-device counterpart of
        read_dom()'s single-port filter, and read_hardware's "sensors"
        list. Shares _decode_entity_sensor with read_dom and
        _poll_environment, so the value/unit/status of a given reading can
        never disagree between them.

        Each row adds `type` (a human label for entPhySensorType),
        `if_index`/`if_name` (via _entity_port_map), `descr` (raw
        entPhysicalDescr, which read_dom labels its rows from) and `source`
        (the MIB the reading came from) on top of _decode_entity_sensor's
        own shape, and prefers entPhysicalName over entPhysicalDescr for
        `label` where an agent populates it -- see _ENT_PHYSICAL_NAME.
        """
        source, cols, tried, _complete = self._walk_sensor_columns(device, config)
        if not cols:
            self._log_sensor_diag(
                device, f"No sensor rows from {device['ip']}: "
                        f"{' and '.join(tried)} answered nothing")
            return []
        types = cols["types"]
        descrs = self._walk_column(device, config, self._ENT_PHYSICAL_DESCR)
        names = self._walk_column(device, config, self._ENT_PHYSICAL_NAME)
        interfaces = list(self.db.interfaces(device["id"]))
        if_names = {row["if_index"]: (row["descr"] or row["alias"] or "")
                   for row in interfaces}
        port_map, alias_rows = self._entity_port_map(
            device, config, names, self._if_index_by_name(interfaces))

        sensors = []
        for suffix, raw in cols["values"].items():
            reading = self._decode_entity_sensor(
                suffix, raw, types, cols["scales"], cols["precisions"],
                cols["statuses"], cols["units"], descrs)
            if reading is None:
                continue
            entity = reading["entity"]
            name = str(names.get(suffix) or "").strip()
            if_index = port_map.get(entity)
            if_name = if_names.get(if_index) if if_index is not None else None
            sensors.append({
                **reading,
                "label": name or reading["label"],
                "descr": str(descrs.get(suffix) or "").strip(),
                "source": source,
                "type": self._SENSOR_TYPE_NAMES.get(
                    int(types.get(suffix) or 0), "other"),
                # The per-port metric key this reading feeds, so the two DOM
                # reads can find the limits the port published for it without
                # re-deriving the direction from the sensor's name.
                "metric_root": self._sfp_root_for(
                    int(types.get(suffix) or 0), suffix, names, descrs),
                "if_index": if_index,
                "if_name": if_name or None,
            })
        sensors.sort(key=lambda s: s["entity"])
        # A UPS or a room monitor maps nothing to a port and is fine; an
        # unmapped optic, or any unmapped row on Cisco gear, is the case
        # this line was written for.
        suspicious = (self._cisco_sensor_table_plausible(device)
                      or any(s["type"] == "optical power" for s in sensors))
        if sensors and suspicious and not any(
                s["if_index"] is not None for s in sensors):
            self._log_sensor_diag(
                device, f"Read {len(sensors)} sensor row(s) from {device['ip']} "
                        f"via {source}, none mapped to an interface: "
                        f"entAliasMappingIdentifier had {alias_rows} row(s), "
                        f"entPhysicalName matched no stored ifDescr")
        return sensors

    @staticmethod
    def _if_index_by_name(interfaces) -> dict[str, int]:
        """Canonicalised ifDescr -> ifIndex, for _entity_port_map's name
        fallback. ifDescr only: ifAlias is whatever an operator typed."""
        by_name: dict[str, int] = {}
        for row in interfaces:
            key = _canonical_if_name(row["descr"] or "")
            if key:
                by_name.setdefault(key, row["if_index"])
        return by_name

    # One sensor-diagnostic event per device per minute. The device dialog
    # re-reads on every open, and a device that answers nothing must not
    # turn that into an event-log flood.
    _SENSOR_DIAG_INTERVAL_S = 60.0

    def _log_sensor_diag(self, device, message: str) -> None:
        now = time.time()
        device_id = device["id"]
        if now - self._sensor_diag_ts.get(device_id, 0.0) < \
                self._SENSOR_DIAG_INTERVAL_S:
            return
        self._sensor_diag_ts[device_id] = now
        self.log.add(NODES, message, target=device["ip"])

    def _log_media_diag(self, device, message: str, cause: str) -> None:
        """Same shape as _log_sensor_diag, but rate-limited to once per
        _SENSOR_REPROBE_S per (device, cause): several independent causes
        in one pass must each get their own event, not just the first."""
        now = time.time()
        key = (device["id"], cause)
        if now - self._media_diag_ts.get(key, 0.0) < self._SENSOR_REPROBE_S:
            return
        self._media_diag_ts[key] = now
        self.log.add(NODES, message, target=device["ip"])

    # entPhySensorType -> device-metric keys and prefixes read_hardware's
    # "metrics" section shows: the polled figures _poll_vendor_health and
    # _poll_environment already keep current, not anything walked here.
    _HARDWARE_METRIC_KEYS = {"cpu_pct", "mem_pct", "humidity_pct"}
    _HARDWARE_METRIC_PREFIXES = ("temp_", "fan_", "psu_")

    def _hardware_metrics(self, device_id: int) -> list[dict]:
        """The stored metrics that are a hardware reading rather than a
        traffic counter, a ping figure or a UPS-MIB one -- cpu_pct,
        mem_pct, every temp_* key (optic/ambient/chassis), humidity_pct,
        and any fan_*/psu_* key a future vendor table adds.

        Read straight off metrics.last_value/last_ts: _poll_vendor_health
        and _poll_environment already keep these current on their own
        poll-cycle cadence, so read_hardware only needs to show the latest
        stored sample, never walk anything itself for this section.
        """
        rows = []
        for row in self.db.metrics(device_id):
            key = row["key"]
            if key not in self._HARDWARE_METRIC_KEYS and \
               not key.startswith(self._HARDWARE_METRIC_PREFIXES):
                continue
            if row["last_value"] is None:
                continue
            rows.append({"key": key, "label": row["label"],
                        "value": row["last_value"], "unit": row["unit"],
                        "status": "", "ts": row["last_ts"]})
        order = {"cpu_pct": 0, "mem_pct": 1}
        rows.sort(key=lambda r: (order.get(r["key"], 2), r["key"]))
        return rows

    # CISCO-ENVMON-MIB (the classic pre-ENTITY-SENSOR-MIB Cisco health
    # tables) columns used by _read_cisco_envmon. ciscoEnvMonSupplyState /
    # ciscoEnvMonFanState / ciscoEnvMonTemperatureState share one enum.
    _ENVMON_SUPPLY_DESCR = "1.3.6.1.4.1.9.9.13.1.5.1.2"
    _ENVMON_SUPPLY_STATE = "1.3.6.1.4.1.9.9.13.1.5.1.3"
    _ENVMON_FAN_DESCR = "1.3.6.1.4.1.9.9.13.1.4.1.2"
    _ENVMON_FAN_STATE = "1.3.6.1.4.1.9.9.13.1.4.1.3"
    _ENVMON_TEMP_DESCR = "1.3.6.1.4.1.9.9.13.1.3.1.2"
    _ENVMON_TEMP_VALUE = "1.3.6.1.4.1.9.9.13.1.3.1.3"
    _ENVMON_TEMP_THRESHOLD = "1.3.6.1.4.1.9.9.13.1.3.1.4"
    _ENVMON_TEMP_STATE = "1.3.6.1.4.1.9.9.13.1.3.1.6"
    _ENVMON_STATE = {1: "normal", 2: "warning", 3: "critical",
                     4: "shutdown", 5: "notPresent", 6: "notFunctioning"}

    def _read_cisco_envmon(self, device, config: dict) -> list[dict]:
        """CISCO-ENVMON-MIB power-supply, fan and temperature status --
        read_hardware's Cisco-only extra section, for gear old or simple
        enough to answer this rather than (or as well as) ENTITY-SENSOR-MIB.
        Only ever called once detected_vendor is "cisco": walking an OID
        subtree the agent has never heard of just times out, and every
        non-Cisco device in the fleet would otherwise pay for a wasted walk
        on every dialog open.
        """
        rows = []
        descrs = self._walk_column(device, config, self._ENVMON_SUPPLY_DESCR)
        states = self._walk_column(device, config, self._ENVMON_SUPPLY_STATE)
        for suffix in _envmon_rows(descrs, states):
            rows.append({
                "kind": "supply",
                "label": str(descrs.get(suffix) or "") or f"supply {suffix}",
                "value": None, "unit": "",
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        descrs = self._walk_column(device, config, self._ENVMON_FAN_DESCR)
        states = self._walk_column(device, config, self._ENVMON_FAN_STATE)
        for suffix in _envmon_rows(descrs, states):
            rows.append({
                "kind": "fan",
                "label": str(descrs.get(suffix) or "") or f"fan {suffix}",
                "value": None, "unit": "",
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        descrs = self._walk_column(device, config, self._ENVMON_TEMP_DESCR)
        values = self._walk_column(device, config, self._ENVMON_TEMP_VALUE)
        thresholds = self._walk_column(device, config, self._ENVMON_TEMP_THRESHOLD)
        states = self._walk_column(device, config, self._ENVMON_TEMP_STATE)
        for suffix in _envmon_rows(descrs, states, values):
            descr = descrs.get(suffix)
            value = values.get(suffix)
            numeric = isinstance(value, (int, float))
            rows.append({
                "kind": "temperature",
                "label": str(descr or "") or f"temperature {suffix}",
                "value": value if numeric else None,
                "unit": "°C" if numeric else "",
                "threshold": thresholds.get(suffix),
                "status": self._ENVMON_STATE.get(
                    int(states.get(suffix) or 0), "unknown")})
        return rows

    def read_hardware(self, device_id: int) -> dict:
        """On-demand snapshot of a device's own hardware health for the
        device dialog's HARDWARE SENSORS section: the polled CPU/memory/
        temperature metrics already stored, every ENTITY-SENSOR-MIB row
        the device answers (not filtered to one port the way read_dom is),
        and CISCO-ENVMON-MIB's supply/fan/temperature status on Cisco gear.

        Walked only while a human has the device dialog open, never on the
        poll cycle -- the same reasoning read_dom's docstring gives. A
        device that answers nothing for a section leaves it an empty list
        rather than raising: this backs a dialog, and "no data" is a fact
        it can show, an exception is not.
        """
        device = self.db.device(device_id)
        if device is None:
            return {"metrics": [], "sensors": [], "envmon": []}
        metrics = self._hardware_metrics(device_id)
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return {"metrics": metrics, "sensors": [], "envmon": []}
        sensors = self._read_entity_sensors(device, config)
        envmon = self._read_cisco_envmon(device, config) \
            if detected_vendor(device).lower() == "cisco" else []
        return {"metrics": metrics, "sensors": sensors, "envmon": envmon}

    def read_dom_all(self, device_id: int) -> list[dict]:
        """Every port's DOM/SFP (ENTITY-SENSOR-MIB) reading across the
        whole device, in the one set of table walks _read_entity_sensors
        already does -- the device-wide counterpart of read_dom(), the
        same relationship read_device_mac_table already has to
        read_mac_table, so opening the device dialog costs one walk rather
        than one read_dom() per interface.

        Built from the exact same decode and the exact same containment
        resolution read_dom() uses, so the two can never disagree about
        which sensor belongs to which port -- only about how many ports
        they answer for in one call. Rows with no port mapping (a chassis
        or environmental-monitor probe, already visible in read_hardware's
        "sensors" list) are left out: this is the DOM/SFP table, one row
        per port, not the whole-device sensor list again.
        """
        device = self.db.device(device_id)
        if device is None:
            return []
        config = self.working_config(device)
        if not config.get("snmp_enabled", True):
            return []
        if_names = {row["if_index"]: (row["descr"] or row["alias"]
                                      or f"port {row['if_index']}")
                   for row in self.db.interfaces(device_id)}
        limits = self.db.interface_thresholds(device_id)
        rows = []
        for sensor in self._read_entity_sensors(device, config):
            if_index = sensor.get("if_index")
            if if_index is None:
                continue
            rows.append({
                "if_index": if_index,
                "if_name": if_names.get(if_index, f"port {if_index}"),
                "label": sensor["label"], "value": sensor["value"],
                "unit": sensor["unit"], "status": sensor["status"],
                **self._sensor_limits(limits, if_index, sensor)})
        rows.sort(key=lambda r: (r["if_index"], r["label"]))
        return rows

    # How often _poll_environment's whole-device ENTITY-SENSOR-MIB walk runs
    # per device. Six column walks cost what the LLDP/MAC walks do, so it
    # gets a cadence rather than the poll cycle; a temperature reading does
    # not change poll to poll the way an interface counter does. Fixed, not
    # a per-device column, and in memory only (see _sensor_read).
    #
    # Must stay well under alertengine's threshold_stale_s (900 s default):
    # a metric older than that reads as absent to a threshold rule, so a
    # slower cadence would flicker the temperature/humidity rules in and out
    # of "no data". PSU state is exempt from this cadence -- see
    # _poll_vendor_sensors, it is read on every poll.
    _SENSOR_REFRESH_S = 300.0

    # How long a device that answered no sensor table waits before being
    # asked again. sensor_capable used to latch 0 forever, which was wrong
    # once a second table existed: a Cisco switch latched incapable before
    # ever being identified as Cisco would never get offered the Cisco
    # table at all. An hour bounds how long that mistake can last.
    _SENSOR_REPROBE_S = 3600.0

    # psu_state for a bay seen before that now reads not-present (>= 2 alerts).
    _PSU_STATE_ABSENT = 3.0

    # How often the published-threshold walk runs, against _SENSOR_REFRESH_S's
    # 300: a DOM reading changes every poll, but the levels a transceiver
    # publishes change only when somebody pulls the optic out of the cage.
    # Three extra column walks an hour on the switches that have optics is
    # the whole cost of per-port optic alerting.
    _SENSOR_THRESHOLD_REFRESH_S = 3600.0

    # The MIB these limits came out of, stored on every row so a second
    # vendor's walk one day replaces only its own. See
    # nodesdb.replace_interface_thresholds.
    _CISCO_THRESHOLD_SOURCE = "CISCO-ENTITY-SENSOR-MIB"

    # ARISTA-ENTITY-SENSOR-MIB publishes its own high-warning/high-critical
    # columns directly -- no severity/relation row to decode, unlike Cisco's
    # entSensorThresholdTable -- so its own source name and its own (much
    # shorter) walk in _poll_published_thresholds.
    _ARISTA_THRESHOLD_SOURCE = "ARISTA-ENTITY-SENSOR-MIB"

    # A published temperature limit outside this range did not come from a
    # sane sensor -- the same role _DBM_LIMIT_RANGE plays for optics, so a
    # scale error on a sensor reading Fahrenheit or millidegrees is caught
    # rather than alerting a switch at "high" 45000.
    _TEMP_LIMIT_RANGE = (0.0, 150.0)

    def _sfp_root_for(self, sensor_type: int, suffix: str, names, descrs
                      ) -> str | None:
        """The per-port DOM metric root (_SFP_METRICS) this sensor writes,
        or None for a row that is not one.

        dBm(14) says a reading is optical power but not which way the light
        is going, so its root comes from the sensor's own name; every other
        type answers from its type alone (_SFP_TYPE_ROOTS). Its own function
        because the threshold walk has to reach the same verdict for a
        sensor the reading loop went on to discard.
        """
        if sensor_type == self._SENSOR_TYPE_OPTICAL:
            direction = _optical_direction(
                str(names.get(suffix) or "") if names else "",
                str(descrs.get(suffix) or ""))
            return f"sfp_{direction}_dbm" if direction else None
        return self._SFP_TYPE_ROOTS.get(sensor_type)

    def _poll_published_thresholds(self, device_id: int, device, config: dict,
                                   threshold_roots: dict, scales: dict,
                                   precisions: dict, now: float) -> None:
        """The alarm/warning levels this device's own sensors publish, into
        nodes.db's interface_thresholds — see that table's schema comment,
        and alertrules.PUBLISHED_THRESHOLD_RULES for what reads them.

        Was _poll_optic_thresholds through 5.15.0, transceivers only;
        `threshold_roots` now also carries chassis-classified ENTITY-SENSOR
        temperature rows as `(entPhysicalIndex, "temp_sensor_c")` (see
        _poll_environment), so the same walk fills their high_warn/
        high_alarm with no extra request. A low-side band on a temperature
        sensor is written like any other column -- nothing here reads it,
        alertrules' rules for temp_sensor_c only look at the high side.

        `threshold_roots` maps a sensor's index suffix to the (index, metric
        root) it belongs to; the caller builds it from the walk it has
        already done, so this costs three column walks (Cisco) or two
        (Arista) and no re-walk of anything.

        Two independent publishers, each gated on its own vendor evidence so
        neither pays for a walk that could only time out on the other's
        gear: CISCO-ENTITY-SENSOR-MIB's entSensorThresholdTable (severity +
        relation decoded into a band and a side, same as always) on
        _cisco_sensor_table_plausible; ARISTA-ENTITY-SENSOR-MIB's own high-
        warning/high-critical columns, no decoding needed, on arc 30065.
        Gated again on this device having at least one entry in
        `threshold_roots` this pass, so routers, PDUs and copper-only
        switches never pay a dead walk an hour for ever.
        """
        if not threshold_roots:
            return
        is_cisco = self._cisco_sensor_table_plausible(device)
        arc = nodeoids.enterprise_arc(
            (device["sys_object_id"]
             if "sys_object_id" in (device.keys() if hasattr(device, "keys")
                                    else device) else "") or "")
        is_arista = arc == 30065
        if not is_cisco and not is_arista:
            return
        if now - self._sensor_threshold_read.get(device_id, 0.0) < \
                self._SENSOR_THRESHOLD_REFRESH_S:
            return
        self._sensor_threshold_read[device_id] = now

        # (index, root) -> {column: value}. Several entities can land on one
        # key -- a multi-lane optic reports a lane per entity -- and one
        # entity can quote the same band twice; both collapse the same way,
        # keeping whichever level alerts EARLIER.
        bands: dict[tuple, dict] = {}
        source = self._CISCO_THRESHOLD_SOURCE

        if is_cisco:
            try:
                values, complete = self._walk_column_status(
                    device, config, self._CISCO_THRESHOLD_VALUE)
                severities, sev_done = self._walk_column_status(
                    device, config, self._CISCO_THRESHOLD_SEVERITY)
                relations, rel_done = self._walk_column_status(
                    device, config, self._CISCO_THRESHOLD_RELATION)
            except SnmpError:
                return
            if not (complete and sev_done and rel_done):
                # Same doctrine as _sfp_slot_media's slots_complete, and it
                # matters more here: an empty answer means "this device
                # publishes nothing", which switches alerting OFF for every
                # sensor on it. A slow device must not be able to say that.
                # All three columns, because a severity row the walk never
                # reached loses its band and drops a level just as silently.
                # Said out loud, and retried on the next sensor pass: a
                # chassis whose walk keeps being cut short used to look
                # exactly like one that publishes no limits at all.
                short = [name for name, done in (("value", complete),
                                                 ("severity", sev_done),
                                                 ("relation", rel_done))
                         if not done]
                self._sensor_threshold_read[device_id] = (
                    now - self._SENSOR_THRESHOLD_REFRESH_S
                    + self._SENSOR_REFRESH_S)
                self._log_media_diag(
                    device, f"Published-threshold walk on {device['ip']} was "
                            f"cut short ({', '.join(short)} column); stored "
                            f"limits are kept and it is retried shortly",
                    "threshold_walk_short")
                return
            # target -> side -> the levels whose severity named no band.
            unbanded: dict[tuple, dict[str, list]] = {}
            for suffix, raw in values.items():
                entity, _, _index = suffix.partition(".")
                target = threshold_roots.get(entity)
                if target is None or not isinstance(raw, (int, float)):
                    continue
                side = self._CISCO_THRESHOLD_SIDE.get(
                    int(relations.get(suffix) or 0) or 0)
                band = self._CISCO_THRESHOLD_BAND.get(
                    int(severities.get(suffix) or 0) or 0)
                if side is None:
                    continue
                # The threshold is quoted in the scale and precision of ITS
                # OWN entity's reading, never the threshold row's index --
                # decoding one against another entity's scale is wrong by a
                # factor of a thousand and still looks like a plausible
                # figure.
                value = self._scaled_sensor_value(
                    raw, scales.get(entity), precisions.get(entity))
                if target[1] == "sfp_bias_ma":
                    # The reading loop above quotes bias in milliamps; a
                    # limit left in the MIB's amperes would be a thousand
                    # times the metric it governs.
                    value *= self._BIAS_A_TO_MA
                if band is None:
                    unbanded.setdefault(target, {}).setdefault(
                        side, []).append(value)
                    continue
                column = f"{side}_{band}"
                existing = bands.setdefault(target, {}).get(column)
                if existing is not None:
                    value = max(existing, value) if side == "low" \
                        else min(existing, value)
                bands[target][column] = value
            # entSensorThresholdSeverity other(1) names no band, and a
            # platform that publishes an optic's whole band that way used to
            # end with no limits at all. Two levels on one side say which is
            # which without it: the outer is the alarm, the inner the
            # warning. One level alone stays dropped -- guessing which of
            # the two it is would invent a limit the device never published.
            for target, sides in unbanded.items():
                if bands.get(target):
                    continue
                for side, levels in sides.items():
                    if len(levels) < 2:
                        continue
                    ordered = sorted(levels, reverse=(side == "high"))
                    columns = bands.setdefault(target, {})
                    columns[f"{side}_alarm"] = ordered[0]
                    columns[f"{side}_warn"] = ordered[1]
        else:
            source = self._ARISTA_THRESHOLD_SOURCE
            try:
                warns = self._walk_column(
                    device, config, nodeoids.ARISTA_SENSOR_THRESHOLD_WARN)
                alarms = self._walk_column(
                    device, config, nodeoids.ARISTA_SENSOR_THRESHOLD_ALARM)
            except SnmpError:
                return
            for column_name, column in (("high_warn", warns), ("high_alarm", alarms)):
                for suffix, raw in column.items():
                    target = threshold_roots.get(suffix)
                    if target is None or not isinstance(raw, (int, float)):
                        continue
                    value = self._scaled_sensor_value(
                        raw, scales.get(suffix), precisions.get(suffix))
                    bands.setdefault(target, {})[column_name] = value

        rows = []
        for (index, root), columns in sorted(bands.items()):
            if not self._published_band_sane(root, columns):
                self._log_sensor_diag(
                    device, f"{device['ip']} publishes {root} limits for "
                            f"index {index} that do not make sense "
                            f"together; they are ignored, so that sensor "
                            f"raises no threshold alerts")
                continue
            rows.append({"if_index": index, "metric_root": root,
                         "low_alarm": columns.get("low_alarm"),
                         "low_warn": columns.get("low_warn"),
                         "high_warn": columns.get("high_warn"),
                         "high_alarm": columns.get("high_alarm"),
                         "updated_ts": now})
        self.db.replace_interface_thresholds(device_id, source, rows)

    def _published_band_sane(self, root: str, columns: dict) -> bool:
        """Whether a published band is coherent enough to alert on.

        Was _optic_band_sane through 5.15.0; renamed once temp_sensor_c
        started sharing it. A partly-published band is fine and common
        (older IOS quotes an alarm and no warning); a band that contradicts
        itself is not, and the only honest thing to do with it is to alert
        on none of it. The range check is the one gate that can catch a
        scale misread, which is otherwise invisible: -14.4 and -14400 are
        both numbers, and so are 45 and 45000.
        """
        lows = [columns[c] for c in ("low_alarm", "low_warn") if c in columns]
        highs = [columns[c] for c in ("high_warn", "high_alarm") if c in columns]
        if root.endswith("_dbm"):
            floor, ceiling = self._DBM_LIMIT_RANGE
            if any(not floor <= v <= ceiling for v in lows + highs):
                return False
        if root == "temp_sensor_c":
            floor, ceiling = self._TEMP_LIMIT_RANGE
            if any(not floor <= v <= ceiling for v in lows + highs):
                return False
        if "low_alarm" in columns and "low_warn" in columns \
                and columns["low_alarm"] > columns["low_warn"]:
            return False
        if "high_alarm" in columns and "high_warn" in columns \
                and columns["high_alarm"] < columns["high_warn"]:
            return False
        return not any(low >= high for low in lows for high in highs)

    def _poll_environment(self, device_id: int, device, config: dict,
                          already: set, now: float) -> None:
        """Device-level temperature/humidity and per-port optic (DOM)
        readings from ENTITY-SENSOR-MIB (RFC 3433) — an environmental
        monitor, a switch's transceivers, or any device exposing its own
        chassis sensors through the standard MIB.

        A sensor is read whether or not it maps to a port; the mapping only
        decides WHICH key a temperature becomes, because 45 C is healthy on
        a chassis, ordinary on an SFP, and a warning in a comms closet. One
        "temp_c" key under one threshold rule alerts on all three:

        - temp_optic_c: the sensor maps to a port (_entity_port_map, the
          same resolution the two dialog reads use).
        - temp_ambient_c: unmapped, AND this device also answers a humidity
          sensor. A chassis essentially never does and a room monitor always
          does, on any vendor's arc — so this generalises past one vendor.
        - temp_chassis_c: everything else unmapped, and the deliberate
          default: a device that cannot be positively identified as an
          environmental monitor must not have its own warmth read as a room
          getting hot. Same key jnxOperatingTable uses, so a device
          answering both never reports two disagreeing temperatures.

        A port-mapped reading additionally becomes a per-port metric —
        `sfp_rx_dbm.<ifIndex>` and its four siblings (_SFP_METRICS) — so an
        alert rule can fire on the failing port rather than a device-wide
        worst-of; there is deliberately no device-level `sfp_*` key, since a
        chassis has no one true Rx power. The same mapping writes
        interfaces.media, rewritten only when the walk answered, so a
        timeout never strips the badge. interfaces.media also gains
        'copper' (5.25.0) for a BASE-T transceiver — module text
        (_sfp_slot_media) or MAU-MIB ifMauType (this method, below) — which
        outranks a DOM reading: a copper module's own temperature sensor is
        still recorded, it just does not make the port read as optical.

        Best-effort, gated twice: nothing runs inside the cadence window
        (_SENSOR_REFRESH_S normally, _SENSOR_REPROBE_S — a cheap hourly
        recheck — for a device that answered nothing), and
        devices.sensor_capable is the probe-once-remember memory
        _poll_poe/_poll_stp/_poll_ups_health also use. Capability is
        recorded only on a probe that learned something new: a device
        already confirmed capable that times out once must not be
        relabelled incapable.
        """
        capable = device["sensor_capable"]
        window = self._SENSOR_REPROBE_S if capable == 0 else self._SENSOR_REFRESH_S
        if now - self._sensor_read.get(device_id, 0.0) < window:
            return
        self._sensor_read[device_id] = now
        try:
            _source, cols, _tried, sensor_complete = self._walk_sensor_columns(device, config)
        except SnmpError:
            cols = {}
            sensor_complete = False
        if cols:
            if not capable:
                # Unproven or found-empty can still turn out capable later.
                self.db.set_sensor_capable(device_id, True)
            sensor_values = cols["values"]
            types = cols["types"]
            scales = cols["scales"]
            precisions = cols["precisions"]
            statuses = cols["statuses"]
            units = cols["units"]
        else:
            # No DOM answer still falls through: cages can be badge-worthy.
            if capable is None:
                self.db.set_sensor_capable(device_id, False)
            cage_capable = self._cage_capable.get(device_id)
            cage_due = now - self._cage_read.get(device_id, 0.0) >= self._SENSOR_REPROBE_S
            if not cage_capable and not cage_due:
                return
            self._cage_read[device_id] = now
            sensor_values = types = scales = precisions = statuses = units = {}

        descrs, descrs_done, descrs_reason = self._walk_column_detail(
            device, config, self._ENT_PHYSICAL_DESCR)
        interfaces = list(self.db.interfaces(device_id))
        media_reasons = [] if descrs_done else [
            f"entPhysicalDescr walk cut short ({descrs_reason})"]
        # The name fallback exists for Cisco gear with no alias rows; nothing
        # else should pay a whole entPhysicalName walk every cadence for it.
        # An incomplete walk must not read as proof a sensor is gone.
        names = if_by_name = None
        names_done = True
        if self._cisco_sensor_table_plausible(device):
            names, names_done, names_reason = self._walk_column_detail(
                device, config, self._ENT_PHYSICAL_NAME)
            if not names_done:
                media_reasons.append(f"entPhysicalName walk cut short ({names_reason})")
            if_by_name = self._if_index_by_name(interfaces)
        contained_in, contained_complete = self._entity_contained_in(device, config)
        port_map, alias_rows = self._entity_port_map(
            device, config, names, if_by_name, contained_in)
        if not port_map:
            if not alias_rows and not contained_in and contained_complete:
                self._cage_capable[device_id] = False
            # Diagnosed only with ENTITY-MIB data to map, so a plain host
            # never earns an event for a scan it was never going to answer.
            if alias_rows or contained_in:
                self._log_media_diag(
                    device, f"SFP scan on {device['ip']}: no entity mapped "
                            f"to a port — entAliasMappingIdentifier had "
                            f"{alias_rows} row(s), entPhysicalName matched "
                            f"no stored ifDescr", "no_entity_mapped")
            sfp_slots, slots_complete, sfp_mode, ent_models = {}, True, {}, {}
        else:
            (sfp_slots, slots_complete, class_rows, slot_reasons, sfp_mode,
             ent_models) = self._sfp_slot_media(
                device, config, port_map, contained_in, descrs)
            media_reasons.extend(slot_reasons)
            if class_rows:
                self._cage_capable[device_id] = True
            elif slots_complete:
                # A clean empty walk is the noSuchObject verdict; a cut-short one proves nothing.
                self._cage_capable[device_id] = False
        slots_complete = slots_complete and descrs_done and names_done
        if not slots_complete and media_reasons:
            for reason in media_reasons:
                # cause is the column name only: the row/dropped counts in
                # `reason` change every poll and would defeat the hourly key.
                self._log_media_diag(
                    device, f"SFP scan on {device['ip']}: {reason}, "
                            f"stored badges kept",
                    reason.split(" walk cut short", 1)[0])

        mau_copper_ports, mau_fiber_ports = self._read_mau_media(
            device, config, device_id, port_map, now)

        has_humidity = any(int(types.get(suffix) or 0) == self._SENSOR_TYPE_HUMIDITY
                           for suffix in sensor_values)

        optic_temps: list[float] = []
        ambient_temps: list[float] = []
        chassis_temps: list[float] = []
        humidities: list[float] = []
        # (ifIndex, metric root) -> readings seen. A multi-lane optic reports
        # one row per lane, so a port can have several of the same root.
        per_port: dict[tuple[int, str], list[float]] = {}
        optic_ports: set[int] = set()
        # Ports with an actual optical-power (dBm, type 14) sensor -- copper
        # text must not beat a real DOM reading. Subset of optic_ports.
        dbm_ports: set[int] = set()
        # Sensor index suffix -> the (index, root) its published limits
        # belong to. See _poll_published_thresholds.
        threshold_roots: dict[str, tuple] = {}
        # entPhysicalIndex -> reading, per chassis-classified temperature row;
        # also in threshold_roots since a chassis sensor publishes limits the same way.
        chassis_sensor_temps: dict[str, float] = {}
        # Sensor rows this poll read that resolved to no port at all --
        # diagnosed below only when port_map is non-empty (the device maps
        # SOME entities, just not these), so a UPS or room monitor with no
        # ports to map anything to is never flagged for it.
        unmapped_sensor_rows = 0
        for suffix, raw in sensor_values.items():
            sensor_type = int(types.get(suffix) or 0)
            try:
                entity = int(suffix)
            except ValueError:
                continue
            if_index = port_map.get(entity)
            if if_index is None:
                unmapped_sensor_rows += 1
            if if_index is not None:
                # A failed optic is still an optic: any sensor resolving to
                # a port is proof one is there, whatever it reads -- unless
                # copper proof (module text or MAU-MIB) overrides it below.
                optic_ports.add(if_index)
                if sensor_type == self._SENSOR_TYPE_OPTICAL:
                    dbm_ports.add(if_index)
            root = self._sfp_root_for(sensor_type, suffix, names, descrs)
            if if_index is not None and root is not None:
                # Recorded BEFORE the status filter below: a transceiver
                # reading nonoperational for one cadence still publishes the
                # same limits, and dropping them would switch that port's
                # optic alerting off and on again with it.
                threshold_roots[suffix] = (if_index, root)
            if sensor_type not in (self._SENSOR_TYPE_TEMPERATURE,
                                   self._SENSOR_TYPE_HUMIDITY,
                                   self._SENSOR_TYPE_OPTICAL) and root is None:
                continue
            reading = self._decode_entity_sensor(
                suffix, raw, types, scales, precisions, statuses, units, descrs)
            # A sensor reporting anything other than "ok" (unplugged,
            # failed, out of range) contributes nothing rather than a
            # bogus reading — an alert on a physical quantity is worth
            # nothing if it can silently be sourced from a dead probe.
            if reading is None or reading["status"] != "ok":
                continue
            value = reading["value"]
            if sensor_type == self._SENSOR_TYPE_HUMIDITY:
                humidities.append(value)
                continue
            if sensor_type == self._SENSOR_TYPE_TEMPERATURE:
                if if_index is not None:
                    optic_temps.append(value)
                elif has_humidity:
                    ambient_temps.append(value)
                else:
                    chassis_temps.append(value)
                    chassis_sensor_temps[suffix] = value
                    threshold_roots[suffix] = (entity, "temp_sensor_c")
            if if_index is None or root is None:
                continue
            if root == "sfp_bias_ma":
                value *= self._BIAS_A_TO_MA
            per_port.setdefault((if_index, root), []).append(value)

        if port_map and unmapped_sensor_rows:
            self._log_media_diag(
                device, f"SFP scan on {device['ip']}: "
                        f"{unmapped_sensor_rows} sensor row(s) mapped to no port",
                "unmapped_sensor_rows")

        self._poll_published_thresholds(device_id, device, config, threshold_roots,
                                        scales, precisions, now)

        # Worst (hottest/most humid) sensor of each kind wins — "the hot
        # spot is what matters", the same reasoning VENDOR_HEALTH's
        # column_max probes already use, applied per kind so an SFP
        # running warm never masks a genuinely hot chassis sensor or vice
        # versa.
        samples = []
        if optic_temps:
            samples.append(("temp_optic_c", "Optic temperature", "°C",
                            "gauge", now, max(optic_temps)))
        if ambient_temps:
            samples.append(("temp_ambient_c", "Ambient temperature", "°C",
                            "gauge", now, max(ambient_temps)))
        if chassis_temps and "temp_chassis_c" not in already:
            # `already` is what this poll's vendor-health pass produced —
            # a device with a better vendor-specific chassis reading
            # (Juniper's jnxOperatingTable) keeps it, and this only fills
            # in for one that has none, same as the pre-split code did.
            samples.append(("temp_chassis_c", "Chassis temperature", "°C",
                            "gauge", now, max(chassis_temps)))
        if humidities:
            samples.append(("humidity_pct", "Humidity", "%RH", "gauge", now,
                            max(humidities)))
        # Per-sensor chassis temperature, alongside the worst-of temp_chassis_c
        # above -- alertrules.SENSOR_FAMILIES treats temp_sensor_c.<idx> as a
        # child entity of its own, so a hot supervisor and a hot PSU alert
        # separately rather than one worst-of figure hiding the other.
        for suffix, value in sorted(chassis_sensor_temps.items()):
            label = (names.get(suffix) if names else None)                 or descrs.get(suffix) or f"Sensor {suffix}"
            samples.append((f"temp_sensor_c.{suffix}", f"{label} temperature",
                            "°C", "gauge", now, value))
        # Light levels take the LOWEST lane (the failing one on a multi-lane
        # optic is the dim one); everything else takes the highest, the same
        # "hot spot wins" rule the device keys above use.
        if_descrs = {row["if_index"]: row["descr"] for row in interfaces}
        for (if_index, root), values in sorted(per_port.items()):
            reading_name, unit = _SFP_METRICS[root]
            if root.endswith("_dbm"):
                # A dark lane is one with the light off, not a dim one, so it
                # must not win min() away from three healthy lanes on the same
                # optic. An optic dark on every lane still records the floor:
                # the port's chart stays continuous and its history stays
                # true. What that reading means for an ALERT is alertrules'
                # job, not this one's -- breaches() will not open one on it
                # and evaluate_threshold closes one already open.
                lit = [v for v in values if not is_dark_optic(root, v)]
                worst = min(lit) if lit else DARK_OPTIC_DBM
            else:
                worst = max(values)
            port = if_descrs.get(if_index) or f"if{if_index}"
            samples.append((f"{root}.{if_index}", f"{port} {reading_name}",
                            unit, "gauge", now, worst))
        if samples:
            self.db.record_metric_samples(device_id, samples)
        # A MAU copper arc only confirms a cage the entity scan found
        # occupied: a Catalyst answers 1000BASE-T for every fixed port too.
        mau_copper_ports &= ({i for i, m in sfp_slots.items()
                              if m in ("sfp", "copper")} | optic_ports)
        # Precedence: a fiber arc or a lit optic beats copper text; copper
        # beats optic (any port-mapped sensor); both beat the cage scan.
        copper_ports = ((
            {if_index for if_index, media in sfp_slots.items()
             if media == "copper"} | mau_copper_ports)
            - mau_fiber_ports - dbm_ports)
        media_by_if = {i: ("sfp" if m == "copper" and i in mau_fiber_ports else m)
                       for i, m in sfp_slots.items()}
        media_by_if.update({if_index: "optic" for if_index in optic_ports})
        media_by_if.update({if_index: "copper" for if_index in copper_ports})
        # optic_mode from _sfp_slot_media's cage/occupant scan covers most
        # ports; a DOM-lit port the cage scan never classified as a
        # container (optic_ports) gets its own scan here, over the same
        # entPhysicalModelName column that walk already fetched -- reusing
        # `ent_models` rather than walking it again.
        optic_mode_by_if: dict[int, str] = dict(sfp_mode)
        missing_mode = optic_ports - set(optic_mode_by_if)
        if missing_mode:
            by_descr = _int_keyed(descrs)
            entities_by_if: dict[int, list[int]] = {}
            for entity, idx in port_map.items():
                entities_by_if.setdefault(idx, []).append(entity)
            children: dict[int, list[int]] = {}
            for entity, parent in contained_in.items():
                children.setdefault(parent, []).append(entity)
            for if_index in missing_mode:
                # Own text first, then the cage's contents, then its
                # ancestors -- and only a text naming a transceiver may vote
                # at all, so a chassis/linecard/service-module model name up
                # the containment chain (e.g. "N9K-C93180YC-EX") can never
                # be mistaken for the DOM-lit port's own optic (F1, 5.36.0).
                texts = []
                for entity in sorted(entities_by_if.get(if_index, ())):
                    texts += [by_descr.get(entity), ent_models.get(entity)]
                    queue, depth = list(children.get(entity, ())), 0
                    while queue and depth < 4:
                        for child in queue:
                            texts += [by_descr.get(child), ent_models.get(child)]
                        queue = [c for parent in queue for c in children.get(parent, ())]
                        depth += 1
                    hop, seen = contained_in.get(entity, 0), 0
                    while hop and seen < 2:
                        texts += [by_descr.get(hop), ent_models.get(hop)]
                        hop = contained_in.get(hop, 0)
                        seen += 1
                transceiver_texts = [t for t in texts
                                     if t and _TRANSCEIVER_TEXT.search(str(t))]
                found_mode = _optic_mode(*transceiver_texts)
                if found_mode:
                    optic_mode_by_if[if_index] = found_mode
        if not slots_complete or not sensor_complete:
            # A walk cut short is not evidence of anything: a cage it never
            # reached reads as absent, and a module it never reached reads
            # as an empty cage, so the pass would strip or downgrade every
            # SFP/copper/optic badge on a device that is merely slow -- and
            # restore them next cadence, flickering the list every five
            # minutes. Only a port THIS poll's own sensors or MAU-MIB proved
            # is optic/copper may overwrite what is stored.
            for row in interfaces:
                stored = row["media"] if "media" in row.keys() else None
                if_index = row["if_index"]
                if (stored in ("sfp", "sfp_empty", "copper", "optic")
                        and if_index not in optic_ports
                        and if_index not in copper_ports):
                    media_by_if[if_index] = stored
                    stored_mode = row["optic_mode"] if "optic_mode" in row.keys() else None
                    if stored_mode:
                        optic_mode_by_if[if_index] = stored_mode
                    else:
                        optic_mode_by_if.pop(if_index, None)
                elif if_index in optic_ports and if_index not in optic_mode_by_if:
                    # A DOM-proven port (media already 'optic' this cycle)
                    # whose ENTITY walk was cut short before its mode text
                    # was reached keeps its stored mode rather than going
                    # NULL until the next full walk (F2, 5.36.0).
                    stored_mode = row["optic_mode"] if "optic_mode" in row.keys() else None
                    if stored_mode:
                        optic_mode_by_if[if_index] = stored_mode
        media_rows = [{"if_index": if_index, "media": media,
                       "optic_mode": (optic_mode_by_if.get(if_index)
                                      if media in ("sfp", "optic") else None)}
                      for if_index, media in sorted(media_by_if.items())]
        media_rows += [{"if_index": row["if_index"], "media": None, "optic_mode": None}
                       for row in interfaces
                       if row["if_index"] not in media_by_if
                       and ("media" in row.keys() and row["media"])]
        # An empty port map is a timed-out ENTITY-MIB walk, not a chassis
        # with no ports; keep the badges until a walk answers.
        if port_map:
            self.db.update_interface_media(device_id, media_rows)

    def _read_mau_media(self, device, config: dict, device_id: int, port_map: dict,
                        now: float) -> tuple[set[int], set[int]]:
        """MAU-MIB: the module text's copper proof, checked against the wire.
        Gated like the cage scan (empty port_map); probe-once-remember'd via
        _mau_read/_mau_capable at the hourly _SENSOR_REPROBE_S cadence."""
        mau_copper_ports: set[int] = set()
        mau_fiber_ports: set[int] = set()
        if port_map:
            mau_capable = self._mau_capable.get(device_id)
            due = now - self._mau_read.get(device_id, 0.0) >= self._SENSOR_REPROBE_S
            if mau_capable is not False or due:
                self._mau_read[device_id] = now
                raw_mau, mau_complete = self._walk_column_status(
                    device, config, nodeoids.IF_MAU_TYPE)
                if raw_mau:
                    self._mau_capable[device_id] = True
                    for suffix, value in raw_mau.items():
                        # ifMauType's value is a dot3MauType OID; reject
                        # anything not under that prefix before trusting
                        # its trailing arc as one.
                        text = str(value).lstrip(".")
                        if not text.startswith("1.3.6.1.2.1.26.4."):
                            continue
                        try:
                            if_index = int(str(suffix).split(".")[0])
                            arc = int(text.rsplit(".", 1)[-1])
                        except (TypeError, ValueError):
                            continue
                        if arc in _COPPER_MAU_ARCS:
                            mau_copper_ports.add(if_index)
                        elif arc in _FIBER_MAU_ARCS:
                            mau_fiber_ports.add(if_index)
                elif mau_complete and mau_capable is None:
                    # A clean empty walk (endOfMibView straight away, not a
                    # timeout) is the noSuchObject verdict: this device does
                    # not have the column, so stop asking every cadence.
                    self._mau_capable[device_id] = False
        return mau_copper_ports, mau_fiber_ports

    # ------------------------------------------------------------- PoE / STP

    @staticmethod
    def _last_index_component(suffix: str) -> int | None:
        """The trailing arc of a table-column suffix, as an int — PoE's
        pethPsePortIndex (see nodeoids' PoE block for why this is treated
        as an ifIndex directly)."""
        parts = suffix.split(".")
        if not parts:
            return None
        try:
            return int(parts[-1])
        except ValueError:
            return None

    def _poll_poe(self, device_id: int, device, config: dict) -> None:
        """POWER-ETHERNET-MIB: PSE budget/consumption and
        per-port admin/detection state, read every poll once the device is
        known to answer it.

        Probed at most once per device: devices.poe_capable is None until
        the first attempt, then True or False, so a device that does not
        implement PoE (the overwhelming majority of a fleet) pays for this
        walk exactly once, ever — not once per poll, and not once per
        process restart either, since the verdict is persisted rather than
        held in memory the way _bulk_repetitions/_credentials are. A device
        already known capable=False is skipped before sending anything.
        """
        capable = device["poe_capable"]
        if capable == 0:
            return
        try:
            pse_power = self._walk_column(device, config, nodeoids.PETH_MAIN_PSE_POWER)
        except SnmpError:
            pse_power = {}
        if not pse_power:
            # Nothing answered even the budget scalar: not a PSE. Recorded
            # only on the FIRST probe (capable is None) — a device that has
            # already been confirmed capable and simply timed out this poll
            # must not be relabeled incapable off one missed walk, the same
            # "a miss is not a verdict" rule read_device_mac_table's None
            # return already follows.
            if capable is None:
                self.db.set_poe_capable(device_id, False)
            return
        if capable is None:
            self.db.set_poe_capable(device_id, True)

        try:
            pse_consumption = self._walk_column(
                device, config, nodeoids.PETH_MAIN_PSE_CONSUMPTION)
        except SnmpError:
            pse_consumption = {}
        budget_w = sum(float(v) for v in pse_power.values()
                       if isinstance(v, (int, float)))
        now = time.time()
        samples = [("poe_budget_w", "PoE power budget", "W", "gauge", now, budget_w)]
        if pse_consumption:
            consumption_w = sum(float(v) for v in pse_consumption.values()
                                if isinstance(v, (int, float)))
            samples.append(("poe_consumption_w", "PoE power in use", "W",
                            "gauge", now, consumption_w))
        self.db.record_metric_samples(device_id, samples)
        self._bump("poe_polls")

        try:
            port_admin = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_ADMIN)
        except SnmpError:
            port_admin = {}
        try:
            port_detect = self._walk_column(device, config, nodeoids.PETH_PSE_PORT_DETECTION)
        except SnmpError:
            port_detect = {}
        try:
            port_power_mw = self._walk_column(device, config, nodeoids.CISCO_POE_PORT_POWER_MW)
        except SnmpError:
            port_power_mw = {}   # not a Cisco PSE, or the extension MIB isn't there

        rows: dict[int, dict] = {}
        for suffix, value in port_admin.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_admin"] = \
                nodeoids.PETH_PORT_ADMIN_ENUM.get(int(value))
        for suffix, value in port_detect.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_detect_status"] = \
                nodeoids.PETH_PORT_DETECTION_ENUM.get(int(value))
        for suffix, value in port_power_mw.items():
            if_index = self._last_index_component(suffix)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            rows.setdefault(if_index, {})["poe_power_mw"] = int(value)
        if rows:
            self.db.update_interface_poe(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

    def _stp_vlan_cadence_s(self, config: dict) -> float:
        """vlan_interval_s when set; the hourly sensor cadence when the VLAN
        membership walk is off. vlan_interval_s=0 only means "skip the
        membership walk" -- it was never a switch for PVST+ blocking
        detection, so that case must not silently go quiet too."""
        interval = float(config.get("vlan_interval_s") or 0)
        return interval if interval > 0 else self._SENSOR_REPROBE_S

    def _cached_bridge_port_map(self, device, config: dict, now: float) -> dict:
        """dot1dBasePortIfIndex, a static table, re-walked at
        _stp_vlan_cadence_s instead of on every poll like the rest of
        _poll_stp. An incomplete/empty walk is not cached, the same rule
        _vendor_psu_rows' own static cache follows. Also dropped early on a
        recorded reboot: IOS can renumber ifIndex across a reload, and the
        poll loop that detects that (poll_mixin.py) is not this cache's
        caller, so it is read back off device_events instead."""
        device_id = device["id"]
        cached = self._bridge_port_map_cache.get(device_id)
        if cached is not None:
            age = now - cached["ts"]
            if (age < self._stp_vlan_cadence_s(config)
                    and not self.db.device_events(
                        device_id, since_s=age, kinds=["rebooted"], limit=1)):
                return cached["map"]
            self._bridge_port_map_cache.pop(device_id, None)
        port_map = self._bridge_port_map(device, config)
        if port_map:
            self._bridge_port_map_cache[device_id] = {"map": port_map, "ts": now}
        return port_map

    def _apply_stp_vlan_latches(self, device_id: int, device, vlan_answered: bool) -> None:
        """stp_capable/stp_vlan_capable latch updates after any per-VLAN STP
        attempt, complete or cut short -- shared by _poll_stp's inline runs
        and _run_stp_vlan_pass's own cadence runs."""
        if device["stp_capable"] is None:
            self.db.set_stp_capable(device_id, bool(vlan_answered))
        if vlan_answered:
            if not device["stp_vlan_capable"]:
                self.db.set_stp_vlan_capable(device_id, True)
        elif device["stp_vlan_capable"] is None:
            self.db.set_stp_vlan_capable(device_id, False)

    def _stp_topology_changed(self, device_id: int, top_changes, time_since_change) -> bool:
        """True when dot1dStpTopChanges moved or dot1dStpTimeSinceTopology-
        Change reset since the last poll -- the signal that bypasses the
        per-VLAN walk's own cadence for an immediate refresh. A poll that
        read neither (a failed GET) does not overwrite what was last seen,
        so a change straddling one missed poll is still caught on the next."""
        prior = self._stp_topology_seen.get(device_id)
        if top_changes is not None or time_since_change is not None:
            self._stp_topology_seen[device_id] = (top_changes, time_since_change)
        if prior is None:
            return False
        prior_top, prior_since = prior
        if top_changes is not None and prior_top is not None and top_changes != prior_top:
            return True
        return (time_since_change is not None and prior_since is not None
                and time_since_change < prior_since)

    def _run_stp_vlan_pass(self, device, config: dict) -> tuple:
        """One Cisco per-VLAN STP walk (_cisco_vlan_stp): latches
        stp_capable/stp_vlan_capable and refreshes _stp_vlan_cache.
        _poll_stp stays the sole writer of interfaces.stp_state/
        stp_blocking_vlans/stp_vlan_count, on its own next poll, so a
        cadence-driven run here can never race a poll's own merge-and-write.

        Guard-free by design: the caller (either _poll_stp inline, holding
        _stp_vlan_running itself, or _run_stp_vlan_walk_job on its own
        cadence) owns _stp_vlan_running, so an inline trigger and a due
        cadence tick never run two 48-context walks against the same
        switch at once.
        """
        device_id = device["id"]
        cisco_v2c = (detected_vendor(device).lower() == "cisco"
                    and snmp_version_of(config) != 3 and bool(config.get("community")))
        if (not cisco_v2c or not config.get("stp_enabled", True)
                or device["stp_capable"] == 0):
            return {}, False, True
        port_map = self._cached_bridge_port_map(device, config, time.time())
        vlan_rows, vlan_answered, vlan_complete = self._cisco_vlan_stp(
            device, config, port_map)
        self._apply_stp_vlan_latches(device_id, device, vlan_answered)
        if vlan_complete:
            if vlan_rows:
                self._stp_vlan_cache[device_id] = {"rows": vlan_rows, "ts": time.time()}
            else:
                # Nothing to merge -- most often the per-VLAN contexts have
                # stopped answering at all (ACL/community change). A stale
                # cache must not go on overriding the fresh global read.
                self._stp_vlan_cache.pop(device_id, None)
        elif vlan_answered:
            self._log_media_diag(
                device, f"Per-VLAN STP scan on {device['ip']}: cut "
                        f"short, stored per-VLAN detail kept",
                "stp_vlan_cut_short")
        return vlan_rows, vlan_answered, vlan_complete

    def _run_stp_vlan_walk_job(self, device_id: int) -> None:
        """_run_stp_vlan_pass, off the poll pool on its own cadence -- the
        _mac_executor entry point _maybe_walk_stp_vlan/_walk_now submit.
        Re-fetches the device's working credential itself (the one it
        actually answers on, not just its profile's primary) since this
        runs well after whatever poll last had cred_config in hand."""
        try:
            device = self.db.device(device_id)
            if device is None:
                return
            if detected_vendor(device).lower() != "cisco" or device["stp_capable"] == 0:
                # _walk_now queues this for every device, so gate here too:
                # working_config() below can probe credentials on the wire.
                return
            config = self.working_config(device)
            self._run_stp_vlan_pass(device, config)
        except Exception:
            self._bump("errors")
            self.log.add(ERROR, f"Per-VLAN STP walk failed for device #{device_id}",
                         detail=traceback.format_exc())
        finally:
            with self._lock:
                self._stp_vlan_running.discard(device_id)

    def _poll_stp(self, device_id: int, device, config: dict) -> None:
        """BRIDGE-MIB dot1dStp: bridge-wide spanning-tree state
        every poll once the device is known to be a bridge, plus per-port
        state joined onto the SAME bridge-port -> ifIndex map the MAC table
        walk already resolves (_bridge_port_map) — dot1dStpPort IS
        dot1dBasePort, so there is no separate index guess to make here the
        way PoE's port-index assumption is. Probed once, same capability
        memory as PoE — see devices.stp_capable and _poll_poe's docstring.
        """
        capable = device["stp_capable"]
        if capable == 0:
            return
        try:
            response = self._snmp_get(device, config, [
                nodeoids.DOT1D_STP_PROTOCOL_SPEC, nodeoids.DOT1D_STP_PRIORITY,
                nodeoids.DOT1D_STP_TIME_SINCE_CHANGE, nodeoids.DOT1D_STP_TOP_CHANGES,
                nodeoids.DOT1D_STP_DESIGNATED_ROOT, nodeoids.DOT1D_STP_ROOT_COST,
                nodeoids.DOT1D_STP_ROOT_PORT])
            values = {vb["oid"]: vb for vb in response.varbinds}
        except SnmpError:
            values = {}

        def num(oid):
            vb = values.get(oid)
            if vb is None or vb["type"] in ("noSuchObject", "noSuchInstance",
                                            "endOfMibView", "null"):
                return None
            return vb["value"] if isinstance(vb["value"], (int, float)) else None

        cisco_v2c = (detected_vendor(device).lower() == "cisco"
                     and snmp_version_of(config) != 3 and bool(config.get("community")))

        protocol_spec_n = num(nodeoids.DOT1D_STP_PROTOCOL_SPEC)
        if protocol_spec_n is None and not cisco_v2c:
            # Same "a miss on the first probe is a verdict, a miss later is
            # just a miss" rule _poll_poe follows.
            if capable is None:
                self.db.set_stp_capable(device_id, False)
            return

        # Hoisted out of the branch below: a pure-PVST+ device -- the whole
        # reason the per-VLAN pass exists -- has no default-context scalars
        # at all, so gating this on protocol_spec_n being present would
        # leave the trigger permanently dead on exactly those devices.
        time_since_change = num(nodeoids.DOT1D_STP_TIME_SINCE_CHANGE)
        top_changes = num(nodeoids.DOT1D_STP_TOP_CHANGES)
        topology_changed = self._stp_topology_changed(
            device_id, top_changes, time_since_change)

        if protocol_spec_n is not None:
            if capable is None:
                self.db.set_stp_capable(device_id, True)
                capable = True

            priority = num(nodeoids.DOT1D_STP_PRIORITY)
            root_cost = num(nodeoids.DOT1D_STP_ROOT_COST)
            root_port = num(nodeoids.DOT1D_STP_ROOT_PORT)
            root_vb = values.get(nodeoids.DOT1D_STP_DESIGNATED_ROOT)
            root_id = (str(root_vb["value"])
                      if root_vb and root_vb["type"] not in
                      ("noSuchObject", "noSuchInstance", "endOfMibView", "null")
                      else None)

            self.db.update_stp_bridge(
                device_id,
                protocol_spec=nodeoids.DOT1D_STP_PROTOCOL_SPEC_ENUM.get(
                    int(protocol_spec_n), str(int(protocol_spec_n))),
                priority=int(priority) if priority is not None else None,
                root_id=root_id,
                root_cost=int(root_cost) if root_cost is not None else None,
                root_port=int(root_port) if root_port is not None else None,
                time_since_change_s=(time_since_change / 100.0
                                     if time_since_change is not None else None))
            self._bump("stp_polls")
            if top_changes is not None:
                # A cumulative counter, stored as a gauge sample the same way
                # dot1dStpTopChanges' RFC-defined semantics are — the future
                # alerting wave rules on it *increasing* between samples
                # (series()), not on any single reading, so no rate math
                # belongs here.
                self.db.record_metric_samples(device_id, [
                    ("stp_topology_changes", "STP topology changes", "count",
                     "gauge", time.time(), float(top_changes))])

        try:
            port_state = self._walk_column(device, config, nodeoids.DOT1D_STP_PORT_STATE)
        except SnmpError:
            port_state = {}
        now = time.time()
        port_map = (self._cached_bridge_port_map(device, config, now)
                   if (port_state or cisco_v2c) else {})
        rows: dict[int, dict] = {}
        for suffix, value in port_state.items():
            try:
                bridge_port = int(suffix)
            except ValueError:
                continue
            if_index = port_map.get(bridge_port)
            if if_index is None or not isinstance(value, (int, float)):
                continue
            state = nodeoids.DOT1D_STP_PORT_STATE_ENUM.get(int(value))
            if state is not None:
                rows[if_index] = {"stp_state": state}

        # Per-VLAN pass (see _cisco_vlan_stp), the only source of state for a
        # PVST+ device whose default context has no dot1dStp scalars at all.
        # Walked on its own cadence (_maybe_walk_stp_vlan) rather than every
        # poll; run inline here only on a device's first-ever sighting or a
        # topology-change trigger, so this merge always has an answer to
        # apply without paying for a fresh walk on every single poll.
        skip_interface_update = False
        if cisco_v2c:
            if device_id not in self._stp_vlan_seen or topology_changed:
                # Take _stp_vlan_running ourselves rather than assume it is
                # free: a due cadence tick (_maybe_walk_stp_vlan) can be
                # running the same 48-context walk on _mac_executor right
                # now. If it already holds the guard, this poll just merges
                # whatever is cached instead of racing it.
                took_guard = False
                with self._lock:
                    if device_id not in self._stp_vlan_running:
                        self._stp_vlan_running.add(device_id)
                        took_guard = True
                if took_guard:
                    try:
                        # Refetch: the scalar block above may have just
                        # written stp_capable this same poll, and `device`
                        # (handed in by the caller) still predates that.
                        fresh_device = self.db.device(device_id) or device
                        _, vlan_answered, vlan_complete = self._run_stp_vlan_pass(
                            fresh_device, config)
                    finally:
                        with self._lock:
                            self._stp_vlan_running.discard(device_id)
                    if vlan_complete:
                        # Only a complete attempt counts as "seen" -- a
                        # cut-short one is retried inline next poll instead
                        # of waiting out the whole cadence.
                        self._stp_vlan_seen.add(device_id)
                    if vlan_answered and not vlan_complete:
                        # SFP badge scan's own cut-short rule: keep what is
                        # stored — the global read is skipped too, so a
                        # blocked uplink doesn't flap to forwarding here.
                        skip_interface_update = True
            cached = self._stp_vlan_cache.get(device_id)
            stale = cached and now - cached["ts"] >= 2 * self._stp_vlan_cadence_s(config)
            if cached and not skip_interface_update and not stale:
                for if_index, detail in cached["rows"].items():
                    blocking = detail["blocking"]
                    states = detail.get("states", set())
                    row = rows.setdefault(if_index, {})
                    if blocking:
                        row["stp_state"] = "blocking"
                    elif "forwarding" in states:
                        row["stp_state"] = "forwarding"
                    elif len(states) == 1:
                        row["stp_state"] = next(iter(states))
                    elif "stp_state" in row:
                        pass
                    elif states:
                        row["stp_state"] = min(states)
                    row["stp_blocking_vlans"] = ",".join(sorted(blocking, key=int))
                    row["stp_vlan_count"] = detail["vlans"]

        if rows and not skip_interface_update:
            self.db.update_interface_stp(
                device_id, [{"if_index": i, **fields} for i, fields in rows.items()])

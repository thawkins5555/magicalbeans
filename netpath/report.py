"""Availability, top-N-saturation and firmware-inventory reports, read-only from
history nodesdb.py/alertsdb.py already keep (device_events, samples_hourly,
maintenance_windows, mutes, device_maintenance). A history gap is not
necessarily downtime: it is clipped to the device's created_ts, excluded
where a maintenance window, a maintenance-mode period or a still-active
mute covers it, and flagged (not hidden) past GAP_FLAG_S in case it was
really a stopped poller rather than a quiet, healthy device.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field

from netpath.analysis import clamp_window

# A segment longer than this with no transition inside it is flagged rather
# than trusted outright — it might be a stopped poller, not a quiet device.
# Well past any shipped poll_interval_s, so a normal poll cycle never trips it.
GAP_FLAG_S = 3 * 3600.0

# Bounds how much of a gap an ad-hoc mute can retroactively explain (matches
# alertsdb.MAX_MUTE_HOURS' one-day ceiling without a hard import dependency).
MUTE_HISTORY_CAVEAT = (
    "ad-hoc device mutes are deleted once they expire, so only a mute "
    "still active when this report ran could be excluded; a mute that "
    "had already lapsed reads as ordinary down time"
)

# Maintenance MODE, unlike a mute, keeps its closed periods on file — which
# is what lets a past period be subtracted at all. They are not kept
# forever: prune() ages a CLOSED period out on the alert retention, so a
# report reaching further back than that reads those seconds as ordinary
# down time. An OPEN period is never pruned at any age.
MAINTENANCE_MODE_HISTORY_CAVEAT = (
    "closed maintenance-mode periods age out on the alert retention, so a "
    "period that ended longer ago than that reads as ordinary down time; a "
    "period still open is always excluded"
)

_WEEK_S = 7 * 86400.0
# Guards _window_occurrences against a pathological or hand-edited window
# row (recurrence weekly, duration far below a week, spanning a huge
# window) rather than trusting MAX_WINDOW_DAYS/add_window's own validation
# to have been the only path a row was ever created through.
_MAX_OCCURRENCES = 10_000


# ------------------------------------------------------------- intervals

def _merge_intervals(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """The union of possibly-overlapping [start, end) pairs, so a stretch
    covered by both a maintenance window and a mute at once is not
    subtracted twice."""
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [list(ordered[0])]
    for lo, hi in ordered[1:]:
        if lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def _interval_total(intervals: list[tuple[float, float]]) -> float:
    return sum(hi - lo for lo, hi in intervals)


def _window_occurrences(row, seg_start: float, seg_end: float) -> list[tuple[float, float]]:
    """The [start, end) sub-intervals of one maintenance_windows row that
    overlap [seg_start, seg_end) — one for a one-off window, one per week
    for a 'weekly' one within the span. Mirrors alertsdb.is_window_active's
    arithmetic (same duration, same modulo), generalised from "is this row
    covering instant now" to "every occurrence overlapping this span",
    which a retrospective report needs and the live alert-gating code
    never did."""
    duration = row["end_ts"] - row["start_ts"]
    if duration <= 0 or seg_end <= seg_start:
        return []
    if row["recurrence"] != "weekly":
        lo, hi = max(seg_start, row["start_ts"]), min(seg_end, row["end_ts"])
        return [(lo, hi)] if hi > lo else []
    if seg_start <= row["start_ts"]:
        k = 0
    else:
        # Step one occurrence earlier than the naive division: the
        # occurrence that STARTED before seg_start can still be running
        # when it reaches seg_start.
        k = max(0, int((seg_start - row["start_ts"]) // _WEEK_S) - 1)
    overlaps = []
    seen = 0
    while seen < _MAX_OCCURRENCES:
        occ_start = row["start_ts"] + k * _WEEK_S
        if occ_start >= seg_end:
            break
        occ_end = occ_start + duration
        lo, hi = max(seg_start, occ_start), min(seg_end, occ_end)
        if hi > lo:
            overlaps.append((lo, hi))
        k += 1
        seen += 1
    return overlaps


def _window_scope_matches(row, device_id: str, device_group_id) -> bool:
    """The same test AlertsDatabase._window_scope_matches makes, reproduced
    rather than called: that method is private to a class this module does
    not want a hard, cross-module dependency on for one nine-line check,
    and duplicating a pure, four-line-bodied predicate is a smaller risk
    than reaching into another module's underscored method."""
    if row["scope_kind"] == "group":
        return (device_group_id is not None and row["scope_group_id"] is not None
                and int(device_group_id) == int(row["scope_group_id"]))
    try:
        ids = json.loads(row["scope_device_ids"] or "[]")
    except (TypeError, ValueError):
        return False
    return device_id in {str(i) for i in ids}


# --------------------------------------------------------------- outages

@dataclass
class Outage:
    start_ts: float
    end_ts: float
    raw_duration_s: float
    net_duration_s: float          # raw_duration_s minus maintenance/mute overlap
    excluded_s: float               # raw_duration_s - net_duration_s
    truncated_start: bool           # device was already down when the window opened
    ongoing: bool                   # still down at the window's end, no recovery seen


@dataclass
class DeviceAvailability:
    device_id: int
    name: str
    ip: str
    requested_start: float
    requested_end: float
    effective_start: float
    effective_end: float
    excluded_before_created_s: float
    up_s: float = 0.0
    down_s: float = 0.0                 # net of maintenance/mute exclusion
    unsupported_s: float = 0.0
    auth_s: float = 0.0
    unknown_s: float = 0.0
    maintenance_excluded_s: float = 0.0
    # Its own bucket, merged into neither of its neighbours: the CSV is read
    # to answer who took a device out of service and by which mechanism, and
    # folding two of them together is unrecoverable.
    maintenance_mode_excluded_s: float = 0.0
    mute_excluded_s: float = 0.0
    availability_pct: float | None = None
    outage_count: int = 0
    longest_outage_s: float = 0.0
    mttr_s: float | None = None
    still_down: bool = False
    currently_disabled: bool = False
    outages: list[Outage] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AvailabilityReport:
    requested_start: float
    requested_end: float
    generated_ts: float
    global_caveats: list[str]
    devices: list[DeviceAvailability]

    def to_dict(self) -> dict:
        return {"requested_start": self.requested_start,
                "requested_end": self.requested_end,
                "generated_ts": self.generated_ts,
                "global_caveats": self.global_caveats,
                "devices": [d.to_dict() for d in self.devices]}


def device_availability_report(nodesdb, device_ids: list[int], t0: float, t1: float,
                               *, alertsdb=None, now: float | None = None
                               ) -> AvailabilityReport:
    """Availability, outage count, total downtime, longest outage and MTTR
    for each of `device_ids` over [t0, t1]. `alertsdb` is optional — without
    it, `caveats` says maintenance/mute exclusion was skipped rather than
    pretending it ran and found nothing to exclude."""
    t0, t1 = clamp_window(t0, t1)
    now = time.time() if now is None else now
    global_caveats = [MUTE_HISTORY_CAVEAT, MAINTENANCE_MODE_HISTORY_CAVEAT]
    if alertsdb is None:
        global_caveats.append(
            "no alerts database was supplied: maintenance-window, "
            "maintenance-mode and mute exclusion were all three skipped, so "
            "down_s includes any time a maintenance window, an indefinite "
            "maintenance-mode period or a still-active mute would otherwise "
            "have excluded")

    # Loaded once, outside the per-device loop: a real deployment has a
    # handful of maintenance windows and a handful of active mutes at a
    # time (alertsdb.py's own reasoning for active_windows()), so this is
    # cheap regardless of how many devices are being reported on, and
    # every device below can be checked against the same in-memory lists
    # instead of re-querying alertsdb per device.
    windows = alertsdb.windows() if alertsdb is not None else []
    mute_by_entity = ({row["entity_id"]: row for row in alertsdb.mutes("device")}
                      if alertsdb is not None else {})
    maintenance_by_device = (alertsdb.maintenance_periods(t0, t1)
                             if alertsdb is not None else {})

    results: list[DeviceAvailability] = []
    for device_id in device_ids:
        row = nodesdb.device(device_id)
        if row is None:
            results.append(DeviceAvailability(
                device_id=device_id, name="", ip="",
                requested_start=t0, requested_end=t1,
                effective_start=t0, effective_end=t0,
                excluded_before_created_s=0.0,
                caveats=["no such device"]))
            continue

        created_ts = float(row["created_ts"] or t0)
        effective_start = max(t0, created_ts)
        excluded_before_created = max(0.0, effective_start - t0)
        report = DeviceAvailability(
            device_id=device_id, name=row["name"] or row["ip"], ip=row["ip"],
            requested_start=t0, requested_end=t1,
            effective_start=effective_start, effective_end=t1,
            excluded_before_created_s=excluded_before_created,
            currently_disabled=not bool(row["enabled"]))
        if excluded_before_created > 0:
            report.caveats.append(
                f"device created at {created_ts:.0f}, {excluded_before_created:.0f}s "
                f"of the requested window predates it and is excluded entirely")
        if report.currently_disabled:
            report.caveats.append(
                "device is currently disabled; this describes its polled "
                "history, not a claim about current monitoring status — "
                "there is no record of WHEN it was disabled, so a past "
                "disabled period inside the window cannot be excluded")
        if effective_start >= t1:
            report.caveats.append("effective window is empty")
            results.append(report)
            continue

        mute_row = mute_by_entity.get(str(device_id))
        maint_mode_periods = maintenance_by_device.get(str(device_id), ())
        applicable_windows = [w for w in windows
                              if _window_scope_matches(w, str(device_id),
                                                        row["device_group_id"])]

        segments = nodesdb.device_status_segments(device_id, effective_start, t1)
        for index, seg in enumerate(segments):
            seg_start, seg_end = seg["ts_start"], seg["ts_end"]
            duration = seg_end - seg_start
            status = seg["status"]

            if duration > GAP_FLAG_S:
                report.caveats.append(
                    f"{status} from {seg_start:.0f} to {seg_end:.0f} "
                    f"({duration:.0f}s) with no transition inside it — "
                    f"longer than {GAP_FLAG_S:.0f}s carries the last known "
                    f"status forward across the gap rather than confirming "
                    f"it; corroborate against a stopped poller before "
                    f"trusting this stretch")

            if status == "up":
                report.up_s += duration
                continue

            excluded_intervals: list[tuple[float, float]] = []
            maint_intervals: list[tuple[float, float]] = []
            for w in applicable_windows:
                maint_intervals.extend(_window_occurrences(w, seg_start, seg_end))
            mute_intervals: list[tuple[float, float]] = []
            if mute_row is not None:
                lo = max(seg_start, mute_row["created_ts"])
                hi = min(seg_end, mute_row["until_ts"])
                if hi > lo:
                    mute_intervals.append((lo, hi))

            mode_intervals: list[tuple[float, float]] = []
            for period in maint_mode_periods:
                # An OPEN period is clamped to `now`, NOT to the segment's
                # end: clamp_window can hand this report a t1 in the future,
                # and excluding time that has not happened yet would subtract
                # it from downtime and inflate uptime.
                end = period["ended_ts"] if period["ended_ts"] is not None else now
                lo = max(seg_start, period["started_ts"])
                hi = min(seg_end, end)
                if hi > lo:
                    mode_intervals.append((lo, hi))

            maint_merged = _merge_intervals(maint_intervals)
            mute_merged = _merge_intervals(mute_intervals)
            mode_merged = _merge_intervals(mode_intervals)
            report.maintenance_excluded_s += _interval_total(maint_merged)
            report.mute_excluded_s += _interval_total(mute_merged)
            report.maintenance_mode_excluded_s += _interval_total(mode_merged)
            # One union across all three, so seconds two mechanisms both
            # cover are subtracted from downtime once while each bucket
            # still reports its own coverage in full.
            excluded_intervals = _merge_intervals(
                maint_intervals + mute_intervals + mode_intervals)
            excluded_s = min(duration, _interval_total(excluded_intervals))
            net = duration - excluded_s

            if status == "down":
                # "Already down when the window opened" is true whenever
                # this is the very first segment AND it is a down segment —
                # device_status_segments always starts its first segment at
                # effective_start, so there is no other way to tell "we
                # walked in on an outage already in progress" apart from
                # "the down status did not begin with an observed
                # transition inside [t0, t1]", which is exactly this.
                truncated_start = index == 0
                ongoing = (index == len(segments) - 1 and seg_end >= t1)
                if net > 0:
                    report.outage_count += 1
                    report.longest_outage_s = max(report.longest_outage_s, net)
                    report.outages.append(Outage(
                        start_ts=seg_start, end_ts=seg_end,
                        raw_duration_s=duration, net_duration_s=net,
                        excluded_s=excluded_s, truncated_start=truncated_start,
                        ongoing=ongoing))
                report.down_s += net
                if ongoing:
                    report.still_down = True
            elif status == "unsupported":
                report.unsupported_s += net
            elif status == "auth":
                report.auth_s += net
            else:
                report.unknown_s += net

        recovered = [o for o in report.outages
                    if not o.truncated_start and not o.ongoing]
        if recovered:
            report.mttr_s = sum(o.net_duration_s for o in recovered) / len(recovered)

        denom = report.up_s + report.down_s
        report.availability_pct = 100.0 * report.up_s / denom if denom > 0 else None
        if denom <= 0:
            report.caveats.append(
                "no up or down time observed in the effective window — "
                "availability_pct is not computable, not zero")

        results.append(report)

    return AvailabilityReport(requested_start=t0, requested_end=t1,
                              generated_ts=now, global_caveats=global_caveats,
                              devices=results)


# ---------------------------------------------------------------- top-N

@dataclass
class MetricRank:
    device_id: int
    device_name: str
    device_ip: str
    metric_id: int
    key: str
    label: str
    unit: str
    if_index: int | None
    peak: float | None
    mean: float | None
    n_hours: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TopMetricReport:
    key: str
    like: bool
    t0: float
    t1: float
    rank_by: str
    ascending: bool
    generated_ts: float
    query_ms: float
    rows: list[MetricRank]

    def to_dict(self) -> dict:
        return {"key": self.key, "like": self.like, "t0": self.t0, "t1": self.t1,
                "rank_by": self.rank_by, "ascending": self.ascending,
                "generated_ts": self.generated_ts, "query_ms": self.query_ms,
                "rows": [r.to_dict() for r in self.rows]}


def _if_index(key: str) -> int | None:
    """The trailing `.N` off a per-interface metric key (`if_in_util_pct.7`
    -> 7), or None for a device-level key (`cpu_pct`) — nodepoll.py's own
    `f"if_{suffix}.{if_index}"` convention, read back rather than guessed."""
    if "." not in key:
        return None
    tail = key.rsplit(".", 1)[1]
    return int(tail) if tail.isdigit() else None


def _model_hint(sys_descr: str) -> str:
    """A short model-ish hint off sysDescr, for a report row that has to fit
    on a line: the first clause, capped. Never parsed into a model number —
    a description is not a model, and pretending otherwise on eleven vendors'
    string formats is exactly the invention swversion.py refuses to make."""
    text = " ".join((sys_descr or "").split())
    if not text:
        return ""
    head = re.split(r"[,;]", text, maxsplit=1)[0].strip()
    return head[:80]


@dataclass
class FirmwareRow:
    device_id: int
    name: str
    ip: str
    vendor: str
    model_hint: str
    sw_version: str
    sw_image: str
    sw_image_file: str
    last_poll_ts: float | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirmwareReport:
    generated_ts: float
    device_count: int
    version_count: int          # distinct non-empty sw_version values
    unknown_count: int          # devices with no version on file at all
    rows: list[FirmwareRow]

    def to_dict(self) -> dict:
        return {"generated_ts": self.generated_ts,
                "device_count": self.device_count,
                "version_count": self.version_count,
                "unknown_count": self.unknown_count,
                "rows": [r.to_dict() for r in self.rows]}


def firmware_inventory(nodesdb, device_ids: list[int] | None = None
                       ) -> FirmwareReport:
    """What every device is running, from the columns the identity poll
    already stores (nodepoll._poll_software_version) — no SNMP, no history.
    `device_ids` narrows it; omitted, the whole fleet is reported on.

    Sorted by vendor then version so a fleet groups itself into "these
    forty are on 15.2(7)E4 and these three are not". A device with no
    version on file is still a row: "which of my switches has never told me
    what it runs" is the other half of the question this answers."""
    rows_in = (nodesdb.devices_by_ids(sorted(set(device_ids)))
               if device_ids is not None else nodesdb.devices())
    rows: list[FirmwareRow] = []
    for row in rows_in:
        keys = row.keys()
        rows.append(FirmwareRow(
            device_id=row["id"], name=row["name"] or row["ip"], ip=row["ip"],
            vendor=row["vendor"] or "",
            model_hint=_model_hint(row["sys_descr"] or ""),
            sw_version=(row["sw_version"] or "") if "sw_version" in keys else "",
            sw_image=(row["sw_image"] or "") if "sw_image" in keys else "",
            sw_image_file=(row["sw_image_file"] or "") if "sw_image_file" in keys else "",
            last_poll_ts=row["last_poll_ts"]))
    # A device with no version sorts last within its vendor rather than
    # first, where an empty string would put it: the rows worth reading are
    # the ones that answered.
    rows.sort(key=lambda r: (r.vendor.lower(), not r.sw_version,
                             r.sw_version.lower(), r.name.lower()))
    versions = {r.sw_version for r in rows if r.sw_version}
    return FirmwareReport(
        generated_ts=time.time(), device_count=len(rows),
        version_count=len(versions),
        unknown_count=sum(1 for r in rows if not r.sw_version), rows=rows)


def top_metric_ranking(nodesdb, key: str, t0: float, t1: float, *,
                       n: int = 20, rank_by: str = "peak",
                       ascending: bool = False, like: bool = False,
                       device_ids: list[int] | None = None
                       ) -> TopMetricReport:
    """The top (or bottom) `n` metric series by peak or mean value over
    [t0, t1], read from samples_hourly (never samples — a raw scan would not
    finish at fleet scale). `query_ms` on the result is the wall-clock cost
    of the whole query, for a caller to watch on a wide/long request.
    """
    t0, t1 = clamp_window(t0, t1)
    h0 = int(t0 // 3600) * 3600
    h1 = int(t1 // 3600) * 3600

    started = time.perf_counter()
    # The aggregate is a nodes_series.db query since 5.0.0; the device names
    # it used to join to are a second, bounded read of nodes.db afterwards.
    agg_rows = nodesdb.series_db.metric_window_aggregates(
        key, h0, h1, like=like, device_ids=device_ids)
    query_ms = (time.perf_counter() - started) * 1000.0
    if not agg_rows:
        return TopMetricReport(key=key, like=like, t0=t0, t1=t1, rank_by=rank_by,
                               ascending=ascending, generated_ts=time.time(),
                               query_ms=query_ms, rows=[])
    devices = {row["id"]: row for row in nodesdb.devices_by_ids(
        sorted({arow["device_id"] for arow in agg_rows}))}

    rows: list[MetricRank] = []
    for arow in agg_rows:
        total_n = arow["total_n"] or 0
        mean = (arow["sum_avg_n"] / total_n) if total_n else None
        device = devices.get(arow["device_id"])
        device_ip = device["ip"] if device else ""
        device_name = (device["name"] if device else "") or device_ip
        rows.append(MetricRank(
            device_id=arow["device_id"], device_name=device_name,
            device_ip=device_ip, metric_id=arow["metric_id"], key=arow["key"],
            label=arow["label"], unit=arow["unit"], if_index=_if_index(arow["key"]),
            peak=arow["peak"], mean=mean, n_hours=arow["n_hours"]))

    # A metric with nothing in the window (an interface that came up after
    # t1, or that was never busy enough to round to non-NULL) is not "the
    # lowest value" — it is missing, and sorting it as zero would put a
    # brand-new, empty series at the bottom of a "least utilised" ranking
    # right alongside genuinely idle ones. So it is dropped before ranking
    # rather than sorted in, regardless of `ascending`.
    ranked = [r for r in rows if (r.peak if rank_by == "peak" else r.mean) is not None]
    ranked.sort(key=lambda r: r.peak if rank_by == "peak" else r.mean,
               reverse=not ascending)
    ranked = ranked[:n]

    return TopMetricReport(key=key, like=like, t0=t0, t1=t1, rank_by=rank_by,
                           ascending=ascending, generated_ts=time.time(),
                           query_ms=query_ms, rows=ranked)

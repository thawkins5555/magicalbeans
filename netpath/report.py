"""The two reports an operator is asked for by name every month, computed
from history the application was already keeping and answering to nobody:
how available was a device over some window, and which links came closest
to saturation.

Both read history that already exists — nodesdb.py's `device_events` (state
transitions) and `samples_hourly` (the year-scale rollup `analysis.py`'s
sibling module never reads) — and nothing here writes anything. This module
sits above nodesdb.py and alertsdb.py rather than inside either: it reaches
into their SQLite connections directly for the handful of aggregate queries
neither module exposes as public methods (see `_conn` below), rather than
adding methods to files someone else is editing this hour, and calls their
existing public methods — `device_status_segments`, `windows`, `mutes` —
for everything they already do correctly. If those aggregate queries earn
their place, the natural next step is promoting them to real methods on
`NodesDatabase`; that is a decision for whoever owns that file, not this one.

Why `device_status_segments` is the source of truth for "was it up", and
`devices.status`/`last_up_ts`/`last_down_ts` are not: the device row only
ever holds the CURRENT status and the timestamp of the most recent
transition into up or down. There is no column anywhere holding "how long
was it down last Tuesday" — that only exists as the sequence of `down`/`up`
rows in `device_events`, which `device_status_segments` (nodesdb.py:2676)
already turns into ordered, non-overlapping [start, end, status) segments
covering an arbitrary window. Building availability on anything else would
be building it on a snapshot, not a history.

Four ways a gap in that history is NOT the same as "the device was down",
and what this module actually does about each one — spelled out here
because getting this wrong is worse than not reporting it at all; an
availability figure that quietly counts the wrong things is exactly the
kind of number somebody puts in front of a manager and later has to
retract:

1. **The device did not exist yet.** `devices.created_ts` is exact and
   permanent, so the window used for each device is clipped to
   `[max(t0, created_ts), t1]` and how much was cut off is reported
   (`excluded_before_created_s`) rather than silently shrinking the
   window with no trace of it having happened.
2. **A maintenance window covered it.** `alertsdb.maintenance_windows`
   rows are never deleted by age — `windows()` returns "past, active and
   future" by its own docstring — so this is the one exclusion this module
   can compute with full retroactive accuracy for any window, including
   one from months ago. `is_window_active` (alertsdb.py:333) only answers
   "is this covering right now", so `_window_occurrences` below
   generalises the same arithmetic (including the weekly-recurrence
   modulo) to "which of this row's occurrences overlap an arbitrary past
   span" — every occurrence, not just the current one, since a month-long
   report can cross several weekly recurrences of the same window.
3. **The device was muted.** This is the one gap this module can only
   partly close, and that limitation is reported, not hidden.
   `alertsdb.purge_expired_mutes` DELETES an `alert_mutes` row once its
   `until_ts` passes — unlike a maintenance window, a mute that already
   lapsed before this report ran leaves no trace anywhere. So only a mute
   that is STILL active (its row still exists) can be excluded
   retroactively, using its own `created_ts`/`until_ts` as the covered
   span; a mute from three weeks ago that has since expired and been
   purged is invisible here, and its downtime — if it had any — reads as
   ordinary down time. `MUTE_HISTORY_CAVEAT` below is attached to every
   report so this is never missed by a reader who only looks at the
   numbers.
4. **The poller itself was stopped**, so nothing was being recorded for
   anyone, not just this device. `device_status_segments` cannot invent a
   down segment from silence — it only marks time "down" where a `down`
   event actually says so — so a poller outage cannot manufacture false
   down time here. What it CAN do is carry the last known status forward
   through a stretch where nothing happened, which silently assumes
   continuity ("it was up before, so it's still up") across a gap that
   might really have been a stopped poller rather than a boring, healthy
   month. Rather than build a fleet-wide silence detector — expensive
   over `samples_hourly` at scale, and still only ever a guess — every
   segment longer than `GAP_FLAG_S` is flagged in the device's own
   `caveats` with its span, so a reader can cross-check it against
   RUNBOOK.md's "The poller has stopped" section rather than trust the
   number blind.

Standard library only, same as everything else this application is built
from.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field

from netpath.analysis import clamp_window

# A segment (of any status) longer than this with no transition inside it
# is flagged rather than trusted outright — see point 4 above. Three hours
# is well past any shipped poll_interval_s (60-120s typical, and the
# down_after grace on top of that), so a real poll cycle running normally
# never trips it; a genuinely quiet, healthy device that just never changed
# state for a week WILL trip it, and that is the honest tradeoff of a
# constant threshold instead of a fleet-wide silence query — flagged, not
# hidden, costs nothing at report time either way.
GAP_FLAG_S = 3 * 3600.0

# Every ad-hoc mute this report can retroactively see is bounded by this —
# see point 3 above and alertsdb.MAX_MUTE_HOURS, which this deliberately
# does not import a hard dependency on beyond documenting the same number:
# a mute is never more than a day, so "the mute might explain more than a
# day of the gap" is never the right suspicion; "the mute already expired
# and was purged before this report ran" is the one that is often right.
MUTE_HISTORY_CAVEAT = (
    "ad-hoc device mutes are deleted once they expire, so only a mute "
    "still active when this report ran could be excluded; a mute that "
    "had already lapsed reads as ordinary down time"
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
    for each of `device_ids` over [t0, t1].

    `alertsdb` is optional so a caller — or a test — that only has a
    NodesDatabase still gets a correct report; without it, every device's
    `caveats` says plainly that maintenance/mute exclusion was skipped, and
    `down_s` includes every reason for the gap this module cannot resolve
    without one, rather than pretending the exclusion ran and finding
    nothing to exclude.
    """
    t0, t1 = clamp_window(t0, t1)
    now = time.time() if now is None else now
    global_caveats = [MUTE_HISTORY_CAVEAT]
    if alertsdb is None:
        global_caveats.append(
            "no alerts database was supplied: maintenance-window and mute "
            "exclusion were both skipped, so down_s includes any time a "
            "maintenance window or a still-active mute would otherwise "
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

            maint_merged = _merge_intervals(maint_intervals)
            mute_merged = _merge_intervals(mute_intervals)
            report.maintenance_excluded_s += _interval_total(maint_merged)
            report.mute_excluded_s += _interval_total(mute_merged)
            excluded_intervals = _merge_intervals(maint_intervals + mute_intervals)
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


def top_metric_ranking(nodesdb, key: str, t0: float, t1: float, *,
                       n: int = 20, rank_by: str = "peak",
                       ascending: bool = False, like: bool = False,
                       device_ids: list[int] | None = None
                       ) -> TopMetricReport:
    """The top (or bottom) `n` metric series by peak or mean value over
    [t0, t1] — "which twenty links came closest to saturation" is
    `key="if_in_util_pct.%", like=True, rank_by="peak"`; "which devices ran
    hottest" is `key="cpu_pct", rank_by="mean"`.

    Reads samples_hourly, never samples: three days of raw samples is not
    a month, and a raw scan at fleet scale would not finish (see the module
    docstring's sibling reasoning in analysis.py's own MAX_BUCKETS comment
    for the same "bound it here, don't trust the caller" instinct). One
    query, structured as a CTE rather than resolving candidate ids in
    Python first and passing them back as a giant `IN (...)` list — at
    fleet scale (2,000 devices x 48 ports is 96,000 candidate metrics for
    one interface-metric family) that list blows past SQLite's own bound
    parameter ceiling (`sqlite3.OperationalError: too many SQL variables`,
    hit while writing this against a 2,000-device benchmark — see
    tests/test_report_topn.py) well before it becomes a performance
    problem:

    1. `candidates`: `metrics` joined to `devices`, filtered by key/like
       and, optionally, `device_ids`. Small — one row per series, not one
       per hour — so `metrics.key` having no index of its own (only
       `UNIQUE(device_id, key)`, so this is a full scan of `metrics`) costs
       nothing next to step 2.
    2. `candidates` joined to `samples_hourly` on `metric_id`, filtered to
       the hour range, GROUP BY metric_id. `samples_hourly`'s primary key
       leads on metric_id, so SQLite can satisfy this as one index range
       scan per candidate metric rather than a scan of the whole rollup
       table — the difference this function exists to make, per the
       task's own instruction to read rollups, not raw samples, for a
       wide window.

    `query_ms` on the returned report is the wall-clock cost of the whole
    query, so a caller or a test can watch it rather than guess at it.
    """
    t0, t1 = clamp_window(t0, t1)
    h0 = int(t0 // 3600) * 3600
    h1 = int(t1 // 3600) * 3600
    conn: sqlite3.Connection = nodesdb._conn

    key_clause = "m.key LIKE ?" if like else "m.key = ?"
    params: list = [key]
    device_clause = ""
    if device_ids:
        marks = ",".join("?" * len(device_ids))
        device_clause = f" AND m.device_id IN ({marks})"
        params.extend(device_ids)
    params.extend([h0, h1])

    started = time.perf_counter()
    agg_rows = conn.execute(
        f"WITH candidates AS ("
        f" SELECT m.id AS metric_id, m.device_id, m.key, m.label, m.unit,"
        f" d.name AS device_name, d.ip AS device_ip"
        f" FROM metrics m JOIN devices d ON d.id = m.device_id"
        f" WHERE {key_clause}{device_clause})"
        f" SELECT c.metric_id, c.device_id, c.key, c.label, c.unit,"
        f" c.device_name, c.device_ip, MAX(sh.vmax) AS peak,"
        f" SUM(sh.vavg * sh.n) AS sum_avg_n, SUM(sh.n) AS total_n,"
        f" COUNT(*) AS n_hours"
        f" FROM candidates c JOIN samples_hourly sh ON sh.metric_id = c.metric_id"
        f" WHERE sh.hour >= ? AND sh.hour <= ? GROUP BY c.metric_id",
        params).fetchall()
    query_ms = (time.perf_counter() - started) * 1000.0
    if not agg_rows:
        return TopMetricReport(key=key, like=like, t0=t0, t1=t1, rank_by=rank_by,
                               ascending=ascending, generated_ts=time.time(),
                               query_ms=query_ms, rows=[])

    rows: list[MetricRank] = []
    for arow in agg_rows:
        total_n = arow["total_n"] or 0
        mean = (arow["sum_avg_n"] / total_n) if total_n else None
        rows.append(MetricRank(
            device_id=arow["device_id"], device_name=arow["device_name"] or arow["device_ip"],
            device_ip=arow["device_ip"], metric_id=arow["metric_id"], key=arow["key"],
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

"""Turn stored traces into the two things the UI draws: a path graph and a
status timeline."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import mean

# Ordered worst-last so max() picks the most severe status in a bucket.
# Worst-last, so max() picks the most severe status in a bucket. "blocked"
# ranks above "fail" because it is the more specific finding: silence tells you
# nothing, a refusal names the router and the reason.
# "overrun" sits above the network faults because it is a measurement fault:
# whatever the path was doing, this slot produced no data and the schedule is
# the reason. Hiding it under a green neighbour would bury the fix.
STATUS_ORDER = {"none": 0, "ok": 1, "warn": 2, "fail": 3, "blocked": 4,
                "overrun": 5, "error": 6}


def worst(statuses) -> str:
    best = "none"
    for status in statuses:
        if STATUS_ORDER.get(status, 0) > STATUS_ORDER[best]:
            best = status
    return best


# --------------------------------------------------------------------- graph

@dataclass
class PathNode:
    ttl: int
    ip: str | None
    traces: int = 0
    rtts: list[float] = field(default_factory=list)
    losses: list[float] = field(default_factory=list)
    is_destination: bool = False
    hostname: str | None = None
    hostname_known: bool = False
    asn: int | None = None
    asn_org: str | None = None
    # Newest trace this hop appeared in. Derived, not stored: `hops` has no
    # timestamp of its own, but every row is joined to its trace's
    # started_ts, so the graph can age a hop out without a schema change.
    last_seen: float = 0.0

    @property
    def key(self) -> tuple[int, str | None]:
        return (self.ttl, self.ip)

    @property
    def label(self) -> str:
        return self.ip if self.ip else "no reply"

    @property
    def hostname_label(self) -> str:
        """What to print under the address.

        A hop with no PTR record is still worth naming if it's an external
        address: asn_lookup() only ever populates asn/asn_org for globally
        routable addresses (namelookup.is_global gates it), so falling back
        to the ASN's org name here is automatically limited to external
        hops \u2014 an internal address with no PTR still shows "no PTR record",
        exactly as before.
        """
        if self.ip is None:
            return ""
        if not self.hostname_known:
            return "resolving\u2026"
        if self.hostname:
            return self.hostname
        if self.asn_org:
            return self.asn_org
        if self.asn:
            return f"AS{self.asn}"
        return "no PTR record"

    @property
    def is_timeout(self) -> bool:
        return self.ip is None

    @property
    def avg_rtt(self) -> float | None:
        return mean(self.rtts) if self.rtts else None

    @property
    def avg_loss(self) -> float:
        return mean(self.losses) if self.losses else 0.0


@dataclass
class PathEdge:
    src: tuple[int, str | None]
    dst: tuple[int, str | None]
    traces: int = 0
    last_seen: float = 0.0


@dataclass
class Topology:
    nodes: dict[tuple[int, str | None], PathNode] = field(default_factory=dict)
    edges: list[PathEdge] = field(default_factory=list)
    columns: dict[int, list[PathNode]] = field(default_factory=dict)
    total_traces: int = 0
    distinct_paths: int = 0

    def share(self, count: int) -> float:
        return count / self.total_traces if self.total_traces else 0.0

    def silent_runs(self, min_length: int = 2) -> list[tuple[int, int]]:
        """Stretches of consecutive hops where nothing ever replied.

        These are usually a single provider's core declining to send ICMP time
        exceeded, so they carry no information beyond their own length and are
        worth folding away by default.
        """
        ttls = sorted(self.columns)
        runs: list[tuple[int, int]] = []
        index = 0
        while index < len(ttls):
            end = index
            while (
                end < len(ttls)
                and len(self.columns[ttls[end]]) == 1
                and self.columns[ttls[end]][0].ip is None
                and (end == index or ttls[end] == ttls[end - 1] + 1)
            ):
                end += 1
            if end - index >= min_length:
                runs.append((ttls[index], ttls[end - 1]))
            index = end if end > index else index + 1
        return runs


def build_topology(hop_rows, dest_ip: str | None = None,
                   hostnames: dict[str, str | None] | None = None,
                   asn_data: dict[str, tuple[int | None, str | None]] | None = None,
                   stale_after_s: float = 0.0,
                   window_end: float | None = None,
                   ) -> Topology:
    """Collapse many traces into one graph.

    A node is a (TTL, address) pair. Two nodes in the same TTL column means the
    path diverged: either between runs, or between probes within a single run.

    `stale_after_s` drops hops that stopped appearing: a router that was
    renumbered out of the path a month ago should not sit in the diagram
    forever just because the window still reaches back far enough to include
    one old trace. Staleness is measured from `window_end` (the end of the
    window these rows came from) and not from wall-clock now, so panning the
    timeline back a week still shows what the path looked like then instead of
    an empty graph. With no `window_end` the newest trace in `hop_rows` stands
    in for it. Zero disables the filter.
    """
    per_trace: dict[int, dict[int, set[str | None]]] = defaultdict(lambda: defaultdict(set))
    trace_ts: dict[int, float] = {}
    rtts: dict[tuple[int, str | None], list[float]] = defaultdict(list)
    losses: dict[tuple[int, str | None], list[float]] = defaultdict(list)

    for row in hop_rows:
        key = (row["ttl"], row["ip"])
        per_trace[row["trace_id"]][row["ttl"]].add(row["ip"])
        trace_ts[row["trace_id"]] = float(row["started_ts"])
        if row["rtt_ms"] is not None:
            rtts[key].append(float(row["rtt_ms"]))
        if row["loss_pct"] is not None:
            losses[key].append(float(row["loss_pct"]))

    node_counts: Counter = Counter()
    edge_counts: Counter = Counter()
    signatures: Counter = Counter()
    node_seen: dict[tuple[int, str | None], float] = {}
    edge_seen: dict[tuple[tuple[int, str | None], tuple[int, str | None]], float] = {}

    for trace_id, ttl_map in per_trace.items():
        started = trace_ts.get(trace_id, 0.0)
        for ttl, ips in ttl_map.items():
            for ip in ips:
                node_counts[(ttl, ip)] += 1
                if started > node_seen.get((ttl, ip), 0.0):
                    node_seen[(ttl, ip)] = started
        for ttl in ttl_map:
            if ttl + 1 not in ttl_map:
                continue
            for src in ttl_map[ttl]:
                for dst in ttl_map[ttl + 1]:
                    edge = ((ttl, src), (ttl + 1, dst))
                    edge_counts[edge] += 1
                    if started > edge_seen.get(edge, 0.0):
                        edge_seen[edge] = started
        sig = tuple(
            sorted(ttl_map[t])[0] if ttl_map[t] else None
            for t in sorted(ttl_map)
        )
        signatures[sig] += 1

    # A hop is stale relative to the end of the window it was read from. When
    # the caller did not say where that is, the newest trace present is the
    # best available stand-in: it is the same value for a live window and it
    # keeps a historical window self-consistent.
    cutoff = 0.0
    if stale_after_s > 0 and trace_ts:
        end = window_end if window_end is not None else max(trace_ts.values())
        cutoff = end - stale_after_s

    hostnames = hostnames or {}
    asn_data = asn_data or {}
    topo = Topology(total_traces=len(per_trace), distinct_paths=len(signatures))
    for key, count in node_counts.items():
        ttl, ip = key
        seen = node_seen.get(key, 0.0)
        if seen < cutoff:
            continue
        asn, asn_org = asn_data.get(ip, (None, None))
        topo.nodes[key] = PathNode(
            ttl=ttl,
            ip=ip,
            traces=count,
            rtts=rtts.get(key, []),
            losses=losses.get(key, []),
            is_destination=bool(dest_ip) and ip == dest_ip,
            hostname=hostnames.get(ip),
            hostname_known=ip in hostnames,
            asn=asn,
            asn_org=asn_org,
            last_seen=seen,
        )
    for (src, dst), count in edge_counts.items():
        # An edge to a hop that aged out has nothing left to point at, so it
        # goes with it even if the edge itself was seen recently.
        if src not in topo.nodes or dst not in topo.nodes:
            continue
        topo.edges.append(PathEdge(src=src, dst=dst, traces=count,
                                   last_seen=edge_seen.get((src, dst), 0.0)))

    columns: dict[int, list[PathNode]] = defaultdict(list)
    for node in topo.nodes.values():
        columns[node.ttl].append(node)
    for ttl in columns:
        columns[ttl].sort(key=lambda n: (-n.traces, n.ip or "\uffff"))
    topo.columns = dict(sorted(columns.items()))
    return topo


# ------------------------------------------------------------------ timeline

@dataclass
class Bucket:
    t0: float
    t1: float
    status: str = "none"
    total: int = 0
    counts: Counter = field(default_factory=Counter)
    avg_rtt: float | None = None
    avg_loss: float = 0.0
    max_loss: float = 0.0
    path_changed: bool = False
    icmp_code: str | None = None
    icmp_from: str | None = None
    note: str | None = None

    @property
    def mid(self) -> float:
        return (self.t0 + self.t1) / 2


def build_timeline(traces, t0: float, t1: float, bucket_s: float) -> list[Bucket]:
    """Bucket traces into slices of `bucket_s` seconds, worst status winning.

    Boundaries snap to a grid anchored at the epoch rather than at t0, so a
    block keeps meaning the same slice of wall-clock time as the window slides
    or the user pans. With bucket_s equal to the polling interval, one block is
    one scheduled poll, and a block with no trace in it is a poll that was
    missed rather than an artefact of where the window happens to start.
    """
    bucket_s = max(float(bucket_s), 1e-3)
    start = math.floor(t0 / bucket_s) * bucket_s
    n_buckets = max(1, int(math.ceil((t1 - start) / bucket_s)))
    buckets = [Bucket(start + i * bucket_s, start + (i + 1) * bucket_s)
               for i in range(n_buckets)]
    rtts: list[list[float]] = [[] for _ in range(n_buckets)]
    lost: list[list[float]] = [[] for _ in range(n_buckets)]

    previous_sig = None
    for row in traces:
        index = int((row["started_ts"] - start) / bucket_s)
        if index < 0 or index >= n_buckets:
            continue
        bucket = buckets[index]
        bucket.total += 1
        bucket.counts[row["status"]] += 1
        bucket.status = worst((bucket.status, row["status"]))
        if row["rtt_ms"] is not None:
            rtts[index].append(float(row["rtt_ms"]))
        if row["loss_pct"] is not None:
            bucket.max_loss = max(bucket.max_loss, float(row["loss_pct"]))
            lost[index].append(float(row["loss_pct"]))
        if row["status"] == "overrun" and bucket.note is None:
            bucket.note = row["error"]
        if row["status"] == "blocked" and bucket.icmp_code is None:
            keys = row.keys()
            bucket.icmp_code = row["icmp_code"] if "icmp_code" in keys else None
            bucket.icmp_from = row["icmp_from"] if "icmp_from" in keys else None

        sig = row["path_sig"]
        if sig and previous_sig and sig != previous_sig:
            bucket.path_changed = True
        if sig:
            previous_sig = sig

    for index, bucket in enumerate(buckets):
        if rtts[index]:
            bucket.avg_rtt = mean(rtts[index])
        if lost[index]:
            bucket.avg_loss = mean(lost[index])
    return buckets


def availability(traces) -> tuple[float, float | None, int]:
    """Return (percent ok, average destination RTT, sample count)."""
    rows = list(traces)
    if not rows:
        return 0.0, None, 0
    ok = sum(1 for r in rows if r["status"] == "ok")
    rtts = [float(r["rtt_ms"]) for r in rows if r["rtt_ms"] is not None]
    return 100.0 * ok / len(rows), (mean(rtts) if rtts else None), len(rows)

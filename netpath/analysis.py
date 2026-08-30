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
                   asn_data: dict[str, tuple[int | None, str | None]] | None = None
                   ) -> Topology:
    """Collapse many traces into one graph.

    A node is a (TTL, address) pair. Two nodes in the same TTL column means the
    path diverged: either between runs, or between probes within a single run.
    """
    per_trace: dict[int, dict[int, set[str | None]]] = defaultdict(lambda: defaultdict(set))
    rtts: dict[tuple[int, str | None], list[float]] = defaultdict(list)
    losses: dict[tuple[int, str | None], list[float]] = defaultdict(list)

    for row in hop_rows:
        key = (row["ttl"], row["ip"])
        per_trace[row["trace_id"]][row["ttl"]].add(row["ip"])
        if row["rtt_ms"] is not None:
            rtts[key].append(float(row["rtt_ms"]))
        if row["loss_pct"] is not None:
            losses[key].append(float(row["loss_pct"]))

    node_counts: Counter = Counter()
    edge_counts: Counter = Counter()
    signatures: Counter = Counter()

    for ttl_map in per_trace.values():
        for ttl, ips in ttl_map.items():
            for ip in ips:
                node_counts[(ttl, ip)] += 1
        for ttl in ttl_map:
            if ttl + 1 not in ttl_map:
                continue
            for src in ttl_map[ttl]:
                for dst in ttl_map[ttl + 1]:
                    edge_counts[((ttl, src), (ttl + 1, dst))] += 1
        sig = tuple(
            sorted(ttl_map[t])[0] if ttl_map[t] else None
            for t in sorted(ttl_map)
        )
        signatures[sig] += 1

    hostnames = hostnames or {}
    asn_data = asn_data or {}
    topo = Topology(total_traces=len(per_trace), distinct_paths=len(signatures))
    for key, count in node_counts.items():
        ttl, ip = key
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
        )
    for (src, dst), count in edge_counts.items():
        topo.edges.append(PathEdge(src=src, dst=dst, traces=count))

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

"""The NetFlow overview route, driven straight through api.get_flow_overview.

No test drove this endpoint before: the rollup suite proves flowdb answers
the same question both ways, and the frontend contracts pin what netflow.js
does with the answer, but what the route puts between the two — which bucket
it picks for a span, where it puts t0, how many bands it names and how many
bars it lists — was checked by nobody. Those are exactly the facts the chart
leans on: it divides the last slot by `t1 - times[-1]`, it swatches bar i in
band i's colour, and it takes the response's t0 as its axis.

The service is a duck-typed stub the way test_mac_tables builds one (`class
Svc: nodes_db = db; ...`): on the unresolved path the route reads flow_db
and flow_settings and nothing else, so that is all the stub carries.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import math
import os
import shutil
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase
from netpath.web import api

TMPDIR = tmpdir("netflow_overview_api_")
FAILS: list[str] = []

# api._flow_bucket's ladder as documented in flowdb.ROLLUP_TIERS' comment and
# pinned in test_netflow_rollup.BUCKETS: the span each rung serves up to, and
# the bucket it hands out for it.
LADDER = ((900, 10), (7200, 60), (43200, 300), (172800, 900),
          (1209600, 3600))
PAST_THE_LADDER = 21600
OTHER = "— other —"


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def flow(index: int, ts: float, **overrides):
    fields = dict(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=40000 + index % 11, dst_port=10000 + index % 30,
        protocol=(6, 17)[index % 2], tos=0, tcp_flags=0,
        in_if=index % 6, out_if=index % 8,
        src_as=64500, dst_as=64600, next_hop=None,
        packets=1 + index % 9, bytes=100 + index, sampling=1,
        domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def service(db: FlowDatabase, **settings):
    """The duck-typed service the route reads: a flow store and its
    settings, with the address-resolution path left off so no app_db or
    nodes_db is ever asked for a name."""
    class Svc:
        flow_db = db
        flow_settings = {**flowdb.DEFAULTS, "resolve_addresses": False,
                         **settings}
        app_db = None
        nodes_db = None
    return Svc


def named(payload: dict) -> list[str]:
    return [s["name"] for s in payload["series"] if s["name"] != OTHER]


# ------------------------------------------------------------------------- 1

def test_1_the_bucket_ladder() -> None:
    print("1: _flow_bucket hands out the bucket the ladder names for a span")
    svc = service(None)
    wrong = []
    low = 0
    for limit, step in LADDER:
        # The rung's own limit, and one second inside it from the rung below.
        for span in (low + 1, limit):
            got = api._flow_bucket(svc, span)
            if got != step:
                wrong.append((span, got, step))
        low = limit
    check(not wrong,
          f"every rung serves its whole span at its own bucket ({wrong})")
    check(api._flow_bucket(svc, LADDER[-1][0] + 1) == PAST_THE_LADDER
          and api._flow_bucket(svc, 30 * 86400) == PAST_THE_LADDER,
          f"past the last rung the bucket is {PAST_THE_LADDER}s, which is "
          f"what a 30-day chart gets")
    check(api._flow_bucket(service(None, bucket_seconds=600), 30 * 86400) == 600
          and api._flow_bucket(service(None, bucket_seconds=600), 600) == 600,
          "a configured chart interval overrides the ladder for every span "
          "whose slot count it keeps under FLOW_MAX_BUCKETS")
    # A configured bucket far too small for the window is widened until the
    # slot count fits, rather than the window being narrowed — the same
    # rule analysis.build_timeline applies to its own MAX_BUCKETS.
    span = 30 * 86400
    got = api._flow_bucket(service(None, bucket_seconds=5), span)
    check(got == math.ceil(span / api.FLOW_MAX_BUCKETS)
          and span / got <= api.FLOW_MAX_BUCKETS,
          f"a 5-second bucket over 30 days is widened to {got}s so the chart "
          f"stays under FLOW_MAX_BUCKETS slots")
    check(api._flow_bucket(service(None, bucket_seconds=0), 3600) == 60,
          "bucket_seconds of 0 means 'choose from the window'")


# ------------------------------------------------------------------------- 2

def test_2_the_window_in_the_response() -> None:
    print("2: the response carries the window the values were read over")
    db = FlowDatabase(os.path.join(TMPDIR, "window.db"))
    t1 = float(flowdb._align_down(time.time() - 300, 60) + 23)
    # Deliberately off the minute: the bucket for an hour is 60s, and flowdb
    # snaps t0 down so a rollup bucket lands wholly inside one slot.
    t0 = t1 - 3600 + 17
    rows = [flow(i, t0 + i * 3600 / 500.0) for i in range(500)]
    db.insert_flows(rows)
    payload = api.get_flow_overview(service(db), {"t0": str(t0), "t1": str(t1),
                                                  "dimension": "Application"}, None)
    aligned = float(flowdb._align_down(t0, 60))
    # The window is 17 seconds short of the hour the rows were spread over,
    # so the last few of them lie past t1 and are not the window's.
    inside = [row for row in rows if aligned <= row.ts_end <= t1]
    check(payload["bucket_s"] == 60.0,
          f"an hour's chart is drawn in 60s buckets ({payload['bucket_s']})")
    check(payload["t0"] == aligned and payload["times"][0] == aligned,
          f"t0 is the aligned one flowdb actually used, not the one asked "
          f"for ({payload['t0']} vs {t0}, aligned {aligned})")
    check(payload["t1"] == t1,
          f"t1 is the requested one, which is the end of the last slot "
          f"({payload['t1']} vs {t1})")
    times = payload["times"]
    step = payload["bucket_s"]
    check(len(times) == int((t1 - aligned) / step) + 1
          and all(times[i] == aligned + i * step for i in range(len(times))),
          f"times is one slot per bucket from t0, int(span / bucket) + 1 of "
          f"them ({len(times)})")
    # What the chart divides the last slot by: the slot starts on the last
    # boundary before t1 and covers only what is left after it.
    covered = t1 - times[-1]
    check(0 <= covered < step,
          f"the last slot is partial, covering {covered:.0f}s of a {step:.0f}s "
          f"bucket, so a rate for it is bytes over that and not over the "
          f"whole bucket")
    check(len(payload["series"]) == len(named(payload)) + 1
          and all(len(s["values"]) == len(times) for s in payload["series"]),
          "every series is one value per slot")
    check(payload["dimension"] == "Application"
          and len(inside) < len(rows)
          and payload["totals"]["flows"] == len(inside)
          and payload["totals"]["bytes"] == sum(row.bytes for row in inside),
          f"the totals are the window's, exactly — {len(inside)} of the "
          f"{len(rows)} rows ({payload['totals']})")
    check(payload["totals"]["bytes"] == round(sum(
        sum(s["values"]) for s in payload["series"])),
          "and the stacked series, other included, add up to them")
    db.close()


# ------------------------------------------------------------------------- 3

def test_3_eight_bands_and_top_n_bars() -> None:
    print("3: the chart names eight bands; the bar list is the operator's Top N")
    db = FlowDatabase(os.path.join(TMPDIR, "bands.db"))
    t1 = float(flowdb._align_down(time.time() - 300, 60))
    t0 = t1 - 3600
    # Thirty applications with thirty distinct volumes, so every rank is
    # unambiguous: application k carries (k + 1) flows of 1000 bytes.
    rows = []
    for k in range(30):
        for j in range(k + 1):
            rows.append(flow(k, t0 + 60 * (j % 59) + 30, dst_port=10000 + k,
                             bytes=1000))
    db.insert_flows(rows)
    params = {"t0": str(t0), "t1": str(t1), "dimension": "Application"}

    payload = api.get_flow_overview(service(db, top_n=20), params, None)
    bands = named(payload)
    check(len(bands) == 8 and payload["series"][-1]["name"] == OTHER,
          f"the series are eight named bands and '{OTHER}' last "
          f"({len(bands)} named, last {payload['series'][-1]['name']!r})")
    check(len(payload["top"]) == 20,
          f"the bars are the twenty top_n asked for ({len(payload['top'])})")
    check([row["label"] for row in payload["top"][:8]] == bands,
          "bar i is band i for the first eight — the order the bars borrow "
          "the chart's colours in")
    heaviest = [f"{10000 + k}" for k in range(29, 21, -1)]
    check([row["key"] for row in payload["top"][:8]] == heaviest,
          f"and those eight are the heaviest eight ({[r['key'] for r in payload['top'][:8]]})")
    check(all(row["bytes"] == 1000 * (30 - i) for i, row in enumerate(payload["top"])),
          "each bar carries its own exact volume")
    folded = payload["top"][8:]
    check(sum(sum(s["values"]) for s in payload["series"][:8])
          == sum(row["bytes"] for row in payload["top"][:8])
          and sum(payload["series"][-1]["values"])
          == sum(1000 * (k + 1) for k in range(22)),
          f"what the bars past the eighth carry is inside '{OTHER}' in the "
          f"chart, with everything below the twentieth ({len(folded)} bars "
          f"folded)")

    # The two limits are independent: fewer bars never means fewer bands,
    # and more bars never means more.
    payload = api.get_flow_overview(service(db, top_n=5), params, None)
    check(len(payload["top"]) == 5 and len(named(payload)) == 8,
          f"top_n 5 lists five bars under eight bands "
          f"({len(payload['top'])} bars, {len(named(payload))} bands)")
    payload = api.get_flow_overview(service(db, top_n=25), params, None)
    check(len(payload["top"]) == 25 and len(named(payload)) == 8,
          f"top_n 25 — the most the settings dialog allows — lists 25 bars "
          f"under the same eight bands ({len(payload['top'])} bars, "
          f"{len(named(payload))} bands)")
    db.close()


# ------------------------------------------------------------------------- 4

def test_4_fewer_keys_than_bands() -> None:
    print("4: with fewer keys than bands, every bar has a band and nothing is "
          "folded")
    db = FlowDatabase(os.path.join(TMPDIR, "few.db"))
    t1 = float(flowdb._align_down(time.time() - 300, 60))
    t0 = t1 - 3600
    db.insert_flows([flow(i, t0 + i * 7.0, dst_port=10000 + i % 3)
                     for i in range(300)])
    payload = api.get_flow_overview(
        service(db, top_n=10), {"t0": str(t0), "t1": str(t1),
                                "dimension": "Application"}, None)
    check(len(named(payload)) == 3 and len(payload["top"]) == 3
          and OTHER not in [s["name"] for s in payload["series"]],
          f"three applications make three bands, three bars, and no "
          f"'{OTHER}' ({len(named(payload))} bands, {len(payload['top'])} "
          f"bars)")
    check([row["label"] for row in payload["top"]] == named(payload),
          "...in the same order")
    db.close()


TESTS = [
    test_1_the_bucket_ladder,
    test_2_the_window_in_the_response,
    test_3_eight_bands_and_top_n_bars,
    test_4_fewer_keys_than_bands,
]


def main() -> int:
    try:
        for test in TESTS:
            test()
            print()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"{len(FAILS)} CHECK(S) FAILED:")
        for item in FAILS:
            print(f"  - {item}")
        return 1
    print("ALL NETFLOW OVERVIEW API ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

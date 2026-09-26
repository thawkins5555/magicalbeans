"""Proves demo/flows.py: every datagram it builds decodes cleanly, carries
the exporter/version/interface/sampling shape its docstring promises, and a
burst arrives oldest first.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on
failure.
"""
import time

from _paths import tmpdir                  # noqa: F401  (puts REPO_ROOT on sys.path)

from demo import flows
from netpath import nfdecode

TMPDIR = tmpdir("flows_simulator_")         # unused, kept for the sys.path side effect
FAILURES: list[str] = []
SEED = 1


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILURES.append(message)


def _midnight_utc(days_back: int) -> float:
    """Epoch seconds of midnight UTC, `days_back` days before today's."""
    now_hour = int(time.time() // 3600)
    return float((now_hour - now_hour % 24 - 24 * days_back) * 3600)


def busy_window(hours: float) -> tuple:
    """A window ending mid-afternoon UTC yesterday - reliably busy, so
    interface/path coverage does not depend on which real hour this suite
    happens to run in."""
    t1 = _midnight_utc(1) + 16 * 3600
    return t1 - hours * 3600, t1


def decode_two_phases(exporters: list, t0: float, t1: float, t2: float,
                      seed: int):
    """Decodes a "burst" window (t0..t1) then a "live" window (t1..t2) with
    one _ExporterState per exporter shared across both stream_datagrams()
    calls, the way main() shares one across _run_burst/_run_live -- so any
    counter that resets at the handoff shows up as seq_missed/seq_resets."""
    decoder = nfdecode.Decoder()
    by_index = {exp.index: exp for exp in exporters}
    states = {exp.index: flows._ExporterState(exp) for exp in exporters}
    for t_lo, t_hi in ((t0, t1), (t1, t2)):
        for exp_index, _ts_end, datagram, _n in flows.stream_datagrams(
                exporters, t_lo, t_hi, seed, states=states):
            decoder.decode(datagram, by_index[exp_index].address)
    return decoder


def decode_all(exporters: list, t0: float, t1: float, seed: int):
    """Every flow decode() yields, in the exact order stream_datagrams()
    sent its datagrams (arrival order)."""
    decoder = nfdecode.Decoder()
    by_index = {exp.index: exp for exp in exporters}
    decoded: list = []                      # (exporter_index, Flow), arrival order
    n_expected = 0
    for exp_index, _ts_end, datagram, n_records in flows.stream_datagrams(
            exporters, t0, t1, seed):
        n_expected += n_records
        for flow in decoder.decode(datagram, by_index[exp_index].address):
            decoded.append((exp_index, flow))
    return decoder, decoded, n_expected


def main() -> int:
    print("flows simulator: packet shape, decode and ordering")

    # boot must precede every flow this suite generates (up to 2 days back),
    # since a v5/v9 uptime counter cannot be negative.
    exporters = flows.build_exporters(4, SEED, time.time() - 3 * 86400)
    t0, t1 = busy_window(2)
    decoder, decoded, n_expected = decode_all(exporters, t0, t1, SEED)

    check(len(decoded) > 1000,
          f"a 2-hour, 4-exporter window yields a realistic record count "
          f"({len(decoded)})")
    check(decoder.stats["no_template"] == 0,
          f"no data set is dropped for want of a template "
          f"(no_template={decoder.stats['no_template']})")
    check(len(decoded) == n_expected,
          f"every record generate_flows() produced decodes to exactly one "
          f"Flow ({len(decoded)} of {n_expected})")

    ipfix_exp = next(exp for exp in exporters if exp.version == nfdecode.IPFIX)
    ipfix_decoder, _, _ = decode_all([ipfix_exp], t0, t1, SEED)
    check(ipfix_decoder.stats["seq_missed"] == 0,
          f"an in-order IPFIX burst counts no missed sequence "
          f"(seq_missed={ipfix_decoder.stats['seq_missed']})")

    by_exporter: dict = {}
    for exp_index, flow in decoded:
        by_exporter.setdefault(exp_index, []).append(flow)

    for exp in exporters:
        rows = by_exporter.get(exp.index, [])
        check(len(rows) > 0,
              f"exporter {exp.index + 1} ({exp.address}) sent decodable flows")
        check(all(flow.version == exp.version for flow in rows),
              f"exporter {exp.index + 1} decodes as version {exp.version} "
              f"throughout ({ {flow.version for flow in rows} })")

    now = time.time()
    ts_values = [flow.ts_end for _, flow in decoded]
    check(max(ts_values) <= now + 1,
          f"no decoded flow lands in the future "
          f"({max(ts_values) - now:.1f}s from now)")
    window = t1 - t0
    check(min(ts_values) < t0 + window * 0.25 and max(ts_values) > t1 - window * 0.25,
          f"decoded ts_end values spread across the window, within a few "
          f"seconds of its edges (min at t0+{min(ts_values) - t0:.0f}s, "
          f"max at t1-{t1 - max(ts_values):.0f}s)")

    # --- oldest first: the datagrams sent early carry the oldest flows ----
    tenth = max(1, len(ts_values) // 10)
    first_avg = sum(ts_values[:tenth]) / tenth
    last_avg = sum(ts_values[-tenth:]) / tenth
    check(first_avg < t0 + window * 0.25 and last_avg > t1 - window * 0.25
          and first_avg < last_avg,
          f"a burst is ordered oldest first (first {tenth} flows average "
          f"t0+{first_avg - t0:.0f}s, last {tenth} average t1-{t1 - last_avg:.0f}s)")

    # --- every interface, both directions ----------------------------------
    for exp in exporters:
        rows = by_exporter.get(exp.index, [])
        seen_in = {flow.in_if for flow in rows}
        seen_out = {flow.out_if for flow in rows}
        ifaces = set(exp.interfaces)
        check(ifaces <= seen_in and ifaces <= seen_out,
              f"exporter {exp.index + 1}: every interface {sorted(ifaces)} "
              f"appears as in_if ({sorted(seen_in)}) and out_if "
              f"({sorted(seen_out)})")

    # --- sampling from the options template ---------------------------------
    options_exp = next(exp for exp in exporters if exp.has_options)
    plain_v9_exp = next(exp for exp in exporters
                        if exp.version == nfdecode.V9 and not exp.has_options)
    options_rates = {flow.sampling for flow in by_exporter.get(options_exp.index, [])}
    check(options_rates == {100},
          f"exporter {options_exp.index + 1}'s options template yields "
          f"sampling=100 on every flow ({options_rates})")
    plain_rates = {flow.sampling for flow in by_exporter.get(plain_v9_exp.index, [])}
    check(plain_rates == {1},
          f"exporter {plain_v9_exp.index + 1} (v9, no options template) "
          f"stays at the default sampling ({plain_rates})")

    # --- the busiest exporter --------------------------------------------
    busy = next(exp for exp in exporters if exp.busy)
    counts = {exp.index: len(by_exporter.get(exp.index, [])) for exp in exporters}
    check(counts[busy.index] == max(counts.values()),
          f"the busiest exporter has the most records ({counts})")

    # --- the diurnal shape, over a full day so it is not tied to when this --
    # --- suite happens to run -----------------------------------------------
    day_t1, day_t0 = _midnight_utc(1), _midnight_utc(2)
    _decoder, day_decoded, _n = decode_all(exporters, day_t0, day_t1, SEED)
    hour3 = sum(1 for _, flow in day_decoded if time.gmtime(flow.ts_end).tm_hour == 3)
    hour15 = sum(1 for _, flow in day_decoded if time.gmtime(flow.ts_end).tm_hour == 15)
    check(hour3 < hour15,
          f"the diurnal shape holds: a 03:00 hour ({hour3} records) is "
          f"quieter than a 15:00 hour ({hour15}) over a one-day window")

    # --- burst -> live handoff: one sequence counter per exporter, so a ----
    # --- collector sees no gap or reset crossing it, including across a ----
    # --- template refresh on each side ---------------------------------
    handoff_end = _midnight_utc(1) + 16 * 3600
    handoff_mid = handoff_end - 24 * 3600
    handoff_start = handoff_mid - 24 * 3600
    handoff_exporters = flows.build_exporters(4, SEED, handoff_start - 3600)
    handoff_decoder = decode_two_phases(
        handoff_exporters, handoff_start, handoff_mid, handoff_end, SEED)
    check(handoff_decoder.stats["templates"] >= 8,
          f"the burst+live windows are long enough to force template "
          f"refreshes on both sides of the handoff "
          f"(templates={handoff_decoder.stats['templates']})")
    check(handoff_decoder.stats["seq_missed"] == 0,
          f"no sequence number is missed across the burst -> live handoff "
          f"(seq_missed={handoff_decoder.stats['seq_missed']})")
    check(handoff_decoder.stats["seq_resets"] == 0,
          f"no exporter's counter resets across the burst -> live handoff "
          f"(seq_resets={handoff_decoder.stats['seq_resets']})")

    print(f"\n{len(FAILURES)} failure(s)" if FAILURES else "\nall checks passed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())

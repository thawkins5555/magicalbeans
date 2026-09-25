"""The NetFlow Exporters and Interfaces routes, plus the pieces they lean on:
namelookup.resolve_names, the overview's exporter names and records_only
flag, iface/direction filters, sequence-gap counting and the two routes'
registration.

The service is a duck-typed stub the way test_netflow_overview_api builds
one, plus a stub nodes_db/app_db for name resolution. A real FlowDatabase
backs every test, so the SQL flowdb runs is exercised, not a mock of it.

This suite is written against the API contract agreed with flowdb's own
work (flow_db.overview(..., info=...), interface_totals, exporter_totals,
coverage()'s scoped floors) landing alongside it. Each test is run inside a
try/except in main() so one still-missing flowdb method fails only that
test, not the whole suite -- see the final report for what that leaves
unproven.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import struct
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb, nfdecode, permissions
from netpath.flowdb import FlowDatabase
from netpath.web import api
from netpath.web.server import ROUTES

TMPDIR = tmpdir("netflow_exporters_api_")
FAILS: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


# --------------------------------------------------------------- fixtures

def flow(index: int, ts: float, **overrides):
    fields = dict(
        exporter="10.70.0.1", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17)[index % 2], tos=0, tcp_flags=0,
        in_if=1, out_if=2,
        src_as=64500, dst_as=64600, next_hop=None,
        packets=1 + index % 9, bytes=100 + index, sampling=1,
        domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def cover(db: FlowDatabase, *, minutes: bool = True, hours: bool = True) -> None:
    """Same helper as tests/test_netflow_rollup.py: bring both tiers up to
    date the way the service does."""
    for tier, wanted in ((60, minutes), (3600, hours)):
        if not wanted:
            continue
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break


class StubNodesDb:
    """devices_by_addresses/device_by_ip/device/interface_labels/interfaces,
    the surface namelookup and api.get_flow_interfaces read."""

    def __init__(self, devices: dict, interfaces: dict):
        self._devices = devices                # {ip: device dict}
        self._interfaces = interfaces           # {device_id: [iface dict]}

    def devices_by_addresses(self, ips):
        return {ip: self._devices[ip] for ip in ips if ip in self._devices}

    def device_by_ip(self, ip):
        return self._devices.get(ip)

    def device(self, device_id):
        for row in self._devices.values():
            if row["id"] == device_id:
                return row
        return None

    def interface_labels(self, device_id):
        return {row["if_index"]: row for row in self._interfaces.get(device_id, [])}

    def interfaces(self, device_id):
        return self._interfaces.get(device_id, [])


class StubAppDb:
    def __init__(self, names: dict):
        self._names = names

    def hostnames(self, ips):
        return {ip: self._names[ip] for ip in ips if ip in self._names}


class StubCollector:
    def __init__(self, decoder):
        self.decoder = decoder


class StubDb:
    """The one method _flow_records_rows reads off service.db: NetPath
    target correlation, unused by any check here."""

    def targets_by_destination_ips(self, ips):
        return {}


def device_row(device_id: int, ip: str, name: str = "", sys_name: str = "") -> dict:
    return {"id": device_id, "ip": ip, "name": name or ip, "sys_name": sys_name,
            "display_name_source": "auto"}


def iface_row(if_index: int, speed_bps, alias: str = "", descr: str = "",
             name: str = "") -> dict:
    return {"if_index": if_index, "speed_bps": speed_bps, "alias": alias,
            "descr": descr, "name": name, "oper_status": "up"}


def service(db: FlowDatabase, nodes_db=None, app_db=None, collector=None, **settings):
    class Svc:
        flow_db = db
        flow_settings = {**flowdb.DEFAULTS, "resolve_addresses": False, **settings}
    Svc.nodes_db = nodes_db
    Svc.app_db = app_db
    Svc.collector = collector or StubCollector(nfdecode.Decoder())
    Svc.db = StubDb()
    return Svc


def run(name: str, fn) -> None:
    print(name)
    try:
        fn()
    except Exception as exc:  # a missing flowdb method fails only this test
        print(f"  FAIL: {name} raised {exc!r}")
        FAILS.append(f"{name} raised {exc!r}")
    print()


# ------------------------------------------------------------------------- 1

def test_1_routes_registered() -> None:
    print("1: the two new routes are registered, read-gated")
    by_path = {(method, path): (handler, gate) for method, path, handler, gate in ROUTES}
    exporters = by_path.get(("GET", r"^/api/netflow/exporters$"))
    interfaces = by_path.get(("GET", r"^/api/netflow/interfaces$"))
    check(exporters is not None and exporters[0] is api.get_flow_exporters
          and exporters[1] == ("netflow", permissions.READ),
          f"/api/netflow/exporters -> get_flow_exporters, ('netflow', R) ({exporters})")
    check(interfaces is not None and interfaces[0] is api.get_flow_interfaces
          and interfaces[1] == ("netflow", permissions.READ),
          f"/api/netflow/interfaces -> get_flow_interfaces, ('netflow', R) ({interfaces})")


# ------------------------------------------------------------------------- 2

def _v5_packet(count: int, flow_sequence: int) -> bytes:
    now = int(time.time())
    header = struct.pack("!HHIIIIBBH", 5, count, 1000, now, 0, flow_sequence, 0, 0, 0)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        0x0A000001, 0x0A000002, 0x0A0000FE, 1, 2, 10, 1500, 500, 900,
        1234, 80, 0, 0x18, 6, 0, 64500, 64501, 0, 0, 0)
    return header + record * count


def _set(set_id: int, payload: bytes) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(payload)) + payload


def _v9_packet(sets: bytes, sequence: int, domain: int = 0) -> bytes:
    header = struct.pack("!HHIIII", 9, 1, 1000, int(time.time()), sequence, domain)
    return header + sets


def _v9_template_and_data(template_id: int, octets: int, packets: int) -> bytes:
    fields = [(nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]
    template = struct.pack("!HH", template_id, len(fields))
    for field_id, size in fields:
        template += struct.pack("!HH", field_id, size)
    record = struct.pack("!I", octets) + struct.pack("!I", packets)
    return _set(0, template) + _set(template_id, record)


def _v9_data_only(template_id: int, octets: int, packets: int) -> bytes:
    record = struct.pack("!I", octets) + struct.pack("!I", packets)
    return _set(template_id, record)


def _ipfix_packet(sets: bytes, sequence: int, domain: int = 0) -> bytes:
    body = struct.pack("!HHIII", 10, 16 + len(sets), int(time.time()), sequence, domain)
    return body + sets


def _ipfix_template(template_id: int) -> bytes:
    fields = [(nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]
    template = struct.pack("!HH", template_id, len(fields))
    for field_id, size in fields:
        template += struct.pack("!HH", field_id, size)
    return _set(2, template)


def _ipfix_data(template_id: int, records: int) -> bytes:
    record = struct.pack("!I", 2000) + struct.pack("!I", 20)
    return _set(template_id, record * records)


def test_2_sequence_gaps_v5_v9_ipfix() -> None:
    print("2: sequence gaps are counted for v5, v9 and IPFIX packets")
    decoder = nfdecode.Decoder()

    # v5: flow_sequence counts records; expected next = last + count.
    exp5 = "10.60.0.1"
    decoder.decode(_v5_packet(count=5, flow_sequence=0), exp5)
    decoder.decode(_v5_packet(count=5, flow_sequence=5), exp5)   # in sequence
    before = decoder.stats["seq_missed"]
    decoder.decode(_v5_packet(count=5, flow_sequence=17), exp5)  # 7 missed
    check(decoder.stats["seq_missed"] - before == 7,
          f"v5: a jump from expected 10 to 17 counts 7 missed "
          f"(+{decoder.stats['seq_missed'] - before})")
    check(decoder.sequence_gaps().get(exp5) == 7,
          f"v5: sequence_gaps() attributes the 7 to {exp5} "
          f"({decoder.sequence_gaps().get(exp5)})")

    # v9: header sequence counts packets; expected next = last + 1.
    exp9 = "10.60.0.2"
    decoder.decode(_v9_packet(_v9_template_and_data(700, 2000, 20), sequence=100), exp9)
    decoder.decode(_v9_packet(_v9_data_only(700, 2000, 20), sequence=101), exp9)
    before = decoder.stats["seq_missed"]
    decoder.decode(_v9_packet(_v9_data_only(700, 2000, 20), sequence=105), exp9)
    check(decoder.stats["seq_missed"] - before == 3,
          f"v9: a jump from expected 102 to 105 counts 3 missed "
          f"(+{decoder.stats['seq_missed'] - before})")
    check(decoder.sequence_gaps().get(exp9) == 3,
          f"v9: sequence_gaps() attributes the 3 to {exp9} "
          f"({decoder.sequence_gaps().get(exp9)})")

    # IPFIX: sequence counts data records; expected next = last + records.
    expfx = "10.60.0.3"
    decoder.decode(_ipfix_packet(_ipfix_template(900), sequence=0), expfx)
    decoder.decode(_ipfix_packet(_ipfix_data(900, 3), sequence=0), expfx)
    before = decoder.stats["seq_missed"]
    decoder.decode(_ipfix_packet(_ipfix_data(900, 2), sequence=10), expfx)
    check(decoder.stats["seq_missed"] - before == 7,
          f"IPFIX: a jump from expected 3 to 10 counts 7 missed "
          f"(+{decoder.stats['seq_missed'] - before})")
    check(decoder.sequence_gaps().get(expfx) == 7,
          f"IPFIX: sequence_gaps() attributes the 7 to {expfx} "
          f"({decoder.sequence_gaps().get(expfx)})")

    check(decoder.stats["seq_missed"] == sum(decoder.sequence_gaps().values()),
          "the running total agrees with the per-exporter breakdown")

    # A decrease resets rather than counts: a restarted exporter is not "billions missed".
    decoder.decode(_v5_packet(count=1, flow_sequence=2), exp5)
    before = decoder.stats["seq_missed"]
    decoder.decode(_v5_packet(count=1, flow_sequence=1), exp5)
    check(decoder.stats["seq_missed"] == before,
          "a lower sequence than expected (a restart) is not counted as missed")


# ------------------------------------------------------------------------- 3

def test_3_resolve_names_batched() -> None:
    print("3: namelookup.resolve_names batches devices_by_addresses then DNS")
    from netpath import namelookup

    nodes = StubNodesDb(
        devices={"10.1.1.1": device_row(1, "10.1.1.1", sys_name="core-sw")},
        interfaces={})
    app = StubAppDb({"10.1.1.2": "edge2.example.net", "10.1.1.1": "should-not-win"})
    names = namelookup.resolve_names(nodes, app, ["10.1.1.1", "10.1.1.2", "10.1.1.3"])
    check(names.get("10.1.1.1") == "core-sw",
          f"a Nodes device's name wins over its own DNS entry ({names.get('10.1.1.1')})")
    check(names.get("10.1.1.2") == "edge2.example.net",
          f"an address with no device falls back to DNS ({names.get('10.1.1.2')})")
    check("10.1.1.3" not in names, "an address with neither is left out, not '' or the IP")
    check(namelookup.resolve_names(None, None, []) == {},
          "an empty address list is a no-op with no nodes_db/app_db call")


# ------------------------------------------------------------------------- 4

def test_4_check_netflow_settings_rollup_interface_days() -> None:
    print("4: rollup_interface_days is validated like the other day settings")
    api._check_netflow_settings({"rollup_interface_days": 30})
    check(True, "30 (the default) is accepted")
    api._check_netflow_settings({"rollup_interface_days": 0})
    check(True, "0 -- keep no interface summaries -- is accepted")
    try:
        api._check_netflow_settings({"rollup_interface_days": -1})
        check(False, "a negative value is refused")
    except ValueError as exc:
        check("rollup_interface_days" in str(exc), f"a negative value is refused ({exc})")
    try:
        api._check_netflow_settings({"rollup_interface_days": 3651})
        check(False, "past 3650 is refused")
    except ValueError as exc:
        check("rollup_interface_days" in str(exc), f"past 3650 is refused ({exc})")


# ------------------------------------------------------------------------- 5

def _exporters_fixture(name: str):
    db = FlowDatabase(os.path.join(TMPDIR, name))
    now = time.time()
    # A: named via Nodes, active, one Gbit interface with known utilisation.
    # B: named via DNS only, idle.
    # C: unnamed, silent.
    db.touch_exporters([
        ("10.70.0.1", 9, 10, 100, 1),
        ("10.70.0.2", 5, 10, 100, 1),
        ("10.70.0.3", 10, 10, 100, 1),
    ])
    db._conn.execute("UPDATE exporters SET last_seen=? WHERE address=?",
                     (now - 60, "10.70.0.1"))
    db._conn.execute("UPDATE exporters SET last_seen=? WHERE address=?",
                     (now - 900, "10.70.0.2"))
    db._conn.execute("UPDATE exporters SET last_seen=? WHERE address=?",
                     (now - 7200, "10.70.0.3"))
    db._conn.commit()
    # Recent flows for A, so its five-minute rate is non-zero. A distinct
    # interface pair (50/51) so these do not add into interface 1's totals
    # below and spoil the exact utilisation figure.
    db.insert_flows([flow(i, now - 30 + i, exporter="10.70.0.1", bytes=50_000,
                         in_if=50, out_if=51) for i in range(5)])
    # Interface 1 on A: known in/out byte totals over an exact window, against
    # a 1 Gbit Nodes-reported speed, for an exact utilisation figure.
    t1 = now
    t0 = t1 - 100.0
    mid = (t0 + t1) / 2
    db.insert_flows([
        flow(900, mid, exporter="10.70.0.1", in_if=1, out_if=999,
            bytes=1_250_000_000, sampling=1),
        flow(901, mid, exporter="10.70.0.1", in_if=999, out_if=1,
            bytes=625_000_000, sampling=1),
    ])

    nodes = StubNodesDb(
        devices={"10.70.0.1": device_row(1, "10.70.0.1", sys_name="core1")},
        interfaces={1: [iface_row(1, 1_000_000_000, descr="Gi0/1")]})
    app = StubAppDb({"10.70.0.2": "edge2.example.net"})
    collector = StubCollector(nfdecode.Decoder())
    return db, nodes, app, collector, t0, t1


def test_5_get_flow_exporters() -> None:
    print("5: GET /api/netflow/exporters names, states and rates")
    db, nodes, app, collector, _t0, _t1 = _exporters_fixture("exporters5.db")
    try:
        payload = api.get_flow_exporters(
            service(db, nodes_db=nodes, app_db=app, collector=collector), {}, None)
        by_address = {row["address"]: row for row in payload["exporters"]}
        check(by_address["10.70.0.1"]["name"] == "core1",
              f"A is named from its Nodes device ({by_address['10.70.0.1']['name']})")
        check(by_address["10.70.0.2"]["name"] == "edge2.example.net",
              f"B falls back to DNS ({by_address['10.70.0.2']['name']})")
        check(by_address["10.70.0.3"]["name"] is None,
              "C has no name at all")
        check(by_address["10.70.0.1"]["state"] == "active",
              f"A, seen 60s ago, is active ({by_address['10.70.0.1']['state']})")
        check(by_address["10.70.0.2"]["state"] == "idle",
              f"B, seen 15m ago, is idle ({by_address['10.70.0.2']['state']})")
        check(by_address["10.70.0.3"]["state"] == "silent",
              f"C, seen 2h ago, is silent ({by_address['10.70.0.3']['state']})")
        check(by_address["10.70.0.1"]["bits_per_s"] > 0
              and by_address["10.70.0.1"]["rate_text"],
              f"A's five-minute rate is non-zero and rendered "
              f"({by_address['10.70.0.1']['rate_text']})")
        check(sorted(payload["exporters"], key=lambda e: (e["name"] or "", e["address"]))
              == payload["exporters"], "sorted by name then address")
    finally:
        db.close()


def test_6_get_flow_interfaces_utilisation() -> None:
    print("6: GET /api/netflow/interfaces utilisation math against a known speed")
    db, nodes, app, collector, t0, t1 = _exporters_fixture("exporters6.db")
    try:
        payload = api.get_flow_interfaces(
            service(db, nodes_db=nodes, app_db=app, collector=collector),
            {"t0": str(t0), "t1": str(t1), "exporter": "10.70.0.1"}, None)
        rows = {r["if_index"]: r for r in payload["interfaces"]}
        row = rows.get(1)
        check(row is not None, "interface 1 is reported")
        if row is not None:
            check(row["speed_bps"] == 1_000_000_000,
                  f"speed comes from the Nodes interfaces row ({row['speed_bps']})")
            check(row["name"] == "Gi0/1", f"named from Nodes descr ({row['name']})")
            check(abs(row["in_util"] - 0.1) < 1e-9,
                  f"1.25 GB of 'in' bytes over 100s against 1 Gbit is 10% "
                  f"util ({row['in_util']})")
            check(abs(row["out_util"] - 0.05) < 1e-9,
                  f"625 MB of 'out' bytes over the same window is 5% util "
                  f"({row['out_util']})")
            check(row["in_text"] and row["out_text"], "rate text is rendered both ways")
    finally:
        db.close()


# ------------------------------------------------------------------------- 7

def test_7_overview_exporter_names_and_records_only() -> None:
    print("7: overview exporters carry a name; records_only follows the filter")
    db = FlowDatabase(os.path.join(TMPDIR, "overview.db"))
    try:
        now = time.time()
        db.touch_exporters([("10.70.0.1", 9, 10, 100, 1)])
        # A week of history, spread daily, so a 3-day window sits mostly
        # behind raw retention and can only be answered from a rollup once
        # one covers it.
        rows = [flow(i, now - 6 * 86400 + i * (6 * 86400 / 2000),
                    exporter="10.70.0.1") for i in range(2000)]
        db.insert_flows(rows)
        cover(db)

        nodes = StubNodesDb(
            devices={"10.70.0.1": device_row(1, "10.70.0.1", sys_name="core1")},
            interfaces={})
        svc = service(db, nodes_db=nodes, app_db=None)

        params = {"t0": str(now - 3 * 86400), "t1": str(now), "dimension": "Application"}
        overview = api.get_flow_overview(svc, params, None)
        exporters = {row["address"]: row["name"] for row in overview["exporters"]}
        check(exporters.get("10.70.0.1") == "core1",
              f"the overview's exporter list carries the resolved name "
              f"({exporters.get('10.70.0.1')})")

        src_params = {**params, "src": "192.168.0.1"}
        src_overview = api.get_flow_overview(svc, src_params, None)
        check(src_overview["records_only"] is True,
              "a src filter has no rollup scope, so it is records_only "
              f"({src_overview['records_only']})")

        exp_params = {**params, "exporter": "10.70.0.1"}
        exp_overview = api.get_flow_overview(svc, exp_params, None)
        check(exp_overview["records_only"] is False,
              "an exporter filter is rollup-served once the exporter scope "
              f"covers the window ({exp_overview['records_only']})")
    finally:
        db.close()


# ------------------------------------------------------------------------- 8

def test_8_iface_direction_filters_narrow_records() -> None:
    print("8: iface/direction filters narrow the records list")
    db = FlowDatabase(os.path.join(TMPDIR, "recfilter.db"))
    try:
        now = time.time()
        rows = [
            flow(0, now - 10, exporter="10.80.0.1", in_if=5, out_if=6),
            flow(1, now - 9, exporter="10.80.0.1", in_if=6, out_if=5),
            flow(2, now - 8, exporter="10.80.0.1", in_if=7, out_if=8),
        ]
        db.insert_flows(rows)
        params = {"t0": str(now - 60), "t1": str(now), "exporter": "10.80.0.1",
                  "iface": "5", "direction": "in"}
        payload = api.get_flow_records(service(db), params, None)
        addrs = {(r["src_ip"], r["dst_ip"]) for r in payload["records"]}
        expected = {(rows[0].src_ip, rows[0].dst_ip)}
        check(addrs == expected,
              f"iface=5, direction=in keeps only the flow that entered on 5 "
              f"({addrs})")
    finally:
        db.close()


TESTS = [
    ("1", test_1_routes_registered),
    ("2", test_2_sequence_gaps_v5_v9_ipfix),
    ("3", test_3_resolve_names_batched),
    ("4", test_4_check_netflow_settings_rollup_interface_days),
    ("5", test_5_get_flow_exporters),
    ("6", test_6_get_flow_interfaces_utilisation),
    ("7", test_7_overview_exporter_names_and_records_only),
    ("8", test_8_iface_direction_filters_narrow_records),
]


def main() -> int:
    try:
        for name, fn in TESTS:
            run(name, fn)
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"{len(FAILS)} CHECK(S) FAILED:")
        for item in FAILS:
            print(f"  - {item}")
        return 1
    print("ALL NETFLOW EXPORTERS API ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

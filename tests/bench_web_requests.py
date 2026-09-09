"""Every request the browser waits on, timed against a real server.

Deliberately not a test_*.py: what a route costs depends on the disk and the
CPU under it, so this prints numbers rather than asserting them (run_all.py
only picks up test_*.py).

    python3 tests/bench_web_requests.py [devices ...] [--tabs N] [--iterations N]

Each `devices` figure is one run: a `Service` over ten SQLite files in a
throwaway directory and a `WebServer` on a free loopback port, seeded with
that many devices (with interfaces), plus alerts, polling profiles and
device groups, then driven with `http.client` over one keep-alive
connection — the same connection a browser holds open. Defaults to
`250 1000`, `--tabs 25`, `--iterations 20`.

The fixture is built straight through the database objects, never through
the API: the API is the thing being measured, and seeding a thousand
devices through POST /api/nodes/devices would time the fixture builder.

Three columns come from the server's own instrumentation rather than from
the wire — `sql`, `lock ms`, and the `sql/s` of the polling row. They read
whatever per-store lock and per-route latency counters `/api/debug`
exposes: a snapshot is taken either side of each route's batch and the
numeric leaves whose names mention sql/queries or a lock are diffed. On a
build where `/api/debug` carries no such fields the columns print `-`,
which is what happens today — the instrumentation is being added on a
separate branch, and this bench deliberately does not depend on it.
"""
import gzip
import http.client
import json
import os
import re
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)
from _paths import tmpdir

# Before anything that stores a credential is imported: the real DPAPI is
# Windows-only and the shipped secret paths refuse without it. Nothing here
# stores a secret, but Service constructs the stores that would.
import netpath.dpapi as dpapi_mod  # noqa: E402
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda plaintext: b"FAKE:" + bytes(plaintext)
dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

from netpath import __version__  # noqa: E402
from netpath.web.server import WebServer  # noqa: E402
from netpath.web.service import Service  # noqa: E402

# Positional, in Service.__init__'s order — the same list test_web_security
# passes.
DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")

PASSWORD = "correct horse battery staple"
IFACES_PER_DEVICE = 8
ALERTS = 1200
PROFILES = 12          # nodesdb "groups" — the Profiles table in the UI
DEVICE_GROUPS = 20
POLL_INTERVAL_S = 2.0  # what app.js's state tick uses
VENDORS = ("Cisco", "Juniper", "Arista", "Moxa")

# A real sysDescr is a banner, not a label. The devices list serialises it,
# so a 40-character placeholder would understate every payload this bench
# reports by more than the gzip saves.
SYS_DESCR = (
    "%s Internetwork Operating System Software, IOS (tm) C3560 Software "
    "(C3560-IPSERVICESK9-M), Version 12.2(55)SE%d, RELEASE SOFTWARE (fc2), "
    "Copyright (c) 1986-2019 by cisco Systems, Inc., Compiled Mon "
    "%02d-Feb-19 03:%02d by prod_rel_team")

# The routes, in the order the columns read best: the shell first, then the
# reads a tab fires, then the two writes. Every path here is copied from
# server.py's ROUTES table (or is a static file under netpath/web/static).
# (label, method, path, body-or-None)
ROUTES = [
    ("GET /", "GET", "/", None),
    ("GET /app.js", "GET", "/app.js", None),
    ("GET /api/state", "GET", "/api/state", None),
    ("GET /api/config", "GET", "/api/config", None),
    ("GET /api/nodes/devices?limit=50", "GET",
     "/api/nodes/devices?limit=50&offset=0", None),
    ("GET /api/nodes/groups", "GET", "/api/nodes/groups", None),
    ("GET /api/nodes/device-groups", "GET", "/api/nodes/device-groups", None),
    ("GET /api/nodes/mibs", "GET", "/api/nodes/mibs", None),
    ("GET /api/alerts?limit=300", "GET", "/api/alerts?limit=300", None),
    ("GET /api/dashboard", "GET", "/api/dashboard", None),
    ("GET /api/debug", "GET", "/api/debug", None),
    ("POST /api/settings (nodes)", "POST", "/api/settings",
     {"scope": "nodes", "values": {}}),
    ("POST /api/settings (netflow)", "POST", "/api/settings",
     {"scope": "netflow", "values": {}}),
    # {id} is filled in with a real device once the fleet is seeded.
    ("PUT /api/nodes/devices/{id}", "PUT", "/api/nodes/devices/{id}",
     {"poll_interval_s": 60}),
]

# What the browser fetches before it can paint anything: index.html and the
# FIVE files its <head>/<script> tags name — tokens.css, app.css, boot.js,
# app.js, dashboard.js. boot.js is easy to miss and is the one that runs
# first, so leaving it out would understate the shell by a whole request.
#
# Each is asked for as `?v=<version>`, the way index.html spells it, because
# `_static` reads `versioned = "v" in params` and answers a versioned URL
# from the immutable-cache branch instead of comparing an ETag. The plain
# `GET /app.js` row in ROUTES above is deliberately the other branch.
FIRST_PAINT = ["/"] + [
    "%s?v=%s" % (path, __version__)
    for path in ("/tokens.css", "/app.css", "/boot.js", "/app.js",
                 "/dashboard.js")]


def nodes_tick(device_id, can_write=True):
    """Exactly what nodes.js fires per refresh tick.

    `refresh()` (nodes.js) awaits five calls in one Promise.all — devices,
    groups, device-groups, mibs and loadDiscJobsIfNeeded() — and then
    `loadDetail()`, which posts the fast-poll focus renewal, fetches the
    device row, fetches ONE sub-pane (whichever nested subtab is on screen,
    per DETAIL_SUBS) and awaits loadStatusTimeline(). Nine, not the twelve
    it was before the detail panes stopped all being fetched while four of
    the five were hidden; Addresses draws off the device row and so makes
    eight. loadWebRelays() is not here: it runs on selection change, not on
    every tick, which loadDetail says in as many words.

    Interfaces is the sub-pane modelled below because it is the one the tab
    opens on.
    """
    now = time.time()
    base = "/api/nodes/devices/%d" % device_id
    calls = [
        ("GET", "/api/nodes/devices?limit=50&offset=0", None),
        ("GET", "/api/nodes/groups", None),
        ("GET", "/api/nodes/device-groups", None),
        ("GET", "/api/nodes/mibs", None),
        ("GET", "/api/nodes/discovery", None),
    ]
    if can_write:
        calls.append(("POST", base + "/focus", {}))
    calls.extend([
        ("GET", base, None),
        ("GET", base + "/interfaces", None),
        ("GET", base + "/timeline?t0=%d&t1=%d" % (now - 86400, now), None),
    ])
    return calls


# --------------------------------------------------------------- the client

class Client:
    """One keep-alive connection, reopened if the server closes it."""

    def __init__(self, port):
        self.port = port
        self.cookie = ""
        self.conn = None
        self._connect()

    def _connect(self):
        if self.conn is not None:
            self.conn.close()
        self.conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                               timeout=60)
        self.conn.connect()

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def send(self, method, path, body=None, retry=True):
        """(status, ms, plain_bytes, wire_bytes, payload).

        `Accept-Encoding: gzip` on every request, the way a browser sends
        it, so `wire_bytes` is what actually crossed the socket and
        `plain_bytes` is what the page received. The clock stops before the
        decompress, which is the client's cost, not the server's.
        """
        headers = {"Accept-Encoding": "gzip", "Connection": "keep-alive"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        started = time.perf_counter()
        try:
            self.conn.request(method, path, payload, headers)
            response = self.conn.getresponse()
            raw = response.read()
        except (http.client.HTTPException, OSError):
            if not retry:
                raise
            self._connect()
            return self.send(method, path, body, retry=False)
        ms = (time.perf_counter() - started) * 1000.0
        if response.getheader("Content-Encoding") == "gzip":
            plain = gzip.decompress(raw)
        else:
            plain = raw
        head = {k.lower(): v for k, v in response.getheaders()}
        if "set-cookie" in head:
            self.cookie = head["set-cookie"].split(";")[0]
        try:
            parsed = json.loads(plain.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return response.status, ms, len(plain), len(raw), parsed

    def sign_in(self):
        """admin/admin, the forced password change, then in again.

        The seeded account is a way in, not an account: every module read is
        refused until `must_change` is lifted. The second sign-in is not
        belt-and-braces — post_password calls sessions.destroy_user, so the
        cookie that changed the password is dead by the time it returns.
        """
        status, _ms, _n, _w, _p = self.send(
            "POST", "/api/login", {"username": "admin", "password": "admin"})
        if status != 200 or not self.cookie:
            raise RuntimeError("could not sign in as admin/admin: %s" % status)
        status, _ms, _n, _w, payload = self.send(
            "POST", "/api/password",
            {"current_password": "admin", "new_password": PASSWORD})
        if status != 200:
            raise RuntimeError("could not lift must_change: %s %s"
                               % (status, payload))
        self.cookie = ""
        status, _ms, _n, _w, payload = self.send(
            "POST", "/api/login", {"username": "admin", "password": PASSWORD})
        if status != 200 or not self.cookie:
            raise RuntimeError("could not sign back in: %s %s"
                               % (status, payload))


# ------------------------------------------------- /api/debug instrumentation

# Leaf names that would carry a statement count, and ones that would carry
# time spent waiting on a store lock. Matched against the last path segment
# only, so a section called "sql" does not make every number under it one.
SQL_LEAF = re.compile(r"(^|_)(sql|queries|query_count|statements)s?$", re.I)
LOCK_LEAF = re.compile(r"lock", re.I)


def _flatten(obj, prefix="", out=None, depth=0):
    """Every numeric leaf of a JSON payload, keyed by its path.

    Lists are skipped: on /api/debug they are the event stream and the
    worker tables, which are rows rather than counters, and walking them
    would make the diff below depend on how many events happened to be
    buffered.
    """
    if out is None:
        out = {}
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            _flatten(value, prefix + "/" + str(key), out, depth + 1)
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (int, float)):
        out[prefix] = float(obj)
    return out


def _diff(before, after):
    return {key: value - before.get(key, 0.0) for key, value in after.items()}


def _sum_for(delta, leaf_re, route_path, to_ms=False):
    """The delta's total for one kind of counter, preferring per-route rows.

    A per-route table keyed by the path (however the lead ends up spelling
    it) is the number this column wants; a process-wide counter is the
    fallback, and is only meaningful because nothing else is talking to
    this server. Returns None when neither exists, which is what prints `-`.
    """
    matched = {key: value for key, value in delta.items()
               if leaf_re.search(key.rsplit("/", 1)[-1])}
    if not matched:
        return None
    scoped = {key: value for key, value in matched.items()
              if route_path and route_path in key}
    chosen = scoped or matched
    total = 0.0
    for key, value in chosen.items():
        leaf = key.rsplit("/", 1)[-1]
        if to_ms and leaf.endswith("_s") and not leaf.endswith("_ms"):
            value *= 1000.0
        total += value
    return total


class DebugProbe:
    """Snapshots /api/debug either side of a batch and diffs the counters.

    `self_cost` is what one snapshot request itself adds, measured from two
    back-to-back snapshots at the start, and subtracted from every window —
    the "after" call's own work would otherwise be charged to the route
    that was being timed.
    """

    def __init__(self, client):
        self.client = client
        self.ok = False
        self.instrumented = False
        self.self_cost = {}
        first = self.snapshot()
        second = self.snapshot()
        if first is not None and second is not None:
            self.self_cost = _diff(first, second)
            self.ok = True
            self.instrumented = any(
                SQL_LEAF.search(key.rsplit("/", 1)[-1])
                or LOCK_LEAF.search(key.rsplit("/", 1)[-1]) for key in second)

    def snapshot(self):
        status, _ms, _n, _w, payload = self.client.send("GET", "/api/debug")
        if status != 200 or not isinstance(payload, dict):
            return None
        return _flatten(payload)

    def window(self, before, after, route_path):
        """(sql, lock_ms) per the diff, or (None, None) with no counters."""
        if before is None or after is None:
            return None, None
        delta = _diff(before, after)
        for key, value in self.self_cost.items():
            if key in delta:
                delta[key] -= value
        return (_sum_for(delta, SQL_LEAF, route_path),
                _sum_for(delta, LOCK_LEAF, route_path, to_ms=True))


# ---------------------------------------------------------------- the fixture

def seed(service, devices):
    """The fleet, straight through the database objects the server holds.

    add_devices_bulk rather than add_device per row for the same reason the
    bulk-import route uses it: add_device commits once per device, and a
    thousand commits would put the fixture's cost in the "seeded in" line
    for no gain — it is the same INSERT either way. Identity and interfaces
    then go through the shipped per-device writers, because those are the
    calls that produce the row shape the read routes serialise.
    """
    nodes = service.nodes_db
    default_group = nodes.ensure_default_group()

    profiles = [default_group]
    for n in range(PROFILES - 1):
        profiles.append(nodes.add_group(
            "profile-%02d" % (n + 1), poll_interval_s=60 + n,
            snmp_version=2, community="public"))
    device_groups = [nodes.add_device_group("site-%02d" % n)
                     for n in range(DEVICE_GROUPS)]

    rows = []
    for n in range(devices):
        rows.append({
            "ip": "10.%d.%d.%d" % (n // 65025, n // 255 % 255, n % 255),
            "name": "sw-%04d.site%02d" % (n, n % DEVICE_GROUPS),
            "group_id": profiles[n % len(profiles)],
            "device_group_id": device_groups[n % len(device_groups)],
            "overrides": {},
        })
    device_ids = nodes.add_devices_bulk(rows)

    for index, device_id in enumerate(device_ids):
        nodes.seed_identity(
            device_id,
            sys_descr=SYS_DESCR % (VENDORS[index % 4], index % 9,
                                   1 + index % 28, index % 60),
            sys_name="sw-%04d" % index,
            sys_object_id="1.3.6.1.4.1.9.1.%d" % (100 + index % 40),
            vendor=VENDORS[index % 4],
            vendor_source="sysobjectid", vendor_confidence="high")
        nodes.replace_interfaces(device_id, [
            {"if_index": port + 1,
             "descr": "GigabitEthernet0/%d" % (port + 1),
             "alias": "uplink" if port == 0 else "access-%d" % (port + 1),
             "phys_addr": "00:1b:%02x:%02x:%02x:%02x"
                          % (index >> 8 & 255, index & 255, 0, port),
             "speed_bps": 1000000000, "admin_status": "up",
             "oper_status": "up" if port % 7 else "down"}
            for port in range(IFACES_PER_DEVICE)])

    seed_alerts(service, device_ids)
    return device_ids


def seed_alerts(service, device_ids):
    """`ALERTS` rows spread over the last week, three in five still open.

    Written as one transaction rather than through open_or_increment,
    which commits per alert: the shape of the row is identical, and the
    rows are the fixture, not the thing being measured (the same reason
    bench_flow_overview.py seeds flows with executemany)."""
    alerts = service.alerts_db
    rule_id = alerts.add_rule("bench.rule", "Bench rule", "threshold", "device")
    now = time.time()
    states = ("open", "open", "open", "acked", "resolved")
    with alerts._lock:
        alerts._conn.executemany(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, detail, state, count,"
            " opened_ts, last_ts, last_notified_ts, extra_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'{}')",
            [(rule_id, "bench:%d" % n, "device",
              str(device_ids[n % len(device_ids)]) if device_ids else "0",
              "sw-%04d" % (n % max(len(device_ids), 1)),
              1 + n % 4,
              "Interface GigabitEthernet0/%d is down" % (1 + n % 48),
              "link down for %d minutes" % (n % 600),
              states[n % len(states)], 1 + n % 5,
              now - 604800 + n * (604800.0 / max(ALERTS, 1)),
              now - 604800 + n * (604800.0 / max(ALERTS, 1)) + 60,
              None if n % 3 else now - 3600)
             for n in range(ALERTS)])
        alerts._conn.commit()


# ----------------------------------------------------------------- the timing

def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = int(round((len(ordered) - 1) * fraction))
    return ordered[index]


def measure(client, probe, method, path, body, iterations):
    """One route, `iterations` times, after a warm-up that is not counted.

    The warm-up matters: the static cache, the settings dicts and SQLite's
    page cache are all cold on the first hit, and a p50 that includes it
    describes the first request after a restart rather than the route.
    """
    client.send(method, path, body)
    before = probe.snapshot() if probe.ok else None
    samples = []
    plain = wire = status = 0
    for _ in range(iterations):
        status, ms, plain, wire, _payload = client.send(method, path, body)
        samples.append(ms)
    after = probe.snapshot() if probe.ok else None
    route_path = path.split("?")[0]
    sql, lock_ms = probe.window(before, after, route_path)
    if sql is not None:
        sql /= iterations
    if lock_ms is not None:
        lock_ms /= iterations
    return {
        "status": status,
        "p50": percentile(samples, 0.50),
        "p95": percentile(samples, 0.95),
        "max": max(samples),
        "bytes": plain,
        "gzip": wire,
        "sql": sql,
        "lock_ms": lock_ms,
    }


def number(value, digits=1):
    return "-" if value is None else ("%.*f" % (digits, value))


HEADER = ("%-34s %9s %9s %9s %10s %9s %7s %9s"
          % ("route", "p50 ms", "p95 ms", "max ms", "bytes", "gzip", "sql",
             "lock ms"))


def row(label, result):
    return ("%-34s %9.2f %9.2f %9.2f %10s %9s %7s %9s"
            % (label[:34], result["p50"], result["p95"], result["max"],
               "{:,}".format(result["bytes"]), "{:,}".format(result["gzip"]),
               number(result["sql"], 1), number(result["lock_ms"], 2)))


COMPOSITE_HEADER = ("%-34s %9s %10s %9s %8s %7s %9s"
                    % ("composite", "total ms", "bytes", "gzip", "requests",
                       "sql", "lock ms"))


def composite_row(label, total_ms, plain, wire, count, sql, lock_ms):
    return ("%-34s %9.2f %10s %9s %8d %7s %9s"
            % (label[:34], total_ms,
               "-" if plain is None else "{:,}".format(plain),
               "-" if wire is None else "{:,}".format(wire),
               count, number(sql, 1), number(lock_ms, 2)))


def composites(client, probe, device_id, tabs, iterations):
    """The three numbers an operator would recognise: how long the shell
    takes to arrive, what one Nodes refresh costs, and what a wall of open
    tabs costs the server just by being open."""
    lines = [COMPOSITE_HEADER]

    # first paint -------------------------------------------------------
    for path in FIRST_PAINT:
        client.send("GET", path)
    before = probe.snapshot() if probe.ok else None
    total_ms = 0.0
    plain_total = wire_total = 0
    for _ in range(iterations):
        plain_total = wire_total = 0
        for path in FIRST_PAINT:
            _s, ms, plain, wire, _p = client.send("GET", path)
            total_ms += ms
            plain_total += plain
            wire_total += wire
    after = probe.snapshot() if probe.ok else None
    sql, lock_ms = probe.window(before, after, "")
    lines.append(composite_row(
        "first paint", total_ms / iterations, plain_total, wire_total,
        len(FIRST_PAINT), _per(sql, iterations), _per(lock_ms, iterations)))

    # nodes tab tick ----------------------------------------------------
    calls = nodes_tick(device_id)
    for method, path, body in calls:
        client.send(method, path, body)
    before = probe.snapshot() if probe.ok else None
    total_ms = 0.0
    for _ in range(iterations):
        for method, path, body in calls:
            _s, ms, _plain, _wire, _p = client.send(method, path, body)
            total_ms += ms
    after = probe.snapshot() if probe.ok else None
    sql, lock_ms = probe.window(before, after, "")
    lines.append(composite_row(
        "nodes tab tick", total_ms / iterations, None, None, len(calls),
        _per(sql, iterations), _per(lock_ms, iterations)))

    # T tabs polling /api/state -----------------------------------------
    state = measure(client, probe, "GET", "/api/state", None, iterations)
    server_ms_per_s = tabs * state["p50"] / POLL_INTERVAL_S
    sql_per_s = (None if state["sql"] is None
                 else tabs * state["sql"] / POLL_INTERVAL_S)
    lines.append("%d tabs polling /api/state every %gs: %.0f server ms/s, "
                 "%s sql/s (p50 %.2f ms and %s statements each)"
                 % (tabs, POLL_INTERVAL_S, server_ms_per_s, number(sql_per_s, 1),
                    state["p50"], number(state["sql"], 1)))
    return lines


def _per(value, iterations):
    return None if value is None else value / iterations


# --------------------------------------------------------------------- a run

def run(folder, devices, tabs, iterations):
    data_dir = os.path.join(folder, "fleet-%d" % devices)
    os.makedirs(data_dir, exist_ok=True)
    service = Service(*[os.path.join(data_dir, name + ".db")
                        for name in DB_NAMES])
    started = time.monotonic()
    device_ids = seed(service, devices)
    seeded_s = time.monotonic() - started

    port = _paths.free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port)
    if not server.start(block=False):
        print("SKIP: could not bind 127.0.0.1:%d: %s" % (port, server.error))
        service.shutdown()
        return
    client = Client(port)
    try:
        client.sign_in()
        probe = DebugProbe(client)
        print("\n%d devices x %d interfaces, %d alerts, %d profiles, "
              "%d device groups (seeded in %.1f s)"
              % (devices, IFACES_PER_DEVICE, ALERTS, PROFILES, DEVICE_GROUPS,
                 seeded_s))
        print("  %d iterations per route, one keep-alive connection, "
              "Accept-Encoding: gzip" % iterations)
        if not probe.instrumented:
            print("  /api/debug carries no sql/lock counters on this build, "
                  "so those two columns read `-`")
        print("  " + HEADER)
        for label, method, path, body in ROUTES:
            real_path = path.replace("{id}", str(device_ids[0]))
            real_label = label.replace("{id}", str(device_ids[0]))
            result = measure(client, probe, method, real_path, body, iterations)
            if result["status"] >= 400:
                real_label += " [HTTP %d]" % result["status"]
            print("  " + row(real_label, result))
        print()
        for line in composites(client, probe, device_ids[0], tabs, iterations):
            print("  " + line)
    finally:
        client.close()
        try:
            server.stop()
        finally:
            service.shutdown()


def main(argv):
    sizes = []
    tabs = 25
    iterations = 20
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--tabs":
            index += 1
            tabs = int(argv[index])
        elif item == "--iterations":
            index += 1
            iterations = int(argv[index])
        elif item.startswith("--"):
            print(__doc__)
            return 2
        else:
            sizes.append(int(item.replace("_", "")))
        index += 1
    sizes = sizes or [250, 1000]

    folder = tmpdir("bench_web_requests_")
    print("scratch: %s" % folder)
    try:
        for devices in sizes:
            run(folder, devices, tabs, iterations)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

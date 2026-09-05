"""4.49.0: bounds-checking the NetPath target fields that reach a subprocess
argument, a worst-case runtime budget, or the scheduler's own arithmetic —
netpath/db.py's _clamp_target_fields already clamps these silently as a
backstop for any caller that is not this route (a test, a migration, a
future internal path); this suite is the visible half, against a real
Service+WebServer: POST/PUT /api/netpath/targets and POST /api/settings
(scope=netpath) reject an out-of-range value with a 400 naming the field
and both bounds, rather than silently rewrite it the way db.py's own
backstop does.

Also covers the one-line addition of `truncated_ttls` to GET
/api/netpath/topology's response (analysis.Topology already computed and
carried this; nothing in the JSON surfaced it before now) — a shape check,
not a forced-truncation scenario (constructing one needs 65+ distinct
addresses answering at a single TTL in one trace, out of proportion to
what this one-line wiring fix needs proving).

Bounds under test (netpath/db.py's own MIN_*/MAX_* constants):
  interval_s   5 .. 2,592,000 (30 days)
  max_hops     1 .. 255
  probes       1 .. 20
  timeout_s    0.1 .. 30.0
  warn_rtt_ms  0 .. (open-ended)
  warn_loss    0 .. 100
  trace_workers, default_interval_s/max_hops/probes/timeout_s: the same
  bounds, via POST /api/settings (scope=netpath).
"""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("target_validation_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if (method != "GET" and body is not None) else None
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": username, "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # --------------------------------------------------------- post_target
    print("POST /api/netpath/targets: a plain, in-range target succeeds")
    status, payload = call("POST", "/api/netpath/targets",
                           {"host": "10.90.9.1", "interval_s": 60, "max_hops": 20,
                            "probes": 3, "timeout_s": 2.0, "warn_rtt_ms": 150.0,
                            "warn_loss": 10.0}, token=admin)
    check("200", status == 200, (status, payload))
    check("a target with no overrides at all (pure defaults) also succeeds",
          call("POST", "/api/netpath/targets", {"host": "10.90.9.2"}, token=admin)[0] == 200)

    print("POST /api/netpath/targets: each out-of-range field is refused")
    OUT_OF_RANGE = [
        ("interval_s", 0), ("interval_s", 2_592_001),
        ("max_hops", 0), ("max_hops", 256),
        ("probes", 0), ("probes", 21),
        ("timeout_s", 0.0), ("timeout_s", 30.1),
        ("warn_rtt_ms", -1.0),
        ("warn_loss", -1.0), ("warn_loss", 100.1),
    ]
    for field, bad_value in OUT_OF_RANGE:
        body = {"host": "10.90.9.3", field: bad_value}
        status, payload = call("POST", "/api/netpath/targets", body, token=admin)
        check(f"{field}={bad_value} -> 400 naming the field",
              status == 400 and field in str(payload.get("error", "")),
              (status, payload))

    print("POST /api/netpath/targets: each field's bounds are inclusive")
    AT_BOUNDS = [("interval_s", 5), ("interval_s", 2_592_000),
                ("max_hops", 1), ("max_hops", 255),
                ("probes", 1), ("probes", 20),
                ("timeout_s", 0.1), ("timeout_s", 30.0),
                ("warn_rtt_ms", 0.0), ("warn_loss", 0.0), ("warn_loss", 100.0)]
    for field, edge_value in AT_BOUNDS:
        body = {"host": "10.90.9.4", field: edge_value}
        status, payload = call("POST", "/api/netpath/targets", body, token=admin)
        check(f"{field}={edge_value} (a bound itself) -> 200", status == 200, (status, payload))

    # ---------------------------------------------------------- put_target
    print("PUT /api/netpath/targets/<id>: same bounds on update")
    status, payload = call("POST", "/api/netpath/targets", {"host": "10.90.9.5"}, token=admin)
    target_id = payload["id"]
    status, payload = call("PUT", f"/api/netpath/targets/{target_id}",
                           {"interval_s": 0}, token=admin)
    check("interval_s=0 on PUT -> 400", status == 400, (status, payload))
    status, payload = call("PUT", f"/api/netpath/targets/{target_id}",
                           {"probes": 999}, token=admin)
    check("probes=999 on PUT -> 400", status == 400, (status, payload))
    status, payload = call("PUT", f"/api/netpath/targets/{target_id}",
                           {"max_hops": 100}, token=admin)
    check("an in-range PUT still succeeds", status == 200, (status, payload))
    status, payload = call("GET", "/api/netpath/targets", token=admin)
    row = next(t for t in payload["targets"] if t["id"] == target_id)
    check("...and the refused PUTs above did not silently apply anyway",
          row["interval_s"] != 0 and row["probes"] != 999 and row["max_hops"] == 100,
          row)

    # ------------------------------------------------- settings (netpath scope)
    print("POST /api/settings (scope=netpath): the same five fields")
    for key, bad_value in [("trace_workers", 0), ("trace_workers", 65),
                           ("default_interval_s", 0), ("default_max_hops", 300),
                           ("default_probes", 21), ("default_timeout_s", 31.0)]:
        status, payload = call("POST", "/api/settings",
                               {"scope": "netpath", "values": {key: bad_value}}, token=admin)
        check(f"{key}={bad_value} -> 400", status == 400 and key in str(payload.get("error", "")),
              (status, payload))
    status, payload = call("POST", "/api/settings",
                           {"scope": "netpath", "values": {"trace_workers": 8}}, token=admin)
    check("trace_workers=8 (in range) -> 200", status == 200, (status, payload))
    check("...and actually took effect", service.settings.get("trace_workers") == 8,
          service.settings.get("trace_workers"))

    # -------------------------------------------------------------- topology
    print("GET /api/netpath/topology carries truncated_ttls")
    status, payload = call("GET", f"/api/netpath/topology?target={target_id}", token=admin)
    check("200", status == 200, (status, payload))
    check("truncated_ttls is present and a list (empty here — no fanout to truncate)",
          isinstance(payload.get("truncated_ttls"), list), payload.get("truncated_ttls"))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)

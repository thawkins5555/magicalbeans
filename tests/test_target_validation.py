"""NetPath target field validation over HTTP, against a real Service+WebServer:
POST/PUT /api/netpath/targets and POST /api/settings (scope=netpath) reject
an out-of-range interval_s/max_hops/probes/timeout_s/warn_* value with a 400
naming the field and both bounds (netpath/db.py's MIN_*/MAX_* constants),
rather than silently clamping. Also a shape check that GET /api/netpath/topology
carries `truncated_ttls`. netpath.monitor.run_trace is stubbed (no real tracer).
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401

import netpath.monitor as monitor_mod
from netpath import httpcheck
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.tracer import TraceResult
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("target_validation_")
FAILS = []

_real_run_trace = monitor_mod.run_trace


def _instant_run_trace(host, **kwargs):
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=0.0)


monitor_mod.run_trace = _instant_run_trace


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
    for index, (field, edge_value) in enumerate(AT_BOUNDS):
        # targets.host is UNIQUE — a distinct host per case, not shared.
        body = {"host": f"10.90.10.{index}", field: edge_value}
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

    # ------------------------------------------------------ https_url field
    print("POST/PUT /api/netpath/targets: the web page URL")
    status, payload = call("POST", "/api/netpath/targets",
                           {"host": "10.90.11.1",
                            "https_url": "https://10.90.11.1/status",
                            "https_insecure": True}, token=admin)
    https_id = payload.get("id")
    check("a destination can be created with an https:// URL", status == 200,
          (status, payload))
    status, payload = call("GET", "/api/netpath/targets", token=admin)
    row = next(t for t in payload["targets"] if t["id"] == https_id)
    check("...and it comes back on the target, with the opt-out",
          row["https_url"] == "https://10.90.11.1/status"
          and row["https_insecure"] is True, row)
    check("...with no check recorded yet, so https_state is 'none'",
          row["https_state"] == "none" and row["https_last_ts"] is None, row)

    for index, bad_url in enumerate(["http://10.90.11.9/", "ftp://10.90.11.9/",
                                     "10.90.11.9", "https://",
                                     "https://" + "x" * 3000]):
        status, payload = call("POST", "/api/netpath/targets",
                               {"host": f"10.90.12.{index}", "https_url": bad_url},
                               token=admin)
        check(f"https_url={bad_url[:24]!r} -> 400 naming the field",
              status == 400 and "https_url" in str(payload.get("error", "")),
              (status, payload))

    status, payload = call("PUT", f"/api/netpath/targets/{https_id}",
                           {"https_url": "http://10.90.11.1/"}, token=admin)
    check("an http:// URL on PUT -> 400", status == 400, (status, payload))
    status, payload = call("PUT", f"/api/netpath/targets/{https_id}",
                           {"https_url": "https://10.90.11.1/health",
                            "https_insecure": False}, token=admin)
    check("an https:// URL on PUT -> 200", status == 200, (status, payload))
    status, payload = call("GET", "/api/netpath/targets", token=admin)
    row = next(t for t in payload["targets"] if t["id"] == https_id)
    check("...and the round trip stored both fields",
          row["https_url"] == "https://10.90.11.1/health"
          and row["https_insecure"] is False, row)
    status, payload = call("PUT", f"/api/netpath/targets/{https_id}",
                           {"https_url": ""}, token=admin)
    status, payload = call("GET", "/api/netpath/targets", token=admin)
    row = next(t for t in payload["targets"] if t["id"] == https_id)
    check("an empty URL turns the check off rather than being refused",
          row["https_url"] == "", row)

    print("GET /api/netpath/https: the bucketed series for the web lane")
    status, payload = call("GET", f"/api/netpath/https?target={https_id}", token=admin)
    check("200 with no URL configured, and nothing to draw",
          status == 200 and payload["buckets"] == []
          and payload["summary"]["state"] == "none", (status, payload))
    call("PUT", f"/api/netpath/targets/{https_id}",
         {"https_url": "https://10.90.11.1/health"}, token=admin)
    service.db.record_https_check(
        https_id, httpcheck.HttpsResult(False, 503, 42.0, "HTTP 503",
                                        "https://10.90.11.1/health"))
    status, payload = call("GET", f"/api/netpath/https?target={https_id}", token=admin)
    failing = [b for b in payload["buckets"] if b["total"]]
    check("the recorded check lands in exactly one bucket", len(failing) == 1,
          [b for b in payload["buckets"] if b["total"]])
    check("...carrying ok_pct, the latency and the reason",
          failing and failing[0]["ok_pct"] == 0.0
          and failing[0]["avg_latency_ms"] == 42.0
          and failing[0]["last_error"] == "HTTP 503", failing[:1])
    check("...and the summary reports the destination down",
          payload["summary"]["state"] == "down"
          and payload["summary"]["last_status_code"] == 503
          and payload["summary"]["checks"] == 1, payload["summary"])

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
    monitor_mod.run_trace = _real_run_trace
    server.stop()

raise SystemExit(1 if FAILS else 0)

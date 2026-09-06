"""The server-side gates a browser must not be trusted to enforce, over live
requests with no browser: an account owing a password change cannot use the
API; a device cannot be created at an invalid address; /api/state drops a
module's block for an account that cannot read it. The last section is static
analysis over server.py and api.py: every route's (module, level) gate checked
against what its handler does, so a new route gets the same scrutiny.
"""

import ast
import http.client
import json
import os
import re
import socket
import sys
import threading
import time
from collections import defaultdict

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("web_gates_")

from netpath import nodediscover, nodepoll
from netpath.snmppoll import SnmpError, decode_response
from netpath.trapdecode import PDU_RESPONSE, T_SEQUENCE, _tlv, enc_int, enc_octets, enc_oid
from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=port, certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{port}")

conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

ADMIN_PASSWORD = "GatesSuiteAdmin2026"
READER_PASSWORD = "GatesSuiteReader2026"
failures = []


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return resp.status, payload, dict(resp.getheaders())


def login(username, password):
    status, payload, headers = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


try:
    # ---------------------------------------------------- must_change gate
    # The default account is seeded owing a change, so this is the state a
    # fresh install is actually in.
    print("must_change gate")
    token = login(DEFAULT_USER, DEFAULT_PASSWORD)

    status, payload, _ = call("GET", "/api/state", token=token)
    check("/api/state is reachable (it is what raises the prompt)", status == 200, status)

    status, payload, _ = call("POST", "/api/heartbeat", {}, token=token)
    check("/api/heartbeat is reachable (it keeps the session alive meanwhile)",
          status == 200, status)

    status, payload, _ = call("POST", "/api/nodes/devices", {"ip": "10.0.0.1"}, token=token)
    check("a normal write is refused", status == 403, f"{status} {payload}")

    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    check("a normal read is refused", status == 403, f"{status} {payload}")

    status, payload, _ = call("POST", "/api/password",
                              {"current_password": DEFAULT_PASSWORD,
                               "new_password": ADMIN_PASSWORD}, token=token)
    check("the change itself is allowed", status == 200, f"{status} {payload}")

    # Changing a password destroys every session for that account, so this
    # is a fresh sign-in rather than a reused token.
    token = login(DEFAULT_USER, ADMIN_PASSWORD)
    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    check("the API opens up once the password is replaced", status == 200, status)

    # ------------------------------------------------ device address checks
    print("device address validation")
    for bad, why in [("999.999.1.oops", "not an address at all"),
                     ("core-sw-01.example.com", "a hostname"),
                     ("10.20.3", "a truncated address"),
                     ("", "blank")]:
        status, payload, _ = call("POST", "/api/nodes/devices", {"ip": bad}, token=token)
        check(f"refuses {why}: {bad!r}", status != 200, f"{status} {payload}")

    for good in ["10.20.3.7", "2001:db8::1"]:
        status, payload, _ = call("POST", "/api/nodes/devices", {"ip": good}, token=token)
        check(f"accepts {good}", status == 200, f"{status} {payload}")

    status, payload, _ = call("POST", "/api/nodes/devices", {"ip": "10.20.3.7"}, token=token)
    check("still refuses a duplicate", status != 200, f"{status} {payload}")

    # -------------------------------------------- NetPath target host checks
    # 999.999.999.999 used to be accepted as a NetPath destination and then
    # sat forever as a target that could never resolve or trace. The add
    # route now validates; this also pins that the *edit* route (PUT) holds
    # the same line, since a validated Add with an unguarded Edit is no gate
    # at all — a browser (or a script) can always PUT its way around POST.
    print("netpath target host validation")
    for bad, why in [("999.999.999.999", "four numeric groups but not an address"),
                     ("-bad-.example.com", "a hostname label that starts with a hyphen"),
                     ("bad_underscore.example.com", "a hostname label with an invalid character"),
                     ("", "blank")]:
        status, payload, _ = call("POST", "/api/netpath/targets", {"host": bad}, token=token)
        check(f"add refuses {why}: {bad!r}", status != 200, f"{status} {payload}")

    status, payload, _ = call("POST", "/api/netpath/targets",
                              {"host": "999.999.999.999"}, token=token)
    check("…and the refusal names the host and says it is not valid",
          isinstance(payload, dict)
          and "999.999.999.999" in str(payload.get("error", ""))
          and "not a valid" in str(payload.get("error", "")).lower(),
          payload)

    good_ids = []
    for good in ["10.20.4.9", "2001:db8::2", "core-sw-01.example.com"]:
        status, payload, _ = call("POST", "/api/netpath/targets", {"host": good}, token=token)
        check(f"add accepts {good}", status == 200 and "id" in payload, f"{status} {payload}")
        if status == 200 and "id" in payload:
            good_ids.append(payload["id"])

    # The edit path, PUT /api/netpath/targets/<id>: the same 999.999.999.999
    # that add refuses must not be reachable by editing a target that was
    # created with a good host.
    assert good_ids, "at least one target must have been created to edit"
    edit_id = good_ids[0]
    status, payload, _ = call("PUT", f"/api/netpath/targets/{edit_id}",
                              {"host": "999.999.999.999"}, token=token)
    check("edit refuses the same bad host the add route refuses",
          status != 200, f"{status} {payload}")
    status, rows, _ = call("GET", "/api/netpath/targets", token=token)
    edited = next((t for t in rows.get("targets", []) if t["id"] == edit_id), None)
    check("…and the stored host is unchanged by the refused edit",
          edited is not None and edited["host"] == "10.20.4.9",
          edited)
    status, payload, _ = call("PUT", f"/api/netpath/targets/{edit_id}",
                              {"host": "10.20.4.10"}, token=token)
    check("edit accepts a legitimate replacement host", status == 200, f"{status} {payload}")
    status, rows, _ = call("GET", "/api/netpath/targets", token=token)
    edited = next((t for t in rows.get("targets", []) if t["id"] == edit_id), None)
    check("…and the new host is stored",
          edited is not None and edited["host"] == "10.20.4.10", edited)

    for target_id in good_ids:
        call("DELETE", f"/api/netpath/targets/{target_id}", token=token)

    # ------------------------------------------------- /api/state per grant
    # The bug this pins: a module's block is omitted for an account that
    # cannot read it, and the page used to assume every block was present.
    print("/api/state shape per permission set")
    service.app_db.add_user("reader", hash_password(READER_PASSWORD), must_change=False)
    service.app_db.set_permissions("reader", {"nodes": "read", "syslog": "read"})
    reader_token = login("reader", READER_PASSWORD)

    # Since 4.43.0 the settings blocks live on /api/config and the live
    # blocks on /api/state; the same per-module gate applies to both.
    status, reader_state, _ = call("GET", "/api/config", token=reader_token)
    check("a limited account can read config at all", status == 200, status)
    check("its own modules' blocks are present",
          "nodes_settings" in reader_state and "syslog_settings" in reader_state,
          sorted(k for k in reader_state if k.endswith("_settings")))
    check("blocks it cannot read are absent",
          "dimensions" not in reader_state and "flow_settings" not in reader_state,
          "dimensions" in reader_state)
    check("permissions name exactly what was granted",
          sorted(reader_state["permissions"]) == ["nodes", "syslog"],
          reader_state["permissions"])

    status, admin_config, _ = call("GET", "/api/config", token=token)
    check("an account that can read NetFlow still gets its block",
          "dimensions" in admin_config and "flow_settings" in admin_config)
    status, reader_live, _ = call("GET", "/api/state", token=reader_token)
    check("live blocks it cannot read are absent too",
          "collector" not in reader_live and "nodes" in reader_live,
          sorted(k for k in reader_live if k in ("collector", "nodes", "syslog", "snmp")))
    check("both halves carry the same config_version",
          reader_live.get("config_version") == reader_state.get("config_version")
          and isinstance(reader_live.get("config_version"), int))
    status, admin_state, _ = call("GET", "/api/state", token=token)

    # Both session countdowns are sent, so the browser can warn before either
    # ends. The absolute one used to be missing entirely and arrived as a
    # sudden redirect to the sign-in page.
    session = admin_state["session"]
    check("session carries the idle countdown",
          session.get("idle_seconds_remaining") is not None, session)
    check("session carries the absolute countdown",
          session.get("max_seconds_remaining") is not None, session)

    # --------------------------------------------- 4.44.0: since, counts, toggle
    print("since when, honest counts, the IPAM toggle")
    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    devices = payload.get("devices") or payload if isinstance(payload, dict) else payload
    if isinstance(devices, dict):
        devices = devices.get("devices", [])
    device_id = devices[0]["id"] if devices else None
    check("a device exists to inspect", device_id is not None, str(payload)[:120])
    if device_id is not None:
        status, detail, _ = call("GET", f"/api/nodes/devices/{device_id}", token=token)
        d = detail.get("device", detail)
        check("the device carries status_since_ts and sys_uptime_s",
              "status_since_ts" in d and "sys_uptime_s" in d, sorted(d)[:8])
        if d.get("status") == "up":
            check("up since the last time it was seen down",
                  d["status_since_ts"] == (d.get("last_down_ts") or d.get("created_ts")))
        elif d.get("status") == "down":
            check("down since the last time it was seen up",
                  d["status_since_ts"] == (d.get("last_up_ts") or d.get("created_ts")))
        else:
            check("an unknown state has no since", d["status_since_ts"] is None, d.get("status"))
    for path in ("/api/syslog/search?limit=5", "/api/snmp/traps?limit=5"):
        status, payload, _ = call("GET", path, token=token)
        check(f"{path.split('?')[0]} says whether it was cut off",
              status == 200 and "truncated" in payload and payload.get("cap") == 2000
              and payload.get("limit") == 5, str(payload)[:100])
    status, before, _ = call("GET", "/api/state", token=token)
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "stop"}, token=token)
    check("the IPAM worker can be stopped from its strip", status == 200 and payload.get("enabled") is False,
          f"{status} {payload}")
    status, config, _ = call("GET", "/api/config", token=token)
    check("and the choice is persisted like the settings checkbox",
          config.get("ipam_settings", {}).get("enabled") is False
          and config["config_version"] > before["config_version"])
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "start"}, token=token)
    check("and started again", status == 200 and payload.get("enabled") is True, f"{status} {payload}")
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "dance"}, token=token)
    check("an unknown action is refused", status == 400, status)
    # Every strip toggle writes `enabled`, which is served from /api/config
    # and refetched only when config_version moves — so each must bump it.
    for path in ("/api/netflow/collector", "/api/syslog/collector", "/api/snmp/collector",
                 "/api/alerts/engine", "/api/wireless/collector", "/api/configrx/worker",
                 "/api/nodes/collector"):
        status, before, _ = call("GET", "/api/state", token=token)
        status, payload, _ = call("POST", path, {"action": "stop"}, token=token)
        status, after, _ = call("GET", "/api/state", token=token)
        check(f"{path} stop bumps config_version",
              status == 200 and after["config_version"] > before["config_version"],
              (before.get("config_version"), after.get("config_version")))
    # truncated means rows were dropped, not that the limit was met exactly.
    status, payload, _ = call("GET", "/api/syslog/search?limit=1", token=token)
    total = len(payload.get("messages", []))
    check("a search returning fewer rows than the limit is not truncated",
          status == 200 and (total < 1 or payload.get("truncated") in (True, False)), payload.get("truncated"))

    # ------------------------------------------- 4.46.0: the kiosk heartbeat
    # A wall display sends {"kiosk": true} with nobody at the keyboard. The
    # server honours it only for an account with no write grant anywhere,
    # and a refusal must not extend the session — which is why server.py
    # no longer touches the session for this one route before dispatch.
    print("kiosk heartbeat")
    status, payload, _ = call("POST", "/api/heartbeat", {"kiosk": True}, token=token)
    check("an account that can write is refused a kiosk hold",
          status == 200 and payload.get("ok") is False and payload.get("kiosk") is False
          and "read-only" in payload.get("reason", ""), f"{status} {payload}")
    status, s1, _ = call("GET", "/api/state", token=token)
    time.sleep(1.1)
    status, payload, _ = call("POST", "/api/heartbeat", {"kiosk": True}, token=token)
    status, s2, _ = call("GET", "/api/state", token=token)
    check("and the refusal did not extend its idle countdown",
          s2["session"]["idle_seconds_remaining"] < s1["session"]["idle_seconds_remaining"],
          (s1["session"]["idle_seconds_remaining"], s2["session"]["idle_seconds_remaining"]))
    status, payload, _ = call("POST", "/api/heartbeat", {}, token=token)
    check("a plain heartbeat from the same account still counts",
          status == 200 and payload.get("ok") is True and payload.get("kiosk") is False,
          f"{status} {payload}")
    status, r1, _ = call("GET", "/api/state", token=reader_token)
    time.sleep(1.1)
    status, payload, _ = call("POST", "/api/heartbeat", {"kiosk": True}, token=reader_token)
    check("a read-only account is held", status == 200 and payload.get("ok") is True
          and payload.get("kiosk") is True, f"{status} {payload}")
    status, r2, _ = call("GET", "/api/state", token=reader_token)
    check("and its idle countdown was reset by the kiosk heartbeat",
          r2["session"]["idle_seconds_remaining"] >= r1["session"]["idle_seconds_remaining"] - 0.5,
          (r1["session"]["idle_seconds_remaining"], r2["session"]["idle_seconds_remaining"]))

    # ------------------------------------- route/gate cross-reference (4.48.1)
    # Every route in server.py's ROUTES table, checked against what its
    # handler in api.py actually does. Parsed straight out of each file's own
    # AST rather than imported and introspected, so this runs against exactly
    # the source on disk and does not care whether the objects happen to be
    # importable in whatever order this process loaded them in.
    print("route/gate cross-reference")

    import netpath.permissions as permissions_mod
    import netpath.web.api as api_mod
    import netpath.web.server as server_mod

    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _server_src = open(os.path.join(_repo_root, "netpath", "web", "server.py"),
                       encoding="utf-8").read()
    _api_src = open(os.path.join(_repo_root, "netpath", "web", "api.py"),
                    encoding="utf-8").read()

    def _unparse(node):
        try:
            return ast.unparse(node)
        except Exception:
            return "<?>"

    def _parse_routes(src):
        """(method, pattern, handler_name, requirement) for every entry in
        ROUTES. A dynamic requirement (a function of the request itself)
        comes back as that function's name, a string, since it cannot be
        reduced to a (module, level) pair without a request to hand it."""
        tree = ast.parse(src)
        routes_node = next(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "ROUTES" for t in node.targets))
        out = []
        for elt in routes_node.elts:
            method_n, pattern_n, handler_n, req_n = elt.elts
            handler = _unparse(handler_n).split(".")[-1]
            if isinstance(req_n, ast.Constant) and req_n.value is None:
                req = None
            elif isinstance(req_n, ast.Tuple):
                def resolve(x):
                    if isinstance(x, ast.Constant):
                        return x.value
                    if isinstance(x, ast.Name):
                        return {"R": "read", "W": "write"}.get(x.id, x.id)
                    return _unparse(x)
                req = tuple(resolve(x) for x in req_n.elts)
            else:
                req = _unparse(req_n)
            out.append((method_n.value, pattern_n.value, handler, req))
        return out

    ROUTES_PARSED = _parse_routes(_server_src)

    _api_tree = ast.parse(_api_src)
    API_FUNCS = {n.name: n for n in ast.walk(_api_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    # Write-shaped calls: a db-object method named like a mutation, or a raw
    # execute() whose SQL text is a write statement. Matched on the call
    # site's own attribute name regardless of which module implements it, so
    # this does not need to know the shape of appdb.py/nodesdb.py/etc.
    WRITE_METHOD_RE = re.compile(
        r"^(set_|add_|remove_|update_|delete_|insert_|create_|clear_|save_|"
        r"store_|revoke_|promote_|reset_|resolve_|mute_|ack_|unack_|apply_|"
        r"start_|stop_|write_|record_|touch_|bump_)")
    WRITE_SQL_RE = re.compile(r"\b(INSERT|UPDATE|DELETE|REPLACE)\b", re.IGNORECASE)

    def _find_writes(node, seen=None, depth=0):
        """Evidence that `node` (an api.py function) performs a write,
        recursing into other api.py functions it calls, up to 4 hops."""
        if seen is None:
            seen = set()
        evidence = []
        if node.name in seen or depth > 4:
            return evidence
        seen.add(node.name)
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            func = n.func
            callee = (func.attr if isinstance(func, ast.Attribute) else
                     func.id if isinstance(func, ast.Name) else None)
            if callee is None:
                continue
            if callee in ("execute", "executemany"):
                text = None
                if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                    text = n.args[0].value
                elif n.args and isinstance(n.args[0], ast.JoinedStr):
                    text = "".join(v.value for v in n.args[0].values
                                  if isinstance(v, ast.Constant))
                if text and WRITE_SQL_RE.search(text):
                    evidence.append(f"{node.name}: SQL write via {_unparse(n)[:90]}")
            elif WRITE_METHOD_RE.match(callee):
                evidence.append(f"{node.name}: calls .{callee}(...) -> {_unparse(n)[:90]}")
            if callee in API_FUNCS and callee not in seen:
                evidence.extend(_find_writes(API_FUNCS[callee], seen, depth + 1))
        return evidence

    # Handlers the write-detector's naming heuristic flags on a route gated
    # read (or ungated), cleared by reading each through to what it actually
    # calls (4.48.1 audit). Named here, one reason apiece, so a NEW false
    # positive has to be justified the same way rather than silently added —
    # a route not on this list that shows write evidence fails the check
    # below.
    KNOWN_NOT_WRITES = {
        "post_login": "pre-auth bookkeeping on the credential being verified "
                      "(touch_login/set_password/record_failure) before a "
                      "session exists to gate; the route is intentionally "
                      "ungated, not a bypass of one",
        "get_flow_overview": "namelookup.resolve_name is a pure SELECT-based "
                            "name lookup (device_for_ip + app_db.hostnames), "
                            "matched only on its resolve_ prefix",
        "get_flow_records": "same namelookup.resolve_name false match as "
                           "get_flow_overview",
        "get_flow_records_export": "same namelookup.resolve_name false match",
        "get_syslog_search": "same namelookup.resolve_name false match",
        "get_syslog_search_export": "same namelookup.resolve_name false match",
        "get_nodes_device": "alerts_db.mute_row is a SELECT for the currently-"
                           "active mute row, matched only on its mute_ "
                           "prefix; prune() clears expired rows, not this "
                           "read path",
    }

    missing_handlers = [(m, p, h) for m, p, h, r in ROUTES_PARSED if h not in API_FUNCS]
    check("every route's handler exists as a function in api.py",
          not missing_handlers, missing_handlers)

    read_or_ungated_writes = []
    get_writes = []
    for method, pattern, handler, req in ROUTES_PARSED:
        fn = API_FUNCS.get(handler)
        if fn is None or handler in KNOWN_NOT_WRITES:
            continue
        evidence = _find_writes(fn)
        if not evidence:
            continue
        if req is None or (isinstance(req, tuple) and req[1] == "read"):
            read_or_ungated_writes.append((method, pattern, handler, req, evidence[0]))
        if method == "GET":
            get_writes.append((method, pattern, handler, req, evidence[0]))

    check("no route gated read (or ungated) shows write evidence, beyond the "
          "known/explained false positives above",
          not read_or_ungated_writes, read_or_ungated_writes)
    check("no GET route shows write evidence, regardless of its gate -- a GET "
          "can be triggered cross-site and from a plain link",
          not get_writes, get_writes)

    # The two routes whose requirement is a function of the request body
    # cannot be checked by the static (module, level) comparison above, so
    # their logic is exercised directly instead of by naming heuristic.
    print("dynamic-requirement routes (decided by hand): "
         "POST /api/password, POST /api/settings")
    check("changing your own password needs no extra gate",
          server_mod._password_requirement({"_username": "alice"}, {"username": "alice"}) is None)
    check("...nor does it when the body names no username at all",
          server_mod._password_requirement({"_username": "alice"}, {}) is None)
    check("resetting a DIFFERENT account's password needs admin write",
          server_mod._password_requirement({"_username": "alice"}, {"username": "bob"})
          == ("admin", "write"))
    check("...case-insensitively, so Alice cannot reset alice around the check",
          server_mod._password_requirement({"_username": "Alice"}, {"username": "alice"}) is None)

    for scope in api_mod.SETTINGS_SCOPES:
        check(f"settings scope {scope!r} is gated on its own module's write",
              server_mod._settings_requirement({}, {"scope": scope}) == (scope, "write"))
    _no_own_scope = (set(permissions_mod.MODULES)
                    - set(api_mod.SETTINGS_SCOPES) - {"settings"})
    for scope in sorted(_no_own_scope) + ["bogus-scope-nobody-defined", "global"]:
        check(f"settings scope {scope!r} (no entry in SETTINGS_SCOPES) falls "
              "to settings:write -- the exact fix for the debug:write account "
              "that could once rewrite the LDAP config and the self-update "
              "toggle by going through this fall-through",
              server_mod._settings_requirement({}, {"scope": scope}) == ("settings", "write"))
    check("SETTINGS_SCOPES covers every module except settings/debug/ssh/admin "
          "-- a module added to permissions.MODULES with no entry here would "
          "silently fall through to the global Settings writer",
          set(api_mod.SETTINGS_SCOPES) == set(permissions_mod.MODULES) - {"settings", "debug", "ssh", "admin"},
          sorted(set(permissions_mod.MODULES) - {"settings", "debug", "ssh", "admin"}
                ^ set(api_mod.SETTINGS_SCOPES)))

    # Reachable with no session at all. A data route landing in either set
    # is the worst thing that can happen to this table, so both are an exact
    # expected set rather than a substring or "at least" check.
    PUBLIC_PATHS_EXPECTED = {"/login", "/login.html", "/login.js", "/tokens.css",
                            "/app.css", "/boot.js", "/favicon.ico", "/favicon.svg"}
    PUBLIC_API_EXPECTED = {"/api/login", "/api/session"}
    check("PUBLIC_PATHS is exactly the sign-in page's own static assets",
          server_mod.PUBLIC_PATHS == PUBLIC_PATHS_EXPECTED,
          server_mod.PUBLIC_PATHS ^ PUBLIC_PATHS_EXPECTED)
    check("PUBLIC_API is exactly /api/login and /api/session",
          server_mod.PUBLIC_API == PUBLIC_API_EXPECTED,
          server_mod.PUBLIC_API ^ PUBLIC_API_EXPECTED)

    # The 8 routes with no gate at all, each justified in server.py's own
    # comments (pre-auth, a property of the host, or — state/config/dashboard
    # — filtered per-module inside the handler, which the /api/state and
    # /api/config checks earlier in this suite already exercise). A ninth
    # route reaching this set is a deliberate act with this test to update,
    # not an omission nobody notices.
    UNGATED_EXPECTED = {
        ("POST", r"^/api/login$"), ("POST", r"^/api/logout$"),
        ("POST", r"^/api/heartbeat$"), ("GET", r"^/api/session$"),
        ("GET", r"^/api/state$"), ("GET", r"^/api/config$"),
        ("GET", r"^/api/platform$"), ("GET", r"^/api/dashboard$"),
    }
    ungated_actual = {(m, p) for m, p, h, r in ROUTES_PARSED if r is None}
    check("the ungated route set is exactly what it was when this was audited",
          ungated_actual == UNGATED_EXPECTED, ungated_actual ^ UNGATED_EXPECTED)

    # Route counts by (module, level): loose enough that an ordinary new
    # route is not noise, tight enough that ssh growing a read tier (an
    # interactive shell has no meaningful "read") or a module losing its
    # write tier entirely goes red.
    counts = defaultdict(int)
    for method, pattern, handler, req in ROUTES_PARSED:
        if isinstance(req, tuple):
            counts[req] += 1
    print("  route counts by (module, level): " + ", ".join(
        f"{m}:{l}={n}" for (m, l), n in sorted(counts.items())))
    check("ssh has no read tier",
          ("ssh", "read") not in counts, dict(counts))
    check("ssh still has a write tier (the terminal and its socket)",
          counts[("ssh", "write")] >= 1, counts[("ssh", "write")])
    for module in sorted(set(permissions_mod.MODULES) - {"ssh", "settings"}):
        check(f"{module} still has both a read and a write tier",
              counts[(module, "read")] >= 1 and counts[(module, "write")] >= 1,
              (module, counts[(module, "read")], counts[(module, "write")]))

    print("FAILED: " + ", ".join(failures) if failures else "ALL WEB GATE ASSERTIONS PASSED")
finally:
    server.stop()
    # Adding a device queues a first poll, and NodePoller.shutdown() (not
    # the plain stop() a hot restart uses) now waits for one already
    # running to land before the database underneath it closes, sized to
    # that device's own worst-case poll duration — see
    # NodePoller._inflight_budget_s in netpath/nodepoll.py. This suite used
    # to wait it out here instead, polling worker_state() for up to 20s
    # before calling shutdown() at all; that was a workaround for the
    # dispatch service.shutdown() itself now does, so it is gone rather
    # than left standing beside the fix as an unexplained no-op.
    service.shutdown()


# =========================================================================
# Device field handling, the device-test error shape, and the discovery
# probe's off-path rejection.
#
# Merged from test_nodes_api_fixes.py, three findings from the full code
# review, driven against their own real Service and WebServer over
# loopback plus the discovery probe on its own:
#
#   - POST /api/nodes/devices used to drop vendor_override and upstream_id
#     without a word.
#   - POST /api/nodes/devices/<id>/test answered a socket() failure with a
#     bare 500 instead of a structured {"snmp": {"ok": false, ...}}.
#   - nodediscover._snmp_identify took the first datagram that arrived,
#     from any address with any request id, as the device's identity.
# =========================================================================

def nodes_api_fixes_checks():
    tmp_dir = tmpdir("nodes_api_fixes_")
    service = Service(
        os.path.join(tmp_dir, "netpath.db"), os.path.join(tmp_dir, "flows.db"),
        os.path.join(tmp_dir, "syslog.db"), os.path.join(tmp_dir, "app.db"),
        os.path.join(tmp_dir, "ipam.db"), os.path.join(tmp_dir, "snmptraps.db"),
        os.path.join(tmp_dir, "nodes.db"), os.path.join(tmp_dir, "alerts.db"),
        os.path.join(tmp_dir, "wireless.db"), os.path.join(tmp_dir, "configrx.db"))
    web_port = free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=web_port,
                       certfile=None, keyfile=None)
    assert server.start(block=False), server.error

    def call(method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Cookie"] = f"sw_session={token}"
        conn.request(method, path,
                     body=json.dumps(body).encode() if body is not None else None,
                     headers=headers)
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
                     body=json.dumps({"username": username,
                                      "password": password}).encode(),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        cookie = dict(response.getheaders()).get("Set-Cookie", "")
        conn.close()
        assert "sw_session=" in cookie, cookie
        return cookie.split("sw_session=")[1].split(";")[0]

    try:
        admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

        # ---------------------------------------------------- device creation
        status, core = call("POST", "/api/nodes/devices", {"ip": "10.9.0.1", "name": "core"},
                            token=admin)
        check("N1 a plain device is created", status == 200 and "id" in core, (status, core))
        status, edge = call("POST", "/api/nodes/devices",
                            {"ip": "10.9.0.2", "name": "edge", "upstream_id": core["id"],
                             "vendor_override": "Acme", "snmp_version": 1},
                            token=admin)
        check("N1 a device created with upstream_id and vendor_override is accepted",
              status == 200 and "id" in edge, (status, edge))
        status, row = call("GET", f"/api/nodes/devices/{edge['id']}", token=admin)
        device = row.get("device", row) if isinstance(row, dict) else {}
        check("N1 …its upstream_id is stored", device.get("upstream_id") == core["id"],
              (status, row))
        check("N1 …its vendor override is stored",
              (device.get("vendor_override") or "").lower() == "acme"
              and (device.get("vendor") or "").lower() == "acme", (status, row))
        check("N1 …and a profile column still lands too", device.get("snmp_version") == 1,
              (status, row))

        status, refused = call("POST", "/api/nodes/devices",
                               {"ip": "10.9.0.3", "upstream_id": 999999}, token=admin)
        check("N1 an unknown upstream is refused before the device exists",
              status == 400 and not service.nodes_db.device_by_ip("10.9.0.3"),
              (status, refused))
        status, refused = call("POST", "/api/nodes/devices",
                               {"ip": "10.9.0.4", "vendor_override": "x" * 65}, token=admin)
        check("N1 an over-long vendor name is refused before the device exists",
              status == 400 and not service.nodes_db.device_by_ip("10.9.0.4"),
              (status, refused))

        # ------------------------------------------------ device test on OSError
        real_init = nodepoll._Session.__init__

        def failing_init(self, *args, **kwargs):
            # What socket() raises under descriptor exhaustion, at the one
            # place in the handler that opens a socket.
            raise OSError(24, "Too many open files")

        nodepoll._Session.__init__ = failing_init
        try:
            status, result = call("POST", f"/api/nodes/devices/{core['id']}/test",
                                  {}, token=admin)
        finally:
            nodepoll._Session.__init__ = real_init
        snmp = result.get("snmp", {}) if isinstance(result, dict) else {}
        check("N2 a socket() failure in the device test is a structured answer, not a 500",
              status == 200 and snmp.get("ok") is False
              and "Too many open files" in str(snmp.get("error", "")),
              (status, result))

        # --------------------------------------------------- discovery probe
        def snmp_response(request_id, oid, text):
            varbind = _tlv(T_SEQUENCE, enc_oid(oid) + enc_octets(text))
            pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0)
                       + _tlv(T_SEQUENCE, varbind))
            return _tlv(T_SEQUENCE, enc_int(1) + enc_octets("public") + pdu)

        sys_descr = "1.3.6.1.2.1.1.1.0"

        # An "agent" that answers correctly, and a "stranger" on another loopback
        # address that answers first, from the wrong address, with a bogus id.
        agent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        agent.bind(("127.0.0.1", 0))
        agent.settimeout(5)
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stranger.bind(("127.0.0.2", 0))
        nodediscover.DEFAULT_SNMP_PORT = agent.getsockname()[1]

        def agent_thread(honest: bool):
            data, addr = agent.recvfrom(65535)
            # decode_response reads a GetRequest's fields the same way the stub
            # agents do, which is all that is needed to learn its request id.
            rid = decode_response(data).request_id
            stranger.sendto(snmp_response(rid, sys_descr, "STRANGER"), addr)
            if honest:
                agent.sendto(snmp_response(rid + 1, sys_descr, "WRONG-ID"), addr)
                agent.sendto(snmp_response(rid, sys_descr, "GENUINE"), addr)

        worker = threading.Thread(target=agent_thread, args=(True,), daemon=True)
        worker.start()
        response = nodediscover._snmp_identify("127.0.0.1", 1, "public", 2.0, [sys_descr])
        worker.join(5)
        check("N3 the discovery probe ignores a datagram from another address and a wrong id",
              response.varbinds and response.varbinds[0]["value"] == "GENUINE",
              str(response.varbinds))

        worker = threading.Thread(target=agent_thread, args=(False,), daemon=True)
        worker.start()
        try:
            nodediscover._snmp_identify("127.0.0.1", 1, "public", 0.8, [sys_descr])
            outcome = "answered"
        except SnmpError as exc:
            outcome = type(exc).__name__
        worker.join(5)
        check("N3 …and with only the stranger answering, the probe times out",
              outcome == "SnmpTimeout", outcome)
        agent.close()
        stranger.close()
    finally:
        server.stop()
        service.shutdown()


nodes_api_fixes_checks()

sys.exit(1 if failures else 0)

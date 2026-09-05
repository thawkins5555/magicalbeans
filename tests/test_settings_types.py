"""B15: settings must be coerced to the type their default declares, so a
`null` or a browser NaN cannot brick startup.

Style of test_security_fixes.py: a real Service + WebServer on a free
loopback port, over a throwaway directory, checked with plain HTTP requests.
Section (d) exercises the POST /api/settings 400-on-bad-input behavior that
the lead adds in api.py's post_settings hook (strict=True); those checks are
exercised end to end against the post_settings hook in
their check name so a red run here is not mistaken for a regression in the
loader-side fix this file otherwise verifies.
"""
import http.client
import json
import math
import os
import shutil

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("settings_types_")

# Before anything that stores a credential is imported.
import netpath.dpapi as dpapi_mod  # noqa: E402
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda plaintext: b"FAKE:" + bytes(plaintext)
dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

from netpath import settingsutil  # noqa: E402
from netpath import appdb as appdb_module  # noqa: E402
from netpath import db as db_module  # noqa: E402
from netpath import nodesdb as nodesdb_module  # noqa: E402
from netpath.web.server import WebServer  # noqa: E402
from netpath.web.service import Service  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def req(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    try:
        conn.request(method, path,
                     json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        data = response.read()
        head = {k.lower(): v for k, v in response.getheaders()}
        try:
            return response.status, head, json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return response.status, head, data
    finally:
        conn.close()


def login(port, username, password):
    status, head, payload = req(port, "POST", "/api/login",
                                 {"username": username, "password": password})
    cookie = head.get("set-cookie", "").split(";")[0]
    return (cookie if status == 200 else ""), status, payload


# ------------------------------------------------------------- (a) unit tests

def test_unit_coerce() -> None:
    d = {"b": True, "i": 4, "f": 2.5, "l": [], "s": "x"}

    check("unit bool 0/1 accepted",
          settingsutil.coerce_settings(d, {"b": 0}, strict=True)["b"] is False
          and settingsutil.coerce_settings(d, {"b": 1}, strict=True)["b"] is True)
    check("unit bool 'true'/'FALSE' accepted",
          settingsutil.coerce_settings(d, {"b": "true"}, strict=True)["b"] is True
          and settingsutil.coerce_settings(d, {"b": "FALSE"}, strict=True)["b"] is False)
    try:
        settingsutil.coerce_settings(d, {"b": "nope"}, strict=True)
        ok = False
    except ValueError as exc:
        ok = "must be a true/false value" in str(exc)
    check("unit bool bad string strict raises", ok)

    check("unit int from numeric string",
          settingsutil.coerce_settings(d, {"i": "6"}, strict=True)["i"] == 6)
    check("unit int from float",
          settingsutil.coerce_settings(d, {"i": 6.0}, strict=True)["i"] == 6)
    check("unit int rejects bool",
          settingsutil.coerce_settings(d, {"i": True}, strict=False)["i"] == d["i"])
    check("unit int rejects None strict raises",
          _raises(lambda: settingsutil.coerce_settings(d, {"i": None}, strict=True)))
    check("unit float from numeric string",
          settingsutil.coerce_settings(d, {"f": "1.5"}, strict=True)["f"] == 1.5)
    check("unit NaN rejected",
          _raises(lambda: settingsutil.coerce_settings(d, {"f": math.nan}, strict=True)))
    check("unit inf rejected",
          _raises(lambda: settingsutil.coerce_settings(d, {"f": math.inf}, strict=True)))
    check("unit NaN falls back to default under strict=False",
          settingsutil.coerce_settings(d, {"f": math.nan}, strict=False)["f"] == d["f"])

    check("unit list of str accepted",
          settingsutil.coerce_settings(d, {"l": ["a@b.com", "c@d.com"]}, strict=True)["l"]
          == ["a@b.com", "c@d.com"])
    check("unit list rejects non-list string strict raises",
          _raises(lambda: settingsutil.coerce_settings(d, {"l": "x"}, strict=True)))
    check("unit list rejects list of non-str strict raises",
          _raises(lambda: settingsutil.coerce_settings(d, {"l": [1, 2]}, strict=True)))

    check("unit str default rejects None strict raises",
          _raises(lambda: settingsutil.coerce_settings(d, {"s": None}, strict=True)))
    check("unit str default rejects list strict raises",
          _raises(lambda: settingsutil.coerce_settings(d, {"s": [1]}, strict=True)))
    check("unit str accepts int/float coerced to str",
          settingsutil.coerce_settings(d, {"s": 7}, strict=True)["s"] == "7")

    check("unit unknown key dropped (strict)",
          "nope" not in settingsutil.coerce_settings(d, {"nope": 1}, strict=True))
    check("unit unknown key dropped (non-strict)",
          "nope" not in settingsutil.coerce_settings(d, {"nope": 1}, strict=False))
    check("unit strict=False bad value returns the default object",
          settingsutil.coerce_settings(d, {"l": "x"}, strict=False)["l"] is d["l"])


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except ValueError:
        return True


# ------------------------------------------------------------- (c) startup

def test_startup_floor() -> None:
    startup_dir = os.path.join(TMPDIR, "startup")
    os.makedirs(startup_dir, exist_ok=True)
    db_path = os.path.join(startup_dir, "netpath.db")
    app_db_path = os.path.join(startup_dir, "app.db")

    netpath_db = db_module.Database(db_path)
    netpath_db.save_settings({"trace_workers": 4})
    with netpath_db._lock:
        netpath_db._conn.execute(
            "INSERT INTO settings(key,value) VALUES ('trace_workers','null')"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        netpath_db._conn.commit()
    netpath_db.close()

    app_db = appdb_module.AppDatabase(app_db_path)
    with app_db._lock:
        app_db._conn.execute(
            "INSERT INTO settings(key,value) VALUES ('dns_workers','\"abc\"')"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        app_db._conn.commit()
    app_db.close()

    other_names = ("flows", "syslog", "ipam", "snmptraps", "nodes",
                   "alerts", "wireless", "configrx")
    paths = [os.path.join(startup_dir, name + ".db") for name in other_names]

    service = None
    try:
        service = Service(db_path, paths[0], paths[1], app_db_path, paths[2],
                           paths[3], paths[4], paths[5], paths[6], paths[7])
        check("startup a poisoned trace_workers/dns_workers DB still constructs Service",
              True)
        check("startup poisoned trace_workers falls back to the default",
              service.settings["trace_workers"] == db_module.NETPATH_DEFAULTS["trace_workers"])
        check("startup poisoned dns_workers falls back to the default",
              service.settings["dns_workers"] == appdb_module.GLOBAL_DEFAULTS["dns_workers"])
    except Exception as exc:  # pragma: no cover - the bug this test guards against
        check("startup a poisoned trace_workers/dns_workers DB still constructs Service",
              False, f"{type(exc).__name__}: {exc}")
    finally:
        if service is not None:
            service.shutdown()


# --------------------------------------------------------------------- main

def main() -> int:
    test_unit_coerce()

    data_dir = os.path.join(TMPDIR, "data")
    os.makedirs(data_dir, exist_ok=True)
    db_names = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
                "nodes", "alerts", "wireless", "configrx")
    service = Service(*[os.path.join(data_dir, name + ".db") for name in db_names])
    port = _paths.free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port)
    if not server.start(block=False):
        print(f"SKIP: could not bind 127.0.0.1:{port}: {server.error}")
        return 77

    try:
        # --------------------------------------------------------- (b) loader floor
        with service.nodes_db._lock:
            service.nodes_db._conn.execute(
                "INSERT INTO settings(key,value) VALUES ('poll_workers','null')"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            service.nodes_db._conn.commit()
        check("loader nodes_db poisoned poll_workers falls back to default",
              service.nodes_db.settings()["poll_workers"]
              == nodesdb_module.DEFAULTS["poll_workers"])

        with service.db._lock:
            service.db._conn.execute(
                "INSERT INTO settings(key,value) VALUES ('trace_workers','null')"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            service.db._conn.commit()
        check("loader netpath db poisoned trace_workers falls back to default",
              service.db.settings()["trace_workers"]
              == db_module.NETPATH_DEFAULTS["trace_workers"])

        with service.app_db._lock:
            service.app_db._conn.execute(
                "INSERT INTO settings(key,value) VALUES ('dns_workers','\"abc\"')"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            service.app_db._conn.commit()
        check("loader appdb poisoned dns_workers falls back to default",
              service.app_db.settings()["dns_workers"]
              == appdb_module.GLOBAL_DEFAULTS["dns_workers"])

        # ------------------------------------------------------------- login
        admin_cookie, status, _p = login(port, "admin", "admin")
        check("login as the seeded admin", status == 200 and bool(admin_cookie))
        ADMIN_PASSWORD = "correct horse battery staple 15"
        status, _h, _p = req(port, "POST", "/api/password",
                              {"current_password": "admin",
                               "new_password": ADMIN_PASSWORD},
                              cookie=admin_cookie)
        check("clear must_change so the settings API is reachable", status == 200)
        admin_cookie, status, _p = login(port, "admin", ADMIN_PASSWORD)
        check("login again after the password change", status == 200)

        # ---------------------------------------------------------- (d) HTTP
        before = service.settings.get("trace_workers")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "netpath",
                                    "values": {"trace_workers": None}},
                                   cookie=admin_cookie)
        check("HTTP null trace_workers -> 400",
              status == 400, f"{status} {payload}")
        check("HTTP null trace_workers left service.settings unchanged",
              service.settings.get("trace_workers") == before,
              str(service.settings.get("trace_workers")))

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "netpath",
                                    "values": {"trace_retention_days": "abc"}},
                                   cookie=admin_cookie)
        check("HTTP non-numeric trace_retention_days -> 400",
              status == 400, f"{status} {payload}")

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "netpath",
                                    "values": {"trace_workers": "6"}},
                                   cookie=admin_cookie)
        check("HTTP numeric-string trace_workers -> 200",
              status == 200, f"{status} {payload}")
        check("HTTP trace_workers coerced to int 6",
              service.settings.get("trace_workers") == 6
              and isinstance(service.settings.get("trace_workers"), int)
              and not isinstance(service.settings.get("trace_workers"), bool),
              str(service.settings.get("trace_workers")))

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "alerts",
                                    "values": {"smtp_to_default": "x"}},
                                   cookie=admin_cookie)
        check("HTTP non-list smtp_to_default -> 400",
              status == 400, f"{status} {payload}")

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_workers": "4"}},
                                   cookie=admin_cookie)
        # A partial body must not reset what it does not mention: the
        # coercion helper once returned every default padded in, and
        # apply_* update()s the live dict with whatever it is handed.
        before = dict(service.settings)
        status, _h, _p = req(port, "POST", "/api/settings",
                             {"scope": "global", "values": {"dns_timeout_s": 4.5}},
                             cookie=admin_cookie)
        untouched = {k: v for k, v in before.items() if k != "dns_timeout_s"}
        after = {k: v for k, v in service.settings.items() if k != "dns_timeout_s"}
        check("HTTP a one-key body leaves every other setting as it was",
              status == 200 and after == untouched,
              str([(k, untouched.get(k), after.get(k)) for k in untouched
                   if untouched.get(k) != after.get(k)][:5]))
        check("HTTP numeric-string dns_workers -> 200",
              status == 200, f"{status} {payload}")
        check("HTTP dns_workers coerced to int 4",
              service.settings.get("dns_workers") == 4
              and isinstance(service.settings.get("dns_workers"), int),
              str(service.settings.get("dns_workers")))

        # ------------------------------------------------- (e) range guard
        # P1-7: a value that types fine but is out of the field's own
        # min/max (dns_workers is 1..32 on both the Settings page and here)
        # must be refused too, not just a wrong type.
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_workers": 999}},
                                   cookie=admin_cookie)
        check("HTTP dns_workers out of range (999) -> 400",
              status == 400, f"{status} {payload}")
        check("HTTP refused dns_workers left service.settings unchanged",
              service.settings.get("dns_workers") == 4,
              str(service.settings.get("dns_workers")))

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"session_idle_minutes": 0}},
                                   cookie=admin_cookie)
        check("HTTP session_idle_minutes below its floor (0) -> 400",
              status == 400, f"{status} {payload}")

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"max_trace_db_mb": 8}},
                                   cookie=admin_cookie)
        check("HTTP max_trace_db_mb below its floor (8), which has no ceiling -> 400",
              status == 400, f"{status} {payload}")

        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_workers": 32}},
                                   cookie=admin_cookie)
        check("HTTP dns_workers at its upper bound (32) -> 200",
              status == 200, f"{status} {payload}")

        # The low end of the same field, not just the high end above.
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_workers": 0}},
                                   cookie=admin_cookie)
        check("HTTP dns_workers below its floor (0) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_workers": 1}},
                                   cookie=admin_cookie)
        check("HTTP dns_workers at its lower bound (1) -> 200",
              status == 200, f"{status} {payload}")

        # A member of the *_refresh_s family other than the ones already
        # exercised above, both ends: these keys share the same range check
        # but are a distinct block in _GLOBAL_SETTINGS_RANGES.
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"netpath_refresh_s": 301}},
                                   cookie=admin_cookie)
        check("HTTP netpath_refresh_s above its ceiling (301) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"netpath_refresh_s": 300}},
                                   cookie=admin_cookie)
        check("HTTP netpath_refresh_s at its ceiling (300) -> 200",
              status == 200, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"netpath_refresh_s": 0}},
                                   cookie=admin_cookie)
        check("HTTP netpath_refresh_s below its floor (0) -> 400",
              status == 400, f"{status} {payload}")

        # session_max_hours: the session-lifetime sibling of session_idle_
        # minutes above, untested there — both ends of its own range (1-168).
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"session_max_hours": 0}},
                                   cookie=admin_cookie)
        check("HTTP session_max_hours below its floor (0) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"session_max_hours": 169}},
                                   cookie=admin_cookie)
        check("HTTP session_max_hours above its ceiling (169) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"session_max_hours": 168}},
                                   cookie=admin_cookie)
        check("HTTP session_max_hours at its ceiling (168) -> 200",
              status == 200, f"{status} {payload}")

        # dns_timeout_s: a float-typed member of the range table, both ends
        # (0.5-30) — every other range check above is on an integer field.
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_timeout_s": 0.4}},
                                   cookie=admin_cookie)
        check("HTTP dns_timeout_s below its floor (0.4) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_timeout_s": 30.1}},
                                   cookie=admin_cookie)
        check("HTTP dns_timeout_s above its ceiling (30.1) -> 400",
              status == 400, f"{status} {payload}")
        status, _h, payload = req(port, "POST", "/api/settings",
                                   {"scope": "global",
                                    "values": {"dns_timeout_s": 30}},
                                   cookie=admin_cookie)
        check("HTTP dns_timeout_s at its ceiling (30) -> 200",
              status == 200, f"{status} {payload}")
    finally:
        try:
            server.stop()
            service.shutdown()
        except Exception:
            pass

    test_startup_floor()
    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed: " + ", ".join(FAILS))
        code = 1
    else:
        print("\nall checks passed")
    raise SystemExit(code)

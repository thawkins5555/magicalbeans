#!/usr/bin/env python3
"""Seed a running SappiWhere instance with the demo fleet.

Standard library only. Talks to the app the same way a browser does — an
`http.client` connection carrying the `sw_session` cookie, every write sent
as `application/json` because `netpath/web/server.py:468-472` refuses any
other content type on POST/PUT/DELETE.

    python3 demo/seed.py --base http://127.0.0.1:8443 --count 250 --out demo/out

Every step prints one line and appends an entry to `<out>/seed_log.json`
recording the endpoint, the HTTP status and the server's error text. Steps
that are *expected* to fail on Linux (anything that stores a secret, which
goes through Windows DPAPI) are called anyway and their refusal recorded as
evidence — see `netpath/web/api.py:2453` and friends.

The script is idempotent: it looks up device groups, polling profiles,
NetPath targets, subnets and controllers by name before creating them, and
skips devices whose IP is already present.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import sys
import time
from urllib.parse import urlparse, urlencode

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- fleet plan
#
# demo/personas.py is written by another builder. Import it lazily and fall
# back to a plan of the same shape so this script is developable and testable
# on its own.

FALLBACK_SITES = ("Site-A", "Site-B", "Site-C")

# index -> (persona, name, profile, knobs) for the scripted special devices.
FALLBACK_SPECIALS = {
    0: ("cisco_core", "core-sw-01", "v2c-public", {}),
    1: ("fortigate_wlc", "wlc-01", "v2c-public", {}),
    2: ("cisco_access", "sw-v1only-01", "v1-public", {"v1_only": True}),
    3: ("cisco_access", "sw-badcomm-01", "v2c-public",
        {"device_community": "wrong-community"}),
    4: ("cisco_access", "sw-authfail-01", "v3-sha", {"auth_fail": True}),
    5: ("cisco_access", "sw-slow-01", "v2c-public", {"slow_ms": 1800}),
    6: ("cisco_access", "sw-toobig-01", "v2c-public", {"too_big": True}),
    7: ("cisco_access", "sw-wrap32-01", "v2c-public", {"wrap32": True}),
    8: ("cisco_chassis", "sw-chassis-01", "v2c-public", {"ports": 500}),
    9: ("cisco_access", "sw-v3noauth-01", "v3-noauth", {}),
    10: ("cisco_access", "sw-v3sha-01", "v3-sha", {}),
    11: ("cisco_access", "sw-dark-01", "v2c-public", {"scheduled_dark": True}),
    12: ("cisco_access", "sw-reboot-01", "v2c-public", {"periodic_reboot": True}),
}


def loopback_ip(index: int) -> str:
    """127.0.0.2 upwards, one address per fleet index."""
    value = 0x7F000002 + int(index)
    return "%d.%d.%d.%d" % ((value >> 24) & 255, (value >> 16) & 255,
                            (value >> 8) & 255, value & 255)


def fallback_fleet_plan(count: int) -> list[dict]:
    """The same shape personas.fleet_plan(count) returns, for solo runs."""
    plan = []
    for index in range(count):
        persona, name, profile, knobs = FALLBACK_SPECIALS.get(
            index, ("cisco_access", "acc-sw-%03d" % index, "v2c-public", {}))
        if index in FALLBACK_SPECIALS:
            site = FALLBACK_SITES[0]
        else:
            site = FALLBACK_SITES[0] if index < 500 else FALLBACK_SITES[
                1 + (index % 2)]
        snmp_version = {"v1-public": 0, "v2c-public": 1,
                        "v3-noauth": 3, "v3-sha": 3}[profile]
        community = knobs.get("device_community") or (
            "public" if snmp_version in (0, 1) else "")
        plan.append({
            "index": index, "ip": loopback_ip(index), "name": name,
            "persona": persona, "site": site, "snmp_version": snmp_version,
            "community": community, "profile": profile, "knobs": dict(knobs),
        })
    return plan


def load_fleet_plan():
    """(callable, source-name). Tolerates personas.py not existing yet."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        import personas  # type: ignore
    except Exception as exc:                       # noqa: BLE001 - developing
        print("[seed] demo/personas.py unavailable (%s: %s); "
              "using the built-in fallback plan" % (type(exc).__name__, exc))
        return fallback_fleet_plan, "fallback"
    plan = getattr(personas, "fleet_plan", None)
    if not callable(plan):
        print("[seed] demo/personas.py has no fleet_plan(); using the fallback")
        return fallback_fleet_plan, "fallback"
    return plan, "personas.py"


# ------------------------------------------------------------------- client

class ApiError(Exception):
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload
        super().__init__("HTTP %s: %s" % (status, error_text(payload)))


def error_text(payload) -> str:
    if isinstance(payload, dict):
        return str(payload.get("error", ""))
    return str(payload)[:400]


class Client:
    """One keep-alive connection carrying the sw_session cookie."""

    def __init__(self, base: str, timeout: float = 60.0):
        parsed = urlparse(base)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.timeout = timeout
        self.cookie = ""
        self.username = ""
        self._creds = None
        self.relogins = 0
        self._conn = None
        self.log = None                     # set by main(); a SeedLog
        self.step = ""

    # -- plumbing ---------------------------------------------------------

    def _connection(self):
        if self._conn is None:
            if self.scheme == "https":
                import ssl
                context = ssl._create_unverified_context()
                self._conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=self.timeout, context=context)
            else:
                self._conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout)
        return self._conn

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:               # noqa: BLE001
                pass
            self._conn = None

    def raw(self, method: str, path: str, body=None):
        """(status, payload, headers). Never raises for an HTTP error."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.cookie:
            headers["Cookie"] = "sw_session=%s" % self.cookie
        data = None
        if method in ("POST", "PUT", "DELETE"):
            data = json.dumps(body if body is not None else {}).encode("utf-8")
        last = None
        for attempt in (1, 2):
            try:
                conn = self._connection()
                conn.request(method, path, body=data, headers=headers)
                response = conn.getresponse()
                blob = response.read()
                try:
                    payload = json.loads(blob.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    payload = {"error": blob[:400].decode("utf-8", "replace")}
                result = (response.status, payload,
                          {k.lower(): v for k, v in response.getheaders()},
                          len(blob))
                break
            except (http.client.HTTPException, OSError) as exc:
                last = exc
                self.close()
                if attempt == 2:
                    result = (0, {"error": "%s: %s" % (type(exc).__name__, exc)},
                              {}, 0)
        status, payload, response_headers, size = result
        if self.log is not None:
            self.log.record(self.step, method, path, status,
                            error_text(payload) if status >= 400 or status == 0 else "",
                            bytes_read=size)
        return status, payload, response_headers

    def call(self, method: str, path: str, body=None):
        status, payload, _headers = self.raw(method, path, body)
        if status == 401 and self._creds and path != "/api/login":
            # The server's idle timeout (10 min by default) counts browser
            # input only, so a script polling the API is signed out mid-run
            # regardless of how busy it is. There are no API tokens; the only
            # remedy is to log in again.
            self.relogins += 1
            self.login(*self._creds)
            status, payload, _headers = self.raw(method, path, body)
        if status < 200 or status >= 300:
            raise ApiError(status, payload)
        return payload

    def get(self, path, **params):
        if params:
            path = "%s?%s" % (path, urlencode(
                {k: v for k, v in params.items() if v is not None}))
        return self.call("GET", path)

    def post(self, path, body=None):
        return self.call("POST", path, body if body is not None else {})

    def put(self, path, body=None):
        return self.call("PUT", path, body if body is not None else {})

    # -- session ----------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        self.cookie = ""
        status, payload, headers = self.raw(
            "POST", "/api/login", {"username": username, "password": password})
        if status != 200:
            raise ApiError(status, payload)
        cookie = headers.get("set-cookie", "")
        if "sw_session=" in cookie:
            self.cookie = cookie.split("sw_session=")[1].split(";")[0]
        self.username = payload.get("username", username)
        self._creds = (username, password)
        return payload


# ---------------------------------------------------------------- seed log

class SeedLog:
    def __init__(self, path: str):
        self.path = path
        self.entries: list[dict] = []
        self.notes: list[dict] = []
        self.refusals: list[dict] = []

    def record(self, step, method, path, status, error="", bytes_read=0):
        self.entries.append({
            "ts": round(time.time(), 3), "step": step, "method": method,
            "endpoint": path, "status": status, "error": error,
            "bytes": bytes_read,
        })
        # Keep the file current after every call: a crashed run still leaves
        # the evidence behind.
        self.flush()

    def note(self, step, message, **extra):
        self.notes.append({"step": step, "message": message, **extra})
        self.flush()

    def refusal(self, step, endpoint, status, text):
        self.refusals.append({"step": step, "endpoint": endpoint,
                              "status": status, "error": text})
        self.flush()

    def flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({"calls": self.entries, "notes": self.notes,
                       "refusals": self.refusals}, handle, indent=1)
        os.replace(tmp, self.path)


# ------------------------------------------------------------- credentials

WORDS = ("copper", "lantern", "harbor", "quartz", "meadow", "cinder", "ledger",
         "tundra", "willow", "basalt", "orchid", "pylon", "kestrel", "marble")


def strong_password(seed_word: str = "") -> str:
    """A 16+ character word-ish password that clears auth.py's rules:
    >=12 chars, not in COMMON_PASSWORDS, not equal to the username,
    >=5 distinct characters (netpath/auth.py:146-165)."""
    parts = [secrets.choice(WORDS), secrets.choice(WORDS),
             str(secrets.randbelow(9000) + 1000)]
    if seed_word:
        parts.insert(1, seed_word)
    text = "-".join(parts)
    while len(text) < 16:
        text += secrets.choice("abcdefghjkmnpqrstuvwxyz")
    return text


def read_creds(path: str) -> dict:
    creds = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                creds[key.strip()] = value.strip()
    except OSError:
        pass
    return creds


def write_creds(path: str, creds: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# SappiWhere demo credentials — generated by demo/seed.py\n")
        for key in sorted(creds):
            handle.write("%s=%s\n" % (key, creds[key]))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# -------------------------------------------------------------- seed steps

PROFILES = [
    # name,           fields for POST /api/nodes/groups (_GROUP_EDITABLE_BODY)
    ("v2c-public", {"snmp_version": 1, "community": "public",
                    "poll_interval_s": 60, "snmp_timeout_s": 2,
                    "snmp_retries": 1, "mac_table_interval_s": 300}),
    ("v1-public", {"snmp_version": 0, "community": "public",
                   "poll_interval_s": 60, "snmp_timeout_s": 2,
                   "snmp_retries": 1, "mac_table_interval_s": 300}),
    ("v3-noauth", {"snmp_version": 3, "v3_user": "poller", "v3_auth_proto": "",
                   "poll_interval_s": 60, "snmp_timeout_s": 2,
                   "snmp_retries": 1, "mac_table_interval_s": 300}),
    ("v3-sha", {"snmp_version": 3, "v3_user": "poller", "v3_auth_proto": "SHA",
                "poll_interval_s": 60, "snmp_timeout_s": 2,
                "snmp_retries": 1, "mac_table_interval_s": 300}),
]

PROFILE_COMMUNITY = {"v2c-public": "public", "v1-public": "public",
                     "v3-noauth": "", "v3-sha": ""}

NETPATH_TARGETS = [
    ("10.0.0.1", "NetPath multihop"),
    ("10.0.0.2", "NetPath route change"),
    ("10.0.0.3", "NetPath admin refused (!X)"),
    ("10.0.0.4", "NetPath silent hop"),
    ("10.0.0.5", "NetPath dead destination"),
    ("10.0.0.6", "NetPath degraded path"),
    ("127.0.0.2", "Core switch (loopback fleet)"),
]

SITES = ("Site-A", "Site-B", "Site-C")


def step_login(client: Client, log: SeedLog, creds_path: str) -> dict:
    """1. Sign in, clearing the forced first-run password change if needed."""
    client.step = "1-login"
    creds = read_creds(creds_path)
    admin_password = creds.get("admin_password", "")

    if admin_password:
        try:
            payload = client.login("admin", admin_password)
            print("[1] login admin (from creds.txt) -> ok, "
                  "must_change=%s" % payload.get("must_change"))
            return {"password": admin_password, "changed": False}
        except ApiError as exc:
            print("[1] stored admin password rejected (%s); trying admin/admin"
                  % exc.status)

    payload = client.login("admin", "admin")
    must_change = bool(payload.get("must_change"))
    print("[1] login admin/admin -> ok, must_change=%s" % must_change)
    if not must_change:
        creds["admin_password"] = "admin"
        write_creds(creds_path, creds)
        return {"password": "admin", "changed": False}

    new = strong_password()
    # Changing your OWN password needs the current one; it then destroys
    # every session for the account (netpath/web/api.py:4037-4064), so the
    # cookie we hold is dead the moment this returns.
    client.post("/api/password", {"username": "admin",
                                  "current_password": "admin",
                                  "new_password": new})
    creds["admin_password"] = new
    write_creds(creds_path, creds)
    client.cookie = ""
    client.login("admin", new)
    print("[1] password changed and re-logged in; credentials in %s"
          % os.path.relpath(creds_path))
    log.note("1-login", "admin password rotated; session destroyed by the "
                        "change, so a second login was required")
    return {"password": new, "changed": True}


def step_groups_and_profiles(client: Client, log: SeedLog) -> dict:
    """2. Device groups (sites) and polling profiles."""
    client.step = "2-groups"
    existing = {g["name"]: g["id"]
                for g in client.get("/api/nodes/device-groups")["groups"]}
    site_ids = {}
    made = 0
    for site in SITES:
        if site in existing:
            site_ids[site] = existing[site]
            continue
        site_ids[site] = client.post("/api/nodes/device-groups",
                                     {"name": site})["id"]
        made += 1
    print("[2] device groups: %d present, %d created -> %s"
          % (len(site_ids), made, site_ids))

    client.step = "2-profiles"
    have = {g["name"]: g for g in client.get("/api/nodes/groups")["groups"]}
    profile_ids = {}
    created = 0
    for name, fields in PROFILES:
        if name in have:
            profile_ids[name] = have[name]["id"]
            continue
        body = {"name": name}
        body.update(fields)
        profile_ids[name] = client.post("/api/nodes/groups", body)["id"]
        created += 1
    print("[2] polling profiles: %d present, %d created -> %s"
          % (len(profile_ids), created, profile_ids))

    # v3-sha wants an auth password. Storing one goes through DPAPI, which is
    # Windows-only — call it anyway and keep the refusal as evidence.
    client.step = "2-profile-credential"
    endpoint = "/api/nodes/groups/%d/credential" % profile_ids["v3-sha"]
    status, payload, _ = client.raw("POST", endpoint, {
        "v3_user": "poller", "v3_auth_proto": "SHA",
        "v3_auth_pass": "demo-v3-auth-passphrase"})
    text = error_text(payload)
    print("[2] store v3-sha auth password -> HTTP %d: %s" % (status, text))
    if status >= 400:
        log.refusal("2-profile-credential", endpoint, status, text)
    return {"sites": site_ids, "profiles": profile_ids}


def step_devices(client: Client, log: SeedLog, plan, site_ids, profile_ids) -> dict:
    """3. One POST /api/nodes/devices per fleet entry. There is no bulk-add."""
    client.step = "3-devices"
    existing = {d["ip"]: d for d in client.get("/api/nodes/devices")["devices"]}
    added = skipped = failed = 0
    first_error = ""
    by_name: dict[str, int] = {}
    started = time.time()
    for entry in plan:
        ip = entry["ip"]
        if ip in existing:
            skipped += 1
            by_name[entry.get("name") or ip] = existing[ip]["id"]
            continue
        profile = entry.get("profile") or "v2c-public"
        body = {
            "ip": ip,
            "name": entry.get("name") or ip,
            "group_id": profile_ids.get(profile),
            "device_group_id": site_ids.get(entry.get("site") or SITES[0]),
        }
        # Only override the community where the plan asks for a different one
        # than the profile already carries; otherwise inherit the profile.
        community = entry.get("community") or ""
        if community and community != PROFILE_COMMUNITY.get(profile, ""):
            body["community"] = community
            body["snmp_version"] = entry.get("snmp_version")
        status, payload, _ = client.raw("POST", "/api/nodes/devices", body)
        if status == 200:
            added += 1
            by_name[body["name"]] = payload["id"]
        else:
            failed += 1
            if not first_error:
                first_error = "%s -> HTTP %d: %s" % (ip, status, error_text(payload))
    elapsed = max(time.time() - started, 1e-6)
    rate = (added + skipped) / elapsed
    print("[3] devices: %d added, %d already present, %d failed in %.1fs "
          "(%.1f devices/s)%s"
          % (added, skipped, failed, elapsed, rate,
             ("; first error: " + first_error) if first_error else ""))
    log.note("3-devices", "device add rate", added=added, skipped=skipped,
             failed=failed, seconds=round(elapsed, 3),
             devices_per_second=round(rate, 2))
    return {"added": added, "skipped": skipped, "failed": failed,
            "seconds": round(elapsed, 3), "devices_per_second": round(rate, 2),
            "ids_by_name": by_name, "first_error": first_error}


def step_netpath(client: Client, log: SeedLog) -> dict:
    """4. NetPath targets, including the six scripted shim destinations."""
    client.step = "4-netpath"
    have = {t["host"] for t in client.get("/api/netpath/targets")["targets"]}
    created = 0
    for host, label in NETPATH_TARGETS:
        if host in have:
            continue
        client.post("/api/netpath/targets", {
            "host": host, "label": label, "interval_s": 60, "max_hops": 12,
            "probes": 3, "timeout_s": 1})
        created += 1
    print("[4] netpath targets: %d created, %d already present"
          % (created, len(NETPATH_TARGETS) - created))
    return {"created": created}


def step_ipam(client: Client, log: SeedLog) -> dict:
    """5. The loopback subnet, then a scan of it."""
    client.step = "5-ipam"
    have = {s["cidr"]: s["id"]
            for s in client.get("/api/ipam/subnets")["subnets"]}
    cidr = "127.0.0.0/24"
    if cidr in have:
        subnet_id = have[cidr]
        made = False
    else:
        subnet_id = client.post("/api/ipam/subnets",
                                {"cidr": cidr, "label": "Loopback fleet"})["id"]
        made = True
    status, payload, _ = client.raw(
        "POST", "/api/ipam/subnets/%d/scan" % subnet_id, {})
    print("[5] ipam subnet %s (id=%d, %s) scan -> HTTP %d %s"
          % (cidr, subnet_id, "created" if made else "existing", status,
             error_text(payload) if status >= 400 else "started"))
    return {"subnet_id": subnet_id, "scan_status": status}


def step_wireless(client: Client, log: SeedLog) -> dict:
    """6. The FortiGate wireless controller, then a poll."""
    client.step = "6-wireless"
    have = {c["name"]: c["id"]
            for c in client.get("/api/wireless/controllers")["controllers"]}
    if "wlc-01" in have:
        controller_id = have["wlc-01"]
        made = False
    else:
        controller_id = client.post("/api/wireless/controllers", {
            "name": "wlc-01", "ip": "127.0.0.3", "snmp_version": 1,
            "community": "public"})["id"]
        made = True
    status, payload, _ = client.raw(
        "POST", "/api/wireless/controllers/%d/poll" % controller_id, {})
    print("[6] wireless controller wlc-01 (id=%d, %s) poll -> HTTP %d %s"
          % (controller_id, "created" if made else "existing", status,
             error_text(payload) if status >= 400 else "started"))
    return {"controller_id": controller_id, "poll_status": status}


def step_configrx(client: Client, log: SeedLog, device_ids: dict) -> dict:
    """7. Enable config backup on two devices, then try to store an SSH
    password — which DPAPI refuses off Windows."""
    client.step = "7-configrx"
    targets = []
    core = device_ids.get("core-sw-01")
    wlc = device_ids.get("wlc-01")
    if core:
        targets.append((core, "core-sw-01", "cisco"))
    if wlc:
        targets.append((wlc, "wlc-01", "fortinet"))
    if not targets:
        # Fall back to whatever the first two devices are.
        devices = client.get("/api/nodes/devices")["devices"][:2]
        targets = [(d["id"], d["name"] or d["ip"], "cisco") for d in devices]

    configured = []
    for device_id, name, vendor in targets:
        client.post("/api/configrx/devices/%d/config" % device_id, {
            "backup_enabled": True, "ssh_port": 22, "ssh_username": "admin",
            "vendor_override": vendor})
        configured.append(name)
    print("[7] configrx backup enabled on %s (vendor override set)"
          % ", ".join(configured))

    refusal = ""
    if targets:
        endpoint = "/api/configrx/devices/%d/credential" % targets[0][0]
        status, payload, _ = client.raw("POST", endpoint, {
            "ssh_username": "admin", "ssh_password": "demo-ssh-password"})
        refusal = error_text(payload)
        print("[7] store SSH password -> HTTP %d: %s" % (status, refusal))
        if status >= 400:
            log.refusal("7-configrx", endpoint, status, refusal)
    return {"devices": configured, "credential_refusal": refusal}


def step_settings(client: Client, log: SeedLog, workers: int) -> dict:
    """8. Alerts/syslog/nodes settings, the alert engine, and two lowered
    thresholds so the fleet actually trips something."""
    client.step = "8-settings"
    results = {}

    alerts_values = {
        "email_enabled": True,
        "smtp_host": "127.0.0.1",
        "smtp_port": 1025,
        "smtp_security": "none",
        "smtp_from": "sappiwhere@demo.invalid",
        "smtp_from_name": "SappiWhere Demo",
        "smtp_to_default": ["noc@demo.invalid"],
        "new_device_grace_s": 0,
        "notify_on_clear": True,
        "max_emails_per_hour": 10000,
        "renotify_minutes": 0,
    }
    payload = client.post("/api/settings", {"scope": "alerts",
                                            "values": alerts_values})
    saved = payload.get("alerts_settings", {})
    print("[8] alerts settings -> email_enabled=%s smtp=%s:%s grace=%ss"
          % (saved.get("email_enabled"), saved.get("smtp_host"),
             saved.get("smtp_port"), saved.get("new_device_grace_s")))
    results["alerts"] = {k: saved.get(k) for k in
                         ("email_enabled", "smtp_host", "smtp_port",
                          "smtp_security", "new_device_grace_s")}

    payload = client.post("/api/settings", {"scope": "syslog",
                                            "values": {"accept_tcp": True}})
    print("[8] syslog settings -> accept_tcp=%s"
          % payload.get("syslog_settings", {}).get("accept_tcp"))
    results["syslog_accept_tcp"] = payload.get(
        "syslog_settings", {}).get("accept_tcp")

    if workers:
        payload = client.post("/api/settings", {"scope": "nodes",
                                                "values": {"poll_workers": workers}})
        got = payload.get("nodes_settings", {}).get("poll_workers")
        print("[8] nodes settings -> poll_workers=%s" % got)
        results["poll_workers"] = got

    status, payload, _ = client.raw("POST", "/api/alerts/engine",
                                    {"action": "start"})
    print("[8] alert engine start -> HTTP %d running=%s"
          % (status, payload.get("running")))
    results["alert_engine_running"] = payload.get("running")

    # Lower two thresholds so a 250-device loopback fleet trips them.
    client.step = "8-rules"
    rules = client.get("/api/alerts/rules")["rules"]
    by_key = {r["key"]: r for r in rules}
    tuned = {}
    for key, threshold, clear, for_polls in (("cpu_high", 20.0, 10.0, 1),
                                             ("response_time_high", 5.0, 2.0, 1)):
        rule = by_key.get(key)
        if not rule:
            print("[8] rule %s not found (built-in list changed?)" % key)
            continue
        client.put("/api/alerts/rules/%d" % rule["id"],
                   {"threshold": threshold, "clear_threshold": clear,
                    "for_polls": for_polls, "enabled": True})
        tuned[key] = {"rule_id": rule["id"], "threshold": threshold,
                      "clear_threshold": clear, "for_polls": for_polls,
                      "was_threshold": rule.get("threshold")}
        print("[8] rule %s (id=%d) threshold %s -> %s"
              % (key, rule["id"], rule.get("threshold"), threshold))
    results["rules"] = tuned
    results["rule_ids"] = {r["key"]: r["id"] for r in rules}
    log.note("8-settings", "tuned alert rules", rules=tuned)
    return results


def _clear_must_change(base: str, username: str, temp: str, log: SeedLog) -> str:
    """post_user always sets must_change=1, and an admin reset sets it again
    (netpath/web/api.py:3977 and :4060). The only way to land an account that
    can sign in without the forced-change dialog is for the account itself to
    change its own password — so do that here."""
    final = strong_password(username)
    helper = Client(base)
    helper.log = log
    helper.step = "9-users/%s" % username
    try:
        helper.login(username, temp)
        helper.post("/api/password", {"username": username,
                                      "current_password": temp,
                                      "new_password": final})
    except ApiError as exc:
        log.note("9-users", "could not clear must_change for %s: %s"
                 % (username, exc))
        helper.close()
        return temp
    helper.close()
    return final


def step_users(client: Client, log: SeedLog, base: str, creds_path: str) -> dict:
    """9. A read-only `viewer` and a nodes/alerts-write `noc`."""
    client.step = "9-users"
    modules = ("netpath", "netflow", "snmp", "syslog", "ipam", "nodes",
               "alerts", "wireless", "configrx", "settings", "debug")
    wanted = {
        "viewer": {m: "read" for m in modules},
        "noc": {**{m: "read" for m in modules},
                "nodes": "write", "alerts": "write"},
    }
    existing = {u["username"] for u in client.get("/api/users")["users"]}
    creds = read_creds(creds_path)
    tweaked = []
    out = {}
    for username, grants in wanted.items():
        key = "%s_password" % username
        if username in existing:
            # Keep the grants current even for an account we did not create.
            # An admin reset would re-arm must_change, so the password is left
            # alone; without creds.txt it simply is not recoverable.
            client.post("/api/users/permissions",
                        {"username": username, "grants": grants})
            known = bool(creds.get(key))
            out[username] = {"created": False, "grants": grants,
                             "password_known": known}
            print("[9] user %s already exists; grants refreshed%s"
                  % (username, "" if known else
                     " (password not in creds.txt — it cannot be recovered, "
                     "delete the account to re-seed it)"))
            if not known:
                log.note("9-users", "%s exists but its password is not in "
                                    "creds.txt" % username)
            continue
        temp = strong_password(username)
        status, payload, _ = client.raw("POST", "/api/users", {
            "username": username, "password": temp, "grants": grants})
        if status >= 400:
            # The most likely cause is the password policy; retry once with a
            # longer passphrase and record that the tweak was needed.
            tweaked.append({"username": username, "first_error": error_text(payload)})
            temp = strong_password(username) + "-" + strong_password()
            status, payload, _ = client.raw("POST", "/api/users", {
                "username": username, "password": temp, "grants": grants})
        if status >= 400:
            print("[9] user %s -> HTTP %d: %s"
                  % (username, status, error_text(payload)))
            out[username] = {"created": False, "error": error_text(payload)}
            continue
        final = _clear_must_change(base, username, temp, log)
        creds[key] = final
        write_creds(creds_path, creds)
        out[username] = {"created": True, "grants": grants,
                         "must_change_cleared": final != temp}
        print("[9] user %s created (%s) and signed in once to clear "
              "must_change" % (username, "read-only" if username == "viewer"
                               else "nodes/alerts write"))
    if tweaked:
        log.note("9-users", "password policy rejected the first generated "
                            "password", details=tweaked)
        print("[9] password policy tweak needed: %s" % tweaked)
    else:
        log.note("9-users", "no password policy tweak needed")
    out["policy_tweaks"] = tweaked
    return out


def step_verify(client: Client, log: SeedLog, expected: int) -> dict:
    """10. device_count == N, and the collectors' running flags."""
    client.step = "10-verify"
    state = client.get("/api/state")
    nodes = state.get("nodes", {})
    device_count = nodes.get("device_count")
    running = {
        "nodes": nodes.get("running"),
        "alerts": state.get("alerts", {}).get("running"),
        "netflow": state.get("collector", {}).get("running"),
        "syslog": state.get("syslog", {}).get("running"),
        "snmp": state.get("snmp", {}).get("running"),
        "ipam": state.get("ipam", {}).get("running"),
        "wireless": state.get("wireless", {}).get("running"),
        "configrx": state.get("configrx", {}).get("running"),
    }
    ok = device_count == expected
    print("[10] device_count=%s (expected %d) %s"
          % (device_count, expected, "OK" if ok else "MISMATCH"))
    print("[10] collectors: %s"
          % ", ".join("%s=%s" % (k, v) for k, v in sorted(running.items())))
    log.note("10-verify", "final state", device_count=device_count,
             expected=expected, running=running)
    return {"device_count": device_count, "expected": expected, "ok": ok,
            "running": running, "version": state.get("version")}


# ------------------------------------------------------------------- driver

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="http://127.0.0.1:8443",
                        help="app base URL (default http://127.0.0.1:8443)")
    parser.add_argument("--count", type=int, default=250,
                        help="fleet size to seed (default 250)")
    parser.add_argument("--out", default=os.path.join(HERE, "out"),
                        help="output directory (default demo/out)")
    parser.add_argument("--workers", type=int, default=32,
                        help="nodes poll_workers to set; 0 leaves the default")
    args = parser.parse_args(argv)

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    creds_path = os.path.join(out, "creds.txt")
    log = SeedLog(os.path.join(out, "seed_log.json"))

    plan_fn, plan_source = load_fleet_plan()
    plan = list(plan_fn(args.count))
    print("[0] fleet plan from %s: %d entries" % (plan_source, len(plan)))
    log.note("0-plan", "fleet plan loaded", source=plan_source, entries=len(plan))

    client = Client(args.base)
    client.log = log
    summary = {"base": args.base, "count": args.count,
               "plan_source": plan_source, "started": time.time()}
    started = time.time()
    try:
        summary["login"] = step_login(client, log, creds_path)
        ids = step_groups_and_profiles(client, log)
        summary["groups"] = ids
        summary["devices"] = step_devices(client, log, plan, ids["sites"],
                                          ids["profiles"])
        summary["netpath"] = step_netpath(client, log)
        summary["ipam"] = step_ipam(client, log)
        summary["wireless"] = step_wireless(client, log)
        summary["configrx"] = step_configrx(
            client, log, summary["devices"]["ids_by_name"])
        summary["settings"] = step_settings(client, log, args.workers)
        summary["users"] = step_users(client, log, args.base, creds_path)
        summary["verify"] = step_verify(client, log, args.count)
    finally:
        summary["seconds"] = round(time.time() - started, 2)
        summary["refusals"] = log.refusals
        with open(os.path.join(out, "seed_summary.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(summary, handle, indent=1, default=str)
        log.flush()
        client.close()

    failures = [e for e in log.entries if e["status"] >= 400 or e["status"] == 0]
    print("\n[done] %d API calls in %.1fs, %d non-2xx (%d recorded as expected "
          "DPAPI refusals)"
          % (len(log.entries), summary["seconds"], len(failures),
             len(log.refusals)))
    print("[done] log: %s" % os.path.join(out, "seed_log.json"))
    return 0 if summary.get("verify", {}).get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

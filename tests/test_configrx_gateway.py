"""ConfigRX's default-gateway fallback (5.35.0): configrx._config_gateway
parses `ip default-gateway`/a default static route out of a cleaned config
capture, configrxdb.set_config_gateway stores it on device_config, and the
device-detail API (api.py get_nodes_device) returns it with
default_gateway_source: "configrx" only when SNMP's own default_gateway
column is empty -- SNMP always wins when it is set.
"""
import http.client
import json
import os

import _paths  # noqa: F401  (repo root on sys.path)

from netpath import configrx
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.configrxdb import ConfigRxDatabase
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("configrx_gateway_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------- _config_gateway parsing

print("1. configrx._config_gateway parsing")
check("`ip default-gateway` is matched",
      configrx._config_gateway("hostname sw1\n!\nip default-gateway 10.9.9.1\n!\n")
      == "10.9.9.1")
check("a default static route is matched when there is no ip default-gateway line",
      configrx._config_gateway("hostname sw1\n!\nip route 0.0.0.0 0.0.0.0 10.9.9.2\n!\n")
      == "10.9.9.2")
check("ip default-gateway wins when both lines are present",
      configrx._config_gateway(
          "ip default-gateway 10.9.9.1\nip route 0.0.0.0 0.0.0.0 10.9.9.2\n")
      == "10.9.9.1")
check("neither line present: empty string",
      configrx._config_gateway("hostname sw1\n!\ninterface Gi1/0/1\n!\n") == "")
check("a value that does not parse as an IP address is not stored",
      configrx._config_gateway("ip default-gateway not-an-ip\n") == "")
check("the header must be at the start of the line (not indented, not "
      "a substring of a longer directive)",
      configrx._config_gateway("description ip default-gateway 10.9.9.1\n") == "")


# --------------------------------------------- configrxdb storage/migration

print("2. configrxdb.set_config_gateway / device_config")
db = ConfigRxDatabase(os.path.join(TMPDIR, "configrx.db"))
try:
    row = db.device_config(1)
    check("a device with no row yet reads as no row (config_gateway column exists)",
          row is None)
    db.set_config_gateway(1, "10.9.9.1")
    row = db.device_config(1)
    check("set_config_gateway creates the row and stores the value",
          row is not None and row["config_gateway"] == "10.9.9.1", dict(row) if row else row)
    db.set_config_gateway(1, "")
    row = db.device_config(1)
    check("an empty string clears it back out (no gateway line found this capture)",
          row["config_gateway"] == "", dict(row))
finally:
    db.close()


# ------------------------------------------------------------- API fallback

print("3. device-detail API: default_gateway_source")
service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx2.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    return response.status, json.loads(raw)


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
    db = service.nodes_db
    gid = db.ensure_default_group()

    # This device's SNMP-published gateway is empty; ConfigRX's own capture
    # names one instead -- the worker's own hook
    # (self.db.set_config_gateway(device_id, _config_gateway(cleaned))) is
    # simulated directly here rather than run through a real SSH backup.
    did_rx = db.add_device("10.97.0.1", name="cx-gw-fallback", group_id=gid)
    capture = "hostname cx-gw-fallback\n!\nip default-gateway 10.9.9.1\n!\n"
    service.configrx_db.add_backup(did_rx, capture)
    service.configrx_db.set_config_gateway(
        did_rx, configrx._config_gateway(capture))

    status, payload = call("GET", f"/api/nodes/devices/{did_rx}", token=admin)
    check("200, and the ConfigRX-parsed gateway rides through",
          status == 200 and payload["device"]["default_gateway"] == "10.9.9.1",
          (status, payload.get("device", {}).get("default_gateway")))
    check("default_gateway_source says configrx when SNMP left the column empty",
          payload["device"]["default_gateway_source"] == "configrx",
          payload["device"].get("default_gateway_source"))

    # SNMP wins when it has published something, even with a ConfigRX
    # capture on file for the same device.
    did_snmp = db.add_device("10.97.0.2", name="cx-gw-snmp", group_id=gid)
    db.set_default_gateway(did_snmp, "10.1.1.1")
    service.configrx_db.set_config_gateway(did_snmp, "10.9.9.9")
    status, payload = call("GET", f"/api/nodes/devices/{did_snmp}", token=admin)
    check("SNMP's own gateway is returned, not ConfigRX's",
          status == 200 and payload["device"]["default_gateway"] == "10.1.1.1",
          payload["device"].get("default_gateway"))
    check("default_gateway_source says snmp",
          payload["device"]["default_gateway_source"] == "snmp",
          payload["device"].get("default_gateway_source"))

    # Neither SNMP nor ConfigRX has anything to offer.
    did_none = db.add_device("10.97.0.3", name="cx-gw-none", group_id=gid)
    status, payload = call("GET", f"/api/nodes/devices/{did_none}", token=admin)
    check("both empty: default_gateway and its source are both the empty string",
          status == 200 and payload["device"]["default_gateway"] == ""
          and payload["device"]["default_gateway_source"] == "",
          payload["device"])
finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")

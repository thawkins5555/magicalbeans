"""The Add DHCP server dialog's own Test connection route
(POST /api/ipam/dhcp/servers/test): the same round trip the id-based Test
button already ran, factored out so it can be reached with nothing saved
yet -- no server row, no stored credential to fall back to.

netpath.ipam_dhcp.test_connection is monkeypatched so this runs without a
real PowerShell/DHCP round trip on any machine."""
import _paths  # noqa: F401

import netpath.ipam_dhcp as ipam_dhcp
from netpath.web import api

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class Service:
    ipam_settings = {"dhcp_timeout_s": 5}


service = Service()

try:
    api.post_ipam_dhcp_server_test_unsaved(service, {}, {"username": "svc", "password": "x"})
    check("a missing address raises ValueError", False)
except ValueError as exc:
    check("a missing address raises ValueError", "address" in str(exc).lower(), str(exc))

seen = {}


def fake_test_connection(server, timeout_s=15.0, username=None, password=None):
    seen["server"] = server
    seen["username"] = username
    seen["password"] = password
    return {"ok": True, "version": "6.2", "scope_count": 3}


ipam_dhcp.test_connection = fake_test_connection
result = api.post_ipam_dhcp_server_test_unsaved(
    service, {}, {"address": "dhcp01.example.net", "username": "svc", "password": "hunter2"})
check("the address and credentials in the body reach test_connection",
      seen == {"server": "dhcp01.example.net", "username": "svc", "password": "hunter2"}, seen)
check("...and its result is returned as-is", result == {
    "ok": True, "version": "6.2", "scope_count": 3}, result)

result2 = api.post_ipam_dhcp_server_test_unsaved(
    service, {}, {"address": "dhcp01.example.net"})
check("blank username/password are passed through as None, not a stored "
      "credential's -- there is none yet",
      seen["username"] is None and seen["password"] is None, seen)


def raising(server, timeout_s=15.0, username=None, password=None):
    raise ipam_dhcp.DhcpUnavailable("no PowerShell on this host")


ipam_dhcp.test_connection = raising
result3 = api.post_ipam_dhcp_server_test_unsaved(
    service, {}, {"address": "dhcp01.example.net"})
check("a DhcpUnavailable comes back as {ok: False, error: ...}, not a 500",
      result3 == {"ok": False, "error": "no PowerShell on this host"}, result3)

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

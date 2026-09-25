"""DHCP credentials are per server, never global: storing one on server A
must not surface on B's JSON, B's decrypted pair, or the username the
worker's poll of B sends out. Uses the portable secret store
(NETPATH_SECRET_PASSPHRASE) the way tests/test_secretstore.py:517-580
drives the real credential route, since DPAPI itself is Windows-only.
"""
import os

import _paths  # noqa: F401

os.environ["NETPATH_SECRET_PASSPHRASE"] = "testpass"

TMPDIR = _paths.tmpdir("ipam_dhcp_credential_")

import netpath.dpapi as dpapi  # noqa: E402
import netpath.secretstore as ss  # noqa: E402
import netpath.ipam_worker as ipam_worker  # noqa: E402
from netpath.ipam_dhcp import DhcpSnapshot  # noqa: E402
from netpath.ipam_worker import IpamWorker, credential_for_server  # noqa: E402
from netpath.ipamdb import IpamDatabase  # noqa: E402
from netpath.web.api.ipam import _dhcp_server_json  # noqa: E402

ss._salt_path = lambda: os.path.join(TMPDIR, "install.salt")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


ipam = IpamDatabase(os.path.join(TMPDIR, "ipam.db"))
worker = IpamWorker(ipam)

a_id = ipam.add_dhcp_server("10.9.0.1", "A")
b_id = ipam.add_dhcp_server("10.9.0.2", "B")

ipam.set_dhcp_credential(a_id, "CORP\\svc-a", dpapi.protect(b"pw-for-a"))

row_a = ipam.dhcp_server(a_id)
row_b = ipam.dhcp_server(b_id)

check("A's row carries its own username", row_a["username"] == "CORP\\svc-a", row_a["username"])
check("A's row carries a password blob", row_a["password_enc"] is not None)
check("A's row got a credential_ts", row_a["credential_ts"] is not None)

check("B's username stays unset", row_b["username"] is None, row_b["username"])
check("B's password stays unset", row_b["password_enc"] is None)
check("B's credential_ts stays unset", row_b["credential_ts"] is None)

json_a = _dhcp_server_json(row_a)
json_b = _dhcp_server_json(row_b)

check("A's JSON has_credential is true", json_a["has_credential"] is True)
check("A's JSON carries the username", json_a["username"] == "CORP\\svc-a", json_a["username"])
check("A's JSON carries a credential_ts", json_a["credential_ts"] is not None)

check("B's JSON has_credential is false", json_b["has_credential"] is False)
check("B's JSON username is None", json_b["username"] is None, json_b["username"])
check("B's JSON credential_ts is None", json_b["credential_ts"] is None)

user_a, pass_a = credential_for_server(row_a)
check("credential_for_server decrypts A's own pair",
      user_a == "CORP\\svc-a" and pass_a == "pw-for-a", (user_a, pass_a))

user_b, pass_b = credential_for_server(row_b)
check("credential_for_server on B (no credential) returns (None, None)",
      (user_b, pass_b) == (None, None), (user_b, pass_b))

# --------------------------------------------------------------- clearing
ipam.clear_dhcp_credential(a_id)
row_a_cleared = ipam.dhcp_server(a_id)
check("clearing A nulls username, password_enc and credential_ts",
      row_a_cleared["username"] is None and row_a_cleared["password_enc"] is None
      and row_a_cleared["credential_ts"] is None, dict(row_a_cleared))

# ------------------------------------------------- two servers, two owners
ipam.set_dhcp_credential(a_id, "CORP\\svc-a2", dpapi.protect(b"pw-a2"))
ipam.set_dhcp_credential(b_id, "CORP\\svc-b", dpapi.protect(b"pw-b"))

row_a2 = ipam.dhcp_server(a_id)
row_b2 = ipam.dhcp_server(b_id)
check("A reads back its own credential, not B's",
      credential_for_server(row_a2) == ("CORP\\svc-a2", "pw-a2"), dict(row_a2))
check("B reads back its own credential, not A's",
      credential_for_server(row_b2) == ("CORP\\svc-b", "pw-b"), dict(row_b2))

# ---------------------------------------------------- the worker's own poll
seen = {}


def fake_dhcp_poll(address, timeout_s=30.0, username=None, password=None):
    seen["address"] = address
    seen["username"] = username
    seen["password"] = password
    return DhcpSnapshot()


ipam_worker.dhcp_poll = fake_dhcp_poll
worker._poll(b_id, ipam.settings())
check("polling B sends B's own username, never A's",
      seen["username"] == "CORP\\svc-b", seen["username"])
check("polling B sends B's own password, never A's",
      seen["password"] == "pw-b", seen["password"])
check("polling B never touches A's address",
      seen["address"] == "10.9.0.2", seen["address"])

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

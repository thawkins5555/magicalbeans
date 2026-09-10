"""The SNMPv3 credential as it is stored, inherited and tested — the
5.8.0 review items that were each reproduced by execution, pinned so they
stay fixed. Stdlib plus the repo, no network: every SNMP exchange the Test
route would attempt is aimed at a port nobody listens on, and the field
under test (`security_level`) is derived before the first datagram.

  1. the Test button derives the level the poll would use, for a body
     shaped exactly like the edit form's Test click (every override key
     present and null) and for an empty body — the PAN-OS case, where it
     said authNoPriv while the scheduled poll ran at authPriv;
  2. effective_config() and credential_candidates() agree on the level
     across the override matrix — nothing set, auth only, privacy only,
     user and auth with privacy inherited, everything overridden — and a
     partial override no longer carries snmp_version None into the poll;
  3. `_clean_priv_proto` stores every accepted spelling of the one cipher
     under the name the form's select offers, so no row can be stored
     that the next Save would silently strip of its privacy blob;
  4. an auth protocol blanked on a row that holds a password is refused
     on every route that can do it — profile, additional credential, and
     a device whose profile has nothing to inherit — while a device blank
     that resolves to the profile's protocol is stored as NULL and polls;
  5. the wireless routes: a privacy field is refused on all three writes,
     a blank pair (the form's shape) is not, the whole auth-protocol list
     is accepted, and v3_verify_replies round-trips through the settings
     store with the boolean type coerce_settings demands;
  6. a privacy protocol stored with no privacy password on a row that
     holds none answers with a warning, and the same body against a row
     that holds one keeps it (the form's "blank keeps").
"""
import os
import sys

os.environ.setdefault("NETPATH_SECRET_PASSPHRASE", "v3-credential-storage-suite")

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import tmpdir

import netpath.nodepoll as nodepoll_mod  # noqa: E402
from netpath import dpapi  # noqa: E402
from netpath.nodepoll import security_level  # noqa: E402
from netpath.nodesdb import NodesDatabase  # noqa: E402
from netpath.sqlitebase import coerce_settings  # noqa: E402
from netpath.web import api  # noqa: E402
from netpath.wirelessdb import DEFAULTS as WIRELESS_DEFAULTS, WirelessDatabase  # noqa: E402

TMP = tmpdir("v3_credential_storage_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def refused(fn, *args, **kwargs):
    """The ValueError's message, or '' when the call was accepted."""
    try:
        fn(*args, **kwargs)
    except ValueError as exc:
        return str(exc)
    return ""


class FakeService:
    """Just enough of web.Service for the credential, device, profile and
    controller routes: the two stores, a log, and an audit sink."""

    class _AuditSink:
        def audit(self, *args, **kwargs):
            pass

    class _Log:
        def add(self, *args, **kwargs):
            pass

    def __init__(self, nodes_db, wireless_db=None):
        self.nodes_db = nodes_db
        self.wireless_db = wireless_db
        self.nodes_settings = {}
        self.log = self._Log()
        self.app_db = self._AuditSink()


def authpriv_profile_db(name):
    """A SHA+AES profile holding both blobs, and a device inheriting all
    of it — the PAN-OS shape. Ping off and one short SNMP attempt at a
    port nobody listens on, so a Test call returns in well under a
    second with its level already derived."""
    db = NodesDatabase(os.path.join(TMP, f"{name}.db"))
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=3, v3_user="poller", v3_auth_proto="SHA",
                    v3_priv_proto="AES", ping_enabled=0, snmp_timeout_s=0.2,
                    snmp_retries=0)
    db.set_group_credential(gid, "poller", "SHA", dpapi.protect(b"auth-secret"),
                            "AES", dpapi.protect(b"priv-secret"))
    did = db.add_device("127.0.0.1", name, group_id=gid)
    return db, gid, did


# nodeoids/nodepoll aim the Test route's datagram here; nothing answers,
# and the level is in the payload before the first send.
nodepoll_mod.DEFAULT_SNMP_PORT = 1

# ======================================= § 1 the Test button's level

print("\n-- the Test button derives the level the poll uses")
db, gid, did = authpriv_profile_db("test_button")
# deviceOverrides() in nodes.js: every override key, null for "(profile)".
FORM_BODY = {key: None for key in (
    "snmp_version", "v3_user", "v3_auth_proto", "v3_priv_proto", "poll_interval_s",
    "snmp_timeout_s", "ping_enabled", "snmp_enabled", "mib_file_id", "ping_count",
    "ping_timeout_ms", "unreachable_ping_only", "mac_table_interval_s",
    "vlan_interval_s")}
result = api.post_nodes_device_test(FakeService(db), {}, dict(FORM_BODY), did)
check("the edit form's Test body (every override null) tests at authPriv",
      result["snmp"]["security_level"] == "authPriv", result["snmp"]["security_level"])
result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
check("an empty body tests at authPriv too",
      result["snmp"]["security_level"] == "authPriv", result["snmp"]["security_level"])
check("...and that is the level the scheduled poll derives",
      security_level(db.effective_config(db.device(did))) == "authPriv")
result = api.post_nodes_device_test(FakeService(db), {}, {**FORM_BODY, "v3_priv_pass": ""}, did)
check("a privacy password present-but-empty still means 'test without one'",
      result["snmp"]["security_level"] == "authNoPriv", result["snmp"]["security_level"])
result = api.post_nodes_device_test(FakeService(db), {}, {**FORM_BODY, "v3_priv_proto": "AES128"}, did)
check("a typed protocol alias is accepted by the Test route as AES",
      result["snmp"]["security_level"] == "authPriv", result["snmp"]["security_level"])

# ================================= § 2 display and poll read one credential

print("\n-- effective_config and credential_candidates agree on the level")
db, gid, did = authpriv_profile_db("inherit_matrix")
MATRIX = {
    "nothing set": {},
    "auth only": {"v3_auth_proto": "SHA256"},
    "privacy only": {"v3_priv_proto": "AES"},
    "user and auth, privacy inherited": {"v3_user": "device-user", "v3_auth_proto": "MD5"},
}
for label, fields in MATRIX.items():
    device_id = db.add_device(f"10.0.0.{len(label)}", label, group_id=gid)
    if fields:
        db.update_device(device_id, **fields)
    row = db.device(device_id)
    effective = db.effective_config(row)
    candidates = db.credential_candidates(row)
    candidate = candidates[0]
    check(f"{label}: the poll's candidate carries a version, not None",
          candidate["snmp_version"] is not None)
    check(f"{label}: effective_config and the poll candidate derive one level",
          security_level(effective) == security_level(candidate) == "authPriv",
          f"effective={security_level(effective)} candidate={security_level(candidate)}")
    check(f"{label}: an override is exactly one candidate" if fields
          else f"{label}: the profile's primary is tried first",
          len(candidates) == 1 and (not fields or all(
              candidate[k] == v for k, v in fields.items())))
    check(f"{label}: the candidate's privacy blob is the effective one",
          candidate["v3_priv_pass_enc"] == effective["v3_priv_pass_enc"])

device_id = db.add_device("10.0.0.99", "everything", group_id=gid)
db.update_device(device_id, snmp_version=3, v3_user="own", v3_auth_proto="MD5",
                 v3_priv_proto="AES")
db.set_device_credential(device_id, "own", "MD5", dpapi.protect(b"a"), "AES",
                         dpapi.protect(b"p"))
row = db.device(device_id)
effective, candidate = db.effective_config(row), db.credential_candidates(row)[0]
check("everything overridden: both derive authPriv from the device's own pairs",
      security_level(effective) == security_level(candidate) == "authPriv"
      and candidate["v3_auth_pass_enc"] == row["v3_auth_pass_enc"]
      and candidate["v3_priv_pass_enc"] == row["v3_priv_pass_enc"])

# A device with no profile: the bare v2c guess, merged under its overrides.
orphan = db.add_device("10.0.1.1", "no-profile")
db.update_device(orphan, group_id=None, v3_user="alone")
candidate = db.credential_candidates(db.device(orphan))[0]
check("a device with no profile and a partial override still gets a version",
      candidate["snmp_version"] == 1 and candidate["v3_user"] == "alone")

# ================================ § 3 the one cipher, one stored name

print("\n-- every accepted spelling of AES is stored as AES")
for spelling in ("AES", "aes", "AES128", "aes128", " AES128 ", "AES-128", "aes-128"):
    fields = {"v3_priv_proto": spelling}
    message = refused(api._clean_priv_proto, fields)
    check(f"{spelling!r} is stored as 'AES'",
          not message and fields["v3_priv_proto"] == "AES",
          message or repr(fields["v3_priv_proto"]))
for spelling in ("", None):
    fields = {"v3_priv_proto": spelling}
    api._clean_priv_proto(fields)
    check(f"{spelling!r} is none", fields["v3_priv_proto"] is None)
for spelling in ("DES", "AES192", "AES256", "3DES"):
    check(f"{spelling!r} is refused by name",
          "not supported" in refused(api._clean_priv_proto, {"v3_priv_proto": spelling}))
# The stored name is the one the form offers: a row stored under any other
# name showed "(none)" in the select and the next Save dropped the blob.
db, gid, did = authpriv_profile_db("alias_row")
service = FakeService(db)
api.put_nodes_group(service, {}, {"v3_priv_proto": "AES128"}, gid)
check("PUT profile v3_priv_proto=AES128 stores AES and keeps the privacy blob",
      db.group(gid)["v3_priv_proto"] == "AES" and bool(db.group(gid)["v3_priv_pass_enc"]))
api.put_nodes_group(service, {}, {"v3_priv_proto": "AES"}, gid)
check("...and the form's own Save of 'AES' afterwards keeps it too",
      db.group(gid)["v3_priv_proto"] == "AES" and bool(db.group(gid)["v3_priv_pass_enc"]))

# ============================ § 4 an authPriv row with no auth protocol

print("\n-- a stored password is never left without its auth protocol")
db, gid, did = authpriv_profile_db("orphan")
service = FakeService(db)
for value in ("", None, "  "):
    message = refused(api.put_nodes_group, service, {}, {"v3_auth_proto": value}, gid)
    check(f"PUT profile v3_auth_proto={value!r} with both blobs stored is refused",
          "auth protocol" in message, message or "accepted")
check("...and the row is untouched",
      db.group(gid)["v3_auth_proto"] == "SHA" and bool(db.group(gid)["v3_auth_pass_enc"]))
api.put_nodes_group(service, {}, {"v3_auth_proto": "SHA256"}, gid)
check("changing the protocol to another real one is allowed",
      db.group(gid)["v3_auth_proto"] == "SHA256")

cred_id = db.add_group_credential(gid, snmp_version=3, v3_user="alt", v3_auth_proto="MD5")
db.set_group_credential_password(cred_id, "alt", "MD5", dpapi.protect(b"alt-secret"))
message = refused(api.put_nodes_group_credential, service, {},
                  {"v3_auth_proto": ""}, gid, cred_id)
check("PUT additional credential v3_auth_proto='' with a blob is refused",
      "auth protocol" in message, message or "accepted")
empty_id = db.add_group_credential(gid, snmp_version=3, v3_user="nopass", v3_auth_proto="MD5")
check("...but the same PUT on a credential holding no password is fine",
      not refused(api.put_nodes_group_credential, service, {},
                  {"v3_auth_proto": ""}, gid, empty_id))

# Devices: NULL means the profile's, so a blank is refused only when the
# profile has nothing to inherit.
db.set_device_credential(did, "own", "MD5", dpapi.protect(b"a"), "AES", dpapi.protect(b"p"))
for value in ("", None):
    check(f"PUT device v3_auth_proto={value!r} under a SHA profile is accepted",
          not refused(api.put_nodes_device, service, {}, {"v3_auth_proto": value}, did))
    row = db.device(did)
    check(f"...stored as NULL (never ''), so the device derives the profile's level",
          row["v3_auth_proto"] is None
          and security_level(db.effective_config(row)) == "authPriv",
          f"stored {row['v3_auth_proto']!r}")
bare_gid = db.add_group("no-auth-profile", snmp_version=3, v3_user="bare")
message = refused(api.put_nodes_device, service, {},
                  {"v3_auth_proto": "", "group_id": bare_gid}, did)
check("PUT device blanking the protocol AND moving to a profile with none is refused",
      "auth protocol" in message, message or "accepted")
check("...and the device did not move",
      db.device(did)["group_id"] == gid)
db.update_device(did, v3_auth_proto="MD5")
api.put_nodes_device(service, {}, {"group_id": bare_gid}, did)
check("a device with its own protocol may move to that profile",
      db.device(did)["group_id"] == bare_gid)
message = refused(api.put_nodes_device, service, {}, {"v3_auth_proto": None}, did)
check("...and then blanking its protocol there is refused",
      "auth protocol" in message, message or "accepted")
api.put_nodes_device(service, {}, {"v3_user": ""}, did)
check("a blank device v3_user is stored as NULL, not ''",
      db.device(did)["v3_user"] is None)
new_id = api.post_nodes_device(service, {}, {"ip": "10.0.2.2", "v3_auth_proto": "",
                                             "v3_user": " "})["id"]
check("add-device stores blank v3 overrides as NULL too",
      db.device(new_id)["v3_auth_proto"] is None and db.device(new_id)["v3_user"] is None)

# ================================================ § 5 the wireless side

print("\n-- wireless: privacy refused on every route, the auth list whole")
wdb = WirelessDatabase(os.path.join(TMP, "wireless.db"))
service = FakeService(NodesDatabase(os.path.join(TMP, "wireless_nodes.db")), wdb)
BASE = {"name": "wlc", "ip": "10.5.5.5"}
for key, value in (("v3_priv_pass", "x"), ("v3_priv_proto", "AES")):
    message = refused(api.post_wireless_controller, service, {}, {**BASE, key: value})
    check(f"POST controller with {key} is refused in words",
          "not supported" in message, message or "accepted")
check("no controller row was left behind by a refused add", not wdb.controllers())
controller_id = api.post_wireless_controller(
    service, {}, {**BASE, "v3_priv_proto": None, "v3_priv_pass": None})["id"]
check("...while the pair present-but-null (the Nodes form's shape) is not refused",
      bool(controller_id))
for key, value in (("v3_priv_pass", "x"), ("v3_priv_proto", "AES")):
    message = refused(api.put_wireless_controller, service, {}, {key: value}, controller_id)
    check(f"PUT controller with {key} is refused in words",
          "not supported" in message, message or "accepted")
message = refused(api.post_wireless_controller_credential, service, {},
                  {"v3_user": "u", "v3_auth_proto": "SHA", "v3_auth_pass": "p",
                   "v3_priv_pass": "x"}, controller_id)
check("POST controller credential with a privacy password is refused in words",
      "not supported" in message, message or "accepted")
check("...and nothing was stored by the refusal",
      not wdb.controller(controller_id)["v3_auth_pass_enc"])
for proto in ("MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"):
    accepted = not refused(api.post_wireless_controller_credential, service, {},
                           {"v3_user": "u", "v3_auth_proto": proto, "v3_auth_pass": "p"},
                           controller_id)
    check(f"a controller credential at {proto} is accepted (fortipoll signs it)",
          accepted and wdb.controller(controller_id)["v3_auth_proto"] == proto)

check("wirelessdb.DEFAULTS carries v3_verify_replies, on",
      WIRELESS_DEFAULTS.get("v3_verify_replies") is True)
values = coerce_settings(WIRELESS_DEFAULTS, {"v3_verify_replies": False}, strict=True)
check("the settings route's strict coercion accepts the switch as a boolean",
      values.get("v3_verify_replies") is False)
check("...and refuses a non-boolean for it",
      "must be" in refused(coerce_settings, WIRELESS_DEFAULTS,
                           {"v3_verify_replies": "maybe"}, strict=True))
wdb.save_settings({"v3_verify_replies": False})
check("the switch round-trips through the wireless settings store",
      wdb.settings()["v3_verify_replies"] is False)
wdb.save_settings({"v3_verify_replies": True})
check("...both ways", wdb.settings()["v3_verify_replies"] is True)

# ======================================== § 6 a protocol with no password

print("\n-- AES with no privacy password: warned first time, kept after")
db = NodesDatabase(os.path.join(TMP, "warning.db"))
gid = db.ensure_default_group()
# The level is version-gated ('' for v1/v2c), and the credential POST does
# not touch the version; the profile form would have set it.
db.update_group(gid, snmp_version=3)
service = FakeService(db)
BODY = {"v3_user": "u", "v3_auth_proto": "SHA", "v3_auth_pass": "p", "v3_priv_proto": "AES"}
result = api.post_nodes_group_credential(service, {}, dict(BODY), gid)
check("stored, with a warning naming authNoPriv, when no privacy blob exists",
      result.get("ok") and "authNoPriv" in str(result.get("warning", "")), result)
check("...the row derives authNoPriv",
      security_level(dict(db.group(gid))) == "authNoPriv")
result = api.post_nodes_group_credential(service, {}, {**BODY, "v3_priv_pass": "q"}, gid)
check("stored without a warning when the privacy password is typed",
      result.get("ok") and "warning" not in result, result)
result = api.post_nodes_group_credential(service, {}, {**BODY, "v3_auth_pass": "p2"}, gid)
check("re-typing the auth password alone keeps the privacy blob, no warning",
      result.get("ok") and "warning" not in result
      and bool(db.group(gid)["v3_priv_pass_enc"])
      and security_level(dict(db.group(gid))) == "authPriv", result)
message = refused(api.post_nodes_group_credential, service, {},
                  {"v3_user": "u", "v3_auth_proto": "SHA", "v3_auth_pass": "p",
                   "v3_priv_pass": "q"}, gid)
check("a privacy password with no protocol is still refused",
      "privacy protocol" in message, message or "accepted")

print()
if FAILS:
    print(f"FAILED {len(FAILS)}:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("ALL V3 CREDENTIAL STORAGE CHECKS PASS")

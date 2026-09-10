"""SNMPv3 authPriv end to end, against tests/stubs/stub_agent_iftable.py's
v3 mode with --priv-pass: the PAN-OS user as provisioned, polled the way
5.7.2 said it could not be.

Skips (exit 77) when AES-CFB is not usable here — see test_snmpv3_priv.py
for why `import cryptography` succeeding is not the test.

  1. an authPriv poll succeeds through a real GETBULK ifTable walk, the
     stub decrypted every request, and no salt repeated in either
     direction across the whole walk;
  2. engine resync still works with privacy on: the IV depends on
     engineBoots, so a poll after the stub's restart proves the key and IV
     are built from the re-learned engine and not a stale cache;
  3. a wrong privacy password surfaces as decryptionErrors — distinct from
     wrongDigests — and the Test button says the auth password is right;
  4. a tampered reply is rejected by the new response verification as an
     auth failure naming the signature; an UNSIGNED reply to a signed
     request is refused as a downgrade whose message says it is new in
     5.8.0, is not filed as an auth failure, and is accepted again with
     v3_verify_replies off;
  5. the stored privacy password: has_priv_credential and security_level
     in the profile JSON, the blob never exposed, a privacy blob that will
     not decrypt failing loudly rather than polling at authNoPriv, and the
     wireless controller route refusing a privacy password in words;
  6. the level in the device row's error and the authNoPriv advice.
"""
import json
import os
import sys
import time

os.environ.setdefault("NETPATH_SECRET_PASSPHRASE", "snmpv3-priv-e2e-suite")

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import spawn_stub, tmpdir

from netpath import snmpcrypt

if not snmpcrypt.available():
    print(f"AES-CFB is not usable here ({snmpcrypt.unavailable_reason()}); "
          f"install 'cryptography' with a working backend to run this suite")
    raise SystemExit(77)

import netpath.nodepoll as nodepoll_mod  # noqa: E402
from netpath import dpapi  # noqa: E402
from netpath.nodepoll import NodePoller, credential_for  # noqa: E402
from netpath.nodesdb import NodesDatabase  # noqa: E402
from netpath.snmppoll import SnmpError  # noqa: E402
from netpath.web import api  # noqa: E402

TMP = tmpdir("snmpv3_priv_e2e_")
AUTH = "correct-horse-battery"
PRIV = "staple-battery-horse"
WRONG = "not-the-password"

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class CaptureLog:
    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append(message)


class FakeService:
    """Just enough of web.Service for post_nodes_device_test and the
    credential routes: nodes_db, nodes_settings, a log, and an audit sink."""

    class _AuditSink:
        def audit(self, *args, **kwargs):
            pass

    def __init__(self, nodes_db, nodes_settings=None):
        self.nodes_db = nodes_db
        self.nodes_settings = dict(nodes_settings or {})
        self.log = CaptureLog()
        self.app_db = self._AuditSink()


def new_db(name, auth_pass, priv_pass, *, priv_proto="AES", timeout_s=1.0):
    db = NodesDatabase(os.path.join(TMP, f"{name}.db"))
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=3, v3_user="poller", v3_auth_proto="SHA",
                    v3_priv_proto=priv_proto if priv_pass else None,
                    ping_enabled=0, snmp_timeout_s=timeout_s, snmp_retries=0,
                    poll_interval_s=999)
    db.set_group_credential(
        gid, "poller", "SHA", dpapi.protect(auth_pass.encode("utf-8")),
        priv_proto if priv_pass else None,
        dpapi.protect(priv_pass.encode("utf-8")) if priv_pass else None)
    did = db.add_device("127.0.0.1", name, group_id=gid)
    return db, gid, did


def poll_once(poller, db, did):
    device = db.device(did)
    poller._poll_device(device, db.effective_config(device))


def kinds(db, did):
    return [e["kind"] for e in db.device_events(did)]


def stats_of(path):
    time.sleep(0.1)
    with open(path) as handle:
        return json.load(handle)


# ===================================== § 1 the walk

print("\n-- an authPriv poll, GETBULK ifTable walk included")
stats = os.path.join(TMP, "walk.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", AUTH,
                        "--priv-pass", PRIV, "--interfaces", "40", "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, gid, did = new_db("walk", AUTH, PRIV)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    check("the poll succeeds: snmp_ok, no error",
          row["snmp_ok"] == 1 and not row["snmp_error"], row["snmp_error"])
    ifaces = db.interfaces(did)
    check("...with the whole 40-row ifTable walked through the encrypted channel",
          len(ifaces) == 40, len(ifaces))
    counts = stats_of(stats)
    check("the stub decrypted every non-discovery request and refused none",
          counts["decrypted"] >= 3 and counts["decrypt_errors"] == 0
          and counts["wrong_digests"] == 0, counts)
    seen, sent = counts["salts_seen"], counts["salts_sent"]
    check(f"no request salt repeated across the walk ({len(seen)} requests)",
          len(seen) == len(set(seen)) and counts["salt_reuse"] == 0 and len(seen) >= 3)
    check(f"no reply salt repeated either ({len(sent)} replies)",
          len(sent) == len(set(sent)) and len(sent) >= 3)
    check("...and none was all-zero",
          "0000000000000000" not in seen and "0000000000000000" not in sent)
    check("the device row's credential label says authPriv",
          "authPriv" in nodepoll_mod._credential_label(db.effective_config(db.device(did))))

    # -- the Test button with the stored credential
    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    check("the Test succeeds at security_level authPriv",
          snmp["ok"] is True and snmp.get("security_level") == "authPriv", snmp)
    check("...auth.ok true, and the detail says the reply was decrypted and its "
          "signature verified here",
          (snmp.get("auth") or {}).get("ok") is True
          and "authPriv" in (snmp.get("auth") or {}).get("detail", "")
          and "verified here" in (snmp.get("auth") or {}).get("detail", ""), snmp.get("auth"))
    check("...the walk phase ran through the encrypted channel too",
          (snmp.get("walk") or {}).get("rows", 0) >= 40, snmp.get("walk"))
    check("the Test payload carries neither password",
          AUTH not in repr(result) and PRIV not in repr(result))

    # -- the same stub, a credential with NO privacy: USM refuses the level
    db2, _gid2, did2 = new_db("nopriv", AUTH, None)
    poller2 = NodePoller(db2)
    poller2.log = CaptureLog()
    poll_once(poller2, db2, did2)
    row2 = db2.device(did2)
    check("an authNoPriv request to an authPriv user is unsupportedSecLevels → "
          "status unsupported, and the message says a privacy password is needed",
          row2["status"] == "unsupported" and "privacy password" in (row2["snmp_error"] or ""),
          (row2["status"], row2["snmp_error"]))
finally:
    stub.kill()


# ===================================== § 2 resync with privacy on

print("\n-- engine restart between two authPriv polls")
stats = os.path.join(TMP, "resync.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", AUTH,
                        "--priv-pass", PRIV, "--bump-boots-at", "0.5", "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, gid, did = new_db("resync", AUTH, PRIV)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    before = stats_of(stats)["engine_boots"]
    time.sleep(0.8)
    poll_once(poller, db, did)
    row = db.device(did)
    after = stats_of(stats)
    check("the stub restarted its engine between the polls",
          after["engine_boots"] == before + 1, (before, after["engine_boots"]))
    check("the second poll still succeeds: the IV and key were rebuilt from the "
          "engine the Report re-taught, not from the stale cache",
          row["snmp_ok"] == 1 and not row["snmp_error"], row["snmp_error"])
    check("...and nothing was recorded as an auth failure",
          "auth_fail" not in kinds(db, did) and poller.counters["auth_fail"] == 0,
          kinds(db, did))
    check("...with no decryption error at the stub",
          after["decrypt_errors"] == 0, after)
finally:
    stub.kill()


# ===================================== § 3 wrong privacy vs wrong auth

print("\n-- a wrong privacy password is decryptionErrors, not wrongDigests")
stats = os.path.join(TMP, "wrongpriv.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", AUTH,
                        "--priv-pass", PRIV, "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, gid, did = new_db("wrongpriv", AUTH, WRONG)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    check("the poll records auth_fail (the credential IS wrong)",
          "auth_fail" in kinds(db, did), kinds(db, did))
    check("...naming usmStatsDecryptionErrors and 'privacy password', and NOT "
          "WrongDigests",
          "DecryptionErrors" in error and "privacy password" in error
          and "WrongDigests" not in error, error)
    check("...and says the authentication password is not the problem",
          "authentication password is not the problem" in error, error)
    check("...never printing either password", WRONG not in error and PRIV not in error)
    counts = stats_of(stats)
    check("the stub verified the signature and then failed to decrypt",
          counts["wrong_digests"] == 0 and counts["decrypt_errors"] >= 1, counts)

    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    check("the Test says auth.ok TRUE with the privacy password blamed",
          snmp["ok"] is False and (snmp.get("auth") or {}).get("ok") is True
          and "privacy password" in (snmp.get("auth") or {}).get("detail", ""), snmp)
    check("...and the report block names decryptionErrors",
          (snmp.get("report") or {}).get("name") == "decryptionErrors", snmp.get("report"))
    result = api.post_nodes_device_test(FakeService(db), {}, {"v3_priv_pass": PRIV}, did)
    check("the right privacy password typed into the form passes the Test",
          result["snmp"]["ok"] is True and result["snmp"]["security_level"] == "authPriv",
          result["snmp"])

    db3, _g3, did3 = new_db("wrongauth", WRONG, PRIV)
    poller3 = NodePoller(db3)
    poller3.log = CaptureLog()
    poll_once(poller3, db3, did3)
    error3 = db3.device(did3)["snmp_error"] or ""
    check("a wrong AUTH password with the right privacy one is still wrongDigests",
          "WrongDigests" in error3 and "DecryptionErrors" not in error3, error3)
finally:
    stub.kill()


# ===================================== § 4 reply verification

print("\n-- a tampered reply is refused by the new verification")
stats = os.path.join(TMP, "tamper.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", AUTH,
                        "--priv-pass", PRIV, "--tamper-reply", "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, gid, did = new_db("tamper", AUTH, PRIV)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    check("the poll fails and stores nothing from the altered reply",
          row["snmp_ok"] == 0 and not row["sys_descr"], (row["snmp_ok"], row["sys_descr"]))
    check("...as an auth failure naming the signature — not a timeout, not 'malformed'",
          "auth_fail" in kinds(db, did) and "signature does not verify" in error
          and "no reply" not in error and "malformed" not in error, error)
    counts = stats_of(stats)
    check("the stub answered (it is the reply that was altered, not the request)",
          counts["responses"] >= 1 and counts["wrong_digests"] == 0, counts)
finally:
    stub.kill()

print("\n-- an unsigned reply to a signed request is a downgrade, with an off switch")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", AUTH,
                        "--unsigned-replies")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, gid, did = new_db("downgrade", AUTH, None)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    check("the poll fails: the reply carried no signature and was refused",
          row["snmp_ok"] == 0 and "no signature" in error and "downgrade" in error, error)
    check("...the message says this is new in 5.8.0 and names the setting",
          "new in 5.8.0" in error and "Verify the signature on every SNMPv3 reply" in error,
          error)
    check("...and it is NOT filed as an auth failure — the password was never "
          "contradicted — nor as unsupported",
          "auth_fail" not in kinds(db, did) and poller.counters["auth_fail"] == 0
          and row["status"] != "unsupported" and poller.counters["errors"] == 1,
          (kinds(db, did), poller.counters))
    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    check("the Test reports the same refusal with auth not proven either way",
          snmp["ok"] is False and "downgrade" in (snmp["error"] or "")
          and (snmp.get("auth") or {}).get("ok") is None
          and "no signature" in (snmp.get("auth") or {}).get("detail", ""), snmp)
    db.save_settings({"v3_verify_replies": False})
    poll_once(poller, db, did)
    row = db.device(did)
    check("with v3_verify_replies off the same unsigned reply is accepted — the "
          "pre-5.8.0 behaviour, for the operator with one such device",
          row["snmp_ok"] == 1 and not row["snmp_error"], row["snmp_error"])
    result = api.post_nodes_device_test(FakeService(db, {"v3_verify_replies": False}), {}, {}, did)
    check("...and the Test honours the setting too", result["snmp"]["ok"] is True, result["snmp"])
finally:
    stub.kill()


# ===================================== § 5 storage and API

print("\n-- the stored privacy password")
db, gid, did = new_db("storage", AUTH, PRIV)
group_json = api._group_json(FakeService(db), db.group(gid))
check("the profile JSON carries has_priv_credential, the protocol and the derived level",
      group_json["has_priv_credential"] is True and group_json["v3_priv_proto"] == "AES"
      and group_json["security_level"] == "authPriv", group_json)
check("...and never the blob",
      "v3_priv_pass_enc" not in group_json and "v3_auth_pass_enc" not in group_json
      and PRIV not in repr(group_json))
device_json = api._device_json(db.device(did))
check("a device that inherits everything has no level of its own (null), "
      "has_priv_credential false",
      device_json["security_level"] is None and device_json["has_priv_credential"] is False,
      device_json)
effective = api._effective_config_json(FakeService(db), db.device(did), reveal=False)
check("...but its effective_config (the device route's) says authPriv, with both "
      "has_* flags and neither blob",
      effective["security_level"] == "authPriv" and effective["has_priv_credential"] is True
      and effective["has_credential"] is True and "v3_priv_pass_enc" not in effective
      and "v3_auth_pass_enc" not in effective and "community" not in effective, effective)
cred = credential_for(db.effective_config(db.device(did)))
check("credential_for decrypts both just in time and derives authPriv",
      cred.auth_password == AUTH and cred.priv_password == PRIV
      and cred.priv_proto == "AES" and cred.security_level == "authPriv")
cred = None

# a privacy blob that will not decrypt
db.set_group_credential(gid, "poller", "SHA", dpapi.protect(AUTH.encode()), "AES",
                        b"not-a-blob-this-machine-can-read")
try:
    credential_for(db.effective_config(db.device(did)))
    check("an undecryptable privacy blob raises rather than polling at authNoPriv", False)
except SnmpError as exc:
    check("an undecryptable privacy blob raises rather than polling at authNoPriv",
          "privacy password" in str(exc) and "authNoPriv" in str(exc), str(exc))
# ...while a "leave blank to keep" re-store of the auth password keeps the blob
db.set_group_credential(gid, "poller", "SHA", dpapi.protect(AUTH.encode()))
check("re-storing only the auth password leaves the privacy blob and protocol",
      db.group(gid)["v3_priv_pass_enc"] == b"not-a-blob-this-machine-can-read"
      and db.group(gid)["v3_priv_proto"] == "AES")
db.update_group(gid, v3_priv_proto="")
check("setting the privacy protocol to none drops the privacy blob with it",
      db.group(gid)["v3_priv_pass_enc"] is None and db.group(gid)["v3_priv_proto"] is None)
db.clear_group_credential(gid)
check("clearing the credential clears both blobs",
      db.group(gid)["v3_auth_pass_enc"] is None and db.group(gid)["v3_priv_pass_enc"] is None)

# the API's own validation
body = {"v3_user": "poller", "v3_auth_proto": "SHA", "v3_auth_pass": AUTH,
        "v3_priv_proto": "AES", "v3_priv_pass": PRIV}
check("_v3_fields accepts the pair for Nodes",
      api._v3_fields(dict(body), allow_priv=True)[3:] == ("AES", PRIV))
try:
    api._v3_fields(dict(body), allow_priv=False)
    check("...and refuses a privacy password for a wireless controller", False)
except ValueError as exc:
    check("...and refuses a privacy password for a wireless controller, in words",
          "not supported" in str(exc) and "authPriv" in str(exc), str(exc))
try:
    api._v3_fields(dict(body, v3_priv_proto=""), allow_priv=True)
    check("a privacy password without a protocol is refused", False)
except ValueError as exc:
    check("a privacy password without a protocol is refused", "protocol" in str(exc))
try:
    api._v3_fields(dict(body, v3_priv_proto="DES"), allow_priv=True)
    check("DES is refused by name at the API", False)
except ValueError as exc:
    check("DES is refused by name at the API, and the message says why",
          "DES" in str(exc) and "AES-192/256" in str(exc), str(exc))
fields = {"v3_priv_proto": "aes"}
api._clean_priv_proto(fields)
check("the protocol name is normalised (aes → AES)", fields["v3_priv_proto"] == "AES")
service = FakeService(db)
api.post_nodes_group_credential(service, {}, body, gid)
check("POST .../credential stores both, encrypted, and the audit names the level",
      db.group(gid)["v3_priv_pass_enc"] not in (None, PRIV.encode())
      and dpapi.unprotect(db.group(gid)["v3_priv_pass_enc"]) == PRIV.encode()
      and db.group(gid)["v3_priv_proto"] == "AES")
try:
    api.post_nodes_group(service, {}, {"name": "bad", "snmp_version": 3, "v3_priv_proto": "3DES"})
    check("a profile with an unknown privacy protocol is refused", False)
except ValueError:
    check("a profile with an unknown privacy protocol is refused", True)


# ===================================== § 6 wording

print("\n-- the advice")
config = db.effective_config(db.device(did))
from netpath.nodepoll import access_denied_advice  # noqa: E402
text = access_denied_advice(config, "authNoPriv")
check("the authNoPriv advice tells the operator to set the privacy protocol and "
      "password on this credential",
      "privacy protocol (AES)" in text and "privacy password on this credential" in text, text)
check("...and no longer claims authPriv is unimplemented",
      "not implemented" not in text and "cannot yet" not in text, text)

print()
if FAILS:
    print(f"{len(FAILS)} FAILED:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all SNMPv3 authPriv end-to-end checks passed")

"""The two ways an SNMPv3 request fails, told apart.

An operator could not poll a PAN-OS firewall: both the Test button and the
device's status said "Authorization Error" against a username and auth
password that were never wrong. PAN-OS provisions its v3 user as authPriv;
this poller sends authNoPriv; RFC 3415's vacmAccessTable is keyed on the
security LEVEL, so the agent verified the signature, found no access entry,
and answered an ordinary Response-PDU with error-status 16 — which the
poller turned into four words and filed as an authentication failure.

Against tests/stubs/stub_agent_iftable.py's v3 mode, which can now verify
a digest (--auth-pass) and refuse an accepted request (--require-priv):

  1. the refused object is named from error-index, and error-index 0 or
     out of range says so rather than guessing;
  2. the operator's case end to end: an authNoPriv credential refused with
     errorStatus 16 names the OID, says the message authenticated, and
     raises authPriv as the likely cause; the event is access_denied, not
     auth_fail; `denied` is bumped and `auth_fail` is not;
  3. a genuine wrong password still records auth_fail (wrongDigests), so
     deciding by exception type did not break the real case;
  4. the Test button carries engine, security_level, auth, report,
     refused_oid and hint, and its wording is the poll's wording;
  5. the shared resync loop learns from a first Report and retries;
     notInTimeWindows twice is `auth.ok = null`, not a failure;
  6. engine discovery failing says that discovery was the phase;
  7. no message ever carries the community, the password or a key.

And, since the 5.8.0 reply verification, the failures that verification
itself can produce — none of which needs a cipher, so none skips:

  8. a datagram from the right address with a wrong-key digest and a
     request id we never sent is a dropped stray (the wait continues),
     not an SnmpAuthError — the id is checked before the digest wherever
     it can be read in the clear;
  9. a Report under an engine id we did not send is not learned and does
     not file the device as unsupported; only unknownEngineIDs may teach
     a new id;
 10. an access_denied after an auth_fail records auth_ok: the agent's own
     word that the password is right closes the alert that said it wasn't;
 11. a device answering unsigned to a signed request stays UP through the
     outage threshold, records snmp_downgrade once and never down or
     snmp_error, and snmp_verified when replies verify again — with the
     device_downgrade rule and its CLEARS pair wired;
 12. a contradicted credential (downgrade, or a digest this end refused)
     does not rotate onto the next candidate, and a sweep that ends in an
     alternate's timeout still reports the primary's named refusal;
 13. an snmp_version of None is the v2c default, not a TypeError that
     freezes the device;
 14. an authentication blob that will not decrypt raises rather than
     polling unsigned — and a v2c profile carrying a stale blob does not.

And the 5.8.1 field report — three firewalls on one working profile that
never polled until the service was restarted:

 15. a cached engine whose signed request is silently dropped (no Report)
     is invalidated on that one timeout, the next poll rediscovers and
     succeeds, and the poll after that makes no new discovery; an engine
     learned INSIDE the failing call is kept; poll_now drops the cache
     before submitting; and _AuthFailure still invalidates as it did.
"""
import json
import os
import socket
import sys
import threading
import time

# Before any netpath import: off Windows dpapi.protect() is the portable
# secret store, which needs a passphrase from the environment.
os.environ.setdefault("NETPATH_SECRET_PASSPHRASE", "snmpv3-diagnostics-suite")

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import free_udp_port, spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath import alertrules, alertsdb, dpapi, nodeoids
from netpath.nodepoll import (
    NodePoller, _AuthFailure, _Session, access_denied_reason, credential_for,
    discover_engine, refused_oid, security_level, snmp_version_of, v3_exchange)
from netpath.nodesdb import NodesDatabase
from netpath.snmppoll import (
    PDU_GET, PDU_REPORT, Response, SnmpAccessDenied, SnmpAuthError,
    SnmpDowngrade, SnmpError, SnmpTimeout, SnmpUnsupported, _v3_message,
    build_v3_request, decode_response)
from netpath.trapdecode import (
    T_COUNTER32, T_SEQUENCE, _tlv, enc_int, enc_octets, enc_unsigned,
    enc_varbind, localized_key)
from netpath.web import api

TMP = tmpdir("snmpv3_diag_")
SYS_DESCR = nodeoids.SYSTEM_SCALARS["sys_descr"]
SCALARS = list(nodeoids.SYSTEM_SCALARS.values())
PASSWORD = "correct-horse-battery"
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
    """Just enough of web.Service for post_nodes_device_test: it reads
    nodes_db and, since 5.8.0, the nodes_settings dict (for
    v3_verify_replies) and nothing else."""

    def __init__(self, nodes_db, nodes_settings=None):
        self.nodes_db = nodes_db
        self.nodes_settings = dict(nodes_settings or {})


def new_v3_db(name: str, password: str | None, *, timeout_s: float = 1.0) -> tuple:
    """A v3 authNoPriv (or, with password None, noAuthNoPriv) device
    against the loopback stub, one socket's worth of retries so a wrong
    branch fails fast rather than slowly."""
    db = NodesDatabase(os.path.join(TMP, f"{name}.db"))
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=3, v3_user="poller", v3_auth_proto="SHA",
                    ping_enabled=0, snmp_timeout_s=timeout_s, snmp_retries=0,
                    poll_interval_s=999)
    if password is not None:
        db.set_group_credential(gid, "poller", "SHA",
                                dpapi.protect(password.encode("utf-8")))
    did = db.add_device("127.0.0.1", name, group_id=gid)
    return db, did


def poll_once(poller: NodePoller, db: NodesDatabase, did: int) -> None:
    device = db.device(did)
    poller._poll_device(device, db.effective_config(device))


def kinds(db: NodesDatabase, did: int) -> list[str]:
    return [e["kind"] for e in db.device_events(did)]


def secrets_absent(text: str, *secrets: str) -> bool:
    return all(secret not in text for secret in secrets if secret)


# ===================================== § 1 naming the refused object

print("\n-- error-index, read the way RFC 3416 counts it")
response = Response(error_status=16, error_index=2,
                    varbinds=[{"oid": "1.3.6.1.2.1.1.1.0", "type": "NULL", "value": None, "text": ""},
                              {"oid": "1.3.6.1.2.1.1.5.0", "type": "NULL", "value": None, "text": ""}])
check("error-index 2 names the SECOND varbind of the response (1-based)",
      refused_oid(response, ["9.9", "8.8"]) == "1.3.6.1.2.1.1.5.0",
      refused_oid(response, ["9.9", "8.8"]))
empty = Response(error_status=16, error_index=1, varbinds=[])
check("an agent that echoed no varbinds is read against the request's own list",
      refused_oid(empty, SCALARS) == SYS_DESCR, refused_oid(empty, SCALARS))
check("error-index 0 names nothing, and nothing is what is reported",
      refused_oid(Response(error_status=16, error_index=0, varbinds=[]), SCALARS) == "")
check("an error-index past both lists names nothing either — no guessing "
      "at the first OID",
      refused_oid(Response(error_status=16, error_index=99, varbinds=[]), SCALARS) == "")
v2_config = {"snmp_version": 1, "community": "sekrit-community"}
text = access_denied_reason(v2_config, Response(error_status=16, error_index=0), SCALARS, "")
check("...and the message says so in words rather than inventing an object",
      "without naming the object it refused" in text and "error-index 0" in text, text)
check("a v2c refusal blames the community's view, without printing the community",
      "community's view does not include it" in text
      and secrets_absent(text, "sekrit-community"), text)
v3_config = {"snmp_version": 3, "v3_user": "poller", "v3_auth_proto": "SHA",
             "v3_auth_pass_enc": b"blob"}
check("security_level follows credential_for's rule: protocol AND password sign",
      security_level(v3_config) == "authNoPriv"
      and security_level({"snmp_version": 3, "v3_user": "poller"}) == "noAuthNoPriv"
      and security_level(v2_config) == "")
text = access_denied_reason(v3_config, empty, SCALARS, "authNoPriv")
check("an authNoPriv refusal names the OID in the walk's own shape",
      f"authorizationError(16) for {SYS_DESCR} — its SNMP agent refuses that object" in text, text)
check("...says the message authenticated and this is VACM, not the password",
      "authenticated" in text and "not a bad password" in text and "VACM" in text, text)
check("...raises authPriv as the likely cause and cites RFC 3415",
      "authPriv" in text and "RFC 3415" in text and "PAN-OS" in text, text)
check("...says what to do: set the privacy protocol and password on this "
      "credential (authPriv is implemented since 5.8.0), or grant an "
      "authNoPriv view",
      "privacy password on this credential" in text and "view at authNoPriv" in text
      and "not implemented" not in text and "cannot" not in text, text)
check("...and names the level the request went out at, beside the user",
      "'poller' at authNoPriv" in text, text)
text = access_denied_reason(v3_config, empty, SCALARS, "authPriv")
check("a request already at authPriv blames the view and stops — no level "
      "left to blame, and the label says authPriv even though the stored "
      "config alone would derive authNoPriv (the Test button's typed password)",
      "does not include that object" in text and "authNoPriv" not in text
      and "'poller' at authPriv" in text, text)
text = access_denied_reason({"snmp_version": 3, "v3_user": "poller"}, empty, SCALARS, "noAuthNoPriv")
check("an unsigned v3 request is told a view at a higher level cannot match it",
      "noAuthNoPriv" in text and "unsigned" in text, text)


# ===================================== § 2 the operator's case, end to end

print("\n-- PAN-OS: authPriv user, authNoPriv request, errorStatus 16")
stats = os.path.join(TMP, "denied.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--require-priv", "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("denied", PASSWORD)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    check("the poll fails SNMP with the refused OID named — sysDescr, the "
          "first object in the request, at error-index 1",
          row["snmp_ok"] == 0 and SYS_DESCR in error, error)
    check("...and the device row says the message authenticated and blames "
          "the level, not the password",
          "authenticated" in error and "not a bad password" in error
          and "authPriv" in error, error)
    check("...and never prints the password", secrets_absent(error, PASSWORD), error)
    check("the event recorded is access_denied, and NOT auth_fail",
          "access_denied" in kinds(db, did) and "auth_fail" not in kinds(db, did),
          kinds(db, did))
    check("`denied` was bumped and `auth_fail` was not",
          poller.counters["denied"] == 1 and poller.counters["auth_fail"] == 0,
          poller.counters)
    check("the device has no status of its own for this: it is reachable "
          "(its agent answered), so status follows reachability as an auth "
          "failure's does, and is not 'unsupported'",
          row["status"] != "unsupported", row["status"])
    poll_once(poller, db, did)
    check("a second refused poll records no second access_denied — it is a "
          "transition, like auth_fail",
          kinds(db, did).count("access_denied") == 1, kinds(db, did))
    check("...and no snmp_error 'SNMP is not answering' either: the agent answered",
          "snmp_error" not in kinds(db, did), kinds(db, did))
    time.sleep(0.05)
    with open(stats) as handle:
        import json
        counts = json.load(handle)
    check("the stub verified the signature and then refused — the fault the "
          "stub could not simulate before",
          counts.get("denied", 0) >= 2 and counts.get("wrong_digests", 0) == 0, counts)

    # -- the Test button, against the same device
    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    check("the Test reports the same fault, not 'engine resync required'",
          snmp["ok"] is False and "resync" not in (snmp["error"] or ""), snmp)
    check("...with security_level derived as authNoPriv",
          snmp.get("security_level") == "authNoPriv", snmp.get("security_level"))
    engine = snmp.get("engine") or {}
    check("...an engine block: discovery ok, id, boots, time, ms",
          engine.get("ok") is True and engine.get("id") and engine.get("boots") is not None
          and engine.get("time") is not None and "ms" in engine, engine)
    check("...auth.ok true: a non-Report reply came back for a signed request",
          (snmp.get("auth") or {}).get("ok") is True, snmp.get("auth"))
    check("...error_status 16 named authorizationError",
          snmp.get("error_status") == 16 and snmp.get("error_status_name") == "authorizationError",
          (snmp.get("error_status"), snmp.get("error_status_name")))
    check("...refused_oid names sysDescr", snmp.get("refused_oid") == SYS_DESCR, snmp.get("refused_oid"))
    check("...and a hint that raises authPriv",
          "authPriv" in (snmp.get("hint") or "") and "not a bad password" in (snmp.get("hint") or ""),
          snmp.get("hint"))
    phases = [p["name"] for p in snmp.get("phases", [])]
    check("...with engine discovery as a phase of its own, before the scalars",
          phases == ["engine discovery", "scalars"], phases)
    check("...and no report block: the agent answered a Response, not a Report",
          snmp.get("report") is None, snmp.get("report"))
    # The Test's headline + hint are the poll's snmp_error, word for word:
    # one function composes both, so they cannot drift apart.
    device = db.device(did)
    echoed = Response(error_status=16, error_index=1,
                      varbinds=[{"oid": o, "type": "NULL", "value": None, "text": ""}
                                for o in SCALARS])
    expected = access_denied_reason(db.effective_config(device), echoed, SCALARS, "authNoPriv")
    check("the Test button and the poll use the same words",
          f"{snmp['error']}. {snmp['hint']}" == expected == error,
          (snmp["error"], snmp["hint"], error))
    check("the Test payload never carries the password",
          secrets_absent(repr(result), PASSWORD), result)

    # -- a noAuthNoPriv credential against the same agent: unsigned is
    #    refused by USM (unsupportedSecLevels), which is 'unsupported', not
    #    access denied and not auth_fail.
    db2, did2 = new_v3_db("unsigned", None)
    poller2 = NodePoller(db2)
    poller2.log = CaptureLog()
    poll_once(poller2, db2, did2)
    row2 = db2.device(did2)
    check("an unsigned request to an auth user is 'unsupported' by type, and "
          "its 'authPriv' text no longer raises auth_fail",
          row2["status"] == "unsupported" and "auth_fail" not in kinds(db2, did2)
          and poller2.counters["auth_fail"] == 0, (row2["status"], kinds(db2, did2)))
finally:
    stub.kill()


# ===================================== § 3 a genuinely wrong password

print("\n-- wrongDigests: the real authentication failure still is one")
stats = os.path.join(TMP, "wrong.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("wrong", WRONG)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    check("a wrong auth password records auth_fail",
          "auth_fail" in kinds(db, did) and "access_denied" not in kinds(db, did),
          kinds(db, did))
    check("...bumps auth_fail and not denied",
          poller.counters["auth_fail"] == 1 and poller.counters["denied"] == 0,
          poller.counters)
    check("...and names usmStatsWrongDigests, never the password",
          "WrongDigests" in error and secrets_absent(error, WRONG, PASSWORD), error)

    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    check("the Test says auth.ok false for wrongDigests",
          snmp["ok"] is False and (snmp.get("auth") or {}).get("ok") is False, snmp)
    report = snmp.get("report") or {}
    check("...with a report block naming the counter, its OID and the explanation",
          report.get("name") == "wrongDigests"
          and report.get("oid") == "1.3.6.1.6.3.15.1.1.5"
          and "password" in (report.get("detail") or ""), report)
    check("...and the engine block still says discovery worked",
          (snmp.get("engine") or {}).get("ok") is True, snmp.get("engine"))

    # The typed-but-unsaved password, the Test button's whole point.
    result = api.post_nodes_device_test(FakeService(db), {}, {"v3_auth_pass": PASSWORD}, did)
    snmp = result["snmp"]
    check("the right password typed into the form passes the Test against the "
          "same agent, auth.ok true",
          snmp["ok"] is True and (snmp.get("auth") or {}).get("ok") is True
          and snmp.get("error_status") == 0, snmp)
    check("...and the successful payload carries neither password",
          secrets_absent(repr(result), PASSWORD, WRONG), result)

    # Recovery: the stored credential fixed, auth_ok follows auth_fail.
    gid = db.ensure_default_group()
    db.set_group_credential(gid, "poller", "SHA", dpapi.protect(PASSWORD.encode("utf-8")))
    poll_once(poller, db, did)
    check("fixing the password records auth_ok, the pair that clears the alert",
          kinds(db, did)[-1:] == ["auth_ok"] or "auth_ok" in kinds(db, did), kinds(db, did))
finally:
    stub.kill()


# ===================================== § 4 the shared resync loop

print("\n-- one resync loop for the poll and the Test")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD)
try:
    session = _Session("127.0.0.1", port, 1.0, 0)
    try:
        engine = discover_engine(session, "127.0.0.1")
        learned = []
        # A stale engine: boots from before a restart, time from long ago.
        stale = (engine[0], engine[1] - 1, 0)
        response = v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller",
                               auth_proto="SHA", password=PASSWORD, engine=stale,
                               ip="127.0.0.1", learned=lambda *e: learned.append(e))
        check("a first Report teaches the agent's boots/time and the retry succeeds",
              response.pdu_tag != PDU_REPORT and response.error_status == 0
              and len(learned) == 1 and learned[0][1] == engine[1], (learned, response.pdu_tag))
        learned = []
        response = v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller",
                              auth_proto="SHA", password=PASSWORD, engine=None,
                              ip="127.0.0.1", learned=lambda *e: learned.append(e))
        check("no engine at all discovers first, and hands the discovery to `learned`",
              response.pdu_tag != PDU_REPORT and len(learned) == 1, learned)
        try:
            v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller",
                        auth_proto="SHA", password=WRONG, engine=engine, ip="127.0.0.1")
            check("a wrong password raises", False)
        except _AuthFailure as exc:
            check("a wrong password raises _AuthFailure carrying the usmStats "
                  "name by attribute, not by substring",
                  exc.usm_name == "wrongDigests" and exc.report is not None
                  and "127.0.0.1" in str(exc), (exc.usm_name, str(exc)))
    finally:
        session.close()
finally:
    stub.kill()

print("\n-- notInTimeWindows twice is transient, not a failed password")
# A window of -1 rejects every signed request's engine time, so even the
# resynced retry draws a Report: the clock case, twice.
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--window", "-1")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("clock", PASSWORD)
    result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
    snmp = result["snmp"]
    auth = snmp.get("auth") or {}
    check("the Test reports auth.ok null for notInTimeWindows — the poller "
          "resyncs and retries on this and it is normally transient",
          snmp["ok"] is False and "ok" in auth and auth["ok"] is None
          and "transient" in (auth.get("detail") or ""), snmp)
    check("...with the report block naming notInTimeWindows",
          (snmp.get("report") or {}).get("name") == "notInTimeWindows", snmp.get("report"))
    check("...and the engine block recording that a Report re-taught it",
          (snmp.get("engine") or {}).get("resynced") is True, snmp.get("engine"))
finally:
    stub.kill()


# ===================================== § 5 discovery is a phase

print("\n-- a discovery timeout says discovery was the phase")
nodepoll_mod.DEFAULT_SNMP_PORT = free_udp_port()      # nothing listens there
db, did = new_v3_db("dark", PASSWORD, timeout_s=0.3)
result = api.post_nodes_device_test(FakeService(db), {}, {}, did)
snmp = result["snmp"]
check("the error names engine discovery and says no signed request was sent",
      snmp["ok"] is False and "engine discovery" in (snmp["error"] or "")
      and "never tested" in (snmp["error"] or ""), snmp["error"])
check("...engine.ok false, and the only phase is discovery",
      (snmp.get("engine") or {}).get("ok") is False
      and [p["name"] for p in snmp.get("phases", [])] == ["engine discovery"], snmp)
check("...and auth is null: nothing was proven either way", snmp.get("auth") is None, snmp)


# ===================================== § 6 classified by type, not substring

print("\n-- the substring bug, directly")
db, did = new_v3_db("substring", PASSWORD)
poller = NodePoller(db)
poller.log = CaptureLog()
canned = [SnmpUnsupported("127.0.0.1: the device refused this security level "
                          "(authPriv is not supported by this poller)")]


def failing(device, config):
    raise canned[0]


poller._poll_snmp_scalars_with_credential = failing
poll_once(poller, db, did)
check("an 'authPriv' message raised as SnmpUnsupported records unsupported, "
      "not auth_fail — the message contains 'auth' and that used to be enough",
      "unsupported" in kinds(db, did) and "auth_fail" not in kinds(db, did), kinds(db, did))
canned[0] = SnmpAccessDenied("the device answered authorizationError(16) for "
                             + SYS_DESCR + " — the message authenticated")
poll_once(poller, db, did)
check("an SnmpAccessDenied records access_denied, not auth_fail",
      "access_denied" in kinds(db, did) and "auth_fail" not in kinds(db, did), kinds(db, did))
canned[0] = _AuthFailure("127.0.0.1: SNMPv3 request refused (wrong community)")
poll_once(poller, db, did)
check("an _AuthFailure whose message does not contain 'auth' still records "
      "auth_fail: the type decides",
      "auth_fail" in kinds(db, did), kinds(db, did))


# ===================================== § 7 the dialog escapes what it renders

print("\n-- nodes.js renders the device's own strings through escape()")
with open(os.path.join(_paths.REPO_ROOT, "netpath", "web", "static", "nodes.js"),
          encoding="utf-8") as handle:
    js = handle.read()
start = js.index("async function testDevice(")
end = js.index("\n  }\n", start)
body = js[start:end]
check("the result is written with innerHTML only through escape() on every "
      "part and on the hint",
      "result.innerHTML = parts.map((part) => escape(part))" in body
      and "escape(r.snmp.hint)" in body, body[-400:])
check("...and nothing else in testDevice assigns innerHTML",
      body.count(".innerHTML") == 1, body.count(".innerHTML"))
check("the catch arm keeps textContent for the transport error",
      "result.textContent = `Error: ${error.message}`" in body)


# ===================================== § 8 a stray before the digest

print("\n-- a spoofed datagram with a foreign request id is a stray, not an auth alert")


class FakeAgent:
    """A loopback UDP peer answering every datagram with whatever
    `answer(data)` returns — for the two faults the stub cannot stage: a
    datagram that answers nothing we sent, and a Report under an engine
    id that is not the agent's."""

    def __init__(self, answer):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            for reply in self.answer(data) or ():
                self.sock.sendto(reply, addr)

    def close(self):
        self.sock.close()


FAKE_ENGINE = b"\x80\x00\x1f\x88\x80fake-engine"
FORGED_ENGINE = b"\x80\x00\x1f\x88\x80forged"
RIGHT_KEY = localized_key("SHA", PASSWORD, FAKE_ENGINE)
WRONG_KEY = localized_key("SHA", WRONG, FAKE_ENGINE)
USM_UNSUPPORTED = "1.3.6.1.6.3.15.1.1.1.0"
USM_NOT_IN_TIME = "1.3.6.1.6.3.15.1.1.2.0"
USM_UNKNOWN_ENGINE = "1.3.6.1.6.3.15.1.1.4.0"


def report_under(engine_id: bytes, boots: int, engine_time: int, oid: str,
                 msg_id: int = 1) -> bytes:
    """An unsigned Report-PDU naming `oid`, under any engine id at all.

    `msg_id` echoes the request's own msgID, which is what a real agent
    does and what the poller now requires of a Report (RFC 3412 s7.2):
    a Report against some other msgID is a stray and is dropped."""
    pdu = _tlv(PDU_REPORT, enc_int(0) + enc_int(0) + enc_int(0) + _tlv(
        T_SEQUENCE, enc_varbind(oid, enc_unsigned(T_COUNTER32, 1))))
    return _v3_message(msg_id, flags=0, engine_id=engine_id, engine_boots=boots,
                       engine_time=engine_time, user="", auth_placeholder_len=0,
                       priv_params=b"",
                       scoped=_tlv(T_SEQUENCE, enc_octets(engine_id) + enc_octets("") + pdu))


# The reviewers' reproduction: FLAG_AUTH, a wrong-key digest, request id
# 424242 while ours is 1000. Before the fix: SnmpAuthError with dropped=0;
# before 5.8.0: dropped, and the wait continued.
spoof = build_v3_request(1, 424242, PDU_GET, [SYS_DESCR], engine_id=FAKE_ENGINE,
                         engine_boots=1, engine_time=1, user="poller",
                         auth_proto="SHA", auth_key=WRONG_KEY)
agent = FakeAgent(lambda data: [spoof])
session = _Session("127.0.0.1", agent.port, 0.4, 0)
ours = build_v3_request(2, 1000, PDU_GET, [SYS_DESCR], engine_id=FAKE_ENGINE,
                        engine_boots=1, engine_time=1, user="poller",
                        auth_proto="SHA", auth_key=RIGHT_KEY)
try:
    try:
        session.request(ours, 1000, auth_proto="SHA", auth_key=RIGHT_KEY)
        check("the spoof is not accepted", False)
    except SnmpTimeout:
        check("a wrong-key datagram answering request id 424242 while we wait on "
              "1000 is dropped and the wait continues: SnmpTimeout, dropped == 1",
              session.dropped == 1, session.dropped)
    except SnmpAuthError as exc:
        check("a stray with a bad digest is dropped, not raised as an auth failure",
              False, str(exc))
    right_id = build_v3_request(1, 1000, PDU_GET, [SYS_DESCR], engine_id=FAKE_ENGINE,
                                engine_boots=1, engine_time=1, user="poller",
                                auth_proto="SHA", auth_key=WRONG_KEY)
    agent.answer = lambda data: [right_id]
    try:
        session.request(ours, 1000, auth_proto="SHA", auth_key=RIGHT_KEY)
        check("a bad digest on OUR id is refused", False)
    except SnmpAuthError:
        check("...while the same datagram carrying OUR request id is SnmpAuthError: "
              "the digest is still checked once the id says it is ours", True)
finally:
    session.close()
    agent.close()


# ===================================== § 9 a Report under a foreign engine id

print("\n-- a forged Report teaches nothing; only unknownEngineIDs may")


def forger(oid: str):
    """Answers discovery honestly (unknownEngineIDs under the real engine)
    and every signed request with a Report naming `oid` under an engine id
    we never sent, boots 99 — the poisoned cache the forgery is after."""
    def answer(data):
        if not decode_response(data).engine_id:
            return [report_under(FAKE_ENGINE, 3, 100, USM_UNKNOWN_ENGINE,
                                 decode_response(data).msg_id)]
        return [report_under(FORGED_ENGINE, 99, 1, oid,
                             decode_response(data).msg_id)]
    return answer


agent = FakeAgent(forger(USM_NOT_IN_TIME))
session = _Session("127.0.0.1", agent.port, 0.4, 0)
learned = []
try:
    try:
        v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller", auth_proto="SHA",
                    password=PASSWORD, engine=(FAKE_ENGINE, 3, 100), ip="127.0.0.1",
                    learned=lambda *e: learned.append(e))
        check("a forged Report on every attempt ends the exchange", False)
    except _AuthFailure as exc:
        check("a Report under a foreign engine id on both attempts is a named "
              "refusal, as a Report twice always was",
              exc.usm_name == "notInTimeWindows", (exc.usm_name, str(exc)))
    check("...but the forged engine id (boots 99) was never learned: the retry "
          "rediscovered instead, and only discovery's real engine reached the cache",
          learned == [(FAKE_ENGINE, 3, 100)], learned)
finally:
    session.close()
    agent.close()

agent = FakeAgent(forger(USM_UNSUPPORTED))
session = _Session("127.0.0.1", agent.port, 0.4, 0)
try:
    try:
        v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller", auth_proto="SHA",
                    password=PASSWORD, engine=(FAKE_ENGINE, 3, 100), ip="127.0.0.1")
        check("a forged unsupportedSecLevels ends the exchange", False)
    except SnmpUnsupported as exc:
        check("a forged unsupportedSecLevels under a foreign engine id does NOT file "
              "the device as unsupported (a week-long alert from one datagram)",
              False, str(exc))
    except _AuthFailure:
        check("a forged unsupportedSecLevels under a foreign engine id does NOT file "
              "the device as unsupported (a week-long alert from one datagram)", True)
finally:
    session.close()
    agent.close()

# The legitimate shape: the same Report under the engine id we sent.
agent = FakeAgent(lambda data: [report_under(
    FAKE_ENGINE, 3, 100, USM_UNSUPPORTED, decode_response(data).msg_id)])
session = _Session("127.0.0.1", agent.port, 0.4, 0)
try:
    try:
        v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller", auth_proto="SHA",
                    password=PASSWORD, engine=(FAKE_ENGINE, 3, 100), ip="127.0.0.1")
        check("a genuine unsupportedSecLevels is SnmpUnsupported", False)
    except SnmpUnsupported:
        check("...while unsupportedSecLevels under the engine id we sent is "
              "SnmpUnsupported, as the stub's own is", True)
finally:
    session.close()
    agent.close()


# ============================== § 9b a Report against another msgID is a stray

# RFC 3412 s7.2 has the receiver match a reply's msgID against the request
# it is waiting on. Reports are (correctly) exempt from the request-id
# filter, and the trusted rule above deliberately admits unknownEngineIDs
# under ANY engine id -- that is the Report whose purpose is to teach one.
# The msgID is what is left: the one field an off-path forger cannot know.

print("\n-- a Report whose msgID is not ours is dropped, not learned from")


def msg_id_offset(data):
    """Discovery answered honestly; every signed request answered with an
    unknownEngineIDs Report under an engine id of the forger's choosing,
    against a msgID one higher than the one we sent."""
    request = decode_response(data)
    if not request.engine_id:
        return [report_under(FAKE_ENGINE, 3, 100, USM_UNKNOWN_ENGINE,
                             request.msg_id)]
    return [report_under(FORGED_ENGINE, 99, 1, USM_UNKNOWN_ENGINE,
                         request.msg_id + 1)]


agent = FakeAgent(msg_id_offset)
session = _Session("127.0.0.1", agent.port, 0.4, 0)
learned = []
try:
    try:
        v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller",
                    auth_proto="SHA", password=PASSWORD,
                    engine=(FAKE_ENGINE, 3, 100), ip="127.0.0.1",
                    learned=lambda *e: learned.append(e))
        check("a Report against the wrong msgID does not complete the exchange",
              False)
    except (SnmpTimeout, SnmpError):
        check("a Report against a msgID we never sent is dropped and the wait "
              "continues, so the exchange ends in silence rather than in the "
              "forger's answer", True)
    check("...the forged engine id is never learned",
          not any(e[0] == FORGED_ENGINE for e in learned), repr(learned))
    check("...and the datagram is counted as a stray",
          session.dropped >= 1, session.dropped)
finally:
    session.close()
    agent.close()

# The same agent, echoing the msgID it was sent: the exchange proceeds
# exactly as it did before, which is what makes the check above safe.
agent = FakeAgent(lambda data: [report_under(
    FAKE_ENGINE, 3, 100, USM_UNKNOWN_ENGINE, decode_response(data).msg_id)])
session = _Session("127.0.0.1", agent.port, 0.4, 0)
learned = []
try:
    try:
        v3_exchange(session, PDU_GET, [SYS_DESCR], identity="poller",
                    auth_proto="SHA", password=PASSWORD,
                    engine=(FAKE_ENGINE, 3, 100), ip="127.0.0.1",
                    learned=lambda *e: learned.append(e))
    except SnmpError:
        pass
    check("a conforming agent's Report -- same msgID -- still teaches its "
          "engine parameters", any(e[0] == FAKE_ENGINE for e in learned),
          repr(learned))
    check("...and nothing was dropped on the way", session.dropped == 0,
          session.dropped)
finally:
    session.close()
    agent.close()

# discovery_probe() defaulted to msgID 1 for every probe ever sent, so the
# one exchange whose whole answer is a Report had nothing to match against.
sent = []


def capture_probe(data):
    sent.append(data)
    return [report_under(FAKE_ENGINE, 3, 100, USM_UNKNOWN_ENGINE,
                         decode_response(data).msg_id)]


agent = FakeAgent(capture_probe)
session = _Session("127.0.0.1", agent.port, 0.4, 0)
try:
    engine = discover_engine(session, "127.0.0.1")
    probes = [decode_response(data).msg_id for data in sent]
    check("discovery still learns the engine", engine[0] == FAKE_ENGINE,
          repr(engine))
    check("...from a probe carrying this session's own msgID rather than the "
          "fixed 1 every probe used to send",
          probes and probes[0] != 1, repr(probes))
finally:
    session.close()
    agent.close()


# ===================================== § 10 auth_ok on the agent's own word

print("\n-- a fixed password refused by VACM still closes the auth alert")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--require-priv")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("authok", WRONG)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    check("a wrong password records auth_fail", "auth_fail" in kinds(db, did), kinds(db, did))
    db.set_group_credential(db.ensure_default_group(), "poller", "SHA",
                            dpapi.protect(PASSWORD.encode("utf-8")))
    poll_once(poller, db, did)
    seen = kinds(db, did)
    check("the fixed password, refused by VACM instead, records access_denied AND "
          "auth_ok — the row says the message authenticated, so the alert saying "
          "authentication is failing has been contradicted and must close",
          "access_denied" in seen and "auth_ok" in seen
          # device_events is newest first: auth_ok must be newer than auth_fail
          and seen.index("auth_ok") < seen.index("auth_fail"), seen)
    check("...and the device is out of _auth_failing", did not in poller._auth_failing)
finally:
    stub.kill()


# ===================================== § 11 a downgrade is not an outage

print("\n-- unsigned replies, polled past the outage threshold, ping off")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--unsigned-replies")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("downgrade", PASSWORD)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    statuses = []
    for _ in range(4):                     # down_after_failures ships as 3
        poll_once(poller, db, did)
        statuses.append(db.device(did)["status"])
    seen = kinds(db, did)
    check("the device is UP on every poll: it answered every request",
          statuses == ["up"] * 4, statuses)
    check("...no down event, no outage, and no auth_fail",
          "down" not in seen and "auth_fail" not in seen, seen)
    check("...one snmp_downgrade event, a transition, not one per poll",
          seen.count("snmp_downgrade") == 1, seen)
    check("...counted as downgraded, not as errors",
          poller.counters["downgraded"] == 4 and poller.counters["errors"] == 0
          and poller.counters["auth_fail"] == 0, poller.counters)
    error = db.device(did)["snmp_error"] or ""
    check("...and the row keeps the message that names the off switch",
          "downgrade" in error and "Verify the signature on every SNMPv3 reply" in error,
          error)
    check("the credential loop did not rotate on it (no probe-failed stamp)",
          did not in poller._credential_probe_failed)
    # Ping on, answering: the device is up by ping alone, and the question
    # is the snmp_error event that reads "SNMP is not answering".
    real_ping = nodepoll_mod.ping_many
    nodepoll_mod.ping_many = lambda ip, count=3, timeout_ms=1000: (count, count, 0.2)
    try:
        db.update_group(db.ensure_default_group(), ping_enabled=1)
        for _ in range(4):                 # snmp_fail_alert_after ships as 3
            poll_once(poller, db, did)
    finally:
        nodepoll_mod.ping_many = real_ping
    check("with ping on, no snmp_error event either: 'SNMP is not answering' is "
          "untrue of an agent that answered every request",
          "snmp_error" not in kinds(db, did), kinds(db, did))
    db.save_settings({"v3_verify_replies": False})
    poll_once(poller, db, did)
    check("with the setting off the next poll succeeds and records snmp_verified",
          db.device(did)["snmp_ok"] == 1 and "snmp_verified" in kinds(db, did),
          kinds(db, did))
    check("...once: a second good poll records nothing",
          (poll_once(poller, db, did), kinds(db, did).count("snmp_verified"))[1] == 1)
    rule = next((r for r in alertsdb._BUILTIN_RULES if r[0] == "device_downgrade"), None)
    check("the device_downgrade rule ships, on device_event/snmp_downgrade, with no "
          "auto-resolve (a state with a real clear)",
          rule is not None and rule[2:4] == ("device_event", "snmp_downgrade")
          and "device_downgrade" not in alertsdb._BUILTIN_AUTO_RESOLVE_S, rule)
    check("...cleared by snmp_verified (alertrules.CLEARS)",
          alertrules.CLEARS.get(("device_event", "snmp_verified")) == "device_downgrade")
finally:
    stub.kill()


# ===================================== § 12 rotation and the error that wins

print("\n-- a contradicted credential does not rotate; the named refusal wins")
db, did = new_v3_db("rotate", PASSWORD)
poller = NodePoller(db)
poller.log = CaptureLog()
db.credential_candidates = lambda device: [
    {"snmp_version": 3, "v3_user": "primary"},
    {"snmp_version": 1, "community": "cleartext-alternate"}]
tried: list[int] = []            # the snmp_version of each candidate tried
scripted: list[Exception] = []


def scripted_scalars(device, config):
    tried.append(snmp_version_of(config))
    raise scripted[len(tried) - 1]


poller._poll_snmp_scalars = scripted_scalars
scripted[:] = [SnmpDowngrade("the device's reply carried no signature — downgrade"),
               SnmpTimeout("no reply from the alternate")]
poll_once(poller, db, did)
check("a downgrade on the primary stops the sweep: the v2c alternate is never "
      "tried, so one forged unsigned reply cannot walk the poller onto a "
      "cleartext community",
      tried == [3], tried)
check("...and the row carries the downgrade",
      "downgrade" in (db.device(did)["snmp_error"] or ""))
tried.clear()
scripted[:] = [_AuthFailure("127.0.0.1: SNMPv3 reply rejected — the reply's "
                            "signature does not verify"),
               SnmpTimeout("no reply")]
poll_once(poller, db, did)
check("a digest THIS END refused (an _AuthFailure with no Report) does not rotate "
      "either", tried == [3], tried)
tried.clear()
poller._credential_probe_failed.clear()
scripted[:] = [_AuthFailure("127.0.0.1: SNMPv3 request refused (the authentication "
                            "password or protocol is wrong) [usmStatsWrongDigests]",
                            usm_name="wrongDigests", report=Response(pdu_tag=PDU_REPORT)),
               SnmpTimeout("no reply from 127.0.0.1")]
poll_once(poller, db, did)
error = db.device(did)["snmp_error"] or ""
check("a refusal the DEVICE named (a wrongDigests Report) does rotate: both "
      "candidates tried", tried == [3, 1], tried)
check("...and the alternate's timeout does not mask it: the row names "
      "WrongDigests, not 'no reply'",
      "WrongDigests" in error and "no reply" not in error, error)
tried.clear()
poller._credential_probe_failed.clear()
scripted[:] = [SnmpTimeout("no reply from 127.0.0.1"),
               SnmpAccessDenied("the device answered authorizationError(16)")]
poll_once(poller, db, did)
check("...the other way round too: a timeout first, then a named refusal — the "
      "refusal is what is stored",
      "authorizationError" in (db.device(did)["snmp_error"] or ""),
      db.device(did)["snmp_error"])


# ===================================== § 13 snmp_version None

print("\n-- a None snmp_version is the v2c default, never a TypeError")
check("snmp_version_of: None and absent are v2c (1); 0 stays v1; 3 stays v3",
      snmp_version_of({"snmp_version": None}) == 1 and snmp_version_of({}) == 1
      and snmp_version_of({"snmp_version": 0}) == 0 and snmp_version_of({"snmp_version": 3}) == 3)
check("credential_for survives the None overlay",
      credential_for({"snmp_version": None, "community": "public"}).identity == "public")
nodepoll_mod.DEFAULT_SNMP_PORT = free_udp_port()      # nothing listens there
db, did = new_v3_db("none-version", PASSWORD, timeout_s=0.2)
poller = NodePoller(db)
poller.log = CaptureLog()
db.credential_candidates = lambda device: [{"snmp_version": None, "community": "public"}]
try:
    poll_once(poller, db, did)
    check("a poll whose candidate carries snmp_version None completes as a timeout "
          "(record_poll ran; the status did not freeze)",
          db.device(did)["last_poll_ts"] is not None
          and "no reply" in (db.device(did)["snmp_error"] or ""), db.device(did)["snmp_error"])
except TypeError as exc:
    check("a poll whose candidate carries snmp_version None completes", False, str(exc))


# ===================================== § 14 an authentication blob that will not decrypt

print("\n-- an undecryptable auth blob raises rather than polling unsigned")
try:
    credential_for({"snmp_version": 3, "v3_user": "poller", "v3_auth_proto": "SHA",
                    "v3_auth_pass_enc": b"not-a-blob-this-machine-can-read"})
    check("an undecryptable authentication blob raises", False, "returned a credential")
except SnmpError as exc:
    check("an undecryptable authentication blob raises, naming the authentication "
          "password and the refusal to poll unsigned — the privacy blob's rule, "
          "applied to both",
          "authentication password" in str(exc) and "unsigned" in str(exc), str(exc))
stale = credential_for({"snmp_version": 1, "community": "public",
                        "v3_auth_pass_enc": b"stale", "v3_priv_proto": "AES",
                        "v3_priv_pass_enc": b"stale-too"})
check("...but a v2c profile carrying stale v3 blobs it never reads still polls "
      "with its community", stale.identity == "public" and stale.auth_password is None)


# ===================================== § 15 the cached engine nobody could drop

# The field report's shape, against the real stub: poll 1 discovers and
# succeeds; the agent restarts (boots + 1) while the poller sleeps; poll 2
# goes out on the cached engine and the agent DROPS it — no Report, so
# nothing the resync loop can learn from. Before 5.8.1 only _AuthFailure
# invalidated the cache, so poll 3, 4, ... rebuilt the same doomed request
# until the service was restarted.
print("\n-- a silently dropped request on a cached engine: invalidated, rediscovered")
stats = os.path.join(TMP, "silent.json")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD,
                        "--bump-boots-at", "0.5", "--silent-out-of-window",
                        "--window", "5", "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port


def stub_counts() -> dict:
    time.sleep(0.05)                      # the stub writes after it answers
    with open(stats) as handle:
        return json.load(handle)


try:
    db, did = new_v3_db("silent", PASSWORD, timeout_s=0.4)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    first = poller._engines.get(did)
    check("poll 1: discovers, polls, and caches the engine",
          db.device(did)["snmp_ok"] == 1 and first is not None
          and stub_counts().get("discoveries") == 1,
          (db.device(did)["snmp_error"], first, stub_counts()))

    time.sleep(0.8)                       # past --bump-boots-at: the agent restarts
    poll_once(poller, db, did)
    row = db.device(did)
    error = row["snmp_error"] or ""
    counts = stub_counts()
    check("poll 2: the cached request is dropped without a Report — a timeout, "
          "'no reply', no auth_fail event, and no discovery in that poll",
          row["snmp_ok"] == 0 and "no reply" in error
          and "auth_fail" not in kinds(db, did)
          and counts.get("dropped_stale") == 1 and counts.get("discoveries") == 1,
          (error, kinds(db, did), counts))
    check("...and the cached engine was DROPPED on that one timeout "
          "(red before 5.8.1: only _AuthFailure ever invalidated it)",
          poller._engines.get(did) is None, poller._engines.get(did))
    check("...the error says so, keeping the 'no reply' prefix every "
          "existing check matches on",
          error.startswith("no reply from") and "cached SNMPv3 engine" in error
          and "next poll" in error, error)

    poll_once(poller, db, did)
    counts = stub_counts()
    check("poll 3: rediscovers (discoveries == 2) and SUCCEEDS "
          "(red before 5.8.1: the same doomed request, forever, until a restart)",
          db.device(did)["snmp_ok"] == 1 and counts.get("discoveries") == 2,
          (db.device(did)["snmp_error"], counts))

    poll_once(poller, db, did)
    counts = stub_counts()
    check("poll 4: a good entry is kept — no new discovery, still polling",
          db.device(did)["snmp_ok"] == 1 and counts.get("discoveries") == 2,
          (db.device(did)["snmp_error"], counts))
    check("nothing along the way carried the password",
          secrets_absent(" ".join(poller.log.lines) + (db.device(did)["snmp_error"] or ""),
                         PASSWORD))
finally:
    stub.kill()

# The scope guard: an engine learned INSIDE the failing call is fresh —
# the agent just taught it — and is kept. Discovery answers honestly, then
# every signed request is dropped: a slow or firewalled device, not a
# stale cache. Nothing invalidates here before OR after 5.8.1 (there was
# nothing cached going in), so this cannot fail against the old code; it
# fails against the naive "invalidate on every v3 timeout" and pins the
# rule that keeps a slow device from rediscovering on every poll.
print("\n-- an engine learned inside the failing call is kept")


def discovery_only(data):
    if not decode_response(data).engine_id:
        return [report_under(FAKE_ENGINE, 3, 100, USM_UNKNOWN_ENGINE,
                             decode_response(data).msg_id)]
    return []


agent = FakeAgent(discovery_only)
nodepoll_mod.DEFAULT_SNMP_PORT = agent.port
try:
    db, did = new_v3_db("fresh", PASSWORD, timeout_s=0.4)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    entry = poller._engines.get(did)
    error = db.device(did)["snmp_error"] or ""
    check("a timeout right after discovery in the same call keeps the fresh "
          "engine: it was just learned, not stale",
          db.device(did)["snmp_ok"] == 0 and "no reply" in error
          and entry is not None and entry[:3] == (FAKE_ENGINE, 3, 100),
          (error, entry))
    check("...and the message does not claim a cached engine was dropped",
          "cached SNMPv3 engine" not in error, error)
finally:
    agent.close()

# An operator's explicit retry is the one place a cache is discarded on
# request: had poll_now done this, the field report would have been
# self-diagnosing (the click would have polled) instead of failing
# identically to the scheduler. Unit-tested on an unstarted poller: there
# is no pool, _submit returns False, and the drop is still observable.
print("\n-- poll_now drops the cached engine before submitting")
db, did = new_v3_db("pollnow", PASSWORD)
poller = NodePoller(db)
poller._engines.set(did, FAKE_ENGINE, 3, 100)
queued = poller.poll_now(did)
check("poll_now on an unstarted poller returns False (nothing to submit to)",
      queued is False, queued)
check("...and has dropped the device's cached engine (red before 5.8.1)",
      poller._engines.get(did) is None, poller._engines.get(did))

# The path that always invalidated must still: a refusal the device named
# (wrongDigests, twice) drops the entry. Passes before and after by
# construction — a regression guard on the arm the fix sits beside.
print("\n-- _AuthFailure still invalidates")
stub, port = spawn_stub("stub_agent_iftable.py", "v3", "--auth-pass", PASSWORD)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, did = new_v3_db("stillauth", WRONG)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, did)
    check("a wrongDigests refusal records auth_fail and drops the cached engine, "
          "as it always did",
          "auth_fail" in kinds(db, did) and poller._engines.get(did) is None,
          (kinds(db, did), poller._engines.get(did)))
finally:
    stub.kill()

print()
if FAILS:
    print(f"{len(FAILS)} FAILED:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all SNMPv3 diagnostics checks passed")

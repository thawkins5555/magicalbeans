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

There was no SNMPv3 suite at all before this one, which is how the fault
shipped.
"""
import os
import sys
import time

# Before any netpath import: off Windows dpapi.protect() is the portable
# secret store, which needs a passphrase from the environment.
os.environ.setdefault("NETPATH_SECRET_PASSPHRASE", "snmpv3-diagnostics-suite")

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import free_udp_port, spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath import dpapi, nodeoids
from netpath.nodepoll import (
    NodePoller, _AuthFailure, _Session, access_denied_reason,
    discover_engine, refused_oid, security_level, v3_exchange)
from netpath.nodesdb import NodesDatabase
from netpath.snmppoll import (
    PDU_GET, PDU_REPORT, Response, SnmpAccessDenied, SnmpError,
    SnmpUnsupported)
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
    nodes_db and nothing else."""

    def __init__(self, nodes_db):
        self.nodes_db = nodes_db


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
check("...says what to do, honestly: an authNoPriv view, since authPriv is "
      "not implemented here",
      "view at authNoPriv" in text and "not" in text and "implemented" in text, text)
text = access_denied_reason(v3_config, empty, SCALARS, "authPriv")
check("a request already at authPriv blames the view and stops — no level "
      "left to blame",
      "does not include that object" in text and "authNoPriv" not in text, text)
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

print()
if FAILS:
    print(f"{len(FAILS)} FAILED:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all SNMPv3 diagnostics checks passed")

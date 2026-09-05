"""Wave 4, job 2: a diff between two of a device's stored ConfigRX backups
(Tier 2 — "the hashes that detect the change are already stored").

Covers, first against configrx.diff_texts() directly (the stdlib difflib
wiring, no server involved), then against a real Service+WebServer:

  - diff_texts() produces the expected unified-diff hunks for two known
    texts, and an empty diff for two identical ones.
  - GET /api/configrx/diff redacts BOTH backups a second time regardless of
    how they were stored: a secret present in both never appears in the
    diff, and a secret that merely changed value renders as no line at all
    (both sides collapse onto the same "<redacted>" token) — the documented
    choice, see api.get_configrx_diff's own docstring.
  - Two backups with the same content hash (the same row picked twice, or
    two distinct rows that happen to match) take the empty-diff fast path.
  - The default adjacent pair (no from/to) diffs the two most recent
    backups; from/to name any other pair; a pair spanning two different
    devices, or a device with fewer than two backups, is refused.
  - The gate matches get_configrx_backup exactly (4.49.0: diffing two
    backups a configrx:read account can already fetch individually is not
    a write, so it no longer needs one): a configrx:write account may
    diff, so may a configrx:read-only account, and an account holding
    write on an unrelated module is refused.
"""
import http.client
import json
import os
import time
from urllib.parse import urlencode

import _paths  # noqa: F401

from netpath import configrx
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("configrx_diff_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------------- diff_texts() alone
print("configrx.diff_texts()")
old = "interface Gi0/1\n description uplink\n no shutdown\n"
new = "interface Gi0/1\n description core-uplink\n no shutdown\n"
text, additions, removals = configrx.diff_texts(old, new, "old.txt", "new.txt")
check("a one-line change produces exactly one +/- pair",
      additions == 1 and removals == 1, (additions, removals))
check("the changed line appears on both sides of the hunk",
      "- description uplink" in text and "+ description core-uplink" in text, text)
check("the file labels are carried through", "old.txt" in text and "new.txt" in text, text)

same_text, same_add, same_rem = configrx.diff_texts(old, old, "a", "b")
check("identical text diffs to nothing", same_text == "" and same_add == 0 and same_rem == 0,
      (same_text, same_add, same_rem))


# ------------------------------------------------------------------- the API
service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    data = None
    if method == "GET":
        if body:
            path = f"{path}?{urlencode(body)}"
    else:
        data = json.dumps(body).encode() if body is not None else None
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, body=data, headers=headers)
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
    device_id = service.nodes_db.add_device(
        "10.50.0.1", name="cx-diff-sw", group_id=service.nodes_db.ensure_default_group())

    # A secret PRESENT IN BOTH versions, and one that CHANGES between them —
    # stored unredacted (redacted=False), the store_secrets=on shape, so the
    # diff route's own second redaction pass is what has to catch these,
    # not anything that already happened at capture time.
    v1 = ("hostname cx-diff-sw\n"
         "snmp-server community s3cr3t-v1 RO\n"
         "enable secret 5 $1$aaa$AAAAAAAAAAAAAAAAAAAAAA\n"
         "interface Gi0/1\n description uplink\n")
    v2 = ("hostname cx-diff-sw\n"
         "snmp-server community s3cr3t-v1 RO\n"          # unchanged secret
         "enable secret 5 $1$bbb$BBBBBBBBBBBBBBBBBBBBBB\n"  # CHANGED secret
         "interface Gi0/1\n description core-uplink\n")   # ordinary change
    v3 = v1    # a config reverted to exactly what v1 was

    backup1_id, hash1 = service.configrx_db.add_backup(device_id, v1, redacted=False)
    time.sleep(0.01)
    backup2_id, hash2 = service.configrx_db.add_backup(device_id, v2, redacted=False)
    time.sleep(0.01)
    backup3_id, hash3 = service.configrx_db.add_backup(device_id, v3, redacted=False)
    check("three distinct backups were stored (v3 matches v1's hash, not v2's)",
          None not in (backup1_id, backup2_id, backup3_id) and hash1 == hash3 != hash2,
          (backup1_id, backup2_id, backup3_id, hash1, hash2, hash3))

    print("GET /api/configrx/diff — redaction and the ordinary change")
    status, payload = call(
        "GET", "/api/configrx/diff",
        {"device": device_id, "from": backup1_id, "to": backup2_id}, token=admin)
    check("200", status == 200, (status, payload))
    diff_text = payload.get("diff", "")
    check("the unchanged secret never appears, redacted in its place",
          "s3cr3t-v1" not in diff_text and "<redacted>" in diff_text, diff_text)
    check("neither secret hash value leaks either",
          "$1$aaa$" not in diff_text and "$1$bbb$" not in diff_text, diff_text)
    # "enable secret" legitimately appears as unchanged CONTEXT (difflib's
    # default 3 lines around a hunk) — what must be absent is a +/- line
    # naming it, which is what would mean the redacted value still differed.
    check("the changed secret produces NO +/- diff line — both sides redact to"
          " the identical token, so there is nothing to show as a change",
          not any(ln[:1] in "+-" and "enable secret" in ln
                  for ln in diff_text.splitlines()[2:]),  # skip the +++/--- file header lines
          diff_text)
    diff_lines = diff_text.splitlines()
    check("the ordinary (non-secret) line change IS shown, as a real -/+ pair",
          any(ln.startswith("-") and "description uplink" in ln for ln in diff_lines)
          and any(ln.startswith("+") and "description core-uplink" in ln for ln in diff_lines),
          diff_text)
    check("additions/removals were tallied", payload.get("additions", 0) >= 1
          and payload.get("removals", 0) >= 1, payload)
    check("metadata carries both backups' timestamps and hashes",
          payload["from"]["id"] == backup1_id and payload["to"]["id"] == backup2_id
          and payload["from"]["sha256"] == hash1 and payload["to"]["sha256"] == hash2
          and payload["from"]["ts"] > 0 and payload["to"]["ts"] > payload["from"]["ts"], payload)
    check("not flagged identical", payload.get("identical") is False, payload)

    print("same-hash pair: the fast path")
    status, payload = call(
        "GET", "/api/configrx/diff",
        {"device": device_id, "from": backup1_id, "to": backup1_id}, token=admin)
    check("picking the same backup twice: empty diff, identical",
          status == 200 and payload.get("diff") == "" and payload.get("identical") is True,
          (status, payload))
    status, payload = call(
        "GET", "/api/configrx/diff",
        {"device": device_id, "from": backup1_id, "to": backup3_id}, token=admin)
    check("two DIFFERENT rows sharing a hash (v3 reverted to v1) also fast-path to empty",
          status == 200 and payload.get("diff") == "" and payload.get("identical") is True,
          (status, payload))

    print("default adjacent pair (no from/to)")
    status, payload = call("GET", "/api/configrx/diff", {"device": device_id}, token=admin)
    check("diffs the two most recent stored backups (v2 -> v3, i.e. v2 -> v1)",
          status == 200 and payload["from"]["id"] == backup2_id
          and payload["to"]["id"] == backup3_id, (status, payload))

    print("refusals")
    other_device_id = service.nodes_db.add_device(
        "10.50.0.2", name="cx-diff-other", group_id=service.nodes_db.ensure_default_group())
    other_backup_id, _ = service.configrx_db.add_backup(other_device_id, "hostname other\n")
    status, payload = call(
        "GET", "/api/configrx/diff",
        {"device": device_id, "from": backup1_id, "to": other_backup_id}, token=admin)
    check("a backup belonging to a different device is refused",
          status == 400, (status, payload))
    lonely_device_id = service.nodes_db.add_device(
        "10.50.0.3", name="cx-diff-lonely", group_id=service.nodes_db.ensure_default_group())
    service.configrx_db.add_backup(lonely_device_id, "hostname lonely\n")
    status, payload = call(
        "GET", "/api/configrx/diff", {"device": lonely_device_id}, token=admin)
    check("a device with only one stored backup is refused",
          status == 400, (status, payload))
    status, payload = call("GET", "/api/configrx/diff", {"device": 999999}, token=admin)
    check("an unknown device is refused", status == 400, (status, payload))

    print("gates: matches get_configrx_backup exactly (configrx read is enough)")
    service.app_db.add_user("cx-diff-writer", hash_password("CxDiffWriterPW2026"), must_change=False)
    service.app_db.set_permissions("cx-diff-writer", {"configrx": "write"})
    writer = login("cx-diff-writer", "CxDiffWriterPW2026")
    service.app_db.add_user("cx-diff-reader", hash_password("CxDiffReaderPW2026"), must_change=False)
    service.app_db.set_permissions("cx-diff-reader", {"configrx": "read"})
    reader = login("cx-diff-reader", "CxDiffReaderPW2026")
    service.app_db.add_user("cx-diff-outsider", hash_password("CxDiffOutsiderPW2026"), must_change=False)
    service.app_db.set_permissions("cx-diff-outsider", {"nodes": "write"})
    outsider = login("cx-diff-outsider", "CxDiffOutsiderPW2026")

    params = {"device": device_id, "from": backup1_id, "to": backup2_id}
    status, payload = call("GET", "/api/configrx/diff", params, token=writer)
    check("a configrx:write account may diff", status == 200, (status, payload))
    status, payload = call("GET", "/api/configrx/diff", params, token=reader)
    check("a configrx:read-only account may diff too (same grant as fetching either "
          "backup on its own)", status == 200, (status, payload))
    status, payload = call("GET", "/api/configrx/diff", params, token=outsider)
    check("an account with write on an unrelated module is refused",
          status == 403, (status, payload))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)

"""4.49.0: POST /api/alerts/templates/<id>/preview renders an in-progress
EDIT (subject/body/is_html in the request body) rather than only the
template's already-saved values — this is what lets a Preview button work
against whatever is currently typed into the edit form, without saving
first and reverting on cancel. Falls back to the stored row for whichever
of the three fields the caller does not send a draft for.
"""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("template_preview_draft_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


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
    data = json.dumps(body).encode() if (method != "GET" and body is not None) else None
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

    status, payload = call("GET", "/api/alerts/templates", token=admin)
    check("200", status == 200, (status, payload))
    template = payload["templates"][0]
    template_id = template["id"]
    stored_subject, stored_body, stored_is_html = (
        template["subject"], template["body"], template["is_html"])

    print("no overrides: renders the stored template unchanged")
    status, payload = call("POST", f"/api/alerts/templates/{template_id}/preview",
                           {}, token=admin)
    check("200", status == 200, (status, payload))
    check("is_html echoes the stored value when not overridden",
          payload["is_html"] == stored_is_html, payload)

    print("subject-only override: body still falls back to the stored template")
    status, draft_payload = call(
        "POST", f"/api/alerts/templates/{template_id}/preview",
        {"subject": "DRAFT SUBJECT {{device}}"}, token=admin)
    check("200", status == 200, (status, draft_payload))
    check("the draft subject rendered, not the stored one",
          "DRAFT SUBJECT" in draft_payload["subject"]
          and draft_payload["subject"] != payload["subject"], draft_payload)
    check("body unaffected — still the stored template's rendering",
          draft_payload["body"] == payload["body"], (draft_payload, payload))

    print("full draft override: subject, body and is_html all come from the request")
    status, payload = call(
        "POST", f"/api/alerts/templates/{template_id}/preview",
        {"subject": "New subject: {{message}}", "body": "New body: {{message}}",
         "is_html": not stored_is_html}, token=admin)
    check("200", status == 200, (status, payload))
    check("draft subject/body both rendered",
          "New subject:" in payload["subject"] and "New body:" in payload["body"], payload)
    check("is_html reflects the override, not the stored value",
          payload["is_html"] == (not stored_is_html), payload)

    print("the stored template itself was never touched by any of this")
    status, payload = call("GET", "/api/alerts/templates", token=admin)
    stored_now = next(t for t in payload["templates"] if t["id"] == template_id)
    check("subject/body/is_html on disk are exactly as they were before any preview call",
          stored_now["subject"] == stored_subject and stored_now["body"] == stored_body
          and stored_now["is_html"] == stored_is_html, stored_now)

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)

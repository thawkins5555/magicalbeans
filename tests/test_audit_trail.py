"""4.49.0: the audit trail's widening from authentication/credential/
destructive-admin actions only (its original scope) to the configuration
changes an operator needs to answer for after the fact — NetPath
destinations, devices and their bulk operations, device groups, polling
profiles, MIBs, alert rule definitions, IPAM subnets, and ConfigRX backup
deletion. Before this, "who changed the CPU threshold from 90 to 99 last
March" was unanswerable; this suite proves each new call site actually
writes a row with the right action/target, via appdb.audit_query, driven
against a real Service+WebServer.

One test per action, plus three cross-cutting checks worth their own
assertions:
  - a device edit's vendor_override gets its OWN audit line, not folded
    into the generic field diff (they are different kinds of change).
  - the SNMP community string never appears in an audit detail, even when
    it is the field that changed (device edits and polling-profile edits
    both carry it).
  - put_alerts_rule's threshold/clear_threshold/enabled sort first in the
    diff, ahead of whatever else changed.
  - configrx.store_secrets' target is device:{ip}, not a bare device id
    (the one pre-existing inconsistency this pass corrected).

post_target (creating a NetPath destination) calls service.monitor.
trace_now() on success, which would otherwise spawn a REAL tracert/
traceroute subprocess against an address nothing answers — real
subprocess time this suite has no use for and, at fleet scale, the kind
of shared-machine resource contention this campaign's coordination rules
exist to avoid (measured hitting this the slow way once while writing
test_target_validation.py). netpath.monitor.run_trace is monkeypatched to
an instant stub for this whole file, the same technique
test_service_shutdown.py already uses for the same reason.
"""
import base64
import http.client
import json
import os
import time

import _paths  # noqa: F401

import netpath.monitor as monitor_mod
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.tracer import TraceResult
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("audit_trail_")
FAILS = []

_real_run_trace = monitor_mod.run_trace


def _instant_run_trace(host, **kwargs):
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=0.0)


monitor_mod.run_trace = _instant_run_trace


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


def last_audit(action, target=None):
    """The newest audit row for this action (optionally also matching
    target), or None. Widened well past "now" on both sides since these
    calls run in quick succession against one shared clock."""
    rows = service.app_db.audit_query(0, time.time() + 60, action=action,
                                      target=target or "", limit=50)
    return rows[0] if rows else None


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()

    # --------------------------------------------------------- NetPath targets
    print("target.create / target.update / target.delete")
    status, payload = call("POST", "/api/netpath/targets", {"host": "10.70.0.1"}, token=admin)
    check("200", status == 200, (status, payload))
    target_id = payload["id"]
    row = last_audit("target.create", str(target_id))
    check("target.create audited with host in detail",
          row is not None and "host=10.70.0.1" in row["detail"], row and dict(row))

    status, payload = call("PUT", f"/api/netpath/targets/{target_id}",
                           {"interval_s": 120}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("target.update", str(target_id))
    check("target.update audited with the old -> new value",
          row is not None and "interval_s:" in row["detail"] and "-> 120" in row["detail"],
          row and dict(row))

    status, payload = call("DELETE", f"/api/netpath/targets/{target_id}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("target.delete", str(target_id))
    check("target.delete audited with the host it removed",
          row is not None and "host=10.70.0.1" in row["detail"], row and dict(row))

    # -------------------------------------------------------------- devices
    print("device.create / device.update / device.delete / device.bulk_*")
    status, payload = call("POST", "/api/nodes/devices",
                           {"ip": "10.70.1.1", "name": "audit-dev-1",
                            "group_id": gid}, token=admin)
    check("200", status == 200, (status, payload))
    dev1 = payload["id"]
    row = last_audit("device.create", "device:10.70.1.1")
    check("device.create audited under device:{ip}",
          row is not None and f"group_id={gid}" in row["detail"], row and dict(row))

    status, payload = call("PUT", f"/api/nodes/devices/{dev1}",
                           {"name": "renamed-dev-1"}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.update", "device:10.70.1.1")
    check("device.update audited with the field diff",
          row is not None and "name:" in row["detail"] and "renamed-dev-1" in row["detail"],
          row and dict(row))

    status, payload = call("PUT", f"/api/nodes/devices/{dev1}",
                           {"vendor_override": "acme-switch"}, token=admin)
    check("200", status == 200, (status, payload))
    rows = service.app_db.audit_query(0, time.time() + 60, action="device.update",
                                      target="device:10.70.1.1", limit=50)
    vendor_row = next((r for r in rows if "vendor_override" in r["detail"]), None)
    check("vendor_override gets its own audit line, not folded into a generic diff",
          vendor_row is not None and "acme-switch" in vendor_row["detail"],
          vendor_row and dict(vendor_row))

    status, payload = call("PUT", f"/api/nodes/devices/{dev1}",
                           {"community": "sekret-string"}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.update", "device:10.70.1.1")
    check("community never appears as a value in the audit detail",
          row is not None and "community: changed" in row["detail"]
          and "sekret-string" not in row["detail"], row and dict(row))

    status, payload = call("POST", "/api/nodes/devices",
                           {"ip": "10.70.1.2", "name": "audit-dev-2",
                            "group_id": gid}, token=admin)
    dev2 = payload["id"]
    status, payload = call("POST", "/api/nodes/devices/bulk-update",
                           {"device_ids": [dev1, dev2], "group_id": gid}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.bulk_update", "2 devices")
    check("device.bulk_update audited with the field name, not per device",
          row is not None and "group_id" in row["detail"], row and dict(row))

    status, payload = call("POST", "/api/nodes/devices/bulk-delete",
                           {"device_ids": [dev2]}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.bulk_delete", "1 devices")
    check("device.bulk_delete audited", row is not None, row)

    status, payload = call("DELETE", f"/api/nodes/devices/{dev1}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.delete", "device:10.70.1.1")
    check("device.delete audited under device:{ip}", row is not None, row)

    status, payload = call("POST", "/api/nodes/devices/bulk-import",
                           {"devices": [{"ip": "10.70.1.3", "name": "bulk-3"},
                                       {"ip": "10.70.1.4", "name": "bulk-4"}]},
                           token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device.bulk_import")
    check("device.bulk_import audited with created/duplicate/invalid counts",
          row is not None and "created=2" in row["detail"], row and dict(row))

    # ----------------------------------------------------- device groups
    print("device_group.create / .update / .delete")
    status, payload = call("POST", "/api/nodes/device-groups", {"name": "Site-Audit"}, token=admin)
    check("200", status == 200, (status, payload))
    dgid = payload["id"]
    row = last_audit("device_group.create", "Site-Audit")
    check("device_group.create audited", row is not None, row)

    status, payload = call("PUT", f"/api/nodes/device-groups/{dgid}",
                           {"name": "Site-Audit-Renamed"}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device_group.update", str(dgid))
    check("device_group.update audited with the new name",
          row is not None and "Site-Audit-Renamed" in row["detail"], row and dict(row))

    status, payload = call("DELETE", f"/api/nodes/device-groups/{dgid}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("device_group.delete", "Site-Audit-Renamed")
    check("device_group.delete audited under its (pre-delete) name", row is not None, row)

    # ------------------------------------------------------ polling profiles
    print("profile.create / .update / .delete / .set_default")
    status, payload = call("POST", "/api/nodes/groups",
                           {"name": "audit-profile", "poll_interval_s": 60}, token=admin)
    check("200", status == 200, (status, payload))
    pid = payload["id"]
    row = last_audit("profile.create", "profile:audit-profile")
    check("profile.create audited", row is not None, row)

    status, payload = call("PUT", f"/api/nodes/groups/{pid}",
                           {"poll_interval_s": 120}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("profile.update", "profile:audit-profile")
    check("profile.update: the literal 'changed a threshold-like number' case",
          row is not None and "poll_interval_s:" in row["detail"]
          and "-> 120" in row["detail"], row and dict(row))

    status, payload = call("PUT", f"/api/nodes/groups/{pid}",
                           {"community": "profile-secret"}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("profile.update", "profile:audit-profile")
    check("community redacted in a profile diff too",
          row is not None and "community: changed" in row["detail"]
          and "profile-secret" not in row["detail"], row and dict(row))

    status, payload = call("POST", f"/api/nodes/groups/{pid}/default", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("profile.set_default", "profile:audit-profile")
    check("profile.set_default audited", row is not None, row)

    status, payload = call("POST", "/api/nodes/groups", {"name": "throwaway-profile"}, token=admin)
    throwaway_pid = payload["id"]
    status, payload = call("DELETE", f"/api/nodes/groups/{throwaway_pid}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("profile.delete", "profile:throwaway-profile")
    check("profile.delete audited under its name", row is not None, row)

    # -------------------------------------------------------------- MIBs
    print("mib.upload / mib.delete")
    mib_text = """
AUDIT-TEST-MIB DEFINITIONS ::= BEGIN
auditTestEnterprise OBJECT IDENTIFIER ::= { enterprises 88888 }
auditTestScalar OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "for test_audit_trail.py"
    ::= { auditTestEnterprise 1 }
END
"""
    content_b64 = base64.b64encode(mib_text.encode()).decode()
    status, payload = call("POST", "/api/nodes/mibs",
                           {"filename": "audit-test.mib", "content": content_b64}, token=admin)
    check("200", status == 200, (status, payload))
    mib_file_id = payload["id"]
    row = last_audit("mib.upload", "audit-test.mib")
    check("mib.upload audited under the filename", row is not None, row)

    status, payload = call("DELETE", f"/api/nodes/mibs/{mib_file_id}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("mib.delete", "audit-test.mib")
    check("mib.delete audited under the filename", row is not None, row)

    # -------------------------------------------------------------- alert rules
    print("alert_rule.create / .update (field-priority ordering) / .delete")
    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "audit_test_rule", "name": "Audit Test Rule",
                            "kind": "threshold", "source_kind": "cpu_pct",
                            "severity": 3, "threshold": 90.0}, token=admin)
    check("200", status == 200, (status, payload))
    rule_id = payload["id"]
    row = last_audit("alert_rule.create", "audit_test_rule")
    check("alert_rule.create audited with kind/severity",
          row is not None and "kind=threshold" in row["detail"], row and dict(row))

    # Multiple fields at once, deliberately including one NOT in the
    # priority list, so ordering is actually exercised rather than
    # trivially satisfied by there being only one changed field.
    status, payload = call("PUT", f"/api/alerts/rules/{rule_id}",
                           {"for_polls": 5, "threshold": 99.0, "enabled": False},
                           token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("alert_rule.update", "Audit Test Rule")
    check("alert_rule.update: threshold changed 90 -> 99 is recorded",
          row is not None and "threshold: 90.0 -> 99.0" in row["detail"], row and dict(row))
    if row is not None:
        detail = row["detail"]
        check("...threshold sorts before enabled",
              detail.index("threshold:") < detail.index("enabled:"), detail)
        check("...enabled sorts before for_polls (not in the priority list)",
              detail.index("enabled:") < detail.index("for_polls:"), detail)

    status, payload = call("DELETE", f"/api/alerts/rules/{rule_id}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("alert_rule.delete", "Audit Test Rule")
    check("alert_rule.delete audited under its name", row is not None, row)

    # -------------------------------------------------------------- IPAM subnets
    print("ipam_subnet.create / .update / .delete")
    status, payload = call("POST", "/api/ipam/subnets", {"cidr": "10.70.9.0/28"}, token=admin)
    check("200", status == 200, (status, payload))
    subnet_id = payload["id"]
    row = last_audit("ipam_subnet.create", "10.70.9.0/28")
    check("ipam_subnet.create audited under the cidr", row is not None, row)

    status, payload = call("PUT", f"/api/ipam/subnets/{subnet_id}",
                           {"label": "audit-subnet"}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("ipam_subnet.update", str(subnet_id))
    check("ipam_subnet.update audited with the field diff",
          row is not None and "audit-subnet" in row["detail"], row and dict(row))

    status, payload = call("DELETE", f"/api/ipam/subnets/{subnet_id}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("ipam_subnet.delete", str(subnet_id))
    check("ipam_subnet.delete audited with the cidr it removed",
          row is not None and "10.70.9.0/28" in row["detail"], row and dict(row))

    # -------------------------------------------------------------- ConfigRX
    print("configrx.store_secrets (device:{ip} target) / backup_delete / backup_bulk_delete")
    status, payload = call("POST", "/api/nodes/devices",
                           {"ip": "10.70.2.1", "name": "cx-audit-dev",
                            "group_id": gid}, token=admin)
    cx_dev = payload["id"]
    status, payload = call("POST", f"/api/configrx/devices/{cx_dev}/config",
                           {"store_secrets": True}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("configrx.store_secrets", f"device:10.70.2.1")
    check("configrx.store_secrets targets device:{ip}, not a bare device id",
          row is not None, row)

    backup_id, _sha = service.configrx_db.add_backup(cx_dev, "hostname audit-dev\n")
    status, payload = call("DELETE", f"/api/configrx/backups/{backup_id}", token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("configrx.backup_delete", "device:10.70.2.1")
    check("configrx.backup_delete audited under device:{ip}, naming the backup id",
          row is not None and f"backup #{backup_id}" in row["detail"], row and dict(row))

    id2, _ = service.configrx_db.add_backup(cx_dev, "hostname audit-dev-2\n")
    id3, _ = service.configrx_db.add_backup(cx_dev, "hostname audit-dev-3\n")
    status, payload = call("POST", "/api/configrx/backups/bulk-delete",
                           {"backup_ids": [id2, id3]}, token=admin)
    check("200", status == 200, (status, payload))
    row = last_audit("configrx.backup_bulk_delete", "2 backups")
    check("configrx.backup_bulk_delete audited", row is not None, row)

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    monitor_mod.run_trace = _real_run_trace
    server.stop()

raise SystemExit(1 if FAILS else 0)

"""Scheduled emailed reports (netpath/reportsched.py + the
/api/nodes/reports/schedules routes). Covers: next_due across all three
cadences, including the month-end clamp and a December->January rollover;
render() produces a body and a CSV for each report kind against a seeded
nodesdb; run_due sends through a monkeypatched alertmail.send, records the
CSV attachment's filename, and advances next_run_ts before it sends; route
validation (name/kind/cadence/hour/minute/weekday/day_of_month/recipients)
and the nodes-write permission gate.
"""
import datetime
import http.client
import json
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import reportsched
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("report_schedules_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def local_ts(year, month, day, hour=0, minute=0):
    return time.mktime((year, month, day, hour, minute, 0, 0, 0, -1))


# =========================================================== 1. next_due

print("1: next_due across cadences and month ends")

daily = {"cadence": "daily", "hour": 9, "minute": 30, "weekday": None, "day_of_month": None}
before_due = local_ts(2026, 3, 10, 9, 0)
check("daily: still due later today rolls forward to today's time, not tomorrow's",
      reportsched.next_due(daily, before_due) == local_ts(2026, 3, 10, 9, 30),
      reportsched.next_due(daily, before_due))

at_due = local_ts(2026, 3, 10, 9, 30)
check("daily: due exactly at the instant is not due again until tomorrow",
      reportsched.next_due(daily, at_due) == local_ts(2026, 3, 11, 9, 30),
      reportsched.next_due(daily, at_due))

after_due = local_ts(2026, 3, 10, 9, 45)
check("daily: past today's time rolls to tomorrow",
      reportsched.next_due(daily, after_due) == local_ts(2026, 3, 11, 9, 30),
      reportsched.next_due(daily, after_due))

# 2026-06-01 is a Monday; 2026-06-30 is a Tuesday -- both verified here so a
# stdlib/timezone surprise fails loudly rather than the fixture silently
# meaning something else.
assert datetime.date(2026, 6, 1).weekday() == 0, "fixture assumption: 2026-06-01 is a Monday"
assert datetime.date(2026, 6, 30).weekday() == 1, "fixture assumption: 2026-06-30 is a Tuesday"

weekly = {"cadence": "weekly", "hour": 7, "minute": 0, "weekday": 0, "day_of_month": None}
check("weekly: mid-week rolls forward to that week's Monday",
      reportsched.next_due(weekly, local_ts(2026, 6, 3, 12, 0))
      == local_ts(2026, 6, 8, 7, 0),
      reportsched.next_due(weekly, local_ts(2026, 6, 3, 12, 0)))
check("weekly: on the day but before the time fires today",
      reportsched.next_due(weekly, local_ts(2026, 6, 1, 6, 0))
      == local_ts(2026, 6, 1, 7, 0),
      reportsched.next_due(weekly, local_ts(2026, 6, 1, 6, 0)))
check("weekly: on the day, past the time, rolls a full week",
      reportsched.next_due(weekly, local_ts(2026, 6, 1, 8, 0))
      == local_ts(2026, 6, 8, 7, 0),
      reportsched.next_due(weekly, local_ts(2026, 6, 1, 8, 0)))

# Month-end clamp: day_of_month=31 in January (31 days, no clamp) rolls to
# February (28 days in 2026, a non-leap year) clamped to the 28th.
monthly = {"cadence": "monthly", "hour": 6, "minute": 0, "weekday": None, "day_of_month": 31}
jan_due = reportsched.next_due(monthly, local_ts(2026, 1, 15, 0, 0))
check("monthly: day 31 in a 31-day month needs no clamp",
      jan_due == local_ts(2026, 1, 31, 6, 0), jan_due)
feb_due = reportsched.next_due(monthly, jan_due)
check("monthly: day 31 clamps to February's 28th (2026 is not a leap year)",
      feb_due == local_ts(2026, 2, 28, 6, 0), feb_due)

# December -> January year rollover.
dec_row = {"cadence": "monthly", "hour": 0, "minute": 0, "weekday": None, "day_of_month": 15}
dec_due = reportsched.next_due(dec_row, local_ts(2026, 12, 20, 0, 0))
check("monthly: rolling past December advances the year",
      dec_due == local_ts(2027, 1, 15, 0, 0), dec_due)

try:
    reportsched.next_due({"cadence": "hourly", "hour": 0, "minute": 0,
                          "weekday": None, "day_of_month": None}, time.time())
    check("an unknown cadence is refused", False)
except ValueError:
    check("an unknown cadence is refused", True)


# ============================================================= 2. render

print("\n2: render() against a seeded nodesdb, one section per kind")

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error

nodes_db = service.nodes_db
gid = nodes_db.ensure_default_group()
sw1 = nodes_db.add_device("10.30.0.1", "acc-sw-01", group_id=gid)
sw2 = nodes_db.add_device("10.30.0.2", "acc-sw-02", group_id=gid)
nodes_db._conn.execute(
    "UPDATE devices SET vendor = 'cisco', sw_version = '15.2(7)E4',"
    " sys_descr = 'Cisco IOS Software, C2960X' WHERE id = ?", (sw1,))
nodes_db._conn.execute(
    "UPDATE devices SET vendor = 'cisco' WHERE id = ?", (sw2,))
nodes_db._conn.commit()

# A metric series for the top_metrics render, the same fixture shape
# test_report_topn.py uses: two hours of hourly rollup on one interface.
series_conn = nodes_db.series_db._conn
series_conn.execute(
    "INSERT INTO metrics(device_id, key, label, unit, kind)"
    " VALUES (?, 'if_in_util_pct.1', 'Gi0/1 in_util_pct', '%', 'gauge')", (sw1,))
series_conn.commit()
metric_id = series_conn.execute(
    "SELECT id FROM metrics WHERE device_id = ? AND key = ?",
    (sw1, "if_in_util_pct.1")).fetchone()[0]
now = time.time()
h0 = int(now // 3600) * 3600 - 2 * 3600
for offset in range(2):
    series_conn.execute(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?, ?, 10, 40.0, 55.0, 90.0)", (metric_id, h0 + offset * 3600))
series_conn.commit()

avail_row = {"kind": "availability", "name": "Weekly availability",
            "params_json": json.dumps({"period_days": 7})}
subject, body, csv_text, filename = reportsched.render(service, avail_row, now)
check("availability: subject carries the schedule's own name",
      subject.startswith("Weekly availability:"), subject)
check("availability: body names both devices",
      "acc-sw-01" in body and "acc-sw-02" in body, body)
csv_lines = csv_text.lstrip("﻿").splitlines()
check("availability: CSV header matches the Reports subtab's own export",
      csv_lines[0].split(",")[:4] == ["device_id", "name", "ip", "group"], csv_lines[0])
check("availability: one CSV row per device",
      len(csv_lines) == 3, csv_lines)
check("availability: filename is a .csv",
      filename.endswith(".csv"), filename)

topn_row = {"kind": "top_metrics", "name": "Busiest ports",
           "params_json": json.dumps({"period_days": 1,
                                      "metric_key": "if_in_util_pct.1", "top_n": 10})}
subject, body, csv_text, filename = reportsched.render(service, topn_row, now)
check("top_metrics: subject carries the schedule's own name",
      subject.startswith("Busiest ports:"), subject)
check("top_metrics: body names the ranked device",
      "acc-sw-01" in body, body)
csv_lines = csv_text.lstrip("﻿").splitlines()
check("top_metrics: CSV has a header plus one row for the one series",
      len(csv_lines) == 2, csv_lines)

no_key_row = {"kind": "top_metrics", "name": "Broken",
             "params_json": json.dumps({"period_days": 1})}
try:
    reportsched.render(service, no_key_row, now)
    check("top_metrics with no metric_key configured is refused", False)
except ValueError:
    check("top_metrics with no metric_key configured is refused", True)

# A row that predates api.py's write-time cap (or was written some other
# way) must still be refused at render time, not run the whole-fleet query.
wide_topn_row = {"kind": "top_metrics", "name": "Too wide",
                 "params_json": json.dumps({"metric_key": "if_in_util_pct.1",
                                            "period_days": 30})}
try:
    reportsched.render(service, wide_topn_row, now)
    check("top_metrics past the whole-fleet cost ceiling is refused at render time", False)
except ValueError:
    check("top_metrics past the whole-fleet cost ceiling is refused at render time", True)

fw_row = {"kind": "firmware", "name": "Firmware inventory", "params_json": "{}"}
subject, body, csv_text, filename = reportsched.render(service, fw_row, now)
check("firmware: subject carries the schedule's own name",
      subject.startswith("Firmware inventory:"), subject)
check("firmware: body names the versioned device",
      "acc-sw-01" in body, body)
csv_lines = csv_text.lstrip("﻿").splitlines()
check("firmware: one CSV row per device",
      len(csv_lines) == 3, csv_lines)

try:
    reportsched.render(service, {"kind": "no_such_kind", "name": "x", "params_json": "{}"}, now)
    check("an unknown report kind is refused", False)
except ValueError:
    check("an unknown report kind is refused", True)


# ============================================================ 3. run_due

print("\n3: run_due sends through alertmail.send and records the attachment")

service.alerts_db.save_settings({
    "email_enabled": True, "smtp_host": "relay.invalid",
})


class FakeMail:
    def __init__(self):
        self.calls = []

    def __call__(self, settings, password, to_addrs, subject, body,
                is_html=False, attachments=None):
        self.calls.append({
            "to_addrs": list(to_addrs), "subject": subject,
            "attachments": attachments or [],
        })


from netpath import alertmail  # noqa: E402  (after the settings above, matching test_alert_engine.py's own import-late idiom)
real_send = alertmail.send
fake = FakeMail()
alertmail.send = fake
try:
    due_now = time.time() - 1
    schedule_id = nodes_db.add_report_schedule(
        "Nightly availability", "availability", json.dumps({"period_days": 3}),
        "daily", 2, 0, None, None, json.dumps(["noc@example.invalid"]),
        enabled=True, next_run_ts=due_now)
    ran = reportsched.run_due(service, time.time())
    check("run_due reports how many schedules were due", ran == 1, ran)
    check("...and actually called alertmail.send once", len(fake.calls) == 1, fake.calls)
    call_made = fake.calls[0]
    check("...to the schedule's own recipients",
          call_made["to_addrs"] == ["noc@example.invalid"], call_made)
    check("...with the CSV as an attachment carrying a .csv filename",
          len(call_made["attachments"]) == 1
          and call_made["attachments"][0][0].endswith(".csv"), call_made["attachments"])
    check("...and real CSV bytes, not an empty attachment",
          len(call_made["attachments"][0][1]) > 20, call_made["attachments"])

    row = nodes_db.report_schedule(schedule_id)
    check("last_status records a successful send",
          row["last_status"].startswith("sent to"), row["last_status"])
    check("next_run_ts advanced past the run, to tomorrow's 02:00",
          row["next_run_ts"] > due_now and row["next_run_ts"] <= due_now + 86400 + 3600,
          row["next_run_ts"])
    check("last_run_ts is stamped",
          row["last_run_ts"] is not None and row["last_run_ts"] >= due_now, row["last_run_ts"])

    fake.calls.clear()
    again = reportsched.run_due(service, time.time())
    check("a schedule just run is not due again immediately",
          again == 0 and not fake.calls, (again, fake.calls))
finally:
    alertmail.send = real_send

# email not configured: the schedule records that instead of raising.
service.alerts_db.save_settings({"email_enabled": False})
unconfigured_id = nodes_db.add_report_schedule(
    "No SMTP", "firmware", "{}", "daily", 3, 0, None, None,
    json.dumps(["noc@example.invalid"]), enabled=True, next_run_ts=time.time() - 1)
reportsched.run_due(service, time.time())
row = nodes_db.report_schedule(unconfigured_id)
check("email not configured records 'not sent: email is not configured'",
      row["last_status"] == "not sent: email is not configured", row["last_status"])
service.alerts_db.save_settings({
    "email_enabled": True, "smtp_host": "relay.invalid",
})

# A single failing schedule must not abort the rest of the tick: a row with
# a cadence next_due cannot compute (a hand-corrupted or pre-migration row)
# due in the same tick as a healthy one.
bad_cadence_id = nodes_db.add_report_schedule(
    "Corrupt cadence", "firmware", "{}", "bogus-cadence", 3, 0, None, None,
    json.dumps(["noc@example.invalid"]), enabled=True, next_run_ts=time.time() - 1)
healthy_id = nodes_db.add_report_schedule(
    "Healthy sibling", "firmware", "{}", "daily", 3, 0, None, None,
    json.dumps(["noc@example.invalid"]), enabled=True, next_run_ts=time.time() - 1)
fake2 = FakeMail()
alertmail.send = fake2
try:
    ran = reportsched.run_due(service, time.time())
finally:
    alertmail.send = real_send
check("run_due processes every schedule due in the tick, not just the first",
      ran == 2, ran)
bad_row = nodes_db.report_schedule(bad_cadence_id)
check("the bad-cadence row records its own failure",
      bad_row["last_status"].startswith("failed:"), bad_row["last_status"])
check("...and is parked roughly a day out, not retried every minute",
      bad_row["next_run_ts"] > time.time() + 80000, bad_row["next_run_ts"])
healthy_row = nodes_db.report_schedule(healthy_id)
check("...while its healthy sibling in the same tick still sent",
      healthy_row["last_status"].startswith("sent to") and len(fake2.calls) == 1,
      (healthy_row["last_status"], fake2.calls))


# ==================================================== 4. routes + gating

print("\n4: routes -- CRUD, validation, permission")


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


admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

valid_body = {"name": "Weekly firmware", "kind": "firmware", "cadence": "weekly",
             "hour": 6, "minute": 0, "weekday": 1,
             "recipients": ["ops@example.invalid"], "params": {}}
status, created = call("POST", "/api/nodes/reports/schedules", valid_body, token=admin)
check("POST creates a schedule", status == 200 and created.get("id"), (status, created))
new_id = created["id"]

status, listed = call("GET", "/api/nodes/reports/schedules", token=admin)
check("GET lists it back", status == 200
      and any(s["id"] == new_id for s in listed["schedules"]), (status, listed))
row = next(s for s in listed["schedules"] if s["id"] == new_id)
check("...with the fields it was created with",
      row["name"] == "Weekly firmware" and row["kind"] == "firmware"
      and row["cadence"] == "weekly" and row["weekday"] == 1
      and row["recipients"] == ["ops@example.invalid"], row)
check("...and a next_run_ts already computed", row["next_run_ts"] is not None, row)

update_body = dict(valid_body)
update_body["name"] = "Weekly firmware (renamed)"
update_body["hour"] = 7
status, _ = call("PUT", f"/api/nodes/reports/schedules/{new_id}", update_body, token=admin)
check("PUT updates it", status == 200, status)
status, listed = call("GET", "/api/nodes/reports/schedules", token=admin)
row = next(s for s in listed["schedules"] if s["id"] == new_id)
check("...and the change is visible",
      row["name"] == "Weekly firmware (renamed)" and row["hour"] == 7, row)

# Validation.
bad_cases = [
    ({**valid_body, "name": ""}, "an empty name"),
    ({**valid_body, "name": "x" * 61}, "a 61-character name"),
    ({**valid_body, "kind": "not_a_kind"}, "an invalid kind"),
    ({**valid_body, "cadence": "hourly"}, "an invalid cadence"),
    ({**valid_body, "hour": 24}, "hour out of range"),
    ({**valid_body, "hour": -1}, "a negative hour"),
    ({**valid_body, "minute": 60}, "minute out of range"),
    ({**valid_body, "cadence": "weekly", "weekday": None}, "weekly with no weekday"),
    ({**valid_body, "cadence": "weekly", "weekday": 7}, "weekday out of range"),
    ({**valid_body, "cadence": "monthly", "day_of_month": None}, "monthly with no day_of_month"),
    ({**valid_body, "cadence": "monthly", "day_of_month": 32}, "day_of_month out of range"),
    ({**valid_body, "recipients": []}, "no recipients at all"),
    ({**valid_body, "recipients": ["not-an-email"]}, "a recipient with no @"),
    ({**valid_body, "recipients": [f"a{i}@example.invalid" for i in range(21)]},
     "21 recipients, one over the cap"),
    ({**valid_body, "kind": "top_metrics", "params": {}}, "top_metrics with no metric_key"),
    ({**valid_body, "kind": "top_metrics",
     "params": {"metric_key": "cpu_pct", "period_days": 8}},
     "top_metrics period_days over the whole-fleet cost ceiling (7 days)"),
]
for body, label in bad_cases:
    status, payload = call("POST", "/api/nodes/reports/schedules", body, token=admin)
    check(f"POST refuses {label}", status == 400, (status, payload))

status, payload = call("POST", "/api/nodes/reports/schedules/999999/run", token=admin)
check("run on an unknown schedule is a 404", status == 404, (status, payload))

route_fake = FakeMail()
alertmail.send = route_fake
try:
    status, run_result = call(
        "POST", f"/api/nodes/reports/schedules/{new_id}/run", token=admin)
finally:
    alertmail.send = real_send
check("POST .../run sends now, outside the schedule",
      status == 200 and run_result.get("status", "").startswith("sent"),
      (status, run_result))
check("...through the same alertmail.send the scheduled run uses",
      len(route_fake.calls) == 1, route_fake.calls)

status, _ = call("DELETE", f"/api/nodes/reports/schedules/{new_id}", token=admin)
check("DELETE removes it", status == 200, status)
status, listed = call("GET", "/api/nodes/reports/schedules", token=admin)
check("...and it is gone", status == 200
      and not any(s["id"] == new_id for s in listed["schedules"]), listed)
status, payload = call("DELETE", f"/api/nodes/reports/schedules/{new_id}", token=admin)
check("deleting it again is a 404", status == 404, (status, payload))

# Permission gate: a nodes:read account may list, never write.
service.app_db.add_user("nodes-reader", hash_password("NodesReaderPW2026"),
                        must_change=False)
service.app_db.set_permissions("nodes-reader", {"nodes": "read"})
viewer = login("nodes-reader", "NodesReaderPW2026")

status, _ = call("GET", "/api/nodes/reports/schedules", token=viewer)
check("a nodes:read account may list schedules", status == 200, status)

status, payload = call("POST", "/api/nodes/reports/schedules", valid_body, token=viewer)
check("...but may not create one", status == 403, (status, payload))
status, payload = call("PUT", "/api/nodes/reports/schedules/1", valid_body, token=viewer)
check("...or update one", status == 403, (status, payload))
status, payload = call("DELETE", "/api/nodes/reports/schedules/1", token=viewer)
check("...or delete one", status == 403, (status, payload))
status, payload = call("POST", "/api/nodes/reports/schedules/1/run", token=viewer)
check("...or send one now", status == 403, (status, payload))

status, payload = call("GET", "/api/nodes/reports/schedules")
check("no session at all is refused with 401", status == 401, (status, payload))


if FAILS:
    print(f"\n{len(FAILS)} CHECK(S) FAILED:")
    for f in FAILS:
        print(f"  - {f}")
    raise SystemExit(1)
print("\nALL REPORT SCHEDULE ASSERTIONS PASSED")

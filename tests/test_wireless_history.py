"""Wireless AP history (G, 5.23.0): ap_samples/radio_samples storage,
the poller's write-throttle, retention pruning, cascade on AP delete, the
two history routes' bucketing, and permission gating.

Sections 1-3 exercise WirelessDatabase and WirelessPoller directly;
section 4 goes over real HTTP through Service/WebServer, the shape
test_mapper_api.py and test_nodes_api_fixes.py already use.
"""
import atexit
import csv
import http.client
import io
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)
from _paths import spawn_stub, tmpdir

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.web import Service, WebServer
from netpath.wirelessdb import WirelessDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


NOW = time.time()

# --------------------------------------------------------------- 1. storage

TMPDIR = tmpdir("wireless_history_")
db = WirelessDatabase(os.path.join(TMPDIR, "wireless1.db"))
controller_id = db.add_controller("C1", "192.0.2.1", snmp_version=1, community="public")
ap_id = db.upsert_ap(controller_id, "AP0001", "", name="Lobby", status="online",
                     station_count=5)
db.replace_radios(ap_id, [{"radio_id": "1", "channel": "6", "operating_power_dbm": 17,
                          "station_count": 3}])

check("last_sample_ts is None before any sample", db.last_sample_ts(ap_id) is None)

t_a, t_b, t_c = NOW - 600, NOW - 300, NOW
db.record_samples(
    [(ap_id, t_a, 1, 5), (ap_id, t_b, 1, 6), (ap_id, t_c, 0, 0)],
    [(ap_id, "1", t_a, 3, "6", 17), (ap_id, "1", t_b, 4, "6", 17),
     (ap_id, "1", t_c, 0, "6", 10)])

check("last_sample_ts reads back the most recent write", db.last_sample_ts(ap_id) == t_c,
      db.last_sample_ts(ap_id))

history = db.ap_history(ap_id, 0, NOW + 1)
check("ap_history returns every AP sample in the window, in order",
      [r["ts"] for r in history["ap"]] == [t_a, t_b, t_c], history["ap"])
check("...with online/station_count carried", history["ap"][0]["online"] == 1
      and history["ap"][0]["station_count"] == 5 and history["ap"][2]["online"] == 0,
      [dict(r) for r in history["ap"]])
check("...and every radio sample too", len(history["radios"]) == 3
      and history["radios"][0]["radio_id"] == "1", history["radios"])

narrow = db.ap_history(ap_id, t_b - 1, t_b + 1)
check("ap_history honours t0/t1", [r["ts"] for r in narrow["ap"]] == [t_b], narrow["ap"])

check("record_samples([], []) is a no-op", db.record_samples([], []) is None)

# ---------------------------------------------------------- 2. prune_history

# t_a is 600s old, t_b 300s old, t_c ~now -- a cutoff of 400s keeps t_b/t_c
# and drops t_a alone, from both tables.
removed = db.prune_history(older_than_days=400 / 86400)
check("prune_history removes exactly the rows older than its cutoff",
      removed == 2,  # one ap_samples row + one radio_samples row
      removed)
after = db.ap_history(ap_id, 0, NOW + 1)
check("...the oldest AP sample is gone, the newer two remain",
      [r["ts"] for r in after["ap"]] == [t_b, t_c], after["ap"])
check("...same for radio_samples", [r["ts"] for r in after["radios"]] == [t_b, t_c],
      after["radios"])

check("a second prune_history pass with nothing to remove returns 0",
      db.prune_history(older_than_days=400 / 86400) == 0)

# ----------------------------------------------------- 3. cascade on AP delete

check("both tables still carry rows for this AP before the delete",
      len(db.ap_history(ap_id, 0, NOW + 1)["ap"]) == 2)
db.remove_ap(ap_id)
with db._lock:
    remaining_ap = db._conn.execute(
        "SELECT COUNT(*) AS n FROM ap_samples WHERE ap_id = ?", (ap_id,)).fetchone()["n"]
    remaining_radio = db._conn.execute(
        "SELECT COUNT(*) AS n FROM radio_samples WHERE ap_id = ?", (ap_id,)).fetchone()["n"]
check("deleting the AP cascades ap_samples away (foreign_keys=ON is live)",
      remaining_ap == 0, remaining_ap)
check("...and radio_samples too", remaining_radio == 0, remaining_radio)
db.close()

# ------------------------------------------- 3b. trim_to_size (size cap)
#
# max_wireless_db_mb (5.23.0): trim_to_size deletes oldest-by-a-shared-ts-
# cutoff from both sample tables per loop, until the file is under cap.
# Several thousand rows, same shape test_netflow_prune.py's own size-cap
# test uses, so the file size actually moves rather than sitting on a
# rounding boundary.

db_trim = WirelessDatabase(os.path.join(TMPDIR, "wireless-trim.db"))
trim_controller_id = db_trim.add_controller("C1", "192.0.2.9", snmp_version=1,
                                            community="public")
trim_ap_id = db_trim.upsert_ap(trim_controller_id, "AP0001", "", name="Trim",
                               status="online")
db_trim.replace_radios(trim_ap_id, [{"radio_id": "1"}, {"radio_id": "2"}])

N_SAMPLES = 60000
base_ts = NOW - N_SAMPLES * 5
ap_rows_trim = [(trim_ap_id, base_ts + i * 5, 1, i % 50) for i in range(N_SAMPLES)]
radio_rows_trim = [(trim_ap_id, r, base_ts + i * 5, i % 20, "6", 10 + i % 10)
                   for i in range(N_SAMPLES) for r in ("1", "2")]
db_trim.record_samples(ap_rows_trim, radio_rows_trim)

with db_trim._lock:
    ap_count_before = db_trim._conn.execute(
        "SELECT COUNT(*) AS n FROM ap_samples").fetchone()["n"]
    radio_count_before = db_trim._conn.execute(
        "SELECT COUNT(*) AS n FROM radio_samples").fetchone()["n"]
check("seeded thousands of AP and radio samples",
      ap_count_before == N_SAMPLES and radio_count_before == N_SAMPLES * 2,
      (ap_count_before, radio_count_before))

before_bytes = db_trim.size_bytes()
cap = int(before_bytes * 0.7)
removed = db_trim.trim_to_size(cap, budget_s=30.0)
check("trim_to_size actually removed rows", removed > 0, removed)
check("...and the file shrank",
      db_trim.size_bytes() < before_bytes,
      f"{before_bytes} -> {db_trim.size_bytes()}")

with db_trim._lock:
    ap_count_after = db_trim._conn.execute(
        "SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM ap_samples").fetchone()
    radio_count_after = db_trim._conn.execute(
        "SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM radio_samples").fetchone()
check("ap_samples lost rows, oldest-first (its floor moved forward)",
      ap_count_after["n"] < ap_count_before
      and (ap_count_after["oldest"] is None or ap_count_after["oldest"] > base_ts),
      (ap_count_before, ap_count_after["n"], ap_count_after["oldest"]))
check("radio_samples lost rows too, oldest-first",
      radio_count_after["n"] < radio_count_before
      and (radio_count_after["oldest"] is None or radio_count_after["oldest"] > base_ts),
      (radio_count_before, radio_count_after["n"], radio_count_after["oldest"]))
check("both tables advanced to the same ts floor (one shared cutoff, not a "
      "fixed row count each -- radio_samples has 2x ap_samples' rows)",
      ap_count_after["oldest"] == radio_count_after["oldest"],
      (ap_count_after["oldest"], radio_count_after["oldest"]))
# Nothing newer than the seeded window was ever touched: the most recent
# sample (base_ts + (N_SAMPLES-1)*5) must still be there regardless of how
# much got trimmed, or this would be deleting by something other than age.
newest_ts = base_ts + (N_SAMPLES - 1) * 5
with db_trim._lock:
    newest_ap = db_trim._conn.execute(
        "SELECT COUNT(*) AS n FROM ap_samples WHERE ts = ?", (newest_ts,)).fetchone()["n"]
check("the newest sample survives a trim that only ever takes the oldest",
      newest_ap == 1, newest_ap)
db_trim.close()

# --------------------------------------------------- 4. poller write-throttle
#
# Real Service/WebServer are not needed here -- WirelessPoller talks to
# WirelessDatabase directly, same fixture test_wireless_poller.py uses.

DB2 = os.path.join(tmpdir("wireless_history_poll_"), "wireless.db")
stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py")
atexit.register(stub.kill)

db2 = WirelessDatabase(DB2)
db2.save_settings({"history_sample_s": 300})
controller2_id = db2.add_controller("Test Controller", "127.0.0.1", snmp_version=1,
                                    community="public")
poller = WirelessPoller(db2)
controller2 = db2.controller(controller2_id)

poller._poll_controller(dict(controller2))
aps = db2.access_points(controller2_id)
lobby_id = next(a["id"] for a in aps if a["wtp_id"] == "AP0001")
first_ts = db2.last_sample_ts(lobby_id)
check("the first poll writes a history sample for every AP", first_ts is not None, first_ts)
first_history = db2.ap_history(lobby_id, 0, first_ts + 1)
check("...and one radio_samples row per radio the stub reports",
      len({r["radio_id"] for r in first_history["radios"]}) == 2, first_history["radios"])

poller._poll_controller(dict(db2.controller(controller2_id)))
check("a second poll inside history_sample_s does not write a new sample",
      db2.last_sample_ts(lobby_id) == first_ts, db2.last_sample_ts(lobby_id))

# Back-date the recorded sample past the throttle window without waiting
# 300s in a test: the poller re-reads last_sample_ts fresh every poll, so
# rewriting it under the lock is equivalent to time having passed.
with db2._lock:
    db2._conn.execute("UPDATE ap_samples SET ts = ? WHERE ap_id = ?",
                      (first_ts - 301, lobby_id))
    db2._conn.execute("UPDATE radio_samples SET ts = ? WHERE ap_id = ?",
                      (first_ts - 301, lobby_id))
    db2._conn.commit()
poller._poll_controller(dict(db2.controller(controller2_id)))
check("...but a poll once the last sample has aged past history_sample_s does",
      db2.last_sample_ts(lobby_id) > first_ts - 301, db2.last_sample_ts(lobby_id))
db2.close()

# -------------------------------------------------------------- 5. web routes

TMPDIR3 = tmpdir("wireless_history_api_")
service = Service(
    os.path.join(TMPDIR3, "netpath.db"), os.path.join(TMPDIR3, "flows.db"),
    os.path.join(TMPDIR3, "syslog.db"), os.path.join(TMPDIR3, "app.db"),
    os.path.join(TMPDIR3, "ipam.db"), os.path.join(TMPDIR3, "snmptraps.db"),
    os.path.join(TMPDIR3, "nodes.db"), os.path.join(TMPDIR3, "alerts.db"),
    os.path.join(TMPDIR3, "wireless.db"), os.path.join(TMPDIR3, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path,
                body=json.dumps(body).encode() if body is not None else None,
                headers=headers)
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
    status, payload = call("POST", "/api/users",
                           {"username": "outsider", "password": "Corr3ct-Horse-Battery",
                            "grants": {"nodes": "read"}}, token=admin)
    assert status == 200, (status, payload)
    outsider = login("outsider", "Corr3ct-Horse-Battery")

    wctl_id = service.wireless_db.add_controller("C1", "192.0.2.1", snmp_version=1,
                                                 community="public")
    wap_id = service.wireless_db.upsert_ap(wctl_id, "AP0001", "", name="Lobby",
                                           status="online", station_count=5)
    service.wireless_db.replace_radios(wap_id, [
        {"radio_id": "1", "channel": "6", "operating_power_dbm": 17, "station_count": 3},
        {"radio_id": "2", "channel": "44", "operating_power_dbm": 14, "station_count": 1}])

    # Before any sample has ever been recorded, radio series are built from
    # what radio_samples actually has for this AP -- nothing yet -- so only
    # the AP-total clients series is offered (also empty). replace_radios
    # having configured two radios does not, by itself, invent series for
    # data that has never been sampled.
    status, payload = call("GET", f"/api/wireless/aps/{wap_id}/history", token=admin)
    check("history route answers 200 with just the clients series before any sample",
          status == 200 and [s["key"] for s in payload["series"]] == ["clients"],
          (status, payload))
    check("...and it starts with no points", payload["series"][0]["points"] == [],
          payload["series"])

    t0 = time.time() - 3600
    rows = [(wap_id, t0 + i * 300, 1, 5 + i) for i in range(6)]
    radio_rows = [(wap_id, "1", t0 + i * 300, 3 + i, "6", 17) for i in range(6)] + \
        [(wap_id, "2", t0 + i * 300, 1, "44", 14) for i in range(6)]
    service.wireless_db.record_samples(rows, radio_rows)

    status, payload = call(
        "GET", f"/api/wireless/aps/{wap_id}/history?t0={t0 - 1}&t1={time.time() + 1}",
        token=admin)
    keys = {s["key"] for s in payload["series"]}
    check("once samples exist, all 5 series appear (clients + 2 radios x clients/power)",
          keys == {"clients", "radio:1:clients", "radio:1:power",
                  "radio:2:clients", "radio:2:power"}, keys)
    clients = next(s for s in payload["series"] if s["key"] == "clients")
    check("raw (bucket_s omitted) points come back one per sample, {ts, value} shaped",
          status == 200 and len(clients["points"]) == 6
          and "value" in clients["points"][0] and "avg" not in clients["points"][0],
          (status, clients["points"][:2]))
    check("...values match what was recorded, in order",
          [p["value"] for p in clients["points"]] == [5, 6, 7, 8, 9, 10],
          [p["value"] for p in clients["points"]])
    power2 = next(s for s in payload["series"] if s["key"] == "radio:2:power")
    check("a second radio's power series is independent of the first's",
          all(p["value"] == 14 for p in power2["points"]), power2["points"])

    status, payload = call(
        "GET", f"/api/wireless/aps/{wap_id}/history"
        f"?t0={t0 - 1}&t1={time.time() + 1}&bucket_s=1200", token=admin)
    clients_b = next(s for s in payload["series"] if s["key"] == "clients")
    check("bucket_s > 0 answers avg/min/max points instead of raw ones",
          status == 200 and clients_b["points"]
          and "avg" in clients_b["points"][0] and "min" in clients_b["points"][0]
          and "max" in clients_b["points"][0], (status, clients_b["points"][:2]))
    check("...fewer buckets than raw samples for a bucket wider than the sample gap",
          len(clients_b["points"]) < 6, len(clients_b["points"]))
    check("...and the reported bucket_s rides along in the envelope",
          payload["bucket_s"] == 1200, payload.get("bucket_s"))

    status, payload = call("GET", "/api/wireless/aps/999999/history", token=admin)
    check("an unknown AP id is a 404", status == 404, (status, payload))

    status, payload = call(
        "GET", f"/api/wireless/aps/{wap_id}/history/export.csv"
        f"?t0={t0 - 1}&t1={time.time() + 1}", token=admin)
    csv_rows = (list(csv.reader(io.StringIO(payload["csv"].lstrip("﻿"))))
               if status == 200 else [])
    check("export.csv answers the time/ts/series/value/min/max header",
          status == 200 and csv_rows
          and csv_rows[0] == ["time", "ts", "series", "value", "min", "max"],
          (status, csv_rows[:1] if csv_rows else payload))
    check("...with one row per point across every series (6 x 5 series)",
          len(csv_rows) - 1 == 30, len(csv_rows) - 1)
    check("...the time column is a real local-time reading, not the bare epoch",
          csv_rows[1][0] != csv_rows[1][1] and "-" in csv_rows[1][0], csv_rows[1])

    status, payload = call("GET", f"/api/wireless/aps/{wap_id}/history", token=outsider)
    check("an account with no wireless grant is refused the history route",
          status == 403, (status, payload))
    status, payload = call("GET", f"/api/wireless/aps/{wap_id}/history/export.csv",
                           token=outsider)
    check("...and the CSV export too", status == 403, (status, payload))

    # ------------------------------------ 5b. settings range validation
    #
    # history_days=-1 makes prune_history's cutoff (now - days*86400) land
    # in the future, so every row reads as "older than the cutoff" on the
    # next sweep; history_sample_s=0 defeats the poller's own throttle
    # entirely, writing a row on every poll.
    status, payload = call("POST", "/api/settings",
                           {"scope": "wireless", "values": {"history_days": -1}},
                           token=admin)
    check("history_days = -1 is refused", status == 400, (status, payload))
    status, payload = call("POST", "/api/settings",
                           {"scope": "wireless", "values": {"history_sample_s": 0}},
                           token=admin)
    check("history_sample_s = 0 is refused", status == 400, (status, payload))
    status, payload = call("POST", "/api/settings",
                           {"scope": "wireless",
                            "values": {"history_days": 10, "history_sample_s": 120}},
                           token=admin)
    check("a valid pair is accepted", status == 200
          and payload["wireless_settings"]["history_days"] == 10
          and payload["wireless_settings"]["history_sample_s"] == 120, (status, payload))
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR3, ignore_errors=True)
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

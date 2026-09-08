"""Re-discover (POST /api/nodes/discovery/<id>/rescan), against a real Service
and WebServer. Covers: a start stores the profile and the per-scan timing on
the job row; a rescan starts a NEW job carrying both and leaves the original
alone; it refuses while that scan is still running, and while any other live
scan has the same target; a row with no stored profile (or one whose profile
has since been deleted) answers `needs_profile` instead of guessing.

The two refusals are driven through the poller's own job registry rather than
by racing a real sweep to the finish line: what the route asks is
`discovery_running(id)`, and a sweep's finishing time is a race no assertion
should depend on.
"""
import http.client
import json
import os
import threading
import time

import _paths  # noqa: F401

from netpath import nodepoll as nodepoll_mod
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("discovery_rescan_")
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


def wait_finished(job_id, timeout_s=30.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        row = service.nodes_db.discovery_job(job_id)
        if row is not None and row["state"] != "running":
            return row["state"]
        time.sleep(0.1)
    return "running"


class StubJob:
    """What discovery_running(id) actually reads. Standing one of these in
    the poller's registry is how a "this scan is running" refusal is tested
    without a sweep that finishes on its own schedule."""

    running = True

    def __init__(self, target="127.0.0.1"):
        self.target = target

    def cancel(self):
        self.running = False


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()

    # ------------------------------------------------- a start stores both
    # A device-kind target: one address, no subnet sweep, and short enough
    # timing that the whole job is over in well under a second whether or
    # not this machine can send an ICMP echo at all.
    started = {"target": "127.0.0.1", "group_id": gid, "allow_ping_only": True,
               "ping_timeout_s": 0.2, "ping_retries": 0,
               "snmp_timeout_s": 0.2, "snmp_retries": 0, "workers": 4}
    status, payload = call("POST", "/api/nodes/discovery", started, token=admin)
    check("a scan starts", status == 200 and payload.get("id"), (status, payload))
    first_id = payload["id"]
    row = db.discovery_job(first_id)
    check("the job row stores the polling profile it ran under",
          row["group_id"] == gid, row["group_id"])
    stored = json.loads(row["overrides_json"] or "{}")
    check("…and the five per-scan timing values, keyed as the dialog sends them",
          stored == {"ping_timeout_s": 0.2, "ping_retries": 0,
                     "snmp_timeout_s": 0.2, "snmp_retries": 0, "workers": 4},
          stored)
    check("…and no credential: the communities are derived from the profile, "
          "never stored on the job",
          "discovery_communities" not in stored and "public" not in (row["overrides_json"] or ""),
          row["overrides_json"])
    check("the first scan finished", wait_finished(first_id) == "done")

    # ------------------------------------------------------- the rescan
    status, payload = call("POST", f"/api/nodes/discovery/{first_id}/rescan",
                           {}, token=admin)
    check("a finished scan can be re-run", status == 200, (status, payload))
    second_id = payload.get("id")
    check("…as a NEW job, not the old one restarted",
          second_id and second_id != first_id, payload)
    check("…which says which job it repeats", payload.get("rescan_of") == first_id, payload)
    check("the original job is still there with its own results",
          db.discovery_job(first_id) is not None
          and len(db.discovery_results(first_id)) == 1,
          db.discovery_results(first_id))
    replay = db.discovery_job(second_id)
    check("the new job replays the same target and kind",
          replay["target"] == "127.0.0.1" and replay["kind"] == "device",
          (replay["target"], replay["kind"]))
    check("…the same profile", replay["group_id"] == gid, replay["group_id"])
    check("…the same ping-only choice", replay["allow_ping_only"] == 1,
          replay["allow_ping_only"])
    check("…and the same timing, so a rescan of a rescan replays it too",
          json.loads(replay["overrides_json"] or "{}") == stored,
          replay["overrides_json"])
    check("the second scan finished", wait_finished(second_id) == "done")

    # ------------------------------------------- refused while one is running
    # The stub stands in for the sweep this row's job would be running.
    service.node_poller._discovery_jobs[second_id] = StubJob()
    status, payload = call("POST", f"/api/nodes/discovery/{second_id}/rescan",
                           {}, token=admin)
    check("re-running a scan that is still running is refused",
          status == 400 and "still running" in str(payload.get("error", "")),
          (status, payload))

    # ------------------------------------------ refused on a duplicate target
    # A second finished job on the same target as the still-"running" one
    # above: a double-click must not put two sweeps of one /24 on the wire.
    db.update_discovery_job(second_id, state="running")
    twin_id = db.add_discovery_job("device", "127.0.0.1", allow_ping_only=True,
                                   group_id=gid, scan_overrides=stored)
    db.update_discovery_job(twin_id, state="done", finished_ts=time.time())
    status, payload = call("POST", f"/api/nodes/discovery/{twin_id}/rescan",
                           {}, token=admin)
    check("a second sweep of a target already being scanned is refused",
          status == 400 and "already running" in str(payload.get("error", "")),
          (status, payload))

    # A row left 'running' by a process that died is not a sweep anybody is
    # waiting for, and must not wedge the button for good.
    del service.node_poller._discovery_jobs[second_id]
    status, payload = call("POST", f"/api/nodes/discovery/{twin_id}/rescan",
                           {}, token=admin)
    check("…but a stranded 'running' row the poller knows nothing about does not",
          status == 200 and payload.get("id"), (status, payload))
    wait_finished(payload.get("id"))

    # --------------------------------------------- the pre-migration fallback
    before = len(db.discovery_jobs(200))
    legacy_id = db.add_discovery_job("subnet", "10.98.0.0/24")
    db.update_discovery_job(legacy_id, state="done", finished_ts=time.time())
    status, payload = call("POST", f"/api/nodes/discovery/{legacy_id}/rescan",
                           {}, token=admin)
    check("a job with no stored profile answers needs_profile rather than guessing",
          status == 200 and payload.get("needs_profile") is True, (status, payload))
    check("…naming the target the browser should prefill",
          payload.get("target") == "10.98.0.0/24", payload)
    check("…and nothing was started", len(db.discovery_jobs(200)) == before + 1,
          len(db.discovery_jobs(200)))

    # A profile deleted since the scan ran is the same answer: the row's
    # group_id points at nothing, so there is nothing faithful to replay.
    gone_gid = db.add_group("Retired profile", snmp_version=1, community="public")
    orphan_id = db.add_discovery_job("subnet", "10.97.0.0/24", group_id=gone_gid)
    db.update_discovery_job(orphan_id, state="done", finished_ts=time.time())
    db.remove_group(gone_gid)
    status, payload = call("POST", f"/api/nodes/discovery/{orphan_id}/rescan",
                           {}, token=admin)
    check("a job whose profile has since been deleted answers needs_profile too",
          status == 200 and payload.get("needs_profile") is True, (status, payload))

    # ---------------------------------------------------------------- gating
    status, payload = call("POST", "/api/nodes/discovery/999999/rescan", {}, token=admin)
    check("an unknown job is refused", status == 400
          and "No such discovery job" in str(payload.get("error", "")), (status, payload))

    service.app_db.add_user("rescan-reader", hash_password("RescanReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("rescan-reader", {"nodes": "read"})
    reader = login("rescan-reader", "RescanReaderPW2026")
    status, payload = call("POST", f"/api/nodes/discovery/{first_id}/rescan",
                           {}, token=reader)
    check("a nodes:read account may not re-run a scan", status == 403, (status, payload))

    # ------------------------------------------- two clicks, one sweep
    # The refusal used to be three steps in the route -- ask whether this
    # job is running, scan the job rows for another live sweep of the same
    # target, then start one -- with nothing held across them, on a
    # threading web server, behind a button that stayed live during its own
    # POST. Both requests passed all three checks and both swept the subnet.
    #
    # The interleaving is pinned rather than raced for: every request is held
    # at the point it has just asked whether a sweep is running, and only
    # released once the other has asked too. What is left is the question the
    # fix answers -- can two callers that have both been told "nothing is
    # running" both start one.
    class HeldJob:
        """A sweep that stays on the wire until the test lets it go, so the
        second request meets a genuinely running one rather than racing a
        real sweep to its finish line."""

        started = []
        release = threading.Event()

        def __init__(self, db, job_id, kind, target, settings, log=None):
            self.job_id = job_id
            self.target = target
            self._started = False

        def start(self):
            self._started = True
            HeldJob.started.append(self.job_id)

        def cancel(self):
            HeldJob.release.set()

        @property
        def running(self):
            return self._started and not HeldJob.release.is_set()

    gate = threading.Barrier(2, timeout=30)
    real_running = service.node_poller.discovery_running
    held_at_check = threading.local()

    def gated_running(job_id):
        answer = real_running(job_id)
        if not getattr(held_at_check, "waited", False):
            held_at_check.waited = True
            gate.wait()
        return answer

    real_job_class = nodepoll_mod.DiscoveryJob
    nodepoll_mod.DiscoveryJob = HeldJob
    service.node_poller.discovery_running = gated_running
    try:
        race_target = "10.96.0.0/24"
        seeds = []
        for _ in range(2):
            seed = db.add_discovery_job("subnet", race_target, group_id=gid,
                                        scan_overrides=stored)
            db.update_discovery_job(seed, state="done", finished_ts=time.time())
            seeds.append(seed)
        answers = {}

        def rescan(seed_id):
            answers[seed_id] = call(
                "POST", f"/api/nodes/discovery/{seed_id}/rescan", {}, token=admin)

        threads = [threading.Thread(target=rescan, args=(seed,)) for seed in seeds]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
    finally:
        HeldJob.release.set()
        nodepoll_mod.DiscoveryJob = real_job_class
        service.node_poller.discovery_running = real_running

    statuses = sorted(status for status, _payload in answers.values())
    check("two concurrent rescans of one target: one is accepted",
          statuses == [200, 400], answers)
    check("...the other is refused in the same words a serial one is",
          any("already running" in str(payload.get("error", ""))
              for status, payload in answers.values() if status == 400),
          answers)
    check("...and exactly one sweep was started, not two",
          len(HeldJob.started) == 1, HeldJob.started)
    check("...leaving one new job row for the target, not two",
          len([row for row in db.discovery_jobs(200)
               if row["target"] == race_target]) == len(seeds) + 1,
          [row["id"] for row in db.discovery_jobs(200)
           if row["target"] == race_target])

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    service.node_poller.stop()
    server.stop()

raise SystemExit(1 if FAILS else 0)

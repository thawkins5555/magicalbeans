"""The update runs as a background job (5.0.0).

Three failures shipped together and each one made the update button lie:
the browser's 30 s deadline fired while the before-restart hook alone took
37-63 s, so a working update reported a timeout; the install markers were
written after the teardown through a fresh connection and hit "database is
locked" 201 times, so the next check said "not installed"; and the restart
thread was a daemon that never reached its first statement in 146 attempts.

Offline throughout, in test_service_lifecycle.py's idiom: _fetch_json and
_fetch_bytes are the only network boundary, _swap_in and schedule_restart
are always mocked so no real restart can happen here, and a real
AppDatabase provides .meta()/.set_meta()/.settings()/.path.
"""
import io
import os
import shutil
import sys
import tarfile
import threading
import urllib.error

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("selfupdate_job_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


from netpath import selfupdate            # noqa: E402
from netpath.appdb import AppDatabase      # noqa: E402

SHA = "e" * 40
NEXT_SHA = "f" * 40


def build_tarball(root: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for name, text in ((f"{root}/netpath/__init__.py", "x = 1\n"),
                           (f"{root}/netpath/web/__init__.py", "y = 1\n")):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


state = {"sha": SHA, "message": "the commit at the tip", "error": None,
         "gate": None}


def fake_json(url, timeout=10.0):
    if state["gate"] is not None:
        state["gate"].wait(10.0)
    if state["error"] is not None:
        raise state["error"]
    if url.endswith("/commits/main"):
        return {"sha": state["sha"], "commit": {"message": state["message"]}}
    raise AssertionError(url)


def fake_bytes(url, timeout=60.0, max_bytes=0):
    if "codeload" in url:
        return build_tarball(f"magicalbeans-{state['sha']}")
    raise AssertionError(url)


def new_db(tag):
    d = os.path.join(TMPDIR, tag)
    os.makedirs(d, exist_ok=True)
    app_db = AppDatabase(os.path.join(d, "app.db"))
    app_db.save_settings({"updates_enabled": True})
    selfupdate._before_restart_hook = None
    selfupdate._before_restart_done = False
    return app_db


real = {"json": selfupdate._fetch_json, "bytes": selfupdate._fetch_bytes,
        "swap": selfupdate._swap_in, "restart": selfupdate.schedule_restart,
        "grace": selfupdate.RESTART_GRACE_S}

selfupdate._fetch_json = fake_json
selfupdate._fetch_bytes = fake_bytes
selfupdate.RESTART_GRACE_S = 0

try:
    # =================================================================
    # 1. One clean run: the steps, the order, and what the hook can see
    # =================================================================
    db1 = new_db("t1")
    steps, swapped, restarts, hook = [], [], [], {}
    selfupdate._swap_in = lambda path: swapped.append(path)
    selfupdate.schedule_restart = lambda delay=1.5: restarts.append(delay)

    def before_restart():
        hook["step"] = selfupdate.status()["step"]
        hook["meta"] = db1.meta(selfupdate.INSTALLED_COMMIT_KEY)
        hook["swapped_yet"] = list(swapped)

    selfupdate.set_before_restart_hook(before_restart)
    quiesce = []
    result1 = selfupdate.apply(
        db1, report=lambda step, _m: steps.append(step),
        before_quiesce=lambda sha, msg: quiesce.append((sha, msg)))

    check("1. apply() reports the install",
          result1.get("ok") and not result1.get("up_to_date")
          and result1.get("commit") == SHA[:10], str(result1))
    check("1. the steps run in order, with no step skipped",
          steps == ["checking", "downloading", "extracting", "installing",
                    "restarting"], str(steps))
    check("1. the before-quiesce callback ran once, with the full sha",
          quiesce == [(SHA, "the commit at the tip")], str(quiesce))
    # The 201 "database is locked" lines: the markers used to be written
    # from a fresh connection after the teardown had (not quite) released
    # app.db. Written through the open connection first, they are there for
    # anything the hook itself wants to record.
    check("1. the installed commit is recorded BEFORE the hook runs",
          hook.get("meta") == SHA, repr(hook.get("meta")))
    check("1. …and the hook runs at the restarting step, before the swap",
          hook.get("step") == "restarting" and hook.get("swapped_yet") == [],
          str(hook))
    check("1. …and the swap happened after it", len(swapped) == 1, str(swapped))
    check("1. the restart is scheduled exactly once",
          restarts == [1.5], str(restarts))
    check("1. no tag is claimed for a branch pull",
          db1.meta(selfupdate.INSTALLED_TAG_KEY) == "",
          repr(db1.meta(selfupdate.INSTALLED_TAG_KEY)))

    # =================================================================
    # 2. The same tip again is "up to date", said honestly
    # =================================================================
    steps.clear()
    result2 = selfupdate.apply(db1, report=lambda step, _m: steps.append(step))
    check("2. the same tip is up to date, not a failure",
          result2.get("ok") and result2.get("up_to_date"), str(result2))
    check("2. …and it is its own step, so the dialog need not guess",
          steps == ["checking", "up_to_date"], str(steps))
    status2 = selfupdate.status()
    check("2. status() answers from module state once the job is over",
          status2["state"] == "done" and status2["step"] == "up_to_date"
          and status2["commit"] == SHA[:10]
          and status2["message"] == "the commit at the tip", str(status2))
    db1.close()

    # =================================================================
    # 3. No network is a failed step carrying the reason
    # =================================================================
    db3 = new_db("t3")
    state["error"] = urllib.error.URLError("no network in this test")
    try:
        result3 = selfupdate.apply(db3)
    finally:
        state["error"] = None
    check("3. an unreachable GitHub is reported, not raised",
          result3.get("ok") is False and "reach" in result3.get("error", ""),
          str(result3))
    status3 = selfupdate.status()
    check("3. …and the job ends on the failed step with the reason on it",
          status3["state"] == "failed" and status3["step"] == "failed"
          and "no network" in status3["error"], str(status3))
    db3.close()

    # =================================================================
    # 4. A swap that fails restarts anyway, on the markers it booted with
    # =================================================================
    db4 = new_db("t4")
    db4.set_meta(selfupdate.INSTALLED_COMMIT_KEY, "0" * 40)
    db4.set_meta(selfupdate.INSTALLED_TAG_KEY, "v4.54.1")
    restarts4 = []
    selfupdate.schedule_restart = lambda delay=1.5: restarts4.append(delay)

    def raising_swap_in(path):
        raise OSError("The process cannot access the file because it is "
                      "being used by another process")

    selfupdate._swap_in = raising_swap_in
    result4 = selfupdate.apply(db4)
    check("4. the failure is reported rather than raised",
          result4.get("ok") is False and "could not be installed"
          in result4.get("error", ""), str(result4))
    check("4. …the restart still happens, on the previous version",
          restarts4 == [1.5], str(restarts4))
    check("4. …the caller is told the service is already torn down",
          result4.get("quiesced") is True, str(result4))
    check("4. …and the markers are put back, so the version that boots is "
          "not reported as the one that never installed",
          db4.meta(selfupdate.INSTALLED_COMMIT_KEY) == "0" * 40
          and db4.meta(selfupdate.INSTALLED_TAG_KEY) == "v4.54.1",
          f"{db4.meta(selfupdate.INSTALLED_COMMIT_KEY)!r} "
          f"{db4.meta(selfupdate.INSTALLED_TAG_KEY)!r}")
    check("4. …and the job says failed with that reason",
          selfupdate.status()["step"] == "failed", str(selfupdate.status()))
    db4.close()

    # =================================================================
    # 5. start_job: one at a time, on a thread that is not a daemon
    # =================================================================
    db5 = new_db("t5")
    selfupdate._swap_in = lambda path: None
    selfupdate.schedule_restart = lambda delay=1.5: None
    state["sha"], state["message"] = NEXT_SHA, "a later commit"
    gate = threading.Event()
    state["gate"] = gate
    results5, quiesce5 = [], []
    started = selfupdate.start_job(db5,
                                   lambda sha, msg: quiesce5.append(sha),
                                   results5.append)
    check("5. start_job answers at once with the job's status",
          started.get("state") == "running"
          and not started.get("already_running"), str(started))
    second = selfupdate.start_job(db5)
    check("5. a second press while one is in flight is refused, not queued",
          second.get("already_running") is True, str(second))
    check("5. the job thread is not a daemon: it has to outlive the request "
          "that asked for it, and the restart it schedules is the only thing "
          "that brings the service back",
          selfupdate._job_thread is not None
          and selfupdate._job_thread.daemon is False, "")
    gate.set()
    state["gate"] = None
    check("5. wait_for_job() joins it", selfupdate.wait_for_job(20) is True, "")
    check("5. the result callback saw the outcome",
          len(results5) == 1 and results5[0].get("ok") is True, str(results5))
    check("5. …and the before-quiesce callback ran on the job thread too",
          quiesce5 == [NEXT_SHA], str(quiesce5))
    final = selfupdate.status()
    check("5. status() after the job is done reports it finished",
          final["state"] == "done" and final["finished_ts"] >= final["started_ts"]
          and final["commit"] == NEXT_SHA[:10], str(final))
    db5.close()
finally:
    selfupdate._fetch_json = real["json"]
    selfupdate._fetch_bytes = real["bytes"]
    selfupdate._swap_in = real["swap"]
    selfupdate.schedule_restart = real["restart"]
    selfupdate.RESTART_GRACE_S = real["grace"]
    selfupdate._before_restart_hook = None
    selfupdate._before_restart_done = False

# =====================================================================
# 6. The restart thread's own two fixes, read from the source
# =====================================================================
# Neither is observable from a test that must never actually restart: the
# thread's daemon flag is checked live above, but "logs before it does
# anything" and "logs a traceback if it dies" can only be asserted here,
# and both are the difference between 146 silent attempts and a log line
# saying what happened.
SRC = open(os.path.join(_paths.REPO_ROOT, "netpath", "selfupdate.py"),
           encoding="utf-8").read()
check("6. schedule_restart's thread is not a daemon",
      "daemon=False" in SRC.split("def schedule_restart")[1], "")
check("6. …it logs before it sleeps, so a thread that never ran is "
      "distinguishable from one that ran and failed",
      "restart thread started pid=" in SRC, "")
check("6. …and any exception out of its body reaches the log with a traceback",
      "restart thread failed" in SRC and "traceback.format_exc()" in SRC, "")
check("6. the POSIX path logs before execv replaces the process image",
      "_log_restart(f\"exec pid=" in SRC, "")

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

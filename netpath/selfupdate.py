"""Update this install from the GitHub repository (stdlib only): check the
tip of `main`, download its tarball, swap it in for the running `netpath`
package, and re-exec.

SECURITY NOTE — accepted debt: step 1 follows the mutable `main` branch and
the download is checked only for size and "looks like SappiWhere", not any
signature or digest — whoever can push to main controls what every install
runs next. The verified path (newest tag + published SHA256SUMS) still
exists and is tested (`latest_tag`, `published_digest`, `tarball_name`);
`apply()` just doesn't call it yet. Until it does, leave `updates_enabled`
off (the default) and install by hand.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request

OWNER = "thawkins5555"
REPO = "magicalbeans"
BRANCH = "main"

INSTALLED_COMMIT_KEY = "update_installed_commit"
INSTALLED_TAG_KEY = "update_installed_tag"
INSTALLED_AT_KEY = "update_installed_at"

# The setting that has to be on before any of this runs. Off by default.
UPDATES_ENABLED_KEY = "updates_enabled"

USER_AGENT = "SappiWhere-Updater"

# The published digest list, as a release asset — see the Releasing section
# of README.md for the name a release must attach it under.
SUMS_ASSET = "SHA256SUMS"

# A source tarball of this application is a couple of megabytes. The cap is
# generous enough for a decade of growth and small enough that a hostile or
# broken endpoint cannot fill the disk while we read it.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024

UPDATES_DISABLED_MESSAGE = (
    "Updating from GitHub is switched off. Turn on \"Allow updates from "
    "GitHub\" in Settings (an administrator's setting) to enable it, or "
    "install the new version by hand.")

# This file is netpath/selfupdate.py, so its own directory is the package
# being replaced and that directory's parent is where it lives.
_NETPATH_DIR = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_NETPATH_DIR)
_CACERT_PATH = os.path.join(_NETPATH_DIR, "cacert.pem")

_COPY_ALONGSIDE = ("requirements.txt", "README.md", "CHANGELOG.md", "FEATURES.md",
                   "INTERNALS.md", "CREDENTIAL-SECURITY.md",
                   "NETWORK-AND-STORAGE-REQUIREMENTS.md")


# --------------------------------------------------------------- the job

# The before-restart hook alone measures 37-63 s against a real fleet, and
# app.js gives a request 30. So the update is a job: the POST answers at
# once and the dialog reads the outcome from status().

STEPS = ("idle", "checking", "up_to_date", "downloading", "extracting",
         "installing", "restarting", "failed")

_TERMINAL = {"up_to_date": "done", "failed": "failed"}

# Long enough for one poll of /api/update/status to see "restarting" before
# the listener goes away. Tests set it to 0.
RESTART_GRACE_S = 2.0

_job_lock = threading.Lock()
_job_thread = None
_job = {"state": "idle", "step": "idle", "message": "", "error": "",
        "commit": "", "started_ts": 0.0, "finished_ts": 0.0}


def _set(step: str, *, message=None, error=None, commit=None) -> None:
    with _job_lock:
        _job["step"] = step
        _job["state"] = _TERMINAL.get(step, "running")
        if message is not None:
            _job["message"] = message
        if error is not None:
            _job["error"] = error
        if commit is not None:
            _job["commit"] = commit
        if step in _TERMINAL:
            _job["finished_ts"] = time.time()


def status() -> dict:
    """Where the current (or last) update got to. Answered from module state
    rather than from anything the caller holds, so a browser that reloaded
    mid-update picks the running job back up instead of showing an idle
    button over an install in flight."""
    with _job_lock:
        return dict(_job)


def _ssl_context() -> ssl.SSLContext:
    """The system's trusted CAs plus our vendored bundle, so either one
    having the certificate GitHub needs is enough to verify the connection."""
    context = ssl.create_default_context()
    if os.path.isfile(_CACERT_PATH):
        try:
            context.load_verify_locations(cafile=_CACERT_PATH)
        except ssl.SSLError:
            pass  # a corrupt bundle shouldn't break the system store's own certs
    return context


# Everything that reaches the network goes through these two functions —
# nothing else here imports urllib — so tests can replace them and run offline.

def _fetch_json(url: str, timeout: float = 10.0):
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout,
                                context=_ssl_context()) as response:
        return json.loads(response.read().decode("utf-8"))


def _fetch_bytes(url: str, timeout: float = 60.0,
                 max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """At most `max_bytes`, refused rather than truncated past it."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout,
                                context=_ssl_context()) as response:
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"{url} is larger than the {max_bytes:,} byte limit")
    return raw


# ------------------------------------------------------------ choosing a tag

_VERSION_PART = re.compile(r"\d+")


def _version_key(tag: str) -> tuple:
    """Sortable form of a tag name: the run of numbers in it, in order, so
    "v4.39.0" sorts above "v4.9.0" (plain string order gets that wrong)."""
    return tuple(int(part) for part in _VERSION_PART.findall(tag)) or (-1,)


def latest_commit(timeout: float = 10.0) -> dict:
    """The current tip of BRANCH, from GitHub's commits API — what apply()
    installs. See the module's SECURITY NOTE: a branch tip moves, and
    nothing here proves who moved it."""
    head = _fetch_json(
        f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{BRANCH}",
        timeout=timeout)
    sha = str((head or {}).get("sha", ""))
    if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        # An answer we cannot read is not a connectivity problem, and saying
        # "could not reach GitHub" for it sends an operator to the firewall.
        raise ValueError(f"GitHub's answer for {BRANCH} carried no commit id")
    message = str(((head or {}).get("commit") or {}).get("message", ""))
    return {"sha": sha, "message": message.splitlines()[0][:200] if message else ""}


def latest_tag(timeout: float = 10.0) -> dict:
    """The newest published tag, from GitHub's tags API, chosen by version
    order (not API return order). Part of the verified path apply() does
    not currently use — see the module's SECURITY NOTE."""
    tags = _fetch_json(f"https://api.github.com/repos/{OWNER}/{REPO}/tags",
                       timeout=timeout)
    named = [t for t in (tags or []) if t.get("name")]
    if not named:
        raise ValueError("that repository has published no tags, so there is "
                         "no release to install")
    newest = max(named, key=lambda t: _version_key(str(t["name"])))
    return {"tag": str(newest["name"]),
            "sha": str((newest.get("commit") or {}).get("sha", ""))}


def tarball_name(tag: str) -> str:
    """What codeload calls the tarball it serves for a tag. The digest list
    is keyed by this name, so both ends have to agree on it."""
    return f"{REPO}-{tag}.tar.gz"


def published_digest(tag: str, timeout: float = 10.0) -> str:
    """The SHA-256 the release for `tag` published, read from the release's
    SHA256SUMS asset (a digest carried inside the archive it describes would
    prove nothing). Part of the verified path apply() does not use yet."""
    release = _fetch_json(
        f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{tag}",
        timeout=timeout)
    asset_url = ""
    for asset in (release or {}).get("assets") or []:
        if str(asset.get("name", "")) == SUMS_ASSET:
            asset_url = str(asset.get("browser_download_url", ""))
            break
    if not asset_url:
        raise ValueError(
            f"the release for {tag} publishes no {SUMS_ASSET}, so the "
            f"download cannot be checked against anything — refusing to "
            f"install it (see the Releasing section of README.md)")
    wanted = tarball_name(tag)
    text = _fetch_bytes(asset_url, timeout=timeout,
                        max_bytes=1024 * 1024).decode("utf-8", "replace")
    for line in text.splitlines():
        parts = line.split()
        # "<hex>  <name>", the format sha256sum writes and checks.
        if len(parts) >= 2 and os.path.basename(parts[-1]) == wanted:
            digest = parts[0].strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    raise ValueError(f"{SUMS_ASSET} for {tag} has no entry for {wanted}")


def _download_tarball(ref: str, dest_path: str, timeout: float = 60.0) -> str:
    """The tarball for `ref`, written to `dest_path`. Returns its SHA-256.
    `ref` is a commit id for apply()'s branch pull; codeload also accepts
    `refs/tags/<tag>` for the (currently unused) verified path."""
    url = f"https://codeload.github.com/{OWNER}/{REPO}/tar.gz/{ref}"
    raw = _fetch_bytes(url, timeout=timeout, max_bytes=MAX_DOWNLOAD_BYTES)
    with open(dest_path, "wb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """Only ordinary files and directories, only inside `dest`, and never
    with the archive's own permissions — defense in depth against a
    corrupted or tampered archive."""
    dest_real = os.path.realpath(dest)
    members = []
    for member in tar.getmembers():
        if member.issym() or member.islnk() or member.isdev():
            continue
        target = os.path.realpath(os.path.join(dest, member.name))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise ValueError(f"unsafe path in archive: {member.name}")
        member.mode = 0o755 if member.isdir() else 0o644
        members.append(member)
    try:
        tar.extractall(dest, members=members, filter="tar")
    except TypeError:
        # Python without the extraction filters (before 3.11.4).
        tar.extractall(dest, members=members)


def _swap_in(new_netpath: str) -> None:
    """Replace the installed `netpath` package with the one just unpacked.

    Keeps exactly one backup: any earlier `.bak` is removed first, so this
    never accumulates disk usage across repeated updates.
    """
    for name in os.listdir(_APP_ROOT):
        if name.startswith("netpath.bak-"):
            shutil.rmtree(os.path.join(_APP_ROOT, name), ignore_errors=True)

    backup = os.path.join(_APP_ROOT, f"netpath.bak-{int(time.time())}")
    os.rename(_NETPATH_DIR, backup)
    try:
        shutil.move(new_netpath, _NETPATH_DIR)
    except Exception:
        os.rename(backup, _NETPATH_DIR)   # put it back rather than leave nothing
        raise


def _relaunch_args() -> list[str]:
    """The command that starts this app fresh via `-m netpath`, not a bare
    script path — launching `sys.argv[0]` directly drops the package
    context every relative import here depends on."""
    return [sys.executable, "-m", "netpath"] + sys.argv[1:]


def _restart_posix() -> None:
    """`execve` replaces this process image in place: same PID, no gap
    where nothing is listening."""
    args = _relaunch_args()
    _log_restart(f"exec pid={os.getpid()} args={args}")
    os.execv(args[0], args)


RESTART_LOG = os.path.join(_APP_ROOT, "update_restart.log")


def _log_restart(line: str) -> None:
    """A plain file rather than the in-memory event log: that log dies with
    the process, which is exactly the moment this needs to survive."""
    try:
        with open(RESTART_LOG, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
    except OSError:
        pass


def _restart_windows() -> None:
    """Windows has no true in-place exec: spawn the replacement first and
    only end this process once it exists, so a watching supervisor's
    cleanup can't kill the new process before it's up. A visible console
    (not a detached child) for non-headless runs, since some AV/EDR treats
    "spawns a windowless child and exits" as suspicious."""
    import subprocess

    headless = "--headless" in sys.argv or "--web" in sys.argv
    creationflags = (subprocess.DETACHED_PROCESS if headless
                     else subprocess.CREATE_NEW_CONSOLE)
    creationflags |= (subprocess.CREATE_NEW_PROCESS_GROUP
                      | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0))

    args = _relaunch_args()
    _log_restart(f"restarting pid={os.getpid()} headless={headless} args={args}")
    try:
        proc = subprocess.Popen(args, cwd=_APP_ROOT, close_fds=True,
                                creationflags=creationflags)
        time.sleep(0.5)   # long enough to catch an immediate failure to start
        _log_restart(f"spawned pid={proc.pid} alive_after_0.5s={proc.poll() is None}")
    except OSError as exc:
        _log_restart(f"spawn failed: {exc}")
    os._exit(0)


# Set by __main__.py once the web server and service exist.
_before_restart_hook = None


_before_restart_done = False


def set_before_restart_hook(fn) -> None:
    global _before_restart_hook, _before_restart_done
    _before_restart_hook = fn
    _before_restart_done = False


def _run_before_restart() -> None:
    """Release the port and stop the collectors, pollers and workers. Runs
    at most once per process. apply() calls this BEFORE the package
    directory is replaced, so nothing is running while lazy imports would
    otherwise resolve against a half-swapped tree."""
    global _before_restart_done
    if _before_restart_done or _before_restart_hook is None:
        return
    _before_restart_done = True
    _log_restart("running before-restart hook (stop server, shut down service)")
    started = time.time()
    try:
        _before_restart_hook()
    except Exception as exc:
        _log_restart(f"before-restart hook failed: {exc}")
    _log_restart(f"before-restart hook finished in {time.time() - started:.1f}s")


def schedule_restart(delay: float = 1.5) -> None:
    """Restart after `delay` seconds, so the response reaches the browser
    first. The replacement is spawned only after the port and databases are
    released — spawning first raced the old process for the same port/files
    and lost.

    Not a daemon thread: the hook that runs before this one has already
    stopped the server and the service, so the interpreter can reach the
    point where it exits every remaining thread while this one is still
    sleeping — and a daemon thread dies there without a line in the log. In
    146 recorded attempts this thread never reached its first statement.
    """
    def _go():
        _log_restart(f"restart thread started pid={os.getpid()} delay={delay}")
        try:
            time.sleep(delay)
            _run_before_restart()      # a no-op when apply() already did it
            _restart_windows() if os.name == "nt" else _restart_posix()
        except BaseException:
            _log_restart("restart thread failed:\n" + traceback.format_exc())
    threading.Thread(target=_go, name="sappiwhere-update-restart",
                     daemon=False).start()


def updates_enabled(app_db) -> bool:
    """Whether the operator has allowed this host to update itself. Read
    from the stored settings on every attempt rather than cached, so
    turning it off takes effect at once."""
    try:
        return bool(app_db.settings().get(UPDATES_ENABLED_KEY, False))
    except Exception:
        return False


_INSTALL_MARKERS = (INSTALLED_COMMIT_KEY, INSTALLED_AT_KEY, INSTALLED_TAG_KEY)


def _restore_meta(db_path: str, previous: dict) -> None:
    """Put the install markers back after a swap that did not happen. app.db
    is closed by then, so this goes through connections of its own; the
    retries are for the moment just after teardown, where the file can still
    be held briefly by a connection that is on its way out."""
    from .appdb import write_meta

    for key, value in previous.items():
        for attempt in range(3):
            try:
                write_meta(db_path, key, value or "")
                break
            except Exception as exc:
                _log_restart(f"restoring {key!r} (try {attempt + 1}): {exc}")
                time.sleep(0.2)


def apply(app_db, report=None, before_quiesce=None) -> dict:
    """Check, and if there is anything new, download it, install it and
    restart. Returns a JSON-able result; never raises — failures come back
    as `{"ok": False, "error": ...}` so the Settings page can show them.

    `report(step, message)`, when given, is called on every step change.
    `before_quiesce(sha, message)` is called once the markers are written
    and before anything is torn down — the last moment at which a caller
    can still write to app.db.
    """
    def step(name, *, message=None, error=None, commit=None):
        _set(name, message=message, error=error, commit=commit)
        if report:
            report(name, error or message or "")

    if not updates_enabled(app_db):
        step("failed", error=UPDATES_DISABLED_MESSAGE)
        return {"ok": False, "disabled": True, "error": UPDATES_DISABLED_MESSAGE}

    step("checking", message="", error="", commit="")
    try:
        head = latest_commit()
    except (urllib.error.URLError, TimeoutError) as exc:
        error = f"Could not reach GitHub: {exc}"
        step("failed", error=error)
        return {"ok": False, "error": error}
    except (ValueError, KeyError) as exc:
        # GitHub answered; what it said is the problem. Reporting "could not
        # reach GitHub" for an answer that arrived intact sent the operator
        # to look at firewalls and proxies for a condition no amount of
        # connectivity would change.
        step("failed", error=str(exc))
        return {"ok": False, "error": str(exc)}

    sha = head["sha"]
    message = head["message"] or sha[:10]
    if app_db.meta(INSTALLED_COMMIT_KEY) == sha:
        # Its own step: "update failed" for a host that was already
        # current is the complaint this job exists to answer.
        step("up_to_date", message=message, commit=sha[:10])
        return {"ok": True, "up_to_date": True, "commit": sha[:10],
                "message": message}

    tmp_dir = tempfile.mkdtemp(prefix="sappiwhere-update-")
    try:
        step("downloading", message=message, commit=sha[:10])
        archive_path = os.path.join(tmp_dir, "update.tar.gz")
        try:
            # Nothing checks this digest: the branch pull has no published
            # digest to check it against. See the SECURITY NOTE at the top.
            _download_tarball(sha, archive_path)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            step("failed", error=f"Download failed: {exc}")
            return {"ok": False, "error": f"Download failed: {exc}"}

        step("extracting")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                _safe_extract(tar, extract_dir)
        except (tarfile.TarError, ValueError, OSError) as exc:
            step("failed", error=f"Could not unpack the update: {exc}")
            return {"ok": False, "error": f"Could not unpack the update: {exc}"}

        entries = os.listdir(extract_dir)
        if len(entries) != 1:
            step("failed", error="Unexpected archive layout from GitHub")
            return {"ok": False, "error": "Unexpected archive layout from GitHub"}
        new_root = os.path.join(extract_dir, entries[0])
        new_netpath = os.path.join(new_root, "netpath")
        if not (os.path.isfile(os.path.join(new_netpath, "__init__.py"))
                and os.path.isfile(os.path.join(new_netpath, "web", "__init__.py"))):
            error = ("Downloaded archive doesn't look like SappiWhere — "
                     "refusing to install it")
            step("failed", error=error)
            return {"ok": False, "error": error}

        step("installing")
        db_path = getattr(app_db, "path", "")
        previous = {key: app_db.meta(key) for key in _INSTALL_MARKERS}
        # Through the still-open connection, before anything is torn down:
        # written afterwards from a fresh connection they hit "database is
        # locked" 201 times, and nothing on disk has changed yet, so a write
        # that fails here costs nothing.
        try:
            app_db.set_meta(INSTALLED_COMMIT_KEY, sha)
            app_db.set_meta(INSTALLED_AT_KEY, str(time.time()))
            # A branch pull cannot honestly claim a tag, and a stale one
            # would read as what is installed.
            app_db.set_meta(INSTALLED_TAG_KEY, "")
        except Exception as exc:
            error = f"Could not record the update in app.db: {exc}"
            step("failed", error=error)
            return {"ok": False, "error": error}

        if before_quiesce:
            try:
                before_quiesce(sha, message)
            except Exception as exc:
                _log_restart(f"before-quiesce callback failed: {exc}")

        step("restarting")
        time.sleep(RESTART_GRACE_S)

        # Nothing of ours runs while the files change: the listener is down
        # and every worker has stopped.
        _run_before_restart()
        try:
            _swap_in(new_netpath)
        except OSError as exc:
            # _swap_in already restored the previous netpath/, so the
            # restart comes back up on the install this booted from — and
            # the markers have to come back with it.
            _restore_meta(db_path, previous)
            error = (f"Update downloaded but could not be installed: {exc}. "
                     f"Restarting on the previous version rather than staying "
                     f"down.")
            step("failed", error=error)
            schedule_restart()
            return {"ok": False, "error": error, "quiesced": True}

        for name in _COPY_ALONGSIDE:
            src = os.path.join(new_root, name)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, os.path.join(_APP_ROOT, name))
                except OSError:
                    pass  # cosmetic only — the package swap is what matters
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    schedule_restart()
    return {"ok": True, "up_to_date": False, "commit": sha[:10],
            "message": message, "restarting": True, "quiesced": True}


def start_job(app_db, before_quiesce=None, on_result=None) -> dict:
    """Run apply() on a thread of its own and return the job's status now.

    One at a time: a second press while an install is in flight would race
    the first for the package directory, so it is refused with
    `already_running` rather than queued. Not a daemon thread — the update
    outlives the request that asked for it, and the restart it schedules is
    the only thing that brings the service back.
    """
    global _job_thread

    with _job_lock:
        if _job_thread is not None and _job_thread.is_alive():
            running = dict(_job)
            running["already_running"] = True
            return running
        _job.update(state="running", step="checking", message="", error="",
                    commit="", started_ts=time.time(), finished_ts=0.0)
        thread = threading.Thread(
            target=_run_job, args=(app_db, before_quiesce, on_result),
            name="sappiwhere-update", daemon=False)
        _job_thread = thread
    thread.start()
    return status()


def _run_job(app_db, before_quiesce, on_result) -> None:
    try:
        result = apply(app_db, before_quiesce=before_quiesce)
    except BaseException as exc:
        _log_restart("update job failed:\n" + traceback.format_exc())
        _set("failed", error=f"The update stopped unexpectedly: {exc}")
        result = {"ok": False, "error": str(exc)}
    with _job_lock:
        _job["finished_ts"] = time.time()
        if _job["state"] == "running":
            _job["state"] = "done" if result.get("ok") else "failed"
    if on_result:
        try:
            on_result(result)
        except Exception as exc:
            _log_restart(f"update result callback failed: {exc}")


def wait_for_job(timeout: float = 10.0) -> bool:
    """Whether the job thread finished within `timeout`. For tests, and for
    a shutdown that would otherwise close app.db under a running install."""
    thread = _job_thread
    if thread is None:
        return True
    thread.join(timeout)
    return not thread.is_alive()

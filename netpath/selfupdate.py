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
    try:
        _before_restart_hook()
    except Exception as exc:
        _log_restart(f"before-restart hook failed: {exc}")


def schedule_restart(delay: float = 1.5) -> None:
    """Restart after `delay` seconds, so the response reaches the browser
    first. The replacement is spawned only after the port and databases are
    released — spawning first raced the old process for the same port/files
    and lost."""
    def _go():
        time.sleep(delay)
        _run_before_restart()          # a no-op when apply() already did it
        _restart_windows() if os.name == "nt" else _restart_posix()
    threading.Thread(target=_go, name="sappiwhere-update-restart",
                     daemon=True).start()


def updates_enabled(app_db) -> bool:
    """Whether the operator has allowed this host to update itself. Read
    from the stored settings on every attempt rather than cached, so
    turning it off takes effect at once."""
    try:
        return bool(app_db.settings().get(UPDATES_ENABLED_KEY, False))
    except Exception:
        return False


def apply(app_db) -> dict:
    """Check, and if there is anything new, download it, install it and
    restart. Returns a JSON-able result; never raises — failures come back
    as `{"ok": False, "error": ...}` so the Settings page can show them."""
    if not updates_enabled(app_db):
        return {"ok": False, "disabled": True, "error": UPDATES_DISABLED_MESSAGE}

    try:
        head = latest_commit()
    except (urllib.error.URLError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach GitHub: {exc}"}
    except (ValueError, KeyError) as exc:
        # GitHub answered; what it said is the problem. Reporting "could not
        # reach GitHub" for an answer that arrived intact sent the operator
        # to look at firewalls and proxies for a condition no amount of
        # connectivity would change.
        return {"ok": False, "error": str(exc)}

    sha = head["sha"]
    message = head["message"] or sha[:10]
    if app_db.meta(INSTALLED_COMMIT_KEY) == sha:
        return {"ok": True, "up_to_date": True, "commit": sha[:10],
                "message": message}

    tmp_dir = tempfile.mkdtemp(prefix="sappiwhere-update-")
    try:
        archive_path = os.path.join(tmp_dir, "update.tar.gz")
        try:
            # Nothing checks this digest: the branch pull has no published
            # digest to check it against. See the SECURITY NOTE at the top.
            _download_tarball(sha, archive_path)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            return {"ok": False, "error": f"Download failed: {exc}"}

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                _safe_extract(tar, extract_dir)
        except (tarfile.TarError, ValueError, OSError) as exc:
            return {"ok": False, "error": f"Could not unpack the update: {exc}"}

        entries = os.listdir(extract_dir)
        if len(entries) != 1:
            return {"ok": False, "error": "Unexpected archive layout from GitHub"}
        new_root = os.path.join(extract_dir, entries[0])
        new_netpath = os.path.join(new_root, "netpath")
        if not (os.path.isfile(os.path.join(new_netpath, "__init__.py"))
                and os.path.isfile(os.path.join(new_netpath, "web", "__init__.py"))):
            return {"ok": False, "error": "Downloaded archive doesn't look like "
                                          "SappiWhere — refusing to install it"}

        # Nothing of ours runs while the files change: the listener is down
        # and every worker has stopped.
        db_path = getattr(app_db, "path", "")
        _run_before_restart()
        try:
            _swap_in(new_netpath)
        except OSError as exc:
            # _swap_in already restored the previous netpath/ on failure, so
            # restarting here comes back up on the same install it booted from
            # rather than leaving the process alive with nothing running.
            schedule_restart()
            return {"ok": False, "error": f"Update downloaded but could not be "
                                          f"installed: {exc}. Restarting on the "
                                          f"previous version rather than staying "
                                          f"down."}

        for name in _COPY_ALONGSIDE:
            src = os.path.join(new_root, name)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, os.path.join(_APP_ROOT, name))
                except OSError:
                    pass  # cosmetic only — the package swap is what matters

        # app.db is already closed, so these go through a short-lived connection
        # of their own; a write failure must not skip schedule_restart() below.
        from .appdb import write_meta
        try:
            write_meta(db_path, INSTALLED_COMMIT_KEY, sha)
        except Exception as exc:
            _log_restart(f"write_meta({INSTALLED_COMMIT_KEY!r}) failed: {exc}")
        try:
            write_meta(db_path, INSTALLED_AT_KEY, str(time.time()))
        except Exception as exc:
            _log_restart(f"write_meta({INSTALLED_AT_KEY!r}) failed: {exc}")
        # The tag marker is what the verified path records, and a branch
        # pull cannot honestly claim one. Cleared rather than left behind,
        # so a stale tag never reads as "this is what is installed".
        try:
            write_meta(db_path, INSTALLED_TAG_KEY, "")
        except Exception as exc:
            _log_restart(f"write_meta({INSTALLED_TAG_KEY!r}) failed: {exc}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    schedule_restart()
    return {"ok": True, "up_to_date": False, "commit": sha[:10],
            "message": message, "restarting": True}

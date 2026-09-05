"""Update this install from the GitHub repository.

Standard library only, matching the rest of the headless service. There is no
configuration for this: the repository, branch and app layout are all fixed,
because the whole point is one button in Settings, not another thing to set up.

The flow behind that button:

0. Refuse outright unless the `updates_enabled` global setting is on. It is
   off by default: on a change-controlled network, "this host installs
   whatever the internet offers it, when anyone presses a button" is not a
   default anyone would choose, and before 4.37 there was no way to say no.
1. Ask GitHub's API for the current tip of the `main` branch.
2. If that commit is what is already installed (`update_installed_commit` in
   app.db), stop there — nothing to do.
3. Otherwise download that commit's tarball, capped at MAX_DOWNLOAD_BYTES.
4. Unpack into a temp directory with the archive's own mode bits discarded,
   sanity-check it looks like this application, quiesce the workers, and
   swap it in for the running `netpath` package.
5. Re-exec the process so the swapped-in code is what actually runs next.

SECURITY NOTE — accepted debt, to be resolved
---------------------------------------------
Step 1 follows a **mutable branch**, and step 3 verifies nothing about what
it downloads beyond the size cap and "does this look like SappiWhere".

That means: whoever can push to `main` — the repo owner, a stolen GitHub
credential, a CI token, a pull request merged by accident — chooses the code
every install in the fleet will run at the next press of this button, on
hosts that hold the plant's SNMP communities and SSH credentials. There is
no tag, no digest and no signature in the path. This is the same exposure
recorded as S-B1 in REVIEW-NETWORK-ENGINEER.md.

It is deliberate and temporary. 4.39.0 had shipped the hardened version of
this — newest published tag, verified against a `SHA256SUMS` published as a
release asset — but that left every install already in the field unable to
reach 4.39.0 through the button at all, since their own copy of this file
predates the setting the hardened path is gated behind. Restoring the branch
pull is what gets the fleet moving again.

The pieces to put it back are still here and still tested: `latest_tag()`,
`published_digest()` and `tarball_name()` below are the verified path, and
RELEASE.md still describes how a release publishes the digest they read.
Re-hardening is a change to `apply()` plus its tests, not a rewrite.

Until then, an installation that cannot accept "whoever holds push access to
this repository can run code here" should leave `updates_enabled` off — the
default — and install by hand. That is the mitigation available today.

The databases live outside this directory entirely (see NETWORK-AND-STORAGE-
REQUIREMENTS.md), so none of this ever touches them. Only the `netpath`
package directory is replaced; the previous copy is kept as one `.bak`
alongside it in case something needs to be recovered by hand.

Re-exec rather than a clean shutdown and restart: `os.execv` replaces this
process image in place, so it keeps the same PID under systemd/NSSM and picks
up the new files on the next import. Sessions are in-memory (see appdb.py),
so everyone signed in — this request included — is signed out by it; the web
UI expects that and sends people back to the sign-in page once it sees the
server answering again.

`cacert.pem` beside this file is Mozilla's CA bundle, the same one `pip` and
`certifi` vendor, checked in rather than pulled from a package at run time so
a headless install still needs nothing but the standard library. It exists
because a locked-down Windows server's own certificate store can be missing
whatever root GitHub's certificate chains to, with no route to Windows
Update's on-demand fetch to fill the gap — `urlopen()`'s default context
then fails with CERTIFICATE_VERIFY_FAILED even though the machine can reach
github.com fine. Trusting this bundle in addition to — not instead of — the
system store means either one having the right root is enough.
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

# The published digest list, as a release asset. Named here because
# RELEASE.md tells whoever cuts a release to attach a file with this name.
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


# ------------------------------------------------------- the network boundary
# Everything that reaches the network goes through these two functions, and
# nothing else in this module imports urllib. That is what makes the update
# path testable offline: a suite replaces these two and exercises the tag
# choice, the digest check and the refusals without a socket.

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
    """Sortable form of a tag name: the run of numbers in it, in order.
    "v4.39.0" sorts above "v4.36.1" and above "v4.9.0", which plain string
    order gets wrong. A tag with no numbers sorts below every tag that has
    some rather than raising."""
    return tuple(int(part) for part in _VERSION_PART.findall(tag)) or (-1,)


def latest_commit(timeout: float = 10.0) -> dict:
    """The current tip of BRANCH, from GitHub's commits API.

    What `apply()` installs. A branch tip moves, and nothing here proves who
    moved it — see the SECURITY NOTE at the top of this module for what that
    costs and what has to change to get the verified path back.
    """
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
    """The newest published tag, from GitHub's tags API — the equivalent of
    `git ls-remote --tags`. Chosen by version order rather than by the
    order the API happens to return, so a tag pushed out of sequence does
    not become "the newest".

    Part of the verified path that `apply()` does not currently use; kept
    (and kept tested) so re-hardening is a change to `apply()` rather than a
    rewrite. See the SECURITY NOTE at the top of this module.
    """
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
    """The SHA-256 the release for `tag` published for its source tarball.

    Read from the release's SHA256SUMS *asset*, not from a file inside the
    archive: a digest carried by the thing it describes proves nothing.

    Part of the verified path that `apply()` does not currently use. See the
    SECURITY NOTE at the top of this module.
    """
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
            f"install it (see RELEASE.md)")
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

    `ref` is a commit id for the branch pull `apply()` does, and codeload
    also accepts `refs/tags/<tag>` for the verified path, so one function
    serves both. The digest is returned whether or not anything checks it:
    it costs nothing to compute while the bytes are in hand, and it is what
    the verified path compares.
    """
    url = f"https://codeload.github.com/{OWNER}/{REPO}/tar.gz/{ref}"
    raw = _fetch_bytes(url, timeout=timeout, max_bytes=MAX_DOWNLOAD_BYTES)
    with open(dest_path, "wb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """Only ordinary files and directories, only inside `dest`, and never
    with the archive's own permissions.

    codeload tarballs never legitimately need symlinks or device nodes; this
    is defense in depth against a corrupted or tampered archive rather than
    anything expected of our own repository. The mode bits are replaced
    outright rather than trusted: `extractall` restores whatever the archive
    carried, so an archive claiming 0777 (or setuid) on a file would get it,
    and nothing in this application has any use for a mode other than "the
    owner may write it, anyone may read it".
    """
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
    """The command that starts this app fresh, as the `netpath` module
    rather than a bare script path.

    `sys.argv` alone is not enough to rebuild this: `-m netpath` rewrites
    `sys.argv[0]` to `__main__.py`'s resolved file path, and launching that
    path directly — rather than through `-m` — drops the package context
    every relative import in this app depends on (`from . import
    selfupdate`, `from .web import Service`, and so on), crashing on the
    very first one with "attempted relative import with no known parent
    package". `-m netpath` is what actually restores that context; the
    rest of the original argv, past whatever argv[0] happened to be,
    still carries the flags this was launched with.
    """
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
    """Windows has no true in-place exec — Python's `os.execv` emulates it by
    starting a new process and then ending this one, and if a supervisor
    (a Windows service wrapper, a job-object-based process tree) is watching
    this process, its cleanup can kill that new process the instant this one
    exits, so the "restart" silently becomes a stop.

    Spawn the replacement first and only end this one once it exists. Headless
    gets a fully detached, windowless child, matching how it already runs.
    A console/GUI session gets its replacement in a new, visible console
    instead of a hidden detached one — some antivirus/EDR products treat "a
    process spawns a windowless child and immediately exits" as a hallmark of
    something trying to hide, and would rather block or kill exactly that
    shape of restart. Either way this also tries to break out of any job
    object this process is in; if that is refused and a supervisor kills the
    child alongside this process anyway, that supervisor's own restart policy
    is the fallback — the files `_swap_in` already put in place are what the
    next launch reads regardless of which path actually restarts it.
    """
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


# Set by __main__.py once the web server and service exist, so the restart
# can release the port and close the databases before spawning a replacement
# rather than after — see the note on _before_restart in schedule_restart().
_before_restart_hook = None


_before_restart_done = False


def set_before_restart_hook(fn) -> None:
    global _before_restart_hook, _before_restart_done
    _before_restart_hook = fn
    _before_restart_done = False


def _run_before_restart() -> None:
    """Release the port and stop the collectors, pollers and workers. Runs
    at most once per process.

    `apply()` calls this BEFORE the package directory is replaced, not
    after. The window between the swap and the re-exec is one where the
    process runs already-imported old code while every lazy import (this
    application has many: `from .. import dpapi` inside handlers, `from
    ..auth import …` inside post_login) resolves against the new tree.
    Collectors, the ConfigRX worker and the DHCP poller used to keep
    running straight through it. Now nothing is running by the time the
    files change.
    """
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
    """Restart after `delay` seconds, so the response to this request has
    time to reach the browser first.

    The replacement is spawned only after the hook has released the port and
    closed the databases, not before: spawning first and cleaning up after
    left a window where the new process tried to bind the same port and open
    the same SQLite files while the old one was still holding both, lost
    that race, and died — and by the time the old process finally let go,
    there was nobody left to take its place.
    """
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
        # and every worker has stopped. Everything that could fail and leave
        # the install broken has already happened by this point.
        db_path = getattr(app_db, "path", "")
        _run_before_restart()
        try:
            _swap_in(new_netpath)
        except OSError as exc:
            # _run_before_restart() has already happened: the listener is
            # down and every worker, collector and database is closed. That
            # makes "return the error and leave the process as it is" the
            # one answer that is never acceptable here — the process would
            # stay alive with nothing running behind it, indefinitely, until
            # an operator noticed the box had gone dark. _swap_in's own
            # except clause has already put the previous netpath/ back for
            # any failure inside shutil.move (a locked file under Windows
            # AV/EDR real-time scanning, or ENOSPC), so what is on disk here
            # is the same install this process booted from. Restarting onto
            # it is what a service manager or `nssm`/`systemd` restart would
            # do anyway, and schedule_restart()'s own before-restart call is
            # a documented no-op once _run_before_restart() has already run
            # once — so this is not a second teardown, just the restart that
            # has to happen regardless of which branch got us here.
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

        # The hook above closed app.db, so the markers go through a
        # short-lived connection of their own rather than the handle the
        # service was using. They are bookkeeping, not the restart — a
        # failure writing any one of them must not skip schedule_restart()
        # below (apply()'s own docstring promises it never raises, and an
        # unguarded write_meta escaping here would also leave the
        # newly-swapped code never actually loaded, which matters far more
        # than one stale marker).
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

"""Update this install from the GitHub repository.

Standard library only, matching the rest of the headless service. There is no
configuration for this: the repository, branch and app layout are all fixed,
because the whole point is one button in Settings, not another thing to set up.

The flow behind that button:

0. Refuse outright unless the `updates_enabled` global setting is on. It is
   off by default: on a change-controlled network, "this host installs
   whatever the internet offers it, when anyone presses a button" is not a
   default anyone would choose, and before 4.37 there was no way to say no.
1. Ask GitHub's API for the newest **release tag** — not the tip of a
   branch. A branch tip moves: whoever can push to it (the repo owner, a
   stolen credential, a CI token, a PR merged by accident) chose the code
   every install would run at the next press of the button. A tag is a
   name someone deliberately published.
2. If it matches what is already installed (`update_installed_tag` in
   app.db), stop there — nothing to do.
3. Otherwise fetch that release's `SHA256SUMS` asset, download the tag's
   tarball (capped, and hashed as it is written), and refuse it unless its
   digest is the one the release published. The digest comes from the
   release's asset list rather than from inside the archive, so tampering
   with the archive alone does not tamper with what it is checked against.
   RELEASE.md at the repo root describes how a release publishes it.
4. Unpack into a temp directory with the archive's own mode bits discarded,
   sanity-check it looks like this application, quiesce the workers, and
   swap it in for the running `netpath` package.
5. Re-exec the process so the swapped-in code is what actually runs next.

None of this is a signature: it proves the tarball is the one the release
named, not who named it. What it removes is the mutable-branch window and
the silent substitution of a tarball in flight; an operator who needs more
than that should leave `updates_enabled` off and install by hand.

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
    "v4.37.0" sorts above "v4.36.1" and above "v4.9.0", which plain string
    order gets wrong. A tag with no numbers sorts below every tag that has
    some rather than raising."""
    return tuple(int(part) for part in _VERSION_PART.findall(tag)) or (-1,)


def latest_tag(timeout: float = 10.0) -> dict:
    """The newest published tag, from GitHub's tags API — the equivalent of
    `git ls-remote --tags`. Chosen by version order rather than by the
    order the API happens to return, so a tag pushed out of sequence does
    not become "the newest"."""
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


def _download_tarball(tag: str, dest_path: str, timeout: float = 60.0) -> str:
    """The tag's tarball, written to `dest_path`. Returns its SHA-256."""
    url = f"https://codeload.github.com/{OWNER}/{REPO}/tar.gz/refs/tags/{tag}"
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
        release = latest_tag()
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach GitHub: {exc}"}

    tag = release["tag"]
    if app_db.meta(INSTALLED_TAG_KEY) == tag:
        return {"ok": True, "up_to_date": True, "tag": tag,
                "commit": release["sha"][:10], "message": tag}

    try:
        expected = published_digest(tag)
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
        return {"ok": False, "error": f"Refusing to install {tag}: {exc}"}

    tmp_dir = tempfile.mkdtemp(prefix="sappiwhere-update-")
    try:
        archive_path = os.path.join(tmp_dir, "update.tar.gz")
        try:
            actual = _download_tarball(tag, archive_path)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            return {"ok": False, "error": f"Download failed: {exc}"}
        if actual != expected:
            return {"ok": False, "error":
                    f"The {tag} tarball does not match the SHA-256 its "
                    f"release published ({actual[:12]}… against "
                    f"{expected[:12]}…) — refusing to install it."}

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
            return {"ok": False, "error": f"Update downloaded but could not be "
                                          f"installed: {exc}"}

        for name in _COPY_ALONGSIDE:
            src = os.path.join(new_root, name)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, os.path.join(_APP_ROOT, name))
                except OSError:
                    pass  # cosmetic only — the package swap is what matters

        # The hook above closed app.db, so the markers go through a
        # short-lived connection of their own rather than the handle the
        # service was using.
        from .appdb import write_meta
        write_meta(db_path, INSTALLED_TAG_KEY, tag)
        write_meta(db_path, INSTALLED_COMMIT_KEY, release["sha"])
        write_meta(db_path, INSTALLED_AT_KEY, str(time.time()))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    schedule_restart()
    return {"ok": True, "up_to_date": False, "tag": tag,
            "commit": release["sha"][:10], "message": tag, "restarting": True}

"""Update this install from the GitHub repository.

Standard library only, matching the rest of the headless service. There is no
configuration for this: the repository, branch and app layout are all fixed,
because the whole point is one button in Settings, not another thing to set up.

The flow behind that button:

1. Ask GitHub's API for the latest commit on the tracked branch.
2. If it matches what is already installed (`update_installed_commit` in
   app.db), stop there — nothing to do.
3. Otherwise download that commit's tarball, unpack it into a temp
   directory, sanity-check it looks like this application, and swap it in
   for the running `netpath` package.
4. Re-exec the process so the swapped-in code is what actually runs next.

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

import json
import os
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
INSTALLED_AT_KEY = "update_installed_at"

USER_AGENT = "SappiWhere-Updater"

# This file is netpath/selfupdate.py, so its own directory is the package
# being replaced and that directory's parent is where it lives.
_NETPATH_DIR = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_NETPATH_DIR)
_CACERT_PATH = os.path.join(_NETPATH_DIR, "cacert.pem")

_COPY_ALONGSIDE = ("requirements.txt", "README.md", "CHANGELOG.md", "FEATURES.md",
                   "CREDENTIAL-SECURITY.md", "NETWORK-AND-STORAGE-REQUIREMENTS.md")


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


def latest_commit(timeout: float = 10.0) -> dict:
    """The tip of the tracked branch, from GitHub's API."""
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{BRANCH}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout,
                                context=_ssl_context()) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return {
        "sha": payload["sha"],
        "message": payload["commit"]["message"].splitlines()[0],
        "date": payload["commit"]["author"]["date"],
    }


def _download_tarball(sha: str, dest_path: str, timeout: float = 60.0) -> None:
    url = f"https://codeload.github.com/{OWNER}/{REPO}/tar.gz/{sha}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout,
                                context=_ssl_context()) as response, \
         open(dest_path, "wb") as handle:
        shutil.copyfileobj(response, handle)


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """Only ordinary files and directories, and only inside `dest`.

    codeload tarballs never legitimately need symlinks or device nodes; this
    is defense in depth against a corrupted or tampered archive rather than
    anything expected of our own repository.
    """
    dest_real = os.path.realpath(dest)
    members = []
    for member in tar.getmembers():
        if member.issym() or member.islnk() or member.isdev():
            continue
        target = os.path.realpath(os.path.join(dest, member.name))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise ValueError(f"unsafe path in archive: {member.name}")
        members.append(member)
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


def schedule_restart(delay: float = 1.5) -> None:
    """Re-exec after `delay` seconds, so the response to this request has
    time to reach the browser first."""
    def _go():
        time.sleep(delay)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=_go, name="sappiwhere-update-restart",
                     daemon=True).start()


def apply(app_db) -> dict:
    """Check, and if there is anything new, download it, install it and
    restart. Returns a JSON-able result; never raises — failures come back
    as `{"ok": False, "error": ...}` so the Settings page can show them."""
    try:
        commit = latest_commit()
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach GitHub: {exc}"}

    installed = app_db.meta(INSTALLED_COMMIT_KEY)
    if installed == commit["sha"]:
        return {"ok": True, "up_to_date": True, "commit": commit["sha"][:10],
                "message": commit["message"]}

    tmp_dir = tempfile.mkdtemp(prefix="sappiwhere-update-")
    try:
        archive_path = os.path.join(tmp_dir, "update.tar.gz")
        try:
            _download_tarball(commit["sha"], archive_path)
        except (urllib.error.URLError, OSError) as exc:
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

        app_db.set_meta(INSTALLED_COMMIT_KEY, commit["sha"])
        app_db.set_meta(INSTALLED_AT_KEY, str(time.time()))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    schedule_restart()
    return {"ok": True, "up_to_date": False, "commit": commit["sha"][:10],
            "message": commit["message"], "restarting": True}

"""Find a temporary directory that actually exists and can be written to,
right now (stdlib only; this module imports nothing else from the package, so
anything may lean on it without risking an import cycle).

Why this module exists — one fault, two victims, both on real Windows
installs. With per-session temporary folders enabled (the default on Remote
Desktop / Terminal Services hosts), Windows gives each logon session its own
`…\\AppData\\Local\\Temp\\<sessionId>` and removes it when that session ends.
A service that was installed or first launched from an interactive session
inherited that session's `TEMP`; once the session ends the numbered directory
is gone, and every `tempfile` call that trusts `%TEMP%` raises against a
parent that no longer exists:

    The update stopped unexpectedly: [WinError 3] The system cannot find the
    path specified:
    'C:\\Users\\ADMNA-~1\\AppData\\Local\\Temp\\2\\sappiwhere-update-jyyd6pii'

    DHCP poll of CLQWSRTM1 failed: [Errno 2] No such file or directory:
    'C:\\Users\\ADMNA-~1\\AppData\\Local\\Temp\\2\\sappi-dhcp-z3_6xg__.ps1'

— the first at the Update button (`selfupdate.py`), the second on every DHCP
poll (`ipam_dhcp.py`). Same missing directory, two symptoms; anyone who hits
one will search for the other. The stale `TEMP` also survives an update,
since the re-exec inherits the environment it was launched with.

`tempfile.gettempdir()` alone does not save us: it caches its answer in
`tempfile.tempdir` the first time it runs, so a folder that vanishes after
that first call is handed back unchanged for the life of the process. This
resolver caches nothing — the right answer changes while the process runs —
proves writability rather than assuming it, and, the whole fix for the
reported case, re-creates a system temp folder that has simply been deleted.
"""

from __future__ import annotations

import os
import tempfile

# netpath/temppath.py: this file's directory is the package, its parent is the
# install root. Computed here rather than imported from selfupdate so this
# module stays a leaf that pulls in nothing else of ours.
_APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _usable(path: str) -> bool:
    """Whether this process can actually create a file in `path`. A directory
    that exists but denies writes is a real case on a locked-down host, so
    existence is never enough — we write a probe file and remove it, and only
    the write proves the point."""
    try:
        fd, probe = tempfile.mkstemp(prefix=".sappiwhere-writetest-", dir=path)
    except OSError:
        return False
    os.close(fd)
    try:
        os.unlink(probe)
    except OSError:
        pass  # the write already proved it; a failed cleanup is not a rejection
    return True


def writable_tempdir() -> str:
    """A directory that exists and is writable *right now*, to hand to
    `tempfile.mkstemp`/`mkdtemp` as their `dir=`. Never cached: call it each
    time a temp file is about to be made, because the answer can go stale
    mid-process (a per-session folder deleted under a running service).

    Tries, in order:

      1. the system temp directory, re-created if it is missing — a vanished
         per-session folder is exactly the reported fault, and `os.makedirs`
         is often the whole remedy;
      2. on Windows, `%LOCALAPPDATA%\\Temp` then `%SystemRoot%\\Temp` — both
         belong to the machine, not a logon session, so neither disappears
         when a Remote Desktop session ends;
      3. the application root, as a last resort — it had to be writable for
         the install to exist at all, so it adds no requirement that was not
         already met.

    Raises `RuntimeError` naming every location tried and why each was
    refused, in one operator-readable sentence, when none can be used — so a
    caller can report the cause instead of letting a bare `FileNotFoundError`
    escape as something generic.
    """
    tried: list[str] = []

    def consider(label: str, path: str) -> str | None:
        if not path:
            return None
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            tried.append(f"{label} ({path}): {exc}")
            return None
        if _usable(path):
            return path
        tried.append(f"{label} ({path}): exists but is not writable")
        return None

    # tempfile.gettempdir() itself raises FileNotFoundError if every one of
    # its own candidates is unusable; that is a location tried and refused,
    # not a reason to abort the whole search.
    try:
        sys_temp = tempfile.gettempdir()
    except OSError as exc:
        sys_temp = ""
        tried.append(f"the system temp folder: {exc}")
    chosen = consider("the system temp folder", sys_temp)
    if chosen:
        return chosen

    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        chosen = consider("%LOCALAPPDATA%\\Temp",
                          os.path.join(local, "Temp") if local else "")
        if chosen:
            return chosen
        systemroot = os.environ.get("SystemRoot")
        chosen = consider("%SystemRoot%\\Temp",
                          os.path.join(systemroot, "Temp") if systemroot else "")
        if chosen:
            return chosen

    chosen = consider("the install directory", _APP_ROOT)
    if chosen:
        return chosen

    raise RuntimeError(
        "No writable temporary directory could be found. Tried "
        + "; ".join(tried) + ". The usual cause on Windows is a per-session "
        "temp folder that no longer exists: a service that inherited its TEMP "
        "from a Remote Desktop (Terminal Services) session is pointed at "
        "\\AppData\\Local\\Temp\\<sessionId>, which Windows deletes when that "
        "session ends. Set TEMP and TMP for the service account to a directory "
        "that persists, free up disk space, or grant write permission to one "
        "of the locations above, then try again.")

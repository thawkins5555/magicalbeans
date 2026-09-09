"""netpath.temppath: the shared resolver that finds a temp directory which
actually exists and can be written to, right now (5.7.1).

The fault it answers hit two call sites on real Windows installs — the Update
button and every DHCP poll — because both trusted a `%TEMP%` that named a
per-session folder Windows had already deleted with the session that owned it.
This suite drives the resolver directly: a working system temp, a system temp
that has vanished (and is re-created), a directory that exists but cannot be
written to, every candidate failing at once, and the promise that it caches
nothing between calls.

Plain script, stdlib only, no pytest: a check() helper, non-zero exit on any
failure.
"""
import os
import shutil
import sys
import tempfile

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("temppath_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


from netpath import temppath            # noqa: E402

_real_tempdir = tempfile.tempdir
_real_app_root = temppath._APP_ROOT


def can_really_write(path):
    """Whether a file can actually be created in `path` — the ground truth
    _usable() has to agree with, whether or not this test runs as root."""
    try:
        fd, probe = tempfile.mkstemp(dir=path)
    except OSError:
        return False
    os.close(fd)
    os.unlink(probe)
    return True


try:
    # =================================================================
    # 1. The leaf-module promise: it imports nothing else of ours, so
    #    any module (selfupdate, the DHCP poller) can lean on it.
    # =================================================================
    src = open(os.path.join(_paths.REPO_ROOT, "netpath", "temppath.py"),
               encoding="utf-8").read()
    check("1. temppath imports nothing else from the package",
          "from ." not in src and "import netpath" not in src, "")

    # =================================================================
    # 2. A working system temp is returned, and it is real and writable
    # =================================================================
    good = os.path.join(TMPDIR, "sys")
    os.makedirs(good, exist_ok=True)
    tempfile.tempdir = good
    got = temppath.writable_tempdir()
    check("2. returns the system temp directory when it works",
          os.path.realpath(got) == os.path.realpath(good), f"{got!r}")
    check("2. …and the directory it returns exists and is writable",
          os.path.isdir(got) and can_really_write(got), f"{got!r}")

    # =================================================================
    # 3. The reported fault: the system temp folder has vanished. It is
    #    re-created rather than reported — makedirs is the whole fix.
    # =================================================================
    gone = os.path.join(TMPDIR, "vanished", "session-2", "Temp")
    check("3. the vanished folder really is absent to begin with",
          not os.path.exists(gone), gone)
    tempfile.tempdir = gone
    got = temppath.writable_tempdir()
    check("3. a missing system temp folder is re-created and returned, "
          "not raised over",
          os.path.realpath(got) == os.path.realpath(gone)
          and os.path.isdir(got), f"{got!r}")

    # =================================================================
    # 4. Writability is proven, not assumed. _usable's verdict must match
    #    an actual write attempt — the assertion holds whether or not this
    #    process is root (root bypasses the mode bits, and so must _usable,
    #    because it writes rather than reading os.access).
    # =================================================================
    check("4. _usable() says yes to a plainly writable directory",
          temppath._usable(good) is True, "")
    check("4. _usable() says no to a directory that does not exist",
          temppath._usable(os.path.join(TMPDIR, "nope")) is False, "")
    readonly = os.path.join(TMPDIR, "readonly")
    os.makedirs(readonly, exist_ok=True)
    os.chmod(readonly, 0o500)
    try:
        check("4. _usable()'s verdict matches a real write attempt on a "
              "read-only directory",
              temppath._usable(readonly) == can_really_write(readonly),
              "")
    finally:
        os.chmod(readonly, 0o700)   # so the tree can be cleaned up

    # =================================================================
    # 5. When the system temp cannot be used, it falls through to the
    #    install directory rather than giving up.
    # =================================================================
    # A regular file where a directory is expected: makedirs(exist_ok=True)
    # raises against it, so the system temp candidate is refused.
    blocker = os.path.join(TMPDIR, "blocker")
    with open(blocker, "w", encoding="utf-8") as _h:
        _h.write("not a directory\n")
    tempfile.tempdir = os.path.join(blocker, "sub")
    app_root = os.path.join(TMPDIR, "install-root")
    os.makedirs(app_root, exist_ok=True)
    temppath._APP_ROOT = app_root
    got = temppath.writable_tempdir()
    check("5. an unusable system temp falls through to the install directory",
          os.path.realpath(got) == os.path.realpath(app_root), f"{got!r}")

    # =================================================================
    # 6. Every candidate failing raises a RuntimeError that names the
    #    locations tried AND explains the per-session cause — no bare
    #    FileNotFoundError escaping to a caller.
    # =================================================================
    tempfile.tempdir = os.path.join(blocker, "sub")
    temppath._APP_ROOT = os.path.join(blocker, "root")   # also uncreatable
    raised = None
    try:
        temppath.writable_tempdir()
    except RuntimeError as exc:
        raised = str(exc)
    except BaseException as exc:      # noqa: BLE001 — this is the bug we forbid
        raised = f"WRONG EXCEPTION TYPE: {type(exc).__name__}: {exc}"
    check("6. total failure raises RuntimeError, not a bare OSError",
          raised is not None and "WRONG EXCEPTION" not in raised, str(raised))
    check("6. …and its message names the system temp folder it could not use",
          raised is not None and os.path.join(blocker, "sub") in raised,
          str(raised))
    check("6. …and the install directory it could not use",
          raised is not None and os.path.join(blocker, "root") in raised,
          str(raised))
    check("6. …and explains the per-session temp folder, the part nobody "
          "guesses",
          raised is not None and "per-session" in raised
          and "Remote Desktop" in raised, str(raised))
    check("6. …and offers a remedy an operator can act on (TEMP / disk / "
          "permission)",
          raised is not None and "TEMP" in raised, str(raised))

    # =================================================================
    # 7. It caches nothing: the answer can change while the process runs,
    #    which is the whole reason gettempdir()'s own cache is not enough.
    # =================================================================
    temppath._APP_ROOT = _real_app_root
    first = os.path.join(TMPDIR, "first")
    second = os.path.join(TMPDIR, "second")
    os.makedirs(first, exist_ok=True)
    os.makedirs(second, exist_ok=True)
    tempfile.tempdir = first
    a = temppath.writable_tempdir()
    tempfile.tempdir = second
    b = temppath.writable_tempdir()
    check("7. a second call reflects a temp directory that changed under it",
          os.path.realpath(a) == os.path.realpath(first)
          and os.path.realpath(b) == os.path.realpath(second),
          f"{a!r} then {b!r}")
finally:
    tempfile.tempdir = _real_tempdir
    temppath._APP_ROOT = _real_app_root
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

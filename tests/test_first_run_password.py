"""5.48.0: a fresh install seeds `admin` with a random password instead of
admin/admin, prints it once (console + event log), and only an explicit
--initial-admin-password overrides the value — and only while no accounts
exist yet. This pins: admin/admin is refused on a fresh store; the printed
password actually signs in and owes a password change; the banner is not
repeated on a second start against the same database; the explicit override
is honoured on a fresh store and ignored once one already has users; and the
plaintext never lands in the database file or in any event-log line but the
one banner.
"""
import contextlib
import io
import os
import re
import shutil
import sys

import _paths  # noqa: F401
from netpath.auth import (DEFAULT_USER, _INITIAL_PASSWORD_ALPHABET,
                          check_password_quality, verify_password)
from netpath.eventlog import SYSTEM
from netpath.web import Service

TMPDIR = _paths.tmpdir("first_run_pw_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def db_paths(folder):
    names = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
             "nodes", "alerts", "wireless", "configrx")
    return [os.path.join(folder, f"{name}.db") for name in names]


def raw_file_text(folder, stem="app"):
    """Every byte of stem.db and its WAL/SHM siblings, decoded loosely --
    plaintext-in-storage is a binary-string question, not a valid-UTF-8 one."""
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        path = os.path.join(folder, f"{stem}.db{suffix}")
        if os.path.exists(path):
            with open(path, "rb") as handle:
                blob += handle.read()
    return blob.decode("latin-1")


def banner_events(service, password):
    return [e for e in service.log.all()
           if e.category == SYSTEM and password in e.message]


# --------------------------------------------------------- 1. no admin/admin
folder1 = os.path.join(TMPDIR, "fresh1")
os.makedirs(folder1, exist_ok=True)
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    service1 = Service(*db_paths(folder1))
printed = captured.getvalue()

try:
    row = service1.app_db.user(DEFAULT_USER)
    check("a fresh store seeds exactly one admin account", row is not None)
    check("admin/admin is refused on a fresh store",
          not verify_password("admin", row["password"]))
    check("must_change is set on the seeded account",
          bool(row["must_change"]))

    # ------------------------------------------------- 2. the banner, once
    check("the banner was printed to stdout on the seeding start",
          "Initial administrator account created" in printed, printed)
    m = re.search(r"Password: (\S+)", printed)
    check("the banner names a password", m is not None, printed)
    generated = m.group(1) if m else ""
    check("the printed password actually verifies against the stored hash",
          bool(generated) and verify_password(generated, row["password"]))
    groups = generated.split("-")
    check("the generated password is 4 dash-joined 5-char groups from the "
          "unambiguous alphabet (no 0/O/1/l/I)",
          len(groups) == 4 and all(len(g) == 5 for g in groups)
          and all(c in _INITIAL_PASSWORD_ALPHABET for g in groups for c in g)
          and not (set("01IlO") & set(generated)),
          generated)
    try:
        check_password_quality(generated)
        check("the generated password clears check_password_quality", True)
    except Exception as exc:                                # noqa: BLE001
        check("the generated password clears check_password_quality", False, str(exc))

    events = banner_events(service1, generated)
    check("the event log carries the password exactly once",
          len(events) == 1, len(events))

    # ------------------------------------------ 3. plaintext stored nowhere else
    blob = raw_file_text(folder1, "app")
    check("the generated password is not sitting in app.db (or its WAL)",
          bool(generated) and generated not in blob)

    # A later log write must not repeat it either.
    service1.log.add(SYSTEM, "unrelated later event, for the count below")
    check("no later log line repeats the password",
          len(banner_events(service1, generated)) == 1)

    # ------------------------------------- 3b. take_initial_admin_notice()
    notice = service1.take_initial_admin_notice()
    check("the notice is returned on the first call after a fresh install",
          notice is not None and DEFAULT_USER in notice and generated in notice,
          notice)
    check("...and is None on every call after that",
          service1.take_initial_admin_notice() is None)
finally:
    service1.shutdown()

# --------------------------------------------- 4. no banner on a second start
captured2 = io.StringIO()
with contextlib.redirect_stdout(captured2):
    service2 = Service(*db_paths(folder1))
try:
    check("a second start against the same database prints no banner",
          "Initial administrator account created" not in captured2.getvalue(),
          captured2.getvalue())
    row2 = service2.app_db.user(DEFAULT_USER)
    check("...and the password is unchanged",
          verify_password(generated, row2["password"]))
    check("...and the notice is None on a start that owed no seeding",
          service2.take_initial_admin_notice() is None)
finally:
    service2.shutdown()

# --------------------------------------- 5. explicit password, fresh store only
folder2 = os.path.join(TMPDIR, "fresh2")
os.makedirs(folder2, exist_ok=True)
EXPLICIT = "Correct-Horse-Battery-Staple-1"
captured3 = io.StringIO()
with contextlib.redirect_stdout(captured3):
    service3 = Service(*db_paths(folder2), initial_admin_password=EXPLICIT)
try:
    row3 = service3.app_db.user(DEFAULT_USER)
    check("an explicit initial password is stored instead of a random one",
          verify_password(EXPLICIT, row3["password"]))
    check("must_change is still set for an explicit initial password too",
          bool(row3["must_change"]))
    check("the banner still names the explicit password, once",
          captured3.getvalue().count(EXPLICIT) >= 1
          and len(banner_events(service3, EXPLICIT)) == 1)
finally:
    service3.shutdown()

# An existing database with a user already: the override must be ignored.
captured4 = io.StringIO()
with contextlib.redirect_stdout(captured4):
    service4 = Service(*db_paths(folder2), initial_admin_password="Some-Other-Password-2")
try:
    check("an explicit password is ignored once the store already has a user",
          verify_password(EXPLICIT, service4.app_db.user(DEFAULT_USER)["password"]))
    check("...and no banner is printed for that no-op",
          "Initial administrator account created" not in captured4.getvalue())
finally:
    service4.shutdown()

print()
print("FAILURES:", FAILS if FAILS else "none")
shutil.rmtree(TMPDIR, ignore_errors=True)
sys.exit(1 if FAILS else 0)

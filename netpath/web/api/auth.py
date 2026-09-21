"""Handlers: sign-in, API tokens, LDAP and TACACS+."""

from __future__ import annotations

import hashlib
import sqlite3
import secrets
import threading
import time

from ...eventlog import ERROR as ERROR_CATEGORY, SYSTEM as SYSTEM_CATEGORY
from ... import appdb as _appdb
from ... import permissions as _permissions

from ._shared import ALERT_TOTAL_CAP, THEMES, _alert_filters, _audit, request_permissions

# ------------------------------------------------------------- account SMS

# A code is good for this long after it is sent...
SMS_CODE_TTL_S = 600
# ...and a fresh one cannot be requested more often than this, so a typo'd
# number cannot be used to spam an arbitrary phone with texts.
SMS_CODE_RESEND_S = 60
# Past this many wrong guesses the code is dead; request a new one.
SMS_CODE_MAX_ATTEMPTS = 5


# --------------------------------------------------------------------- auth

def _client(params) -> str:
    return params.get("_client", "")


class Busy(Exception):
    """"Come back in a moment" — server.py answers 503 with a `Retry-After`."""

    retry_after = 2


# At most this many password verifications at once. Each is a scrypt at
# N=2^17 — about 128 MiB and half a second — on an endpoint that needs no
# session, so unbounded concurrency is a memory exhaustion (30 parallel
# attempts is ~4 GB) on a threaded server. It bounds the HASHING only: the
# throttle delay is slept before the slot is taken, so a throttled caller
# never holds one of the four while it waits.
_LOGIN_SLOTS = threading.Semaphore(4)

# A caller that waits longer than this gets a 503 with a Retry-After.
_LOGIN_SLOT_WAIT_S = 5.0

_dummy_hash_value: str | None = None
_dummy_hash_lock = threading.Lock()


def _dummy_hash() -> str:
    """A real hash of a random string, built with the parameters in force
    now.

    The point of hashing when the account does not exist is that the time
    taken says nothing about whether it does — a fixed hash at cheaper
    parameters than the stored ones would answer faster and make this
    endpoint a username oracle. Derived from hash_password so it cannot
    drift from the real cost, including onto the PBKDF2 fallback where
    scrypt is unavailable.
    """
    global _dummy_hash_value
    with _dummy_hash_lock:
        if _dummy_hash_value is None:
            from ...auth import hash_password
            _dummy_hash_value = hash_password(secrets.token_urlsafe(32))
        return _dummy_hash_value


def _login_check_lockout(service, client, params, label) -> None:
    """Raise LockedOut if this address is still locked out.

    Checked before the semaphore and before any hashing: a locked-out
    caller must not be able to hold a verification slot or spend a
    half-second of scrypt.
    """
    from ...auth import LockedOut

    remaining = service.throttle.lockout_remaining(client)
    if remaining > 0:
        # Logged and audited once per lock episode, not once per request.
        if service.throttle.announce_lockout(client):
            service.log.add(ERROR_CATEGORY,
                            f"Refused sign-in for {label} from {client}: too many "
                            f"failures, locked for another {remaining / 60:.0f} min")
            _audit(service, dict(params, _username=label), "signin.locked_out",
                   target=label, detail=f"locked for another {remaining:.0f}s")
        raise LockedOut(f"Too many failed sign-ins. Try again in "
                        f"{max(1, round(remaining / 60))} minute(s).")


def _login_apply_delay(service, username, client) -> None:
    """Sleep for the throttle's back-off delay.

    Slept OUTSIDE the semaphore: a throttled caller waiting inside one of
    the four verification slots holds it for the whole delay, so a handful
    of already-throttled attempts would queue every legitimate sign-in
    behind them. Truncated at 5 s either way — the throttle's own ceiling
    is 30 s, but a request thread held that long is its own denial.
    """
    delay = service.throttle.delay_for(username, client)
    if delay:
        time.sleep(min(delay, 5))


def _login_acquire_slot(service, client, label) -> None:
    """Take a password-verification slot, or raise Busy if none is free."""
    if not _LOGIN_SLOTS.acquire(timeout=_LOGIN_SLOT_WAIT_S):
        service.log.add(ERROR_CATEGORY,
                        f"Refused sign-in for {label} from {client}: every "
                        f"password-verification slot busy for "
                        f"{_LOGIN_SLOT_WAIT_S:.0f}s")
        raise Busy("The server is busy verifying sign-ins. Try again in a moment.")


def post_login(service, params, body) -> dict:
    """Verify a password. Deliberately slow to fail, and vague about why."""
    from ...auth import (AuthError, check_username, needs_rehash,
                        hash_password, verify_password)
    from ..service import LdapUnavailable, TacacsUnavailable

    password = str(body.get("password", ""))
    client = _client(params)

    # Validated before it is used as a throttle key or written anywhere: a
    # 200 KB username would otherwise produce a 200 KB event, a cheap way to
    # push everything else out of the 3,000-entry ring. Every name that is
    # not a username shares one key and one log line, so trying millions of
    # them costs one entry.
    try:
        username = check_username(str(body.get("username", "")))
    except AuthError:
        username = ""
    label = username or "(not a username)"

    _login_check_lockout(service, client, params, label)
    _login_apply_delay(service, username, client)
    _login_acquire_slot(service, client, label)
    # Whether the credential was already verified below (the auto-create
    # branch), so the auth_source=="tacacs" branch further down does not
    # spend a second AAA round trip re-checking what it just checked.
    already_authed = False

    try:
        row = service.app_db.user(username) if username else None
        stored = row["password"] if row else None

        if (row is None and username
                and service.settings.get("tacacs_enabled")
                and service.settings.get("tacacs_auto_create")):
            # No dummy hash here -- the AAA round trip already dominates
            # the timing a dummy hash exists to flatten.
            role = str(service.settings.get("tacacs_default_role", "viewer"))
            try:
                if role not in _permissions.AUTO_CREATE_ROLES:
                    # Saving it is refused, but a value stored before 5.51.0
                    # is still in the settings row until someone re-saves.
                    raise ValueError(
                        "auto-create may grant only "
                        + " or ".join(_permissions.AUTO_CREATE_ROLES))
                grants = _permissions.role_grants(role)
            except ValueError as exc:
                service.log.add(
                    ERROR_CATEGORY,
                    f"Refused auto-create for {label}: tacacs_default_role "
                    f"{role!r} cannot be granted -- {exc}")
                raise PermissionError(
                    "Sign-in is misconfigured. Contact an administrator."
                ) from exc
            try:
                accepted = service.authenticate_tacacs(username, password, client)
            except TacacsUnavailable as exc:
                service.throttle.record_failure(username, client)
                service.log.add(
                    ERROR_CATEGORY,
                    f"TACACS+ AAA server unreachable while signing in "
                    f"{label} from {client}: {exc}")
                _audit(service, dict(params, _username=label),
                       "signin.tacacs_unreachable", target=label,
                       detail=str(exc)[:200])
                raise PermissionError(
                    "Could not reach the AAA server. Try again shortly, or "
                    "contact an administrator.") from exc
            if not accepted:
                service.throttle.record_failure(username, client)
                service.log.add(ERROR_CATEGORY,
                                f"Failed sign-in for {label} from {client}")
                _audit(service, dict(params, _username=label), "signin.failed",
                       target=label, detail="tacacs rejected")
                raise PermissionError("Wrong username or password")
            try:
                service.app_db.add_user(username, "", must_change=False,
                                        auth_source="tacacs")
            except sqlite3.IntegrityError:
                # Two PASSes for the same new username raced; the loser
                # just re-reads the row the winner created.
                pass
            service.app_db.set_permissions(username, grants)
            service.log.add(
                SYSTEM_CATEGORY,
                f"Auto-created TACACS+ account {username} (role {role})")
            _audit(service, dict(params, _username=username), "user.autocreate",
                   target=username, detail=f"tacacs, role {role}")
            row = service.app_db.user(username)
            stored = row["password"]
            already_authed = True

        # Hash something even when the account does not exist, so the time
        # taken cannot be used to discover which usernames are real. Only
        # "no such account" versus "an account exists" — it says nothing
        # about whether that account is local, LDAP or TACACS+.
        if stored is None:
            verify_password(password, _dummy_hash())
            service.throttle.record_failure(username, client)
            service.log.add(ERROR_CATEGORY,
                            f"Failed sign-in for {label} from {client}")
            _audit(service, dict(params, _username=label), "signin.failed",
                   target=label, detail="no such account")
            raise PermissionError("Wrong username or password")

        auth_source = row["auth_source"]

        if auth_source == "tacacs" and not already_authed:
            # tacacs-mapped: the AAA server verifies, never the empty local hash.
            if not service.settings.get("tacacs_enabled"):
                service.throttle.record_failure(username, client)
                service.log.add(
                    ERROR_CATEGORY,
                    f"Failed sign-in for {row['username']} from {client}: "
                    f"TACACS+ sign-in is switched off")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="tacacs disabled")
                raise PermissionError("Wrong username or password")
            try:
                bound = service.authenticate_tacacs(row["username"], password, client)
            except TacacsUnavailable as exc:
                service.log.add(
                    ERROR_CATEGORY,
                    f"TACACS+ AAA server unreachable while signing in "
                    f"{row['username']} from {client}: {exc}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.tacacs_unreachable", target=row["username"],
                       detail=str(exc)[:200])
                raise PermissionError(
                    "Could not reach the AAA server. Try again shortly, or "
                    "contact an administrator.") from exc
            if not bound:
                service.throttle.record_failure(username, client)
                service.log.add(ERROR_CATEGORY,
                                f"Failed sign-in for {row['username']} from {client}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="tacacs rejected")
                raise PermissionError("Wrong username or password")
        elif auth_source == "ldap":
            # An LDAP-mapped account: the directory verifies the password,
            # not the empty, never-consulted local hash. With the feature
            # switched off this account simply cannot sign in — it never
            # falls back to an empty local hash (verify_password refuses that
            # anyway), and failing here first gives a clearer audit trail
            # than "wrong password".
            if not service.settings.get("ldap_enabled"):
                service.throttle.record_failure(username, client)
                service.log.add(
                    ERROR_CATEGORY,
                    f"Failed sign-in for {row['username']} from {client}: "
                    f"directory sign-in is switched off")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="ldap disabled")
                raise PermissionError("Wrong username or password")
            try:
                bound = service.authenticate_ldap(row["username"], password)
            except LdapUnavailable as exc:
                # Fails closed, and says so honestly rather than as a 500:
                # this is the one login outcome that is not about the
                # credential at all, so it gets its own message and its own
                # audit action rather than being folded into signin.failed.
                service.log.add(
                    ERROR_CATEGORY,
                    f"LDAP directory unreachable while signing in "
                    f"{row['username']} from {client}: {exc}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.ldap_unreachable", target=row["username"],
                       detail=str(exc)[:200])
                raise PermissionError(
                    "Could not reach the directory service. Try again "
                    "shortly, or contact an administrator.") from exc
            if not bound:
                service.throttle.record_failure(username, client)
                service.log.add(ERROR_CATEGORY,
                                f"Failed sign-in for {row['username']} from {client}")
                _audit(service, dict(params, _username=row["username"]),
                       "signin.failed", target=row["username"],
                       detail="ldap bind refused")
                raise PermissionError("Wrong username or password")
        elif not already_authed and not verify_password(password, stored):
            service.throttle.record_failure(username, client)
            service.log.add(ERROR_CATEGORY,
                            f"Failed sign-in for {row['username']} from {client}")
            _audit(service, dict(params, _username=row["username"]),
                   "signin.failed", target=row["username"],
                   detail="wrong password")
            raise PermissionError("Wrong username or password")
    finally:
        _LOGIN_SLOTS.release()

    service.throttle.clear(username)
    service.app_db.touch_login(row["username"])

    # Upgrade the stored hash quietly, now that we hold the password. Local
    # accounts only: an LDAP account's stored hash is the empty string it was
    # created with, and needs_rehash("") says True (an unrecognised scheme
    # "needs" upgrading), so without the guard this would hash the directory
    # password into a local hash nothing ever checks.
    if auth_source == "local" and needs_rehash(stored):
        service.app_db.set_password(row["username"], hash_password(password),
                                must_change=bool(row["must_change"]))

    # The real User-Agent header, not a body field: the session list claims
    # to show what signed in, so a caller-supplied "_agent" would let it show
    # anything, markup included.
    token = service.sessions.create(row["username"], client,
                                    str(params.get("_agent", "")))
    service.log.add(SYSTEM_CATEGORY, f"{row['username']} signed in from {client}")
    _audit(service, dict(params, _username=row["username"]), "signin.ok",
           target=row["username"], detail=str(params.get("_agent", ""))[:120])
    return {"token": token, "username": row["username"],
            "must_change": bool(row["must_change"])}


def post_logout(service, params, body) -> dict:
    token = params.get("_token", "")
    session = service.sessions.get(token)
    if session:
        service.log.add(SYSTEM_CATEGORY, f"{session['username']} signed out")
        _audit(service, dict(params, _username=session["username"]),
               "signout", target=session["username"])
    service.sessions.destroy(token)
    return {"ok": True}


def post_heartbeat(service, params, body) -> dict:
    """Confirms a person is present, or — in kiosk mode — that a wall
    display is allowed to stay signed in without one.

    server.py touches the session for every other POST before dispatch; this
    route is the one exception, so that the kiosk case can be REFUSED without
    extending anything. The rule: a heartbeat carrying ``{"kiosk": true}``
    is honoured only for an account with no write grant on any module. A
    read-only wall account stays signed in until the absolute ceiling
    (session_max_hours); an administrator who adds ?kiosk=1 keeps the idle
    sign-out, and the reply says so in words the kiosk bar shows. Enforced
    here rather than in the browser because the idle policy is a security
    control, and a client-side exception to a security control is not one.
    """
    kiosk = bool(isinstance(body, dict) and body.get("kiosk"))
    minutes = service.sessions.idle_seconds // 60
    if kiosk:
        granted = request_permissions(service, params)
        if any(_permissions.allows(level, _permissions.WRITE) for level in granted.values()):
            return {"ok": False, "kiosk": False, "idle_timeout_minutes": minutes,
                    "reason": "Kiosk mode keeps only a read-only account signed in; "
                              "this account can write, so the idle sign-out applies."}
    service.sessions.touch(params.get("_token", ""))
    return {"ok": True, "kiosk": kiosk, "idle_timeout_minutes": minutes}


def _first_run(service) -> bool:
    """Whether this is a fresh install nobody has signed in to yet.

    The seeded admin account exists, is the only account, still owes its
    password change and has never signed in. The sign-in page says so,
    because a first-run administrator otherwise faces a blank form with no
    hint that a default account exists at all. It is deliberately not a
    password check — that would be a full scrypt on every unauthenticated
    request — and it goes false the moment anyone signs in."""
    from ...auth import DEFAULT_USER
    if service.app_db.user_count() != 1:
        return False
    row = service.app_db.user(DEFAULT_USER)
    return bool(row is not None and row["must_change"] and row["last_login"] is None)


def get_session(service, params, body) -> dict:
    # The version goes to the sign-in page as well as to a signed-in one:
    # it is the first thing asked for when someone reports a problem. Not a
    # secret — every asset the version is stamped on is already served
    # before any session exists.
    from ... import __version__
    session = service.sessions.get(params.get("_token", ""))
    if not session:
        return {"authenticated": False, "first_run": _first_run(service),
                "version": __version__}
    row = service.app_db.user(session["username"])
    idle_remaining = service.sessions.idle_seconds - (time.time() - session["last_seen"])
    return {
        "authenticated": True,
        "username": session["username"],
        "version": __version__,
        "must_change": bool(row["must_change"]) if row else False,
        "idle_timeout_minutes": service.sessions.idle_seconds // 60,
        "idle_seconds_remaining": max(0, round(idle_remaining)),
        "theme": (row["theme"] or "") if row and row["theme"] in THEMES else "",
    }


def get_users(service, params, body) -> dict:
    return {
        "users": [
            {"username": row["username"], "created": row["created_ts"],
             "updated": row["updated_ts"], "last_login": row["last_login"],
             "must_change": bool(row["must_change"]),
             "auth_source": row["auth_source"],
             "permissions": service.app_db.permissions_for(row["username"])}
            for row in service.app_db.users()
        ],
        "sessions": service.sessions.active(),
        "modules": list(_permissions.MODULES),
    }


def post_user(service, params, body) -> dict:
    from ...auth import AuthError, check_password_quality, check_username, hash_password

    try:
        username = check_username(str(body.get("username", "")))
    except AuthError as exc:
        raise ValueError(str(exc)) from exc

    auth_source = str(body.get("auth_source", "local") or "local").strip().lower()
    if auth_source not in ("local", "ldap", "tacacs"):
        raise ValueError("auth_source must be 'local', 'ldap' or 'tacacs'")

    if service.app_db.user(username):
        raise ValueError(f"There is already an account called {username}")

    if auth_source in ("ldap", "tacacs"):
        # No local password hash at all — the directory or AAA server is
        # the only place this account's credential lives, so a database
        # compromise finds nothing here for it. must_change is meaningless
        # without a local password to change, so it starts False rather
        # than locking the account behind a change it has no route to make.
        service.app_db.add_user(username, "", must_change=False, auth_source=auth_source)
    else:
        password = str(body.get("password", ""))
        try:
            check_password_quality(password, username)
        except AuthError as exc:
            raise ValueError(str(exc)) from exc
        service.app_db.add_user(username, hash_password(password), must_change=True,
                                auth_source="local")

    grants = body.get("grants") or {}
    if grants:
        service.app_db.set_permissions(username, grants)
    service.bump_config()
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {username} ({auth_source}) created by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "user.create", target=username,
           detail=f"auth_source={auth_source}; " +
                  (", ".join(f"{m}:{lvl}" for m, lvl in sorted(grants.items()))
                   or "no grants"))
    return {"username": username, "auth_source": auth_source}


def _last_admin_guard(service, target: str, keeps_admin: bool) -> None:
    """Refuse a change that would leave the install with no LOCAL
    administrator.

    Deleting the last *account* was already refused; losing the last
    administrator is the same trap by a different route — an install with
    no admin has no way back into its own user management short of editing
    app.db by hand. LDAP accounts do not count: an administrator that
    exists only in the directory is no fallback at all
    if the directory is down or unreachable, so at least one *local*
    admin:write account must always remain — an ldap admin does not count
    toward keeping this guard satisfied, only toward the plain "some admin
    exists" check `usernames_with` would otherwise imply.
    """
    if keeps_admin:
        return
    admins = service.app_db.usernames_with("admin", _permissions.WRITE)

    def is_local(name: str) -> bool:
        row = service.app_db.user(name)
        return row is not None and row["auth_source"] == "local"

    others_local = [name for name in admins
                    if name.lower() != target.lower() and is_local(name)]
    if others_local:
        return
    if any(name.lower() == target.lower() for name in admins):
        raise ValueError(
            f"Removing administrator access from {target} would leave no "
            f"local administrator account — if the directory becomes "
            f"unreachable there would be no way back into user management "
            f"at all. Give another local account administrator access "
            f"first.")


def post_user_permissions(service, params, body) -> dict:
    username = str(body.get("username", "")).strip()
    if not username:
        raise ValueError("Which account?")
    if not service.app_db.user(username):
        raise ValueError(f"No account called {username}")
    me = params.get("_username", "")
    # Nobody edits their own grants. An administrator who wants a different
    # set asks another administrator for it, which makes the grid a record
    # of a decision rather than a self-service action — and closes the
    # "grant yourself every module" escalation.
    if username.lower() == me.lower():
        raise ValueError(
            "You cannot change your own permissions. Ask another "
            "administrator to make the change.")
    grants = body.get("grants") or {}
    _last_admin_guard(service, username,
                      grants.get("admin") == _permissions.WRITE)
    service.app_db.set_permissions(username, grants)
    service.bump_config()
    service.log.add(SYSTEM_CATEGORY,
                    f"Permissions for {username} changed by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "user.permissions", target=username,
           detail=", ".join(f"{m}:{lvl}" for m, lvl in sorted(grants.items()))
                  or "no grants")
    return {"username": username, "permissions": service.app_db.permissions_for(username)}


def delete_user(service, params, body, username: str = "") -> dict:
    # The client sends it in the body; the query string is a convenience for
    # anyone driving the API by hand.
    target = str(body.get("username", "") or params.get("username", "")
                 or username).strip()
    me = params.get("_username", "")
    if not target:
        raise ValueError("Which account?")

    if target.lower() == me.lower():
        raise ValueError("You cannot delete the account you are signed in with")
    if not service.app_db.user(target):
        raise ValueError(f"No account called {target}")
    if service.app_db.user_count() <= 1:
        raise ValueError("That is the only account; there would be no way back in")
    _last_admin_guard(service, target, keeps_admin=False)

    service.app_db.remove_user(target)

    service.bump_config()
    ended = service.sessions.destroy_user(target)
    service.log.add(SYSTEM_CATEGORY,
                    f"Account {target} removed by {me}; {ended} session(s) ended")
    _audit(service, params, "user.delete", target=target,
           detail=f"{ended} session(s) ended")
    return {"removed": target}


def post_password(service, params, body) -> dict:
    """Change a password: your own with the current one, or anyone's as a reset."""
    from ...auth import (AuthError, check_password_quality, hash_password,
                        verify_password)

    me = params.get("_username", "")
    client = _client(params)
    target = str(body.get("username", "") or me)
    new = str(body.get("new_password", ""))
    resetting = target.lower() != me.lower()

    row = service.app_db.user(target)
    if not row:
        raise ValueError(f"No account called {target}")

    if row["auth_source"] in ("ldap", "tacacs"):
        # post_login's ldap/tacacs branches never look at `row["password"]`,
        # so setting one here would sit unused while suggesting a local
        # fallback exists. The directory or AAA server is the only place
        # this account's password is ever changed.
        source = "the directory (LDAP)" if row["auth_source"] == "ldap" else "TACACS+"
        raise ValueError(
            f"{target} signs in through {source}; there is no local "
            f"password to change here.")

    if not resetting:
        # Same order post_login uses: refused outright if already locked,
        # else slowed, before a verification slot is ever taken.
        _login_check_lockout(service, client, params, me)
        _login_apply_delay(service, me, client)

    # Shares login's own slot semaphore: up to three scrypt calls below
    # must not let a signed-in account exhaust server memory either.
    if not _LOGIN_SLOTS.acquire(timeout=_LOGIN_SLOT_WAIT_S):
        service.log.add(ERROR_CATEGORY,
                        f"Refused password change for {target} by {me} from "
                        f"{client}: every password-verification slot busy "
                        f"for {_LOGIN_SLOT_WAIT_S:.0f}s")
        raise Busy("The server is busy verifying passwords. Try again in a moment.")
    try:
        if not resetting:
            # Changing your own password needs the current one, so a walk-up
            # at an unlocked screen cannot lock the real owner out.
            if not verify_password(str(body.get("current_password", "")),
                                   row["password"]):
                service.throttle.record_failure(me, client)
                raise PermissionError("That is not the current password")

        try:
            check_password_quality(new, target)
        except AuthError as exc:
            raise ValueError(str(exc)) from exc

        if verify_password(new, row["password"]):
            raise ValueError("That is already the password")

        service.app_db.set_password(target, hash_password(new), must_change=resetting)
    finally:
        _LOGIN_SLOTS.release()
    service.throttle.clear(me)
    ended = service.sessions.destroy_user(target)
    service.log.add(SYSTEM_CATEGORY,
                    f"Password for {target} changed by {me}; "
                    f"{ended} session(s) ended")
    _audit(service, params, "password.reset" if resetting else "password.change",
           target=target, detail=f"{ended} session(s) ended")
    return {"username": target, "sessions_ended": ended, "reset": resetting}


def put_account_theme(service, params, body) -> dict:
    """Save the caller's theme to their account so it follows them to any
    browser they sign into. Own account only, like post_password's
    self-service half."""
    me = params.get("_username", "")
    theme = str(body.get("theme", ""))
    if theme not in THEMES:
        raise ValueError(f"Unknown theme: {theme}")
    service.app_db.set_user_theme(me, theme)
    _audit(service, params, "account.theme", target=me, detail=f"theme: {theme}")
    return {"theme": theme}


def _sms_available(service) -> bool:
    """Whether Alerts is set up well enough to send a text at all — the
    same conditions _sms_notify checks before it will use the queue, plus
    a credential actually being on file."""
    settings = service.alerts_settings
    if not settings.get("sms_enabled"):
        return False
    if not settings.get("twilio_account_sid"):
        return False
    if not (settings.get("twilio_from") or settings.get("twilio_messaging_service_sid")):
        return False
    if not service.alerts_db.sms_token_enc():
        return False
    auth_mode = str(settings.get("twilio_auth_mode", "auth_token") or "auth_token").strip()
    if auth_mode == "api_key" and not settings.get("twilio_api_key_sid"):
        return False
    return True


def _sms_send(service, number, text, kind: str, record_text: str | None = None) -> None:
    """One text, sent with the stored Twilio credential the same way
    post_alerts_sms_test resolves it, and recorded to notifications either
    way. `record_text` overrides what is stored for the notification row
    (sms_verify masks its code); raises with the send error on failure."""
    from ... import alertmail, dpapi

    settings = dict(service.alerts_settings)
    logged_text = text if record_text is None else record_text
    blob = service.alerts_db.sms_token_enc()
    wanted = alertmail.sms_binding(settings)
    saved = service.alerts_db.sms_credential_binding()
    if blob and wanted != (saved["auth_mode"], saved["account_sid"], saved["api_key_sid"]):
        error = ("The stored Twilio credential does not match the Alerts "
                 "settings; ask an administrator to re-enter it")
        service.alerts_db.record_notification(None, kind, number, logged_text, False, error)
        raise ValueError(error)
    token = None
    if blob:
        try:
            token = dpapi.unprotect(blob).decode("utf-8")
        except Exception:
            token = None
    try:
        alertmail.send_sms(settings, token, number, text)
        ok, error = True, ""
    except Exception as exc:
        ok, error = False, str(exc)
    finally:
        token = None
    service.alerts_db.record_notification(None, kind, number, logged_text, ok, error)
    if not ok:
        raise ValueError(error)


def _account_sms(service, row) -> dict:
    return {
        "available": _sms_available(service),
        "status": _appdb.sms_status(row),
        "number": row["number"] if row else "",
        "consent_ts": row["consent_ts"] if row else 0.0,
        "verified_ts": row["verified_ts"] if row else 0.0,
        "stopped_ts": row["stopped_ts"] if row else 0.0,
        "stopped_by": row["stopped_by"] if row else "",
        "code_sent_ts": row["code_sent_ts"] if row else 0.0,
    }


def get_account_sms(service, params, body) -> dict:
    me = params.get("_username", "")
    return _account_sms(service, service.app_db.user_sms(me))


def post_account_sms_start(service, params, body) -> dict:
    """Begin (or restart) opting the caller's own account into alert texts:
    stores the number, sends a six-digit code, and leaves the row pending
    until post_account_sms_confirm verifies it."""
    from ... import alertmail

    me = params.get("_username", "")
    if body.get("consent") is not True:
        raise ValueError("Accept the terms to receive alert texts")
    number = str(body.get("number", "")).strip()
    if not alertmail.is_e164(number):
        raise ValueError("A mobile number in E.164 form (+15551234567) is required")
    if not _sms_available(service):
        raise ValueError("Alert texts are not set up on this server; an "
                         "administrator turns them on under Alerts → Settings")
    now = time.time()
    row = service.app_db.user_sms(me)
    if _appdb.sms_status(row) == "on":
        raise ValueError("Alert texts are already on for this account; press Stop texts first")
    if row is not None and now - row["code_sent_ts"] < SMS_CODE_RESEND_S:
        remaining = max(1, int(SMS_CODE_RESEND_S - (now - row["code_sent_ts"])) + 1)
        raise ValueError(f"Wait {remaining} s before requesting another code")
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    service.app_db.sms_start(me, number, code_hash, now)
    text = (f"SappiWhere: your alert text verification code is {code}. It "
           f"expires in 10 minutes. Reply STOP to opt out, HELP for help. "
           f"Msg & data rates may apply.")
    try:
        _sms_send(service, number, text, "sms_verify", record_text=text.replace(code, "******"))
    except Exception as exc:
        service.app_db.sms_clear_code(me)
        raise ValueError(str(exc)) from exc
    _audit(service, params, "account.sms.start", target=me, detail=f"code sent to {number}")
    return _account_sms(service, service.app_db.user_sms(me))


def post_account_sms_confirm(service, params, body) -> dict:
    """Confirm the code post_account_sms_start sent and turn texts on."""
    me = params.get("_username", "")
    row = service.app_db.user_sms(me)
    if _appdb.sms_status(row) != "pending":
        raise ValueError("No verification code is outstanding; request one first")
    now = time.time()
    if now - row["code_sent_ts"] > SMS_CODE_TTL_S:
        service.app_db.sms_clear_code(me)
        raise ValueError("That code has expired; request a new one")
    code = str(body.get("code", "")).strip()
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(code_hash, row["code_hash"]):
        attempts = service.app_db.sms_code_attempt(me)
        if attempts >= SMS_CODE_MAX_ATTEMPTS:
            service.app_db.sms_clear_code(me)
            raise ValueError("Too many wrong codes; request a new one")
        raise ValueError(f"Wrong code ({SMS_CODE_MAX_ATTEMPTS - attempts} tries left)")
    number = row["number"]
    service.app_db.sms_confirm(me, now)
    text = ("SappiWhere alerts: you are now opted in to network alert texts "
           "at this number. Msg frequency varies. Msg & data rates may "
           "apply. Reply STOP to opt out, HELP for help.")
    try:
        _sms_send(service, number, text, "sms_optin")
    except Exception as exc:
        service.log.add(ERROR_CATEGORY,
                        f"Alert text opt-in confirmation to {number} failed: {exc}")
    _audit(service, params, "account.sms.confirm", target=me, detail=f"texts on for {number}")
    return _account_sms(service, service.app_db.user_sms(me))


def delete_account_sms(service, params, body) -> dict:
    """Turn the caller's own alert texts off: stops a live number, or just
    forgets a pending code / a previously stopped number."""
    me = params.get("_username", "")
    row = service.app_db.user_sms(me)
    status = _appdb.sms_status(row)
    if status == "on":
        service.app_db.sms_stop(me, time.time(), "user")
        _audit(service, params, "account.sms.stop", target=me)
    elif row is not None:
        if time.time() - row["code_sent_ts"] < SMS_CODE_RESEND_S:
            # A resend guard is still running on this row's code_sent_ts;
            # forgetting it here would let start->delete->start bypass the
            # guard, so just drop the code and keep the row (and guard).
            service.app_db.sms_clear_code(me)
        else:
            service.app_db.sms_forget(me)
        _audit(service, params, "account.sms.cancel", target=me)
    return _account_sms(service, service.app_db.user_sms(me))


# ------------------------------------------------------------- API tokens
#
# A token belongs to an account and carries exactly that account's grants:
# there is no second permission model to keep in sync, and nothing about how
# a request is authorized changes once it is past authentication. All three
# routes are administrator-only rather than self-service — a token is a
# durable, unattended credential with no idle timeout, so handing one out is
# the same class of decision as creating an account or changing its grants,
# which nobody may do for themselves either.

def get_tokens(service, params, body) -> dict:
    """Metadata for every token — never the token itself, which existed
    only in the response that created it. `username` names the account
    whose grants the token authenticates with; a caller wanting "my
    account's tokens" filters this client-side, the same way the accounts
    grid itself is one list rather than one route per account."""
    return {
        "tokens": [
            {"id": row["id"], "username": row["username"], "label": row["label"],
             "created": row["created_ts"], "created_by": row["created_by"],
             "expires": row["expires_ts"], "last_used": row["last_used_ts"]}
            for row in service.app_db.api_tokens()
        ],
    }


def post_token(service, params, body) -> dict:
    """Issue a token for an existing account. The plaintext token is
    returned in THIS response only — never again, anywhere, including this
    same account's own future GET /api/tokens — because only its SHA-256 is
    kept (see auth.hash_api_token)."""
    from ... import auth

    username = str(body.get("username", "")).strip()
    if not username:
        raise ValueError("Which account is this token for?")
    if not service.app_db.user(username):
        raise ValueError(f"No account called {username}")

    label = str(body.get("label", "")).strip()
    if not label:
        raise ValueError("Give this token a label — what it is for, or what "
                         "will use it — so it can be told apart on the list "
                         "and in the audit log later.")
    if len(label) > 120:
        raise ValueError("That label is too long (120 characters max)")

    expires_ts = None
    expires_days = body.get("expires_days")
    if expires_days not in (None, "", 0):
        try:
            days = float(expires_days)
        except (TypeError, ValueError):
            raise ValueError("expires_days must be a number")
        if days <= 0:
            raise ValueError("expires_days must be positive, or omitted for no expiry")
        expires_ts = time.time() + days * 86400

    raw_token = auth.generate_api_token()
    token_id = service.app_db.add_api_token(
        username, label, auth.hash_api_token(raw_token),
        created_by=params.get("_username", ""), expires_ts=expires_ts)

    service.log.add(SYSTEM_CATEGORY,
                    f"API token '{label}' issued for {username} by "
                    f"{params.get('_username', 'someone')}")
    _audit(service, params, "token.issue", target=username,
           detail=f"id={token_id}; label={label}"
                  + (f"; expires in {expires_days}d" if expires_ts else "; no expiry"))
    # `token` appears in exactly one response body, ever — this one. Every
    # other route that touches tokens (get_tokens, the audit log, the event
    # log line above) carries only what post_token returns besides it.
    return {"id": token_id, "token": raw_token, "username": username,
            "label": label, "expires": expires_ts}


def delete_token(service, params, body) -> dict:
    """Revoke a token by id, immediately: the row is removed outright, so
    the very next request it would have authenticated is refused like any
    other unrecognised credential — there is no grace period and nothing
    left for a compromised token to still do."""
    token_id = body.get("id")
    try:
        token_id = int(token_id)
    except (TypeError, ValueError):
        raise ValueError("id must be a token id")

    row = service.app_db.revoke_api_token(token_id)
    if row is None:
        raise ValueError(f"No token with id {token_id}")

    service.log.add(SYSTEM_CATEGORY,
                    f"API token '{row['label']}' for {row['username']} "
                    f"revoked by {params.get('_username', 'someone')}")
    _audit(service, params, "token.revoke", target=row["username"],
           detail=f"id={token_id}; label={row['label']}")
    return {"revoked": token_id}


# ---------------------------------------------------------------- LDAP test
#
# A dry-run bind, so an administrator finds out whether
# ldap_url/ldap_bind_dn_template/ldap_allow_cleartext work before turning
# ldap_enabled on for a real account. Never creates a session and never
# consults or changes a stored account: purely a bind against the saved
# settings or the overrides in the body, so the dialog can be tested before
# Apply is pressed.

def post_ldap_test(service, params, body) -> dict:
    from ... import ldapclient

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password:
        raise ValueError("A username and password are needed to test a bind")

    url = str(body.get("url", "") or service.settings.get("ldap_url", ""))
    template = str(body.get("bind_dn_template", "")
                   or service.settings.get("ldap_bind_dn_template", ""))
    allow_cleartext = bool(body.get("allow_cleartext",
                                    service.settings.get("ldap_allow_cleartext", False)))
    timeout = float(service.settings.get("ldap_timeout_s", 10.0) or 10.0)

    try:
        dn = ldapclient.render_bind_dn(template, username)
        ldapclient.simple_bind(url, dn, password, timeout=timeout,
                               allow_cleartext=allow_cleartext)
        ok, message = True, f"Bind succeeded as {dn}"
    except ldapclient.LDAPInvalidCredentials:
        ok, message = False, "The directory rejected that username or password"
    except ldapclient.LDAPReferralError:
        ok, message = False, ("The directory returned a referral, which this "
                              "minimal client cannot follow")
    except ldapclient.LDAPBindError as exc:
        ok, message = False, str(exc)
    except (ldapclient.LDAPConnectError, ldapclient.LDAPProtocolError,
            ldapclient.LDAPConfigError) as exc:
        ok, message = False, str(exc)

    # No password, either way — only whether the test was run and against
    # what result.
    _audit(service, params, "ldap.test", target=username,
           detail=f"ok={ok}: {message}"[:400])
    return {"ok": ok, "message": message}


# ------------------------------------------------------------ TACACS+ test
#
# The TACACS+ counterpart to post_ldap_test above: a dry-run PAP login,
# never touching a stored account.

def post_tacacs_test(service, params, body) -> dict:
    import base64

    from ... import dpapi, tacacsclient

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password:
        raise ValueError("A username and password are needed to test a sign-in")

    servers_text = str(body.get("servers", "")
                       or service.settings.get("tacacs_servers", ""))
    secret_override = str(body.get("secret", ""))
    timeout = float(body.get("timeout_s", 0)
                    or service.settings.get("tacacs_timeout_s", 5.0) or 5.0)
    timeout = min(max(timeout, 1.0), 60.0)

    try:
        servers = tacacsclient.parse_servers(servers_text)
        secret = secret_override
        if not secret:
            secret_enc = str(service.settings.get("tacacs_secret_enc", ""))
            if not secret_enc:
                raise tacacsclient.TacacsConfigError(
                    "No shared secret is set, or saved yet")
            try:
                secret = dpapi.unprotect(base64.b64decode(secret_enc)).decode("utf-8")
            except dpapi.DpapiUnavailable as exc:
                raise tacacsclient.TacacsConfigError(
                    f"The stored shared secret could not be decrypted: {exc}") from exc
        accepted = tacacsclient.authenticate(
            servers, secret, username, password, timeout=timeout,
            rem_addr=str(params.get("_client", "")))
        ok = accepted
        message = ("Accepted" if accepted else
                   "The AAA server rejected that username or password")
    except tacacsclient.TacacsConfigError as exc:
        ok, message = False, str(exc)
    except tacacsclient.TacacsConnectError as exc:
        ok, message = False, f"Could not reach the AAA server: {exc}"
    except tacacsclient.TacacsProtocolError as exc:
        ok, message = False, str(exc)

    # No password or secret, either way — only whether the test was run and
    # against what result.
    _audit(service, params, "tacacs.test", target=username,
           detail=f"ok={ok}: {message}"[:400])
    return {"ok": ok, "message": message}


def get_alerts_total(service, params, body) -> dict:
    """How many alerts match the filters the list is showing."""
    filters = _alert_filters(params)
    counter = getattr(service.alerts_db, "count_alerts", None)
    if callable(counter):
        return {"total": int(counter(**filters)), "capped": False,
                "cap": None}
    rows = service.alerts_db.alerts(limit=ALERT_TOTAL_CAP + 1, **filters)
    total = len(rows)
    capped = total > ALERT_TOTAL_CAP
    return {"total": ALERT_TOTAL_CAP if capped else total,
            "capped": capped, "cap": ALERT_TOTAL_CAP}


# Which of this host's features can work at all, so the front end can gate a
# credential form instead of letting somebody fill it in and be refused with
# a 400. A route of its own rather than a key on /api/state: the answer
# cannot change while the process is running, so it is fetched once at
# start-up and never polled. Nothing here is a secret, so read on any module
# is enough.
def get_platform(service, params, body) -> dict:
    """What this host can and cannot do, for the forms that depend on it."""
    from ... import dpapi
    from ... import ipam_dhcp

    powershell = False
    if ipam_dhcp.IS_WINDOWS:
        try:
            ipam_dhcp._powershell_binary()
            powershell = True
        except Exception:                                     # noqa: BLE001
            powershell = False

    return {
        "platform": {
            "is_windows": bool(dpapi.IS_WINDOWS),
            "powershell": powershell,
            # The same call every credential route makes before accepting a
            # POST: true unconditionally on Windows, true off Windows once
            # secretstore.configured() has a passphrase
            # (NETPATH_SECRET_PASSPHRASE_FILE or NETPATH_SECRET_PASSPHRASE,
            # see CREDENTIAL-SECURITY.md §10). Answered rather than assumed,
            # so a configured Linux host's form is not greyed out while the
            # API accepts the same credential.
            "secret_store": bool(dpapi.available()),
            "credential_store": ("Windows DPAPI" if dpapi.IS_WINDOWS
                                 else ("Portable secret store" if dpapi.available()
                                       else None)),
        },
    }

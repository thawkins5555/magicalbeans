"""Regression guards for two CONFIRMED findings from a code review (see the
review's own write-up for the full incident chain; this suite only proves
the fixes hold):

  1. netpath.ldapclient.simple_bind() used to forward a zero-length
     password straight into a BindRequest. RFC 4511 section 4.2 makes that
     a legal, distinct operation — an "unauthenticated bind" — that many
     directories answer with resultCode 0 (success) rather than
     invalidCredentials (49), because as far as the protocol is concerned
     no credential was being checked at all. Combined with
     netpath.web.api's password read (no emptiness check) and
     Service.authenticate_ldap passing it straight through, POST /api/login
     with {"password": ""} could mint a full session for any ldap-mapped
     username with nothing verified whatsoever. Both simple_bind (RFC 4513
     section 5.1.2's SHOULD-prohibit) and authenticate_ldap (defence in
     depth) now refuse an empty password before any of it can happen.

  2. netpath.auth.SessionStore.destroy_user() used to match sessions with
     `session["username"] == username` — exact, case-sensitive. Every
     account lookup elsewhere (app_db.user, set_password, remove_user) is
     case-insensitive (COLLATE NOCASE), so resetting "Bob.Smith"'s password
     updated the right row but killed zero sessions if the live one was
     created as "bob.smith" — defeating a password reset's entire point as
     an incident-response action. destroy_user now casefolds both sides.

Same conventions as tests/test_ldap_auth.py and tests/test_api_tokens.py:
a plain script, stdlib only, no pytest, `check()` prints ok/FAIL per
assertion and the process exits non-zero if any failed.
"""
import sys
import time

from _paths import free_tcp_port  # noqa: F401  (kept for parity; unused directly)

from netpath import ldapclient
from netpath.auth import SessionStore

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


# =========================================================================
# 1a. simple_bind refuses an empty password before opening any socket.
# =========================================================================
print("simple_bind: empty password refused before any network access")

# Nothing listens on port 1 (a reserved, unassigned port) on loopback: if
# simple_bind's empty-password guard did not fire first and it actually
# tried to connect, that attempt would fail with LDAPConnectError, not
# LDAPInvalidCredentials — so seeing the latter is proof the guard ran
# before _parse_url/socket work, not just that the bind eventually failed
# somehow.
DEAD_URL = "ldaps://127.0.0.1:1"

try:
    ldapclient.simple_bind(DEAD_URL, "uid=alice,ou=people,dc=example,dc=com", "")
    check("empty password: did not raise (unexpected)", False)
except ldapclient.LDAPInvalidCredentials:
    check("empty password raises LDAPInvalidCredentials, not "
          "LDAPConnectError — proof it never touched the socket", True)
except ldapclient.LDAPError as exc:
    check("empty password raises LDAPInvalidCredentials, not something else",
          False, repr(exc))

# The guard must not depend on allow_cleartext, a valid dn, or any other
# argument — an empty password is refused unconditionally.
try:
    ldapclient.simple_bind("ldap://127.0.0.1:1", "uid=alice,ou=people,dc=example,dc=com",
                           "", allow_cleartext=True)
    check("empty password over ldap://+allow_cleartext: did not raise "
          "(unexpected)", False)
except ldapclient.LDAPInvalidCredentials:
    check("empty password is refused the same way over ldap:// with "
          "allow_cleartext=True", True)
except ldapclient.LDAPError as exc:
    check("empty password over ldap://+allow_cleartext raises "
          "LDAPInvalidCredentials, not something else", False, repr(exc))

# =========================================================================
# 1b. A non-empty password still reaches the bind path (the guard is not
#     overly broad — it only catches the empty case).
# =========================================================================
print("simple_bind: a non-empty password still reaches the network")

try:
    ldapclient.simple_bind(DEAD_URL, "uid=alice,ou=people,dc=example,dc=com",
                           "not-empty")
    check("non-empty password: did not raise (unexpected — nothing is "
          "listening on this port)", False)
except ldapclient.LDAPConnectError:
    check("non-empty password gets past the empty-password guard and "
          "reaches the connect attempt (LDAPConnectError on a dead port)",
          True)
except ldapclient.LDAPError as exc:
    check("non-empty password should reach LDAPConnectError on a dead "
          "port, not something else", False, repr(exc))

# =========================================================================
# 2. Service.authenticate_ldap returns False for an empty password without
#    needing a real (or even reachable) directory — defence in depth over
#    simple_bind's own guard.
# =========================================================================
print("authenticate_ldap: empty password refused before ldapclient is asked")

import os
import tempfile

from netpath.web import Service

TMPDIR = tempfile.mkdtemp(prefix="auth_review_fixes_")
service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

try:
    # ldap_url is deliberately left unset/unreachable: if authenticate_ldap's
    # own empty-password guard did not fire, this would fall through into
    # ldapclient and raise LdapUnavailable (a misconfigured/unreachable
    # directory) rather than returning False — so a clean False here is
    # proof the guard is in authenticate_ldap itself, not just inherited
    # from simple_bind by accident.
    result = service.authenticate_ldap("alice", "")
    check("authenticate_ldap('alice', '') returns False without raising",
          result is False, repr(result))

    # Setting a real (if unreachable) ldap_url changes nothing about the
    # empty-password answer — still refused before any directory is asked.
    service.settings["ldap_url"] = "ldaps://127.0.0.1:1"
    service.settings["ldap_bind_dn_template"] = \
        "uid={username},ou=people,dc=example,dc=com"
    result = service.authenticate_ldap("alice", "")
    check("…still False once ldap_url is configured (defence in depth, "
          "not just an accident of no config)", result is False, repr(result))
finally:
    service.shutdown()

# =========================================================================
# 3. SessionStore.destroy_user matches case-insensitively, agreeing with
#    app.db's COLLATE NOCASE account lookups.
# =========================================================================
print("SessionStore.destroy_user: case-insensitive, like every account lookup")

store = SessionStore()
token = store.create("bob.smith", client="127.0.0.1", agent="test")
check("the session was actually created", store.get(token) is not None)

ended = store.destroy_user("Bob.Smith")
check("destroy_user('Bob.Smith') ends a session created as 'bob.smith'",
      ended == 1, ended)
check("…and the session is actually gone", store.get(token) is None)

# The reverse casing direction, and a completely different case shape, to
# make sure this is a real casefold and not a lucky one-off comparison.
token2 = store.create("BOB.SMITH")
ended2 = store.destroy_user("bob.smith")
check("destroy_user('bob.smith') ends a session created as 'BOB.SMITH'",
      ended2 == 1, ended2)
check("…and that session is gone too", store.get(token2) is None)

# A session for an unrelated user must survive — this is case-INsensitive
# matching of the same account, not a match-everything bug.
token3 = store.create("carol")
ended3 = store.destroy_user("Bob.Smith")
check("destroy_user for an account with no live sessions returns 0",
      ended3 == 0, ended3)
check("…and an unrelated account's session is untouched",
      store.get(token3) is not None)
store.destroy(token3)

print("FAILED: " + ", ".join(failures) if failures else "ALL ASSERTIONS PASSED")
sys.exit(1 if failures else 0)

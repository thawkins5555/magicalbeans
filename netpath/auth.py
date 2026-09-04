"""Local users, password hashing and sessions.

Passwords are never stored, only verified against a hash. The hash is scrypt
with the parameters OWASP currently recommends (N=2^17, r=8, p=1 — about
128 MiB per verification), falling back to PBKDF2-HMAC-SHA256 at 600,000
iterations if the SSL library underneath is too old for scrypt. The stored
string records which was used and with what parameters, so raising the cost
later does not invalidate existing passwords: they are rehashed on the next
successful login.

Sessions live in memory only. Restarting the service logs everyone out, which
is the safe default and avoids a token surviving in a file that also holds
network data.

This module has no concept of roles or per-module access itself — an
account here is just a username, a password hash, and a session. Per-
module read/write permissions are a layer above it (see `permissions.py`
and `appdb.py`'s `user_permissions` table); adding an account is still an
administrative act, since it's the point at which those grants are
decided.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import OrderedDict

# OWASP Password Storage Cheat Sheet, 2024 figures.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
PBKDF2_ROUNDS = 600_000
SALT_BYTES = 16
KEY_BYTES = 32

MIN_PASSWORD_LENGTH = 12
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "admin"

# Not a serious dictionary — just the handful that turn up in real breaches of
# small internal tools, plus the ones this application invites by existing.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "123456", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "letmein", "welcome",
    "welcome1", "admin", "admin123", "administrator", "root", "changeme",
    "abc123", "iloveyou", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "trustno1", "sappi", "sappi123", "netpath",
    "sappiwhere", "network", "cisco", "cisco123", "secret", "p@ssw0rd",
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")

# API tokens (Tier 1 #10): a service-account credential that authenticates
# an HTTP request the same way a session cookie does, checked wherever the
# cookie is (server.py's Bearer handling), but never expires from idleness
# and carries exactly the owning account's permission grants — see
# appdb.api_tokens for the storage side.
#
# Prefixed the way GitHub's and Slack's tokens are: a leak scanner (or a
# human skimming a log dump) can recognise "sw_api_…" as a credential on
# sight, where a bare base64url blob looks like any other opaque string.
API_TOKEN_PREFIX = "sw_api_"
API_TOKEN_BYTES = 32           # 256 bits, from secrets.token_urlsafe


def generate_api_token() -> str:
    """A fresh token. Returned to the caller exactly once, by the route
    that creates it — see appdb.add_api_token, which stores only its hash."""
    return API_TOKEN_PREFIX + secrets.token_urlsafe(API_TOKEN_BYTES)


def hash_api_token(raw_token: str) -> str:
    """The SHA-256 hex digest of a token, which is what is actually stored
    and looked up (appdb.api_token_by_hash) — never the token itself.

    Deliberately not scrypt, and deliberately not salted, unlike
    hash_password above. Both of those exist to make a *human-chosen*
    secret expensive to brute-force offline, because a password's real
    entropy is far below its length — dictionaries and pattern-mangling get
    an attacker most of the way there. A token from generate_api_token() has
    256 bits of entropy from `secrets.token_urlsafe`, chosen uniformly at
    random: there is no dictionary to run, no pattern to mangle, and no
    feasible amount of hardware makes searching a 256-bit space practical
    before the heat death of the universe. A slow, salted hash would only
    make every legitimate request pay a scrypt call for no matching benefit
    — the entropy is already doing the work a salt and a cost factor exist
    to add for a weaker secret. A plain SHA-256 lookup is what lets an
    automation script authenticate on every request without a
    half-second-per-call tax.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class AuthError(Exception):
    """Anything the user is allowed to be told about."""


class LockedOut(AuthError):
    """Too many failures in the window: this username, or this address, is
    refused outright for a while rather than merely slowed down. Its own
    type so the web layer answers 429 (with the wait) instead of 401,
    which is the difference between "wrong password" and "stop"."""


# ------------------------------------------------------------------ hashing

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _scrypt_available() -> bool:
    try:
        hashlib.scrypt(b"x", salt=b"y", n=2, r=1, p=1, dklen=16)
        return True
    except (ValueError, AttributeError):
        return False


def hash_password(password: str) -> str:
    """Return a self-describing hash. The password itself is never kept."""
    if not isinstance(password, str) or not password:
        raise AuthError("A password is required")
    salt = secrets.token_bytes(SALT_BYTES)

    if _scrypt_available():
        try:
            key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                 n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                                 dklen=KEY_BYTES, maxmem=(SCRYPT_N * SCRYPT_R * 256))
            return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}"
        except ValueError:
            pass    # not enough memory allowed; fall through

    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                              PBKDF2_ROUNDS, dklen=KEY_BYTES)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash."""
    if not stored or not isinstance(password, str):
        return False
    parts = stored.split("$")
    try:
        if parts[0] == "scrypt":
            _, n, r, p, salt, key = parts
            computed = hashlib.scrypt(
                password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r),
                p=int(p), dklen=len(_unb64(key)),
                maxmem=(int(n) * int(r) * 256))
        elif parts[0] == "pbkdf2_sha256":
            _, rounds, salt, key = parts
            computed = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), _unb64(salt), int(rounds),
                dklen=len(_unb64(key)))
        else:
            return False
    except (ValueError, IndexError, TypeError):
        return False
    return hmac.compare_digest(computed, _unb64(parts[-1]))


def needs_rehash(stored: str) -> bool:
    """True when the hash was made with weaker parameters than we now use."""
    parts = (stored or "").split("$")
    if parts[0] == "scrypt":
        try:
            return (int(parts[1]) < SCRYPT_N or int(parts[2]) < SCRYPT_R
                    or int(parts[3]) < SCRYPT_P)
        except (ValueError, IndexError):
            return True
    if parts[0] == "pbkdf2_sha256":
        # Upgrade to scrypt where it is available now but was not before.
        if _scrypt_available():
            return True
        try:
            return int(parts[1]) < PBKDF2_ROUNDS
        except (ValueError, IndexError):
            return True
    return True


def check_password_quality(password: str, username: str = "") -> None:
    """Raise AuthError with a readable reason if the password is too weak.

    Length and blocklist only. Composition rules (a digit, a symbol, a capital)
    are no longer recommended: they push people toward predictable patterns
    without adding much, and NIST dropped them.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Use at least {MIN_PASSWORD_LENGTH} characters. "
                        f"A short phrase is easier to remember and harder to "
                        f"guess than a mangled word.")
    if len(password) > 256:
        raise AuthError("That is longer than 256 characters")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        raise AuthError("That password is one of the first any attacker tries")
    if username and lowered == username.lower():
        raise AuthError("The password cannot be the username")
    if len(set(password)) < 5:
        raise AuthError("That password repeats too few distinct characters")


def check_username(username: str) -> str:
    name = (username or "").strip()
    if not USERNAME_RE.match(name):
        raise AuthError("Usernames are 2 to 64 characters: letters, digits, "
                        "dot, dash or underscore, starting with a letter or digit")
    return name


# ----------------------------------------------------------------- sessions

class SessionStore:
    """In-memory sessions, with an idle timeout and an absolute lifetime."""

    def __init__(self, idle_minutes: int = 240, max_hours: int = 12):
        self._lock = threading.Lock()
        self._sessions: dict[str, dict] = {}
        self.idle_seconds = idle_minutes * 60
        self.max_seconds = max_hours * 3600

    def configure(self, idle_minutes: int, max_hours: int) -> None:
        with self._lock:
            self.idle_seconds = max(1, int(idle_minutes)) * 60
            self.max_seconds = max(1, int(max_hours)) * 3600

    def create(self, username: str, client: str = "", agent: str = "") -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[token] = {"username": username, "created": now,
                                     "last_seen": now, "client": client,
                                     "agent": agent[:120]}
        return token

    def get(self, token: str) -> dict | None:
        """Validate without extending. Background polling — the periodic
        state fetch every open tab makes, whether or not anyone is at the
        keyboard — reads through here, so merely having the app open does not
        by itself keep a session alive. An explicit action does; see touch()."""
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if (now - session["last_seen"] > self.idle_seconds
                    or now - session["created"] > self.max_seconds):
                self._sessions.pop(token, None)
                return None
            return dict(session, token=token)

    def touch(self, token: str) -> dict | None:
        """Validate and mark the session as used just now.

        Called for requests that represent a deliberate action — a POST, PUT
        or DELETE, or the heartbeat the browser sends when it has detected
        real mouse or keyboard input — so the idle clock tracks presence
        rather than an open tab.
        """
        session = self.get(token)
        if session is None:
            return None
        with self._lock:
            live = self._sessions.get(token)
            if live is not None:
                live["last_seen"] = time.time()
        return session

    def destroy(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def destroy_user(self, username: str) -> int:
        """Used when a password changes or an account is removed."""
        with self._lock:
            gone = [token for token, session in self._sessions.items()
                    if session["username"] == username]
            for token in gone:
                self._sessions.pop(token, None)
        return len(gone)

    def active(self) -> list[dict]:
        now = time.time()
        with self._lock:
            return [
                {"username": s["username"], "client": s["client"],
                 "agent": s["agent"], "created": s["created"],
                 "last_seen": s["last_seen"],
                 "idle_s": now - s["last_seen"]}
                for s in self._sessions.values()
            ]


# ----------------------------------------------------------- login throttle

# Failures in `window_s` before an account or an address is refused
# outright rather than merely slowed. Counted independently, so one noisy
# address does not lock an account for everyone else and one account
# cannot be used to lock out an address.
LOCKOUT_THRESHOLD = 20

# How many distinct usernames and addresses are remembered at once. A
# plain dict grew one entry per username tried, forever — a few million
# guesses at distinct names was a memory leak with an attacker's hand on
# the tap. Least-recently-touched keys are dropped past this; dropping a
# key only forgets failures, and the ones that matter are by definition
# the ones being touched.
MAX_TRACKED_KEYS = 10_000


class LoginThrottle:
    """Slow down guessing, then stop it.

    Counted per username and per source address, so one noisy address cannot
    lock an account for everyone else, and one account cannot be used to lock
    out an address.
    """

    def __init__(self, threshold: int = 5, window_s: float = 900,
                 max_delay_s: float = 30,
                 lockout_threshold: int = LOCKOUT_THRESHOLD,
                 max_keys: int = MAX_TRACKED_KEYS):
        self._lock = threading.Lock()
        # Ordered so the least recently touched key is the one evicted.
        self._failures: "OrderedDict[str, list[float]]" = OrderedDict()
        self.threshold = threshold
        self.window_s = window_s
        self.max_delay_s = max_delay_s
        self.lockout_threshold = lockout_threshold
        self.max_keys = max_keys

    @staticmethod
    def _keys(username: str, client: str) -> tuple[str, str]:
        return f"u:{(username or '?').lower()}", f"c:{client}"

    def _recent(self, key: str, now: float) -> list[float]:
        """The failures still inside the window, with `key` marked as just
        used. Called with the lock held."""
        stamps = [ts for ts in self._failures.get(key, []) if now - ts < self.window_s]
        if stamps:
            self._failures[key] = stamps
            self._failures.move_to_end(key)
        else:
            self._failures.pop(key, None)
        return stamps

    def delay_for(self, username: str, client: str) -> float:
        now = time.time()
        with self._lock:
            worst = 0
            for key in self._keys(username, client):
                worst = max(worst, len(self._recent(key, now)))
        if worst < self.threshold:
            return 0.0
        # Doubling, capped: 5 failures is a second, 10 is half a minute.
        return min(self.max_delay_s, 2 ** (worst - self.threshold))

    def lockout_remaining(self, username: str, client: str) -> float:
        """Seconds this username or this address is refused for, 0 when
        neither is. Either being over the threshold is enough — they are
        counted independently on purpose."""
        now = time.time()
        with self._lock:
            worst = 0.0
            for key in self._keys(username, client):
                stamps = self._recent(key, now)
                if len(stamps) >= self.lockout_threshold:
                    # The lock lifts when the oldest failure that still
                    # counts towards the threshold ages out of the window.
                    oldest_counted = sorted(stamps)[-self.lockout_threshold]
                    worst = max(worst, oldest_counted + self.window_s - now)
        return max(0.0, worst)

    def record_failure(self, username: str, client: str) -> None:
        now = time.time()
        with self._lock:
            for key in self._keys(username, client):
                self._failures.setdefault(key, []).append(now)
                self._failures.move_to_end(key)
            while len(self._failures) > self.max_keys:
                self._failures.popitem(last=False)

    def clear(self, username: str) -> None:
        """Forget this account's failures. The address's are NOT forgotten:
        anyone holding one valid low-privilege account could otherwise reset
        the per-address counter at will and go on guessing other accounts
        from the same machine as fast as they liked."""
        with self._lock:
            self._failures.pop(f"u:{(username or '?').lower()}", None)

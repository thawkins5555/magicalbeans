"""The portable secret store: a stand-in for Windows DPAPI on hosts that
don't have it, for the one design CREDENTIAL-SECURITY.md's analysis calls
"genuinely equivalent to DPAPI for the file-theft case" — a passphrase
supplied at start-up, a key derived from it with scrypt, held in memory and
never written to disk. `dpapi.py` is the module every caller in this
application actually imports; this one is the implementation it dispatches
to when `os.name != "nt"` and a passphrase source is configured. See
CREDENTIAL-SECURITY.md, "The portable secret store", for the full analysis
of why this design was chosen over a key file beside the database (protects
against nothing) or the platform keyring (wrong fit for a headless server,
and a third-party dependency this application does not take).

What this module does NOT try to be: a key-file scheme. The 32-byte "key"
that actually encrypts data is derived from the passphrase every time it is
needed (and then cached in memory — see `_keys_for`) — nothing that could
decrypt a stored credential is ever written to disk. What IS written to disk
is a per-install salt (`_salt_path`), which is not a secret: its only job is
to make the same passphrase derive a different key on every install, so a
password reused across two installs of this application does not hand an
attacker who breaks one of them a working key for the other. An attacker who
already has the salt file gains nothing without the passphrase too.

Blob format (see `protect`/`_unpack` for the exact byte layout):

    MAGIC(4) | version(1) | scrypt_n(4) | scrypt_r(4) | scrypt_p(4) |
    nonce(16) | ciphertext(len(plaintext)) | mac(32)

`MAGIC` (b"NPSS") is what lets `dpapi.py` tell a portable-store blob apart
from an opaque DPAPI blob without guessing — a real DPAPI blob is CMS-ish
binary with no reason to ever start with these four bytes, but the tag
means `dpapi.py` doesn't have to rely on that being merely unlikely, it can
dispatch on it directly. The scrypt parameters travel with every blob (not
just implied by this module's current constants) so that raising the cost
in a future release doesn't strand credentials encrypted under the old one:
`unprotect` always uses whatever a blob says was used to make it.

Encryption is encrypt-then-MAC: a keystream is built by running
HMAC-SHA256(key_enc, nonce || counter) for successive 32-bit counters and
concatenating the digests, then XORed with the plaintext — the textbook
"keyed hash in counter mode" construction, built entirely from
`hashlib`/`hmac`, no invented cipher. `key_enc` and `key_mac` are two
independent 32-byte keys, both derived from the same scrypt output with
distinct HMAC labels (see `_derive_keys`) — never the same bytes doing two
jobs. The MAC covers version || nonce || ciphertext, exactly as the design
brief for this module specifies, and NOT the header's own salt/n/r/p fields
explicitly — it does not need to. Those fields feed the key derivation, so
an attacker who tampers with them derives a different key_mac than the one
that produced the stored MAC, and the comparison fails anyway. The MAC
comparison itself is `hmac.compare_digest`, not `==` — constant-time, so a
timing side channel cannot be used to guess the MAC one byte at a time.

What this module deliberately does not solve: rotating the passphrase. A
credential encrypted under one passphrase stays encrypted under it; there is
no re-key operation. Changing the passphrase means every stored credential
becomes undecryptable and has to be re-entered — see CREDENTIAL-SECURITY.md.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import struct
import threading

MAGIC = b"NPSS"
VERSION = 1

# OWASP Password Storage Cheat Sheet, 2024 figures — the same figures
# auth.py uses for login password hashing (see auth.py's SCRYPT_N/R/P).
# Recorded in every blob rather than only assumed, so raising these later
# does not break decrypting what is already stored (see module docstring).
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1

SALT_BYTES = 16
NONCE_BYTES = 16
MAC_BYTES = 32          # SHA-256 digest size

# A fixed ceiling on the memory any single scrypt call may use, sized to
# exactly what SCRYPT_N/R/P above need. (n, r, p) for unprotect() come from
# the blob's own header, not from these constants — that is the whole point
# of recording them, so a future release can raise the cost without
# breaking older blobs — but a blob's header is also the one place in this
# module that is not fully trusted (a corrupted file, or a deliberately
# hostile one). Deriving `maxmem` from n*r themselves, the way auth.py does
# for its own always-trusted constants, would let a blob claiming a huge n
# ask this process to allocate however much memory it likes; capped at a
# fixed ceiling instead, an oversized claim fails fast with ValueError
# (caught below and turned into SecretStoreError) rather than trying to
# honour it.
_SCRYPT_MAXMEM = SCRYPT_N * SCRYPT_R * 256

ENV_PASSPHRASE_FILE = "NETPATH_SECRET_PASSPHRASE_FILE"
ENV_PASSPHRASE = "NETPATH_SECRET_PASSPHRASE"


class SecretStoreError(Exception):
    """A passphrase is missing or misconfigured, or a blob failed to
    authenticate. Always a message safe to show an operator — never a
    stack trace from inside scrypt or the MAC comparison."""


# ------------------------------------------------------------ configuration

def configured() -> bool:
    """A passphrase source is named, whether or not it will actually work
    once read (bad file permissions, an empty file, a garbled scrypt
    parameter...). Mirrors dpapi.available() being just `os.name == "nt"`
    regardless of whether CryptProtectData will actually succeed — the
    detailed reason for failure, if there is one, surfaces from protect()
    or unprotect(), not from this cheap, side-effect-free check. Called by
    dpapi.available(), which is what the web UI gates every credential
    field on."""
    return bool(os.environ.get(ENV_PASSPHRASE_FILE) or os.environ.get(ENV_PASSPHRASE))


def _load_passphrase() -> bytes:
    """The passphrase, per the documented order: a file (preferred — the
    only source an unattended restart can plausibly use safely, and even
    then only if nothing but its owner can read it), then a plain
    environment variable (documented as weaker: visible to anything that
    can read this process's environment, e.g. /proc/<pid>/environ), then a
    refusal naming both. Raises SecretStoreError with a message meant to be
    shown to whoever configured this, not logged and hidden from them."""
    file_path = os.environ.get(ENV_PASSPHRASE_FILE)
    if file_path:
        try:
            mode = stat.S_IMODE(os.stat(file_path).st_mode)
        except OSError as exc:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE is set to {file_path!r} but "
                f"it could not be read: {exc}") from exc
        # Windows has no meaningful POSIX mode bits (see __main__.py's own
        # note on the data folder) — this check only means something on the
        # platforms this module exists for in the first place.
        if os.name != "nt" and mode & 0o077:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE ({file_path!r}) is readable "
                f"by more than its owner (mode {oct(mode)}). Anyone who can "
                f"read it can decrypt every credential this application has "
                f"stored, so it is refused until the file is chmod 600 (or "
                f"narrower) and owned by the account this service runs as.")
        try:
            with open(file_path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE ({file_path!r}) could not "
                f"be read: {exc}") from exc
        passphrase = raw.rstrip(b"\r\n")
        if not passphrase:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE ({file_path!r}) is empty.")
        return passphrase

    env_value = os.environ.get(ENV_PASSPHRASE)
    if env_value:
        return env_value.encode("utf-8")

    raise SecretStoreError(
        "No passphrase source is configured, so this host cannot encrypt or "
        "decrypt a stored credential. Set NETPATH_SECRET_PASSPHRASE_FILE to "
        "a file only its owner can read (recommended — the only source an "
        "unattended restart can use without also weakening this), or "
        "NETPATH_SECRET_PASSPHRASE directly (weaker: visible to anything "
        "that can read this process's environment). See "
        "CREDENTIAL-SECURITY.md, \"The portable secret store\".")


# ------------------------------------------------------------ install salt

def _default_data_dir() -> str:
    """The same folder __main__.default_db_path() puts the databases in.
    Duplicated here rather than imported — this module has no business
    depending on the entry point, and the test suite constructs a Service
    directly over throwaway database paths without ever importing
    __main__ — but the resolution logic itself must stay identical, since
    a salt file that moves between runs is a salt file that stops working."""
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    return os.path.join(base, "netpath-monitor")


def _salt_path() -> str:
    """Overridden wholesale by tests (`secretstore._salt_path = lambda: ...`),
    the same way the rest of this test suite replaces a module-level
    function rather than threading a parameter through every caller."""
    return os.path.join(_default_data_dir(), "secret.salt")


def _install_salt() -> bytes:
    """A random value generated once per install and kept next to the
    databases it protects (mode 600, like them — not because the salt is
    secret, but because there is no reason to advertise it either). Not
    itself part of the key: it is scrypt input, there so the same
    passphrase does not derive the same key on two different installs."""
    path = _salt_path()
    try:
        with open(path, "rb") as fh:
            existing = fh.read()
        if len(existing) == SALT_BYTES:
            return existing
    except FileNotFoundError:
        pass

    salt = secrets.token_bytes(SALT_BYTES)
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(salt)
            return salt
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
    except FileExistsError:
        # Lost a startup race with another process (or this is a leftover
        # from a half-written attempt) — use what is actually on disk
        # rather than have two processes derive keys from different salts.
        with open(path, "rb") as fh:
            existing = fh.read()
        if len(existing) == SALT_BYTES:
            return existing
        raise SecretStoreError(f"{path} exists but is not a valid salt file")


# --------------------------------------------------------------- key derivation

_cache_lock = threading.Lock()
_key_cache: dict[tuple[int, int, int], tuple[bytes, bytes]] = {}

# A generous but firmly bounded range for a blob's recorded n/r/p, checked
# in plain Python *before* n/r/p ever reach hashlib.scrypt. `maxmem` alone
# is not enough of a guard: it is meant to reject a request that would need
# more memory than that bound, but the memory a given (n, r, p) needs is
# itself computed from n*r*p, and a wide enough p can overflow that
# computation inside the underlying OpenSSL implementation and wrap back
# around to something small enough to slip past the maxmem check — at
# which point the real n/r/p are used anyway, and the process is left
# trying to honour them: a multi-gigabyte allocation, minutes of paging, or
# worse, not the fast, clean ValueError maxmem is there to provide. A blob
# is not trusted input (it can be corrupted, or deliberately hostile), so
# this range is checked first, unconditionally, however maxmem behaves.
_MIN_N, _MAX_N = 1 << 10, 1 << 22          # 1,024 .. ~4.2 million
_MAX_R, _MAX_P = 64, 16


def _sane_scrypt_params(n: int, r: int, p: int) -> bool:
    return (isinstance(n, int) and isinstance(r, int) and isinstance(p, int)
            and _MIN_N <= n <= _MAX_N and (n & (n - 1)) == 0    # power of two
            and 1 <= r <= _MAX_R and 1 <= p <= _MAX_P)


def _derive_keys(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> tuple[bytes, bytes]:
    """scrypt once (the expensive step — deliberately so, that cost is the
    whole point of scrypt over an unsalted hash), then two independent
    32-byte keys pulled out of that one output with distinct HMAC labels —
    a plain HKDF-Expand step, not a second scrypt run. key_enc and key_mac
    never share a byte."""
    if not _sane_scrypt_params(n, r, p):
        raise SecretStoreError(
            f"This credential's stored scrypt parameters (n={n}, r={r}, "
            f"p={p}) are outside the range this build accepts — refused "
            f"before being handed to scrypt at all, rather than risking "
            f"whatever a memory request that size would actually do.")
    try:
        master = hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, dklen=32,
                                maxmem=_SCRYPT_MAXMEM)
    except ValueError as exc:
        # Belt and suspenders: _sane_scrypt_params() above is meant to be
        # the real guard, but a genuinely valid, in-range (n, r, p) can
        # still ask for more than _SCRYPT_MAXMEM allows (a lower-N blob
        # from an older, cheaper release never will; a higher one, from a
        # release with a raised default, correctly can) — land here rather
        # than as a raw ValueError out of a MAC-checking function.
        raise SecretStoreError(
            f"This credential's stored scrypt parameters (n={n}, r={r}, "
            f"p={p}) ask for more memory than this build allows: {exc}") from exc
    key_enc = hmac.new(master, b"netpath-secretstore:enc", hashlib.sha256).digest()
    key_mac = hmac.new(master, b"netpath-secretstore:mac", hashlib.sha256).digest()
    return key_enc, key_mac


def _keys_for(n: int, r: int, p: int) -> tuple[bytes, bytes]:
    """The derived keys for one (n, r, p) triple, computed once and cached
    in memory for the rest of the process — "held in memory only" is the
    property this design is chosen for, and re-running scrypt on every
    single protect()/unprotect() call (nodepoll.py alone can make one of
    these calls per device, per poll cycle) would be needlessly slow
    without buying anything extra: the raw passphrase is not what is being
    protected by not caching it, the derived key already is the secret.
    A cache miss means either the first call in this process, or a blob
    made under different scrypt parameters after this module's defaults
    were changed in a later release — both read the passphrase source
    fresh, so a corrected/rotated passphrase file takes effect on the next
    key this process has not already derived."""
    with _cache_lock:
        cached = _key_cache.get((n, r, p))
        if cached is not None:
            return cached
        passphrase = _load_passphrase()
        salt = _install_salt()
        keys = _derive_keys(passphrase, salt, n, r, p)
        _key_cache[(n, r, p)] = keys
        return keys


# --------------------------------------------------------------------- cipher

def _keystream(key_enc: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key_enc, nonce + counter.to_bytes(4, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pack(n: int, r: int, p: int, nonce: bytes, ciphertext: bytes, mac: bytes) -> bytes:
    return (MAGIC + bytes([VERSION]) + struct.pack(">III", n, r, p)
            + nonce + ciphertext + mac)


def _unpack(blob: bytes):
    """None if `blob` doesn't even carry the tag (not ours to decrypt) — a
    caller decides what that means, since dpapi.py's answer differs by
    platform. Raises SecretStoreError for anything tagged as ours but
    malformed: a version this build does not understand, or a blob too
    short to hold its own header."""
    if not blob.startswith(MAGIC):
        return None
    body = blob[len(MAGIC):]
    if len(body) < 1 + 12 + NONCE_BYTES + MAC_BYTES:
        raise SecretStoreError(
            "This credential's stored blob is too short to be a portable "
            "secret store blob — it is truncated or corrupted.")
    version = body[0]
    if version != VERSION:
        raise SecretStoreError(
            f"This credential was encrypted by a portable secret store "
            f"format version {version}; this build only understands "
            f"version {VERSION}.")
    n, r, p = struct.unpack(">III", body[1:13])
    rest = body[13:]
    nonce, ciphertext, mac = (rest[:NONCE_BYTES], rest[NONCE_BYTES:-MAC_BYTES],
                              rest[-MAC_BYTES:])
    return n, r, p, nonce, ciphertext, mac


# ---------------------------------------------------------------- public API

def protect(plaintext: bytes) -> bytes:
    """Encrypt with the currently configured passphrase. Raises
    SecretStoreError instead of falling back to anything weaker — same
    contract dpapi.protect() keeps for the Windows path."""
    plaintext = bytes(plaintext)
    key_enc, key_mac = _keys_for(SCRYPT_N, SCRYPT_R, SCRYPT_P)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = _xor(plaintext, _keystream(key_enc, nonce, len(plaintext)))
    mac = hmac.new(key_mac, bytes([VERSION]) + nonce + ciphertext,
                   hashlib.sha256).digest()
    return _pack(SCRYPT_N, SCRYPT_R, SCRYPT_P, nonce, ciphertext, mac)


def unprotect(blob: bytes) -> bytes:
    """Decrypt a blob this module produced. Raises SecretStoreError for a
    wrong passphrase, a tampered byte anywhere in the blob, or a blob this
    build cannot read — the MAC is checked before anything derived from the
    ciphertext is returned, so a caller can never receive garbage
    plaintext and mistake it for a real (if oddly formed) credential."""
    parsed = _unpack(bytes(blob))
    if parsed is None:
        raise SecretStoreError("Not a portable secret store blob.")
    n, r, p, nonce, ciphertext, mac = parsed
    key_enc, key_mac = _keys_for(n, r, p)
    expected = hmac.new(key_mac, bytes([VERSION]) + nonce + ciphertext,
                        hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise SecretStoreError(
            "This credential could not be decrypted: either the configured "
            "passphrase is wrong, or the stored value has been corrupted or "
            "tampered with.")
    return _xor(ciphertext, _keystream(key_enc, nonce, len(ciphertext)))


def is_portable_blob(blob: bytes) -> bool:
    """Cheap tag check, no passphrase or MAC involved — what dpapi.py uses
    to decide which implementation a given stored blob belongs to."""
    return bytes(blob).startswith(MAGIC)


def self_test() -> bool:
    """Round-trips a throwaway value, the same shape as dpapi.self_test()
    and used for the same reason: a "Check encryption" style verification
    that does not depend on any credential actually being stored yet."""
    if not configured():
        return False
    probe = os.urandom(32)
    try:
        return unprotect(protect(probe)) == probe
    except SecretStoreError:
        return False

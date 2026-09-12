"""The portable secret store: a stand-in for Windows DPAPI on hosts without
it. A start-up passphrase is stretched with scrypt into an encrypt-then-MAC
key pair (HMAC-SHA256 counter-mode cipher, constant-time MAC compare), kept
in memory only. Blob: MAGIC(4)|version(1)|scrypt_n/r/p(4 each)|nonce(16)|
ciphertext|mac(32) — see `protect`/`_unpack`. No re-keying: a changed
passphrase strands every credential encrypted under the old one.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import struct
import threading
from collections import OrderedDict

MAGIC = b"NPSS"
VERSION = 1

# Same figures auth.py uses for login password hashing. Recorded in every
# blob (not just assumed) so raising these later doesn't strand old blobs.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1

SALT_BYTES = 16
NONCE_BYTES = 16
MAC_BYTES = 32          # SHA-256 digest size

# Fixed ceiling, not derived from the blob's own (untrusted) n/r/p header —
# a hostile blob claiming a huge n must fail fast, not get however much
# memory it asks for.
_SCRYPT_MAXMEM = SCRYPT_N * SCRYPT_R * 256

ENV_PASSPHRASE_FILE = "NETPATH_SECRET_PASSPHRASE_FILE"
ENV_PASSPHRASE = "NETPATH_SECRET_PASSPHRASE"


class SecretStoreError(Exception):
    """A passphrase is missing or misconfigured, or a blob failed to
    authenticate. Always a message safe to show an operator — never a
    stack trace from inside scrypt or the MAC comparison."""


# ------------------------------------------------------------ configuration

# Whether this host has POSIX ownership and mode bits worth checking. A
# module attribute, not `os.name != "nt"` inline, so the two refusals below
# can be exercised on the Windows runners where they were dead code.
_POSIX = os.name != "nt"


def configured() -> bool:
    """A passphrase source is named, whether or not it will actually work
    once read — mirrors dpapi.available()'s cheap, side-effect-free check;
    a detailed failure surfaces from protect()/unprotect() instead."""
    return bool(os.environ.get(ENV_PASSPHRASE_FILE) or os.environ.get(ENV_PASSPHRASE))


def _load_passphrase() -> bytes:
    """The passphrase: a file (preferred, owner-only readable) then a plain
    env var (weaker — visible via /proc/<pid>/environ), then
    SecretStoreError naming both, meant to be shown to whoever configured this."""
    file_path = os.environ.get(ENV_PASSPHRASE_FILE)
    if file_path:
        try:
            info = os.stat(file_path)
        except OSError as exc:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE is set to {file_path!r} but "
                f"it could not be read: {exc}") from exc
        mode = stat.S_IMODE(info.st_mode)
        # Windows has no meaningful POSIX mode bits (see __main__.py's own
        # note on the data folder) — this check only means something on the
        # platforms this module exists for in the first place.
        if _POSIX and mode & 0o077:
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE ({file_path!r}) is readable "
                f"by more than its owner (mode {oct(mode)}). Anyone who can "
                f"read it can decrypt every credential this application has "
                f"stored, so it is refused until the file is chmod 600 (or "
                f"narrower) and owned by the account this service runs as.")
        # The other half of the sentence above, which used to be promised and
        # not enforced: a 0600 file belonging to somebody else is exactly the
        # case it says is refused. root is allowed because a service started
        # as root before dropping privileges reads a root-owned file.
        if _POSIX and info.st_uid not in (0, os.getuid()):
            raise SecretStoreError(
                f"NETPATH_SECRET_PASSPHRASE_FILE ({file_path!r}) is owned by "
                f"uid {info.st_uid}, not by root or by the account this "
                f"service runs as (uid {os.getuid()}). Anyone who can "
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
    Duplicated rather than imported (this module has no business depending
    on the entry point), but must stay identical or the salt file moves."""
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
    """Generated once per install; scrypt input, not a secret itself — its
    job is making the same passphrase derive a different key per install."""
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

# Keyed on (n, r, p, passphrase_digest), not (n, r, p) alone — see
# _keys_for's docstring for why the passphrase has to be part of the key
# rather than something looked up only on a cache miss. An OrderedDict
# rather than a plain dict so a cache hit can be moved to the end
# (`move_to_end`) and eviction can drop from the other end in O(1),
# turning this into a bounded least-recently-used cache rather than a
# structure with no eviction policy at all — see _MAX_CACHE_ENTRIES.
_key_cache: "OrderedDict[tuple[int, int, int, bytes], tuple[bytes, bytes]]" = OrderedDict()

# A process that lives through many passphrase rotations (or, less
# alarmingly, just polls devices whose blobs were written under more than
# one historical scrypt parameter set) would otherwise grow _key_cache
# forever — nothing ever expired an entry. Each distinct (n, r, p,
# passphrase) combination is one scrypt run's worth of memory pressure
# once (the two 32-byte keys themselves are trivial; the risk is entries
# accumulating without bound over a very long-lived process), so a small
# fixed ceiling with least-recently-used eviction is enough to stop that
# growth while still keeping the common case -- the current passphrase,
# possibly alongside one or two blobs made under an older scrypt cost --
# fully cached.
_MAX_CACHE_ENTRIES = 8

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
        # Belt and suspenders: an in-range (n, r, p) can still exceed _SCRYPT_MAXMEM.
        raise SecretStoreError(
            f"This credential's stored scrypt parameters (n={n}, r={r}, "
            f"p={p}) ask for more memory than this build allows: {exc}") from exc
    key_enc = hmac.new(master, b"netpath-secretstore:enc", hashlib.sha256).digest()
    key_mac = hmac.new(master, b"netpath-secretstore:mac", hashlib.sha256).digest()
    return key_enc, key_mac


def _keys_for(n: int, r: int, p: int) -> tuple[bytes, bytes]:
    """The derived keys for one (n, r, p, passphrase) combination, cached in
    memory keyed on (n, r, p, sha256(passphrase)) rather than (n, r, p)
    alone — the passphrase source is re-read every call (cheap) so a
    rotated file or env var re-derives and takes effect immediately, not
    only after a restart. Only the passphrase's digest is ever cached,
    never the passphrase itself."""
    passphrase = _load_passphrase()
    passphrase_tag = hashlib.sha256(passphrase).digest()
    cache_key = (n, r, p, passphrase_tag)
    with _cache_lock:
        cached = _key_cache.get(cache_key)
        if cached is not None:
            _key_cache.move_to_end(cache_key)
            return cached
        salt = _install_salt()
        keys = _derive_keys(passphrase, salt, n, r, p)
        _key_cache[cache_key] = keys
        if len(_key_cache) > _MAX_CACHE_ENTRIES:
            _key_cache.popitem(last=False)
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

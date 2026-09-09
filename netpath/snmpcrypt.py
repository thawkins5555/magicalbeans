"""The SNMPv3 USM privacy construction this application speaks:
AES-128-CFB (usmAesCfb128Protocol, RFC 3826), and only that.

What this module is NOT: it is not a cryptographic library, it does not
implement a cipher, it derives no keys (that is trapdecode.privacy_key,
beside the password-to-key routine it shares with authentication), and it
offers exactly one construction. The cipher itself is OpenSSL's, reached
through the `cryptography` package; what lives here is the part that is
ours rather than OpenSSL's — RFC 3826's IV, the salt discipline that keeps
that IV from ever repeating under one key, and the two guards that decide
whether the backend is usable at all — because that is where a mistake
would be ours to make and ours to test.

A leaf module on purpose: it imports `cryptography` and the standard
library and nothing from netpath, so snmppoll.py, nodepoll.py and, later,
trapdecode.py (inbound trap decryption is a deliberate follow-up) can all
use it without a cycle — snmppoll.py already imports from trapdecode.py.

Why not DES, and why not AES-192/256. DES (RFC 3414) is not offered on the
firewall this exists for and is a downgrade anyone would have to opt into.
AES-192 and AES-256 would cost nothing in cipher terms, but USM's key
derivation yields at most a digest's length of key material and the
"key extension" that stretches it to 24 or 32 bytes (the Reeder and
Blumenthal drafts) has two incompatible readings in shipping agents and no
RFC behind either; a construction that interoperates with some devices and
silently fails against others is worse than one that is absent, so it is
absent until it can be validated against real hardware.

Why the salt matters more than anything else here. CFB with a repeated IV
under one key leaks P1 XOR P2, and an SNMP plaintext is almost entirely
known structure — the same OIDs, poll after poll — so one repeat is
practical plaintext recovery, not a theoretical weakness. The salt is an
8-byte counter from a random start (os.urandom, never `random`: that
module seeds request ids, which is the right tool for an id and the wrong
one for an IV), advanced under a lock, and it shares the IV with
engineBoots and engineTime, so a collision across a device reboot is
impossible in principle rather than merely unlikely.
"""

from __future__ import annotations

import os
import struct
import threading
import warnings

# Protocol names as the credential forms store them, mapped to the key
# length the cipher needs. "AES" is what every vendor's CLI calls
# AES-128-CFB (PAN-OS, IOS, net-snmp's `-x AES`); "AES128" is accepted as
# the same thing so a name copied from an agent's own configuration works.
PRIV_PROTOCOLS = {
    "AES": 16,        # usmAesCfb128Protocol, RFC 3826
    "AES128": 16,
}

SALT_LEN = 8          # msgPrivacyParameters, RFC 3826 s3.1.2.1
IV_LEN = 16           # engineBoots(4) || engineTime(4) || salt(8)
KEY_LEN = 16


class PrivError(Exception):
    """The privacy layer cannot do what was asked: an unusable backend, a
    key or salt of the wrong length, or ciphertext that is not the shape
    RFC 3826 sends. Deliberately not a subclass of anything in snmppoll —
    this module imports nothing from netpath — so the caller decides what
    kind of SNMP failure it is."""


# --------------------------------------------------------------- backend

_lock = threading.Lock()
_backend = None            # (Cipher, AES, CFB) once loaded
_status: tuple[bool, str] | None = None   # cached verdict of available()

# NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt: the first two blocks. A
# known answer rather than a bare round trip because a backend that
# round-trips through the wrong mode (CFB8, say) would still round-trip;
# what we need to know is that it is THIS cipher.
_KAT_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_KAT_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_KAT_PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                           "ae2d8a571e03ac9c9eb76fac45af8e51")
_KAT_CIPHER = bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a"
                            "c8a64537a0b3a93fcde3cdad9f1ce58b")


def _load_backend():
    """Import the three names the cipher needs, tolerating the move CFB is
    in the middle of. On current `cryptography` CFB lives at
    hazmat.decrepit.ciphers.modes and importing it from
    hazmat.primitives.ciphers.modes emits CryptographyDeprecationWarning
    saying it will be removed; on older releases only the primitives path
    exists. Both work today; on some version only one will, and a pinned
    path here is exactly the bug that resurfaces months later as "polling
    stopped after a patch". So: decrepit first, primitives as the fallback,
    and the fallback's warning swallowed here rather than sprayed into the
    service log on every worker start."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography.hazmat.primitives.ciphers.modes import CFB
    return Cipher, algorithms.AES, CFB


def _self_test(backend) -> None:
    """One encrypt and one decrypt against the NIST vector, and a check that
    an odd length survives without padding. Raises on any disagreement."""
    cipher_cls, aes, cfb = backend
    encryptor = cipher_cls(aes(_KAT_KEY), cfb(_KAT_IV)).encryptor()
    if encryptor.update(_KAT_PLAIN) + encryptor.finalize() != _KAT_CIPHER:
        raise PrivError("AES-CFB known-answer test failed")
    decryptor = cipher_cls(aes(_KAT_KEY), cfb(_KAT_IV)).decryptor()
    if decryptor.update(_KAT_CIPHER) + decryptor.finalize() != _KAT_PLAIN:
        raise PrivError("AES-CFB decrypt of the known answer failed")
    encryptor = cipher_cls(aes(_KAT_KEY), cfb(_KAT_IV)).encryptor()
    if len(encryptor.update(b"seven b") + encryptor.finalize()) != 7:
        raise PrivError("AES-CFB padded a 7-byte plaintext")


def available(recheck: bool = False) -> bool:
    """Whether AES-CFB actually works in this process — not whether
    `cryptography` imports.

    `import cryptography` succeeding proves nothing: a build whose
    Rust/CFFI backend is broken imports fine, reports a version, and then
    dies inside the first real cipher call with a pyo3 PanicException —
    which is a BaseException, not an ImportError and not an Exception. So
    this runs a real known-answer encrypt/decrypt and catches BaseException
    around it, and only then says yes.

    Cached and lock-guarded for the reason configrx.paramiko_available is:
    the verdict is read on hot paths (every authPriv exchange, the
    settings/status page) and a failed import is not cached by Python, so
    an uncached probe would re-run the import machinery forever when the
    package is missing. Worker start passes recheck=True, so "install it,
    then restart the worker" is picked up without an application restart.
    """
    global _backend, _status
    with _lock:
        if _status is None or recheck:
            try:
                backend = _load_backend()
                _self_test(backend)
                _backend, _status = backend, (True, "")
            except BaseException as exc:      # noqa: BLE001 — see docstring
                _backend = None
                _status = (False, f"{type(exc).__name__}: {exc}"[:200])
        return _status[0]


def unavailable_reason() -> str:
    """Why available() said no, for an operator-facing message; '' when it
    said yes or has not been asked."""
    available()
    return _status[1] if _status else ""


def _cipher(key: bytes, iv: bytes):
    if not available():
        raise PrivError(
            "SNMPv3 privacy needs the 'cryptography' package with a working "
            "AES backend, and this process does not have one ("
            + (unavailable_reason() or "unknown reason") +
            "); install it, then restart the worker")
    cipher_cls, aes, cfb = _backend
    return cipher_cls(aes(key), cfb(iv))


# ------------------------------------------------------------------ salt

_salt_lock = threading.Lock()
# A random 64-bit start, then a counter: uniqueness within this process is
# then a property of the arithmetic rather than of a random generator's
# distribution, and the random start keeps two processes (two workers, or
# this one before and after a restart) from walking the same sequence.
_salt_counter = int.from_bytes(os.urandom(SALT_LEN), "big")


def next_salt() -> bytes:
    """The next msgPrivacyParameters value: 8 bytes, never repeated within
    this process for 2**64 messages, never all-zero. Zero is skipped not
    because RFC 3826 forbids it but because an all-zero salt is what a
    forgotten initialisation looks like, and a test that sees one should
    be able to call it a bug."""
    global _salt_counter
    with _salt_lock:
        _salt_counter = (_salt_counter + 1) % (1 << 64) or 1
        return _salt_counter.to_bytes(SALT_LEN, "big")


def iv_for(engine_boots: int, engine_time: int, salt: bytes) -> bytes:
    """RFC 3826 s3.1.2.1: the 128-bit IV is snmpEngineBoots (4 bytes,
    big-endian) || snmpEngineTime (4 bytes, big-endian) || salt (8 bytes),
    and that same salt travels in the clear as msgPrivacyParameters. Both
    integers are masked to 32 bits the way the wire field is, so an engine
    whose counters have wrapped still yields the IV the agent computes."""
    if len(salt) != SALT_LEN:
        raise PrivError(f"privacy salt must be {SALT_LEN} bytes, got {len(salt)}")
    return struct.pack(">II", int(engine_boots) & 0xFFFFFFFF,
                       int(engine_time) & 0xFFFFFFFF) + salt


def _check_key(priv_key: bytes) -> None:
    if not isinstance(priv_key, (bytes, bytearray)) or len(priv_key) != KEY_LEN:
        raise PrivError(
            f"AES-128 privacy key must be {KEY_LEN} bytes, got "
            f"{len(priv_key) if isinstance(priv_key, (bytes, bytearray)) else type(priv_key).__name__}")


def encrypt(priv_key: bytes, engine_boots: int, engine_time: int,
            plaintext: bytes, *, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """(ciphertext, msgPrivacyParameters) for one message. CFB128 needs no
    padding, so the ciphertext is exactly as long as the plaintext — a BER
    SEQUENCE in, an OCTET STRING of the same length out.

    `salt` is for tests only: it lets a suite pin the IV and compare
    against a fixed answer. Production callers never pass it; a caller that
    did would be choosing the one thing this module exists to choose
    correctly on their behalf."""
    _check_key(priv_key)
    if salt is None:
        salt = next_salt()
    iv = iv_for(engine_boots, engine_time, salt)
    encryptor = _cipher(bytes(priv_key), iv).encryptor()
    return encryptor.update(bytes(plaintext)) + encryptor.finalize(), salt


def decrypt(priv_key: bytes, engine_boots: int, engine_time: int,
            priv_params: bytes, ciphertext: bytes) -> bytes:
    """The scoped PDU behind an encryptedPDU, given the salt the message
    carried. Raises PrivError for a salt or key of the wrong length or an
    unusable backend; it cannot raise for a wrong key — CFB decrypts
    anything to something — so "the result is not a BER SEQUENCE" is the
    caller's test for that, and the caller should say "wrong privacy key"
    rather than "malformed", because that is what it almost always is."""
    _check_key(priv_key)
    if len(priv_params) != SALT_LEN:
        raise PrivError(
            f"msgPrivacyParameters must be {SALT_LEN} bytes for AES-CFB, got "
            f"{len(priv_params)}")
    iv = iv_for(engine_boots, engine_time, priv_params)
    decryptor = _cipher(bytes(priv_key), iv).decryptor()
    return decryptor.update(bytes(ciphertext)) + decryptor.finalize()

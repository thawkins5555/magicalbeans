"""Encrypts every optionally-stored credential (DHCP/SNMPv3/ConfigRX SSH/
SMTP/wireless passwords): Windows DPAPI, machine-scoped via
`CRYPTPROTECT_LOCAL_MACHINE` since the decrypting service may not run as
the account that encrypted it. Off Windows, dispatches to secretstore.py's
passphrase-based store instead. A blob is tagged (`secretstore.MAGIC`) so
`unprotect()` picks the right implementation regardless of platform.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os

from . import secretstore

IS_WINDOWS = os.name == "nt"

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


class DpapiUnavailable(Exception):
    """Not running on Windows, or the OS call itself failed."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """True on Windows unconditionally; off Windows, true once a passphrase
    source is configured (secretstore.configured()). Every caller gates a
    credential field on this one boolean."""
    return IS_WINDOWS or secretstore.configured()


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _from_blob(blob: _DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        # DPAPI allocates the output with LocalAlloc; it is ours to free, not
        # Python's garbage collector's — the pointer means nothing to it.
        if blob.pbData:
            ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect(plaintext: bytes) -> bytes:
    """Encrypt for this machine: DPAPI on Windows, the portable store
    elsewhere. Raises DpapiUnavailable on any failure — never a plaintext
    or weaker-cipher fallback."""
    if not IS_WINDOWS:
        try:
            return secretstore.protect(plaintext)
        except secretstore.SecretStoreError as exc:
            raise DpapiUnavailable(str(exc)) from exc
    blob_in = _to_blob(plaintext)
    blob_out = _DATA_BLOB()
    flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out))
    if not ok:
        raise DpapiUnavailable(f"CryptProtectData failed: {ctypes.WinError()}")
    return _from_blob(blob_out)


def unprotect(ciphertext: bytes) -> bytes:
    """Decrypt a blob protect() produced. Dispatches on the blob's own tag,
    not the current platform, so a portable-store blob is never handed to
    CryptUnprotectData and vice versa."""
    ciphertext = bytes(ciphertext)
    if secretstore.is_portable_blob(ciphertext):
        try:
            return secretstore.unprotect(ciphertext)
        except secretstore.SecretStoreError as exc:
            raise DpapiUnavailable(str(exc)) from exc
    if not IS_WINDOWS:
        raise DpapiUnavailable(
            "This credential was encrypted with Windows DPAPI, which only "
            "decrypts on the machine (and OS) that encrypted it — this host "
            "cannot read it back at all, portable secret store or not. "
            "Re-enter it after configuring the portable secret store here "
            "(NETPATH_SECRET_PASSPHRASE_FILE or NETPATH_SECRET_PASSPHRASE — "
            "see CREDENTIAL-SECURITY.md, \"The portable secret store\"); a "
            "credential protect()-ed under DPAPI has to be re-typed, not "
            "migrated.")
    blob_in = _to_blob(ciphertext)
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise DpapiUnavailable(f"CryptUnprotectData failed: {ctypes.WinError()}")
    return _from_blob(blob_out)


def self_test() -> bool:
    """Round-trips a throwaway value through whichever implementation
    available() says this host has. For a "Check encryption" button and
    confirming a fresh install works before anyone depends on it."""
    if not available():
        return False
    probe = os.urandom(32)
    try:
        return unprotect(protect(probe)) == probe
    except DpapiUnavailable:
        return False

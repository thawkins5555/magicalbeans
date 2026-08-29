"""Windows DPAPI, for the one secret this application optionally stores: a
DHCP polling password.

Everywhere else in SappiWhere, a credential lives in Windows itself — a user's
login for the web interface is a scrypt hash, and the preferred way to reach a
DHCP server is Windows Credential Manager, which needs no code here at all
(see ipam_dhcp.py). This module exists for the case that isn't: someone
migrating from a tool that took a username and password directly, who wants
the same shape of field rather than a trip to Credential Manager first.

DPAPI is the right tool for that, not a hand-rolled cipher with a key sitting
next to the data it protects. `CRYPTPROTECT_LOCAL_MACHINE` ties the encrypted
blob to this machine rather than to whichever Windows account encrypted it,
because the service that decrypts it on the next launch may not be running as
the same user who typed the password into the browser. The trade-off is the
one that matters here: the blob decrypts for any account on this machine, but
not for a copy of ipam.db moved to different hardware, which is what "only
this machine" is supposed to mean. A closer-scoped alternative,
`CRYPTPROTECT_UI_FORBIDDEN`-only user-scoped protection, would decrypt only
for the one account that encrypted it — safer in principle, unusable in
practice, since a headless service and the browser session that configured it
are not reliably the same account.

There is nothing to fall back to when this fails. If DPAPI is unavailable —
every code path here except a real Windows machine — storing a credential
raises rather than writing a plaintext password or a weaker cipher instead.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os

IS_WINDOWS = os.name == "nt"

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


class DpapiUnavailable(Exception):
    """Not running on Windows, or the OS call itself failed."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    return IS_WINDOWS


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
    """Encrypt for this machine. Raises DpapiUnavailable off Windows or on
    any OS failure — never returns a plaintext fallback."""
    if not IS_WINDOWS:
        raise DpapiUnavailable("DPAPI is only available on Windows")
    blob_in = _to_blob(plaintext)
    blob_out = _DATA_BLOB()
    flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out))
    if not ok:
        raise DpapiUnavailable(f"CryptProtectData failed: {ctypes.WinError()}")
    return _from_blob(blob_out)


def unprotect(ciphertext: bytes) -> bytes:
    """Decrypt a blob this same machine produced with protect()."""
    if not IS_WINDOWS:
        raise DpapiUnavailable("DPAPI is only available on Windows")
    blob_in = _to_blob(ciphertext)
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise DpapiUnavailable(f"CryptUnprotectData failed: {ctypes.WinError()}")
    return _from_blob(blob_out)


def self_test() -> bool:
    """Round-trips a throwaway value. For a "Check encryption" button in the
    UI and for confirming a fresh install can actually do this before anyone
    depends on it — DPAPI has no meaningful failure mode to unit test against
    on a machine that isn't Windows, so this is the verification available.
    """
    if not IS_WINDOWS:
        return False
    probe = os.urandom(32)
    try:
        return unprotect(protect(probe)) == probe
    except DpapiUnavailable:
        return False

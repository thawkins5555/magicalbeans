"""Windows DPAPI, for every secret this application optionally stores: a
DHCP polling password, an SNMPv3 auth password, ConfigRX's SSH backup
password, an authenticated SMTP password, and a wireless controller's SNMP
credential.

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

On Windows, nothing below has changed: DPAPI is still the only implementation
this module uses there, and every caller in this application still speaks
only `available()`, `protect()`, `unprotect()` and `DpapiUnavailable`. What
has changed is off Windows: `secretstore.py` implements the passphrase-at-
start-up design CREDENTIAL-SECURITY.md's analysis endorses (see "The
portable secret store" there), and this module now dispatches to it when
`os.name != "nt"` — `available()` becomes true there once an operator has
configured a passphrase source, and `protect()`/`unprotect()` route to it
instead of raising outright. There is still nothing to fall back to beyond
that: with neither DPAPI nor a configured passphrase, storing a credential
raises rather than writing a plaintext password or a weaker cipher instead.

A stored blob is tagged so the two implementations are never confused for
each other: a portable-store blob starts with `secretstore.MAGIC`, which a
real DPAPI blob has no reason to ever start with. `unprotect()` checks the
tag before it checks the platform, so a portable-store blob decrypts
wherever its passphrase is configured — Windows included, if someone sets
one there — while an untagged blob is assumed to be DPAPI's and refused with
a clear message on anything that isn't Windows, rather than silently
returning garbage.
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
    """True on Windows unconditionally (DPAPI itself may still fail for a
    real reason, surfaced from protect()/unprotect() when it does — same as
    always). Off Windows, true once a passphrase source is configured for
    the portable store; see secretstore.configured(). Every caller in this
    application gates a credential field on this one boolean, so this is
    also the answer to "can this host store a secret at all right now"."""
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
    """Encrypt for this machine: DPAPI on Windows, unchanged; the portable
    store elsewhere, if a passphrase source is configured. Raises
    DpapiUnavailable on any failure — a missing/misconfigured passphrase
    source off Windows, or an OS failure on it — never a plaintext or
    weaker-cipher fallback."""
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
    """Decrypt a blob protect() produced, on this machine or (for the
    portable store only, by design — see the module docstring) any machine
    with the same passphrase configured. Dispatches on the blob's own tag,
    not on the current platform, so a portable-store blob is never handed
    to CryptUnprotectData and an untagged (DPAPI) blob is never handed to
    secretstore off Windows."""
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
    available() says this host has right now — DPAPI on Windows, the
    portable store elsewhere once a passphrase is configured, False (no
    round trip attempted) otherwise. For a "Check encryption" button in the
    UI and for confirming a fresh install can actually do this before
    anyone depends on it.
    """
    if not available():
        return False
    probe = os.urandom(32)
    try:
        return unprotect(protect(probe)) == probe
    except DpapiUnavailable:
        return False

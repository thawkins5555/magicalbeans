"""Remembered SSH host keys, shared by ConfigRX's backups and the terminal.
Trust-on-first-use, keyed by (host, port); a changed key is refused and
reported with both fingerprints rather than silently accepted or replaced.
Keys are compared BY THEIR BYTES, never by name — the same RSA key can
negotiate under more than one algorithm label. paramiko is imported lazily,
since the app must start on a machine that has none.
"""

from __future__ import annotations

import base64
import hashlib
import time


def fingerprint_bytes(blob: bytes) -> str:
    """OpenSSH's `SHA256:<base64 without padding>` for a key in its wire
    form — the one spelling, so what this app shows can be read against
    `ssh-keyscan` / `ssh-keygen -lf` output directly."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fingerprint(key) -> str:
    """The same, for a paramiko key object. Keys are compared and described
    by their bytes throughout, so this is `fingerprint_bytes` of them."""
    return fingerprint_bytes(key.asbytes())


def host_key_name(host: str, port: int) -> str:
    """paramiko's known_hosts naming: the bare host on port 22, `[host]:port`
    otherwise. It has to match exactly, or paramiko looks up a key we stored
    under a different name and calls the connection unknown."""
    port = int(port or 22)
    return host if port == 22 else f"[{host}]:{port}"


def _when(ts) -> str:
    if not ts:
        return "an unknown date"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))


class HostKeyChanged(Exception):
    """A host presented a key that is not the one this app remembers for it.
    Carries both fingerprints, the new key type and date first seen, plus
    the new key object itself so trusting it needs no reconnect."""

    def __init__(self, host: str, port: int, old_fingerprint: str,
                 new_fingerprint: str, key_type: str = "",
                 old_first_seen=None, new_key=None):
        self.host = host
        self.port = int(port or 22)
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        self.key_type = key_type
        self.old_first_seen = old_first_seen
        self.new_key = new_key
        super().__init__(self.message())

    def message(self, label: str | None = None) -> str:
        """The sentence shown wherever this is reported. `label` lets a caller
        name the device the way its own page does; it defaults to the host."""
        where = label or self.host
        return (f"Host key for {where} changed (was {self.old_fingerprint} first seen "
                f"{_when(self.old_first_seen)}, now {self.new_fingerprint}). "
                f"Trust it from the SSH window or forget it in ConfigRX.")


class HostKeyStore:
    """The (host, port) -> host key table, as paramiko wants to see it.
    Constructed with the ConfigRX database (where the table lives). Usage:
    prepare() to load, policy() for set_missing_host_key_policy, then
    connect() (may raise HostKeyChanged), then record_seen()."""

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------- reading

    def stored(self, host: str, port: int):
        """The stored row for this host and port, or None."""
        return self.db.host_key(host, int(port or 22))

    def stored_key(self, host: str, port: int):
        """The stored key as a paramiko key object, or None when nothing is
        stored — or when the stored type is one this paramiko cannot build,
        which is a reason to treat the host as unknown rather than to raise."""
        row = self.stored(host, port)
        return self._key_from_row(row) if row else None

    @staticmethod
    def _key_from_row(row):
        from paramiko.hostkeys import HostKeyEntry
        try:
            entry = HostKeyEntry.from_line(
                f"stored {row['key_type']} {row['key_b64']}")
        except Exception:
            return None
        return entry.key if entry else None

    # ------------------------------------------------------------- writing

    def trust(self, host: str, port: int, key, by: str = ""):
        """Store `key` as the key for this host and port, replacing whatever
        was there. `by` is the app username that decided to, kept for the
        device dialog — never a password, and never the SSH username."""
        self.db.store_host_key(host, int(port or 22), key.get_name(),
                               key.get_base64(), fingerprint(key), by or "")
        return self.stored(host, port)

    def record_seen(self, host: str, port: int) -> None:
        """"The same key was presented again just now." Called after a
        connection paramiko accepted against the stored key. No guarding
        SELECT first: touching a row that is not there is already a no-op."""
        self.db.touch_host_key(host, int(port or 22))

    def forget(self, host: str, port: int) -> bool:
        return self.db.forget_host_key(host, int(port or 22))

    # ------------------------------------------------------------ paramiko

    def prepare(self, client, host: str, port: int):
        """Load the remembered key into `client` under paramiko's own naming,
        so paramiko itself checks the connection against it. Returns the key
        it loaded, or None when there is nothing to load — in which case the
        policy below is what decides."""
        key = self.stored_key(host, port)
        if key is None:
            return None
        client.get_host_keys().add(host_key_name(host, port), key.get_name(), key)
        return key

    def policy(self, host: str, port: int):
        """A `paramiko.MissingHostKeyPolicy` for this host and port. Reached
        on first connection (stored and accepted, with the fingerprint left
        on `policy.stored_new`/`stored_type`) or when the stored bytes
        differ from what the host just presented (refused). Built inside
        the function since paramiko is imported lazily."""
        import paramiko

        store = self
        target_host, target_port = host, int(port or 22)

        class _StoreOrRefusePolicy(paramiko.MissingHostKeyPolicy):
            def __init__(self):
                # The fingerprint and type stored on first sight; "" when
                # nothing was stored, which is how a caller tells the two
                # apart without asking the store again.
                self.stored_new = ""
                self.stored_type = ""

            def missing_host_key(self, client, hostname, key):
                row = store.stored(target_host, target_port)
                if row is None:
                    store.trust(target_host, target_port, key, by="")
                    self.stored_new = fingerprint(key)
                    self.stored_type = key.get_name()
                elif base64.b64decode(row["key_b64"]) != key.asbytes():
                    raise store.changed(row, key, target_host, target_port)
                else:
                    store.db.touch_host_key(target_host, target_port)
                client.get_host_keys().add(hostname, key.get_name(), key)

        return _StoreOrRefusePolicy()

    # ------------------------------------------------------------- mapping

    def changed(self, row, new_key, host: str, port: int) -> HostKeyChanged:
        """The exception for "the stored row says one key, the host presented
        another"."""
        return HostKeyChanged(
            host, port, row["fingerprint"] if row else "",
            fingerprint(new_key), new_key.get_name(),
            row["first_seen_ts"] if row else None, new_key)

    def as_changed(self, exc, host: str, port: int) -> HostKeyChanged:
        """paramiko's `BadHostKeyException` as this app's `HostKeyChanged`,
        with first-seen filled in from the store. Passing an already-mapped
        `HostKeyChanged` straight back lets a caller funnel both through
        one line."""
        if isinstance(exc, HostKeyChanged):
            return exc
        row = self.stored(host, port)
        new_key = getattr(exc, "key", None)
        if new_key is None:
            # Nothing on the exception to fingerprint — not a
            # BadHostKeyException at all, then. Report what we do know rather
            # than raising a second exception out of the error path.
            return HostKeyChanged(
                host, port, row["fingerprint"] if row else "", "an unrecognized key",
                "", row["first_seen_ts"] if row else None, None)
        return self.changed(row, new_key, host, port)

"""PLACEHOLDER — the real module is workstream B's.

The SSH terminal (sshterm.py) is written against the host-key store's
interface, not against its storage: `HostKeyStore(configrx_db)` with
`prepare(client, host, port)`, `policy(host, port)`, `trust(host, port,
key, by)`, the `HostKeyChanged` exception and `fingerprint(key)`. This file
exists so that interface resolves — and so the terminal's own tests run —
before the persistent implementation (a `ssh_host_keys` table in
configrx.db, shared with ConfigRX's backups) lands. It keeps its keys in
memory for the life of the process and is replaced wholesale by that work;
nothing here should grow a feature of its own.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time

# (host, port) -> {"key": PKey, "key_type": str, "fingerprint": str,
#                  "first_seen_ts": float, "last_seen_ts": float,
#                  "trusted_by": str}
_KEYS: dict[tuple[str, int], dict] = {}
_LOCK = threading.Lock()


def fingerprint(key) -> str:
    """The SHA-256 fingerprint in OpenSSH's spelling: base64 of the digest
    of the key blob, unpadded, prefixed "SHA256:". Over the key's own bytes
    rather than its advertised name, because one RSA key is negotiated as
    ssh-rsa, rsa-sha2-256 or rsa-sha2-512 depending on the peer."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class HostKeyChanged(Exception):
    """The device presented a different key from the one on file. Carries
    both fingerprints, the new key type, when the old key was first seen,
    and the new key itself so a deliberate `trust` can store it."""

    def __init__(self, host: str, port: int, old_fingerprint: str,
                 new_fingerprint: str, key_type: str,
                 old_first_seen: float | None, new_key=None):
        super().__init__(
            f"Host key for {host} changed (was {old_fingerprint}, "
            f"now {new_fingerprint})")
        self.host = host
        self.port = port
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        self.key_type = key_type
        self.old_first_seen = old_first_seen
        self.new_key = new_key


class _Policy:
    """paramiko.MissingHostKeyPolicy — duck-typed so this module never has
    to import paramiko, which is imported lazily everywhere else too."""

    def __init__(self, store: "HostKeyStore", host: str, port: int):
        self.store = store
        self.host = host
        self.port = port
        self.stored_new = False

    def missing_host_key(self, client, hostname, key):
        record = self.store.record(self.host, self.port)
        if record is None:
            self.store.remember(self.host, self.port, key, by="first connection")
            self.stored_new = True
            client.get_host_keys().add(hostname, key.get_name(), key)
            return
        if record["fingerprint"] != fingerprint(key):
            raise HostKeyChanged(self.host, self.port, record["fingerprint"],
                                 fingerprint(key), key.get_name(),
                                 record["first_seen_ts"], key)
        self.store.touch(self.host, self.port)


class HostKeyStore:
    def __init__(self, configrx_db=None):
        self.db = configrx_db

    # -------------------------------------------------------------- reading

    def record(self, host: str, port: int) -> dict | None:
        with _LOCK:
            found = _KEYS.get((host, int(port)))
            return dict(found) if found else None

    def prepare(self, client, host: str, port: int) -> None:
        """Load the stored key for this host into `client`, so paramiko
        itself refuses a changed one (as BadHostKeyException) before any
        credential is offered."""
        record = self.record(host, port)
        if not record:
            return
        name = host if int(port) == 22 else f"[{host}]:{int(port)}"
        client.get_host_keys().add(name, record["key"].get_name(), record["key"])

    def policy(self, host: str, port: int) -> _Policy:
        return _Policy(self, host, int(port))

    # -------------------------------------------------------------- writing

    def remember(self, host: str, port: int, key, by: str = "") -> dict:
        now = time.time()
        entry = {"key": key, "key_type": key.get_name(),
                 "fingerprint": fingerprint(key), "first_seen_ts": now,
                 "last_seen_ts": now, "trusted_by": by}
        with _LOCK:
            _KEYS[(host, int(port))] = entry
        return dict(entry)

    def touch(self, host: str, port: int) -> None:
        with _LOCK:
            entry = _KEYS.get((host, int(port)))
            if entry:
                entry["last_seen_ts"] = time.time()

    def trust(self, host: str, port: int, key, by: str = "") -> dict:
        """Replace whatever is on file with `key` — the operator has looked
        at both fingerprints and said yes."""
        return self.remember(host, port, key, by=by)

    def forget(self, host: str, port: int) -> None:
        with _LOCK:
            _KEYS.pop((host, int(port)), None)

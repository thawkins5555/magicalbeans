"""ConfigRxWorker: pulls a read-only "show config" snapshot from each
enabled device over SSH, on a schedule.

The hard safety boundary lives here: `_pull_config()` is the only place
in this module that talks to a device's shell, and it sends exactly the
fixed vendor.pager_off lines plus vendor.show_config from
configrx_vendors.py — nothing else, ever. There is no free-form command
execution anywhere in ConfigRX, by construction.

The SSH password follows this app's one credential discipline
(nodepoll.credential_for's shape): decrypted from its DPAPI blob
immediately before opening the connection, held only in a local variable,
and discarded (the variable is reassigned to None) the moment the
connection attempt finishes, success or failure.

Scheduler shape mirrors fortipoll.WirelessPoller (a small
ThreadPoolExecutor, a 1s-tick scanning loop) rather than nodepoll.py's
larger multi-candidate-credential machinery, since a device here has
exactly one fixed SSH credential.
"""

from __future__ import annotations

import re
import socket
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import configrx_vendors
from .configrxdb import ConfigRxDatabase
from .eventlog import CONFIGRX, ERROR, NullLog

CONNECT_TIMEOUT_S = 10
SHELL_QUIET_S = 1.5
SHELL_MAX_S = 25

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x08")
_PAGER_RE = re.compile(r"^\s*--\s*More\s*--\s*$", re.IGNORECASE)


def _clean_output(raw: str) -> str:
    """Strips ANSI escape sequences and pager prompts a device's shell may
    have echoed back even with paging disabled. Best-effort — this is
    display/storage hygiene, not a parser, so it never raises."""
    text = _ANSI_RE.sub("", raw).replace("\r", "")
    lines = [line for line in text.split("\n") if not _PAGER_RE.match(line)]
    return "\n".join(lines).strip() + "\n"


class _AcceptAndRecordPolicy:
    """paramiko.MissingHostKeyPolicy: never blocks on an unrecognized host
    key (this is network gear rarely carrying a stable known_hosts entry),
    but — unlike AutoAddPolicy — flags that it happened so the caller can
    say so in the backup's own status rather than silently accepting it."""

    def __init__(self):
        self.accepted_unknown = False

    def missing_host_key(self, client, hostname, key):
        self.accepted_unknown = True
        client.get_host_keys().add(hostname, key.get_name(), key)


def _drain(channel, quiet_s: float, max_s: float) -> str:
    channel.settimeout(0.5)
    chunks = []
    started = time.time()
    last_data = started
    while True:
        now = time.time()
        if now - started > max_s:
            break
        if chunks and now - last_data > quiet_s:
            break
        try:
            data = channel.recv(65536)
        except socket.timeout:
            continue
        if not data:
            break
        chunks.append(data.decode("utf-8", "replace"))
        last_data = time.time()
    return "".join(chunks)


def _pull_config(client, vendor: configrx_vendors.Vendor) -> str:
    """The only function in this file that talks to a device's shell.
    Sends exactly vendor.pager_off, then vendor.show_config — nothing
    else is ever written to this channel."""
    channel = client.invoke_shell(width=512, height=1000)
    try:
        _drain(channel, quiet_s=0.5, max_s=5)          # the login banner/prompt
        for line in vendor.pager_off:
            channel.send(line + "\n")
            _drain(channel, quiet_s=0.5, max_s=5)
        channel.send(vendor.show_config + "\n")
        return _drain(channel, quiet_s=SHELL_QUIET_S, max_s=SHELL_MAX_S)
    finally:
        channel.close()


class ConfigRxWorker:
    def __init__(self, db: ConfigRxDatabase, nodes_db, log=None):
        self.db = db
        self.nodes_db = nodes_db
        self.log = log or NullLog()
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._queued: set[int] = set()
        self._lock = threading.Lock()
        self.counters = {"backups": 0, "changed": 0, "unchanged": 0, "errors": 0}
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._thread = threading.Thread(target=self._loop, name="configrx-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return "Worker stopped"
        return "Running"

    def backup_now(self, device_id: int) -> None:
        with self._lock:
            if device_id in self._queued or not self._executor:
                return
            self._queued.add(device_id)
        try:
            self._executor.submit(self._run_one, device_id)
        except RuntimeError:
            with self._lock:
                self._queued.discard(device_id)

    def _loop(self) -> None:
        while not self._stop.is_set():
            settings = self.db.settings()
            if settings.get("enabled", True):
                interval = float(settings.get("backup_interval_hours", 24))
                for row in self.db.devices_due(interval):
                    self.backup_now(row["device_id"])
            self._stop.wait(30.0)

    def _run_one(self, device_id: int) -> None:
        try:
            self.counters["backups"] += 1
            self._backup_device(device_id)
        except Exception:
            self.counters["errors"] += 1
            traceback.print_exc()
            self.log.add(ERROR, f"ConfigRX backup of device {device_id} failed",
                        detail=traceback.format_exc())
        finally:
            with self._lock:
                self._queued.discard(device_id)

    # --------------------------------------------------------------- backup

    def _backup_device(self, device_id: int) -> None:
        import paramiko

        device = self.nodes_db.device(device_id)
        if not device:
            self.db.record_backup_attempt(device_id, ok=False, status="error",
                                          error="Device no longer exists in Nodes")
            return
        config = self.db.device_config(device_id)
        if not config or not config["backup_enabled"]:
            return

        vendor_key = (config["vendor_override"] or device["vendor"] or "")
        vendor = configrx_vendors.resolve(vendor_key)
        if vendor is None:
            self.db.record_backup_attempt(
                device_id, ok=False, status="error",
                error=f"Unrecognized vendor '{vendor_key or '(none)'}' — set a "
                      f"vendor override in this device's ConfigRX settings")
            return

        if not config["ssh_username"] or not config["ssh_password_enc"]:
            self.db.record_backup_attempt(device_id, ok=False, status="error",
                                          error="No SSH credential stored")
            return

        from . import dpapi
        password = None
        try:
            password = dpapi.unprotect(bytes(config["ssh_password_enc"])).decode("utf-8")
        except Exception:
            self.db.record_backup_attempt(device_id, ok=False, status="error",
                                          error="Stored SSH credential could not be decrypted")
            return

        client = paramiko.SSHClient()
        policy = _AcceptAndRecordPolicy()
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                device["ip"], port=int(config["ssh_port"]), username=config["ssh_username"],
                password=password, timeout=CONNECT_TIMEOUT_S, banner_timeout=CONNECT_TIMEOUT_S,
                auth_timeout=CONNECT_TIMEOUT_S, look_for_keys=False, allow_agent=False)
        except Exception as exc:
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=str(exc))
            self.log.add(ERROR, f"ConfigRX could not reach {device['ip']}", detail=str(exc))
            return
        finally:
            password = None
        try:
            raw = _pull_config(client, vendor)
        except Exception as exc:
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=str(exc))
            return
        finally:
            client.close()

        cleaned = _clean_output(raw)
        if len(cleaned.strip()) < 20:
            self.db.record_backup_attempt(
                device_id, ok=False, status="error",
                error="The device returned no usable output for the show-config command")
            return

        backup_id, _digest = self.db.add_backup(device_id, cleaned)
        note = " (host key not previously known)" if policy.accepted_unknown else ""
        if backup_id is not None:
            self.counters["changed"] += 1
            self.db.record_backup_attempt(device_id, ok=True, status="changed" + note)
            self.log.add(CONFIGRX, f"Stored a changed config backup for {device['ip']}")
        else:
            self.counters["unchanged"] += 1
            self.db.record_backup_attempt(device_id, ok=True, status="unchanged" + note)

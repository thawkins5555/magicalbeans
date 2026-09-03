"""ConfigRxWorker: pulls a read-only "show config" snapshot from each
enabled device over SSH, on a schedule.

The hard safety boundary of the BACKUP PATH lives here: `_pull_config()`
is the only place in this module that talks to a device's shell, and it
sends exactly the fixed vendor.pager_off lines plus vendor.show_config
from configrx_vendors.py — nothing else, ever. There is no free-form
command execution anywhere in ConfigRX, by construction.

That is a statement about backups, not about the whole application. The
interactive SSH terminal (sshterm.py) is a different feature with a
different boundary: it is a real shell, a human types into it, and it is
gated behind its own `ssh` permission which nobody holds by default.
Nothing on this path can send anything the operator typed there, and
nothing there runs through this module.

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

from . import configrx_redact
from . import configrx_vendors
from .configrxdb import ConfigRxDatabase
from .hostkeys import HostKeyChanged, HostKeyStore
from .nodesdb import detected_vendor
from .eventlog import CONFIGRX, ERROR, NullLog

CONNECT_TIMEOUT_S = 10
# Quiet fallback for a device whose prompt could not be learned. Deliberately
# far longer than the 1.5s it used to be: a switch answers "Building
# configuration..." immediately and then thinks, and 1.5s of that thinking
# used to end the read and store the banner as the whole backup.
SHELL_QUIET_S = 8.0
SHELL_SETUP_MAX_S = 15          # per pager_off line
# How many pager prompts to answer before deciding paging cannot be turned
# off on this device. A real config is longer than one screen but not
# thousands of them; a loop here would otherwise sit answering forever.
MAX_PAGER_REPLIES = 2000

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x08")
_PAGER_RE = re.compile(r"^\s*--\s*More\s*--\s*$", re.IGNORECASE)
# The marker anywhere in a line, for stripping it back out of a capture that
# was paged through (the device erases its own marker with backspaces, which
# _ANSI_RE removes, leaving the bare text mid-line).
_PAGER_INLINE_RE = re.compile(
    r"-{2,}\s*\(?\s*more[^)\n]{0,12}\)?\s*-{0,3}", re.IGNORECASE)
# The same thing, matched at the END of a buffer with no trailing newline —
# which is how it actually arrives, because the device is sitting there
# waiting for a keypress. Covers Cisco's "--More--", HP's "-- MORE --" and
# Junos' "---(more 23%)---".
_PAGER_TAIL_RE = re.compile(
    r"-{2,}\s*\(?\s*more[^)\n]{0,12}\)?\s*-{0,3}\s*$", re.IGNORECASE)
# A prompt ends in one of these once the shell is ready for another command.
_PROMPT_ENDS = "#>$%"
# The line a device prints before it starts building its config. Seeing it as
# the LAST thing in a capture means the read ended while the device was still
# working — the exact failure this module shipped with.
_STILL_WORKING_RE = re.compile(r"building configuration|^\s*\.{2,}\s*$",
                               re.IGNORECASE)

# paramiko is the one third-party dependency in this otherwise stdlib-only
# app, and it is imported lazily (inside the backup path) so that a machine
# without it can still run every other module. Missing it is a deployment
# fact, not a bug: it gets reported as a plain, actionable status on every
# affected device and in the worker's own status line, never as a raised
# traceback in the Errors log.
PARAMIKO_MISSING = ("paramiko is not installed on this server — ConfigRX needs it"
                    " for SSH. Install it with: pip install paramiko")

_paramiko_ok: bool | None = None
_paramiko_identity: str | None = None
# One lock over both cached probes. They are read from the web request
# threads (status_text sits on the frontend's /api/state poll), from the
# terminal's socket threads and from the backup workers, and written by
# whichever of them gets there first — and the write is not one store but
# an import followed by a store. Without this, a worker restarting with
# recheck=True could publish `False` for the instant its import took while
# a request thread read it, and two threads could pay for the paramiko +
# cryptography import at once.
_paramiko_lock = threading.Lock()


def paramiko_identity() -> str:
    """Which paramiko this *process* actually loaded, as "5.0.0 (/path/…)".

    The whole point is that "the installed paramiko" and "the paramiko this
    process is running" are different things, and only the second one decides
    anything. pip installs into whichever interpreter it was run from, and a
    downgrade of an already-imported module cannot take effect until the
    process restarts, because Python caches modules in sys.modules. Reporting
    a bare "the installed paramiko has removed it" left an operator who had
    just installed 3.4 with no way to see that 5.0 was still what was running.
    """
    global _paramiko_identity
    with _paramiko_lock:
        if _paramiko_identity is None:
            try:
                import paramiko
                version = getattr(paramiko, "__version__", "unknown version")
                path = getattr(paramiko, "__file__", None)
                _paramiko_identity = f"{version} ({path})" if path else str(version)
            except ImportError:
                _paramiko_identity = "not installed"
        return _paramiko_identity


def paramiko_available(recheck: bool = False) -> bool:
    """Cached: status_text() sits on the frontend's 2-second /api/state
    poll, and an *uncached* probe would re-run the import machinery on
    every call forever when paramiko is missing (failed imports are not
    cached in sys.modules), or pay the full paramiko+cryptography import
    inside the first web request thread when it is present. Worker start
    passes recheck=True, so 'install it, then restart the worker' still
    picks the new install up without an app restart."""
    global _paramiko_ok
    with _paramiko_lock:
        if _paramiko_ok is None or recheck:
            try:
                import paramiko  # noqa: F401
                _paramiko_ok = True
            except ImportError:
                _paramiko_ok = False
        return _paramiko_ok


# Key exchanges and host-key types that modern paramiko no longer prefers,
# most-preferred first within the group. Every one of them is SHA-1 based and
# every one of them is what an older switch, router or firewall offers as its
# best option — which is exactly the gear ConfigRX exists to back up.
_LEGACY_KEX = ("diffie-hellman-group-exchange-sha1",
               "diffie-hellman-group14-sha1",
               "diffie-hellman-group1-sha1")
_LEGACY_KEYS = ("ssh-rsa", "ssh-dss")

# Two separate facts, because a key-exchange failure has a different remedy
# depending on which one is false: does the installed paramiko implement SHA-1
# key exchange at all, and are we currently offering it? Telling an operator to
# reinstall paramiko when the real fix is a checkbox wastes their afternoon.
_legacy_kex_implemented: bool | None = None
_legacy_kex_offered: bool | None = None

# paramiko's preference lists exactly as the installed version shipped them,
# captured before anything is appended. Turning the setting back off restores
# this rather than subtracting our own names from the live list: it puts back
# the real original, in its original order, without assuming what was added.
_pristine_algorithms: tuple[tuple[str, ...], tuple[str, ...]] | None = None

LEGACY_KEX_UNAVAILABLE = (
    "This device offers only SHA-1 key exchange, which the paramiko this "
    "process actually loaded ({identity}) has removed entirely — there is no "
    "setting that re-enables it. If you have already installed an older "
    "paramiko, check that version above: pip may have installed it for a "
    "different interpreter, and a downgrade of an already-imported module "
    "cannot take effect until the process restarts, because Python caches "
    "modules in sys.modules. Either install a version that still implements "
    "it (pip install \"paramiko<5\") for this interpreter and restart the "
    "app, or enable a modern key exchange on the device "
    "(diffie-hellman-group14-sha256 or better).")

LEGACY_KEX_DISABLED = (
    "This device offers only SHA-1 key exchange, and \"Allow legacy SSH "
    "algorithms\" is switched off in ConfigRX settings. Turn it back on to "
    "reach this device, or enable a modern key exchange on the device "
    "(diffie-hellman-group14-sha256 or better).")


def _apply_legacy_algorithms(paramiko, enabled: bool = True) -> bool:
    """Offer — or stop offering — SHA-1 key exchange and ssh-rsa host keys.

    Feature-detected rather than version-checked: paramiko 3.x still ships
    these classes and merely leaves them out of the preferred lists, while
    paramiko 5.0 deleted them outright (`paramiko.kex_group1` is gone,
    `kex_gex` keeps only `KexGexSHA256`, `_key_info` has no plain `ssh-rsa`).
    Intersecting against what `Transport` actually implements is therefore
    correct on both, and on whatever comes next, where a version test would
    either crash or silently do nothing.

    Appended, never prepended: a device that can do curve25519 still does, and
    only one offering nothing better falls back this far.

    Both directions, deliberately. These are class-level attributes on
    `Transport`, so an "apply only" function could never revoke: switching the
    setting off used to leave the algorithms offered until the whole app
    restarted, with the checkbox unticked and no way to tell. Rebuilding from
    the pristine lists each time makes it symmetric and idempotent at once.

    Returns whether legacy key exchange is now being offered.
    """
    global _legacy_kex_implemented, _legacy_kex_offered, _pristine_algorithms
    transport = paramiko.Transport
    if _pristine_algorithms is None:
        _pristine_algorithms = (tuple(transport._preferred_kex),
                                tuple(transport._preferred_keys))
    base_kex, base_keys = _pristine_algorithms

    _legacy_kex_implemented = any(name in transport._kex_info
                                  for name in _LEGACY_KEX)
    if enabled:
        transport._preferred_kex = base_kex + tuple(
            name for name in _LEGACY_KEX
            if name in transport._kex_info and name not in base_kex)
        transport._preferred_keys = base_keys + tuple(
            name for name in _LEGACY_KEYS
            if name in transport._key_info and name not in base_keys)
    else:
        transport._preferred_kex = base_kex
        transport._preferred_keys = base_keys
    _legacy_kex_offered = bool(enabled and _legacy_kex_implemented)
    return _legacy_kex_offered


def _connect_error_text(exc: Exception) -> str:
    """The message an operator sees in the Errors log for a failed connect.

    paramiko's own "Incompatible ssh peer (no acceptable kex algorithm)" names
    the symptom and none of the cause, and the cause is usually this end
    rather than the device. Three cases, three different fixes: the installed
    paramiko cannot do SHA-1 key exchange at all; it can but the setting is
    off; or we are offering it and the device still refused — which is the one
    case where paramiko's own text is the whole truth and is left alone.
    """
    text = str(exc)
    if "kex" not in text.lower() or _legacy_kex_offered is not False:
        return text
    if _legacy_kex_implemented:
        return f"{text}. {LEGACY_KEX_DISABLED}"
    return f"{text}. {LEGACY_KEX_UNAVAILABLE.format(identity=paramiko_identity())}"


def ssh_algorithm_status() -> dict:
    """What this process is actually able to, and currently does, offer.

    Surfaced before anything fails — in ConfigRX settings and the module's
    status line — rather than only in the error text of a connection that
    already went wrong. `implemented` and `offered` are the two facts
    _apply_legacy_algorithms already computes and nothing used to show.
    """
    status = {
        "paramiko": paramiko_identity(),
        "available": paramiko_available(),
        "legacy_implemented": _legacy_kex_implemented,
        "legacy_offered": _legacy_kex_offered,
        "preferred_kex": [],
        "preferred_keys": [],
    }
    if status["available"]:
        try:
            import paramiko
            status["preferred_kex"] = list(paramiko.Transport._preferred_kex)
            status["preferred_keys"] = list(paramiko.Transport._preferred_keys)
        except Exception:      # pragma: no cover - a paramiko we don't know
            pass
    return status


def _offered_algorithms_detail() -> str:
    """The lists actually in force, for the Debug log line of a failed
    connect. "We offered these and the device refused" is then checkable
    rather than something an operator has to take on faith."""
    status = ssh_algorithm_status()
    lines = [f"paramiko: {status['paramiko']}"]
    if status["legacy_implemented"] is not None:
        lines.append(
            f"legacy SHA-1 key exchange: "
            f"{'implemented' if status['legacy_implemented'] else 'not implemented'}"
            f" by this paramiko, "
            f"{'offered' if status['legacy_offered'] else 'not offered'} by ConfigRX")
    if status["preferred_kex"]:
        lines.append("key exchange offered: " + ", ".join(status["preferred_kex"]))
    if status["preferred_keys"]:
        lines.append("host key types offered: " + ", ".join(status["preferred_keys"]))
    return "\n".join(lines)


def _clean_output(raw: str) -> str:
    """Strips ANSI escape sequences and pager prompts a device's shell may
    have echoed back even with paging disabled. Best-effort — this is
    display/storage hygiene, not a parser, so it never raises.

    Two passes over pager markers, because they arrive two ways: on a line of
    their own (paging left on, the device drew "--More--" and a newline), and
    embedded mid-line where the device erased its own marker with backspaces
    after we answered it. The second is what a paged capture looks like now
    that _read_until_prompt answers pagers instead of waiting them out.
    """
    text = _ANSI_RE.sub("", raw).replace("\r", "")
    lines = [line for line in text.split("\n") if not _PAGER_RE.match(line)]
    return _PAGER_INLINE_RE.sub("", "\n".join(lines)).strip() + "\n"


def _learn_prompt(banner: str) -> str:
    """The device's shell prompt, taken from the last non-blank line of the
    login banner — "switch#", "fw01 #", "[admin@rtr] >".

    Empty when that line does not look like a prompt, which is the honest
    answer for a device that logs in straight into a menu or prints a motd
    last. A wrong prompt is worse than none: it would end every read at the
    first config line that happened to match, so the callers fall back to a
    silence timeout instead of guessing.
    """
    text = _ANSI_RE.sub("", banner or "").replace("\r", "")
    for line in reversed(text.split("\n")):
        if not line.strip():
            continue
        candidate = line.strip()
        return candidate if candidate[-1] in _PROMPT_ENDS else ""
    return ""


def _waiting_at(text: str, needle_re=None, prompt: str = "") -> bool:
    """True when the device has stopped talking and is sitting at `prompt`
    (or at a pager marker matching `needle_re`) waiting for input.

    The "waiting" part is what makes this safe to check against a stream that
    is still arriving: a prompt is written WITHOUT a trailing newline, because
    the cursor stays on it. A config line that merely reads "switch#" is
    followed by a newline and so never ends the read.
    """
    tail = _ANSI_RE.sub("", text[-4096:]).replace("\r", "").rstrip(" \t")
    if not tail or tail.endswith("\n"):
        return False
    if needle_re is not None:
        return bool(needle_re.search(tail))
    return bool(prompt) and tail.split("\n")[-1].strip() == prompt


def _read_until_prompt(channel, prompt: str, max_s: float,
                       quiet_s: float = SHELL_QUIET_S) -> tuple[str, str]:
    """Reads a command's output until the device is finished with it.

    Returns (text, ended) where `ended` is how the read stopped:

      "prompt"     the device's prompt came back — the command is complete.
      "quiet"      no prompt was learned (or it never returned) and the device
                   went quiet for quiet_s. Complete as far as we can tell.
      "pager-loop" the device kept asking for a keypress past MAX_PAGER_REPLIES.
      "timeout"    the max_s ceiling was hit mid-output — TRUNCATED.
      "closed"     the device hung up.

    Ending on silence alone is what produced the two-line backups this
    replaced: a Cisco answers "Building configuration..." instantly and then
    thinks for several seconds, so any quiet window shorter than its thinking
    time ends the read on the banner. The prompt is what a human waits for,
    so it is what this waits for; silence is only the fallback.
    """
    channel.settimeout(0.5)
    chunks: list[str] = []
    started = time.time()
    last_data = started
    pager_replies = 0
    while True:
        now = time.time()
        if now - started > max_s:
            return "".join(chunks), "timeout"
        if chunks and now - last_data > quiet_s:
            return "".join(chunks), "quiet"
        try:
            data = channel.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return "".join(chunks), "closed"
        if not data:
            return "".join(chunks), "closed"
        chunks.append(data.decode("utf-8", "replace"))
        last_data = time.time()
        text = "".join(chunks)
        if _waiting_at(text, needle_re=_PAGER_TAIL_RE):
            if pager_replies >= MAX_PAGER_REPLIES:
                return text, "pager-loop"
            pager_replies += 1
            channel.send(" ")
            continue
        if _waiting_at(text, prompt=prompt):
            return text, "prompt"


def _pull_config(client, vendor: configrx_vendors.Vendor,
                 max_s: float) -> tuple[str, str]:
    """The only function in this file that talks to a device's shell.

    Sends exactly vendor.pager_off, then vendor.show_config — nothing else,
    with one deliberate exception: when the device stops mid-output at its own
    pager marker ("--More--"), a single space character is sent to advance it.
    That is a fixed in-band answer to a prompt the device raised, carrying no
    newline and no text, so it cannot execute anything; it is the keypress a
    human would make. The boundary — only pager_off and show_config are ever
    run on the device — is intact.

    The boundary is this path's, not the application's: sshterm.py opens an
    interactive shell for a human to type into, behind the separate `ssh`
    permission. Nothing it carries reaches this function, and nothing here
    grows a way to send anything else.

    Returns (raw text, how the read ended); see _read_until_prompt.
    """
    channel = client.invoke_shell(width=512, height=1000)
    try:
        # The login banner. No prompt is known yet, so this one genuinely does
        # end on silence — and its last line is where the prompt comes from.
        banner, _ = _read_until_prompt(channel, "", max_s=5, quiet_s=0.5)
        prompt = _learn_prompt(banner)
        for line in vendor.pager_off:
            channel.send(line + "\n")
            _read_until_prompt(channel, prompt, max_s=SHELL_SETUP_MAX_S, quiet_s=0.5)
        channel.send(vendor.show_config + "\n")
        return _read_until_prompt(channel, prompt, max_s=max_s)
    finally:
        channel.close()


# Two floors, because "too short to be a config" means different things
# depending on how the read ended.
#
# When the device gave its prompt back, the command demonstrably ran to
# completion, so a short result is genuinely a short config — a stripped-down
# MikroTik /export really is only a few lines. The floor there only has to
# reject a capture that is nothing but an error line ("% Invalid input
# detected...", "Permission denied") or the ~45-character banner failure this
# release exists to stop.
#
# When the read ended any other way there is no such evidence, so the floor is
# the one that says "a real running-config is hundreds of lines".
MIN_CONFIG_CHARS = 200
MIN_PROMPT_TERMINATED_CHARS = 80


def _capture_problem(cleaned: str, ended: str) -> str:
    """Why this capture must not be stored, or "" when it looks complete."""
    body = cleaned.strip()
    if not body:
        return "The device returned no output for the show-config command"
    if ended == "timeout":
        return ("The device was still sending its config when the capture "
                "timeout was reached, so the capture is incomplete. Raise "
                "the capture timeout in ConfigRX settings.")
    if ended == "pager-loop":
        return ("The device kept asking for a keypress to continue, so paging "
                "could not be turned off. Check the vendor override for this "
                "device.")
    if ended == "closed":
        return "The device closed the connection before the config finished"
    last = [line for line in body.split("\n") if line.strip()][-1]
    if _STILL_WORKING_RE.search(last):
        return ("The device was still building its config when the read "
                "ended, so only the banner was captured")
    floor = MIN_PROMPT_TERMINATED_CHARS if ended == "prompt" else MIN_CONFIG_CHARS
    if len(body) < floor:
        return (f"The device returned only {len(body)} characters, which is too "
                f"short to be a config — the command may not be right for this "
                f"vendor, or the account may lack the privilege to run it")
    return ""


class ConfigRxWorker:
    def __init__(self, db: ConfigRxDatabase, nodes_db, log=None):
        self.db = db
        self.nodes_db = nodes_db
        self.log = log or NullLog()
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Two maps, not one set: a device in the middle of an SSH session and
        # one waiting behind three others are different things to an operator
        # watching a backup, and the single set could not tell them apart —
        # _run_one only discarded the id in its finally. Same shape as
        # NodePoller's _queued/_started, and worker_state() below returns the
        # same dict the Nodes API already joins per device.
        self._queued: dict[int, float] = {}
        self._started: dict[int, float] = {}
        self._lock = threading.Lock()
        self.counters = {"backups": 0, "changed": 0, "unchanged": 0, "errors": 0}
        self.error: str | None = None
        # Last settings start() was handed; only allow_legacy_ssh is read from
        # here (the loop reads the rest from the database each pass).
        self.settings: dict = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: dict | None = None) -> None:
        self.stop()
        self._stop.clear()
        # Re-probe here so a paramiko installed since the last start is
        # seen; every other caller gets the cached verdict.
        paramiko_available(recheck=True)
        if settings is not None:
            self.settings = dict(settings)
        # Applied at start rather than per connection: it edits paramiko's
        # class-level preference lists, so doing it once is enough. Called
        # unconditionally and told which way to go — guarding the call site
        # instead was the bug that made the setting one-way, since skipping
        # the call cannot undo a previous one.
        if paramiko_available():
            import paramiko
            _apply_legacy_algorithms(
                paramiko, bool(self.settings.get("allow_legacy_ssh", False)))
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
        # Cached probe (see paramiko_available); start() re-checks, so
        # installing paramiko and restarting the worker is enough — no
        # app restart needed.
        if not paramiko_available():
            return PARAMIKO_MISSING
        if not self.running:
            return "Worker stopped"
        return "Running"

    class NotRunning(RuntimeError):
        """Asked to back up while the worker is stopped. Its own type so the
        API can turn it into a plain message rather than a 500, and so the
        scheduled loop can go on ignoring it."""

    def backup_now(self, device_id: int) -> bool:
        """Queues one device's backup. True when it was queued, False when
        that device is already waiting for one — a second click is a no-op,
        not an error.

        Raises NotRunning when the worker is stopped. It used to return
        silently, so pressing "Back up now" with the worker off reported
        success and did nothing at all: the operator was told the backup had
        been queued and then watched no backup ever appear.
        """
        with self._lock:
            if not self._executor or not self.running:
                raise self.NotRunning(
                    "The ConfigRX worker is not running, so nothing would "
                    "run this backup. Start it with the Start worker button "
                    "and try again."
                    if paramiko_available() else PARAMIKO_MISSING)
            if device_id in self._queued or device_id in self._started:
                return False
            self._queued[device_id] = time.time()
        try:
            self._executor.submit(self._run_one, device_id)
        except RuntimeError:
            with self._lock:
                self._queued.pop(device_id, None)
            raise self.NotRunning(
                "The ConfigRX worker stopped while the backup was being "
                "queued. Start it and try again.")
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            settings = self.db.settings()
            if settings.get("enabled", True):
                interval = float(settings.get("backup_interval_hours", 24))
                for row in self.db.devices_due(interval):
                    try:
                        self.backup_now(row["device_id"])
                    except self.NotRunning:
                        # Shutting down between the due-list and the submit;
                        # the next start picks these up again.
                        break
            self._stop.wait(30.0)

    def worker_state(self) -> dict:
        """{device_id: {"queued": ts, "started": ts}} for every backup in
        flight — the same shape NodePoller.worker_state() returns, so the API
        joins it per device the identical way."""
        with self._lock:
            return {device_id: {"queued": self._queued.get(device_id),
                                "started": self._started.get(device_id)}
                    for device_id in set(self._queued) | set(self._started)}

    def _run_one(self, device_id: int) -> None:
        with self._lock:
            self._queued.pop(device_id, None)
            self._started[device_id] = time.time()
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
                self._queued.pop(device_id, None)
                self._started.pop(device_id, None)

    # --------------------------------------------------------------- backup

    def _backup_device(self, device_id: int) -> None:
        try:
            import paramiko
        except ImportError:
            # Recorded like any other per-device failure so the device row
            # says exactly what is wrong and how to fix it, rather than the
            # whole backup raising into _run_one's traceback handler.
            self.db.record_backup_attempt(device_id, ok=False, status="error",
                                          error=PARAMIKO_MISSING)
            self.log.add(CONFIGRX, f"Backup of device {device_id} skipped: paramiko missing",
                        detail=PARAMIKO_MISSING)
            return

        device = self.nodes_db.device(device_id)
        if not device:
            self.db.record_backup_attempt(device_id, ok=False, status="error",
                                          error="Device no longer exists in Nodes")
            return
        config = self.db.device_config(device_id)
        if not config or not config["backup_enabled"]:
            return

        # detected_vendor rather than device["vendor"]: configrx_vendors.resolve
        # is an exact dict lookup, and a device whose custom vendor OID answers
        # "Cisco Systems, Inc." must still back up as cisco. The explicit
        # per-device override still wins over both.
        vendor_key = (config["vendor_override"] or detected_vendor(device) or "")
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

        # The shared host-key store (hostkeys.py), the same one the SSH
        # terminal uses: prepare() loads what we remember so paramiko itself
        # checks the connection against it, and the policy stores the key on a
        # first connection and refuses a changed one. A backup NEVER runs
        # against a device presenting a different key — that is the one case
        # where "carry on and mention it" would be the wrong answer, because
        # the config we would store came from something we cannot identify.
        host = device["ip"]
        port = int(config["ssh_port"])
        store = HostKeyStore(self.db)
        client = paramiko.SSHClient()
        store.prepare(client, host, port)
        policy = store.policy(host, port)
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                host, port=port, username=config["ssh_username"],
                password=password, timeout=CONNECT_TIMEOUT_S, banner_timeout=CONNECT_TIMEOUT_S,
                auth_timeout=CONNECT_TIMEOUT_S, look_for_keys=False, allow_agent=False)
        except (HostKeyChanged, paramiko.BadHostKeyException) as exc:
            # paramiko raises its own BadHostKeyException when the key loaded
            # by prepare() is not the one the host presented; the policy
            # raises ours when nothing was loaded but something is stored.
            # Both mean the same thing and read the same way.
            changed = store.as_changed(exc, host, port)
            detail = changed.message(host)
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=detail)
            self.log.add(ERROR, f"ConfigRX refused to back up {host}: its SSH host key changed",
                         detail=detail)
            return
        except Exception as exc:
            detail = _connect_error_text(exc)
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=detail)
            # The event's detail carries what we actually offered, so a
            # handshake failure can be read against the device's own logs
            # instead of guessed at. Kept out of the stored per-device error,
            # which is a one-line status.
            self.log.add(ERROR, f"ConfigRX could not reach {device['ip']}",
                         detail=f"{detail}\n\n{_offered_algorithms_detail()}")
            return
        finally:
            password = None
        # "This same key was presented again just now" — the stored row's
        # last_seen_ts is the only thing that says a remembered key is still
        # in use rather than left over from a device that has since gone.
        store.record_seen(host, port)
        try:
            capture_max_s = float(self.db.settings().get("capture_timeout_s", 180))
        except (TypeError, ValueError):
            capture_max_s = 180.0
        try:
            raw, ended = _pull_config(client, vendor, max_s=capture_max_s)
        except Exception as exc:
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=str(exc))
            return
        finally:
            client.close()

        cleaned = _clean_output(raw)
        # A truncated capture must never be stored. Storing one is worse than
        # storing nothing: it overwrites nothing, but it becomes the newest
        # "good" version, so the next real backup reads as a huge change and
        # a restore from history hands someone a two-line file. Each of these
        # is recorded as a failed attempt naming what actually went wrong.
        problem = _capture_problem(cleaned, ended)
        if problem:
            self.db.record_backup_attempt(device_id, ok=False, status="error", error=problem)
            self.log.add(CONFIGRX, f"Discarded a truncated config capture from {device['ip']}",
                         detail=f"{problem}\n\nCaptured {len(cleaned.strip())} characters, "
                                f"read ended on '{ended}'.")
            return

        # Redaction happens here, before anything is stored: what reaches
        # configrx.db is what an operator will be able to download, so the
        # secrets have to be gone by this line and not merely hidden by the
        # endpoint that serves it. Per-device opt-out, off by default.
        store_secrets = bool(config["store_secrets"]
                             if "store_secrets" in config.keys() else False)
        if store_secrets:
            redacted_count = 0
        else:
            cleaned, redacted_count = configrx_redact.redact(cleaned)

        backup_id, _digest = self.db.add_backup(
            device_id, cleaned, redacted=not store_secrets)
        # Only when a key was actually stored, and said once: the note used to
        # be appended to every backup, because the accepted key was thrown
        # away with the connection and every device was unknown again next
        # time. It now marks the one backup that taught this app the key.
        note = " (host key stored on first connection)" if policy.stored_new else ""
        if backup_id is not None:
            self.counters["changed"] += 1
            self.db.record_backup_attempt(device_id, ok=True, status="changed" + note)
            self.log.add(
                CONFIGRX, f"Stored a changed config backup for {device['ip']}",
                detail=(f"{redacted_count} secret-bearing line(s) redacted "
                        f"before storage" if not store_secrets else
                        "Stored verbatim: this device has \"keep secrets in "
                        "backups\" switched on"))
        else:
            self.counters["unchanged"] += 1
            self.db.record_backup_attempt(device_id, ok=True, status="unchanged" + note)

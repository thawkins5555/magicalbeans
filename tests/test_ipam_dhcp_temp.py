"""The DHCP poller survives a temp folder that no longer exists, and every
failure to stage its script surfaces as a DhcpUnavailable an operator can
act on — not as a bare OSError, and never as an UnboundLocalError from the
cleanup path standing in for the real error.

The fault this guards against, from a real Windows install:

    DHCP poll of CLQWSRTM1 failed: [Errno 2] No such file or directory:
    'C:\\Users\\ADMNA-~1\\AppData\\Local\\Temp\\2\\sappi-dhcp-z3_6xg__.ps1'

`%TEMP%` there names a per-session temp folder (`...\\Temp\\2`), which Windows
removes when the Remote Desktop session that owned it ends; the service had
inherited it and kept using it, so `tempfile.mkstemp()` failed against a
missing parent on every poll. That state is reproduced here without Windows
by pointing `tempfile.tempdir` — tempfile's own cache, which is exactly what
goes stale on the real host — at a directory that does not exist.

No PowerShell here: `subprocess.run` is replaced with a recorder that reads
the staged script the moment it would have been executed, and
`_powershell_binary` with a constant, the same way the other suites swap a
module attribute and put it back. The script-writing, the encoding, the
cleanup and the credential scrub are what is under test."""
import os
import shutil
import subprocess
import sys
import tempfile

from _paths import tmpdir

import netpath.ipam_dhcp as ipam_dhcp
from netpath.ipam_dhcp import DhcpUnavailable

ROOT = tmpdir("ipam_dhcp_temp_")
FAILS = []

BOM = b"\xef\xbb\xbf"
SERVER = "dhcp01.example.test"
PASSWORD = "s3cret-pw"
OK_JSON = '{"ok":true,"major":10,"minor":0,"scope_count":3}'


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class Recorder:
    """Stands in for subprocess.run. Captures what _run() would have handed
    PowerShell — the argv, the env dict (by reference, so the scrub in
    _run()'s finally is visible afterwards), and the staged script's bytes
    as they were at the moment of the call — then returns or raises whatever
    `outcome` says."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def __call__(self, argv, **kw):
        path = argv[argv.index("-File") + 1]
        existed = os.path.isfile(path)
        self.calls.append({
            "argv": argv, "env": kw["env"], "path": path, "existed": existed,
            "bytes": open(path, "rb").read() if existed else b"",
            "password_at_run": kw["env"].get("SAPPI_DHCP_PASSWORD"),
            "timeout": kw.get("timeout"),
        })
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def completed(returncode=0, stdout=OK_JSON + "\n", stderr=""):
    return subprocess.CompletedProcess(["pwsh"], returncode, stdout=stdout, stderr=stderr)


def run_with(recorder, resolver=None, **kw):
    """One _run() call with the stubs in place and put back afterwards,
    whatever happens. Returns (payload, raised) — exactly one is set — and
    `raised` is whatever escaped, of any type, so a test can assert on the
    *class* of the failure rather than only on DhcpUnavailable."""
    real_run = subprocess.run
    real_binary = ipam_dhcp._powershell_binary
    # getattr, not attribute access: on a module that has lost the import
    # this must still run, so the regression is reported as the failed
    # checks below rather than as an AttributeError before any of them.
    real_resolver = getattr(ipam_dhcp, "writable_tempdir", None)
    subprocess.run = recorder
    ipam_dhcp._powershell_binary = lambda: "/opt/fake/pwsh"
    if resolver is not None:
        ipam_dhcp.writable_tempdir = resolver
    try:
        try:
            payload = ipam_dhcp._run(ipam_dhcp._TEST_SCRIPT, SERVER,
                                     kw.pop("timeout_s", 30.0),
                                     username="svc-dhcp", password=PASSWORD)
        except BaseException as exc:        # noqa: BLE001 — the type is the assertion
            return None, exc
        return payload, None
    finally:
        subprocess.run = real_run
        ipam_dhcp._powershell_binary = real_binary
        ipam_dhcp.writable_tempdir = real_resolver


# A per-session temp folder, in the shape the report shows, that Windows has
# already deleted: its parent exists, the numbered folder does not.
MISSING = os.path.join(ROOT, "Temp", "2")
os.makedirs(os.path.dirname(MISSING), exist_ok=True)
shutil.rmtree(MISSING, ignore_errors=True)

real_tempdir_cache = tempfile.tempdir
try:
    # ------------------------------ 0. the directory comes from the resolver
    check("0. ipam_dhcp takes its directory from temppath.writable_tempdir, "
          "the one resolver the updater uses too",
          getattr(ipam_dhcp, "writable_tempdir", None) is not None)

    # ------------------------------------------ 1. the reported fault, directly
    tempfile.tempdir = MISSING
    check("1a. tempfile now answers with a directory that does not exist "
          "— the state a service inherits from an ended RDP session",
          tempfile.gettempdir() == MISSING and not os.path.isdir(MISSING))

    try:
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="sappi-dhcp-")
        os.close(fd)
        os.remove(path)
        unguarded = None
    except OSError as exc:
        unguarded = exc
    check("1b. the unguarded mkstemp the poller used to make fails there "
          "with the reported error — the fault is reproduced, not assumed",
          isinstance(unguarded, FileNotFoundError), repr(unguarded))

    rec = Recorder(completed())
    payload, raised = run_with(rec)
    check("1c. _run() succeeds anyway", raised is None and payload == {
        "ok": True, "major": 10, "minor": 0, "scope_count": 3}, repr(raised))
    check("1d. the script was staged in the re-created folder — the folder "
          "%TEMP% names is preferred, so nothing else about the host changes",
          len(rec.calls) == 1 and rec.calls[0]["existed"]
          and os.path.dirname(rec.calls[0]["path"]) == MISSING
          and os.path.isdir(MISSING),
          rec.calls[0]["path"] if rec.calls else "no call")
    check("1e. ...as a .ps1 handed to PowerShell with -File, not on stdin",
          rec.calls and rec.calls[0]["path"].endswith(".ps1")
          and "-File" in rec.calls[0]["argv"]
          and rec.calls[0]["argv"][0] == "/opt/fake/pwsh")
    check("1f. ...written as UTF-8 with a BOM, the whole script, unchanged",
          rec.calls and rec.calls[0]["bytes"].startswith(BOM)
          and rec.calls[0]["bytes"][len(BOM):].decode("utf-8") == ipam_dhcp._TEST_SCRIPT)
    check("1g. the server and credential reached the script as environment "
          "variables, the password intact at the moment of the run",
          rec.calls and rec.calls[0]["env"]["SAPPI_DHCP_SERVER"] == SERVER
          and rec.calls[0]["env"]["SAPPI_DHCP_USERNAME"] == "svc-dhcp"
          and rec.calls[0]["password_at_run"] == PASSWORD)
    check("1h. the script file is removed after a successful run",
          rec.calls and not os.path.exists(rec.calls[0]["path"]))
    check("1i. the password is scrubbed from the env dict after a successful run",
          rec.calls and rec.calls[0]["env"]["SAPPI_DHCP_PASSWORD"] == "")

    # --------------------------- 2. resolved on every call, not once at import
    # The whole point: the answer changes while the process runs. Delete the
    # folder again between two polls and both must still succeed.
    shutil.rmtree(MISSING, ignore_errors=True)
    resolver_calls = []
    real_resolver = getattr(ipam_dhcp, "writable_tempdir", tempfile.gettempdir)

    def counting_resolver():
        resolver_calls.append(1)
        return real_resolver()

    rec = Recorder(completed())
    _, raised1 = run_with(rec, resolver=counting_resolver)
    shutil.rmtree(MISSING, ignore_errors=True)
    _, raised2 = run_with(rec, resolver=counting_resolver)
    check("2a. two polls with the folder deleted in between both succeed",
          raised1 is None and raised2 is None, f"{raised1!r} / {raised2!r}")
    check("2b. the resolver was consulted once per poll — never cached",
          len(resolver_calls) == 2, str(len(resolver_calls)))
    check("2c. each poll staged its script and then removed it",
          len(rec.calls) == 2 and all(c["existed"] for c in rec.calls)
          and not any(os.path.exists(c["path"]) for c in rec.calls))

    # ------------------------------ 3. no temp directory obtainable at all
    resolver_text = ("No writable temporary directory could be found. Tried "
                     "the system temp folder (C:\\Users\\svc\\AppData\\Local\\Temp\\2): "
                     "[WinError 5] Access is denied; the install directory "
                     "(C:\\apps\\sappiwhere): exists but is not writable.")

    def no_resolver():
        raise RuntimeError(resolver_text)

    rec = Recorder(completed())
    _, raised = run_with(rec, resolver=no_resolver)
    check("3a. the failure surfaces as DhcpUnavailable",
          isinstance(raised, DhcpUnavailable), f"{type(raised).__name__}: {raised}")
    check("3b. ...not as a bare OSError/FileNotFoundError",
          not isinstance(raised, OSError), type(raised).__name__)
    check("3c. ...and not as UnboundLocalError from the cleanup path masking "
          "the real error",
          not isinstance(raised, UnboundLocalError), type(raised).__name__)
    message = str(raised)
    check("3d. the message keeps what the resolver said — every location "
          "tried and why", resolver_text in message, message)
    check("3e. ...names the per-session temp folder as the usual cause, and "
          "the Remote Desktop session that owned it",
          "Remote Desktop" in message and "per-session" in message
          and "no longer exists" in message, message)
    check("3f. ...says what to do: point TEMP/TMP at a folder that persists "
          "and restart the service",
          "TEMP" in message and "TMP" in message and "restart" in message
          and "nssm" in message, message)
    check("3g. ...and where the fault is: this machine, not the DHCP server",
          "not the DHCP server" in message, message)
    check("3h. PowerShell was never started", rec.calls == [])

    # --------------- 4. the folder vanished between the probe and our write
    # writable_tempdir() proved the folder writable a moment ago; it can
    # still be gone by the time mkstemp runs. That OSError must get the same
    # treatment, not escape raw the way the original report did.
    vanished = os.path.join(ROOT, "gone-again")
    rec = Recorder(completed())
    _, raised = run_with(rec, resolver=lambda: vanished)
    check("4a. an OSError from mkstemp itself surfaces as DhcpUnavailable",
          isinstance(raised, DhcpUnavailable) and not isinstance(raised, OSError),
          f"{type(raised).__name__}: {raised}")
    check("4b. ...carrying the original errno text, so nothing is hidden",
          "gone-again" in str(raised) and "No such file" in str(raised), str(raised))
    check("4c. ...not UnboundLocalError", not isinstance(raised, UnboundLocalError))
    check("4d. PowerShell was never started", rec.calls == [])

    # ---------------------------------------------------- 5. failed runs
    # Every way the run itself can fail: the script is still removed and the
    # password still scrubbed, and each is a DhcpUnavailable.
    rec = Recorder(PermissionError(13, "Permission denied"))
    _, raised = run_with(rec)
    check("5a. PowerShell refusing to start is DhcpUnavailable naming the binary",
          isinstance(raised, DhcpUnavailable) and "/opt/fake/pwsh" in str(raised)
          and "Permission denied" in str(raised), f"{type(raised).__name__}: {raised}")
    check("5b. ...the script file was removed",
          rec.calls and not os.path.exists(rec.calls[0]["path"]))
    check("5c. ...the password was scrubbed",
          rec.calls and rec.calls[0]["password_at_run"] == PASSWORD
          and rec.calls[0]["env"]["SAPPI_DHCP_PASSWORD"] == "")

    rec = Recorder(subprocess.TimeoutExpired(["pwsh"], 30.0))
    _, raised = run_with(rec, timeout_s=30.0)
    check("5d. a timeout is DhcpUnavailable naming the server and the wait",
          isinstance(raised, DhcpUnavailable) and SERVER in str(raised)
          and "30s" in str(raised), f"{type(raised).__name__}: {raised}")
    check("5e. ...the script file was removed",
          rec.calls and not os.path.exists(rec.calls[0]["path"]))
    check("5f. ...the password was scrubbed",
          rec.calls and rec.calls[0]["env"]["SAPPI_DHCP_PASSWORD"] == "")

    rec = Recorder(completed(1, '{"ok":false,"error":"Connecting to remote server '
                                'failed: TrustedHosts"}\n'))
    _, raised = run_with(rec)
    check("5g. the script reporting an error is DhcpUnavailable with the "
          "friendly guidance appended",
          isinstance(raised, DhcpUnavailable) and "TrustedHosts" in str(raised)
          and "winrm set" in str(raised), f"{type(raised).__name__}: {raised}")
    check("5h. ...the script file was removed",
          rec.calls and not os.path.exists(rec.calls[0]["path"]))
    check("5i. ...the password was scrubbed",
          rec.calls and rec.calls[0]["env"]["SAPPI_DHCP_PASSWORD"] == "")

    rec = Recorder(completed(1, "", "The term 'Import-Module' is not recognized"))
    _, raised = run_with(rec)
    check("5j. no JSON at all is DhcpUnavailable showing what PowerShell printed",
          isinstance(raised, DhcpUnavailable) and "exited with code 1" in str(raised)
          and "Import-Module" in str(raised), f"{type(raised).__name__}: {raised}")
    check("5k. ...the script file was removed",
          rec.calls and not os.path.exists(rec.calls[0]["path"]))
    check("5l. ...the password was scrubbed",
          rec.calls and rec.calls[0]["env"]["SAPPI_DHCP_PASSWORD"] == "")
finally:
    tempfile.tempdir = real_tempdir_cache
    shutil.rmtree(ROOT, ignore_errors=True)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed:")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("all checks passed")

"""Read-only polling of a Windows DHCP server's scopes and leases, via
PowerShell `DhcpServer` cmdlets with `-ComputerName` over DHCP RPC, run
locally — as the ambient Windows identity, or, with a stored credential, in
a local `Start-Job -Credential` job as that account. No WinRM. All scripts
are fixed constants; server name/username/password travel as environment
variables, never woven into command text.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime

from .ipam_scan import mac_colon
from .temppath import writable_tempdir
from .worker import hidden

IS_WINDOWS = os.name == "nt"

# A hostname, FQDN or IPv4/IPv6 address. Loose enough for real server names,
# strict enough to refuse anything that would be meaningful to a shell — belt
# and braces alongside the environment-variable passing above, which is the
# actual injection defense.
_VALID_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,253}$")

# The DHCP query itself, as a scriptblock: the ambient path runs it in-process,
# the credentialed path runs the identical block in a local job as the stored
# account. Both use -ComputerName over DHCP RPC; no WinRM. One definition, one
# data shape.
_BODY = r"""
$body = {
    param($ComputerName)
    $ErrorActionPreference = 'Stop'
    Import-Module DhcpServer -ErrorAction Stop
    $out = [ordered]@{ scopes = @(); leases = @(); reservations = @() }
    $scopeObjs = @(Get-DhcpServerv4Scope -ComputerName $ComputerName)
    $out.scopes = @($scopeObjs | ForEach-Object {
        # The router (option 3) isn't set on every scope, so a missing one
        # is not an error -- just nothing to report for that scope.
        $router = $null
        try {
            $opt = Get-DhcpServerv4OptionValue -ComputerName $ComputerName `
                -ScopeId $_.ScopeId -OptionId 3 -ErrorAction Stop
            if ($opt -and $opt.Value -and $opt.Value.Count -gt 0) {
                $router = $opt.Value[0].ToString()
            }
        } catch { $router = $null }
        [ordered]@{
            scope_id         = $_.ScopeId.ToString()
            name             = $_.Name
            start_ip         = $_.StartRange.ToString()
            end_ip           = $_.EndRange.ToString()
            mask             = $_.SubnetMask.ToString()
            state            = $_.State.ToString()
            lease_duration_s = [int]$_.LeaseDuration.TotalSeconds
            description      = $_.Description
            router           = $router
        }
    })
    foreach ($scope in $scopeObjs) {
        $out.leases += @(Get-DhcpServerv4Lease -ComputerName $ComputerName -ScopeId $scope.ScopeId |
            ForEach-Object {
                [ordered]@{
                    scope_id       = $scope.ScopeId.ToString()
                    ip             = $_.IPAddress.ToString()
                    mac            = $_.ClientId
                    hostname       = $_.HostName
                    address_state  = $_.AddressState.ToString()
                    lease_expires  = if ($_.LeaseExpiryTime) { $_.LeaseExpiryTime.ToUniversalTime().ToString('o') } else { $null }
                    is_reservation = $_.AddressState.ToString() -like '*Reservation*'
                }
            })
        $out.reservations += @(Get-DhcpServerv4Reservation -ComputerName $ComputerName -ScopeId $scope.ScopeId |
            ForEach-Object {
                [ordered]@{
                    scope_id    = $scope.ScopeId.ToString()
                    ip          = $_.IPAddress.ToString()
                    mac         = $_.ClientId
                    name        = $_.Name
                    description = $_.Description
                }
            })
    }
    $out
}
"""

# Every verb below is Get-, plus Import-Module, the *-Job cmdlets and
# formatting/output cmdlets. The job only ever runs the fixed $body scriptblock
# above, locally, as the stored account; never a string built at runtime.
_SCRIPT = _BODY + r"""
$ErrorActionPreference = 'Stop'
$server   = $env:SAPPI_DHCP_SERVER
$username = $env:SAPPI_DHCP_USERNAME
$timeout  = [int]$env:SAPPI_DHCP_TIMEOUT_S
if ($timeout -le 0) { $timeout = 30 }
try {
    if ([string]::IsNullOrEmpty($username)) {
        $result = & $body $server
    } else {
        $securePw = ConvertTo-SecureString $env:SAPPI_DHCP_PASSWORD -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($username, $securePw)
        # Local child powershell as the stored account; DHCP RPC to $server.
        $job = Start-Job -Credential $cred -ScriptBlock $body -ArgumentList $server
        try {
            if (-not (Wait-Job -Job $job -Timeout $timeout)) {
                throw "The DHCP query as $username did not finish within $timeout seconds"
            }
            if ($job.State -eq 'Failed' -and $job.ChildJobs[0].JobStateInfo.Reason) {
                throw $job.ChildJobs[0].JobStateInfo.Reason.Message
            }
            $result = Receive-Job -Job $job -ErrorAction Stop
            if ($null -eq $result) {
                throw "The DHCP query as $username returned nothing (job state $($job.State))"
            }
        } finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    $result | ConvertTo-Json -Depth 6 -Compress
} catch {
    [ordered]@{ error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
"""

# A cheap reachability check, separate from the full poll: version and
# service state only, no scope enumeration, for a fast "Test connection"
# button that does not wait on every scope's leases. Branches the same way.
_TEST_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$server   = $env:SAPPI_DHCP_SERVER
$username = $env:SAPPI_DHCP_USERNAME
$timeout  = [int]$env:SAPPI_DHCP_TIMEOUT_S
if ($timeout -le 0) { $timeout = 30 }
$probe = {
    param($ComputerName)
    $ErrorActionPreference = 'Stop'
    Import-Module DhcpServer -ErrorAction Stop
    $version = Get-DhcpServerVersion -ComputerName $ComputerName
    $scopeCount = @(Get-DhcpServerv4Scope -ComputerName $ComputerName).Count
    [ordered]@{ ok = $true; major = $version.MajorVersion; minor = $version.MinorVersion
               scope_count = $scopeCount }
}
try {
    if ([string]::IsNullOrEmpty($username)) {
        $result = & $probe $server
    } else {
        $securePw = ConvertTo-SecureString $env:SAPPI_DHCP_PASSWORD -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($username, $securePw)
        $job = Start-Job -Credential $cred -ScriptBlock $probe -ArgumentList $server
        try {
            if (-not (Wait-Job -Job $job -Timeout $timeout)) {
                throw "The DHCP query as $username did not finish within $timeout seconds"
            }
            if ($job.State -eq 'Failed' -and $job.ChildJobs[0].JobStateInfo.Reason) {
                throw $job.ChildJobs[0].JobStateInfo.Reason.Message
            }
            $result = Receive-Job -Job $job -ErrorAction Stop
            if ($null -eq $result) {
                throw "The DHCP query as $username returned nothing (job state $($job.State))"
            }
        } finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    $result | ConvertTo-Json -Compress
} catch {
    [ordered]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
"""


class DhcpUnavailable(Exception):
    """PowerShell, the DhcpServer module, or the target server did not
    answer — no PowerShell/RSAT tools, nowhere to stage the script, or the
    remote call itself failed."""


def _powershell_binary() -> str:
    for name in ("pwsh", "powershell.exe", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    raise DhcpUnavailable(
        "No PowerShell found on this host. Reading a Windows DHCP server "
        "needs PowerShell with the DhcpServer module (part of RSAT: DHCP "
        "Server Tools), installed on the machine running SappiWhere — not "
        "necessarily on the DHCP server itself.")


def _validate_address(server: str) -> str:
    server = (server or "").strip()
    if not server or not _VALID_ADDRESS.match(server):
        raise ValueError(f"Not a usable DHCP server address: {server!r}")
    return server


def _friendly_error(message: str) -> str:
    """Append actionable guidance to a handful of errors the credentialed
    (local job as the stored account) path is known to hit, keeping the
    original message first."""
    if ("has not been granted the requested logon type" in message
            or "Logon failure" in message
            or "starting the background process" in message):
        return (
            f"{message}\n\nThis is on the machine running SappiWhere, not the "
            f"DHCP server: the stored account is used by starting a local "
            f"PowerShell as that account, so it must be allowed to log on "
            f"here. Grant it in Local Security Policy -> User Rights "
            f"Assignment -> \"Allow log on locally\" (and make sure it is not "
            f"listed under \"Deny log on locally\"), and check that the "
            f"Secondary Logon service is not disabled. Or store a different "
            f"account that already has that right. If the message says the "
            f"user name or password is wrong, re-enter the stored password.")
    if "CIM server" in message:
        return (
            f"{message}\n\nThe DhcpServer cmdlets run on the machine running "
            f"SappiWhere, as the stored account, and this is that machine's "
            f"local WMI/CIM refusing the account. Check its WMI permissions "
            f"there. Separately, the account still needs membership in the "
            f"DHCP server's local `DHCP Users` group (or Administrators), "
            f"added on the DHCP server itself.")
    if "DhcpServer" in message and "not loaded" in message:
        return (
            f"{message}\n\nThe DhcpServer PowerShell module must be installed "
            f"on the machine running SappiWhere (the DHCP server itself needs "
            f"nothing extra). As Administrator there:\n"
            f"  Server OS: Install-WindowsFeature RSAT-DHCP\n"
            f"  Client OS: Add-WindowsCapability -Online -Name "
            f"Rsat.DHCP.Tools~~~~0.0.1.0\n"
            f"Confirm with: Get-Module -ListAvailable DhcpServer")
    return message


def _raw_output_message(returncode: int, stdout: str, stderr: str) -> str:
    """Shows exactly what PowerShell printed when its output could not be
    parsed as the expected JSON. Whole stdout/stderr, not just the last
    line — the useful detail on failure is often earlier."""
    parts = [f"PowerShell exited with code {returncode}."]
    if stdout:
        parts.append(f"stdout:\n{stdout}")
    if stderr:
        parts.append(f"stderr:\n{stderr}")
    if not stdout and not stderr:
        parts.append("It produced no output on either stdout or stderr.")
    return "\n\n".join(parts)


def _staging_error(detail: str) -> str:
    """The message for "could not write the script file", with the cause an
    operator can actually act on appended, in the manner of _friendly_error.

    This is the failure a real install reported on every poll:

        DHCP poll of CLQWSRTM1 failed: [Errno 2] No such file or directory:
        'C:\\Users\\ADMNA-~1\\AppData\\Local\\Temp\\2\\sappi-dhcp-z3_6xg__.ps1'

    Nothing in that line says which machine, which folder, or why a folder
    Python was told to use is not there — and the `\\Temp\\2` is the tell: a
    per-session temp folder, which Windows removes when the Remote Desktop
    session that owned it ends. A service launched from that session keeps
    the dead path in its environment for as long as it runs, so the poll
    fails every cycle, not intermittently. temppath.writable_tempdir() now
    routes around the missing folder; this message is for when even that
    finds nowhere, or the folder it found vanished before we could use it."""
    return (
        f"Could not write the PowerShell script this poll runs: {detail}\n\n"
        f"This is on the machine running SappiWhere, not the DHCP server. "
        f"Every poll writes its script to a temporary .ps1 file and hands "
        f"that file to PowerShell, so with no writable temporary folder no "
        f"DHCP server can be polled at all — expect every server here to "
        f"show this same error until it is fixed. The usual cause is that the "
        f"temporary folder the service was told to use no longer exists: a "
        f"service started from a Remote Desktop session inherits that "
        f"session's per-session temp folder (...\\AppData\\Local\\Temp\\<n>), "
        f"which Windows deletes when the session ends. Point the service at a "
        f"folder that outlives any logon session — for a service installed "
        f"with NSSM as the README describes:\n"
        f"  nssm set SappiWhere AppEnvironmentExtra TEMP=C:\\Windows\\Temp TMP=C:\\Windows\\Temp\n"
        f"  nssm restart SappiWhere\n"
        f"or set TEMP and TMP as system-wide (not per-user) environment "
        f"variables and restart the service. If the folder does exist, the "
        f"detail above says what else was wrong with it — full disk, or an "
        f"account with no write permission there.")


def _run(script: str, server: str, timeout_s: float,
        username: str | None = None, password: str | None = None) -> dict:
    server = _validate_address(server)
    binary = _powershell_binary()
    env = dict(os.environ)
    env["SAPPI_DHCP_SERVER"] = server
    # Blank rather than absent either way, so the script's IsNullOrEmpty
    # check is the one source of truth for "was a credential given" — no
    # separate flag that could disagree with whether the value is actually
    # usable.
    env["SAPPI_DHCP_USERNAME"] = username or ""
    env["SAPPI_DHCP_PASSWORD"] = password or ""
    # Five seconds inside the Python limit, so the job is cleaned up here.
    env["SAPPI_DHCP_TIMEOUT_S"] = str(max(5, int(timeout_s) - 5))

    # A temp .ps1 file rather than piping the script in on stdin with
    # `-Command -`: that form is unreliable for a multi-statement script with
    # scriptblocks and try/catch on native Windows PowerShell — it can exit 0
    # having read and executed nothing at all, with no output on either
    # stream to say why. `-File` is the officially supported way to run a
    # script and does not have that failure mode. UTF-8 with a BOM so Windows
    # PowerShell 5.1 — which, unlike pwsh, guesses a script's encoding from
    # its byte order mark and otherwise assumes the system codepage — reads
    # it correctly regardless of what that codepage is.
    #
    # Where that file goes is decided on every call, never at import: the
    # directory `%TEMP%` names can stop existing while this process runs (a
    # per-session temp folder deleted under a service — see _staging_error),
    # and tempfile's own cached answer would keep pointing at it for the life
    # of the process. writable_tempdir() re-creates a vanished folder, or
    # finds another, and proves it is writable before handing it over.
    #
    # `script_path` is bound before the try so the cleanup below cannot
    # itself raise UnboundLocalError when staging fails — that would replace
    # the real error with a meaningless one — and the whole of staging sits
    # inside the try so the password scrub in `finally` runs no matter where
    # the failure happens.
    script_path = None
    try:
        try:
            fd, script_path = tempfile.mkstemp(
                suffix=".ps1", prefix="sappi-dhcp-", dir=writable_tempdir())
            with os.fdopen(fd, "w", encoding="utf-8-sig") as handle:
                handle.write(script)
        except (RuntimeError, OSError) as exc:
            # RuntimeError is the resolver saying it found nowhere at all;
            # OSError is the folder it found failing us anyway — deleted in
            # the moment between its probe and our write, or a full disk.
            # Either way a bare OSError in the log names a path and nothing
            # else, which is the report this fix started from.
            raise DhcpUnavailable(_staging_error(str(exc)))
        try:
            completed = subprocess.run(
                [binary, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", script_path],
                capture_output=True, text=True, timeout=timeout_s,
                env=env, **hidden())
        except subprocess.TimeoutExpired:
            raise DhcpUnavailable(
                f"{server} did not respond within {timeout_s:.0f}s")
        except OSError as exc:
            # The binary shutil.which found a moment ago could not be
            # started — removed, or denied to this account. Name it: the
            # OSError alone says "[WinError 2]" and leaves the operator to
            # guess which of several files it means.
            raise DhcpUnavailable(f"Could not start PowerShell ({binary}): {exc}")
    finally:
        # The password lived in this dict only as long as the call took;
        # drop the reference rather than let it linger in a local variable
        # for the rest of whatever calls _run(). This runs on every exit
        # path above, including a failure to stage the script at all.
        env["SAPPI_DHCP_PASSWORD"] = ""
        if script_path is not None:
            try:
                os.remove(script_path)
            except OSError:
                pass

    output = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if not output:
        raise DhcpUnavailable(_raw_output_message(completed.returncode, output, stderr))

    # PowerShell can print more than the JSON — a progress line, a warning —
    # ahead of it; take the last line, which is where ConvertTo-Json -Compress
    # always lands since nothing after it writes to stdout.
    line = output.splitlines()[-1]
    try:
        payload = json.loads(line)
    except ValueError:
        raise DhcpUnavailable(_raw_output_message(completed.returncode, output, stderr))

    if isinstance(payload, dict) and payload.get("error"):
        raise DhcpUnavailable(_friendly_error(payload["error"]))
    if isinstance(payload, dict) and payload.get("ok") is False:
        raise DhcpUnavailable(_friendly_error(payload.get("error") or "Unknown error"))
    return payload


def _as_list(value) -> list:
    """ConvertTo-Json collapses a one-element array to a bare object in some
    PowerShell versions; normalize both shapes here rather than trust the
    script's own @() wrapping to survive every version this runs against."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _parse_iso(text: str | None) -> float | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def stored_mac(client_id) -> str | None:
    """A lease's ClientId as dhcp_leases.mac stores it — the one place the
    rule lives: ingest calls it per row here, and IpamDatabase's open-time
    rewrite of an older store calls the same function rather than restate
    it, so the two cannot drift.

    The DhcpServer module reports a client as `AA-BB-CC-DD-EE-FF` — dashes,
    upper case — where everything else in ipam.db holds a MAC the way
    ipam_scan.mac_colon() writes it (`aa:bb:cc:dd:ee:ff`): the sweep's
    hosts.mac comes straight out of that function. Leaving the DHCP form
    as-is meant a lease and the sweep's sighting of the same card never
    compared equal, and an operator typing the colon form into the search
    box never found a lease at all. Converting here, at ingest, is what
    lets an exact lookup use the index on the column instead of every
    reader re-deriving the canonical spelling for itself.

    A ClientId that is not a MAC — a DHCPv6 DUID, a hardware-type-prefixed
    id on a BOOTP reservation — is kept as the server reported it rather
    than blanked: the lease table shows the column, and an empty cell would
    read as "the server has no client id", which is not what happened.
    """
    text = (client_id or "").strip() if isinstance(client_id, str) else client_id
    if not text:
        return None
    return mac_colon(text) or text


@dataclass
class DhcpSnapshot:
    scopes: list[dict] = field(default_factory=list)
    leases: list[dict] = field(default_factory=list)
    reservations: list[dict] = field(default_factory=list)


def poll(server: str, timeout_s: float = 30.0,
        username: str | None = None, password: str | None = None) -> DhcpSnapshot:
    """One read-only snapshot of every scope, lease and reservation. Raises
    DhcpUnavailable on anything short of success — no partial results, since
    the caller replaces its stored snapshot wholesale. Pass username/password
    already decrypted; this function never touches DPAPI."""
    payload = _run(_SCRIPT, server, timeout_s, username, password)

    reservations = _as_list(payload.get("reservations"))
    reserved_ips = {r.get("ip") for r in reservations if r.get("ip")}

    leases = []
    for row in _as_list(payload.get("leases")):
        leases.append({
            "scope_id": row.get("scope_id"),
            "ip": row.get("ip"),
            "mac": stored_mac(row.get("mac")),
            "hostname": row.get("hostname"),
            "address_state": row.get("address_state"),
            "lease_expires_ts": _parse_iso(row.get("lease_expires")),
            "is_reservation": bool(row.get("is_reservation")) or row.get("ip") in reserved_ips,
            "description": None,
        })

    reservation_by_ip = {r.get("ip"): r for r in reservations if r.get("ip")}
    for ip, res in reservation_by_ip.items():
        for lease in leases:
            if lease["ip"] == ip:
                lease["description"] = res.get("name") or res.get("description")
                break
        else:
            # A reservation with no matching lease row — never claimed by a
            # client, so it would otherwise be invisible.
            leases.append({
                "scope_id": res.get("scope_id"), "ip": ip,
                "mac": stored_mac(res.get("mac")),
                "hostname": None, "address_state": "ReservedUnclaimed",
                "lease_expires_ts": None, "is_reservation": True,
                "description": res.get("name") or res.get("description"),
            })

    scopes = []
    for row in _as_list(payload.get("scopes")):
        scopes.append({
            "scope_id": row.get("scope_id"), "name": row.get("name"),
            "start_ip": row.get("start_ip"), "end_ip": row.get("end_ip"),
            "mask": row.get("mask"), "state": row.get("state"),
            "lease_duration_s": row.get("lease_duration_s"),
            "description": row.get("description"), "router": row.get("router"),
        })

    return DhcpSnapshot(scopes=scopes, leases=leases, reservations=reservations)


def test_connection(server: str, timeout_s: float = 15.0,
                    username: str | None = None, password: str | None = None) -> dict:
    """A fast reachability check for a "Test connection" button: version and
    scope count, without walking every scope's leases."""
    payload = _run(_TEST_SCRIPT, server, timeout_s, username, password)
    return {
        "ok": True,
        "version": f"{payload.get('major', '?')}.{payload.get('minor', '?')}",
        "scope_count": payload.get("scope_count", 0),
    }

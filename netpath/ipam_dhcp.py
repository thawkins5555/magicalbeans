"""Read-only polling of a Windows DHCP server's scopes and leases, via
PowerShell `DhcpServer` cmdlets — either ambient Windows identity
(`-ComputerName`, local module) or a stored credential over
`Invoke-Command -Credential` (module runs on the DHCP server itself). All
scripts are fixed constants; server name/username/password travel as
environment variables, never woven into command text.
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

from .worker import hidden

IS_WINDOWS = os.name == "nt"

# A hostname, FQDN or IPv4/IPv6 address. Loose enough for real server names,
# strict enough to refuse anything that would be meaningful to a shell — belt
# and braces alongside the environment-variable passing above, which is the
# actual injection defense.
_VALID_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,253}$")

# The DHCP query itself, as a scriptblock rather than inline: the ambient path
# runs it locally (Import-Module + -ComputerName, over RPC), the credentialed
# path hands the identical block to Invoke-Command to run on the DHCP server
# itself (over WinRM). One definition, so the two paths cannot drift apart and
# report different shapes of data.
_BODY = r"""
$body = {
    param($ComputerName)
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

# Every verb below is Get-, plus Import-Module and formatting/output cmdlets,
# with one exception: Invoke-Command, used only to run the fixed $body
# scriptblock above on the DHCP server when a stored credential is supplied.
# It is never handed a string built at runtime.
_SCRIPT = _BODY + r"""
$ErrorActionPreference = 'Stop'
$server   = $env:SAPPI_DHCP_SERVER
$username = $env:SAPPI_DHCP_USERNAME
try {
    if ([string]::IsNullOrEmpty($username)) {
        $result = & $body $server
    } else {
        $securePw = ConvertTo-SecureString $env:SAPPI_DHCP_PASSWORD -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($username, $securePw)
        # Runs ON the DHCP server over WinRM, so $ComputerName targeting the
        # server's own name works the same as "localhost" would.
        $result = Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock $body -ArgumentList $server
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
$probe = {
    param($ComputerName)
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
        $result = Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock $probe -ArgumentList $server
    }
    $result | ConvertTo-Json -Compress
} catch {
    [ordered]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
"""


class DhcpUnavailable(Exception):
    """PowerShell, the DhcpServer module, or the target server did not
    answer — no PowerShell/RSAT tools, or the remote call itself failed."""


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
    """Append actionable guidance to a handful of WinRM errors this module's
    credentialed path is known to hit, without hiding the original message —
    the person editing the DHCP server still sees exactly what PowerShell
    said, just with the fix appended rather than left as a lookup exercise.
    """
    if "TrustedHosts" in message:
        return (
            f"{message}\n\nThis is a WinRM client setting on the machine "
            f"running SappiWhere, not the DHCP server — by default it will "
            f"only use Kerberos to authenticate a remote target, and "
            f"Kerberos cannot vouch for a bare IP address, only a hostname. "
            f"Easiest fix: edit this server here and use its hostname or "
            f"FQDN instead of its IP address; that alone resolves it, no "
            f"WinRM configuration needed. If it must stay an IP address, "
            f"add it to TrustedHosts on the SappiWhere machine instead, run "
            f"as Administrator:\n"
            f"  winrm set winrm/config/client '@{{TrustedHosts=\"<address>\"}}'\n"
            f"That falls back to NTLM and skips verifying the server's "
            f"identity, so prefer the hostname fix where the address has one.")
    if "CIM server" in message:
        return (
            f"{message}\n\nThis one is on the DHCP server itself: WinRM "
            f"reached it and authenticated fine, but once there, the "
            f"DhcpServer cmdlets talk to it over CIM/WMI, and this account "
            f"isn't authorized for that — a different permission from "
            f"WinRM access. It needs membership in the DHCP server's local "
            f"`DHCP Users` group (Administrator rights are not required, "
            f"just that group), added on the DHCP server itself, not here."
        )
    if "DhcpServer" in message and "not loaded" in message:
        return (
            f"{message}\n\nAlso on the DHCP server itself: the script got "
            f"this far — WinRM and CIM access both worked — but the "
            f"server's PowerShell management module for DHCP isn't "
            f"installed there, separately from the DHCP Server role "
            f"actually running. Fix, on the DHCP server as Administrator:\n"
            f"  Install-WindowsFeature RSAT-DHCP\n"
            f"Confirm with: Get-Module -ListAvailable DhcpServer\n\n"
            f"If that already shows the module installed and this error "
            f"still happens, the WinRM service itself was already running "
            f"before the feature was added and is still using its old "
            f"environment — an interactive session picks up the change "
            f"immediately, a long-running service does not. Restart it, "
            f"on the DHCP server:\n"
            f"  Restart-Service WinRM\n"
            f"A full reboot of the DHCP server is the fallback if that "
            f"alone doesn't clear it.")
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

    # A temp .ps1 file rather than piping the script in on stdin with
    # `-Command -`: that form is unreliable for a multi-statement script with
    # scriptblocks and try/catch on native Windows PowerShell — it can exit 0
    # having read and executed nothing at all, with no output on either
    # stream to say why. `-File` is the officially supported way to run a
    # script and does not have that failure mode. UTF-8 with a BOM so Windows
    # PowerShell 5.1 — which, unlike pwsh, guesses a script's encoding from
    # its byte order mark and otherwise assumes the system codepage — reads
    # it correctly regardless of what that codepage is.
    fd, script_path = tempfile.mkstemp(suffix=".ps1", prefix="sappi-dhcp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as handle:
            handle.write(script)
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
            raise DhcpUnavailable(str(exc))
    finally:
        # The password lived in this dict only as long as the call took;
        # drop the reference rather than let it linger in a local variable
        # for the rest of whatever calls _run().
        env["SAPPI_DHCP_PASSWORD"] = ""
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
            "mac": row.get("mac"),
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
                "scope_id": res.get("scope_id"), "ip": ip, "mac": res.get("mac"),
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

"""Read-only polling of a Windows DHCP server's scopes and leases.

Two ways to authenticate, and a server can use either:

* **Ambient identity** (the default). The DhcpServer module's own `Get-*`
  cmdlets are called with `-ComputerName`, which authenticates as whichever
  Windows account is running SappiWhere — or, if Windows Credential Manager
  on this machine has an entry for that server's name, whatever credential
  Windows itself picks for that target. This needs the `DhcpServer` module
  installed locally (on the machine running SappiWhere), talks to the DHCP
  server over its own RPC endpoint, and needs nothing enabled there beyond
  what the DHCP Server role already opens.

* **A stored credential**, for a server whose `username` and `password_enc`
  columns are set. The username and the *already-decrypted* password are
  passed in by the caller — this module never touches DPAPI itself, see
  dpapi.py — and the script runs the same query through `Invoke-Command
  -Credential`, over PowerShell remoting. That scriptblock executes ON the
  DHCP server rather than being relayed through it, so this path needs WinRM
  reachable on the DHCP server and the `DhcpServer` module present there,
  which a real DHCP server almost always already has since it ships with the
  role. It does not need the module installed on the SappiWhere machine.

Either way, nothing here can write to a DHCP server. The scripts below are
fixed constants, never built from user input. The server name, and the
username and password when a stored credential is used, all travel as
environment variables rather than being woven into command text, so there is
no string for any of them to inject into. Every DHCP cmdlet called is a
`Get-`; `Invoke-Command` only ever runs the one fixed scriptblock defined in
this file, never a string built at runtime.

The password exists as plaintext for as short a window as this design
allows: decrypted by the caller just before the call, read by PowerShell out
of an environment variable and immediately wrapped in a SecureString, and
never written to a log, an error message, or disk. It is still plaintext in
memory for that window, in the Python process and the child PowerShell
process both — there is no way to hand a script a password it can use
without it existing somewhere before that use.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .procs import hidden

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
        [ordered]@{
            scope_id         = $_.ScopeId.ToString()
            name             = $_.Name
            start_ip         = $_.StartRange.ToString()
            end_ip           = $_.EndRange.ToString()
            mask             = $_.SubnetMask.ToString()
            state            = $_.State.ToString()
            lease_duration_s = [int]$_.LeaseDuration.TotalSeconds
            description      = $_.Description
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
    """PowerShell, the DhcpServer module, or the target server did not answer.

    Distinct from a plain connection failure so the caller can show the
    person a reason rather than a bare traceback: no PowerShell on this host,
    the RSAT DHCP tools are not installed, or the remote call itself failed
    (unreachable, access denied, no matching Credential Manager entry).
    """


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
    """Build a diagnostic message that shows exactly what PowerShell printed,
    for cases where we could not make sense of it (empty output, or output
    that was not the JSON we expected). Used instead of a generic summary so
    the person editing the DHCP server can see the real error — a module not
    found, an access-denied, a WinRM trust failure — rather than just being
    told parsing failed.

    Whole stdout and stderr, not just the last line: the JSON line is always
    last when things succeed, but when they don't, the useful detail (an
    exception message, a stack trace) is usually earlier and would otherwise
    be thrown away.
    """
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
    """One read-only snapshot of every scope, lease and reservation.

    Raises DhcpUnavailable on anything short of success — no partial results,
    since the caller replaces its stored snapshot wholesale and a partial one
    would look like scopes or leases had been deleted from the server.

    Pass username and password already decrypted — this function never
    touches DPAPI, so if a caller is storing an encrypted credential, it must
    decrypt it just before this call and let it go out of scope right after.
    """
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
            "description": row.get("description"),
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

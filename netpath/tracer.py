"""Traceroute execution and output parsing.

Uses the operating system's own traceroute/tracert binary so no elevated
privileges or raw sockets are required. Output is parsed into a TraceResult
that keeps every address seen at every TTL, which is what makes divergent
paths visible.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

from .procs import hidden
from statistics import mean

IS_WINDOWS = os.name == "nt"
IS_LINUX = os.name != "nt" and os.uname().sysname == "Linux"

# Butskoy's traceroute, the Linux one, sends up to this many probes at once
# (its own -N default). Windows tracert is strictly serial, and the BSD
# traceroute macOS ships has no -N at all, so both stay at 1.
PROBE_PARALLELISM = 16 if IS_LINUX else 1

# Set to False once a traceroute has rejected -N, so a build without it (an
# embedded busybox, say) costs one failed run rather than every run.
_SUPPORTS_PARALLEL: bool = IS_LINUX

# The header line names the address the traceroute binary itself resolved,
# which is the one the probes actually went to.
_UNIX_HEADER = re.compile(r"^traceroute to \S+ \(([0-9A-Fa-f:.]+)\)", re.M)
_WIN_HEADER = re.compile(r"^\s*Tracing route to \S+ \[([0-9A-Fa-f:.]+)\]", re.M | re.I)

_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
_UNIX_TIME = re.compile(r"^\d+(?:\.\d+)?$")
_WIN_TIME = re.compile(r"^<?\d+$")
_BRACKETED = re.compile(r"\[([0-9A-Fa-f:.]+)\]")

# ICMP destination-unreachable annotations. A router that sends one of these is
# actively refusing the packet and saying so, which is a different fault from
# silence: the path to that router works, and something past it said no.
UNREACHABLE_CODES = {
    "!": "unreachable, reason not stated",
    "!H": "host unreachable",
    "!N": "network unreachable",
    "!P": "protocol unreachable",
    "!S": "source route failed",
    "!F": "fragmentation needed",
    "!X": "administratively prohibited",
    "!V": "host precedence violation",
    "!C": "precedence cutoff",
    "!A": "administratively prohibited",
}

WINDOWS_UNREACHABLE = {
    "destination host unreachable": "!H",
    "destination net unreachable": "!N",
    "destination network unreachable": "!N",
    "destination protocol unreachable": "!P",
    "destination port unreachable": "!P",
    "communication administratively prohibited": "!X",
}


def _windows_unreachable_code(text: str) -> str | None:
    lowered = (text or "").lower()
    for phrase, code in WINDOWS_UNREACHABLE.items():
        if phrase in lowered:
            return code
    return None


def unreachable_text(code: str | None) -> str:
    if not code:
        return ""
    return UNREACHABLE_CODES.get(code, f"ICMP unreachable {code}")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


@dataclass
class Hop:
    """One TTL of a trace. May hold several addresses when the path forks."""

    ttl: int
    addrs: dict[str, list[float]] = field(default_factory=dict)
    sent: int = 0
    lost: int = 0
    # ICMP annotations keyed by the address that sent them, e.g. {"10.0.0.1": "!H"}
    annotations: dict[str, str] = field(default_factory=dict)

    @property
    def rtts(self) -> list[float]:
        return [r for rtts in self.addrs.values() for r in rtts]

    @property
    def loss_pct(self) -> float:
        return 100.0 * self.lost / self.sent if self.sent else 0.0

    @property
    def avg_rtt(self) -> float | None:
        rtts = self.rtts
        return mean(rtts) if rtts else None

    def primary_ip(self) -> str | None:
        """The address that answered the most probes at this TTL."""
        if not self.addrs:
            return None
        return max(self.addrs.items(), key=lambda kv: (len(kv[1]), kv[0]))[0]


@dataclass
class TraceResult:
    host: str
    dest_ip: str | None
    hops: list[Hop]
    reached: bool
    started_ts: float
    duration_s: float
    error: str | None = None
    # Kept for the debug page: what was actually run, and what came back.
    command: list[str] = field(default_factory=list)
    raw_output: str = ""

    @property
    def unreachable(self) -> tuple[str, str] | None:
        """(code, responding address) if a router refused the packet."""
        for hop in reversed(self.hops):
            for address, code in hop.annotations.items():
                return code, address
        return None

    @property
    def unreachable_code(self) -> str | None:
        found = self.unreachable
        return found[0] if found else None

    @property
    def unreachable_from(self) -> str | None:
        found = self.unreachable
        return found[1] if found else None

    def path_signature(self) -> str:
        parts = [hop.primary_ip() or "*" for hop in self.hops]
        joined = ">".join(parts)
        return hashlib.sha1(joined.encode()).hexdigest()[:16]

    def path_text(self) -> str:
        return " > ".join(hop.primary_ip() or "*" for hop in self.hops)

    def dest_hop(self) -> Hop | None:
        """The hop that answered as the destination, else the last hop."""
        if self.dest_ip:
            for hop in reversed(self.hops):
                if self.dest_ip in hop.addrs:
                    return hop
        return self.hops[-1] if self.hops else None

    def dest_rtt(self) -> float | None:
        hop = self.dest_hop()
        if hop is not None and hop.avg_rtt is not None:
            return hop.avg_rtt

        # A refusal often carries no timing of its own — Windows prints the
        # "reports: Destination host unreachable" line with no ms columns — but
        # the router that refused usually answered an earlier TTL, and that is
        # a real measurement of the path up to the point it was rejected.
        found = self.unreachable
        if found:
            _, address = found
            for candidate in reversed(self.hops):
                rtts = candidate.addrs.get(address)
                if rtts:
                    return mean(rtts)
            for candidate in reversed(self.hops):
                if candidate.avg_rtt is not None:
                    return candidate.avg_rtt
        return None

    @property
    def rtt_is_to_refuser(self) -> bool:
        """True when dest_rtt measures the refusing router, not the target."""
        hop = self.dest_hop()
        if hop is not None and hop.avg_rtt is not None:
            return False
        return self.unreachable is not None and self.dest_rtt() is not None

    def dest_loss(self) -> float:
        hop = self.dest_hop()
        if hop is None:
            return 100.0
        return hop.loss_pct


class TracerouteUnavailable(RuntimeError):
    pass


def _binary() -> str:
    name = "tracert" if IS_WINDOWS else "traceroute"
    path = shutil.which(name)
    if not path:
        raise TracerouteUnavailable(
            f"{name} was not found on this system. "
            + (
                "Install it with your package manager, e.g. "
                "'sudo apt install traceroute' or 'sudo dnf install traceroute'."
                if not IS_WINDOWS
                else "tracert ships with Windows; check your PATH."
            )
        )
    return path


def _build_command(host: str, max_hops: int, probes: int, timeout_s: float,
                   parallel: bool = True) -> list[str]:
    exe = _binary()
    if IS_WINDOWS:
        # tracert always sends 3 probes per hop and has no -q equivalent.
        return [exe, "-d", "-h", str(max_hops), "-w", str(int(timeout_s * 1000)), host]
    command = [
        exe,
        "-n",
        "-q", str(probes),
        "-m", str(max_hops),
        "-w", str(int(max(1, timeout_s))),
    ]
    if parallel and _SUPPORTS_PARALLEL:
        # Ask for the parallelism explicitly rather than inheriting whatever
        # the build defaults to, so expected_budget below is arithmetic about
        # this run rather than a guess.
        command += ["-N", str(PROBE_PARALLELISM)]
    return command + [host]


def _parse_unix(output: str) -> list[Hop]:
    hops: list[Hop] = []
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if not match:
            continue
        hop = Hop(ttl=int(match.group(1)))
        tokens = match.group(2).split()
        current: str | None = None
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "*":
                hop.sent += 1
                hop.lost += 1
                i += 1
                continue
            if token.startswith("!"):
                # An annotation such as !H belongs to the address that answered,
                # and is not itself a probe result.
                if current is not None:
                    hop.annotations[current] = token
                i += 1
                continue
            if _UNIX_TIME.match(token) and i + 1 < len(tokens) and tokens[i + 1] == "ms":
                hop.sent += 1
                if current is not None:
                    hop.addrs.setdefault(current, []).append(float(token))
                else:
                    hop.lost += 1
                i += 2
                continue
            # Anything else is an address, possibly "name (1.2.3.4)".
            addr = token
            if i + 1 < len(tokens) and tokens[i + 1].startswith("("):
                addr = tokens[i + 1].strip("()")
                i += 2
            else:
                i += 1
            current = addr
            hop.addrs.setdefault(current, [])
        hops.append(hop)
    return hops


def _parse_windows(output: str) -> list[Hop]:
    hops: list[Hop] = []
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if not match:
            continue
        hop = Hop(ttl=int(match.group(1)))
        tokens = match.group(2).split()
        times: list[float | None] = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "*":
                times.append(None)
                i += 1
                continue
            if _WIN_TIME.match(token) and i + 1 < len(tokens) and tokens[i + 1] == "ms":
                times.append(0.5 if token.startswith("<") else float(token))
                i += 2
                continue
            break
        tail = " ".join(tokens[i:])
        refusal = _windows_unreachable_code(tail)
        if not times and not refusal and not _first_address(tail):
            # No timings, no phrase we know and no address: not a hop line.
            continue
        ip = None
        bracket = _BRACKETED.search(tail)
        if bracket:
            ip = bracket.group(1)
        elif tail:
            # On a plain hop the tail is just the address, but an unreachable
            # line reads "10.0.0.1  reports: Destination host unreachable.",
            # so take the first address-looking token rather than the last.
            for token in tail.split():
                candidate = token.strip("[]")
                if _is_ip(candidate):
                    ip = candidate
                    break
        hop.sent = len(times)
        for value in times:
            if value is None or ip is None:
                hop.lost += 1
            else:
                hop.addrs.setdefault(ip, []).append(value)
        if ip is not None:
            hop.addrs.setdefault(ip, [])

        if not refusal and not times and ip is not None:
            # Match on the structure, not on English: a numbered line naming a
            # router with no "ms" columns is that router refusing the packet.
            # On a German tracert ("meldet: Zielhost nicht erreichbar") the
            # phrase table finds nothing and the whole hop used to be dropped
            # from the result, so a refusal degraded to silence and the
            # timeline said "fail" where it should say "blocked".
            refusal = "!"
        if refusal:
            hop.annotations[ip or "?"] = refusal
        hops.append(hop)
    return hops


def _first_address(text: str) -> str | None:
    """The first address-looking token in a line, brackets stripped."""
    bracket = _BRACKETED.search(text or "")
    if bracket:
        return bracket.group(1)
    for token in (text or "").split():
        candidate = token.strip("[]")
        if _is_ip(candidate):
            return candidate
    return None


def expected_budget(max_hops: int, probes: int, timeout_s: float = 2.0,
                    parallel: int | None = None) -> float:
    """Worst-case run time for a trace, used to kill it and to flag a slow one.

    Shared so the watchdog in run_trace and the debug page's "overdue" marker
    can never disagree about what too long means.

    The old formula assumed strictly serial probes, which is true of Windows
    tracert and of nothing else: Linux traceroute sends 16 at a time, so a
    fully black-holed 30-hop path finishes in about 12 s rather than the 195 s
    the arithmetic claimed. Being 16x too generous is not harmless — a
    genuinely hung binary held a worker for the whole of it — and it made the
    documented remedy, lowering the hop count, buy far less than stated.
    """
    if parallel is None:
        parallel = PROBE_PARALLELISM if _SUPPORTS_PARALLEL else 1
    rounds = math.ceil(max_hops / max(1, parallel))
    return rounds * probes * timeout_s + 15


def _run(command: list[str], budget: float):
    """One traceroute run. The C locale keeps the binary's own wording in
    English so the unreachable phrases stay recognisable on a host with a
    localised environment."""
    env = dict(os.environ)
    if not IS_WINDOWS:
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=budget,
        env=env,
        # Otherwise every trace flashes a console window when the parent
        # has none of its own, which is the case under pythonw.exe.
        **hidden(),
    )


def _rejected_parallel(completed, output: str) -> bool:
    """True when the run failed because the binary does not know -N."""
    if IS_WINDOWS or not _SUPPORTS_PARALLEL or completed.returncode == 0:
        return False
    lowered = (output or "").lower()
    return any(phrase in lowered for phrase in
               ("invalid option", "unrecognized option", "unknown option",
                "usage:", "illegal option"))


_UNIX_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
_WIN_PING_TIME = re.compile(r"time[=<]\s*(\d+)\s*ms", re.IGNORECASE)


@dataclass
class PingResult:
    """One ICMP echo probe to a single address, for continuous hop probing
    (MTR-style loss/RTT stats) rather than a full multi-hop traceroute."""

    ip: str
    sent: int
    lost: int
    rtt_ms: float | None
    error: str | None = None


def _ping_command(ip: str, timeout_s: float) -> list[str]:
    exe = shutil.which("ping") or "ping"
    if IS_WINDOWS:
        return [exe, "-n", "1", "-w", str(max(1, int(timeout_s * 1000))), ip]
    return [exe, "-n", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]


def ping(ip: str, timeout_s: float = 1.5) -> PingResult:
    """One ICMP echo probe. Never raises — a failure comes back as full loss,
    the same convention run_trace() uses for traceroute."""
    command = _ping_command(ip, timeout_s)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_s + 2,
            **hidden(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PingResult(ip, 1, 1, None, error=str(exc))
    output = completed.stdout + "\n" + completed.stderr
    pattern = _WIN_PING_TIME if IS_WINDOWS else _UNIX_PING_TIME
    match = pattern.search(output)
    if match:
        return PingResult(ip, 1, 0, float(match.group(1)))
    return PingResult(ip, 1, 1, None)


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def run_trace(
    host: str,
    max_hops: int = 30,
    probes: int = 3,
    timeout_s: float = 2.0,
) -> TraceResult:
    """Run one traceroute and return the parsed result.

    Never raises for network problems: failures come back as a result with
    an error string set.
    """
    started = time.time()
    dest_ip = resolve(host)

    if dest_ip is None:
        return TraceResult(
            host=host,
            dest_ip=None,
            hops=[],
            reached=False,
            started_ts=started,
            duration_s=time.time() - started,
            error=f"Could not resolve {host}",
        )

    try:
        command = _build_command(host, max_hops, probes, timeout_s)
    except TracerouteUnavailable as exc:
        return TraceResult(host, dest_ip, [], False, started, 0.0, error=str(exc))

    budget = expected_budget(max_hops, probes, timeout_s)
    try:
        completed = _run(command, budget)
        output = completed.stdout + "\n" + completed.stderr
        if _rejected_parallel(completed, output):
            # This build has no -N. Remember that, and run it again without.
            globals()["_SUPPORTS_PARALLEL"] = False
            command = _build_command(host, max_hops, probes, timeout_s)
            budget = expected_budget(max_hops, probes, timeout_s)
            completed = _run(command, budget)
            output = completed.stdout + "\n" + completed.stderr
    except subprocess.TimeoutExpired:
        return TraceResult(
            host, dest_ip, [], False, started, time.time() - started,
            error=f"traceroute did not finish within {budget:.0f}s",
            command=command,
        )
    except OSError as exc:
        return TraceResult(host, dest_ip, [], False, started, time.time() - started,
                           error=str(exc), command=command)

    hops = _parse_windows(output) if IS_WINDOWS else _parse_unix(output)
    # The binary prints the address it resolved in its header line. For a
    # round-robin, GSLB or anycast name that is routinely not the address this
    # process resolved a moment earlier, and comparing the final hop against
    # our answer recorded a perfectly successful trace as reached=0 for ever.
    header = (_WIN_HEADER if IS_WINDOWS else _UNIX_HEADER).search(output)
    header_ip = header.group(1) if header else None

    # tracert can print the refusal on a line of its own, with no hop number,
    # after the numbered hops. Attribute it to the last router that answered.
    if hops and not any(hop.annotations for hop in hops):
        code = _windows_unreachable_code(output)
        if code:
            for hop in reversed(hops):
                address = hop.primary_ip()
                if address:
                    hop.annotations[address] = code
                    break

    wanted = {ip for ip in (dest_ip, header_ip) if ip}
    reached = any(address in hop.addrs for hop in hops for address in wanted)

    error = None
    if not hops:
        error = (output.strip().splitlines() or ["traceroute produced no output"])[0][:200]

    return TraceResult(
        host=host,
        dest_ip=dest_ip,
        hops=hops,
        reached=reached,
        started_ts=started,
        duration_s=time.time() - started,
        error=error,
        command=command,
        raw_output=output.strip(),
    )

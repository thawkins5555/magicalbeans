"""Take the secrets out of a captured device configuration before it is stored.

A `show running-config` is not a document about a device, it is the device's
credentials: SNMP communities, the local user database, TACACS+ and RADIUS
shared secrets, IPsec pre-shared keys, enable passwords, wireless PSKs. The
review found all of it sitting zlib-compressed (not encrypted) in
configrx.db and served verbatim to anyone with ConfigRX *read*.

Gating the download on write is one half; this is the other. What ConfigRX
exists for is answering "what changed on this switch", and every secret-
bearing line answers that just as well with `<redacted>` where the secret
was: the line is still there, its shape is still there, and a change to it
still shows as a change, because the surrounding text differs whenever the
directive does. What is lost is using a backup as a restore file — and a
restore was never what this feature offered, since the capture is
read-only by construction (configrx.py's `_pull_config`).

Per-device opt-out: `configrx_store_secrets` in the device's ConfigRX
settings, off by default. An operator who genuinely needs the verbatim
text on a particular device turns it on for that device, deliberately, and
the backup rows record which of the two they got.

Scope and honesty about it
--------------------------
This is a pattern list, not a parser, and a pattern list is never
complete: a vendor keyword nobody here has seen goes through untouched.
It covers the directives that actually carry secrets on the two vendor
families ConfigRX ships support for (Cisco IOS/IOS-XE/NX-OS and FortiOS),
plus the handful of cross-vendor spellings that cost nothing to add. The
right way to read a redacted backup is "these secrets are certainly
gone", not "no secret can possibly remain".

Every pattern is anchored on the directive rather than on the secret, so a
line that merely *mentions* one of these words in a description or a
banner is not mangled, and each rewrites only the secret's own token —
the keyword, any encryption-type digit, and everything after the secret
(interface names, `address` clauses, `timeout` values) is preserved so a
diff still reads.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"

# (name, compiled pattern). Each pattern must capture the text to keep in
# group "keep" and the secret in group "secret"; anything after the secret
# is kept by the trailing group "tail" where the directive has one.
#
# All are case-insensitive and anchored to the start of a line (allowing
# leading indentation), because these are configuration directives, not
# prose. `[^\s]` for the secret rather than `.*`: a quoted or spaced
# password is handled by the explicit quoted alternatives below.
_FLAGS = re.MULTILINE | re.IGNORECASE

PATTERNS = [
    # ---------------------------------------------------------- Cisco IOS
    # snmp-server community <string> [RO|RW|view ...|<acl>]
    ("snmp-server community", re.compile(
        r"(?P<keep>^\s*snmp-server\s+community\s+)(?P<secret>\S+)"
        r"(?P<tail>.*)$", _FLAGS)),
    # snmp-server user <user> <group> v3 auth sha <key> priv aes 128 <key>
    ("snmp-server user auth/priv", re.compile(
        r"(?P<keep>^\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+.*?"
        r"\b(?:auth|priv)\s+(?:\S+\s+)*?)(?P<secret>\S+)(?P<tail>\s*$)",
        _FLAGS)),
    # enable secret [level N] [0|5|8|9] <hash>   /   enable password ...
    ("enable secret/password", re.compile(
        r"(?P<keep>^\s*enable\s+(?:secret|password)\s+"
        r"(?:level\s+\d+\s+)?(?:\d+\s+)?)(?P<secret>\S+)(?P<tail>.*)$",
        _FLAGS)),
    # username <name> [privilege N] secret|password [0|5|7|8|9] <secret>
    ("username secret/password", re.compile(
        r"(?P<keep>^\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?"
        r"(?:secret|password)\s+(?:\d+\s+)?)(?P<secret>\S+)(?P<tail>.*)$",
        _FLAGS)),
    # tacacs-server key [7] <key>  /  tacacs-server host X key <key>
    # radius-server key [7] <key>  /  radius-server host X key <key>
    # and the newer "  key 7 <key>" inside a `tacacs server NAME` block.
    ("tacacs/radius key", re.compile(
        r"(?P<keep>^\s*(?:tacacs|radius)-server\s+.*?\bkey\s+(?:\d+\s+)?)"
        r"(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
    ("server-block key", re.compile(
        r"(?P<keep>^\s+key\s+(?:\d+\s+)?)(?P<secret>\S+)(?P<tail>\s*$)",
        _FLAGS)),
    # key-string <key>  (EIGRP/OSPF/NTP authentication key chains)
    ("key-string", re.compile(
        r"(?P<keep>^\s*key-string\s+(?:\d+\s+)?)(?P<secret>\S+)"
        r"(?P<tail>\s*$)", _FLAGS)),
    # crypto isakmp key <key> address 1.2.3.4  /  ... hostname foo
    ("crypto isakmp key", re.compile(
        r"(?P<keep>^\s*crypto\s+isakmp\s+key\s+(?:\d+\s+)?)(?P<secret>\S+)"
        r"(?P<tail>\s+(?:address|hostname)\b.*)$", _FLAGS)),
    # pre-shared-key [local|remote] <key>  (IKEv2 keyrings)
    ("pre-shared-key", re.compile(
        r"(?P<keep>^\s*pre-shared-key\s+(?:local\s+|remote\s+)?"
        r"(?:\d+\s+)?)(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
    # neighbor 1.2.3.4 password [7] <key>  (BGP)
    ("bgp neighbor password", re.compile(
        r"(?P<keep>^\s*neighbor\s+\S+\s+password\s+(?:\d+\s+)?)"
        r"(?P<secret>\S+)(?P<tail>\s*$)", _FLAGS)),
    # ppp chap password / ppp pap sent-username X password Y
    ("ppp password", re.compile(
        r"(?P<keep>^\s*ppp\s+.*?\bpassword\s+(?:\d+\s+)?)(?P<secret>\S+)"
        r"(?P<tail>\s*$)", _FLAGS)),
    # wpa-psk ascii 0 <key> / wlan ... psk <key>
    ("wpa-psk", re.compile(
        r"(?P<keep>^\s*wpa-psk\s+(?:ascii|hex)\s+(?:\d+\s+)?)"
        r"(?P<secret>\S+)(?P<tail>\s*$)", _FLAGS)),

    # ------------------------------------------------------------ FortiOS
    # set password ENC xxxxx / set passwd ENC xxxxx / set psksecret ENC xxx
    # FortiOS quotes its values, so the quoted form is matched first.
    ("fortios set secret (quoted)", re.compile(
        r"(?P<keep>^\s*set\s+(?:password|passwd|psksecret|secondary-secret|"
        r"tertiary-secret|key|private-key|passphrase|auth-password-l1|"
        r"auth-password-l2|ppk-secret)\s+(?:ENC\s+)?)"
        r"(?P<secret>\"[^\"]*\")(?P<tail>\s*$)", _FLAGS)),
    ("fortios set secret", re.compile(
        r"(?P<keep>^\s*set\s+(?:password|passwd|psksecret|secondary-secret|"
        r"tertiary-secret|key|private-key|passphrase|auth-password-l1|"
        r"auth-password-l2|ppk-secret)\s+(?:ENC\s+)?)"
        r"(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
    # FortiOS SNMP communities: `config system snmp community` … set name "x"
    # is not a secret (it is a label); the community itself is the `set
    # query-v1-status`-adjacent `set name`, so nothing is redacted there
    # deliberately — see the module docstring on completeness.
]

# Values that are not secrets and must not be replaced: redacting them
# turns a readable diff into a mystery and, worse, makes an unset password
# look like a set one.
_NOT_SECRET = {"", '""', "''", "none", "no", "disable", "disabled"}


def redact(text: str) -> tuple[str, int]:
    """`text` with every recognised secret replaced by `<redacted>`.

    Returns (redacted text, number of replacements). A count of zero means
    nothing matched — which is the normal case for a switch with no local
    users, no SNMP and no VPN, not a sign that the pass failed.
    """
    if not text:
        return text or "", 0
    total = 0

    def replace(match: re.Match) -> str:
        nonlocal total
        secret = match.group("secret")
        if secret.strip().lower() in _NOT_SECRET:
            return match.group(0)
        total += 1
        tail = match.groupdict().get("tail") or ""
        # A quoted value keeps its quotes, so the line still parses as the
        # vendor's own syntax if anyone reads it back.
        placeholder = f'"{REDACTED}"' if secret.startswith('"') else REDACTED
        return f"{match.group('keep')}{placeholder}{tail}"

    for _name, pattern in PATTERNS:
        text = pattern.sub(replace, text)
    return text, total

"""Strips secrets (SNMP communities, TACACS+/RADIUS keys, PSKs, passwords,
enable secrets) out of a captured device config before it is stored.

Per-device opt-out is `configrx_store_secrets`, off by default. This is a
pattern list, not a parser — best-effort coverage per vendor family (see
`configrx.VENDORS`), not a guarantee that no secret remains; an
unrecognised vendor keyword passes through untouched. Each pattern
anchors on the directive, not the secret, so a diff still reads.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"

# (name, compiled pattern). Each pattern captures "keep" (text to keep),
# "secret", and an optional trailing "tail".
_FLAGS = re.MULTILINE | re.IGNORECASE

PATTERNS = [
    # ---------------------------------------------------------- Cisco IOS
    # snmp-server community <string> [RO|RW|view ...|<acl>]
    ("snmp-server community", re.compile(
        r"(?P<keep>^\s*snmp-server\s+community\s+)(?P<secret>\S+)"
        r"(?P<tail>.*)$", _FLAGS)),
    # snmp-server user ... v3 auth sha <key> priv aes 128 <key> [access <acl>]
    # Two patterns, one per key — a single end-anchored pattern only caught the last token.
    ("snmp-server user auth key", re.compile(
        r"(?P<keep>^\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+.*?"
        r"\bauth\s+\S+\s+)(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
    ("snmp-server user priv key", re.compile(
        r"(?P<keep>^\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+.*?"
        r"\bpriv\s+\S+(?:\s+(?:128|192|256))?\s+)(?P<secret>\S+)(?P<tail>.*)$",
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
    # password sha256 <hash>  (ArubaOS-CX). Must precede "bare line password" below —
    # that pattern's \d+ enc-type would otherwise treat "sha256" itself as the secret.
    ("hp/aruba password sha256", re.compile(
        r"(?P<keep>^\s*password\s+sha256\s+)(?P<secret>\S+)(?P<tail>.*)$",
        _FLAGS)),
    # A bare `password [<enc-type>] <secret>` line (line vty/con/aux blocks).
    # `(?!sha256|encryption)` excludes the sha256 case (handled above) and
    # `encryption` (an IOS type-6 switch, not a password itself).
    ("bare line password", re.compile(
        r"(?P<keep>^\s*password\s+(?!(?:sha256|encryption)\b)(?:\d+\s+)?)"
        r"(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
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
    # FortiOS SNMP communities are a label (`set name`), not a secret — nothing
    # redacted there deliberately.

    # ------------------------------------------------------- Juniper Junos
    # Junos's CLI is `set <hierarchy...> <leaf> <value>`, so these anchor on
    # the leaf keyword with a non-greedy `.*?` for whatever hierarchy precedes
    # it; both quoted and unquoted values are accepted.
    ("junos radius/tacplus secret", re.compile(
        r"(?P<keep>^\s*set\s+system\s+(?:radius-server|tacplus-server)\s+"
        r"\S+\s+secret\s+)(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    ("junos pre-shared-key", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bpre-shared-key\s+ascii-text\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    # OSPF/RIP/NTP simple auth; does not cover NTP's separate "type md5 value" form.
    ("junos authentication-key", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bauthentication-key\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    # set system root-authentication encrypted-password "..."
    # set system login user <name> authentication encrypted-password "..."
    ("junos encrypted-password", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bencrypted-password\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),

    # ---------------------------------------------------- MikroTik RouterOS
    # `/export` output is `key=value` pairs per line, so these anchor on `\b`
    # before the key rather than the line start; no `tail` group needed since
    # any further key=value pairs sit outside the match.
    ("mikrotik password/secret", re.compile(
        r"(?P<keep>\b(?:password|secret)=)(?P<secret>\"[^\"]*\"|\S+)", _FLAGS)),
    ("mikrotik wpa psk", re.compile(
        r"(?P<keep>\bwpa2?-pre-shared-key=)(?P<secret>\"[^\"]*\"|\S+)", _FLAGS)),

    # ------------------------------------------------------------ HP/Aruba
    # snmp-server community and password sha256 reuse the Cisco patterns above
    # (identical syntax) — no separate entry needed.
    #
    # wpa-passphrase <passphrase>  (ArubaOS wireless SSID profile)
    ("hp/aruba wpa-passphrase", re.compile(
        r"(?P<keep>^\s*wpa-passphrase\s+)(?P<secret>\"[^\"]*\"|\S+)"
        r"(?P<tail>.*)$", _FLAGS)),
    # key <n> key-string [cipher|simple] <key>  (Comware/ProCurve; distinct from
    # Cisco's bare key-string above, which has no leading key-id digit)
    ("hp/aruba key-string", re.compile(
        r"(?P<keep>^\s*key\s+\d+\s+key-string\s+(?:cipher\s+|simple\s+)?)"
        r"(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),

    # ------------------------------------------- Siemens SCALANCE, Moxa
    # `snmp community <string> ro|rw` — the same secret as Cisco's
    # `snmp-server community`, spelled without the hyphen, so the Cisco
    # pattern above never saw it. The tail keeps ro/rw readable in a diff.
    ("snmp community", re.compile(
        r"(?P<keep>^\s*snmp\s+community\s+)(?P<secret>\S+)"
        r"(?P<tail>.*)$", _FLAGS)),

    # ------------------------------------------------------ Ubiquiti airOS
    # airOS has no CLI config: /tmp/system.cfg is key=value, one per line,
    # so these anchor on the key the way the MikroTik pair above do. The
    # section index varies (snmp.1.community, snmp.community).
    ("airos snmp community", re.compile(
        r"(?P<keep>\bsnmp(?:\.\d+)*\.community=)(?P<secret>\S+)", _FLAGS)),
    ("airos wpa key", re.compile(
        r"(?P<keep>\b(?:wpakey|wpapsk|psk)=)(?P<secret>\S+)", _FLAGS)),
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

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
Redaction is best-effort coverage, not a guarantee — read a redacted
backup as "these secrets are certainly gone", never as "no secret can
possibly remain".

`configrx_vendors.VENDORS` ships backup support for eleven vendor keys:
cisco, cisco-nxos, cisco-iosxr, cisco-sb, cisco-asa, cisco-wlc,
rockwellautomation (documented as genuine Cisco IOS/IOS-XE under the
Stratix label — see `configrx_vendors.py`'s own note), fortinet, juniper,
mikrotik, hp and aruba. PATTERNS below covers what those directive
families actually emit: Cisco IOS/IOS-XE/NX-OS/IOS-XR (enable secrets,
local users, bare line passwords, AAA/VPN/routing keys, SNMP and wireless
PSKs), FortiOS (`set <field> [ENC] <value>`), Juniper Junos (`set`
hierarchy secrets — RADIUS/TACACS+ shared secrets, IKE pre-shared keys and
authentication keys, encrypted local-user and root passwords), MikroTik
RouterOS (`/export`'s `key=value` pairs — password, secret and WPA PSKs)
and HP/Aruba (SNMP communities, local SHA-256 password hashes, WPA
passphrases and key-chain strings), plus the handful of cross-vendor
spellings that cost nothing to add. `moxa` and `siemens` are also shipped
but documentation-sourced only (see `configrx_vendors.py`) with no
hardware-verified secret-bearing directive of their own to write a
pattern against yet; their captures pass through whatever of the above
happens to match, which may be little or nothing. A vendor keyword this
module has never seen — on any of these families, or one added to
`configrx_vendors.py` later without a matching entry here — goes through
untouched; that is what "best-effort" means in practice.

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
    # snmp-server user <user> <group> v3 [encrypted] auth sha <key> priv aes 128 <key> [access <acl>]
    # Two patterns, one per key. A single pattern anchored on the end of the
    # line redacted only the last token: the auth key survived whenever a
    # priv key followed it, and both survived behind an `access` clause.
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
    # password sha256 <hash>  (ArubaOS-CX local user password line).
    # Deliberately placed *before* the generic "bare line password" entry
    # just below: that one's optional encryption-type group only matches
    # an all-digit IOS enc-type (`\d+`), so on a line like
    # "password sha256 <hash>" it would otherwise treat the literal word
    # "sha256" as the secret and leave the real hash sitting in its `tail`
    # untouched -- the same reason FortiOS's quoted pattern above runs
    # before its own unquoted fallback.
    ("hp/aruba password sha256", re.compile(
        r"(?P<keep>^\s*password\s+sha256\s+)(?P<secret>\S+)(?P<tail>.*)$",
        _FLAGS)),
    # A bare `password [<enc-type>] <secret>` line, as found inside
    # `line vty 0 4` / `line con 0` / `line aux 0` blocks -- one of the
    # most common secret-bearing lines in a real IOS config, and missed
    # entirely before this pattern existed: every other password-shaped
    # pattern in this list requires a leading keyword of its own (`enable`,
    # `username ...`, `neighbor ... `, `ppp ... `) and none of them fire on
    # a line whose very first token is `password` itself. Anchored on that
    # so it cannot double-redact (harmlessly) or, worse, misfire on any of
    # those other directives, none of which start their line with the word
    # `password`. `(?!sha256\b)` excludes the one enc-type spelling that
    # is not a bare `\d+` digit and is already handled, on its own terms,
    # by the "hp/aruba password sha256" entry just above -- without it,
    # this pattern would treat the literal word "sha256" as the secret on
    # that vendor's line and leave the real hash sitting in `tail`.
    # `encryption` joins the lookahead for a different reason than sha256:
    # `password encryption aes` is IOS's switch for type-6 encryption of
    # every OTHER password in the config, not a password itself, so matching
    # it rewrote a directive into `password <redacted> aes`. Both sides of a
    # diff are redacted equally so nothing was ever mis-compared, but a
    # pattern list the documentation now describes as vendor-checked should
    # not be quietly redacting a keyword.
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
    # FortiOS SNMP communities: `config system snmp community` … set name "x"
    # is not a secret (it is a label); the community itself is the `set
    # query-v1-status`-adjacent `set name`, so nothing is redacted there
    # deliberately — see the module docstring on completeness.

    # ------------------------------------------------------- Juniper Junos
    # Junos's whole CLI is `set <hierarchy...> <leaf> <value>` — there is no
    # separate directive vocabulary the way IOS or FortiOS have one, so
    # these are anchored on the leaf keyword with a non-greedy `.*?` for
    # whatever hierarchy precedes it, the same device this file already
    # uses for Cisco's `tacacs-server ... key` and `ppp ... password`.
    # Junos almost always quotes a secret value (`"$9$..."` hashed, or a
    # plain quoted string for `ascii-text`), but an unquoted token is
    # accepted too rather than assuming quoting was used.
    #
    # set system radius-server <ip> secret "..."
    # set system tacplus-server <ip> secret "..."
    ("junos radius/tacplus secret", re.compile(
        r"(?P<keep>^\s*set\s+system\s+(?:radius-server|tacplus-server)\s+"
        r"\S+\s+secret\s+)(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    # set security ike ... pre-shared-key ascii-text "..."
    ("junos pre-shared-key", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bpre-shared-key\s+ascii-text\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    # set protocols ospf ... authentication-key "..."  (OSPF/RIP/NTP simple
    # authentication -- the key immediately follows the leaf, unlike the
    # NTP `authentication-key <id> type md5 value "..."` form, which this
    # pattern does not claim to cover)
    ("junos authentication-key", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bauthentication-key\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),
    # set system root-authentication encrypted-password "..."
    # set system login user <name> authentication encrypted-password "..."
    ("junos encrypted-password", re.compile(
        r"(?P<keep>^\s*set\s+.*?\bencrypted-password\s+)"
        r"(?P<secret>\"[^\"]*\"|\S+)(?P<tail>.*)$", _FLAGS)),

    # ---------------------------------------------------- MikroTik RouterOS
    # `/export` output is one or more `key=value` pairs per line rather
    # than one directive per line (e.g. `add name=default
    # authentication-types=wpa2-psk wpa-pre-shared-key="..."
    # wpa2-pre-shared-key="..."`), so unlike every pattern above these are
    # anchored on `\b` before the key name rather than on the start of the
    # line -- the secret is frequently not the first token on it. A value
    # is quoted whenever it contains characters RouterOS's own syntax needs
    # escaped and bare otherwise, so both forms are accepted in one group
    # the same way the Junos patterns above do it. No `tail` group: nothing
    # needs to be preserved after the value, because whatever key=value
    # pairs follow on the same line sit entirely outside this match.
    ("mikrotik password/secret", re.compile(
        r"(?P<keep>\b(?:password|secret)=)(?P<secret>\"[^\"]*\"|\S+)", _FLAGS)),
    ("mikrotik wpa psk", re.compile(
        r"(?P<keep>\bwpa2?-pre-shared-key=)(?P<secret>\"[^\"]*\"|\S+)", _FLAGS)),

    # ------------------------------------------------------------ HP/Aruba
    # snmp-server community "..." is already handled above by the Cisco
    # entry near the top of this list -- `\S+` there matches a quoted,
    # space-free community string (quotes and all) exactly as well as a
    # bare one, and HP/Aruba's own syntax for the directive is identical to
    # Cisco's, so no separate pattern is needed for it here. Nor is one
    # needed for "password sha256 <hash>" -- it lives up in the Cisco
    # section above, ahead of the generic bare-password pattern it has to
    # pre-empt (see the comment there).
    #
    # wpa-passphrase <passphrase>  (ArubaOS wireless SSID profile)
    ("hp/aruba wpa-passphrase", re.compile(
        r"(?P<keep>^\s*wpa-passphrase\s+)(?P<secret>\"[^\"]*\"|\S+)"
        r"(?P<tail>.*)$", _FLAGS)),
    # key <n> key-string [cipher|simple] <key>  (Comware/ProCurve
    # authentication key chain -- distinct from Cisco's own bare
    # `key-string <key>` above, which has no leading key-id digit)
    ("hp/aruba key-string", re.compile(
        r"(?P<keep>^\s*key\s+\d+\s+key-string\s+(?:cipher\s+|simple\s+)?)"
        r"(?P<secret>\S+)(?P<tail>.*)$", _FLAGS)),
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

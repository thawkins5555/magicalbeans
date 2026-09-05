"""The hard safety boundary of ConfigRX's BACKUP path: an exhaustive,
per-vendor allow-list of exactly what a backup may ever send over an SSH
session. Nothing on that path sends anything beyond a vendor's
`pager_off` lines (session-scoped, read-only pagination settings) and its
single `show_config` command — there is no free-form command execution
anywhere in ConfigRX, by construction: nothing here accepts arbitrary
text and there is no code path that builds a command from anything other
than these fixed strings.

A vendor whose privileged EXEC mode is not the login mode (Cisco ASA)
also carries `enable_command` — always the literal `enable`, never
anything else. The only other new thing that can ever cross the wire
because of it is the device's OWN stored enable secret, sent back
verbatim as the answer to that device's own password prompt
(`enable_password_re` is only used to recognise that prompt in the
device's output, never to build a command). No vendor entry accepts a
secret from anywhere other than the encrypted per-device credential this
backup already holds.

That guarantee is about backups. The interactive SSH terminal
(sshterm.py) is a separate feature with a separate boundary — a real
shell, driven by a human, behind its own `ssh` permission that nobody
holds by default — and it neither uses this table nor reaches the backup
path. ConfigRX write still means only "may back up configs".

Vendor keys are lowercase, matching nodeoids.vendor_for()'s output (itself
sourced from trapoids.WELL_KNOWN's vendor-root names) so a Nodes device's
already-detected vendor can be used directly; a device_config row's
vendor_override is free text for anyone WELL_KNOWN or vendor_for() doesn't
cover (e.g. "hp"/"aruba", which has no SNMP enterprise root registered
there today).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Vendor:
    label: str
    pager_off: tuple = field(default_factory=tuple)
    show_config: str = ""
    # "" (the default) means this vendor's login shell is already privileged
    # EXEC — _pull_config never attempts the escalation. Set only for a
    # vendor whose login mode is user EXEC (prompt ends '>') and needs a
    # separate step to reach the mode `show_config` requires.
    enable_command: str = ""
    # How _pull_config recognises the device's OWN password prompt for
    # enable_command, in the device's own output — never used to build
    # anything sent to the device.
    enable_password_re: str = r"[Pp]assword:"


VENDORS = {
    # --- Hardware-verified: exercised against real devices of these platforms. ---
    "cisco": Vendor("Cisco IOS/IOS-XE", ("terminal length 0",), "show running-config"),
    "cisco-nxos": Vendor("Cisco NX-OS", ("terminal length 0",), "show running-config"),
    "cisco-iosxr": Vendor("Cisco IOS-XR", ("terminal length 0",), "show running-config"),
    "cisco-sb": Vendor("Cisco Small Business SG/CBS",
                       ("terminal datadump",), "show running-config"),
    "cisco-asa": Vendor("Cisco ASA", ("terminal pager 0",), "show running-config",
                       enable_command="enable"),
    "cisco-wlc": Vendor("Cisco WLC AireOS", ("config paging disable",), "show run-config"),
    "fortinet": Vendor("Fortinet FortiOS",
                       ("config system console", "set output standard", "end"),
                       "show full-configuration"),
    "juniper": Vendor("Juniper Junos", ("set cli screen-length 0",), "show configuration"),
    "mikrotik": Vendor("MikroTik RouterOS", (), "/export"),
    "hp": Vendor("HP/Aruba", ("no page",), "show running-config"),
    "aruba": Vendor("HP/Aruba", ("no paging",), "show running-config"),

    # --- Documentation-sourced only: no hardware of these platforms was
    # reachable here, so these are built from vendor CLI manuals (cited
    # below) rather than a live capture. Flag any capture against real
    # hardware as suspect until it's been eyeballed once. ---
    #
    # Moxa EDS/IKS/ICS/PT-series switches (classic "Command Line Interface
    # (FW_5.x)" CLI, v1.7 Nov 2023 — covers EDS-510E/518E/528E/G50xE/G51xE,
    # IKS-6726A/6728A/G6524A/G6824A, ICS-G75xxA/78xxA, PT-G7728/G7828).
    # `terminal length 0` disables pagination ("0 ... mean unlimited to
    # prevent pagination"); `show running-config` is documented as valid in
    # both User EXEC and Privileged EXEC. Moxa's *other* CLI family — the
    # newer "Next-generation OS" used on e.g. RKS-G4000 — only exposes
    # config backup via `copy running-config <tftp/sftp/usb/...>`, which
    # can't be captured this way; this entry is for the classic FW_5.x CLI
    # only and should not be assumed to cover Next-gen-OS switches.
    "moxa": Vendor("Moxa EDS/IKS/ICS-series (CLI FW_5.x)",
                   ("terminal length 0",), "show running-config"),
    #
    # Siemens SCALANCE X/S-series (CLI manuals for S615, XB-200/XC-200/
    # XP-200, XM-400/XR-500 families all document identical
    # `show running-config` syntax). No pager-off command is documented
    # anywhere in these manuals' CLI command lists; some models page long
    # output behind a "-- more --" prompt, but that's handled by
    # _pull_config's own generic pager responder, not a vendor command, so
    # pager_off is empty here by design, not by omission. An `enable`
    # command exists (cli> -> cli#, admin-password-gated) but is not
    # required for this command specifically. Siemens's SNMP enterprise arc
    # (4196) covers the whole Siemens tree, not SCALANCE switches alone —
    # a Siemens S7 PLC on the same arc has no SSH shell and will simply
    # fail to connect, not produce a false capture.
    "siemens": Vendor("Siemens SCALANCE (CLI)", (), "show running-config"),
    #
    # Rockwell/Allen-Bradley Stratix switches (5200/5400/5700/5800/8000):
    # multiple Rockwell and Cisco sources confirm these run genuine Cisco
    # IOS/IOS-XE with Cisco-compatible CLI syntax, so this entry is
    # identical to the "cisco" entry above rather than invented separately.
    # Key must be "rockwellautomation" (lowercase) to match resolve()'s
    # lowercasing of nodeoids.vendor_for()'s canonical key
    # "rockwellAutomation" (enterprises.py, arc 95) — that arc is itself
    # CURATED not VERIFIED there (no Rockwell device or MIB was reachable
    # to cross-check the PEN), so auto-detection onto this entry is
    # medium-confidence on top of this entry's own documentation-only
    # status.
    "rockwellautomation": Vendor("Rockwell Stratix (Cisco IOS/IOS-XE)",
                                 ("terminal length 0",), "show running-config"),
}


def resolve(vendor_key: str) -> Vendor | None:
    return VENDORS.get((vendor_key or "").strip().lower()) or None

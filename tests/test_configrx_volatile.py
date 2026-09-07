"""configrx_volatile.strip_volatile per vendor, wired into configrx._clean_output
so a device's own polling-jitter lines (Cisco's ntp clock-period, NX-OS/IOS-XR
save-time banners, Junos' "Last commit", MikroTik's export banner, HP/Aruba's
change banner, FortiOS' #conf_file_ver=) never turn into a new stored version;
an operator's own ignore_line_patterns entry strips a site-specific line on top
of the built-ins; and api._check_configrx_settings refuses an unsafe pattern
before it is ever saved (api.post_settings calls it for scope "configrx").
"""
import os

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import configrx, configrx_compliance, configrx_volatile
from netpath.configrxdb import ConfigRxDatabase
from netpath.web import api

TMPDIR = _paths.tmpdir("configrx_volatile_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


print("configrx_volatile.strip_volatile: per-vendor built-ins")

cisco_text = ("Building configuration...\n"
             "Current configuration : 4521 bytes\n"
             "! Last configuration change at 10:15:22 UTC Mon Sep 1 2026\n"
             "! NVRAM config last updated at 10:15:24 UTC Mon Sep 1 2026\n"
             "! No configuration change since last restart\n"
             "hostname sw1\n"
             "ntp clock-period 17179869\n"
             "interface Gi0/1\n"
             " description uplink\n")
stripped = configrx_volatile.strip_volatile(cisco_text, "cisco")
check("cisco: every built-in volatile line is gone",
      "Building configuration" not in stripped and "Current configuration" not in stripped
      and "Last configuration change" not in stripped and "NVRAM config" not in stripped
      and "No configuration change" not in stripped and "ntp clock-period" not in stripped,
      stripped)
check("cisco: the real config lines survive",
      "hostname sw1" in stripped and "description uplink" in stripped, stripped)

check("cisco-sb/cisco-asa/cisco-wlc share the classic Cisco set",
      configrx_volatile.strip_volatile("ntp clock-period 5\nhostname x\n", "cisco-sb")
      == "hostname x\n"
      and configrx_volatile.strip_volatile("ntp clock-period 5\nhostname x\n", "cisco-asa")
      == "hostname x\n"
      and configrx_volatile.strip_volatile("ntp clock-period 5\nhostname x\n", "cisco-wlc")
      == "hostname x\n")

nxos_text = "!Running configuration last done at 10:00:00\n!Time: Mon Sep 1\nhostname nx1\n"
check("cisco-nxos: its own three lines stripped, config kept",
      configrx_volatile.strip_volatile(nxos_text, "cisco-nxos") == "hostname nx1\n")

iosxr_text = "!! Last configuration change at 10:00:00\nhostname xr1\n"
check("cisco-iosxr",
      configrx_volatile.strip_volatile(iosxr_text, "cisco-iosxr") == "hostname xr1\n")

juniper_text = "## Last commit: 2026-09-01\n## Last changed: 2026-09-01\nsystem { host-name jn1; }\n"
check("juniper",
      configrx_volatile.strip_volatile(juniper_text, "juniper") == "system { host-name jn1; }\n")

mikrotik_text = "# sep/01/2026 10:00:00 by RouterOS 7.1\n/interface print\n"
check("mikrotik",
      configrx_volatile.strip_volatile(mikrotik_text, "mikrotik") == "/interface print\n")

hp_text = "; Last configuration change at 10:00:00\nhostname hp1\n"
check("hp", configrx_volatile.strip_volatile(hp_text, "hp") == "hostname hp1\n")
check("aruba", configrx_volatile.strip_volatile(hp_text, "aruba") == "hostname hp1\n")

fortinet_text = "#conf_file_ver=123456\nconfig system global\nend\n"
check("fortinet", configrx_volatile.strip_volatile(fortinet_text, "fortinet")
      == "config system global\nend\n")

check("a documentation-sourced vendor with no built-ins passes every line through",
      configrx_volatile.strip_volatile("hostname plc1\n", "siemens") == "hostname plc1\n")


print("an operator pattern strips a site-specific line, on top of the built-ins")
extra = (configrx_compliance.compile_bounded(r"^! Site: DC1$"),)
site_text = "! Site: DC1\nhostname sw1\nntp clock-period 5\n"
stripped = configrx_volatile.strip_volatile(site_text, "cisco", extra)
check("both the built-in AND the extra pattern applied",
      "Site: DC1" not in stripped and "ntp clock-period" not in stripped
      and "hostname sw1" in stripped, stripped)


print("configrx._clean_output wires strip_volatile in before the hash")
raw_v1 = ("Building configuration...\n\n"
         "! Last configuration change at 10:00:00 UTC Mon Sep 1 2026\n"
         "hostname sw1\n"
         "ntp clock-period 17179869\n"
         "interface Gi0/1\n description uplink\n")
raw_v2 = ("Building configuration...\n\n"
         "! Last configuration change at 11:30:45 UTC Mon Sep 1 2026\n"
         "hostname sw1\n"
         "ntp clock-period 17179912\n"          # only the volatile counter differs
         "interface Gi0/1\n description uplink\n")
cleaned_v1 = configrx._clean_output(raw_v1, "cisco")
cleaned_v2 = configrx._clean_output(raw_v2, "cisco")
check("two captures differing only in volatile lines clean to byte-identical text",
      cleaned_v1 == cleaned_v2, (cleaned_v1, cleaned_v2))

db = ConfigRxDatabase(os.path.join(TMPDIR, "configrx.db"))
try:
    backup1_id, hash1 = db.add_backup(1, cleaned_v1)
    backup2_id, hash2 = db.add_backup(1, cleaned_v2)
    check("the first capture is stored", backup1_id is not None, backup1_id)
    check("the second capture (volatile-only difference) stores no new version",
          backup2_id is None and hash1 == hash2, (backup2_id, hash1, hash2))

    print("a genuine config change still stores a new version")
    raw_v3 = raw_v2.replace("description uplink", "description core-uplink")
    cleaned_v3 = configrx._clean_output(raw_v3, "cisco")
    backup3_id, hash3 = db.add_backup(1, cleaned_v3)
    check("a real line change stores a new version",
          backup3_id is not None and hash3 != hash1, (backup3_id, hash3, hash1))

    print("a site-specific extra pattern, plumbed through _clean_output, also collapses "
          "two otherwise-identical captures to one stored version")
    extra_patterns = configrx._compile_extra_patterns("^! Site: DC1$")
    raw_site_a = "! Site: DC1\nhostname sw2\n"
    raw_site_b = "! Site: DC1\nhostname sw2\n"   # identical here; the pattern just proves plumbing
    cleaned_a = configrx._clean_output(raw_site_a, "cisco", extra_patterns)
    cleaned_b = configrx._clean_output(raw_site_b, "cisco", extra_patterns)
    check("extra_patterns reaches strip_volatile through _clean_output",
          "Site: DC1" not in cleaned_a and cleaned_a == cleaned_b, (cleaned_a, cleaned_b))
finally:
    db.close()


print("api._check_configrx_settings refuses an unsafe pattern, accepts a safe one")
try:
    api._check_configrx_settings({"ignore_line_patterns": "(a+)+"})
    check("an unsafe (catastrophic-backtracking-shaped) pattern is refused", False)
except ValueError as exc:
    check("an unsafe (catastrophic-backtracking-shaped) pattern is refused", True, str(exc))

try:
    api._check_configrx_settings(
        {"ignore_line_patterns": "^# site banner$\n^ntp clock-period \\d+$"})
    check("a safe multi-line pattern list is accepted", True)
except ValueError as exc:
    check("a safe multi-line pattern list is accepted", False, str(exc))

check("a request that doesn't mention the key is a no-op, not a refusal",
      api._check_configrx_settings({"enabled": True}) is None)


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

"""ConfigRX on the industrial vendors: Moxa EDS/IKS/ICS, Siemens SCALANCE X/S
and Rockwell Stratix (Cisco IOS-based, "cisco" commands under the
"rockwellautomation" vendor key). Drives the real _pull_config -> _clean_output
-> _capture_problem chain against each persona in demo/fake_ssh.py's PERSONAS,
as test_configrx_cisco_platforms.py does. None of the three is hardware-verified
(see "Documentation-sourced only" in netpath/configrx.py's VENDORS table).
"""
import os
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

try:
    import paramiko  # noqa: E402
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from demo import fake_ssh  # noqa: E402
from netpath import configrx  # noqa: E402
from netpath import configrx_redact  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def connect(port, password="demo"):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="tester", password=password,
                   timeout=10, look_for_keys=False, allow_agent=False)
    return client


# name -> (vendor key, a substring the stored capture must contain,
# the exact bytes ConfigRX must have sent — the safety-boundary check).
INDUSTRIAL_PERSONAS = {
    "moxa": (
        "moxa", "hostname Plant1-EDS-G516E-12",
        "terminal length 0\nshow running-config\n",
    ),
    "siemens-scalance": (
        "siemens", "hostname Plant1-XC208-04",
        # No pager_off line: the "siemens" vendor entry sends none.
        "show running-config\n",
    ),
    "rockwell-stratix": (
        "rockwellautomation", "hostname Plant1-Stratix5700-07",
        "terminal length 0\nshow running-config\n",
    ),
}

print("every new industrial persona in demo.fake_ssh.PERSONAS")
missing = set(INDUSTRIAL_PERSONAS) - set(fake_ssh.PERSONAS)
check("this suite's persona list matches demo.fake_ssh.PERSONAS (nothing renamed/removed there)",
      not missing, missing)

for name, (vendor_key, marker, expected_sent) in INDUSTRIAL_PERSONAS.items():
    persona = fake_ssh.PERSONAS[name]
    vendor = configrx.resolve(vendor_key)
    check(f"{name}: vendor '{vendor_key}' is registered", vendor is not None)
    if vendor is None:
        continue

    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        raw, ended = configrx._pull_config(client, vendor, max_s=15)
        client.close()
        cleaned = configrx._clean_output(raw)
        problem = configrx._capture_problem(cleaned, ended)
        check(f"{name}: STORED (no capture problem)", problem == "", problem)
        check(f"{name}: the captured text is this persona's own config",
              marker in cleaned, cleaned[:200])
    finally:
        device.close()

    # A fresh device for the safety-boundary check: proves nothing beyond
    # this vendor's own pager_off + show_config ever crossed the wire, the
    # same guarantee the VENDORS table's own comment makes for every
    # entry in VENDORS.
    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        configrx._pull_config(client, vendor, max_s=15)
        client.close()
        sent = b"".join(device.sent_bytes).decode("utf-8", "replace")
        check(f"{name}: only pager_off + show_config were ever sent, nothing else",
              sent == expected_sent, repr(sent))
    finally:
        device.close()

# ---- resolve() lowercases: nodeoids.vendor_for() returns "rockwellAutomation"
# (mixed case, enterprises.py's canonical key for arc 95) but the VENDORS
# dict key is "rockwellautomation" (all lowercase) — proving that mismatch
# does not silently fall through to "vendor not registered" the way it
# would if resolve() ever stopped lowercasing its argument.
print("rockwellautomation: resolve() finds the lowercase key from the mixed-case canonical form")
check("resolve() is case-insensitive on the canonical vendor key",
      configrx.resolve("rockwellAutomation") is configrx.resolve("rockwellautomation"))


# ---- Redaction. Every SNMP-community pattern anchored on the Cisco spelling
# `snmp-server community`, so SCALANCE's own `snmp community <x> ro` was
# stored verbatim in configrx.db and served by the backup-content and diff
# routes — which the module documents as redacted by default.
print("siemens-scalance: the SNMP community is redacted before storage")
siemens = fake_ssh.PERSONAS["siemens-scalance"]["config"]
redacted, count = configrx_redact.redact(siemens)
check("at least one secret is recognised in a SCALANCE capture", count >= 1, count)
check("the read community is not left in the clear",
      "PlantRO2026" not in redacted,
      [line for line in redacted.splitlines() if "community" in line])
check("and ro/rw survives, so the line still reads in a diff",
      "snmp community <redacted> ro" in redacted,
      [line for line in redacted.splitlines() if "community" in line])

print("moxa: the Cisco-spelled community stays redacted as it was")
moxa_redacted, moxa_count = configrx_redact.redact(fake_ssh.PERSONAS["moxa"]["config"])
check("a Moxa capture still redacts snmp-server community",
      moxa_count >= 1 and "PlantRO2026" not in moxa_redacted, moxa_count)


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

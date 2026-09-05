"""ConfigRX on the industrial vendors added for the 2,000-device plant
estate survey: Moxa EDS/IKS/ICS-series switches, Siemens SCALANCE X/S
switches, and Rockwell/Allen-Bradley Stratix switches (Cisco IOS-based,
reusing the "cisco" command set under the "rockwellautomation" vendor
key SNMP auto-detection resolves to).

Drives the real `_pull_config` -> `_clean_output` -> `_capture_problem`
chain (nothing here reimplements ConfigRX's capture logic) against each
persona in demo/fake_ssh.py's PERSONAS, shared verbatim with
`stubs.stub_ssh_device.StubDevice(persona=...)`, the same pattern
test_configrx_cisco_platforms.py uses for the existing Cisco platforms.

Unlike that file's Cisco personas, none of these three vendor entries are
hardware-verified — see the "Documentation-sourced only" block in
netpath/configrx_vendors.py for what each is actually sourced from. This
file proves the command set that documentation describes round-trips
through ConfigRX's real capture chain against a scripted double of that
CLI; it cannot and does not claim to prove a real Moxa/SCALANCE/Stratix
device would answer the same way.
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
from netpath import configrx, configrx_vendors  # noqa: E402
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
    vendor = configrx_vendors.resolve(vendor_key)
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
    # same guarantee configrx_vendors.py's module docstring makes for every
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
      configrx_vendors.resolve("rockwellAutomation") is configrx_vendors.resolve("rockwellautomation"))


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

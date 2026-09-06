#!/usr/bin/env python3
"""A realistic ConfigRX compliance demonstration — not a unit test.

Runs a plant's day-one rule set against REAL captures pulled over real SSH
from five of demo/fake_ssh.py's personas (four purpose-built access
switches plus "fortinet" as an out-of-scope device), evaluates the five
rules a network engineer would write first, and prints which devices
pass, which fail, which rules they fail, and how long the fleet took.

    python3 demo/configrx_compliance_fixture.py [--out demo/out/configrx_compliance]

Offline by design: two throwaway SQLite databases in --out, SSH servers
this script starts itself on loopback ports nothing else uses, no HTTP,
no app, no fleet.py.

Establishes two things a synthetic string test cannot: whether the
250-character line cap (configrx_compliance.MAX_LINE_CHARS_FOR_MATCH) is
comfortable against a real Cisco running-config's longest lines, and
whether the redaction boundary holds — acc-legacy's plaintext password is
unfindable by literal search in the redacted index, yet the same line
still fails its compliance rule (which reads the real capture, not the
index).

It also surfaces a case neither of those was looking for: a rule checking
a SECRET-SHAPED VALUE (a specific SNMP community, not just "is one
configured") can only be meaningfully evaluated with store_secrets on —
redaction replaces every community with the same "<redacted>" token, so
the rule cannot tell a default from a good one once redacted. A rule
checking a directive merely EXISTS is unaffected, since redaction
preserves a line's shape. This script runs the SNMP rule once with
store_secrets on and once normally redacted, side by side.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import paramiko  # noqa: E402

from demo import fake_ssh  # noqa: E402
from netpath import configrx, configrx_compliance, configrx_redact  # noqa: E402
from netpath.configrxdb import ConfigRxDatabase  # noqa: E402
from netpath.nodesdb import NodesDatabase  # noqa: E402
from stubs import stub_ssh_device  # noqa: E402

# name -> (fake_ssh persona name, vendor key, device_group, store_secrets)
# The four acc-* devices are the fixture's real subject; "fortinet" is
# reused as-is (fake_ssh.py already has it) purely to prove device-group
# scoping — a firewall has no switchports at all, so a port-security rule
# that fires on it anyway would mean the scoping is broken, not that the
# firewall is non-compliant.
FIXTURE_DEVICES = [
    ("acc-sw-101", "acc-compliant", "cisco", "Access Switches", True),
    ("acc-sw-102", "acc-no-ntp", "cisco", "Access Switches", True),
    ("acc-sw-103", "acc-legacy", "cisco", "Access Switches", True),
    ("acc-sw-104", "acc-default-snmp", "cisco", "Access Switches", True),
    ("fw-01", "fortinet", "fortinet", "Firewalls", True),
]

# The plant's own NTP server, for the rule below and for reading the
# report — not a placeholder, the actual value every ACC_*_CONFIG in
# fake_ssh.py either does or deliberately does not carry.
PLANT_NTP_SERVER = "10.10.0.1"

RULES = [
    # (description, kind, pattern)
    ("Must point at the plant NTP server (10.10.0.1)",
     configrx_compliance.RuleKind.MUST_MATCH, rf"ntp server {PLANT_NTP_SERVER.replace('.', chr(92) + '.')}"),
    ("SNMP community must not be a vendor default (public/private)",
     configrx_compliance.RuleKind.MUST_NOT_MATCH, r"snmp-server community (public|private)\b"),
    ("Access ports must have port security",
     configrx_compliance.RuleKind.MUST_MATCH, r"switchport port-security"),
    ("No plaintext (type 0) password lines",
     configrx_compliance.RuleKind.MUST_NOT_MATCH, r"password 0 \S+"),
    ("Telnet transport must not be enabled",
     configrx_compliance.RuleKind.MUST_NOT_MATCH, r"transport input telnet"),
]
# Index of the one rule that is scoped, not fleet-wide — see build_rule_set.
PORT_SECURITY_RULE_INDEX = 2

# The literal secret value acc-legacy's plaintext-password line carries —
# used only to prove it is unfindable through search once redacted, never
# to decide anything about the rule itself (the rule matches the
# DIRECTIVE'S shape, not this value — see the module docstring).
LEGACY_PLAINTEXT_PASSWORD = "letmein123"


def connect(port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="tester", password="demo",
                   timeout=10, look_for_keys=False, allow_agent=False)
    return client


def pull_real_capture(persona_name: str, vendor_key: str) -> tuple[str, str]:
    """(cleaned text, capture problem or "") — a REAL SSH pull against a
    REAL demo/fake_ssh.py persona over a real socket, using ConfigRX's own
    _pull_config exactly as ConfigRxWorker._backup_device does. Not a
    string handed straight to the database — see the module docstring."""
    persona = fake_ssh.PERSONAS[persona_name]
    vendor = configrx.resolve(vendor_key)
    device = stub_ssh_device.StubDevice(persona=persona)
    try:
        client = connect(device.port)
        try:
            raw, ended = configrx._pull_config(client, vendor, max_s=15)
        finally:
            client.close()
    finally:
        device.close()
    cleaned = configrx._clean_output(raw)
    problem = configrx._capture_problem(cleaned, ended)
    return cleaned, problem


def build_rule_set(db: ConfigRxDatabase, access_group_id: int) -> int:
    rule_set_id = configrx_compliance.add_rule_set(db, "Plant baseline — day one")
    for i, (description, kind, pattern) in enumerate(RULES):
        scope_note = " (scoped to Access Switches)" if i == PORT_SECURITY_RULE_INDEX else ""
        configrx_compliance.add_rule(db, rule_set_id, description + scope_note, kind, pattern, ordinal=i)
    # The port-security rule is the only one scoped; add_rule_set/rules
    # above are fleet-wide by construction (this function creates ONE rule
    # set with all five rules, matching how an operator would actually
    # write a baseline — "everything but the switch-only rule applies to
    # everything"). Scoping happens at RULE SET granularity in this
    # module's current shape, not per-rule, so the scoped rule gets its
    # own one-rule set instead, and evaluate_all is called once per set.
    return rule_set_id


def build_scoped_port_security_rule_set(db: ConfigRxDatabase, access_group_id: int) -> int:
    description, kind, pattern = RULES[PORT_SECURITY_RULE_INDEX]
    rule_set_id = configrx_compliance.add_rule_set(
        db, "Access switch baseline — port security", device_group_id=access_group_id)
    configrx_compliance.add_rule(db, rule_set_id, description, kind, pattern, ordinal=0)
    return rule_set_id


def build_unscoped_rule_set(db: ConfigRxDatabase) -> int:
    rule_set_id = configrx_compliance.add_rule_set(db, "Plant baseline — every device")
    ordinal = 0
    for i, (description, kind, pattern) in enumerate(RULES):
        if i == PORT_SECURITY_RULE_INDEX:
            continue
        configrx_compliance.add_rule(db, rule_set_id, description, kind, pattern, ordinal=ordinal)
        ordinal += 1
    return rule_set_id


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(HERE, "out", "configrx_compliance"),
                    help="where to put the two throwaway SQLite databases")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    configrx_db_path = os.path.join(args.out, "configrx.db")
    nodes_db_path = os.path.join(args.out, "nodes.db")
    for path in (configrx_db_path, nodes_db_path):
        if os.path.exists(path):
            os.remove(path)

    print(f"ConfigRX compliance fixture — databases in {args.out}\n")

    nodes_db = NodesDatabase(nodes_db_path)
    configrx_db = ConfigRxDatabase(configrx_db_path)
    access_group_id = nodes_db.add_device_group("Access Switches")
    firewall_group_id = nodes_db.add_device_group("Firewalls")
    group_by_name = {"Access Switches": access_group_id, "Firewalls": firewall_group_id}
    default_group = nodes_db.ensure_default_group()

    device_ids: dict[str, int] = {}
    print("Pulling real captures over real SSH (demo/fake_ssh.py, in-process):")
    for i, (name, persona_name, vendor_key, group_name, store_secrets) in enumerate(
            FIXTURE_DEVICES, start=1):
        t0 = time.time()
        cleaned, problem = pull_real_capture(persona_name, vendor_key)
        elapsed = time.time() - t0
        if problem:
            print(f"  {name:<10} FAILED TO CAPTURE: {problem}")
            continue
        device_id = nodes_db.add_device(
            f"127.0.100.{i}", name=name, group_id=default_group,
            device_group_id=group_by_name[group_name])
        device_ids[name] = device_id
        # Exactly configrx.py's own _backup_device split: the STORED backup
        # respects store_secrets (verbatim when it's on); the cross-device
        # SEARCH index is redacted unconditionally, regardless — see
        # configrx_compliance.py's module docstring for why that is stricter
        # than the storage decision on purpose.
        if store_secrets:
            stored_text = cleaned
            search_text, _ = configrx_redact.redact(cleaned)
        else:
            stored_text, _ = configrx_redact.redact(cleaned)
            search_text = stored_text
        backup_id, _digest = configrx_db.add_backup(
            device_id, stored_text, redacted=not store_secrets)
        configrx_db.replace_search_lines(device_id, search_text)
        print(f"  {name:<10} {persona_name:<18} {len(cleaned):>6} chars captured "
              f"in {elapsed:.2f}s, store_secrets={store_secrets}")

    longest_line = max(
        (len(line) for name in device_ids
         for line in (configrx_db.backup_content(configrx_db.backups_for(device_ids[name], limit=1)[0]["id"])
                     or "").split("\n")), default=0)
    print(f"\nLongest single line across every real capture: {longest_line} characters "
         f"(configrx_compliance.MAX_LINE_CHARS_FOR_MATCH is "
         f"{configrx_compliance.MAX_LINE_CHARS_FOR_MATCH}).")

    print("\nBuilding the plant's day-one rule set (4 fleet-wide rules, 1 scoped "
         "to Access Switches):")
    for description, kind, _pattern in RULES:
        print(f"  - [{kind}] {description}")

    unscoped_id = build_unscoped_rule_set(configrx_db)
    scoped_id = build_scoped_port_security_rule_set(configrx_db, access_group_id)

    print("\nEvaluating across the fleet ...")
    t0 = time.time()
    n1 = configrx_compliance.evaluate_all(configrx_db, nodes_db, unscoped_id)
    n2 = configrx_compliance.evaluate_all(configrx_db, nodes_db, scoped_id)
    elapsed = time.time() - t0
    print(f"Evaluated {n1 + n2} device x rule-set results across "
         f"{len(device_ids)} devices in {elapsed * 1000:.2f}ms.\n")

    print("=" * 72)
    print("RESULT, as an operator would read it")
    print("=" * 72)
    pass_count = fail_count = 0
    for name, device_id in device_ids.items():
        unscoped = configrx_db.compliance_result(device_id, unscoped_id)
        scoped = configrx_db.compliance_result(device_id, scoped_id)
        failed = json.loads(unscoped["failed_rules"]) if unscoped else []
        scoped_status = scoped["status"] if scoped else "not_assessed"
        if scoped_status == "fail":
            failed = failed + json.loads(scoped["failed_rules"])
        overall = "FAIL" if failed else "PASS"
        if overall == "FAIL":
            fail_count += 1
        else:
            pass_count += 1
        print(f"\n{name} ({FIXTURE_DEVICES[[d[0] for d in FIXTURE_DEVICES].index(name)][3]}): {overall}")
        if scoped_status == "not_assessed":
            print("    (port-security rule: not in scope for this device group)")
        for rule in failed:
            print(f"    FAILS: {rule['description']}")
    print(f"\n{pass_count} of {len(device_ids)} devices pass every rule that applies to them; "
         f"{fail_count} fail at least one.")

    # -------------------------------------------- the redaction boundary
    print("\n" + "=" * 72)
    print("Redaction boundary: does search leak what compliance is allowed to see?")
    print("=" * 72)
    result = configrx_compliance.search(configrx_db, LEGACY_PLAINTEXT_PASSWORD, mode="text")
    print(f"Searching for the literal plaintext password value "
         f"({LEGACY_PLAINTEXT_PASSWORD!r}): {len(result['matches'])} match(es) "
         f"— {'LEAK' if result['matches'] else 'not findable, as designed'}.")
    legacy_id = device_ids.get("acc-sw-103")
    if legacy_id is not None:
        legacy_result = configrx_db.compliance_result(legacy_id, unscoped_id)
        legacy_failed = json.loads(legacy_result["failed_rules"]) if legacy_result else []
        caught = any("plaintext" in r["description"].lower() for r in legacy_failed)
        print(f"Compliance still flags acc-sw-103's plaintext-password line: "
             f"{'yes' if caught else 'no'} (reads the real capture, not the "
             f"redacted search index — the directive's shape survives "
             f"redaction even where the search index would not show the value).")

    # ------------------------------------- the secret-shaped-value lesson
    print("\n" + "=" * 72)
    print("A rule that checks a SECRET-SHAPED VALUE needs store_secrets, not just a capture")
    print("=" * 72)
    demo_device_id = device_ids.get("acc-sw-104")   # the deliberately-default-SNMP switch
    if demo_device_id is not None:
        raw_backup_id = configrx_db.backups_for(demo_device_id, limit=1)[0]["id"]
        raw_text = configrx_db.backup_content(raw_backup_id)
        redacted_text, _ = configrx_redact.redact(raw_text)
        snmp_rule = configrx_compliance.compile_bounded(RULES[1][2])
        raw_hit = bool(snmp_rule.search(raw_text))
        redacted_hit = bool(snmp_rule.search(redacted_text))
        print(f"acc-sw-104's real capture (store_secrets=True, as captured): "
             f"SNMP-default rule {'FIRES (correct — it really is public)' if raw_hit else 'does not fire'}.")
        print(f"The SAME capture, redacted as a store_secrets=False device would store it: "
             f"SNMP-default rule {'still fires' if redacted_hit else 'CANNOT fire — the value is gone, replaced by <redacted>, identical to a good community'}.")
        print("Lesson: a rule checking a specific secret-shaped value (an SNMP "
             "community string, a password) only means anything on a device "
             "with store_secrets on. A rule checking whether a risky DIRECTIVE "
             "exists at all (telnet, a plaintext-password marker) works either way.")

    configrx_db.close()
    nodes_db.close()
    return 0   # an informational demonstration, not a pass/fail test


if __name__ == "__main__":
    sys.exit(main())

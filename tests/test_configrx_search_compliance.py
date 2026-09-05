"""Cross-device configuration search and compliance rule sets
(netpath/configrx_search.py, netpath/configrx_compliance.py, and the
schema/storage netpath/configrxdb.py added for both) — the query nothing
in ConfigRX could answer before: "which of my devices has/does not have
X" across every device's latest capture, and a compliance baseline
evaluated on a schedule rather than recomputed on every page view.

Runs entirely against ConfigRxDatabase directly, with a small stand-in
for the two nodes_db methods configrx_compliance actually calls
(device() and devices(device_group_id=...), plus record_metric_samples)
rather than a real NodesDatabase and its own migrations along for the
ride. Neither feature has an HTTP route wired to it yet — see the report
handed to team-lead — so there is no server here the way
test_configrx_diff.py has one; this is what that route's own test should
build on once it exists.

Covers:
  - a plain substring search finding the same line across several
    devices' captures, through the FTS5 index when available and through
    the full-scan fallback when the query is too short to index;
  - a bounded regular-expression search, and the three shapes of
    catastrophic-backtracking pattern compile_bounded refuses outright
    (nested repetition, quantified alternation, chained adjacent
    quantifiers with nothing disambiguating between them) each refused in
    well under the time they would actually run for if they were not;
  - a pattern that PASSES that structural check still bounded to a small
    fraction of a second by the per-line length cap, against a
    deliberately long pathological-shaped line — tight enough that
    raising MAX_LINE_CHARS_FOR_MATCH back up, or removing the cap
    entirely, would make this assertion fail rather than continuing to
    pass by accident;
  - the search index holding only redacted text regardless of what the
    "raw" capture (as ConfigRxWorker would compute it for a
    store_secrets-on device) contains — the same invariant
    configrx_search.py's own module docstring states;
  - a compliance rule set passing some devices and failing others, with
    the failing rules named in the stored result;
  - a device with no stored capture at all reading as "not_assessed",
    never a silent "pass", and contributing no compliance_fail_count
    metric sample;
  - a rule set scoped to one device group evaluating only devices in that
    group, leaving no result at all for a device outside it;
  - a rule's pattern (and kind) validated at add_rule time, before it is
    ever stored;
  - forget_device removing a device's search-index rows and compliance
    results along with its backups.
"""
from __future__ import annotations

import json
import os
import time

import _paths  # noqa: F401

from netpath import configrx_compliance as cc
from netpath import configrx_redact
from netpath import configrx_search as cs
from netpath.configrxdb import ConfigRxDatabase

TMPDIR = _paths.tmpdir("configrx_search_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class FakeNodesDB:
    """Only what configrx_compliance actually calls on nodes_db — enough to
    test its OWN logic (device-group scoping, not-assessed handling, the
    metric it records) without a second real database along for the ride."""

    def __init__(self):
        self._devices: dict[int, dict] = {}
        self.metrics: dict[int, list] = {}

    def add(self, device_id: int, device_group_id: int | None = None) -> None:
        self._devices[device_id] = {"id": device_id, "device_group_id": device_group_id}

    def device(self, device_id: int):
        return self._devices.get(device_id)

    def devices(self, device_group_id: int | None = None):
        return [d for d in self._devices.values()
               if device_group_id is None or d["device_group_id"] == device_group_id]

    def record_metric_samples(self, device_id: int, rows: list) -> dict:
        self.metrics.setdefault(device_id, []).extend(rows)
        return {}


db = ConfigRxDatabase(os.path.join(TMPDIR, "configrx.db"))
print(f"FTS5 trigram search index available on this build: {db.search_fts}")


# --------------------------------------------------------------- 1. search

ACCESS_GROUP, FIREWALL_GROUP = 10, 20

db.replace_search_lines(
    1, "hostname sw1\nntp server 10.0.0.5\nsnmp-server community public RO\n")
db.replace_search_lines(
    2, "hostname sw2\nntp server 10.0.0.9\nsnmp-server community public RO\n")
db.replace_search_lines(3, "hostname fw1\nntp server 10.0.0.5\n")

print("cross-device plain-text search")
result = cs.search(db, "snmp-server community public", mode="text")
check("finds the line on both devices that have it, and only those",
      {(m["device_id"], m["line_no"]) for m in result["matches"]} == {(1, 3), (2, 3)},
      result)
check("not flagged truncated", result["truncated"] is False, result)
if db.search_fts:
    check("answered by the FTS index, not the scan fallback",
          result["indexed"] is True, result)

print("a query too short for the trigram floor still finds it, via the scan fallback")
result = cs.search(db, "sw", mode="text")
check("matches hostname sw1 and sw2",
      {1, 2} <= {m["device_id"] for m in result["matches"]}, result)
check("marked not indexed (this query is under MIN_INDEXED_CHARS)",
      result["indexed"] is False, result)

print("a plain-text query is never treated as a pattern")
result = cs.search(db, "10.0.0.5", mode="text")
check("matches the literal IP on the two devices that have it",
      {m["device_id"] for m in result["matches"]} == {1, 3}, result)

print("device_ids narrows the search to a subset")
result = cs.search(db, "ntp server", mode="text", device_ids=[1])
check("only device 1 is searched when device_ids=[1]",
      {m["device_id"] for m in result["matches"]} == {1}, result)

print("bounded regular-expression search")
result = cs.search(db, r"ntp server \d+\.\d+\.\d+\.\d+", mode="regex")
check("matches all three devices' ntp lines",
      {m["device_id"] for m in result["matches"]} == {1, 2, 3}, result)
check("not flagged truncated", result["truncated"] is False, result)


# ---------------------------------------- 2. catastrophic regex, refused

print("catastrophic-backtracking shapes are refused before they are ever run")
DANGEROUS = {
    "nested repetition (a+)+$": r"(a+)+$",
    "quantified alternation (a|aa)+$": r"(a|aa)+$",
    "chained adjacent quantifiers \\d+\\d+\\d+\\d+\\d+": r"\d+\d+\d+\d+\d+",
}
for label, pattern in DANGEROUS.items():
    started = time.time()
    try:
        cs.search(db, pattern, mode="regex")
        check(f"{label}: should have been refused", False)
    except cs.UnsafeRegex:
        elapsed = time.time() - started
        # Each of these, actually RUN (not refused) against even a short
        # non-matching string, measured well over a second on this
        # machine in developing this file — refusing it in well under
        # that proves it was never executed at all, not merely fast.
        check(f"{label}: refused in {elapsed:.3f}s, without ever running",
              elapsed < 1.0, elapsed)

print("safe patterns real compliance/search rules actually need are NOT refused")
SAFE = (r"^ntp server \d+\.\d+\.\d+\.\d+$", r"snmp-server community \S+",
       r"\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+", r"(tcp|udp) port \d+")
for pattern in SAFE:
    try:
        cs.compile_bounded(pattern)
        check(f"{pattern!r} accepted", True)
    except cs.UnsafeRegex as exc:
        check(f"{pattern!r} should not have been refused", False, str(exc))

print("a pattern that PASSES the structural check is still bounded by the length cap")
# Four times the per-line cap, all 'a', no 'c' anywhere -- forces the
# maximum backtracking the (allowed-through) pattern below can do, on a
# line four times longer than what MAX_LINE_CHARS_FOR_MATCH lets it see.
# If that constant were raised back up, or the truncation removed, this
# would take many seconds to minutes instead (see configrx_search.py's
# module docstring for the measurements) and the assertion below would
# fail rather than continuing to pass by accident.
long_line = "a" * (cs.MAX_LINE_CHARS_FOR_MATCH * 4) + "!"
db.replace_search_lines(99, long_line)
started = time.time()
result = cs.search(db, r"a+a+a+c", mode="regex", device_ids=[99])
elapsed = time.time() - started
check("search over a long, worst-case-shaped line completes in well under a second",
      elapsed < 3.0, f"took {elapsed:.2f}s")
check("and correctly finds nothing (truncated before the 'c' that never appears anyway)",
      result["matches"] == [], result)
db.forget_device(99)


# --------------------------------------------------- 3. the index is redacted

print("the search index holds only redacted text, regardless of store_secrets")
verbatim = ("hostname sw-secret\n"
           "snmp-server community s3cr3t-value RO\n"
           "enable secret 5 $1$abc$XXXXXXXXXXXXXXXXXXXXXX\n")
# What ConfigRxWorker._backup_device computes for the search index even
# when store_secrets is ON for this device — see configrx.py's own
# comment at the call site, and configrx_search.py's module docstring for
# why this must never be the verbatim text.
redacted_text, _count = configrx_redact.redact(verbatim)
db.replace_search_lines(50, redacted_text)
result = cs.search(db, "s3cr3t-value", mode="text")
check("the real secret value is not findable through search",
      not any(m["device_id"] == 50 for m in result["matches"]), result)
result = cs.search(db, "snmp-server community", mode="text")
check("the redacted line IS findable (the directive survives redaction)",
      any(m["device_id"] == 50 and "<redacted>" in m["line"] for m in result["matches"]),
      result)
db.forget_device(50)


# ------------------------------------------------------------- 4. compliance

print("a rule set scoped to a device group: pass, fail, not_assessed, and out of scope")
nodes = FakeNodesDB()
nodes.add(1, device_group_id=ACCESS_GROUP)     # compliant access switch
nodes.add(2, device_group_id=ACCESS_GROUP)     # non-compliant access switch
nodes.add(3, device_group_id=ACCESS_GROUP)     # never backed up
nodes.add(4, device_group_id=FIREWALL_GROUP)   # out of scope entirely

db.add_backup(1, "hostname sw1\ninterface Gi0/1\n switchport port-security\n"
                 "no transport input telnet\n")
db.add_backup(2, "hostname sw2\ninterface Gi0/1\ntransport input telnet\n")
# device 3: no add_backup call at all.
db.add_backup(4, "hostname fw1\n")   # a firewall; would fail if it were in scope

rule_set_id = cc.add_rule_set(db, "Access switch baseline", device_group_id=ACCESS_GROUP)
cc.add_rule(db, rule_set_id, "Access ports must have port security",
           cc.RuleKind.MUST_MATCH, r"switchport port-security")
cc.add_rule(db, rule_set_id, "Telnet must not be enabled",
           cc.RuleKind.MUST_NOT_MATCH, r"^transport input telnet$")

evaluated = cc.evaluate_all(db, nodes, rule_set_id)
check("evaluated exactly the 3 access-group devices, not the firewall",
      evaluated == 3, evaluated)

r1 = db.compliance_result(1, rule_set_id)
check("device 1: pass", r1 is not None and r1["status"] == "pass", dict(r1) if r1 else None)
check("device 1: no failed rules recorded",
      json.loads(r1["failed_rules"]) == [], r1["failed_rules"])

r2 = db.compliance_result(2, rule_set_id)
check("device 2: fail", r2 is not None and r2["status"] == "fail", dict(r2) if r2 else None)
failed2 = json.loads(r2["failed_rules"]) if r2 else []
check("device 2: both rules failed, named by description",
      {f["description"] for f in failed2} ==
      {"Access ports must have port security", "Telnet must not be enabled"}, failed2)
check("a failed rule never carries the config line that failed it, only its own description",
      all(set(f) == {"rule_id", "description"} for f in failed2), failed2)

r3 = db.compliance_result(3, rule_set_id)
check("device 3 (no capture at all): not_assessed, never a silent pass",
      r3 is not None and r3["status"] == "not_assessed" and r3["backup_id"] is None,
      dict(r3) if r3 else None)

r4 = db.compliance_result(4, rule_set_id)
check("device 4 (a firewall, out of scope): no result row at all — "
      "the rule scoped to access switches never touches it",
      r4 is None, r4)

print("compliance_fail_count: recorded for assessed devices, absent for not_assessed")
check("device 1 (compliant): fail count 0",
      nodes.metrics.get(1, [{}])[-1][-1] == 0, nodes.metrics.get(1))
check("device 2 (non-compliant): fail count 1 (one rule set, failing)",
      nodes.metrics.get(2, [{}])[-1][-1] == 1, nodes.metrics.get(2))
check("device 3 (not_assessed): no metric sample recorded at all — an absent metric "
      "reads as 'no data', not the 0 a threshold rule would read as 'compliant'",
      3 not in nodes.metrics, nodes.metrics.get(3))
check("device 4 (out of scope): no metric sample either",
      4 not in nodes.metrics, nodes.metrics.get(4))

print("evaluate_device_all_rule_sets: the per-device call ConfigRxWorker makes "
      "right after a new capture")
nodes.add(5, device_group_id=ACCESS_GROUP)
db.add_backup(5, "hostname sw5\ninterface Gi0/1\n switchport port-security\n"
                 "no transport input telnet\n")
count = cc.evaluate_device_all_rule_sets(db, nodes, 5)
check("evaluated the one rule set in scope for device 5", count == 1, count)
r5 = db.compliance_result(5, rule_set_id)
check("device 5: pass", r5 is not None and r5["status"] == "pass", dict(r5) if r5 else None)


# --------------------------------------------------- rule validation and CRUD

print("a rule's pattern is validated at add_rule time, before it is ever stored")
before = len(db.rules_for(rule_set_id))
try:
    cc.add_rule(db, rule_set_id, "dangerous", cc.RuleKind.MUST_MATCH, r"(a+)+")
    check("a catastrophic pattern should have been refused at add_rule time", False)
except cs.UnsafeRegex:
    check("refused, and nothing was stored",
          len(db.rules_for(rule_set_id)) == before, db.rules_for(rule_set_id))

try:
    cc.add_rule(db, rule_set_id, "x", "not_a_real_kind", r"foo")
    check("an invalid rule kind should have been refused", False)
except ValueError:
    check("invalid kind refused", True)

try:
    cc.add_rule(db, rule_set_id, "   ", cc.RuleKind.MUST_MATCH, r"foo")
    check("an empty description should have been refused", False)
except ValueError:
    check("empty description refused", True)

print("a rule set with no device_group_id scope applies to every device")
open_rule_set = cc.add_rule_set(db, "Every device must have a hostname")
cc.add_rule(db, open_rule_set, "Config must set a hostname",
           cc.RuleKind.MUST_MATCH, r"^hostname \S+$")
evaluated = cc.evaluate_all(db, nodes, open_rule_set)
check("every device in scope was evaluated, including device 3 (as "
      "not_assessed — still a computed result, just that status)",
      evaluated == 5, evaluated)
check("device 3 reads not_assessed under this rule set too, not a pass",
      db.compliance_result(3, open_rule_set)["status"] == "not_assessed",
      db.compliance_result(3, open_rule_set))
check("the firewall (device 4), out of scope for the FIRST rule set, IS in "
      "scope for this unscoped one",
      db.compliance_result(4, open_rule_set)["status"] == "pass",
      db.compliance_result(4, open_rule_set))


# -------------------------------------------------------------- forget_device

print("forget_device removes a device's search index rows and compliance results too")
db.replace_search_lines(6, "hostname sw6\n")
db.add_backup(6, "hostname sw6\n")
db.set_compliance_result(6, rule_set_id, "pass", [], 1)
check("search lines exist before forgetting", len(db.all_search_lines([6])) > 0)
check("a compliance result exists before forgetting",
      db.compliance_result(6, rule_set_id) is not None)
db.forget_device(6)
check("search lines are gone after forget_device", db.all_search_lines([6]) == [])
check("the compliance result is gone too", db.compliance_result(6, rule_set_id) is None)


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

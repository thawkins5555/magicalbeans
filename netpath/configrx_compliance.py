"""Compliance rule sets — the second half of the gap search.py's own module
docstring names: even with a working cross-device search, a site with
2,000 switches still cannot ask "which of them fails our baseline" as a
column on a device list without running every rule's regex on every page
view. This file is what runs those rules on a schedule and when a new
capture arrives instead, and stores the one result per (device, rule set)
that view actually reads (configrxdb.compliance_results).

A rule is `must_match` or `must_not_match` — RuleKind — a description an
operator wrote (never echoed back with the line that satisfied or failed
it, see below), and a pattern validated through configrx_search.
compile_bounded before it is ever stored (add_rule), so a rule set can
never be SAVED with something that would hang an evaluation later.

Evaluated line by line against the device's LATEST capture, not as one
whole-document regex search. Two different reasons land on the same
design:

  Safety. configrx_search.py's own measurements are about a single LINE,
  capped at MAX_LINE_CHARS_FOR_MATCH (250 characters) — the shape its
  heuristics let through (three chained overlapping quantifiers) costs
  0.22s at that size and grows roughly cubically. A real device capture is
  tens of thousands of characters; the same pattern run against the whole
  document at once would cost minutes, not milliseconds, and there is no
  smaller bound to give a whole-document match the way there is for one
  line. Splitting on lines and reusing configrx_search's own per-line cap
  is what keeps a compliance sweep over 2,000 devices' captures bounded at
  all, at the cost of not supporting a rule that must span more than one
  line — every realistic example in this feature's own brief (an NTP
  server, an SNMP community, port security, a VLAN) is a single directive
  on a single line, so this is a real but narrow scope limit, stated
  plainly rather than silently.

  The per-line cap alone is NOT enough, though — configrx_search.py's own
  _scan() checks a wall-clock budget before every line for exactly this
  reason (its own docstring: "a device with thousands of lines could still
  add those up... without a check this fine-grained"), and this file
  reuses the identical compile_bounded()/bounded_line() machinery, so the
  identical gap applies here. A MUST_NOT_MATCH rule that legitimately
  never matches is the expensive case — proving no match means checking
  EVERY line, not stopping at the first — and a pattern shaped like a
  doubled quantifier (compile_bounded allows up to MAX_ADJACENT_QUANTIFIER_
  RUN chained atoms; a run of exactly that many, like a+a+a+c, is an
  honest mistake, not an attack) costs 0.23s on one 250-character line
  with no match. evaluate_all() runs from ConfigRxWorker._loop on the SAME
  thread that schedules every device's backup — a sweep that takes hours
  to return is a sweep where devices_due() is never checked again in the
  meantime, silently switching off backups for the entire fleet.
  COMPLIANCE_SWEEP_BUDGET_S is the wall-clock ceiling this needs: checked
  before every rule and before every line (evaluate_device's own inner
  loop), so a bad rule bounds the cost of the CALL it is in rather than
  the cost of every line it is run against. A device whose evaluation is
  cut short reads as STATUS_NOT_YET_ASSESSED — never a silent pass, and
  distinct from not_assessed (see below) — unless a rule already failed
  before time ran out, in which case that real, already-detected failure
  is kept rather than hidden behind the timeout. A device or rule set the
  sweep never reached at all is left with whatever result it already had;
  only work actually attempted this call gets a new row written. A normal
  fleet (2,000 devices x 800 realistic lines x 4 realistic rules) finishes
  in well under a second, so the ceiling is headroom for the ordinary case
  and a hard stop for the pathological one.

  Secrets. Unlike configrx_search.py's cross-device index, THIS evaluation
  reads a device's capture exactly as stored — respecting that device's
  own store_secrets setting and that backup row's own `redacted` flag,
  never the always-redacted search index. That is deliberate, not an
  oversight: a compliance RESULT is pass/fail plus the rule's own
  author-written description ("SNMP community must not be a vendor
  default") — never the line that made it pass or fail — so nothing a
  reader of a result ever sees depends on whether the capture underneath
  held a real secret. A rule that genuinely needs to check a secret's
  VALUE (a community string that must not still be a vendor default) can
  only do that against the real text; checking it against
  "<redacted>" would make every device that redacts its captures read as
  a false pass or fail depending on the rule's own kind. The one thing
  this module must never do — and does not — is put a matched LINE
  anywhere a caller without ConfigRX access to that device could read it;
  see set_compliance_result's own column comment in configrxdb.py.

A device with no stored capture reads as status "not_assessed", never a
silent "pass" (a device nobody has backed up yet is not "compliant") and
never counted in the alert metric below (see _record_metric) — an absent
metric key is what the alert engine already reads as "no data", where 0
is what it reads as "definitely fine right now", and those are not the
same claim. A device that DOES have a capture, but whose rules were not
all checked before COMPLIANCE_SWEEP_BUDGET_S ran out, reads as the
distinct STATUS_NOT_YET_ASSESSED instead — also never counted by
_record_metric, for the identical reason: an incomplete check is not a
pass, and reusing "not_assessed" for it would erase the difference
between "nobody has ever backed this device up" and "this device is
backed up and mostly fine, a rule just did not finish being checked in
time."

The scheduled evaluation itself lives in configrx.ConfigRxWorker
(configrx.py, which this module's caller owns): once right after a new
capture is stored for one device (evaluate_device_all_rule_sets), and
once on a periodic sweep across every device (evaluate_all), so a rule
set someone just edited, or a device group someone just re-scoped a rule
set to, catches up within one sweep interval rather than only the next
time that one device happens to be backed up again.

Alerting is a SPECIFICATION, not code here: netpath/alertsdb.py is not
this module's to edit (another agent owns it this campaign), so this
file only records the metric a threshold rule would read —
`compliance_fail_count`, how many rule sets a device currently fails —
and the exact `_BUILTIN_RULES` tuple to add is written out at the bottom
of this docstring for whoever does own that file.

    ("configrx_out_of_compliance", "Device fell out of ConfigRX compliance",
     "threshold", "compliance_fail_count", 3, "threshold_breach", 1.0, 1.0, 1)

Severity 3 (comparable to ups_battery_low, a state a person should look at
soon rather than an emergency); threshold and clear_threshold both 1.0
with for_polls 1 — zero hysteresis, the same call alertsdb.py's own
ups_on_battery rule already makes for a quantized either-or metric ("a UPS
is either running off the mains or it is not" — a device is either
compliant or it is not, and there is no noisy single-sample fluctuation
here to debounce the way there is for cpu_pct or mem_pct).
"""

from __future__ import annotations

import time

from . import configrx_search


class RuleKind:
    MUST_MATCH = "must_match"
    MUST_NOT_MATCH = "must_not_match"


_VALID_KINDS = (RuleKind.MUST_MATCH, RuleKind.MUST_NOT_MATCH)

# The metric evaluate_all/evaluate_device_all_rule_sets record via
# nodes_db.record_metric_samples — see the module docstring for the exact
# alertsdb._BUILTIN_RULES tuple this is meant to be read by.
COMPLIANCE_FAIL_METRIC = "compliance_fail_count"

# Wall-clock ceiling on any ONE call to evaluate_all or
# evaluate_device_all_rule_sets — see the module docstring's "per-line cap
# alone is NOT enough" paragraph for the measurements behind this. 2,000
# devices x 800 realistic lines x 4 realistic rules finishes in well under
# a second; this is headroom for that case and a hard stop for a single
# rule shaped like a typo, not a throttle either has to think about day to
# day.
COMPLIANCE_SWEEP_BUDGET_S = 10.0

# Distinct from "not_assessed" (see module docstring): this device HAS a
# capture and at least some of its rules were checked, there was just not
# time to finish every rule set in scope for it before the budget above
# ran out. Never counted as "assessed" by _record_metric.
STATUS_NOT_YET_ASSESSED = "not_yet_assessed"


def add_rule_set(db, name: str, device_group_id: int | None = None) -> int:
    return db.add_rule_set(name, device_group_id)


def add_rule(db, rule_set_id: int, description: str, kind: str, pattern: str,
            ordinal: int = 0) -> int:
    """Stores one rule — after, not instead of, validating it.

    `kind` must be RuleKind.MUST_MATCH or MUST_NOT_MATCH; `pattern` is run
    through configrx_search.compile_bounded (raises UnsafeRegex, the same
    exception a caller turns into a 400 for a search query) before this
    ever reaches the database. This is the ONLY place a rule's pattern
    should be validated — configrxdb.add_rule itself just stores what it
    is given, so calling that directly instead of this would bypass the
    check.
    """
    if kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}, got {kind!r}")
    if not description or not description.strip():
        raise ValueError("A rule needs a human-readable description")
    configrx_search.compile_bounded(pattern)
    return db.add_rule(rule_set_id, description, kind, pattern, ordinal)


def _device_ids_in_scope(nodes_db, rule_set_row) -> list[int]:
    group_id = rule_set_row["device_group_id"]
    rows = (nodes_db.devices(device_group_id=group_id) if group_id is not None
           else nodes_db.devices())
    return [row["id"] for row in rows]


def evaluate_device(db, device_id: int, rules, deadline: float | None = None) -> dict:
    """One device against an already-fetched list of compliance_rules rows
    — evaluate_all/evaluate_device_all_rule_sets fetch a rule set's rules
    once, not once per device. Returns {"status", "failed_rules",
    "backup_id", "truncated"}; does not write anything (see
    set_compliance_result, which the caller runs). status is
    "not_assessed" — not "pass" — for a device with no stored capture at
    all. See the module docstring for why this reads the capture exactly
    as stored, line by line, rather than the always-redacted search index
    or a single whole-document match.

    `deadline`, when given, is a time.monotonic() ceiling checked before
    every rule AND before every line within a rule's own scan — the
    latter is what actually matters, since a single MUST_NOT_MATCH rule
    that never matches must check every line to prove that, and that is
    exactly the cost the module docstring measures blowing up
    unbounded. Hitting it stops evaluation of THIS device immediately
    (truncated=True in the result) rather than finishing the remaining
    rules however long that takes. A rule already found failing before
    the deadline hit is kept in `failed_rules` — a real, already-detected
    failure is never hidden behind a timeout — so status is "fail" if
    anything failed, STATUS_NOT_YET_ASSESSED if nothing failed yet but
    the scan was cut short, and "pass" only when every rule was actually
    checked to completion.
    """
    backups = db.backups_for(device_id, limit=1)
    if not backups:
        return {"status": "not_assessed", "failed_rules": [], "backup_id": None,
               "truncated": False}
    backup_id = backups[0]["id"]
    content = db.backup_content(backup_id) or ""
    lines = [configrx_search.bounded_line(line) for line in content.split("\n")]

    failed = []
    truncated = False
    for rule in rules:
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        try:
            pattern = configrx_search.compile_bounded(rule["pattern"])
        except configrx_search.UnsafeRegex:
            # A row that somehow got stored unsafely — a rule saved before
            # this check existed, or compile_bounded's own rules
            # tightening in a later release — fails CLOSED: counted as a
            # failure with its own description, never silently skipped,
            # so "this rule needs attention" is what a reader sees rather
            # than the rule quietly vanishing from every result.
            failed.append({"rule_id": rule["id"], "description": rule["description"]})
            continue
        matched = False
        for line in lines:
            if deadline is not None and time.monotonic() > deadline:
                truncated = True
                break
            if pattern.search(line):
                matched = True
                break
        if truncated:
            # This rule was not actually resolved either way — do not
            # score it as pass or fail, just stop.
            break
        ok = matched if rule["kind"] == RuleKind.MUST_MATCH else not matched
        if not ok:
            failed.append({"rule_id": rule["id"], "description": rule["description"]})

    if failed:
        status = "fail"
    elif truncated:
        status = STATUS_NOT_YET_ASSESSED
    else:
        status = "pass"
    return {"status": status, "failed_rules": failed, "backup_id": backup_id,
           "truncated": truncated}


def _record_metric(nodes_db, db, device_id: int) -> None:
    """See the module docstring's alert-rule spec. Reads back this
    device's own just-written results rather than accumulating a running
    total in the caller, so it stays correct regardless of how many rule
    sets the caller evaluated this device against in one pass. Records
    nothing for a device every result of which is "not_assessed" — a
    device nobody has ever captured must leave no metric sample at all,
    not a 0 a threshold rule would read as "compliant". A device with a
    STATUS_NOT_YET_ASSESSED result (see evaluate_device) is excluded the
    same way and for the same reason — its rules were not all checked, so
    it does not get to read as compliant just because none of the rules
    checked so far happened to fail."""
    results = db.compliance_results_for_device(device_id)
    assessed = [r for r in results if r["status"] in ("pass", "fail")]
    if not assessed:
        return
    fail_count = sum(1 for r in assessed if r["status"] == "fail")
    nodes_db.record_metric_samples(device_id, [
        (COMPLIANCE_FAIL_METRIC, "ConfigRX rule sets failing", "count",
         "gauge", time.time(), fail_count),
    ])


def evaluate_device_all_rule_sets(db, nodes_db, device_id: int,
                                  budget_s: float | None = COMPLIANCE_SWEEP_BUDGET_S,
                                  stats: dict | None = None) -> int:
    """Every enabled rule set in scope for this one device — the call
    configrx.ConfigRxWorker._backup_device makes right after storing a new
    capture, so a change is reflected without waiting for the next
    scheduled sweep. Returns how many rule sets were (re)evaluated — the
    same int this always returned, so an existing caller that only reads
    the count sees no change in behaviour for the ordinary case.

    `budget_s` is a wall-clock ceiling for this WHOLE call (default
    COMPLIANCE_SWEEP_BUDGET_S; pass None only if a caller genuinely wants
    unbounded evaluation, e.g. a test with a small fixed fixture) — see
    the module docstring for why an unbounded evaluation is dangerous when
    this runs on the same thread that schedules backups. When the budget
    is reached partway through, remaining rule sets in scope are left
    untouched (whatever result they already had stands) rather than
    written over with a rushed one; pass a `stats` dict to learn whether
    that happened (`stats["truncated"]`) so a caller that logs can say so.
    """
    device = nodes_db.device(device_id)
    if not device:
        return 0
    deadline = time.monotonic() + budget_s if budget_s is not None else None
    count = 0
    truncated = False
    for rule_set in db.rule_sets(enabled_only=True):
        group_id = rule_set["device_group_id"]
        if group_id is not None and device["device_group_id"] != group_id:
            continue
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        rules = db.rules_for(rule_set["id"])
        result = evaluate_device(db, device_id, rules, deadline=deadline)
        db.set_compliance_result(device_id, rule_set["id"], result["status"],
                                 result["failed_rules"], result["backup_id"])
        count += 1
        if result["truncated"]:
            truncated = True
            break
    if count:
        _record_metric(nodes_db, db, device_id)
    if stats is not None:
        stats["truncated"] = truncated
    return count


def evaluate_all(db, nodes_db, rule_set_id: int | None = None,
                 budget_s: float | None = COMPLIANCE_SWEEP_BUDGET_S,
                 stats: dict | None = None) -> int:
    """Every device in scope, for one rule set (rule_set_id given) or
    every enabled one (the default) — the periodic sweep
    configrx.ConfigRxWorker._loop runs, and what a manual "re-evaluate
    now" action would call. Returns how many device x rule-set results
    were (re)computed — the same int this always returned; an existing
    caller that only reads the count sees no change in behaviour for the
    ordinary (well under budget) case.

    `budget_s` is a wall-clock ceiling for this WHOLE call (default
    COMPLIANCE_SWEEP_BUDGET_S; pass None only if a caller genuinely wants
    to run to completion regardless of how long that takes — see the
    module docstring for exactly why the default must not be None: this
    is called from ConfigRxWorker._loop, the same thread that schedules
    every device's backup). Checked before starting each rule set, before
    each device within it, AND inside evaluate_device itself before each
    rule and each line — the last of those is what actually bounds a
    single bad MUST_NOT_MATCH rule, since proving "never matches" means
    scanning every line. A rule set or device the budget was reached
    before reaching at all is left with whatever result it already had —
    only work actually attempted this call gets a new row written,
    including a device evaluate_device cut short partway through (see its
    own docstring for how that scores). Pass a `stats` dict to learn
    whether the budget was hit (`stats["truncated"]`) so a caller that
    logs, or counts, can say so — see configrx.py's own counters for
    where that lands.
    """
    if rule_set_id is not None:
        row = db.rule_set(rule_set_id)
        rule_sets = [row] if row is not None and row["enabled"] else []
    else:
        rule_sets = db.rule_sets(enabled_only=True)

    deadline = time.monotonic() + budget_s if budget_s is not None else None
    count = 0
    truncated = False
    touched_devices: set[int] = set()
    for rule_set in rule_sets:
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        device_ids = _device_ids_in_scope(nodes_db, rule_set)
        rules = db.rules_for(rule_set["id"])
        for device_id in device_ids:
            if deadline is not None and time.monotonic() > deadline:
                truncated = True
                break
            result = evaluate_device(db, device_id, rules, deadline=deadline)
            db.set_compliance_result(device_id, rule_set["id"], result["status"],
                                     result["failed_rules"], result["backup_id"])
            touched_devices.add(device_id)
            count += 1
            if result["truncated"]:
                truncated = True
                break
        if truncated:
            break
    for device_id in touched_devices:
        _record_metric(nodes_db, db, device_id)
    if stats is not None:
        stats["truncated"] = truncated
    return count

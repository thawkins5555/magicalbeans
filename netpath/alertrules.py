"""Alert rule evaluation: the Occurrence shape the engine turns into (or
increments) an alert, rule/occurrence matching, and the built-in
cross-occurrence evaluators (interface flapping, threshold hysteresis).

kind='device_event' and kind='interface_event' occurrences need no
per-rule evaluator function at all — the engine's drain functions already
emit exactly one Occurrence per event row, and rule matching is just
(rule.kind, rule.source_kind) == (occurrence.kind, occurrence.source_kind)
plus match_device(). Evaluator functions exist only for the two kinds that
need cross-occurrence logic: flapping (many events -> one occurrence) and
threshold (a live value against hysteresis, not an event at all).
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field

SEVERITY_NAMES = ["emergency", "alert", "critical", "error", "warning",
                  "notice", "informational", "debug"]


@dataclass
class Occurrence:
    """One fact the engine learned this tick, on its way to becoming (or
    incrementing) an alert."""
    kind: str              # matches rules.kind
    source_kind: str       # matches rules.source_kind
    entity_kind: str
    entity_id: str
    entity_label: str
    ts: float
    message: str
    severity: int | None = None  # syslog occurrences only; 0=most severe
    detail: str = ""
    device_name: str = ""  # for device_filter matching, independent of entity_label's exact text
    device_ip: str = ""
    extra: dict = field(default_factory=dict)   # template context extras (trap_name, value, etc.)
    # Whether the sender is a device this installation polls. None where the
    # question does not apply (thresholds, device events — those are about a
    # device by construction); True/False for traps and syslog, where it is
    # the difference between a port flapping on a switch we monitor and one
    # on somebody else's. New fields go at the END with a default: parked
    # occurrences are stored as JSON and replayed through Occurrence(**row),
    # so a row written before this field existed must still load.
    managed: bool | None = None
    # kind="threshold" only: the source rule's own key. Two threshold rules
    # CAN legitimately share a source_kind — ups_battery_low/
    # ups_battery_replace already did, and temp_chassis_high/
    # temp_chassis_critical now read the same temp_chassis_c metric on
    # purpose (see alertsdb._BUILTIN_RULES) — and AlertEngine._apply matches
    # an occurrence against every enabled rule with the same (kind,
    # source_kind), not just the one that raised it. Without this field, an
    # occurrence _evaluate_thresholds built for evaluating ONE rule's own
    # threshold/streak also matched the OTHER rule sharing the metric,
    # double-incrementing it with the wrong rule's message. Left "" (falsy,
    # and the default for every other kind) so _apply's extra check only
    # ever narrows a threshold occurrence to its own rule, never changes
    # matching for anything else — including a pending occurrence parked
    # before this field existed, which loads with "" the same way.
    rule_key: str = ""


def dedup_key(rule, occurrence: Occurrence) -> str:
    """rule.key + entity — the same (device_down, device #7) pair always
    maps to the same open alert regardless of how many times it recurs."""
    return f"{rule['key']}:{occurrence.entity_kind}:{occurrence.entity_id}"


# The Cisco/IOS-XE/NX-OS message identifier: %FACILITY-SEVERITY-MNEMONIC.
# Anchored on the literal % and the two dashes, so it matches the identifier
# and not, say, a percentage in the free text after it.
_CISCO_MNEMONIC = re.compile(r"%([A-Z0-9_$]{2,32})-(\d)-([A-Z0-9_$]{2,32})")

# Everything a message can carry that varies between two reports of the SAME
# fault: interface indexes, session ids, byte counts, addresses.
_DIGITS = re.compile(r"\d")


def syslog_signature(message: str) -> str:
    """A stable identifier for "the same kind of syslog message".

    Syslog alerts used to dedup on the source host alone, so three unrelated
    faults on one switch became one alert row and open_or_increment
    overwrote the first two messages with the third. The fix is to put
    something about the message itself in the dedup key — but not the message
    verbatim, or "session 123 failed" and "session 456 failed" would be two
    alerts for one problem and a flapping port would open one row per event.

    Two forms, in order:

    - The Cisco mnemonic where there is one. %LINK-3-UPDOWN is precisely the
      vendor's own answer to "what kind of message is this", it is stable
      across releases, and it deliberately excludes the interface name — a
      switch with two ports bouncing is one fault to look at, not two.
    - Otherwise a short hash of the message with every digit replaced by '#'
      and whitespace collapsed, over the first 200 characters. Digits are
      what varies between repeats; 200 characters is enough to tell two
      messages apart and short enough that a long payload cannot make every
      occurrence unique.

    The "h" prefix keeps the two forms visibly distinct in a dedup key.
    """
    text = str(message or "")
    match = _CISCO_MNEMONIC.search(text)
    if match:
        return f"%{match.group(1)}-{match.group(2)}-{match.group(3)}"
    normalized = " ".join(_DIGITS.sub("#", text).split())[:200]
    return "h" + hashlib.sha1(
        normalized.encode("utf-8", "replace")).hexdigest()[:12]


# Rules that are ONLY about senders this installation does not poll. The
# shipped one is the link-down trap: a managed switch's port going down is
# already reported by interface_down from polling, so raising a second
# "unmanaged device" alert for it named the wrong thing three times over.
# The rule has advertised this check since it shipped and never performed it.
UNMANAGED_ONLY_RULES = frozenset({"trap_link_down_unmanaged"})


def device_id_for(entity_kind: str, entity_id) -> int | None:
    """The Nodes device an alert/occurrence entity is about, or None when it
    is about nothing in Nodes.

    One rule, in the one module both the engine and the web API already
    import: a `device` entity's id IS the device id, an `interface` entity's
    is "<device_id>:<if_index>" and resolves to the switch the port is on --
    which is why muting a switch silences its ports with it -- and everything
    structurally outside Nodes (traps from unpolled hosts, syslog from an
    unknown source, IPAM conflicts, DHCP scopes, wireless APs, NetPath
    destinations) resolves to nothing and therefore cannot be muted.

    It lived in three places before 4.37.1 (the engine's mute check, the
    engine's hold/still-true lookup and the API's alert row), which is three
    chances for a future entity kind to be taught to two of them.
    """
    try:
        if entity_kind == "device":
            return int(entity_id)
        if entity_kind == "interface":
            return int(str(entity_id).split(":")[0])
    except (TypeError, ValueError):
        return None
    return None


def _field(row, name: str) -> str:
    try:
        value = row[name]
    except (TypeError, KeyError, IndexError):
        return ""
    return str(value or "").strip()


def interface_label(row, if_index=None) -> str:
    """A port as an operator names it: "GigabitEthernet1/0/7 (uplink to
    core)".

    The alias is appended only when it adds something -- a device that
    copies ifDescr into ifAlias would otherwise produce "Gi1/0/7 (Gi1/0/7)".
    `if<n>` is the last resort, for a metric whose interface row has since
    been replaced by a re-walk.
    """
    descr = _field(row, "descr")
    alias = _field(row, "alias")
    if if_index is None:
        if_index = _field(row, "if_index") or None
    name = descr or alias or (f"if{if_index}" if if_index is not None
                              else "interface")
    if alias and alias.lower() != name.lower():
        return f"{name} ({alias})"
    return name


def match_device(rule, occurrence: Occurrence) -> bool:
    """Empty device_filter matches everything. Otherwise a case-insensitive
    substring match against device_name or device_ip."""
    text = (rule["device_filter"] or "").strip()
    if not text:
        return True
    text = text.lower()
    return text in occurrence.device_name.lower() or text in occurrence.device_ip.lower()


def evaluate_flapping(recent_interface_events: list, window_s: float = 600,
                      min_transitions: int = 3) -> bool:
    """True if the same interface has at least min_transitions link_down/
    link_up events within window_s. `recent_interface_events` is already
    filtered to one interface, newest-first, each a dict with a 'ts' key."""
    if len(recent_interface_events) < min_transitions:
        return False
    newest_ts = recent_interface_events[0]["ts"]
    within_window = [e for e in recent_interface_events
                     if newest_ts - e["ts"] <= window_s]
    return len(within_window) >= min_transitions


def comparison_of(rule) -> str:
    """A threshold rule's direction: 'below' for a low-water rule, 'above'
    for every other. Read through here, not off the row directly, because
    an older database row (or a plain dict built by a test) has no such
    column."""
    try:
        keys = rule.keys()
    except AttributeError:
        keys = rule
    if "comparison" not in keys:
        return "above"
    return "below" if str(rule["comparison"] or "above") == "below" else "above"


def _metric_root_of(rule) -> str:
    """A threshold rule's metric family (rules.source_kind), read the same
    defensive way comparison_of reads its own column: a plain dict built by
    a test need not carry one."""
    try:
        keys = rule.keys()
    except AttributeError:
        keys = rule
    if "source_kind" not in keys:
        return ""
    return str(rule["source_kind"] or "")


# An optic with no fiber in it, or a port powered down, reports the bottom
# of its own scale rather than a fault: -40 dBm is where the common vendors
# clamp, and nothing that is actually working ever reads there (receive
# sensitivity bottoms out around -23 dBm on the worst 1G/10G part). A 0 is
# the same statement from an agent quoting milliwatts of nothing, and a
# non-finite value is an agent with no reading at all to give.
DARK_OPTIC_DBM = -40.0
_DARK_OPTIC_TOLERANCE_DB = 0.5
# The two metric families (rules.source_kind) a dark reading may silence.
# Keyed off the family, not off the value alone, so no other 'below' rule
# can ever inherit this.
OPTIC_POWER_METRICS = frozenset({"sfp_rx_dbm", "sfp_tx_dbm"})


def is_dark_optic(metric_root: str, value) -> bool:
    """Whether an optical-power reading means "no light" rather than "too
    little light". Lives here rather than in the poller because both ends
    have to agree on it: nodepoll keeps dark lanes out of a multi-lane
    optic's worst-of, and breaches() below refuses to alert on one."""
    if metric_root not in OPTIC_POWER_METRICS:
        return False
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    if not math.isfinite(value):
        return True
    return value == 0.0 or value <= DARK_OPTIC_DBM + _DARK_OPTIC_TOLERANCE_DB


def breaches(rule, value) -> bool:
    """Whether `value` is on the wrong side of `rule`'s threshold. The one
    place the direction lives -- _evaluate_thresholds counts its streak
    with this same predicate, so streak and verdict never disagree."""
    if value is None:
        return False
    threshold = rule["threshold"]
    if threshold is None:
        return False
    # Guarded here rather than where the metric is written: threshold_stale_s
    # is 900 s, so a -40 already recorded would go on re-evaluating for
    # fifteen minutes, and one written by an older build would never expire
    # at all.
    if is_dark_optic(_metric_root_of(rule), value):
        return False
    if comparison_of(rule) == "below":
        return value <= threshold
    return value >= threshold


def _clears(rule, value) -> bool:
    """Whether `value` has recovered past `rule`'s clear threshold -- for a
    'below' rule this means ABOVE the clear threshold, the far side of the
    hysteresis band from breaches() above."""
    if value is None:
        return False
    clear_threshold = rule["clear_threshold"]
    if clear_threshold is None:
        return False
    if comparison_of(rule) == "below":
        return value > clear_threshold
    return value < clear_threshold


def evaluate_threshold(rule, current_value: float | None, streak: int,
                       breach_seconds: float = 0.0) -> str:
    """Returns 'breach' once current_value is on the wrong side of
    rule.threshold and the breach has been sustained long enough; 'clear'
    once a value has recovered past rule.clear_threshold; '' otherwise
    (either not sustained yet, or in the hysteresis gap between
    clear_threshold and threshold). The threshold/clear_threshold gap is
    hysteresis — without it a value oscillating exactly at the threshold
    reopens and recloses the alert every single poll.

    Direction is rule.comparison's call, via breaches()/_clears() above:
    for a 'below' rule (an optic whose receive power has fallen) the band
    is entered from the other end, so clear_threshold sits ABOVE threshold.

    "Long enough" is measured one of two ways, and only ever one:

    - `for_seconds` set: the breach must have lasted that many seconds of
      real sample time. `breach_seconds` is how long the metric has been
      continuously at or over the threshold, measured between the sample
      timestamps themselves — never between engine ticks, which run every
      five seconds regardless of whether anything was polled.
    - `for_seconds` NULL (the shipped default for every rule but packet
      loss): `streak` consecutive polls at or over the threshold, including
      this one, must reach `for_polls`.

    Both counters are the caller's to keep, and both must only advance when
    a genuinely new sample arrives; see alertengine._evaluate_thresholds."""
    if current_value is None:
        return ""
    if rule["threshold"] is None:
        return ""
    if breaches(rule, current_value):
        for_seconds = rule["for_seconds"] if "for_seconds" in rule.keys() else None
        if for_seconds:
            return "breach" if breach_seconds >= float(for_seconds) else ""
        for_polls = max(1, int(rule["for_polls"] or 1))
        return "breach" if streak >= for_polls else ""
    if _clears(rule, current_value):
        return "clear"
    return ""


# CLEARS: an occurrence of this kind/source_kind automatically resolves any
# open alert whose dedup_key matches the *paired* rule's dedup_key for the
# same entity — e.g. a device_up occurrence resolves the device_down alert
# for that same device, without device_up needing its own alert to stay
# open (device_up's own rule can still independently fire its own
# short-lived recovery notification per notify_on_clear).
CLEARS = {
    ("device_event", "up"): "device_down",
    ("device_event", "auth_ok"): "device_auth_fail",
    # mib_present is recorded when a device's vendor-MIB coverage flips
    # from missing to present (a MIB got uploaded), pairing with
    # mib_missing exactly the way up pairs with down.
    ("device_event", "mib_present"): "mib_missing",
    ("interface_event", "link_up"): "interface_down",
    # ap_returned is recorded whenever upsert_ap inserts a brand-new AP
    # row — including one that was previously aged out and reappeared. A
    # genuinely new AP resolves nothing (no matching open alert), so the
    # pairing is noise-free.
    ("wireless_event", "ap_returned"): "wireless_ap_removed",
    # An AP whose connection state comes back to online clears its offline
    # alert, the same pairing one line up — recorded by
    # wirelessdb._record_status_change on the transition, so it fires once
    # rather than on every poll that finds it healthy.
    ("wireless_event", "ap_online"): "wireless_ap_offline",
    # threshold clears are handled by evaluate_threshold's 'clear' return,
    # not this map, since they're keyed by (rule, entity) not a fixed pair
}


# The entity kinds that take part in rollup at all. A rollup pairing says
# "this alert is implied by that one about the SAME thing", so it is only
# meaningful where an entity can have both; listing the kinds explicitly stops
# a future entity kind inheriting the device pairings by accident.
#
# `interface` joined in 5.1.0: a dead switch's ports report nothing, so a
# per-port utilization/error-rate alert is as much an outage artefact as
# the device-level one it replaced. This set is necessary but not
# sufficient -- ROLLED_UP_BY below is the actual gate.
ROLLUP_ENTITY_KINDS = frozenset({"device", "interface", "netpath_target"})


# ROLLED_UP_BY: rule key -> the rule key whose open alert makes it redundant.
#
# A device that has stopped answering will always also look slow and lossy,
# and its CPU, memory, interface and storage metrics will all be stale or
# absent — so a single outage used to arrive as five or six emails saying the
# same thing in different words. Every rule here measures something that can
# only be measured BY polling the device, so an open "Device not responding"
# already says it.
#
# Static, mirroring CLEARS above, because "which alerts a dead device implies"
# is a property of what this app measures, not a per-site preference. The
# alerts setting `rollup_enabled` is the on/off switch, not a rewrite of this.
#
# Deliberately NOT here: interface_down, interface_up and interface_flapping.
# Those come from ifOperStatus transitions the device itself reported before
# it went away, and a port that went down for its own reason stays worth
# knowing about — it is a fact about the network, not an artefact of the
# device being unreachable.
#
# Suppressing a neighbour's port transitions when a chassis loses power would
# need to know which port faces which device: upstream_id records the device
# relationship but not the interface, and the LLDP/CDP `neighbors` table's
# device match is a suggestion, not a fact an operator confirmed. Suppressing
# a real port fault whenever that guess is wrong is the one failure mode an
# alert system must not have, so this stays undone by choice.
ROLLED_UP_BY = {
    # ping, measured by this app's own probes
    "response_time_high": "device_down",
    "packet_loss_high": "device_down",
    # SNMP-polled device metrics
    "cpu_high": "device_down",
    "mem_high": "device_down",
    "disk_high": "device_down",
    "if_in_util_high": "device_down",
    "if_out_util_high": "device_down",
    "if_in_errors_high": "device_down",
    "if_out_errors_high": "device_down",
    "if_in_discards_high": "device_down",
    "if_out_discards_high": "device_down",
    # A poll that overran because every request timed out says nothing the
    # outage does not. nodepoll._record_overrun already declines to record
    # one while the device is failing, so this only catches an overrun
    # alert opened in the moments before the first poll actually failed.
    "poll_overrun": "device_down",
    # NetPath: a destination nothing comes back from is also, necessarily, a
    # path whose traces are not reaching it and one whose latency cannot be
    # measured. One broken path is one alert, the same rule as an unreachable
    # device — and the same recovery mechanism too, since all three re-derive
    # from the next trace rather than needing to be un-suppressed.
    "netpath_path_unstable": "netpath_unreachable",
    "netpath_latency_high": "netpath_unreachable",
    # Not an outage rollup like every entry above — both rules read the SAME
    # temp_chassis_c metric (see alertsdb._BUILTIN_RULES), so a device at
    # 90 C breaches both. Reusing ROLLED_UP_BY here rather than inventing a
    # second suppression mechanism: "an open Critical already says what
    # Warning is about to say" is exactly the shape this map already exists
    # to express, and _rollup_parent's case 1 (a same-entity open parent
    # alert) is entity-kind generic — it only special-cases device_down for
    # the topology cases (2 and 3), which a same-metric pair like this one
    # has no use for and simply never reaches. _apply's own is_new handling
    # (ROLLS_UP, built from this map) is what retroactively resolves a
    # Warning that opened moments before Critical did in the same tick.
    "temp_chassis_high": "temp_chassis_critical",
    # DOM is read by polling the device, so a switch that stopped
    # answering reports no optic readings -- an outage artefact, like the
    # temperature pair above.
    "sfp_rx_power_low": "device_down",
    "sfp_tx_power_low": "device_down",
    "sfp_temp_high": "device_down",
}

# The rules that roll up under a given parent, the other way round — built
# once here rather than scanned per tick.
ROLLS_UP: dict[str, tuple[str, ...]] = {}
for _child, _parent in ROLLED_UP_BY.items():
    ROLLS_UP[_parent] = ROLLS_UP.get(_parent, ()) + (_child,)
del _child, _parent

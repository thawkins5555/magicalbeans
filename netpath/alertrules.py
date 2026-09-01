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


def dedup_key(rule, occurrence: Occurrence) -> str:
    """rule.key + entity — the same (device_down, device #7) pair always
    maps to the same open alert regardless of how many times it recurs."""
    return f"{rule['key']}:{occurrence.entity_kind}:{occurrence.entity_id}"


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


def evaluate_threshold(rule, current_value: float | None, streak: int) -> str:
    """Returns 'breach' once current_value is over rule.threshold AND
    `streak` (consecutive polls at/over threshold *including this one* —
    the caller increments it before calling this) reaches rule.for_polls;
    'clear' once a value drops below rule.clear_threshold; '' otherwise
    (either still under for_polls, or in the hysteresis gap between
    clear_threshold and threshold). The threshold/clear_threshold gap is
    hysteresis — without it a value oscillating exactly at the threshold
    reopens and recloses the alert every single poll."""
    if current_value is None:
        return ""
    threshold = rule["threshold"]
    clear_threshold = rule["clear_threshold"]
    if threshold is None:
        return ""
    if current_value >= threshold:
        for_polls = max(1, int(rule["for_polls"] or 1))
        return "breach" if streak >= for_polls else ""
    if clear_threshold is not None and current_value < clear_threshold:
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
}

# The rules that roll up under a given parent, the other way round — built
# once here rather than scanned per tick.
ROLLS_UP: dict[str, tuple[str, ...]] = {}
for _child, _parent in ROLLED_UP_BY.items():
    ROLLS_UP[_parent] = ROLLS_UP.get(_parent, ()) + (_child,)
del _child, _parent

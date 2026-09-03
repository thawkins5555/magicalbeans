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


def evaluate_threshold(rule, current_value: float | None, streak: int,
                       breach_seconds: float = 0.0) -> str:
    """Returns 'breach' once current_value is over rule.threshold and the
    breach has been sustained long enough; 'clear' once a value drops below
    rule.clear_threshold; '' otherwise (either not sustained yet, or in the
    hysteresis gap between clear_threshold and threshold). The
    threshold/clear_threshold gap is hysteresis — without it a value
    oscillating exactly at the threshold reopens and recloses the alert
    every single poll.

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
    threshold = rule["threshold"]
    clear_threshold = rule["clear_threshold"]
    if threshold is None:
        return ""
    if current_value >= threshold:
        for_seconds = rule["for_seconds"] if "for_seconds" in rule.keys() else None
        if for_seconds:
            return "breach" if breach_seconds >= float(for_seconds) else ""
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


# The entity kinds that take part in rollup at all. A rollup pairing says
# "this alert is implied by that one about the SAME thing", so it is only
# meaningful where an entity can have both; listing the kinds explicitly stops
# a future entity kind inheriting the device pairings by accident.
ROLLUP_ENTITY_KINDS = frozenset({"device", "netpath_target"})


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
# The reviewer's counter-argument is real: when a chassis loses power the
# transitions that matter come from its NEIGHBOURS' ports, and those genuinely
# ARE implied by the downstream outage. Suppressing them needs to know which
# port faces which device, and nothing in this application knows that —
# devices.upstream_id (4.37) records the device relationship but not the
# interface, and there is no LLDP/CDP neighbour walk. Guessing from MAC
# forwarding tables would suppress a real port fault whenever the guess was
# wrong, which is the one failure mode an alert system must not have. Left
# undone on purpose until there is a neighbour table to consult.
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
}

# The rules that roll up under a given parent, the other way round — built
# once here rather than scanned per tick.
ROLLS_UP: dict[str, tuple[str, ...]] = {}
for _child, _parent in ROLLED_UP_BY.items():
    ROLLS_UP[_parent] = ROLLS_UP.get(_parent, ()) + (_child,)
del _child, _parent

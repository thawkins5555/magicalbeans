"""Vendor identification from what a device actually answers.

Pure functions: nothing here opens a socket or a database. The poller and
the discovery sweep hand in a `getnext` callable and walked rows; the
database hands in its MIB objects; this module decides and explains.

The idea that makes it affordable
---------------------------------
Vendor identity lives entirely under 1.3.6.1.4.1 (`enterprises`). Which
enterprise arcs a device populates can be enumerated in (arcs + 1) GETNEXTs
by *hopping*: GETNEXT 1.3.6.1.4.1 lands on the first populated arc N;
GETNEXT 1.3.6.1.4.1.(N+1) skips arc N entirely and lands on the next. A
device usually populates two to six arcs, so this is cheaper than one poll
— and it finds vendors this app holds no MIB for, because the arc number
alone names them through enterprises.py.

Precedence (see decide())
-------------------------
manual > learned > a real vendor arc in sysObjectID > the walk > sysDescr >
a generic-agent arc > nothing. A real vendor arc in sysObjectID is an IANA
assignment and stays authoritative; the walk decides only when sysObjectID
is a generic agent (net-snmp, UCD) or outside `enterprises`, where it
outranks the sysDescr substring guess. The walk never substitutes a
different arc for a real one: OEM gear routinely implements the chipset
vendor's arc alongside its own.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import enterprises
from .nodeoids import ENTERPRISES, GENERIC_AGENT_VENDORS, enterprise_arc, oid_key, \
    vendor_for, vendor_from_descr

MAX_ARCS = 64
PER_ARC_OBJECTS = 150
PER_ARC_BUDGET_S = 5.0
GENERIC_ARCS = frozenset({8072, 2021})   # netSnmp, ucdavis — the agent, not the maker

SOURCES = ("manual", "learned", "sysObjectID", "walk", "sysDescr", "oid", "")
CONFIDENCES = ("high", "medium", "low", "")


# ------------------------------------------------------------- arc hopping

@dataclass
class HopResult:
    arcs: list[int] = field(default_factory=list)
    requests: int = 0
    stopped: str = ""


def hop_enterprise_arcs(getnext, max_arcs: int = MAX_ARCS) -> HopResult:
    """Enumerate the enterprise arcs a device populates.

    `getnext(oid)` returns `(oid, type, value)` for the next object, or
    None when the agent signalled the end (endOfMibView, noSuchObject,
    noSuchInstance, an empty reply, or a non-zero error-status such as a v1
    agent's noSuchName). It raises SnmpTimeout/SnmpError otherwise; both are
    caught here and named in `stopped`, keeping the arcs found so far — a
    partial answer is still an answer.

    Two loop guards, because a looping agent is the one failure that would
    otherwise never end: the reply must be strictly greater than the probe,
    and its arc must be greater than the last arc recorded.
    """
    result = HopResult()
    probe = ENTERPRISES
    while True:
        if len(result.arcs) >= max_arcs:
            result.stopped = f"{max_arcs}-arc cap"
            break
        try:
            result.requests += 1
            answer = getnext(probe)
        except Exception as exc:   # SnmpTimeout / SnmpError; nothing else reaches here
            name = exc.__class__.__name__
            result.stopped = ("timeout" if "Timeout" in name
                              else f"agent error ({exc})" if str(exc) else f"agent error ({name})")
            break
        if answer is None:
            result.stopped = "endOfMibView"
            break
        oid = str(answer[0] or "")
        if not oid.startswith(ENTERPRISES + "."):
            result.stopped = "end of enterprises"
            break
        if oid_key(oid) <= oid_key(probe):
            result.stopped = "non-increasing OID"
            break
        arc = enterprise_arc(oid)
        if arc is None:
            result.stopped = "malformed OID"
            break
        if result.arcs and arc <= result.arcs[-1]:
            result.stopped = "non-increasing arc"
            break
        result.arcs.append(arc)
        probe = f"{ENTERPRISES}.{arc + 1}"
    if not result.stopped:
        result.stopped = "end of enterprises"
    return result


# ------------------------------------------------------------ MIB corpus

@dataclass
class MibIndex:
    prefixes: dict[str, set[int]] = field(default_factory=dict)   # object OID -> {mib_file_id}
    arcs_by_file: dict[int, set[int]] = field(default_factory=dict)
    names: dict[int, str] = field(default_factory=dict)          # mib_file_id -> module/filename
    root_only: set[int] = field(default_factory=set)


def build_mib_index(rows, files) -> MibIndex:
    """`rows` = (mib_file_id, oid) for every resolved object under
    `enterprises`; `files` = rows with id/module/filename.

    A file is root-only when every enterprise object it owns is exactly the
    arc itself (seven parts) — the bundled enterprise-roots.mib entries.
    Those name a vendor and describe nothing, so they must not score as
    coverage; the same "strictly below the arc" rule nodesdb.has_mib_covering
    applies. Files are tracked as a *set* per OID: two MIBs can define the
    same object, and neither should silently lose the credit.
    """
    index = MibIndex()
    below_arc: dict[int, bool] = {}
    for mib_file_id, oid in rows:
        if not oid:
            continue
        arc = enterprise_arc(oid)
        if arc is None:
            continue
        index.prefixes.setdefault(oid, set()).add(mib_file_id)
        index.arcs_by_file.setdefault(mib_file_id, set()).add(arc)
        if len(oid.split(".")) > 7:
            below_arc[mib_file_id] = True
        else:
            below_arc.setdefault(mib_file_id, False)
    for mib_file_id, has_objects in below_arc.items():
        if not has_objects:
            index.root_only.add(mib_file_id)
    for row in files:
        index.names[row["id"]] = row["module"] or row["filename"] or str(row["id"])
    return index


@dataclass
class Candidate:
    mib_file_id: int
    module: str
    arc: int
    seen: int
    named: int
    score: float

    def json(self) -> dict:
        return {"mib_file_id": self.mib_file_id, "module": self.module, "arc": self.arc,
                "seen": self.seen, "named": self.named, "score": round(self.score, 3)}


def _owners(index: MibIndex, oid: str) -> set[int]:
    """Every file with an object that is this OID or an ancestor of it."""
    parts = oid.split(".")
    owners: set[int] = set()
    for cut in range(len(parts), 6, -1):
        hit = index.prefixes.get(".".join(parts[:cut]))
        if hit:
            owners |= hit
    return owners


def fingerprint(rows_by_arc: dict[int, list[str]], index: MibIndex) -> list[Candidate]:
    """Score every installed MIB against what was walked under each arc.

    For each (file, arc): `seen` = objects walked under that arc, `named` =
    those the file has an object for (itself or an ancestor). Ranked by
    score then by absolute count, so a file that names 90 % of 150 objects
    beats one that names 100 % of 2.
    """
    candidates: list[Candidate] = []
    for arc, oids in rows_by_arc.items():
        if arc in GENERIC_ARCS or not oids:
            continue
        named_by: dict[int, int] = {}
        for oid in oids:
            for mib_file_id in _owners(index, oid):
                named_by[mib_file_id] = named_by.get(mib_file_id, 0) + 1
        for mib_file_id, named in named_by.items():
            if mib_file_id in index.root_only:
                continue
            if arc not in index.arcs_by_file.get(mib_file_id, ()):
                continue
            candidates.append(Candidate(
                mib_file_id=mib_file_id, module=index.names.get(mib_file_id, str(mib_file_id)),
                arc=arc, seen=len(oids), named=named, score=named / len(oids)))
    candidates.sort(key=lambda c: (c.score, c.named), reverse=True)
    return candidates


# ---------------------------------------------------------------- deciding

@dataclass
class Decision:
    vendor: str = ""
    source: str = ""
    confidence: str = ""
    vendor_arc: int | None = None
    mib_file_id: int | None = None
    suggest_bundle: str | None = None
    reason: str = ""

    def json(self) -> dict:
        return {"vendor": self.vendor, "source": self.source, "confidence": self.confidence,
                "vendor_arc": self.vendor_arc, "mib_file_id": self.mib_file_id,
                "suggest_bundle": self.suggest_bundle, "reason": self.reason}


def arc_name(arc: int | None) -> str:
    """The vendor key for an enterprise arc: the sysObjectID table first
    (its keys are what every behavioural reader compares against), then
    the enterprise-number list."""
    if arc is None:
        return ""
    key = vendor_for(f"{ENTERPRISES}.{arc}")
    if key:
        return key
    hit = enterprises.lookup(arc)
    return hit[0] if hit else ""


def _arc_confidence(arc: int) -> str:
    """How much to trust a name that came from the arc number alone: high
    when the arc was read out of MIB text (trapoids.WELL_KNOWN or
    enterprises.VERIFIED), medium for a curated-from-memory entry. Checked
    against the tables directly — vendor_for() now falls back to the
    curated list too, so it can no longer tell the two apart."""
    from .trapoids import WELL_KNOWN
    if f"{ENTERPRISES}.{arc}" in WELL_KNOWN or enterprises.is_verified(arc):
        return "high"
    return "medium"


def decide(sys_object_id: str, sys_descr: str, arcs, candidates, *,
           manual: str = "", learned: str = "", catalog_arcs=None) -> Decision:
    """The precedence rule, in one place. See the module docstring.

    `arcs` are the hopped enterprise arcs (may be empty — a sysObjectID-only
    call from the poll path); `candidates` the fingerprint's ranking (may be
    empty — discovery has no walk); `catalog_arcs` maps arc -> bundle key
    for the bundles the catalog could install.
    """
    catalog_arcs = catalog_arcs or {}
    arcs = [int(a) for a in (arcs or [])]
    candidates = list(candidates or [])
    sys_arc = enterprise_arc(sys_object_id)
    real_sys_arc = sys_arc is not None and sys_arc not in GENERIC_ARCS

    decision = Decision()
    if manual:
        decision = Decision(manual, "manual", "high", sys_arc if real_sys_arc else None,
                            reason="set by an operator")
    elif learned:
        decision = Decision(learned, "learned", "high", sys_arc if real_sys_arc else None,
                            reason=f"learned from an operator's override on a device "
                                   f"with the same sysObjectID ({sys_object_id})")
    elif real_sys_arc:
        name = arc_name(sys_arc)
        if name:
            decision = Decision(name, "sysObjectID", _arc_confidence(sys_arc), sys_arc,
                                reason=f"sysObjectID {sys_object_id} is under enterprise "
                                       f"arc {sys_arc} ({name})")
        else:
            descr = vendor_from_descr(sys_descr)
            if descr:
                decision = Decision(descr, "sysDescr", "low", sys_arc,
                                    reason=f"sysObjectID arc {sys_arc} is not a vendor this "
                                           f"build can name; sysDescr mentions {descr}")
            else:
                decision = Decision("", "", "", sys_arc,
                                    reason=f"unknown enterprise arc {sys_arc}")
    else:
        # A generic agent, or a sysObjectID outside enterprises: the walk decides.
        chosen = _walk_choice(arcs, candidates)
        if chosen is not None:
            arc, best = chosen
            name = arc_name(arc)
            confidence = ("high" if best is not None and best.score >= 0.5 and best.named >= 10
                          else "medium")
            why = ("sysObjectID names only the SNMP agent" if sys_arc in GENERIC_ARCS
                   else "sysObjectID is outside the enterprises tree")
            detail = (f"; {best.module} names {best.named} of {best.seen} objects there"
                      if best is not None else "")
            decision = Decision(name, "walk", confidence, arc,
                                reason=f"{why}; the walk found enterprise arc {arc} "
                                       f"({name}){detail}")
        else:
            descr = vendor_from_descr(sys_descr)
            if descr:
                decision = Decision(descr, "sysDescr", "low", None,
                                    reason="sysDescr mentions it; no vendor arc answered")
            elif sys_arc in GENERIC_ARCS:
                name = arc_name(sys_arc)
                decision = Decision(name, "sysObjectID", "low", None,
                                    reason=f"only the SNMP agent's own arc ({sys_arc}) answered")
            else:
                decision = Decision("", "", "", None, reason="nothing identified this device")

    # The MIB to assign and the bundle to suggest follow the vendor arc,
    # whichever rule chose it — never a different arc.
    arc = decision.vendor_arc
    if arc is None and arcs:
        arc = next((a for a in arcs if a not in GENERIC_ARCS), None)
    if arc is not None:
        best = next((c for c in candidates if c.arc == arc and c.named > 0), None)
        if best is not None:
            decision.mib_file_id = best.mib_file_id
        elif arc in catalog_arcs:
            decision.suggest_bundle = catalog_arcs[arc]
    return decision


def _walk_choice(arcs: list[int], candidates: list[Candidate]):
    """(arc, best candidate or None) — the arc the walk votes for.

    Ordered by evidence: an arc an installed MIB names objects under, by
    score; then an arc the enterprise list can name at all. An arc nothing
    can name loses to a sysDescr guess, which is at least a word.
    """
    usable = [a for a in arcs if a not in GENERIC_ARCS]
    if not usable:
        return None
    for cand in candidates:            # already ranked by (score, named)
        if cand.arc in usable and cand.named > 0 and arc_name(cand.arc):
            return cand.arc, cand
    for arc in usable:
        if arc_name(arc):
            return arc, None
    return None


def poll_decision(sys_object_id: str, sys_descr: str, device_row, learned: str = ""):
    """The per-poll, zero-SNMP form: (vendor, source, confidence, vendor_arc).

    Same rule as decide() except that where the walk would be consulted, the
    walk already stored for THIS sysObjectID is reused — so a walk-identified
    device stays stable between identifications, and a manual or learned
    vendor takes effect on the next poll without a walk.
    """
    keys = device_row.keys() if hasattr(device_row, "keys") else ()
    manual = (device_row["vendor_override"] if "vendor_override" in keys else "") or ""
    stored_for = (device_row["identified_sys_object_id"]
                  if "identified_sys_object_id" in keys else None)
    sys_arc = enterprise_arc(sys_object_id)
    real_sys_arc = sys_arc is not None and sys_arc not in GENERIC_ARCS
    if not manual and not learned and not real_sys_arc and stored_for == sys_object_id:
        # The walk's verdict lives in the evidence, not in the row's current
        # vendor_source: that column says what is showing NOW, and while a
        # manual or learned vendor was in force it said so. Reading the
        # evidence is what lets a cleared override fall back to the walk
        # rather than to the agent's own name.
        stored = (_evidence_dict(device_row).get("decision") or {})
        if stored.get("source") == "walk" and stored.get("vendor"):
            return (stored["vendor"], "walk", stored.get("confidence") or "medium",
                    stored.get("vendor_arc"))
    decision = decide(sys_object_id, sys_descr, [], [], manual=manual, learned=learned)
    return decision.vendor, decision.source, decision.confidence, decision.vendor_arc


def _evidence_dict(device_row) -> dict:
    import json
    keys = device_row.keys() if hasattr(device_row, "keys") else ()
    raw = device_row["vendor_evidence"] if "vendor_evidence" in keys else None
    if not raw:
        return {}
    try:
        value = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def evidence(sys_object_id: str, trigger: str, hop: HopResult | None,
             rows_by_arc: dict[int, list[str]] | None, capped: dict[int, bool] | None,
             candidates: list[Candidate], decision: Decision, walk: dict | None,
             catalog_arcs=None, error: str = "", attempts: int = 1) -> dict:
    """The stored explanation: what was asked, what answered, what was
    decided and why. Small on purpose — counts and scores, never values."""
    catalog_arcs = catalog_arcs or {}
    rows_by_arc = rows_by_arc or {}
    capped = capped or {}
    best_by_arc: dict[int, Candidate] = {}
    for cand in candidates:
        best_by_arc.setdefault(cand.arc, cand)
    arcs = []
    for arc in (hop.arcs if hop else []):
        best = best_by_arc.get(arc)
        arcs.append({
            "arc": arc, "name": arc_name(arc),
            "display": (enterprises.lookup(arc) or ("", ""))[1],
            "objects": len(rows_by_arc.get(arc, [])), "capped": bool(capped.get(arc)),
            "generic": arc in GENERIC_ARCS,
            "mib_file_id": best.mib_file_id if best else None,
            "module": best.module if best else "",
            "named": best.named if best else 0,
            "score": round(best.score, 3) if best else 0.0,
            "bundle": catalog_arcs.get(arc),
        })
    return {
        "ts": time.time(), "trigger": trigger, "sys_object_id": sys_object_id or "",
        "hop": {"requests": hop.requests if hop else 0, "stopped": hop.stopped if hop else ""},
        "arcs": arcs,
        "candidates": [c.json() for c in candidates[:20]],
        "chosen_mib_file_id": decision.mib_file_id,
        "suggest_bundle": decision.suggest_bundle,
        "walk": walk or {},
        "decision": decision.json(),
        "error": error or "",
        "attempts": attempts,
    }


__all__ = ["MAX_ARCS", "PER_ARC_OBJECTS", "PER_ARC_BUDGET_S", "GENERIC_ARCS",
           "HopResult", "hop_enterprise_arcs", "MibIndex", "build_mib_index",
           "Candidate", "fingerprint", "Decision", "decide", "poll_decision",
           "evidence", "arc_name"]

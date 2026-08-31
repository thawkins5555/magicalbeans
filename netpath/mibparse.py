"""A stdlib-only, best-effort MIB text parser.

Not a compliant ASN.1/SMI compiler — a real vendor MIB is parsed the way a
person skimming it would: find every `NAME OBJECT-TYPE ... ::= { PARENT
NUMBER }` (or `OBJECT IDENTIFIER`, or `NOTIFICATION-TYPE`) clause with a
regex anchored on the literal `::=` token, and resolve `PARENT` against
whatever OIDs are already known — this file's own siblings resolved so
far, plus everything the app already knows from nodeoids.py/trapoids.py/
previously uploaded MIBs.

Explicit non-goals, matching trapoids.py's own "not a MIB compiler"
framing:
  - IMPORTS is recorded for information (which symbol names which FROM
    module) but never resolved by fetching that module automatically — a
    MIB that imports from a module this app has not also been given stays
    partially unresolved until that module is uploaded too and a
    re-resolve is requested.
  - No macro bodies are actually parsed (SYNTAX, ACCESS, STATUS, INDEX,
    etc.) beyond pulling SYNTAX's textual type name, an INTEGER enum
    table when present, and DESCRIPTION's quoted text — everything else
    in an OBJECT-TYPE clause is ignored.
  - TEXTUAL-CONVENTION clauses are recognized only in that they still
    match the "NAME ... ::= { ... }"-shaped OBJECT-TYPE regex when they
    themselves define an object; a bare `Foo ::= TEXTUAL-CONVENTION ...`
    type alias (no trailing `{ parent number }`) is not modeled at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Seeds IMPORTS resolution — every real-world MIB transitively imports one
# of these, directly or not, so parent lookups bottom out here rather than
# needing SNMPv2-SMI itself to be uploaded.
WELL_KNOWN_ROOTS = {
    "iso": "1", "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1",
    "directory": "1.3.6.1.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
    "experimental": "1.3.6.1.3", "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1", "security": "1.3.6.1.5",
    "snmpV2": "1.3.6.1.6", "snmpModules": "1.3.6.1.6.3",
}


@dataclass
class ParsedObject:
    name: str
    parent: str | None          # symbolic name this OID hangs off; None once oid is set
    last_arc: str | None        # the dotted arc chain under `parent`, e.g. "2" or "2.0"
    oid: str | None = None      # filled in by resolve(), or already known for a literal OID
    description: str = ""
    syntax: str = ""
    enums: dict[int, str] | None = None
    is_notification: bool = False


@dataclass
class ParseResult:
    module: str
    objects: list[ParsedObject]
    imports: dict[str, str] = field(default_factory=dict)   # symbol -> FROM module
    notes: list[str] = field(default_factory=list)


def _strip_comments_and_strings(text: str) -> str:
    """Masks `-- comment` (to the next `--` or end of line, per ASN.1
    comment syntax) and `"quoted strings"` with spaces of the same
    length, preserving every other byte's offset. Never removes bytes —
    only overwrites them — so a later regex match's span still indexes
    correctly into the *original* text when the caller wants the real
    (unmasked) content back, e.g. a DESCRIPTION's actual text.

    This is what lets the structural regexes below treat `--` or `::=`
    appearing inside a comment or a quoted description as inert text
    instead of real syntax."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = text.find('"', i + 1)
            end = (j + 1) if j != -1 else n
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
            continue
        if text[i:i + 2] == "--":
            j = i + 2
            while j < n and text[j] != "\n" and text[j:j + 2] != "--":
                j += 1
            end = (j + 2) if text[j:j + 2] == "--" else j
            for k in range(i, min(end, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = end
            continue
        i += 1
    return "".join(out)


_MODULE_RE = re.compile(r"([A-Za-z][\w-]*)\s+DEFINITIONS\b")
_IMPORTS_BLOCK_RE = re.compile(r"\bIMPORTS\b(.*?);", re.DOTALL)
_IMPORT_GROUP_RE = re.compile(r"([\w,\s-]+?)\s+FROM\s+([A-Za-z][\w-]*)")

_OBJECT_TYPE_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+OBJECT-TYPE\b(.*?)::=\s*\{([^{}]*)\}", re.DOTALL)
_OBJECT_ID_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^{}]*)\}")
_NOTIFICATION_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+NOTIFICATION-TYPE\b(.*?)::=\s*\{([^{}]*)\}", re.DOTALL)

_SYNTAX_RE = re.compile(r"\bSYNTAX\s+([A-Za-z][\w-]*)")
_SYNTAX_ENUM_RE = re.compile(r"\bSYNTAX\s+INTEGER\s*\{([^{}]*)\}")
_ENUM_PAIR_RE = re.compile(r"([A-Za-z][\w-]*)\s*\((-?\d+)\)")
_DESCRIPTION_RE = re.compile(r'\bDESCRIPTION\s+"([^"]*)"', re.DOTALL)


def _parse_oid_tail(braces_text: str):
    """The whole strategy in one function: tokenize whatever is inside a
    `::= { ... }` clause into arc names/numbers, without parsing anything
    about how it got there. Returns (parent_name, last_arc, literal_oid)
    with exactly one of (parent_name and last_arc) or literal_oid set.

    A fully-numeric brace body (`{ 1 3 6 1 4 1 9999 }`) needs no parent
    resolution at all. Otherwise the FIRST token is the symbolic parent —
    not necessarily the second-to-last, because a clause can carry more
    than one trailing arc (`{ ifMIB 2 0 }`, a NOTIFICATION-TYPE's usual
    shape) as well as annotated intermediate arcs written for readability
    (`{ iso org(3) dod(6) 1 }`); every token after the first contributes
    one arc to `last_arc`, joined with '.', so resolve() can append the
    whole chain to the parent's OID in one step."""
    tokens = re.findall(r"[A-Za-z][\w-]*(?:\(-?\d+\))?|-?\d+", braces_text)
    if not tokens:
        return None, None, None
    if all(re.fullmatch(r"-?\d+", t) for t in tokens):
        return None, None, ".".join(tokens)
    if re.fullmatch(r"-?\d+", tokens[0]):
        return None, None, None   # malformed: starts numeric but isn't all-numeric
    parent_name = re.sub(r"\(-?\d+\)$", "", tokens[0])
    arcs = []
    for token in tokens[1:]:
        annotated = re.fullmatch(r"[A-Za-z][\w-]*\((-?\d+)\)", token)
        if annotated:
            arcs.append(annotated.group(1))
        elif re.fullmatch(r"-?\d+", token):
            arcs.append(token)
        else:
            return None, None, None   # an unannotated bare name mid-chain: bail
    if not arcs:
        return None, None, None
    return parent_name, ".".join(arcs), None


def _parse_imports(masked_text: str) -> dict[str, str]:
    imports: dict[str, str] = {}
    block = _IMPORTS_BLOCK_RE.search(masked_text)
    if not block:
        return imports
    for group in _IMPORT_GROUP_RE.finditer(block.group(1)):
        module_name = group.group(2)
        for symbol in group.group(1).split(","):
            symbol = symbol.strip()
            if symbol:
                imports[symbol] = module_name
    return imports


def _extract_enums(body_original: str) -> dict[int, str] | None:
    match = _SYNTAX_ENUM_RE.search(body_original)
    if not match:
        return None
    enums = {int(v): n for n, v in _ENUM_PAIR_RE.findall(match.group(1))}
    return enums or None


def parse(text: str, max_bytes: int = 8 * 1024 * 1024) -> ParseResult:
    """Best-effort. Never raises for malformed input — a file with zero
    recognizable definitions comes back as a ParseResult with an empty
    object list and a note explaining why, not an exception; the only
    exception this raises is the size guard, checked before any regex
    work so a pasted multi-megabyte file is refused cheaply."""
    if len(text.encode("utf-8", "replace")) > max_bytes:
        raise ValueError(f"File exceeds the {max_bytes:,} byte limit")

    notes: list[str] = []
    masked = _strip_comments_and_strings(text)

    module_match = _MODULE_RE.search(masked)
    module = module_match.group(1) if module_match else ""
    if not module:
        notes.append("No 'NAME DEFINITIONS ::= BEGIN' header was found; "
                     "the module name is left blank.")

    imports = _parse_imports(masked)

    objects: dict[str, ParsedObject] = {}

    for match in _OBJECT_ID_RE.finditer(masked):
        name, braces = match.group(1), match.group(2)
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        objects[name] = ParsedObject(name=name, parent=parent, last_arc=last_arc,
                                     oid=literal)

    for match in _OBJECT_TYPE_RE.finditer(masked):
        name, braces = match.group(1), match.group(3)
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        body_original = text[match.start(2):match.end(2)]
        syntax_match = _SYNTAX_RE.search(body_original)
        desc_match = _DESCRIPTION_RE.search(body_original)
        objects[name] = ParsedObject(
            name=name, parent=parent, last_arc=last_arc, oid=literal,
            description=(desc_match.group(1).strip() if desc_match else ""),
            syntax=(syntax_match.group(1) if syntax_match else ""),
            enums=_extract_enums(body_original))

    for match in _NOTIFICATION_RE.finditer(masked):
        name, braces = match.group(1), match.group(3)
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        body_original = text[match.start(2):match.end(2)]
        desc_match = _DESCRIPTION_RE.search(body_original)
        objects[name] = ParsedObject(
            name=name, parent=parent, last_arc=last_arc, oid=literal,
            description=(desc_match.group(1).strip() if desc_match else ""),
            is_notification=True)

    if not objects:
        notes.append("No OBJECT-TYPE, OBJECT IDENTIFIER, or "
                     "NOTIFICATION-TYPE definitions were recognized in "
                     "this file.")

    return ParseResult(module=module, objects=list(objects.values()),
                       imports=imports, notes=notes)


def resolve(objects: list[ParsedObject], known: dict[str, str]) -> tuple[int, list[str]]:
    """Repeatedly resolves any object whose parent is now known — either
    already in `known` (pre-seeded by the caller with WELL_KNOWN_ROOTS
    plus every OID this app already has a name for) or itself just
    resolved this pass — until a fixed point. Mutates each ParsedObject's
    `.oid` in place. Returns (resolved_count, sorted unresolved parent
    names) — the latter is exactly the diagnostic that makes upload order
    visible: uploading a dependent MIB before the one that defines its
    parent branch leaves it with unresolved=["thatParentName"], and
    calling resolve() again after the dependency is uploaded (or after
    the caller adds its objects into `known` via all_known_oids())
    finishes the job without re-parsing anything."""
    known = dict(known)
    resolved = 0
    changed = True
    while changed:
        changed = False
        for obj in objects:
            if obj.oid is not None or obj.parent is None:
                continue
            parent_oid = known.get(obj.parent)
            if parent_oid is None:
                continue
            obj.oid = f"{parent_oid}.{obj.last_arc}"
            known[obj.name] = obj.oid
            resolved += 1
            changed = True
    unresolved = sorted({obj.parent for obj in objects
                        if obj.oid is None and obj.parent})
    return resolved, unresolved


def known_oids_for(nodes_db) -> dict[str, str]:
    """WELL_KNOWN_ROOTS plus every OID `nodes_db` has already resolved
    from a previously stored MIB — the only "IMPORTS resolution" this
    parser ever does, never by fetching the imported module itself, only
    against what's already known (see this module's own non-goals
    above). Shared by both the upload endpoint and the default-MIB
    seeding step in service.py, so the two can never define this
    differently."""
    known = dict(WELL_KNOWN_ROOTS)
    known.update(nodes_db.all_known_oids())
    return known


def load_into(nodes_db, filename: str, text: str, known_oids: dict[str, str],
              max_bytes: int) -> dict:
    """Parses, resolves against `known_oids`, and stores into `nodes_db`
    — the exact three-step sequence a real upload runs, so a bundled
    default MIB and an admin's own upload are provably the same code
    path and indistinguishable afterward (same review UI, same
    re-resolve button, same edit-survives-reresolve behavior). Returns
    the same summary shape the upload endpoint returns to the browser."""
    result = parse(text, max_bytes=max_bytes)
    resolved_count, unresolved = resolve(result.objects, known_oids)
    mib_file_id = nodes_db.add_mib_file(
        filename, result.module, len(result.objects), unresolved,
        "; ".join(result.notes), content=text)
    nodes_db.replace_mib_objects(mib_file_id, [
        {"name": obj.name, "oid": obj.oid, "description": obj.description,
         "syntax": obj.syntax, "enums": obj.enums,
         "is_notification": obj.is_notification}
        for obj in result.objects])
    return {"id": mib_file_id, "module": result.module,
            "object_count": len(result.objects), "resolved_count": resolved_count,
            "unresolved": unresolved, "notes": result.notes}


if __name__ == "__main__":
    sample_if_mib = """
    IF-MIB DEFINITIONS ::= BEGIN
    IMPORTS
        MODULE-IDENTITY, OBJECT-TYPE, Counter32
            FROM SNMPv2-SMI
        mib-2
            FROM RFC1213-MIB;

    -- this comment has a fake ::= { in it, must not confuse the parser
    ifMIB OBJECT IDENTIFIER ::= { mib-2 31 }
    ifMIBObjects OBJECT IDENTIFIER ::= { ifMIB 1 }
    interfaces OBJECT IDENTIFIER ::= { mib-2 2 }
    ifTable OBJECT IDENTIFIER ::= { interfaces 2 }
    ifEntry OBJECT IDENTIFIER ::= { ifTable 1 }

    ifDescr OBJECT-TYPE
        SYNTAX      DisplayString
        MAX-ACCESS  read-only
        STATUS      current
        DESCRIPTION
            "A textual string containing information about the
            interface, including a string with -- two dashes and a
            literal ::= sequence, neither of which is real syntax here."
        ::= { ifEntry 2 }

    ifOperStatus OBJECT-TYPE
        SYNTAX      INTEGER { up(1), down(2), testing(3) }
        MAX-ACCESS  read-only
        STATUS      current
        DESCRIPTION "The current operational state."
        ::= { ifEntry 8 }

    linkDown NOTIFICATION-TYPE
        STATUS      current
        DESCRIPTION "A linkDown trap."
        ::= { ifMIB 2 0 }
    END
    """

    result = parse(sample_if_mib, max_bytes=1_000_000)
    assert result.module == "IF-MIB", result.module
    names = {obj.name for obj in result.objects}
    assert names == {"ifMIB", "ifMIBObjects", "interfaces", "ifTable", "ifEntry",
                     "ifDescr", "ifOperStatus", "linkDown"}, names
    assert result.imports.get("mib-2") == "RFC1213-MIB", result.imports
    assert result.imports.get("OBJECT-TYPE") == "SNMPv2-SMI", result.imports
    print("parse() found every definition and the IMPORTS map OK")

    by_name = {obj.name: obj for obj in result.objects}
    descr = by_name["ifDescr"]
    assert "-- two dashes" in descr.description, descr.description
    assert "::= sequence" in descr.description, descr.description
    print("DESCRIPTION text survives comment/string masking intact OK")

    oper = by_name["ifOperStatus"]
    assert oper.enums == {1: "up", 2: "down", 3: "testing"}, oper.enums
    print("INTEGER enum table extracted OK")

    known = dict(WELL_KNOWN_ROOTS)
    resolved_count, unresolved = resolve(result.objects, known)
    assert not unresolved, unresolved
    assert resolved_count == len(result.objects), (resolved_count, len(result.objects))
    assert by_name["ifMIB"].oid == "1.3.6.1.2.1.31"
    assert by_name["ifEntry"].oid == "1.3.6.1.2.1.2.2.1"
    assert by_name["ifDescr"].oid == "1.3.6.1.2.1.2.2.1.2"
    assert by_name["linkDown"].oid == "1.3.6.1.2.1.31.2.0"
    print("resolve() walked the whole chain to real OIDs OK")

    # --- the upload-order story: a dependent MIB uploaded before its
    # parent module leaves objects unresolved; uploading the parent and
    # re-resolving against the combined object set finishes the job.
    cisco_smi = """
    CISCO-SMI DEFINITIONS ::= BEGIN
    ciscoMgmt OBJECT IDENTIFIER ::= { enterprises 9 9 }
    END
    """
    cisco_process = """
    CISCO-PROCESS-MIB DEFINITIONS ::= BEGIN
    ciscoProcessMIB OBJECT IDENTIFIER ::= { ciscoMgmt 109 }
    cpmCPUTotalTable OBJECT IDENTIFIER ::= { ciscoProcessMIB 1 }
    END
    """
    process_result = parse(cisco_process, max_bytes=1_000_000)
    known2 = dict(WELL_KNOWN_ROOTS)
    _, unresolved2 = resolve(process_result.objects, known2)
    # ciscoMgmt is the actual missing root; ciscoProcessMIB is reported
    # too since it is itself blocked on ciscoMgmt, which correctly makes
    # its own dependent (cpmCPUTotalTable) unresolvable in the same pass —
    # the diagnostic surfaces the whole broken chain, not just its root.
    assert unresolved2 == ["ciscoMgmt", "ciscoProcessMIB"], unresolved2
    print("dependent MIB uploaded first correctly reports the broken chain OK")

    smi_result = parse(cisco_smi, max_bytes=1_000_000)
    known3 = dict(WELL_KNOWN_ROOTS)
    resolve(smi_result.objects, known3)
    for obj in smi_result.objects:
        if obj.oid:
            known3[obj.name] = obj.oid
    _, unresolved3 = resolve(process_result.objects, known3)
    assert not unresolved3, unresolved3
    by_name2 = {obj.name: obj for obj in process_result.objects}
    assert by_name2["cpmCPUTotalTable"].oid == "1.3.6.1.4.1.9.9.109.1", \
        by_name2["cpmCPUTotalTable"].oid
    print("re-resolving after the parent MIB is uploaded finishes the chain OK")

    # --- negative cases
    empty = parse("just some prose, no MIB syntax at all", max_bytes=1_000_000)
    assert empty.module == "" and empty.objects == [] and empty.notes
    print("non-MIB text yields an empty result with a note, not an exception OK")

    try:
        parse("x" * 100, max_bytes=10)
        raise AssertionError("oversized input must be refused")
    except ValueError:
        print("oversized input refused OK")

    print("all self-tests passed")

"""A stdlib-only, best-effort MIB text parser.

Not a compliant ASN.1/SMI compiler — a real vendor MIB is parsed the way a
person skimming it would: find every `NAME OBJECT-TYPE ... ::= { PARENT
NUMBER }` (or `OBJECT IDENTIFIER`, `MODULE-IDENTITY`, `OBJECT-IDENTITY`,
or `NOTIFICATION-TYPE`) clause with a regex anchored on the literal
`::=` token, and resolve `PARENT` against
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
  - A bare `Foo ::= TEXTUAL-CONVENTION ...` type alias is counted
    (ParseResult.textual_conventions) but not modeled: it names a type,
    not an OID, so there is nothing in it to resolve or poll. The count
    is there so a module that is nothing else — SNMPv2-TC is exactly
    that, 16 conventions and no objects — reports what it is rather than
    "nothing was recognized in this file", which reads as a failed
    import. TEXTUAL-CONVENTION clauses that do define an object still
    match the "NAME ... ::= { ... }"-shaped OBJECT-TYPE scan as before.

Why every scan below is written as "find the next landmark, then look
forward a bounded distance" rather than as one regex per clause: a lazy
`(.*?)` between a macro keyword and its `::=` re-reads the rest of the
file from every candidate start, so a truncated MIB — all the headers,
none of the closing clauses, which is exactly how a half-downloaded file
looks — costs O(n^2). CPython's `re` does not release the GIL while it
matches, so that is not a slow request but a frozen appliance: no web UI,
no poller timers, no trap or syslog drain, for as long as it runs. Every
pass here is linear in the file, and `parse()` carries a wall-clock
budget on top so no single upload can hold the interpreter for long even
if some input shape defeats the analysis.
"""

from __future__ import annotations

import re
import time
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

# How long one file may spend inside parse(). Every shipped MIB parses in
# under 0.05 s and the largest module anyone has ever published is a few
# hundred KB, so this is three orders of magnitude of headroom for real
# input and still a hard ceiling on how long a hostile upload can hold the
# GIL. Checked between phases and every few hundred clauses within one.
PARSE_BUDGET_S = 5.0

# A macro clause ("NAME OBJECT-TYPE ... ::= { parent 3 }") is a few hundred
# bytes in every real MIB; the largest in the shipped bundle is under 2 KB.
# Bounding how far past a macro keyword the `::=` may sit is what stops a
# file of bare headers from making each failed clause cost the whole file.
MACRO_CLAUSE_LIMIT = 20_000


class MibTooLarge(ValueError):
    """The input is larger than the caller's byte cap.

    A distinct type so `resolve_all()` can tell "this file is bigger than
    the cap that is in force today" — which is a stored file to leave
    exactly as it is — from "this file could not be parsed", which is
    something the operator has to be told about.
    """


class MibParseTimeout(ValueError):
    """Parsing spent longer than `budget_s` and was abandoned."""


def _check_deadline(deadline: float | None, budget_s: float) -> None:
    """Raises MibParseTimeout once `deadline` (an absolute time.monotonic()
    value) has passed; `deadline is None` means no budget is in force.
    Shared by parse()'s own per-phase checks and by any phase — currently
    just the comment/string masking pass — that checks its own progress from
    inside a loop, so both report the same message regardless of which one
    caught it."""
    if deadline is not None and time.monotonic() > deadline:
        raise MibParseTimeout(
            f"This file took longer than {budget_s:g}s to parse and was "
            "abandoned; it is far larger or far more unusual than any "
            "real MIB module.")


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
    # `Foo ::= TEXTUAL-CONVENTION ...` type aliases. Counted, never turned
    # into objects: a textual convention names a *type*, not an OID, so there
    # is nothing here to resolve or poll. The count exists so a module that is
    # nothing but textual conventions — SNMPv2-TC is exactly that — can say so
    # instead of reporting that nothing was recognized in it.
    textual_conventions: int = 0


# The only two spans that get blanked: a quoted string and an ASN.1 comment.
_MASK_OPEN_RE = re.compile(r'"|--')


def _strip_comments_and_strings(text: str, deadline: float | None = None,
                                budget_s: float = 0.0) -> str:
    """Masks `-- comment` (to the next `--` or end of line, per ASN.1
    comment syntax) and `"quoted strings"` with spaces of the same
    length, preserving every other byte's offset. Never removes bytes —
    only overwrites them — so a later regex match's span still indexes
    correctly into the *original* text when the caller wants the real
    (unmasked) content back, e.g. a DESCRIPTION's actual text.

    This is what lets the structural regexes below treat `--` or `::=`
    appearing inside a comment or a quoted description as inert text
    instead of real syntax.

    Written as "copy the span up to the next `"` or `--`, then blank that
    one span" rather than as a per-character walk: `list(text)` cost nine
    bytes of memory per input byte and 3.6 s on an 8 MB file before any
    regex had run, for a pass that only ever blanks two kinds of span.

    `no_newline_from` caches the result of the "where does this comment end"
    search below: once a search for the next `\\n` comes up empty, no later
    search — starting further along the same string — can find one either,
    so it is never searched for again. Without this, a file whose ASN.1 `--`
    comments run to end-of-file with nothing to close them and no newline
    anywhere in between (one long logical line, which is exactly how a
    minified or half-downloaded MIB looks) paid one full end-of-file scan
    *per comment marker* — O(markers x length) — the same bug class this
    function's own docstring already names two instances of, a third one,
    found by fuzzing rather than by review. The equivalent search for the
    next `--` (a comment's other possible closer) does not need the same
    cache: each one only ever looks for a `--` that a *later* iteration of
    this same loop would otherwise have opened a new comment on, so at most
    one such search per call can come up empty, however large the file is.

    `deadline`/`budget_s` let a caller with its own wall-clock budget (see
    parse()) be checked from inside this loop rather than only after it
    returns — a budget checked solely between phases cannot bound the phase
    it is checked after, which is exactly how the bug above outlasted it."""
    parts: list[str] = []
    i, n = 0, len(text)
    no_newline_from: int | None = None
    iterations = 0
    while i < n:
        iterations += 1
        if deadline is not None and not iterations % 4096:
            _check_deadline(deadline, budget_s)
        opener = _MASK_OPEN_RE.search(text, i)
        if opener is None:
            parts.append(text[i:])
            break
        start = opener.start()
        if start > i:
            parts.append(text[i:start])
        if opener.group(0) == '"':
            closer = text.find('"', start + 1)
            end = (closer + 1) if closer != -1 else n
        else:
            # ASN.1: a comment runs to the next `--` or to end of line,
            # whichever comes first. The newline itself is not part of it.
            search_from = start + 2
            if no_newline_from is not None and search_from >= no_newline_from:
                newline = -1
            else:
                newline = text.find("\n", search_from)
                if newline == -1:
                    no_newline_from = search_from
            dashes = text.find("--", search_from)
            if dashes != -1 and (newline == -1 or dashes < newline):
                end = dashes + 2
            else:
                end = newline if newline != -1 else n
        span = text[start:end]
        parts.append(" " * len(span) if "\n" not in span
                     else "".join("\n" if ch == "\n" else " " for ch in span))
        i = end
    return "".join(parts)


_MODULE_RE = re.compile(r"([A-Za-z][\w-]*)\s+DEFINITIONS\b")
_IMPORTS_KW_RE = re.compile(r"\bIMPORTS\b")
# The symbol list of one IMPORTS group is everything between the previous
# `FROM <module>` and the next `FROM`; the lookbehind keeps `FROM` a word of
# its own rather than the tail of a symbol name.
_IMPORT_FROM_RE = re.compile(r"(?<=\s)FROM\s+([A-Za-z][\w-]*)")
_IMPORT_SYMBOL_RE = re.compile(r"[\w-]+")

# Each macro is found by its header alone; the `::= { ... }` that closes the
# clause is then looked for in a bounded window that stops at the next
# header of the same macro (see _iter_macro_clauses).
# `(?!\s+MACRO\b)` skips the ASN.1 macro *definitions* themselves, which
# SNMPv2-SMI carries in full ("NOTIFICATION-TYPE MACRO ::= BEGIN ... END").
# Without it the word before the macro keyword — `END`, from the previous
# macro definition — was read as an object name and given the OID of the
# next real clause in the file.
_MACRO_DEFN_TAIL = r"(?!\s+MACRO\b)"
_OBJECT_TYPE_HEAD_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+OBJECT-TYPE\b" + _MACRO_DEFN_TAIL)
_OBJECT_ID_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^{}]*)\}")
_NOTIFICATION_HEAD_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+NOTIFICATION-TYPE\b" + _MACRO_DEFN_TAIL)
# The two other macros that define a real branch node rather than describing
# one. Nearly every RFC MIB names its own root with MODULE-IDENTITY
# (`dot1dBridge MODULE-IDENTITY ... ::= { mib-2 17 }`) and hangs the whole
# module beneath it, so without these two a file like BRIDGE-MIB or LLDP-MIB
# parsed to a list of objects none of which could resolve. The conformance
# macros (OBJECT-GROUP, NOTIFICATION-GROUP, MODULE-COMPLIANCE) are
# deliberately still ignored: they are agent-capability paperwork, never
# polled, and nothing hangs off them.
_MODULE_IDENTITY_HEAD_RE = re.compile(
    r"\b([a-zA-Z][\w-]*)\s+(?:MODULE-IDENTITY|OBJECT-IDENTITY)\b"
    + _MACRO_DEFN_TAIL)
_OID_ASSIGN_RE = re.compile(r"::=\s*\{([^{}]*)\}")
# `DisplayString ::= TEXTUAL-CONVENTION`. The MACRO definition SNMPv2-TC
# opens with reads the other way round ("TEXTUAL-CONVENTION MACRO ::=") and
# is correctly not counted.
_TEXTUAL_CONVENTION_RE = re.compile(r"\b[A-Za-z][\w-]*\s*::=\s*TEXTUAL-CONVENTION\b")

_SYNTAX_RE = re.compile(r"\bSYNTAX\s+([A-Za-z][\w-]*)")
_SYNTAX_ENUM_RE = re.compile(r"\bSYNTAX\s+INTEGER\s*\{([^{}]*)\}")
# `\d{1,100}` rather than `\d+`: since 3.11 `int()` refuses a decimal string
# longer than sys.get_int_max_str_digits() (4,300 by default, and settable as
# low as 640), and an unbounded capture made that ValueError escape parse() —
# so an operator uploading a MIB with a silly enum value got a message about
# Python's integer limits, and resolve_all() then skipped the file silently
# on every later re-resolve. No SMI enum is anywhere near 100 digits; one that
# is simply is not recorded.
_ENUM_PAIR_RE = re.compile(r"([A-Za-z][\w-]*)\s*\((-?\d{1,100})\)")
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


def _imports_span(masked_text: str) -> tuple[int, int, int] | None:
    """(block_start, body_start, block_end) of the `IMPORTS ... ;` block,
    or None. Two `str` searches rather than `\\bIMPORTS\\b(.*?);`, which
    re-reads the file once per `IMPORTS` keyword when the `;` is missing."""
    keyword = _IMPORTS_KW_RE.search(masked_text)
    if keyword is None:
        return None
    semicolon = masked_text.find(";", keyword.end())
    if semicolon == -1:
        return None
    return keyword.start(), keyword.end(), semicolon + 1


def _parse_imports(masked_text: str, body_start: int, body_end: int) -> dict[str, str]:
    """symbol -> module, read by walking the block once.

    The block reads `sym, sym, sym FROM Module sym FROM Module ...`, so
    every `FROM` closes the run of symbols since the previous one. Written
    as a scan because the regex this replaces (`([\\w,\\s-]+?)\\s+FROM\\s+...`)
    re-expanded its lazy symbol run from every start position whenever a
    stretch of the block held no `FROM` at all — a truncated import list
    cost 66 s at 64 KB.
    """
    imports: dict[str, str] = {}
    position = body_start
    for group in _IMPORT_FROM_RE.finditer(masked_text, body_start, body_end):
        module_name = group.group(1)
        for symbol in masked_text[position:group.start()].split(","):
            symbol = symbol.strip()
            if symbol and _IMPORT_SYMBOL_RE.fullmatch(symbol):
                imports[symbol] = module_name
        position = group.end()
    return imports


def _blank_span(text: str, start: int, end: int) -> str:
    """`text` with [start:end) replaced by spaces, newlines kept, so every
    later match's offset still indexes into the original text."""
    span = text[start:end]
    blanked = "".join("\n" if ch == "\n" else " " for ch in span)
    return text[:start] + blanked + text[end:]


def _iter_macro_clauses(masked_text: str, head_re: re.Pattern,
                        limit: int = MACRO_CLAUSE_LIMIT):
    """Yield (name, body_start, body_end, brace_text) for every
    `NAME <macro> ...body... ::= { ... }` clause, in one left-to-right pass.

    The window in which the closing `::= { ... }` is looked for stops at
    whichever comes first: `limit` bytes, or the next header of the same
    macro. Both bounds matter. The second is what makes the pass linear —
    the sum of all windows is at most the length of the file — and it is
    also the more faithful reading: one macro's clause has never legally
    contained another's header, so a header with no clause of its own
    should be skipped rather than allowed to swallow the definition that
    follows it.
    """
    text_len = len(masked_text)
    heads = head_re.finditer(masked_text)
    head = next(heads, None)
    while head is not None:
        following = next(heads, None)
        body_start = head.end()
        stop = min(text_len, body_start + limit)
        if following is not None:
            stop = min(stop, following.start())
        assignment = _OID_ASSIGN_RE.search(masked_text, body_start, stop)
        if assignment is not None:
            yield (head.group(1), body_start, assignment.start(),
                   assignment.group(1))
        head = following


def _extract_enums(body_original: str) -> dict[int, str] | None:
    match = _SYNTAX_ENUM_RE.search(body_original)
    if not match:
        return None
    enums: dict[int, str] = {}
    for name, value in _ENUM_PAIR_RE.findall(match.group(1)):
        try:
            enums[int(value)] = name
        except ValueError:      # belt and braces behind the digit bound
            continue
    return enums or None


def parse(text: str, max_bytes: int = 8 * 1024 * 1024,
          budget_s: float | None = None) -> ParseResult:
    """Best-effort. Never raises for malformed input — a file with zero
    recognizable definitions comes back as a ParseResult with an empty
    object list and a note explaining why, not an exception.

    Two guards do raise, both subclasses of ValueError so the upload
    endpoint keeps turning them into a 400 with their own message:
    `MibTooLarge` for the byte cap, checked before any scanning so a
    pasted multi-megabyte file is refused cheaply, and `MibParseTimeout`
    for the wall-clock budget, checked between every phase and, within the
    ones that scan the file more than once per pass — the comment/string
    masking, and the object-scanning loops below it — periodically inside
    them too, so no single phase can itself outlast the budget uncaught.
    Nothing else escapes: an enum value too long for `int()`, a truncated
    clause, an unterminated string are all just definitions that do not
    get recorded."""
    if len(text.encode("utf-8", "replace")) > max_bytes:
        raise MibTooLarge(f"File exceeds the {max_bytes:,} byte limit")

    # Read from the module constant, not from a default argument bound at
    # import time, so an operator's build or a test can change the ceiling.
    if budget_s is None:
        budget_s = PARSE_BUDGET_S
    deadline = (time.monotonic() + budget_s) if budget_s and budget_s > 0 else None

    def check_budget() -> None:
        _check_deadline(deadline, budget_s)

    notes: list[str] = []
    # The masking pass gets the deadline directly, and checks it from inside
    # its own loop, rather than only being checked here once it returns: a
    # budget applied solely between phases cannot bound the phase it is
    # applied after.
    masked = _strip_comments_and_strings(text, deadline, budget_s)
    check_budget()

    module_match = _MODULE_RE.search(masked)
    module = module_match.group(1) if module_match else ""
    if not module:
        notes.append("No 'NAME DEFINITIONS ::= BEGIN' header was found; "
                     "the module name is left blank.")

    # An IMPORTS list names macros as bare symbols ("IMPORTS MODULE-IDENTITY,
    # OBJECT-TYPE ... FROM SNMPv2-SMI"), which reads to a regex exactly like a
    # definition whose name is IMPORTS. Blank the block out — keeping its
    # length and newlines so offsets into the original text still line up —
    # once its symbols have been recorded.
    span = _imports_span(masked)
    if span is None:
        imports: dict[str, str] = {}
    else:
        block_start, body_start, block_end = span
        imports = _parse_imports(masked, body_start, block_end - 1)
        masked = _blank_span(masked, block_start, block_end)
    check_budget()

    objects: dict[str, ParsedObject] = {}

    for index, match in enumerate(_OBJECT_ID_RE.finditer(masked)):
        if not index % 256:
            check_budget()
        name, braces = match.group(1), match.group(2)
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        objects[name] = ParsedObject(name=name, parent=parent, last_arc=last_arc,
                                     oid=literal)

    clauses = _iter_macro_clauses(masked, _OBJECT_TYPE_HEAD_RE)
    for index, (name, body_start, body_end, braces) in enumerate(clauses):
        if not index % 256:
            check_budget()
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        body_original = text[body_start:body_end]
        syntax_match = _SYNTAX_RE.search(body_original)
        desc_match = _DESCRIPTION_RE.search(body_original)
        objects[name] = ParsedObject(
            name=name, parent=parent, last_arc=last_arc, oid=literal,
            description=(desc_match.group(1).strip() if desc_match else ""),
            syntax=(syntax_match.group(1) if syntax_match else ""),
            enums=_extract_enums(body_original))

    clauses = _iter_macro_clauses(masked, _MODULE_IDENTITY_HEAD_RE)
    for index, (name, body_start, body_end, braces) in enumerate(clauses):
        if not index % 256:
            check_budget()
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        body_original = text[body_start:body_end]
        desc_match = _DESCRIPTION_RE.search(body_original)
        objects[name] = ParsedObject(
            name=name, parent=parent, last_arc=last_arc, oid=literal,
            description=(desc_match.group(1).strip() if desc_match else ""))

    clauses = _iter_macro_clauses(masked, _NOTIFICATION_HEAD_RE)
    for index, (name, body_start, body_end, braces) in enumerate(clauses):
        if not index % 256:
            check_budget()
        if name in objects:
            continue
        parent, last_arc, literal = _parse_oid_tail(braces)
        body_original = text[body_start:body_end]
        desc_match = _DESCRIPTION_RE.search(body_original)
        objects[name] = ParsedObject(
            name=name, parent=parent, last_arc=last_arc, oid=literal,
            description=(desc_match.group(1).strip() if desc_match else ""),
            is_notification=True)

    textual_conventions = len(_TEXTUAL_CONVENTION_RE.findall(masked))
    if not objects:
        if textual_conventions:
            # SNMPv2-TC and its vendor equivalents are nothing but type
            # definitions. Saying "nothing was recognized" about a file that
            # imported perfectly reads as a failed import, and the obvious
            # response is to delete it and try again.
            notes.append(f"{textual_conventions} textual convention(s) and no "
                         "objects, which is what this module is: it defines "
                         "SNMP types, not OIDs, so there is nothing here to "
                         "resolve or poll. The import succeeded.")
        else:
            notes.append("No OBJECT-TYPE, OBJECT IDENTIFIER, MODULE-IDENTITY, "
                         "or NOTIFICATION-TYPE definitions were recognized in "
                         "this file.")

    return ParseResult(module=module, objects=list(objects.values()),
                       imports=imports, notes=notes,
                       textual_conventions=textual_conventions)


def resolve(objects: list[ParsedObject], known: dict[str, str]) -> tuple[int, list[str]]:
    """Resolves every object whose parent is known — either already in
    `known` (pre-seeded by the caller with WELL_KNOWN_ROOTS plus every OID
    this app already has a name for) or itself resolvable from one of
    those. Mutates each ParsedObject's `.oid` in place. Returns
    (resolved_count, sorted unresolved parent names) — the latter is
    exactly the diagnostic that makes upload order visible: uploading a
    dependent MIB before the one that defines its parent branch leaves it
    with unresolved=["thatParentName"], and calling resolve() again after
    the dependency is uploaded (or after the caller adds its objects into
    `known` via all_known_oids()) finishes the job without re-parsing
    anything.

    Resolution follows the dependency chain instead of repeating passes
    over the whole list. A MIB is free to list an object before the parent
    it hangs off — legal, and usual in generated MIBs — and the old
    "keep sweeping until a sweep gains nothing" loop then needed one sweep
    per link, i.e. O(n^2): a 20,000-object file took 26 s. Here each
    object is walked up to the first ancestor with a known OID and the
    chain is filled in from the top down, so every object is visited once
    whether it resolves or not; the same 20,000-object file takes under
    0.1 s. `visiting` guards the walk against a MIB whose parents form a
    cycle, and `dead` remembers a chain that ended nowhere so a second
    object hanging off it does not walk it again."""
    known = dict(known)
    # Only unresolved objects are worth indexing: an object that already
    # carries a literal numeric OID has never been fed back into `known` by
    # this function (resolve_all does that between files), so a walk must
    # stop at it rather than continue through it.
    by_name: dict[str, ParsedObject] = {}
    for obj in objects:
        if obj.oid is None and obj.parent is not None:
            by_name.setdefault(obj.name, obj)

    resolved = 0
    dead: set[str] = set()
    for start in objects:
        if start.oid is not None or start.parent is None:
            continue
        chain: list[ParsedObject] = []
        visiting: set[str] = set()
        obj = start
        while True:
            if obj.name in dead or obj.name in visiting:
                dead.update(visiting)
                dead.add(obj.name)
                chain = []
                break
            visiting.add(obj.name)
            chain.append(obj)
            if obj.parent in known:
                break
            parent = by_name.get(obj.parent)
            if parent is None:
                dead.update(visiting)
                chain = []
                break
            obj = parent
        for node in reversed(chain):
            node.oid = f"{known[node.parent]}.{node.last_arc}"
            known[node.name] = node.oid
            resolved += 1

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


def resolve_all(nodes_db, max_bytes: int, max_passes: int = 8) -> dict:
    """Re-resolve every stored MIB against every other, to a fixpoint.

    `resolve()` already follows a chain within one file; what it cannot do
    on its own is see a parent that lives in a *different* file. That is
    the whole reason MIB upload order used to matter: CISCO-PROCESS-MIB
    uploaded before CISCO-SMI resolved nothing, and only a manual Resolve
    on each file afterwards finished the chain. Every file's objects are
    therefore resolved as one list, so a chain that crosses files is
    followed exactly like one that does not, in a single walk — where the
    previous code re-swept all files up to `max_passes` (8) times, one
    sweep per link of cross-file depth, at up to 400 files per bundle.
    `max_passes` is accepted and ignored, so an existing caller keeps
    working.

    Only files whose object set actually changed are written back, so calling
    this when everything is already resolved is a read-only no-op rather than
    a rewrite of every row.
    """
    rows = [row for row in nodes_db.mib_files() if row["content"]]
    parsed: dict[int, ParseResult] = {}
    failed = 0
    for row in rows:
        try:
            parsed[row["id"]] = parse(row["content"], max_bytes=max_bytes)
        except MibTooLarge:
            continue          # oversized now that the cap is lower: leave as-is
        except ValueError as exc:
            # Anything else — the parse budget, or a guard added later — is a
            # file that will be skipped on every re-resolve from here on. Say
            # so on the file itself: silently skipping it forever is how a MIB
            # ends up shown as "0 objects" with nothing to explain it.
            failed += 1
            nodes_db.update_mib_file(row["id"],
                                     parse_notes=f"Could not be parsed: {exc}")

    known = dict(WELL_KNOWN_ROOTS)
    known.update(nodes_db.all_known_oids())
    every_object: list[ParsedObject] = []
    for result in parsed.values():
        every_object.extend(result.objects)
    # A literal numeric OID (`::= { 1 3 6 1 4 1 9999 }`) is a name other
    # files hang off, so it has to be visible before the walk starts.
    for obj in every_object:
        if obj.oid:
            known.setdefault(obj.name, obj.oid)
    resolve(every_object, known)
    passes = 1

    changed = 0
    resolved_total = 0
    object_total = 0
    for row in rows:
        result = parsed.get(row["id"])
        if result is None:
            continue
        object_total += len(result.objects)
        resolved_total += sum(1 for obj in result.objects if obj.oid)
        before = {r["name"]: r["oid"] for r in nodes_db.mib_objects(row["id"])}
        after = {obj.name: obj.oid for obj in result.objects}
        if before == after:
            continue
        unresolved = sorted({obj.parent for obj in result.objects
                             if obj.oid is None and obj.parent})
        nodes_db.update_mib_file(
            row["id"], module=result.module, object_count=len(result.objects),
            unresolved=unresolved, parse_notes="; ".join(result.notes))
        nodes_db.replace_mib_objects(row["id"], [
            {"name": obj.name, "oid": obj.oid, "description": obj.description,
             "syntax": obj.syntax, "enums": obj.enums,
             "is_notification": obj.is_notification}
            for obj in result.objects])
        changed += 1
    return {"files": len(parsed), "files_changed": changed, "passes": passes,
            "files_failed": failed,
            "object_count": object_total, "resolved_count": resolved_total}


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

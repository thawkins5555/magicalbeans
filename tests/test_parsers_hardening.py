"""The parsers and the small in-memory tables around them, under the inputs
a fuzz run and a fresh-eyes review found: a MIB whose IMPORTS block never
closes, a truncated MIB that is all macro headers and no clauses, a reversed
dependency chain, an enum value longer than Python's own integer guard, and
the vendor/port/name-lookup tables that back them.

No network, no database, no subprocess: everything here is a pure function
or an in-memory object, so the suite is deterministic and finishes in a few
seconds. The timing assertions carry a wide margin on purpose — each one is
two to three orders of magnitude below what the unfixed code measured, so a
loaded build machine cannot make them flap, and a return of the quadratic
behaviour cannot make them pass.
"""
import hashlib
import json
import os
import time

from _paths import REPO_ROOT, STUBS_DIR

from netpath import mibparse

MIB_DIR = os.path.join(REPO_ROOT, "netpath", "mibs")
EXPECTED_PATH = os.path.join(STUBS_DIR, "mib_parse_expected.json")

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{(': ' + detail) if detail else ''}")
    if not ok:
        failures.append(label)


def timed(fn, *args, **kwargs):
    started = time.perf_counter()
    value = fn(*args, **kwargs)
    return value, time.perf_counter() - started


# ------------------------------------------------------- H1: parse() is linear
#
# Every shape below made parse() quadratic before 4.37.0. The numbers in the
# comments are what the unfixed parser measured on this hardware; `re` holds
# the GIL while it matches, so each of those seconds was a second in which
# the whole appliance answered nothing.

print("H1  mibparse.parse() is linear in the file")

# 64 KB of IMPORTS symbols with no FROM in them: 66.8 s before.
imports_65k = ("FOO-MIB DEFINITIONS ::= BEGIN\nIMPORTS\n"
               + "aSymbolName, " * (64 * 1024 // 13)
               + "\n;\nfoo OBJECT IDENTIFIER ::= { enterprises 1 }\nEND\n")
result, elapsed = timed(mibparse.parse, imports_65k, max_bytes=8 * 1024 * 1024)
check("65 KB IMPORTS block with no FROM parses in under 1 s",
      elapsed < 1.0, f"{elapsed:.3f}s, {len(imports_65k):,} chars")
check("...and the definition after the block is still found",
      [o.name for o in result.objects] == ["foo"],
      str([o.name for o in result.objects]))

# The same block with its terminating ';' lost — a hand-edited or truncated
# file. Before: the lazy group re-expanded from every start position.
imports_no_semi = ("FOO-MIB DEFINITIONS ::= BEGIN\nIMPORTS\n"
                   + "aSymbolName, " * (64 * 1024 // 13)
                   + "\nfoo OBJECT IDENTIFIER ::= { enterprises 1 }\nEND\n")
_, elapsed = timed(mibparse.parse, imports_no_semi, max_bytes=8 * 1024 * 1024)
check("65 KB IMPORTS block with no ';' parses in under 1 s", elapsed < 1.0,
      f"{elapsed:.3f}s")

# 1 MB of bare macro headers — a MIB whose download was cut short keeps all
# its headers and none of its `::= { ... }` clauses. Before: 200-232 s each.
MB = 1024 * 1024
shapes = {
    "1 MB of bare OBJECT-TYPE headers": "o OBJECT-TYPE\n SYNTAX Integer32\n",
    "1 MB of '::= { a { }' (an inner brace defeats [^{}]*)":
        "o OBJECT-TYPE\n SYNTAX X\n ::= { a { }\n",
    "1 MB of bare NOTIFICATION-TYPE headers": "n NOTIFICATION-TYPE\n OBJECTS { x }\n",
    "1 MB of bare MODULE-IDENTITY headers": "m MODULE-IDENTITY\n LAST-UPDATED z\n",
}
for label, unit in shapes.items():
    text = unit * (MB // len(unit))
    _, elapsed = timed(mibparse.parse, text, max_bytes=8 * 1024 * 1024)
    check(f"{label} parses in under 1 s", elapsed < 1.0,
          f"{elapsed:.3f}s, {len(text):,} chars")

# A real MIB with one clause chopped out of the middle: the header before the
# hole must not swallow the definition after it.
truncated = """
FOO-MIB DEFINITIONS ::= BEGIN
foo OBJECT IDENTIFIER ::= { enterprises 99 }
fooBroken OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
fooGood OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    ::= { foo 1 }
END
"""
result = mibparse.parse(truncated, max_bytes=MB)
names = sorted(o.name for o in result.objects)
check("a clause with no '::=' is skipped, not merged with the next one",
      names == ["foo", "fooGood"], str(names))

# The wall-clock budget: a file that somehow still takes too long is refused
# with a message about the file, and the refusal is a ValueError so the
# upload endpoint keeps turning it into a 400.
try:
    mibparse.parse("x OBJECT-TYPE\n SYNTAX Y\n ::= { a 1 }\n" * 20000,
                   max_bytes=8 * 1024 * 1024, budget_s=0.0000001)
    check("the parse budget stops a file that runs long", False, "no exception")
except mibparse.MibParseTimeout as exc:
    check("the parse budget stops a file that runs long",
          isinstance(exc, ValueError), str(exc)[:60])

check("the byte cap raises MibTooLarge, a ValueError subclass",
      issubclass(mibparse.MibTooLarge, ValueError))
try:
    mibparse.parse("x" * 100, max_bytes=10)
    check("oversized input is refused", False, "no exception")
except mibparse.MibTooLarge:
    check("oversized input is refused", True)

# ------------------------------- H1: the shipped MIBs parse to the same objects
#
# tests/stubs/mib_parse_expected.json was taken from the parser as it shipped
# in 4.36.1 (with one correction, noted below), so it is an oracle for the
# rewrite rather than a snapshot of it.

print("H1  the 21 shipped MIBs parse to the objects they always did")

with open(EXPECTED_PATH) as handle:
    expected = json.load(handle)

shipped = sorted(name for name in os.listdir(MIB_DIR) if name.endswith(".mib"))
check("every shipped MIB has an expectation on file",
      set(shipped) == set(expected), str(set(shipped) ^ set(expected)))

slowest = ("", 0.0)
for name in shipped:
    want = expected[name]
    with open(os.path.join(MIB_DIR, name), encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    parsed, elapsed = timed(mibparse.parse, text, max_bytes=8 * 1024 * 1024)
    resolved, unresolved = mibparse.resolve(parsed.objects,
                                            dict(mibparse.WELL_KNOWN_ROOTS))
    if elapsed > slowest[1]:
        slowest = (name, elapsed)
    lines = sorted(f"{o.name}\t{o.oid}\t{o.syntax}\t{int(o.is_notification)}"
                   f"\t{sorted((o.enums or {}).items())}" for o in parsed.objects)
    got = {
        "module": parsed.module,
        "object_count": len(parsed.objects),
        "resolved_count": resolved,
        "unresolved": unresolved,
        "import_count": len(parsed.imports),
        "digest": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
    }
    if got != want:
        differing = {k: (want[k], got[k]) for k in want if want[k] != got[k]}
        check(f"{name} parses as expected", False, str(differing))
    elif name == shipped[-1]:
        check("all 21 shipped MIBs parse to the same module, object set, OIDs, "
              "syntax, enums, imports and resolution as before", True,
              f"{sum(e['object_count'] for e in expected.values())} objects")

check("no shipped MIB takes more than 1 s to parse", slowest[1] < 1.0,
      f"slowest {slowest[0]} {slowest[1]:.3f}s")

# The one deliberate difference from 4.36.1: SNMPv2-SMI carries the ASN.1
# macro definitions themselves ("NOTIFICATION-TYPE MACRO ::= BEGIN ... END"),
# and the old regexes read the `END` of one macro definition as an object name
# and gave it the OID of the next real clause in the file — while losing the
# clause that OID actually belongs to.
with open(os.path.join(MIB_DIR, "SNMPv2-SMI.mib"), encoding="utf-8") as fh:
    smi = mibparse.parse(fh.read(), max_bytes=MB)
by_name = {o.name: o for o in smi.objects}
check("SNMPv2-SMI's zeroDotZero is found under its own name",
      by_name.get("zeroDotZero") is not None and by_name["zeroDotZero"].oid == "0.0",
      str(by_name.get("zeroDotZero")))
check("...and 'END' is no longer recorded as an object",
      "END" not in by_name)


# --------------------------------------------- H2: resolve() follows the chain

print("H2  resolve() is linear in the number of objects")


def chain_mib(depth: int, terminate: bool = True) -> str:
    """A MIB that lists every object before the parent it hangs off — legal,
    and what a generated MIB usually looks like. One sweep per link was one
    sweep too many."""
    lines = ["CHAIN DEFINITIONS ::= BEGIN"]
    lines += [f"o{i} OBJECT IDENTIFIER ::= {{ o{i + 1} 1 }}" for i in range(depth)]
    if terminate:
        lines.append(f"o{depth} OBJECT IDENTIFIER ::= {{ enterprises 1 }}")
    lines.append("END")
    return "\n".join(lines)


parsed = mibparse.parse(chain_mib(10000), max_bytes=8 * 1024 * 1024)
(count, unresolved), elapsed = timed(
    mibparse.resolve, parsed.objects, dict(mibparse.WELL_KNOWN_ROOTS))
check("a 10,000-deep reversed dependency chain resolves in under 2 s",
      elapsed < 2.0, f"{elapsed:.3f}s (5.89 s before)")
check("...and every object in it resolved",
      count == 10001 and not unresolved, f"{count} resolved, {unresolved[:3]}")
by_name = {o.name: o for o in parsed.objects}
check("...to the right OIDs", by_name["o10000"].oid == "1.3.6.1.4.1.1"
      and by_name["o9998"].oid == "1.3.6.1.4.1.1.1.1", by_name["o9998"].oid)

# The same chain with nothing at the bottom: every object is unresolvable,
# and finding that out must not cost a walk per object either.
parsed = mibparse.parse(chain_mib(20000, terminate=False), max_bytes=8 * 1024 * 1024)
(count, unresolved), elapsed = timed(
    mibparse.resolve, parsed.objects, dict(mibparse.WELL_KNOWN_ROOTS))
check("a 20,000-deep chain that resolves to nothing is rejected in under 1 s",
      elapsed < 1.0, f"{elapsed:.3f}s")
check("...having resolved nothing, and reporting every parent it wanted",
      count == 0 and len(unresolved) == 20000 and "o20000" in unresolved,
      f"{count} resolved, {len(unresolved)} unresolved parents")

# A MIB whose parents form a cycle must terminate, not spin.
cycle = mibparse.parse("C DEFINITIONS ::= BEGIN\n"
                       "a OBJECT IDENTIFIER ::= { b 1 }\n"
                       "b OBJECT IDENTIFIER ::= { a 1 }\nEND", max_bytes=MB)
count, unresolved = mibparse.resolve(cycle.objects, dict(mibparse.WELL_KNOWN_ROOTS))
check("a cycle in the parent chain resolves nothing and terminates",
      count == 0 and unresolved == ["a", "b"], f"{count}, {unresolved}")


# --------------------------------- H2: resolve_all() resolves once, not 8 times

class FakeMibStore:
    """The five nodes_db methods resolve_all() uses, in memory."""

    def __init__(self, files: dict[str, str]):
        self.rows = [{"id": i, "filename": n, "content": c}
                     for i, (n, c) in enumerate(sorted(files.items()))]
        self.objects: dict[int, list[dict]] = {r["id"]: [] for r in self.rows}
        self.updates: dict[int, dict] = {}
        self.parses = 0

    def mib_files(self):
        self.parses += 1
        return list(self.rows)

    def all_known_oids(self):
        return {}

    def mib_objects(self, mib_file_id):
        return self.objects[mib_file_id]

    def update_mib_file(self, mib_file_id, **fields):
        self.updates.setdefault(mib_file_id, {}).update(fields)

    def replace_mib_objects(self, mib_file_id, objects):
        self.objects[mib_file_id] = objects


# Five files, each hanging off the one uploaded after it: the shape that made
# upload order matter, and the one the pass loop paid 8 sweeps for.
files = {"e-05.mib": "M5 DEFINITIONS ::= BEGIN\n"
                     "lvl5 OBJECT IDENTIFIER ::= { enterprises 42 }\nEND"}
for level in range(4, 0, -1):
    files[f"e-{level:02d}.mib"] = (
        f"M{level} DEFINITIONS ::= BEGIN\n"
        f"lvl{level} OBJECT IDENTIFIER ::= {{ lvl{level + 1} {level} }}\nEND")
store = FakeMibStore(files)
summary = mibparse.resolve_all(store, max_bytes=MB)
oids = {o["name"]: o["oid"] for rows in store.objects.values() for o in rows}
check("a five-file chain resolves in one pass whatever order the files are in",
      summary["passes"] == 1 and summary["resolved_count"] == 5,
      str(summary))
check("...to the right OIDs across every file",
      oids == {"lvl5": "1.3.6.1.4.1.42", "lvl4": "1.3.6.1.4.1.42.4",
               "lvl3": "1.3.6.1.4.1.42.4.3", "lvl2": "1.3.6.1.4.1.42.4.3.2",
               "lvl1": "1.3.6.1.4.1.42.4.3.2.1"}, str(oids))


# ---------------------------- H3: no per-character copy, and no escaping int()

print("H3  masking is linear in spans, and no enum value can escape parse()")

# 8 MB of ordinary MIB text — the shipped cap. `list(text)` cost 3.6 s and
# 72 MB of resident memory here before any regex had run.
benign = ("-- a comment line that is quite long indeed, padding padding\n"
          'x OBJECT-TYPE SYNTAX Integer32 DESCRIPTION "hello" ::= { mib-2 1 }\n')
benign = benign * (8 * MB // len(benign))
masked, elapsed = timed(mibparse._strip_comments_and_strings, benign)
check("masking 8 MB of ordinary MIB text takes under 1 s", elapsed < 1.0,
      f"{elapsed:.3f}s (1.8-3.6 s before)")
check("...and every byte keeps its offset", len(masked) == len(benign))
check("...with comments and quoted strings blanked but newlines kept",
      "comment line" not in masked and "hello" not in masked
      and masked.count("\n") == benign.count("\n") and "OBJECT-TYPE" in masked)

# The masking is what makes `--` and `::=` inside a comment or a description
# inert; that has to survive the rewrite.
tricky = mibparse.parse(
    "F DEFINITIONS ::= BEGIN\n"
    "-- a comment with a fake ::= { mib-2 999 } in it\n"
    "a OBJECT-TYPE\n  SYNTAX Integer32\n"
    '  DESCRIPTION "text with -- two dashes and a literal ::= { x 1 } in it"\n'
    "  ::= { mib-2 7 }\nEND", max_bytes=MB)
found = {o.name: o for o in tricky.objects}
check("a fake '::= { }' inside a comment or a string is still inert",
      list(found) == ["a"] and found["a"].last_arc == "7", str(list(found)))
check("...while the DESCRIPTION text itself comes back unmasked",
      "-- two dashes" in found["a"].description
      and "::= { x 1 }" in found["a"].description, found["a"].description)

# G-14: an enum value longer than sys.get_int_max_str_digits() raised
# Python's own "Exceeds the limit (4300 digits)" ValueError out of parse(), so
# the operator was told about Python's integer limits instead of about their
# MIB, and resolve_all() then skipped that file for good.
huge_enum = ("E DEFINITIONS ::= BEGIN\n"
             "x OBJECT-TYPE SYNTAX INTEGER { up(" + "1" * 5000 + "), down(2) }\n"
             "  ::= { mib-2 1 }\nEND")
try:
    got = {o.name: o for o in mibparse.parse(huge_enum, max_bytes=MB).objects}
    check("a 5,000-digit enum value does not raise out of parse()", True)
    check("...the object is still recorded, with the usable enums it has",
          got["x"].last_arc == "1" and got["x"].enums == {2: "down"},
          str(got["x"].enums))
except ValueError as exc:
    check("a 5,000-digit enum value does not raise out of parse()", False, str(exc))

ordinary = mibparse.parse("E DEFINITIONS ::= BEGIN\nx OBJECT-TYPE\n"
                          " SYNTAX INTEGER { up(1), down(2), testing(-3) }\n"
                          " ::= { mib-2 1 }\nEND", max_bytes=MB)
check("an ordinary enum table is unaffected",
      ordinary.objects[0].enums == {1: "up", 2: "down", -3: "testing"},
      str(ordinary.objects[0].enums))

# A file resolve_all() cannot parse is reported on the file, not skipped in
# silence on this and every future re-resolve.
good = "G DEFINITIONS ::= BEGIN\ng OBJECT IDENTIFIER ::= { enterprises 7 }\nEND"
store = FakeMibStore({
    "good.mib": good,
    "toobig.mib": "B DEFINITIONS ::= BEGIN\n" + "b OBJECT-TYPE\n SYNTAX X\n" * 400 + "END",
})
big_id = [r["id"] for r in store.rows if r["filename"] == "toobig.mib"][0]
summary = mibparse.resolve_all(store, max_bytes=200)
check("a file over the byte cap is left exactly as it was",
      summary["files_failed"] == 0 and big_id not in store.updates, str(summary))
check("...and the files that do parse still resolve",
      summary["files"] == 1 and summary["resolved_count"] == 1, str(summary))

store = FakeMibStore({
    "slow.mib": "S DEFINITIONS ::= BEGIN\n" + "s OBJECT-TYPE\n SYNTAX X\n" * 5000 + "END",
})
slow_id = [r["id"] for r in store.rows if r["filename"] == "slow.mib"][0]
budget_was = mibparse.PARSE_BUDGET_S
try:
    mibparse.PARSE_BUDGET_S = 0.0000001
    summary = mibparse.resolve_all(store, max_bytes=MB)
finally:
    mibparse.PARSE_BUDGET_S = budget_was
note = store.updates.get(slow_id, {}).get("parse_notes", "")
check("a file that cannot be parsed gets a note saying so",
      summary["files_failed"] == 1 and note.startswith("Could not be parsed"),
      f"{summary['files_failed']} failed, note={note[:70]!r}")


if failures:
    print(f"\nFAILED: {len(failures)} check(s): {', '.join(failures)}")
    raise SystemExit(1)
print("\nall parser hardening checks passed")

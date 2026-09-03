"""The parsers, resolvers and small in-memory tables, under the inputs a
fuzz run and a fresh-eyes review found: a MIB whose IMPORTS block never
closes, a truncated MIB that is all macro headers and no clauses, a reversed
dependency chain, an enum value longer than Python's own integer guard, a
DNS answer from the wrong host, and the vendor and port tables around them.

No database and no subprocess; the only sockets are loopback UDP, from a
fake resolver this file starts and stops itself. Everything else is a pure
function or an in-memory object, so the suite is deterministic and finishes
in a few seconds. The timing assertions carry a wide margin on purpose —
each one is two to three orders of magnitude below what the unfixed code
measured, so a loaded build machine cannot make them flap, and a return of
the quadratic behaviour cannot make them pass.
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


# ------------------------------------ H4: a pure textual-convention module

print("H4  SNMPv2-TC reports what it is instead of looking like a failed import")

with open(os.path.join(MIB_DIR, "SNMPv2-TC.mib"), encoding="utf-8") as fh:
    tc = mibparse.parse(fh.read(), max_bytes=MB)
check("SNMPv2-TC's textual conventions are counted",
      tc.textual_conventions == 16, str(tc.textual_conventions))
check("...and none of them is turned into an object", tc.objects == [])
note = " ".join(tc.notes)
check("...and the note says the import succeeded, not that nothing was found",
      "16 textual convention(s)" in note and "The import succeeded." in note
      and "No OBJECT-TYPE" not in note, note)

# A file with neither objects nor conventions still says so plainly.
empty = mibparse.parse("just some prose, no MIB syntax at all", max_bytes=MB)
check("a file with nothing in it at all still reports that",
      empty.objects == [] and empty.textual_conventions == 0
      and any("No OBJECT-TYPE" in n for n in empty.notes), str(empty.notes))

# A module with both is unchanged: no note at all, and the objects are real.
mixed = mibparse.parse("M DEFINITIONS ::= BEGIN\n"
                       "Foo ::= TEXTUAL-CONVENTION STATUS current\n"
                       "m OBJECT IDENTIFIER ::= { enterprises 3 }\nEND",
                       max_bytes=MB)
check("a module with both conventions and objects is unchanged",
      mixed.textual_conventions == 1 and [o.name for o in mixed.objects] == ["m"]
      and mixed.notes == [], str(mixed.notes))


# ------------------------------- H5: one key per vendor, and an honest claim

print("H5  enterprise arcs: one key per manufacturer, Rockwell reachable")

from netpath import enterprises, vendorid            # noqa: E402

# G-16. Each of these arcs used to key its own vendor row, so one HPE or
# Dell fleet was spread over several rows of the Nodes vendor filter.
for arc, want in ((47196, "aruba"), (14823, "aruba"), (8744, "hp"),
                  (40310, "hp"), (11, "hp"), (6027, "dell"), (10297, "dell"),
                  (674, "dell"), (12276, "f5"), (3375, "f5"),
                  (1588, "brocade"), (1991, "brocade")):
    got = vendorid.arc_name(arc)
    check(f"arc {arc} keys the vendor as {want!r}", got == want, got)

check("an alias still displays as its manufacturer, not as its arc",
      enterprises.display_name("arubaCx") == "Aruba"
      and enterprises.display_name("silverPeak") == "HP / HPE"
      and enterprises.display_name("dellPowerConnect") == "Dell",
      enterprises.display_name("arubaCx"))
check("...while the arc's own label survives as a model hint",
      enterprises.arc_label(47196) == "Aruba CX (HPE)"
      and enterprises.arc_label(40310) == "Silver Peak / HPE",
      enterprises.arc_label(47196))
decision = vendorid.decide("1.3.6.1.4.1.47196.1.2", "ArubaOS-CX", [], [])
check("...and the evidence line carries both",
      decision.vendor == "aruba" and "Aruba CX (HPE)" in decision.reason,
      decision.reason)
check("hpCompaq is deliberately left alone (HP's server arc, not its switches)",
      vendorid.arc_name(232) == "hpCompaq", vendorid.arc_name(232))
check("a vendor with one arc is untouched",
      vendorid.arc_name(9) == "cisco" and vendorid.arc_name(2636) == "juniper")

# G-17. Rockwell/Allen-Bradley holds PEN 95; without it a controller
# answering its own arc read as "unknown enterprise arc 95".
check("PEN 95 names Rockwell Automation / Allen-Bradley",
      enterprises.lookup(95) == ("rockwellAutomation",
                                 "Rockwell Automation / Allen-Bradley"),
      str(enterprises.lookup(95)))
logix = vendorid.decide("1.3.6.1.4.1.95.1.2", "Allen-Bradley ControlLogix", [], [])
check("a controller on arc 95 is named, at curated confidence",
      logix.vendor == "rockwellAutomation" and logix.confidence == "medium",
      f"{logix.vendor} {logix.confidence}")
check("...and it is not claimed as cross-checked", not enterprises.is_verified(95))

# A Stratix switch is Rockwell's product built by Cisco: a 1.3.6.1.4.1.9
# sysObjectID and an IOS sysDescr, so the arc branch wins and the sysDescr
# rule that knows about Rockwell is never reached. The vendor key stays
# cisco — the box runs IOS, so the Cisco MIB, poll and ConfigRX profiles are
# the right ones — but the evidence now says whose box it is.
stratix = vendorid.decide(
    "1.3.6.1.4.1.9.1.2694",
    "Cisco IOS Software, Stratix 5700 Software (STRATIX-5700-UNIVERSALK9-M)",
    [], [])
check("a Stratix switch still polls as Cisco", stratix.vendor == "cisco")
check("...but the evidence names the Rockwell rebadge",
      "Rockwell Automation / Allen-Bradley rebadge" in stratix.reason,
      stratix.reason)
plain = vendorid.decide("1.3.6.1.4.1.9.1.1", "Cisco IOS Software, C2960", [], [])
check("...and an ordinary Cisco switch says nothing of the sort",
      plain.vendor == "cisco" and "rebadge" not in plain.reason, plain.reason)
check("ArmorStratix and a bare Allen-Bradley string match too",
      vendorid.rebadged_by(9, "cisco ios, ArmorStratix 5700") == "rockwellAutomation"
      and vendorid.rebadged_by(9, "Allen-Bradley 1783-BMS") == "rockwellAutomation"
      and vendorid.rebadged_by(2636, "Stratix") == ""
      and vendorid.rebadged_by(None, "Stratix") == "")

# G-15. The docstring claimed a provenance the tree contradicts.
check("the module no longer claims the arcs were read from vendor MIB text",
      "read out of the vendor's own MIB text" not in (enterprises.__doc__ or ""))
check("...and says what VERIFIED and CURATED actually mean",
      "cross-checked against a real device's sysObjectID or a bundled\n  MIB"
      in (enterprises.__doc__ or ""), (enterprises.__doc__ or "")[:0])

# Every alias target must itself be a real key, or a fleet lands on nothing.
targets = {v for v in enterprises.VENDOR_ALIASES.values()}
keys = {key for key, _ in enterprises.ENTERPRISES.values()}
check("every alias points at an arc that exists", targets <= keys,
      str(targets - keys))
check("no alias points at another alias",
      not (targets & set(enterprises.VENDOR_ALIASES)),
      str(targets & set(enterprises.VENDOR_ALIASES)))


# ------------------------------------------------------------ H6: namelookup

print("H6  name lookup: no global timeout, no off-path answers, checked args")

import ast                                           # noqa: E402
import inspect                                       # noqa: E402
import socket                                        # noqa: E402
import struct                                        # noqa: E402
import threading                                     # noqa: E402

from netpath import namelookup                       # noqa: E402

source = inspect.getsource(namelookup)
# Read as code, not as text: the docstring names setdefaulttimeout to explain
# why it is gone, and that mention must not make this check pass or fail.
called = {node.func.attr for node in ast.walk(ast.parse(source))
          if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
check("reverse() no longer calls the process-global socket timeout setter",
      "setdefaulttimeout" not in called)
check("the query id no longer comes from the Mersenne Twister",
      "random.randint" not in source and "os.urandom" in source)

# The leak the review reproduced: while reverse() ran, every socket created
# anywhere in the process was born with the resolver's timeout, and eight
# concurrent workers left the global set for good.
socket.setdefaulttimeout(None)
observed: set = set()
stop = threading.Event()


def watch_new_sockets() -> None:
    while not stop.is_set():
        probe = socket.socket()
        observed.add(probe.gettimeout())
        probe.close()


watcher = threading.Thread(target=watch_new_sockets, daemon=True)
watcher.start()
barrier = threading.Barrier(8)


def resolve_worker() -> None:
    barrier.wait()
    for _ in range(4):
        namelookup.reverse("127.0.0.1", timeout_s=3.0, use_nslookup=False)


workers = [threading.Thread(target=resolve_worker) for _ in range(8)]
for worker in workers:
    worker.start()
for worker in workers:
    worker.join()
stop.set()
watcher.join(2.0)
check("no unrelated socket inherits a timeout while reverse() runs",
      observed == {None}, str(sorted(observed, key=str)))
check("...and eight concurrent resolvers leave the global default alone",
      socket.getdefaulttimeout() is None, str(socket.getdefaulttimeout()))


class FakeResolver:
    """A UDP server on loopback that answers however the test tells it to.

    `spoof_from` is a second socket on a different port, standing in for an
    off-path host that guessed the query id.
    """

    def __init__(self, mode: str, answer: str = "host.example."):
        self.mode, self.answer = mode, answer
        self.ids: list[int] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.25)
        self.spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.spoof.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _reply(self, query: bytes, name: str, question: bytes | None = None) -> bytes:
        question = query[12:] if question is None else question
        rdata = namelookup._encode(name)
        return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question
                + b"\xc0\x0c" + struct.pack("!HHIH", namelookup.PTR, 1, 60,
                                            len(rdata)) + rdata)

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                query, client = self.sock.recvfrom(4096)
            except OSError:
                continue
            self.ids.append(struct.unpack("!H", query[:2])[0])
            if self.mode == "answer":
                self.sock.sendto(self._reply(query, self.answer), client)
            elif self.mode == "spoof":
                # Correct id, correct question, wrong source address.
                self.spoof.sendto(self._reply(query, "forged.example."), client)
            elif self.mode == "wrong-question":
                other = namelookup._encode("9.9.9.9.in-addr.arpa") + \
                    struct.pack("!HH", namelookup.PTR, namelookup.IN)
                self.sock.sendto(self._reply(query, self.answer, other), client)
            elif self.mode == "junk":
                # A wrong-id datagram every 0.15 s, forever: each one used to
                # restart the per-recv clock and could hold a worker for good.
                while not self.stop.is_set():
                    bad = struct.pack("!H", (struct.unpack("!H", query[:2])[0]
                                             ^ 0xFFFF)) + query[2:]
                    try:
                        self.sock.sendto(self._reply(bad, "junk.example."), client)
                    except OSError:
                        return
                    time.sleep(0.15)

    def close(self) -> None:
        self.stop.set()
        self.thread.join(2.0)
        self.sock.close()
        self.spoof.close()


server = FakeResolver("answer")
try:
    got, elapsed = timed(namelookup.query_ptr, "10.1.2.3", "127.0.0.1",
                         2.0, server.port)
    check("a genuine reply from the nominated server is accepted",
          got == "host.example", str(got))
finally:
    server.close()

server = FakeResolver("spoof")
try:
    got, elapsed = timed(namelookup.query_ptr, "10.1.2.3", "127.0.0.1",
                         1.0, server.port)
    check("an answer from any other source address is not accepted",
          got is None, str(got))
    check("...and the query still ends at its deadline", elapsed < 3.0,
          f"{elapsed:.2f}s")
finally:
    server.close()

server = FakeResolver("wrong-question")
try:
    got = namelookup.query_ptr("10.1.2.3", "127.0.0.1", 1.0, server.port)
    check("a reply whose question section is not the one asked is rejected",
          got is None, str(got))
finally:
    server.close()

server = FakeResolver("junk")
try:
    got, elapsed = timed(namelookup.query_ptr, "10.1.2.3", "127.0.0.1",
                         1.0, server.port)
    check("a stream of wrong-id datagrams cannot extend the deadline",
          got is None and elapsed < 3.0, f"{got}, {elapsed:.2f}s")
finally:
    server.close()

server = FakeResolver("answer")
try:
    for _ in range(40):
        namelookup.query_ptr("10.1.2.3", "127.0.0.1", 2.0, server.port)
    ids = server.ids
finally:
    server.close()
check("query ids do not repeat across 40 queries", len(set(ids)) >= 36,
      f"{len(set(ids))} distinct of {len(ids)}")
check("...and are not a sequence",
      not all(b - a == 1 for a, b in zip(ids, ids[1:])), str(ids[:4]))

# G-20: nslookup's arguments are checked here, not assumed from the callers.
ran: list = []
real_run = namelookup.subprocess.run
namelookup.subprocess.run = lambda *a, **k: ran.append(a) or real_run(*a, **k)
try:
    check("nslookup refuses an argument that is not an address",
          namelookup.nslookup("-debug") is None
          and namelookup.nslookup("example.com; id") is None
          and namelookup.nslookup("") is None)
    check("...and refuses a nominated server that is not one",
          namelookup.nslookup("10.1.2.3", "-port=9999") is None
          and namelookup.nslookup("10.1.2.3", "$(id)") is None)
    check("...without ever starting a process", ran == [], str(ran))
    check("reverse() refuses an argument that is not an address",
          namelookup.reverse("-debug", use_nslookup=True) == (None, "none")
          and namelookup.reverse("evil.example", use_nslookup=True) == (None, "none"))
    check("...without ever starting a process either", ran == [], str(ran))
finally:
    namelookup.subprocess.run = real_run

check("an ordinary address and resolver are still accepted",
      namelookup.is_ip_literal("10.1.2.3") and namelookup.is_ip_literal("fe80::1")
      and namelookup.is_resolver_address("10.0.0.53")
      and namelookup.is_resolver_address("ns1.example.com")
      and not namelookup.is_resolver_address("-timeout=1")
      and not namelookup.is_resolver_address("a b")
      and not namelookup.is_resolver_address(""))


# ------------------------------------------------------- H7: EventLog targets

print("H7  the event log is bounded in both of its collections")

from netpath import eventlog                         # noqa: E402

log = eventlog.EventLog()
for i in range(eventlog.TARGET_LIMIT + 500):
    log.add(eventlog.DNS, "resolved", target=f"10.0.{i // 256}.{i % 256}")
check("the target set stops at its limit",
      len(log.targets()) == eventlog.TARGET_LIMIT, str(len(log.targets())))
check("...keeping the most recently seen, dropping the oldest",
      "10.0.1.244" in log.targets() and "10.0.0.0" not in log.targets())

# LRU, not FIFO: a target seen again is not the next one evicted.
log = eventlog.EventLog(target_limit=4)
for name in ("a", "b", "c", "d"):
    log.add(eventlog.DNS, "x", target=name)
log.add(eventlog.DNS, "x", target="a")               # refreshes 'a'
log.add(eventlog.DNS, "x", target="e")               # evicts 'b', not 'a'
check("a target seen again survives the next eviction",
      log.targets() == ["a", "c", "d", "e"], str(log.targets()))

# The sort is cached: repeats must not re-sort, but a new target must.
log = eventlog.EventLog(target_limit=10)
for name in ("z", "y", "x"):
    log.add(eventlog.SNMP, "x", target=name)
check("targets() comes back sorted", log.targets() == ["x", "y", "z"],
      str(log.targets()))
first = log.targets()
log.add(eventlog.SNMP, "x", target="z")
check("...and a repeat does not change it", log.targets() == first)
log.add(eventlog.SNMP, "x", target="a")
check("...while a new target does", log.targets() == ["a", "x", "y", "z"],
      str(log.targets()))

# clear() cleared the events and left the targets, so the debug page's filter
# went on offering every device the log had ever mentioned.
log.clear()
check("clear() empties the targets as well as the events",
      log.targets() == [] and log.all() == [], str(log.targets()))
log.add(eventlog.TRACE, "after clear", target="10.9.9.9")
check("...and the log still works afterwards",
      log.targets() == ["10.9.9.9"] and len(log.all()) == 1, str(log.targets()))

# Reading targets() is on the debug-page poll path, so it must stay cheap
# with a full set. 20,000 remembered targets sorted under the lock on every
# poll was the shape being fixed; 1,000 cached is the shape now.
log = eventlog.EventLog()
for i in range(eventlog.TARGET_LIMIT):
    log.add(eventlog.NODES, "x", target=f"device-{i:05d}")
_, elapsed = timed(lambda: [log.targets() for _ in range(2000)])
check("2,000 polls of a full target list take under 1 s", elapsed < 1.0,
      f"{elapsed:.3f}s")

check("an event with no target adds nothing",
      (lambda fresh: (fresh.add(eventlog.SYSTEM, "started"),
                      fresh.targets() == [])[1])(eventlog.EventLog()))


# ------------------------------------------------- H8: the timeline's ceilings

print("H8  build_timeline clamps its own window and block count")

from netpath import analysis                         # noqa: E402

now = 1_700_000_000.0

# The review's own reproduction: t0/t1 and the pixel width they are derived
# from come straight off a query string that only needs the read-only role.
# t1=1e9 with a wide viewport allocated 326,798 buckets; width=3e7 would have
# reached about ten million, some 4 GB, from one GET.
for label, (t0, t1, bucket_s) in {
    "t1=1e9, 3 s blocks": (0.0, 1e9, 3.0),
    "a decade of 1 s blocks": (now - 10 * 365 * 86400, now, 1.0),
    "a 0.001 s block over ten minutes": (now - 600, now, 0.0),
    "a negative block width": (now - 600, now, -5.0),
}.items():
    buckets, elapsed = timed(analysis.build_timeline, [], t0, t1, bucket_s)
    check(f"{label} yields at most {analysis.MAX_BUCKETS} blocks",
          len(buckets) <= analysis.MAX_BUCKETS, f"{len(buckets)} in {elapsed:.3f}s")
    check(f"...and {label} still spans the whole window",
          buckets[0].t0 <= t0 + 1 and buckets[-1].t1 >= min(t1, analysis.MAX_TIMESTAMP)
          or len(buckets) == analysis.MAX_BUCKETS,
          f"{buckets[0].t0:.0f}..{buckets[-1].t1:.0f}")

# Values no client sends, which nothing rejected: infinities, NaN, a reversed
# window, and strings.
for label, args in {
    "infinities": (float("-inf"), float("inf"), 0.0),
    "NaN": (float("nan"), 1.0, 60.0),
    "a reversed window": (now, now - 3600, 60.0),
    "strings": ("x", "y", "z"),
    "None": (None, None, None),
}.items():
    try:
        buckets = analysis.build_timeline([], *args)
        check(f"{label} produce a bounded result rather than an exception",
              0 < len(buckets) <= analysis.MAX_BUCKETS, f"{len(buckets)} blocks")
    except Exception as exc:                          # noqa: BLE001
        check(f"{label} produce a bounded result rather than an exception",
              False, f"{type(exc).__name__}: {exc}")

check("clamp_window refuses a span beyond ten years",
      analysis.clamp_window(0.0, 1e12)[1] - analysis.clamp_window(0.0, 1e12)[0]
      <= analysis.MAX_SPAN_S,
      str(analysis.clamp_window(0.0, 1e12)))
check("...and a t0 before the epoch",
      analysis.clamp_window(-1e9, now)[0] >= 0.0,
      str(analysis.clamp_window(-1e9, now)[0]))
check("...and leaves an ordinary window exactly as it is",
      analysis.clamp_window(now - 3600, now) == (now - 3600, now))

# What the UI actually asks for must be untouched: one hour of 60 s blocks,
# and a trace in each one still lands in the right block.
traces = [{"started_ts": now - 3600 + i * 60 + 5, "status": "ok",
           "rtt_ms": float(i), "loss_pct": 0.0, "path_sig": "a",
           "icmp_code": None, "icmp_from": None} for i in range(60)]
buckets = analysis.build_timeline(traces, now - 3600, now, 60.0)
check("an ordinary hour of 60 s blocks is unchanged",
      60 <= len(buckets) <= 61 and sum(b.total for b in buckets) == 60,
      f"{len(buckets)} blocks, {sum(b.total for b in buckets)} traces placed")
check("...and each block still carries its own trace",
      all(b.total <= 1 for b in buckets) and all(b.status in ("ok", "none")
                                                 for b in buckets))


# ------------------------------------ H9: the console's client list and hint

print("H9  the service console renders a bounded client list and true text")

# console.py imports PySide6 at module level and PySide6 is not a dependency
# of this application, so the Qt-free parts are lifted out of its source and
# run on their own rather than imported.
CONSOLE_PATH = os.path.join(REPO_ROOT, "netpath", "console.py")
with open(CONSOLE_PATH, encoding="utf-8") as handle:
    console_source = handle.read()
console_tree = ast.parse(console_source)
wanted = {"client_rows", "_ago", "CLIENT_ROWS"}
lifted: list = []
for node in console_tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in wanted:
        lifted.append(node)
    elif isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") in wanted:
        lifted.append(node)
    elif isinstance(node, ast.Assign) and any(
            getattr(t, "id", "") in wanted for t in node.targets):
        lifted.append(node)
console = {"heapq": __import__("heapq"), "time": time,
           "datetime": __import__("datetime").datetime}
exec(compile(ast.Module(body=lifted, type_ignores=[]), CONSOLE_PATH, "exec"),
     console)
check("console.py still exposes the row selection on its own",
      "client_rows" in console and console.get("CLIENT_ROWS") == 200,
      str(sorted(k for k in console if not k.startswith("__"))))

# The shape being fixed: one entry per source address for the life of the
# process — every port-scanner source, every health-check probe, every
# DHCP-reassigned laptop — sorted and redrawn as 6 widgets per row, once a
# second, on the GUI thread.
many = {f"198.51.{i // 256}.{i % 256}": {
    "requests": i, "errors": i % 3, "first_seen": now - 10000 + i,
    "last_seen": now - 20000 + i, "agent": "probe"} for i in range(20000)}
(total, rows), elapsed = timed(console["client_rows"], many)
check("20,000 remembered clients render as 200 rows",
      total == 20000 and len(rows) == console["CLIENT_ROWS"],
      f"{total} seen, {len(rows)} rows")
newest_first = sorted(many, key=lambda a: -many[a]["last_seen"])
check("...and they are the 200 most recently seen, newest first",
      [row[0] for row in rows] == newest_first[:console["CLIENT_ROWS"]],
      f"{rows[0][0]} vs {newest_first[0]}")
check("...selected in well under a second", elapsed < 0.5, f"{elapsed:.3f}s")
check("a small fleet is unaffected",
      console["client_rows"]({k: many[k] for k in list(many)[:5]})[1].__len__() == 5)

# The redraw guard: the same snapshot twice must produce the same rows, so
# the caller's `!=` check skips the repaint.
check("the same clients produce equal rows, so the table is not repainted",
      console["client_rows"](many) == console["client_rows"](many))

# G-23, the console's copy. auth.py, the login page, PUBLIC_PATHS gating,
# per-module permissions, a forced first-run password change and sign-in
# throttling all exist; this card said otherwise, once a second, forever.
hint_source = console_source[console_source.index("self.listener_hint.setText("):]
hint_source = hint_source[:hint_source.index("\n\n")]
check("the listener card no longer claims there is no authentication",
      "no authentication" not in console_source.lower()
      and "authentication yet" not in console_source.lower())
check("...and says what is true instead: TLS, reach, and that sign-in applies",
      "TLS" in hint_source and "reach" in hint_source
      and "Sign-in is required" in hint_source, hint_source[:80])


# --------------------------------------------- H10: IPAM scans are staggered

print("H10 IPAM scans are staggered and capped, not fanned out at once")

from netpath import ipam_worker                      # noqa: E402


class FakeIpamDb:
    """The three IpamWorker scheduling methods read, and nothing else: the
    scan body itself is replaced below, so no ping, no ARP table and no
    database are involved."""

    def __init__(self, subnets: int, **settings):
        self.rows = [{"id": i + 1, "enabled": 1, "cidr": f"10.{i}.0.0/24",
                      "label": f"subnet-{i}"} for i in range(subnets)]
        self._settings = {"enabled": True, "scan_interval_minutes": 60,
                          "ping_workers": 64, **settings}

    def settings(self) -> dict:
        return dict(self._settings)

    def subnets(self) -> list:
        return list(self.rows)

    def dhcp_servers(self) -> list:
        return []


class CountingWorker(ipam_worker.IpamWorker):
    """Records how many scans were in flight at once, and for how long."""

    def __init__(self, db):
        super().__init__(db)
        self.counter_lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0
        self.ran: list = []

    def _scan(self, subnet_id, settings):
        with self.counter_lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            self.ran.append(subnet_id)
        time.sleep(0.05)
        with self.counter_lock:
            self.in_flight -= 1


def drain(worker, expected, seconds=20.0):
    """Wait until `expected` scans have run, or give up."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        with worker.counter_lock:
            if len(worker.ran) >= expected and worker.in_flight == 0:
                return True
        time.sleep(0.02)
    return False


# G-25, the first tick: _next_scan starts empty, so `now >= _next_scan.get(id, 0)`
# was true for every enabled subnet at once — 50 subnets meant 50 scan threads
# and up to 3,200 concurrent ping subprocesses on a box already polling a fleet.
worker = CountingWorker(FakeIpamDb(50))
try:
    started_at = time.time()
    worker._tick()
    check("the first tick starts one subnet, not all fifty",
          len(worker.ran) <= 1, f"{len(worker.ran)} started")
finally:
    worker.stop()

# The stagger itself, without the scheduling that follows it: every subnet
# gets its own first due time inside the spread window.
spread_worker = CountingWorker(FakeIpamDb(50))
try:
    started_at = time.time()
    spread_worker._stagger_first_scans(spread_worker.db.subnets(),
                                       spread_worker.db.settings(), started_at)
    due = [spread_worker._next_scan[row["id"]] for row in spread_worker.db.rows]
    check("every subnet's first scan lands inside the stagger window",
          all(started_at <= t <= started_at + ipam_worker.FIRST_SCAN_SPREAD_S
              for t in due) and len(set(due)) == 50,
          f"{min(due) - started_at:.1f}s..{max(due) - started_at:.1f}s, "
          f"{len(set(due))} distinct")
    check("...so nothing is left in lockstep", max(due) - min(due) > 60,
          f"{max(due) - min(due):.0f}s apart")
    check("...and a subnet added afterwards is still due immediately",
          spread_worker._next_scan.get(999, 0) == 0)
finally:
    spread_worker.stop()

# The cap: with everything due at once, no more than max_concurrent_scans run
# together, and every subnet still gets scanned.
worker = CountingWorker(FakeIpamDb(20, max_concurrent_scans=4))
try:
    worker._tick()                    # stagger
    worker._next_scan.clear()         # ...then make everything due
    worker._tick()
    check("every due subnet is eventually scanned", drain(worker, 20),
          f"{len(worker.ran)} of 20")
    check("...but never more than max_concurrent_scans at a time",
          worker.peak <= 4, f"peak {worker.peak}")
    check("...and each was scanned once", sorted(worker.ran) == list(range(1, 21)),
          str(sorted(worker.ran)[:5]))
finally:
    worker.stop()

# scan_now() reaches the same pool, so a bulk "scan all subnets" from the API
# is capped too rather than fanning out with no limit.
worker = CountingWorker(FakeIpamDb(20, max_concurrent_scans=3))
try:
    for row in worker.db.rows:
        worker.scan_now(row["id"])
    check("a bulk scan-all from the API is capped as well", drain(worker, 20)
          and worker.peak <= 3, f"peak {worker.peak}, {len(worker.ran)} ran")
finally:
    worker.stop()

# A subnet already queued or running is not handed in again.
worker = CountingWorker(FakeIpamDb(1, max_concurrent_scans=1))
try:
    for _ in range(10):
        worker.scan_now(1)
    drain(worker, 1)
    time.sleep(0.2)
    check("asking for the same subnet ten times runs it once",
          worker.ran.count(1) == 1, str(worker.ran))
finally:
    worker.stop()

check("the default cap is small enough to matter",
      1 <= ipam_worker.DEFAULT_MAX_CONCURRENT_SCANS <= 8,
      str(ipam_worker.DEFAULT_MAX_CONCURRENT_SCANS))


if failures:
    print(f"\nFAILED: {len(failures)} check(s): {', '.join(failures)}")
    raise SystemExit(1)
print("\nall parser hardening checks passed")

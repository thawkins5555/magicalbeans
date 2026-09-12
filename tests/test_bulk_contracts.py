"""Two bulk-list contracts, checked by reading the source rather than by
sending a 50,000-id request through every route.

1. The API reads a caller's id list in exactly ONE place. `_bulk_ids` owns
   the cap, the refusal wording and the int coercion; `_bulk_device_ids` is
   its device wrapper. A route that hand-rolls `body.get("..._ids")` gets its
   own cap (or none), which is how a bulk route ends up accepting a list the
   store cannot bind. The one caller list deliberately NOT here is
   `post_nodes_upstream_suggestions_apply`'s `assignments`: it is a list of
   {device_id, upstream_id} dicts, not ids, with its own
   UPSTREAM_APPLY_MAX_ASSIGNMENTS cap, and the write behind it
   (nodesdb.set_upstream_ids) is an executemany with no `IN (...)` at all.

2. Every store function that builds `... IN (?,?,…)` from a list splits it
   with sqlitebase.id_chunks. One statement binds at most
   SQLITE_MAX_VARIABLE_NUMBER parameters: 32,766 on SQLite 3.32 and newer,
   999 on anything older, and this application does not choose which SQLite
   its Python was linked against — so an unsplit statement works on one
   operator's install and answers 500, "too many SQL variables", on
   another's. test_bulk_id_chunking.py proves the split gives the same
   answer; this proves no reader is missing one.

ALLOWED lists the functions whose placeholder list provably cannot come from
a caller (a fixed vocabulary, or rows this store just read itself), each with
its reason. A new offender fails here rather than in the field.
"""
import ast
import pathlib
import re
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web import api as api_mod

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


ROOT = pathlib.Path(_paths.REPO_ROOT) / "netpath"

# A placeholder list interpolated into an IN clause, however it is spelled:
# f"... IN ({marks})" and the older `" IN (" + ",".join(...)`.
IN_CLAUSE = re.compile(r'(?:NOT )?IN \(\{|(?:NOT )?IN \(" *\+')

# function -> why its list cannot be a caller's, so cannot outgrow a bind.
ALLOWED = {
    "appdb.migrate_from":
        "global_keys is the subset of GLOBAL_DEFAULTS, a module constant.",
    "db.last_traces":
        "target_ids are NetPath's configured destinations; netpath/db.py is "
        "outside this change's scope.",
    "db.last_https_checks":
        "same destination list as last_traces; netpath/db.py is outside this "
        "change's scope.",
    "db.reset_hop_stats":
        "the stale ips are read from hop_stats for one target, bounded by a "
        "traceroute's hop count.",
    "nodesdb.interface_thresholds_for_roots":
        "roots are metric-root names from the metric catalogue, not ids.",
    "nodesdb.replace_interfaces":
        "the removed if_index list is this device's own interface rows, not a "
        "caller's list.",
    "nodesdb.device_events":
        "kinds/exclude_kinds are event-kind names from a fixed vocabulary.",
    "nodesdb.has_method_events":
        "the list is the TIMELINE_ONLY_EVENT_KINDS constant.",
    "nodesdb.device_method_segments":
        "kinds come from its own status_map literal.",
    "nodesdb._event_segments":
        "kinds are the keys of the caller's status_map literal.",
    "nodesdb.count_events_by_device":
        "kinds are event-kind names from a fixed vocabulary.",
    "nodesseriesdb.record_metric_samples":
        "the keys are one device's own poll payload, already one statement's "
        "worth of metrics.",
    "nodesseriesdb.metrics_for_keys":
        "keys are metric names named by the alert rule set, not request ids.",
    "wirelessdb.prune_stale":
        "stale_ids are rows this store just read for one controller; "
        "netpath/wirelessdb.py is outside this change's scope.",
}

offenders = []
seen_allowed = set()
for path in sorted(ROOT.glob("*.py")):
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = "\n".join(lines[node.lineno - 1:node.end_lineno])
        if not IN_CLAUSE.search(body):
            continue
        name = f"{path.stem}.{node.name}"
        if name in ALLOWED:
            seen_allowed.add(name)
            continue
        if "id_chunks(" not in body:
            offenders.append(f"{name} (line {node.lineno})")

check("every dynamic IN (...) list is split by sqlitebase.id_chunks",
      not offenders, "; ".join(offenders))
check("the allow-list has no entry for a function that no longer builds one",
      seen_allowed == set(ALLOWED), sorted(set(ALLOWED) - seen_allowed))
check("every allow-list entry carries a reason",
      all(reason.strip() for reason in ALLOWED.values()))

api_source = (ROOT / "web" / "api.py").read_text(encoding="utf-8")
api_lines = api_source.splitlines()
api_tree = ast.parse(api_source)

# Only _bulk_ids itself may read a body's id list directly.
BODY_ID_READ = re.compile(r'body\.get\("[a-z_]*ids"\)')
hand_rolled = []
for node in ast.walk(api_tree):
    if not isinstance(node, ast.FunctionDef) or node.name == "_bulk_ids":
        continue
    body = "\n".join(api_lines[node.lineno - 1:node.end_lineno])
    if BODY_ID_READ.search(body):
        hand_rolled.append(f"{node.name} (line {node.lineno})")

check("no route reads a bulk id list without _bulk_ids",
      not hand_rolled, "; ".join(hand_rolled))
check("_bulk_device_ids is a wrapper over _bulk_ids, not a second reader",
      "_bulk_ids(body, \"device_ids\")" in api_source)


# The cap, the coercion and the two "required" semantics, on the one reader.
def refusal(*args, **kwargs):
    try:
        api_mod._bulk_ids(*args, **kwargs)
    except ValueError as exc:
        return str(exc)
    return ""


check("_bulk_ids coerces to int", api_mod._bulk_ids({"a": ["1", 2]}, "a") == [1, 2])
check("a required list that is absent is refused by name",
      refusal({}, "device_ids") == "device_ids is required")
check("an optional list that is absent is an empty selection, not a refusal",
      api_mod._bulk_ids({}, "device_ids", required=False) == [])
check("the cap names the row kind, not always 'devices'",
      refusal({"alert_ids": [1, 2, 3]}, "alert_ids", cap=2, noun="alerts")
      == "Too many alerts in one request: 3, limit is 2. Send them in batches.")
check("a non-numeric entry is a 400 naming the key, not a TypeError",
      refusal({"device_ids": ["x"]}, "device_ids")
      == "device_ids must be a list of ids")
check("_id_list still tells 'not given' from an empty list",
      api_mod._id_list(None) is None and api_mod._id_list("1,2,3") == [1, 2, 3])
check("the query-string reader routes through the same capped reader",
      '_bulk_ids({"device_ids": out}, "device_ids", required=False)' in api_source)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

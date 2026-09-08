"""Settings -> Data & Retention: the storage readouts and the shape of the
rows that carry them.

showUsage() is run for real rather than pattern-matched: the two defects it
is pinned against here -- "0 B used - NaN%" for an account whose storage
block the API withheld, and a database over its cap reading exactly 100% --
were both arithmetic, and no amount of reading the source proves arithmetic.
The function is sliced out of settings.js and evaluated by node against a
DOM stub, so what runs is the shipped text. Node is the one thing here that
a machine may not have; those checks say so and are skipped rather than
failing, the way the SSH suites treat paramiko.

The rest is structure that no runtime can check: every store in the page has
a full set of spans, the store list the browser walks is the STORES table
the server drives everything else from, and the fieldset -- not each label
-- is the grid, which is what puts one column of labels beside one column of
controls instead of thirteen rows each measured against its own label.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web.service import STORES

STATIC = os.path.join(_paths.REPO_ROOT, "netpath", "web", "static")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


INDEX = read("index.html")
SETTINGS = read("settings.js")
CSS = read("app.css")

RETENTION = INDEX[INDEX.index('<div id="settings-sub-retention"'):
                  INDEX.index('<div id="settings-sub-signin"')]
USAGE = SETTINGS[SETTINGS.index("  function showUsage(storage) {"):
                 SETTINGS.index("  function status(message, colour) {")]


# --------------------------------------------- 1. every store has its row

CAPPED = [store for store in STORES if store.cap_key]

for store in STORES:
    dashed = store.name.replace("_", "-")
    check(f"{store.name}: DATA FILES carries its path, size and age",
          f'id="set-{dashed}-path"' in RETENTION
          and f'id="size-{dashed}"' in RETENTION
          and f'id="age-{dashed}"' in RETENTION)
    check(f"{store.name}: and showUsage fills all three",
          f"'size-{dashed}'" in USAGE and f"'age-{dashed}'" in USAGE)

for store in CAPPED:
    dashed = store.name.replace("_", "-")
    check(f"{store.name}: its cap row carries the meter, beside the cap box",
          f'id="set-{dashed}-cap"' in RETENTION and f'id="use-{dashed}"' in RETENTION
          and RETENTION.index(f'id="set-{dashed}-cap"') < RETENTION.index(f'id="use-{dashed}"'))
    check(f"{store.name}: and its cap setting is an Apply field",
          f"['{store.cap_key}', 'set-{dashed}-cap', 'num']" in SETTINGS)

check("the browser's store list is exactly the server's STORES, so a "
      "database added to one is not missed by the other",
      all(f"['{store.name}', 'size-" in USAGE for store in STORES)
      and len(re.findall(r"^      \['", USAGE, re.M)) == len(STORES),
      len(re.findall(r"^      \['", USAGE, re.M)))

check("an uncapped store gets no meter span at all -- a full grey track "
      "with a zero-width fill is what read as broken",
      not any(f'id="use-{s.name.replace("_", "-")}"' in RETENTION
              for s in STORES if not s.cap_key),
      [s.name for s in STORES if not s.cap_key
       and f'id="use-{s.name.replace("_", "-")}"' in RETENTION])

check("the free-space thresholds have inputs of their own, so the alert "
      "they drive can be tuned from the page it is about",
      'id="set-disk-warn"' in RETENTION and 'id="set-disk-critical"' in RETENTION
      and "['disk_free_warn_pct', 'set-disk-warn', 'num']" in SETTINGS
      and "['disk_free_critical_pct', 'set-disk-critical', 'num']" in SETTINGS)


# ------------------------------------------------------ 2. the row layout

check("the retention FIELDSET is the grid, not each label: one column set "
      "for every row is the whole point",
      "#settings-sub-retention fieldset {" in CSS
      and "#settings-sub-retention fieldset > label { display: contents; }" in CSS)
check("...and its hints and legend span the whole width rather than "
      "sitting in the label column",
      "#settings-sub-retention fieldset > p { grid-column: 1 / -1; }" in CSS)
check(".usage has no margin of its own -- it stacked on the grid's own "
      "column-gap and made the gap before a meter differ from the gap "
      "before an age",
      "margin-left: 10px" not in CSS[CSS.index(".usage {"):CSS.index(".usage .meter {")])
check("the meter is still .meter, not .bar (see its comment above the rule)",
      ".usage .meter {" in CSS and '<span class="meter">' in USAGE)


# ------------------------------------- 3. what showUsage actually renders

NODE = shutil.which("node") or shutil.which("nodejs")

HARNESS = """
'use strict';
const CAPS = %s;
const elements = {};
function stub(id) {
  if (!elements[id]) {
    elements[id] = { id, textContent: '', innerHTML: '', className: '',
                     value: CAPS[id] === undefined ? '' : String(CAPS[id]) };
  }
  return elements[id];
}
const App = {
  el: (id) => (id === null || id === undefined ? null : stub(id)),
  bytes: (n) => `${Math.round(Number(n) / 1048576)} MB`,
  ago: () => '3 days ago',
};
%s
showUsage(%s);
console.log(JSON.stringify(elements));
"""


def render(storage, caps):
    """`elements` after showUsage has run over this storage block."""
    script = HARNESS % (json.dumps(caps), USAGE, json.dumps(storage))
    folder = tempfile.mkdtemp(prefix="storage_ui_")
    try:
        path = os.path.join(folder, "run.js")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        out = subprocess.run([NODE, path], capture_output=True, text=True,
                             encoding="utf-8", timeout=60)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip()[:400])
        return json.loads(out.stdout)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


MB = 1024 * 1024
CAPS = {f"set-{s.name.replace('_', '-')}-cap": 512 for s in CAPPED}

if NODE is None:
    print("SKIP  node is not on this machine, so showUsage was not run "
          "(structure above still checked)")
else:
    # The exact shape an account without Settings read gets: _drop_unreadable
    # takes the whole storage block away and leaves the cap inputs full.
    withheld = render({}, CAPS)
    painted = json.dumps(withheld)
    check("with the storage block withheld nothing anywhere says NaN",
          "NaN" not in painted, painted[:300])
    check("...and no figure is claimed at all rather than 0 B against a "
          "real cap",
          all(not withheld[key]["textContent"] and not withheld[key]["innerHTML"]
              for key in withheld if key.startswith(("size-", "use-", "age-")))
          and not withheld["set-sizes"]["textContent"],
          {k: v for k, v in withheld.items()
           if (v["textContent"] or v["innerHTML"]) and k != "set-sizes"})

    over = render({"trace_bytes": int(512 * MB * 1.5), "trace_oldest_ts": 1,
                   "app_bytes": 3 * MB,
                   "nodes_mibs_bytes": MB, "mapper_bytes": MB,
                   "alerts_bytes": int(512 * MB * 0.5)}, CAPS)
    check("a database at 150% of its cap says 150%, not 100% -- the "
          "Dashboard's headroom tile has always said the true figure and "
          "the two disagreed",
          "150% of cap" in over["use-trace"]["innerHTML"],
          over["use-trace"]["innerHTML"])
    check("...while its BAR stops at the end of the track",
          "width:100%" in over["use-trace"]["innerHTML"],
          over["use-trace"]["innerHTML"])
    check("...and is coloured as full",
          over["use-trace"]["className"] == "usage full",
          over["use-trace"]["className"])
    check("a database at half its cap reads 50% and is not coloured",
          "50% of cap" in over["use-alerts"]["innerHTML"]
          and over["use-alerts"]["className"] == "usage",
          (over["use-alerts"]["innerHTML"], over["use-alerts"]["className"]))
    check("an uncapped store shows its size on its file row",
          over["size-app"]["textContent"] == "3 MB",
          over["size-app"]["textContent"])
    check("...and never a meter, which is what made the two uncapped rows "
          "look broken",
          "use-app" not in over and "use-nodes-mibs" not in over,
          sorted(k for k in over if k.startswith("use-")))
    check("a store that keeps no history says nothing about its age, "
          "rather than 'no history' for ever",
          over["age-nodes-mibs"]["textContent"] == ""
          and over["age-mapper"]["textContent"] == "",
          (over["age-nodes-mibs"]["textContent"], over["age-mapper"]["textContent"]))
    check("a store that keeps history and has none yet still says so",
          over["age-alerts"]["textContent"] == "no history",
          over["age-alerts"]["textContent"])
    check("...and one with history reports how far back it reaches",
          over["age-trace"]["textContent"] == "oldest record 3 days ago",
          over["age-trace"]["textContent"])
    check("the total counts every file the server reported",
          over["set-sizes"]["textContent"].startswith("1029 MB on disk in total"),
          over["set-sizes"]["textContent"][:60])

    # A cap of 0 is "no cap" everywhere else in the product; the meter has
    # to read it the same way rather than dividing by it.
    zero = render({"trace_bytes": 5 * MB}, dict(CAPS, **{"set-trace-cap": 0}))
    check("a cap of 0 renders no meter and no percentage, not Infinity",
          zero["use-trace"]["innerHTML"] == "" and "NaN" not in json.dumps(zero),
          zero["use-trace"]["innerHTML"])

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

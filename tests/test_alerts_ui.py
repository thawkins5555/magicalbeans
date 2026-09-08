"""Alerts -> Rules: the rule editor's dialog, run rather than read.

The 5.3.0 defect it is pinned against was a template nesting one -- the
flapping fields were written inside the `isThreshold` branch while Save
read them outside it, so editing the one rule with source_kind='flapping'
rendered no such fields, read null, and threw "Cannot read properties of
null" the moment Save was pressed. Reading the source is exactly what
failed to catch that, so editRule() is sliced out of alerts.js and run by
node against a DOM stub: the dialog is rendered, its boxes are typed into,
Save is pressed, and what would have reached PUT /api/alerts/rules/<id> is
asserted. Node is the one thing a machine here may not have; those checks
say so and are skipped, the way the SSH suites treat paramiko.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import _BUILTIN_RULES

STATIC = os.path.join(_paths.REPO_ROOT, "netpath", "web", "static")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


ALERTS = read("alerts.js")
APP = read("app.js")

NODE = shutil.which("node") or shutil.which("nodejs")


def run_js(script):
    folder = tempfile.mkdtemp(prefix="alerts_ui_")
    try:
        path = os.path.join(folder, "run.mjs")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        out = subprocess.run([NODE, path], capture_output=True, text=True,
                             encoding="utf-8", timeout=60)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip()[:600])
        return json.loads(out.stdout)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ===========================================================================
# 1. The rule editor (ITEM 1): the flapping rule can be edited and saved.
# ===========================================================================

# The rule the defect was reported against, taken from the shipped table
# rather than retyped -- if interface_flapping ever stops being an
# interface_event rule with source_kind='flapping', this test should stop
# claiming to cover it.
FLAPPING = next(r for r in _BUILTIN_RULES if r[0] == "interface_flapping")
check("interface_flapping is still an interface_event rule whose source_kind "
      "is 'flapping' -- the editor's isThreshold is false for it, which is "
      "the whole reason its fields may not live in that branch",
      FLAPPING[2] == "interface_event" and FLAPPING[3] == "flapping",
      (FLAPPING[2], FLAPPING[3]))

EDITOR = ALERTS[ALERTS.index("  function templateOptionsHtml("):
                ALERTS.index("  function addRule() {")]

HARNESS = """
'use strict';
const RULE = %s;
const TYPED = %s;
const view = { rules: [RULE], rulesSelected: RULE.id, templates: [],
               ruleExtras: { [String(RULE.id)]: {} } };
const escape = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');
let dialog = null;
const puts = [];
const App = {
  modal: (title, body, buttons) => { dialog = { title, body, buttons }; return {}; },
  closeModal: () => {},
  refreshNow: () => {},
  put: async (path, values) => { puts.push({ path, values }); return {}; },
  state: { severities: ['emergency', 'alert', 'critical', 'error',
                        'warning', 'notice', 'info', 'debug'] },
};

%s

/* The smallest thing that behaves like the dialog body: the fields the
   markup actually rendered, and null for every one it did not -- which is
   what querySelector returns, and the whole defect. */
function makeBox(html) {
  const nodes = {};
  const re = /<(input|select|textarea)\\b([^>]*)>/g;
  let m;
  while ((m = re.exec(html))) {
    const attrs = m[2];
    const found = /\\bid="([^"]+)"/.exec(attrs);
    if (!found) continue;
    let value = (/\\bvalue="([^"]*)"/.exec(attrs) || [])[1] || '';
    if (m[1] === 'select') {
      const tail = html.slice(m.index, html.indexOf('</select>', m.index));
      const picked = /<option value="([^"]*)"[^>]*\\bselected\\b/.exec(tail)
        || /<option value="([^"]*)"/.exec(tail);
      value = picked ? picked[1] : '';
    }
    nodes['#' + found[1]] = { value, checked: /\\bchecked\\b/.test(attrs) };
  }
  return { nodes, querySelector: (sel) => (sel in nodes ? nodes[sel] : null) };
}

editRule();
const box = makeBox(dialog.body);
/* A field that is not there is reported, not thrown: the case this suite
   exists for is a dialog missing the very boxes it is being asked about,
   and that has to arrive as a failed check rather than as a dead runner. */
let error = null;
for (const [sel, value] of Object.entries(TYPED)) {
  if (!box.nodes[sel]) { error = `the dialog never rendered ${sel}`; continue; }
  box.nodes[sel].value = value;
}
const save = dialog.buttons.find((b) => b.primary);
try {
  await save.onClick(box);
} catch (e) {
  error = error || String(e && e.message || e);
}
console.log(JSON.stringify({ fields: Object.keys(box.nodes), puts, error }));
"""


def save_rule(rule, typed=None):
    """Open the editor on `rule`, type `typed` in, press Save."""
    result = run_js(HARNESS % (json.dumps(rule), json.dumps(typed or {}), EDITOR))
    # So a Save that never happened reads as empty values rather than as an
    # IndexError two checks later.
    result["saved"] = result["puts"][0]["values"] if result["puts"] else {}
    return result


FLAP_RULE = {"id": 9, "key": "interface_flapping", "name": "Interface flapping",
             "kind": "interface_event", "source_kind": "flapping", "severity": 3,
             "enabled": 1, "device_filter": "", "template_id": None,
             "threshold": None, "clear_threshold": None, "comparison": "above",
             "for_polls": 1, "for_seconds": None,
             "flap_min_transitions": 5, "flap_window_s": 900}

CPU_RULE = {"id": 3, "key": "cpu_high", "name": "CPU utilization high",
            "kind": "threshold", "source_kind": "cpu_pct", "severity": 4,
            "enabled": 1, "device_filter": "", "template_id": None,
            "threshold": 90.0, "clear_threshold": 80.0, "comparison": "above",
            "for_polls": 2, "for_seconds": None,
            "flap_min_transitions": None, "flap_window_s": None}

if NODE is None:
    print("SKIP  node is not on this machine, so the rule editor was not run")
else:
    stored = save_rule(FLAP_RULE)
    check("editing the flapping rule and pressing Save does not throw",
          stored["error"] is None, stored["error"])
    check("...because the dialog renders the two flapping boxes for a rule "
          "whose kind is interface_event, not threshold",
          "#ar-flapcount" in stored["fields"] and "#ar-flapwindow" in stored["fields"],
          stored["fields"])
    check("...and it renders no threshold boxes for it, so the fields above "
          "are the flapping branch's own and not a stray isThreshold",
          "#ar-threshold" not in stored["fields"]
          and "#ar-forpolls" not in stored["fields"],
          stored["fields"])
    check("...and the stored numbers reach the PUT unchanged: 5 transitions, "
          "and 900 s shown as 15 minutes and sent back as 900",
          len(stored["puts"]) == 1
          and stored["puts"][0]["path"] == "/api/alerts/rules/9"
          and stored["saved"].get("flap_min_transitions") == 5
          and stored["saved"].get("flap_window_s") == 900,
          stored["saved"])

    typed = save_rule(FLAP_RULE, {"#ar-flapcount": "8", "#ar-flapwindow": "20"})
    check("a number typed into either box is what is saved -- transitions as "
          "typed, the window in MINUTES multiplied up to seconds",
          typed["error"] is None
          and typed["saved"].get("flap_min_transitions") == 8
          and typed["saved"].get("flap_window_s") == 1200,
          (typed["error"], typed["saved"]))

    cleared = save_rule(FLAP_RULE, {"#ar-flapcount": "", "#ar-flapwindow": ""})
    check("and a box cleared means NULL -- 'use the shipped defaults' -- "
          "not 0, which would be 'fire on no transitions at all'",
          cleared["error"] is None
          and cleared["saved"].get("flap_min_transitions", 0) is None
          and cleared["saved"].get("flap_window_s", 0) is None,
          (cleared["error"], cleared["saved"]))

    blank = save_rule(dict(FLAP_RULE, flap_min_transitions=None, flap_window_s=None))
    check("a rule that has never had either set opens with both boxes empty "
          "and saves them back as NULL rather than as 0",
          blank["error"] is None
          and blank["saved"].get("flap_min_transitions", 0) is None
          and blank["saved"].get("flap_window_s", 0) is None,
          (blank["error"], blank["saved"]))

    threshold = save_rule(CPU_RULE)
    check("a threshold rule still gets its own fields, and no flapping ones",
          threshold["error"] is None
          and "#ar-threshold" in threshold["fields"]
          and "#ar-flapcount" not in threshold["fields"],
          (threshold["error"], threshold["fields"]))
    check("...and saves the numbers it was opened with",
          threshold["saved"].get("threshold") == 90
          and threshold["saved"].get("clear_threshold") == 80
          and threshold["saved"].get("for_polls") == 2,
          threshold["saved"])


# ---------------------------------------------------------------------------
# 1b. The reader helpers cannot repeat this class of bug quietly.
check("App.form.readers names the field it could not find rather than "
      "reading .checked/.value off null",
      "This dialog has no field" in APP
      and not re.search(r"on: \(id\) => box\.querySelector\(id\)\.checked", APP))
check("...and it throws rather than answering with a sentinel: a false or a "
      "NaN posted for a field nobody rendered is saved silently",
      "throw new Error(`This dialog has no field" in APP)


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

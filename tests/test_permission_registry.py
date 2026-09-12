"""The four hand-kept permission registries agree with each other.

A module is gate-able because it is in permissions.MODULES, gated because
server.ROUTES names it, settings-bearing because api.SETTINGS_SCOPES names it,
and its settings apply because service._MODULE_SCOPES names it. Nothing
derives any of the four from another, so a new module is four edits and a
forgotten one is a silent hole: a route gated against a module no account can
ever be granted refuses everyone, and a settings scope missing from
SETTINGS_SCOPES falls through to the global writer (which is how a
debug:write account once rewrote the listener's bind address — see the
comment above SETTINGS_SCOPES). These checks are the derivation the code
does not do.

Imports only, no server: the four tables are module-level constants.
"""
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import permissions
from netpath.web.api import SETTINGS_SCOPES
from netpath.web.server import ROUTES
from netpath.web.service import _MODULE_SCOPES

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


MODULES = set(permissions.MODULES)

# Modules with no Settings tab section of their own: Settings is the tab that
# hosts the global settings, and debug/web/ssh/admin are capabilities rather
# than tabs (see the comments in permissions.py). Everything else in MODULES
# is a tab with settings, and must therefore own a scope.
NO_SETTINGS_SCOPE = {"settings", "debug", "web", "ssh", "admin"}

# ------------------------------------------------- ROUTES against MODULES

# permission is None, a (module, level) pair, or fn(params, body); only the
# pairs name a module statically. The callables are covered by the
# SETTINGS_SCOPES check below (_settings_requirement) and by
# test_web_security.py's live probes.
route_modules = {entry[3][0] for entry in ROUTES
                 if isinstance(entry[3], tuple)}
check(f"all {len(route_modules)} modules gated by ROUTES are in MODULES",
      not (route_modules - MODULES), sorted(route_modules - MODULES))
# The other direction: every module should be reachable through the table,
# except the two gated dynamically instead — "ssh" in the terminal handler's
# own check, and "settings", which _settings_requirement derives from
# SETTINGS_SCOPES rather than naming in a tuple.
unrouted = (MODULES - route_modules) - {"ssh", "settings"}
check("every other module is named by at least one static route",
      not unrouted, sorted(unrouted))

# -------------------------------------------- SETTINGS_SCOPES vs MODULES

scopes = set(SETTINGS_SCOPES)
check("every SETTINGS_SCOPES key is a real module",
      not (scopes - MODULES), sorted(scopes - MODULES))
expected = MODULES - NO_SETTINGS_SCOPE
check(f"all {len(expected)} settings-bearing modules have a SETTINGS_SCOPES entry",
      not (expected - scopes), sorted(expected - scopes))
check("...and SETTINGS_SCOPES claims no non-settings module",
      not (scopes & NO_SETTINGS_SCOPE), sorted(scopes & NO_SETTINGS_SCOPE))

# --------------------------------------- _MODULE_SCOPES vs SETTINGS_SCOPES

applied = set(_MODULE_SCOPES)
check("every _MODULE_SCOPES key owns a settings scope",
      not (applied - scopes), sorted(applied - scopes))
# `netpath` is the one settings-bearing module _MODULE_SCOPES does not carry:
# it writes Service.settings (the global dict) rather than a module dict of
# its own, which is exactly what SETTINGS_SCOPES["netpath"] == "settings"
# says, and it has its own apply method instead of a table row. `global` is
# not a module at all.
check('netpath is the only settings module without a _MODULE_SCOPES row',
      (scopes - applied) == {"netpath"}, sorted(scopes - applied))
check('...because its scope is the global one',
      SETTINGS_SCOPES.get("netpath") == "settings",
      SETTINGS_SCOPES.get("netpath"))

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

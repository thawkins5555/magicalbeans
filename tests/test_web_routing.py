"""server._route used to scan all of COMPILED per request; it now looks up
a bucket keyed on (method, the literal segment right after /api/) built at
import time by _route_candidates (see server.py, above COMPILED). This pins
that the bucketed lookup answers exactly what the old linear scan did, for
every route, every HTTP method, and the edge cases _route falls through on.

Imports only, no server: COMPILED/_route_candidates are module-level.
"""
import re
import sys
from urllib.parse import urlparse

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web import server
from netpath.web.server import COMPILED, ROUTES

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


METHODS = sorted({method for method, _, _, _ in ROUTES})

# The only capture-group shapes ROUTES uses today (checked in _make_path
# below); a new shape added to server.py without a sample here fails loudly
# instead of silently synthesizing a non-matching path.
GROUP_SAMPLES = {
    r"(\d+)": "123",
    r"([\w-]+)": "sample-key",
    r"(r[A-Za-z0-9_-]+)": "rSample123",
}


def _make_path(pattern_text: str) -> str:
    """A path that pattern_text (a ROUTES regex) matches, built by
    substituting each capture group with a plausible value."""
    text = pattern_text[1:-1] if pattern_text.startswith("^") and pattern_text.endswith("$") \
        else pattern_text.lstrip("^")
    for group, sample in GROUP_SAMPLES.items():
        text = text.replace(group, sample)
    remaining = re.findall(r"\([^)]*\)", text)
    assert not remaining, f"unhandled capture group(s) {remaining} in {pattern_text!r}"
    return text.replace(r"\.", ".")


def _old_scan(method: str, path: str):
    """server._route's dispatch loop before bucketing, reimplemented here
    rather than kept in server.py so nothing but this test pays for it."""
    for route_method, pattern, handler, requirement in COMPILED:
        if route_method != method:
            continue
        match = pattern.match(path)
        if match:
            return (handler, requirement, match.groups())
    return None


def _new_lookup(method: str, path: str):
    for _idx, pattern, handler, requirement in server._route_candidates(method, path):
        match = pattern.match(path)
        if match:
            return (handler, requirement, match.groups())
    return None


def _compare(label, method, path):
    old = _old_scan(method, path)
    new = _new_lookup(method, path)
    check(f"{label}: {method} {path}", old == new, (old, new))


# ---------------------------------------------------------- every route

for _method, _pattern, _handler, _requirement in ROUTES:
    path = _make_path(_pattern)
    # The route's own method, and every other method ROUTES uses (covers
    # "known path, wrong method" for free, and first-match order when two
    # patterns under the same method both match this path).
    for method in METHODS:
        _compare("route", method, path)
    _compare("trailing slash", _method, path + "/")
    # _route always matches on urlparse(...).path, with the query already
    # stripped off -- confirm a query string changes nothing once that's
    # done, the same as it changes nothing for the old scan.
    _compare("query string", _method, urlparse(path + "?v=1&x=2").path)

# ---------------------------------------------------------- edge cases

for method in METHODS:
    _compare("unknown path", method, "/api/does-not-exist")
    _compare("unknown path, no api prefix", method, "/dashboard.html")
    _compare("bare /api/", method, "/api/")

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

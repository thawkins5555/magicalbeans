"""Perf: Service._extra_resolve_targets() vs. the Resolver's own throttled
wrapper, _cached_extra_targets().

The Resolver calls its extra_ips() every poll_s (15 s) whenever its own
batch is under 40 -- the common case -- and _extra_resolve_targets() answers
that with a flow settings read plus a full ipam_db.hosts() and
nodes_db.devices() and two neighbour-table DISTINCT scans, each under that
store's lock. _cached_extra_targets() is what the Resolver is actually wired
to; it recomputes at most once per _EXTRA_TARGETS_TTL_S and is the only
thing throttled -- _extra_resolve_targets() itself must stay live, since
tests and any other direct caller expect its answer to reflect the current
database on every call.
"""
import os
import sys
import time

import _paths  # noqa: F401

from netpath.web import Service

TMPDIR = _paths.tmpdir("extra_resolve_cache_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class StatementCounter:
    def __init__(self, conn):
        self.conn = conn
        self.statements = []

    def __enter__(self):
        self.conn.set_trace_callback(self.statements.append)
        return self

    def __exit__(self, *exc):
        self.conn.set_trace_callback(None)
        return False


def make_service():
    tag = str(time.time()).replace(".", "")
    d = os.path.join(TMPDIR, tag)
    os.makedirs(d, exist_ok=True)
    return Service(
        os.path.join(d, "netpath.db"), os.path.join(d, "flows.db"),
        os.path.join(d, "syslog.db"), os.path.join(d, "app.db"),
        os.path.join(d, "ipam.db"), os.path.join(d, "snmptraps.db"),
        os.path.join(d, "nodes.db"), os.path.join(d, "alerts.db"),
        os.path.join(d, "wireless.db"), os.path.join(d, "configrx.db"))


def main():
    service = make_service()

    check("the Resolver is wired to the throttled wrapper, not the raw method",
          service.resolver.extra_ips == service._cached_extra_targets)

    # ---------------------------------------------------- throttling itself
    calls = []

    def counting():
        calls.append(1)
        return [f"10.0.0.{len(calls)}"]

    service._extra_resolve_targets = counting
    service._extra_targets_cache = None

    first = service._cached_extra_targets()
    second = service._cached_extra_targets()
    third = service._cached_extra_targets()
    check("a hit within the TTL does not recompute",
          len(calls) == 1, f"calls={len(calls)}")
    check("every caller within the TTL gets the same answer",
          first == second == third, (first, second, third))

    # Age the cache past _EXTRA_TARGETS_TTL_S without waiting for real time.
    stamp, value = service._extra_targets_cache
    service._extra_targets_cache = (
        stamp - service._EXTRA_TARGETS_TTL_S - 1, value)
    fourth = service._cached_extra_targets()
    check("a hit past the TTL recomputes",
          len(calls) == 2, f"calls={len(calls)}")
    check("...and the newly-computed value is what callers see",
          fourth == ["10.0.0.2"], fourth)

    # -------------------------------------- the raw method is never cached
    del service._extra_resolve_targets  # restore the real bound method
    service.flow_db.recent_endpoints = lambda: ["198.51.100.5"]

    service.flow_settings["resolve_addresses"] = True
    with StatementCounter(service.flow_db._conn) as counter:
        addrs = service._extra_resolve_targets()
    reads = [s for s in counter.statements if "FROM settings" in s]
    check("_extra_resolve_targets reads the live flow_settings dict, "
          "not a fresh settings query",
          not reads, f"{len(reads)} settings read(s)")
    check("...and picks up the flow endpoint while the setting is on",
          "198.51.100.5" in addrs, addrs)

    service.flow_settings["resolve_addresses"] = False
    addrs = service._extra_resolve_targets()
    check("a direct call reflects a setting flipped a moment ago, uncached",
          "198.51.100.5" not in addrs, addrs)

    # ------------------------- a settings save invalidates the cached copy
    calls = []

    def counting():
        calls.append(1)
        return []

    service._extra_resolve_targets = counting
    service._extra_targets_cache = None
    service._cached_extra_targets()
    check("warm-up: the cache is primed before the settings save",
          service._extra_targets_cache is not None and len(calls) == 1)

    service.apply_settings("netflow", {"resolve_addresses": True})
    check("saving netflow settings drops the cached extra-target set",
          service._extra_targets_cache is None)
    service._cached_extra_targets()
    check("...so the very next tick recomputes rather than waiting out the TTL",
          len(calls) == 2, f"calls={len(calls)}")

    service._cached_extra_targets()
    check("...and a save to an unrelated scope leaves a warm cache alone",
          len(calls) == 2, f"calls={len(calls)}")
    service.apply_settings("wireless", {})
    check("...(wireless does not gate _extra_resolve_targets, so it must not "
          "invalidate the cache)", service._extra_targets_cache is not None)

    # ------------- a settings save landing mid-compute must not be undone
    # _extra_resolve_targets() below plays the part of a Resolver-thread
    # compute that read the OLD settings; while it is "in flight" (here,
    # synchronously, before it returns) a settings save invalidates the
    # cache the way apply_settings does. The stale result it eventually
    # returns must not overwrite that invalidation with a fresh timestamp.
    calls = []

    def racing():
        calls.append(1)
        if len(calls) == 1:
            service._extra_targets_cache = None
            service._extra_targets_generation += 1
        return [f"race-{len(calls)}"]

    service._extra_resolve_targets = racing
    service._extra_targets_cache = None
    raced = service._cached_extra_targets()
    check("a stale in-flight compute does not overwrite a concurrent invalidation",
          service._extra_targets_cache is None, service._extra_targets_cache)
    check("...but its own caller still gets what it computed",
          raced == ["race-1"], raced)
    next_value = service._cached_extra_targets()
    check("...and the very next call recomputes and caches normally",
          next_value == ["race-2"] and service._extra_targets_cache is not None,
          (next_value, service._extra_targets_cache))

    print()
    if FAILS:
        print(f"FAILURES: {len(FAILS)}")
        for item in FAILS:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

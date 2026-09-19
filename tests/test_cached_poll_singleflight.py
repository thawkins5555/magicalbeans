"""Perf: Service.cached_poll's single-flight behaviour on a cache miss.

The old cached_poll was an unlocked read-modify-write: N HTTP threads racing
a cold or expired key all saw the miss and all ran `compute()`, for a figure
whose whole point is that it is too expensive to run on every request. This
pins that only one of them actually computes -- the rest block and reuse
that answer -- with the same TTL semantics as before, that a failed compute
is never cached and reaches its own caller, and that a key's own lock is
never held while compute() runs (so compute() re-entering cached_poll on a
different key cannot deadlock on it).
"""
import os
import sys
import threading
import time

import _paths  # noqa: F401

from netpath.web import Service

TMPDIR = _paths.tmpdir("cached_poll_singleflight_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


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


def run_threads(fn, k: int):
    results = [None] * k
    errors = [None] * k

    def run(i):
        try:
            results[i] = fn()
        except Exception as exc:
            errors[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(k)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    return results, errors


def test_stampede(service):
    calls = []
    lock = threading.Lock()

    def slow_compute():
        with lock:
            calls.append(1)
        time.sleep(0.2)
        return object()

    results, errors = run_threads(
        lambda: service.cached_poll("k_stampede", 10.0, slow_compute), 20)
    check("no thread saw an exception", all(e is None for e in errors), errors)
    check("compute() ran exactly once for 20 racing threads",
          len(calls) == 1, f"calls={len(calls)}")
    check("every thread got the same object back",
          all(r is results[0] for r in results),
          [id(r) for r in results])


def test_exception_not_cached(service):
    calls = []

    def failing_compute():
        calls.append(1)
        raise ValueError("compute is broken")

    try:
        service.cached_poll("k_fail", 10.0, failing_compute)
        raised = False
    except ValueError:
        raised = True
    check("a failing compute()'s exception reaches its own caller",
          raised)
    check("nothing was cached for a key whose only compute() failed",
          "k_fail" not in service._poll_cache)

    try:
        service.cached_poll("k_fail", 10.0, failing_compute)
        raised_again = False
    except ValueError:
        raised_again = True
    check("the next caller for that key runs compute() again, independently",
          raised_again and len(calls) == 2, f"calls={len(calls)}")

    service.cached_poll("k_fail", 10.0, lambda: "ok")
    check("a key can recover once compute() succeeds",
          service.cached_poll("k_fail", 10.0, lambda: "unused") == "ok")


def test_ttl_expiry(service):
    calls = []

    def compute():
        calls.append(1)
        return len(calls)

    first = service.cached_poll("k_ttl", 0.05, compute)
    second = service.cached_poll("k_ttl", 0.05, compute)
    check("a hit within the TTL does not recompute",
          first == second == 1, (first, second))
    time.sleep(0.1)
    third = service.cached_poll("k_ttl", 0.05, compute)
    check("a hit past the TTL recomputes",
          third == 2, third)


def test_no_deadlock_on_reentry(service):
    def inner():
        return service.cached_poll("k_inner", 10.0, lambda: "inner-value")

    outer = service.cached_poll("k_outer", 10.0, inner)
    check("compute() calling cached_poll on a different key does not deadlock",
          outer == "inner-value", outer)


def main():
    service = make_service()
    test_stampede(service)
    test_exception_not_cached(service)
    test_ttl_expiry(service)
    test_no_deadlock_on_reentry(service)

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

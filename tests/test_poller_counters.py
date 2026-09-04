"""Poller counters incremented from worker threads with proper locking.

B7 fix: counters[...] += 1 from a pool worker is a read-modify-write on a
shared dict; without the lock the totals can be wrong. The _bump method takes
the lock on each increment, so many threads bumping the same counter produces
the exact total."""
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import _paths
from _paths import tmpdir

TMPDIR = tmpdir("poller_counters_")

from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def main():
    db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
    poller = NodePoller(db)

    # Capture the original keys before bumping
    original_keys = set(poller.counters.keys())
    original_values = dict(poller.counters)

    # Run 50 threads, each calling _bump("polls") 1000 times
    num_threads = 50
    bumps_per_thread = 1000
    total_expected = num_threads * bumps_per_thread

    def bump_worker():
        for _ in range(bumps_per_thread):
            poller._bump("polls")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(bump_worker) for _ in range(num_threads)]
        for future in futures:
            future.result()

    # Check the total
    check(
        poller.counters["polls"] == total_expected,
        f"50 threads x 1000 bumps of polls == {total_expected} "
        f"(got {poller.counters['polls']})"
    )

    # Check that all original keys are still present
    current_keys = set(poller.counters.keys())
    check(
        current_keys == original_keys,
        f"all original counter keys are still present "
        f"(original: {original_keys}, current: {current_keys})"
    )

    # Check that other keys haven't been modified
    for key in original_keys:
        if key != "polls":
            check(
                poller.counters[key] == original_values[key],
                f"counter[{key}] unchanged "
                f"(was {original_values[key]}, got {poller.counters[key]})"
            )

    if FAILURES:
        print(f"\n{len(FAILURES)} test(s) failed:")
        for failure in FAILURES:
            print(f"  - {failure}")
        sys.exit(1)
    else:
        print(f"\nAll tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()

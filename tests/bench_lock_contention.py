"""Does a web read actually wait on the poller's writes, and by how much?

Deliberately not a test_*.py: it prints numbers rather than asserting them,
because what it measures depends on the disk and the core count under it.

    python3 tests/bench_lock_contention.py

The question it answers is whether each store being one SQLite connection
behind one lock -- so a read queues behind every write, although WAL would
have allowed them to run together -- costs anything at a real fleet size.
It is the measurement the read-only-connection question turns on, and the
reason that work was NOT done: at the write rate a 2,000-device fleet
actually produces, it does not.

The pacing is the whole point. An unpaced writer commits as fast as the CPU
allows -- about eleven thousand transactions a second here -- and reports a
p95 two orders of magnitude worse than the truth. A fleet of 2,000 devices
on the shipped 120-second interval commits about 17 a second. Measuring the
first and deciding from it would buy an architectural change to fix a
problem no install has.

Reads the lock instrumentation on the store directly rather than going over
HTTP, so what is measured is the contention rather than the request
plumbing around it.
"""
import os
import statistics
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)
from _paths import tmpdir

from netpath.nodesdb import NodesDatabase

DEVICES = 2000
WRITERS = 16          # a poll pool's worth of concurrent writers
SECONDS = 12.0


def main():
    db = NodesDatabase(os.path.join(tmpdir("contention_"), "nodes.db"))
    group = db.ensure_default_group()
    ids = [db.add_device("10.%d.%d.%d" % (i // 65025, (i // 255) % 255, i % 255),
                         "dev%d" % i, group_id=group)
           for i in range(DEVICES)]
    print("seeded %d devices" % DEVICES)

    stop = threading.Event()
    writes = [0]
    write_lock = threading.Lock()

    def writer(seed, rate):
        """Paced, because an unpaced writer measures an artifact, not a poller.

        A real fleet of 2,000 devices on a 120 s interval commits about 17
        record_poll transactions a second in TOTAL; `rate` is this thread's
        share. rate == 0 means unpaced, kept only to show what the ceiling
        would look like if a poller ever behaved that way.
        """
        n = 0
        interval = 1.0 / rate if rate else 0.0
        nxt = time.monotonic()
        while not stop.is_set():
            device_id = ids[(seed * 977 + n * 13) % len(ids)]
            db.record_poll(device_id, ping_ok=True, ping_rtt_ms=1.0, snmp_ok=True,
                           snmp_error="", identity=None, uptime_ticks=None,
                           status="up", reachable=True)
            n += 1
            if interval:
                nxt += interval
                delay = nxt - time.monotonic()
                if delay > 0:
                    stop.wait(delay)
                else:
                    nxt = time.monotonic()
        with write_lock:
            writes[0] += n

    def measure(label, fn, writers, total_rate):
        threads = []
        stop.clear()
        writes[0] = 0
        for i in range(writers):
            t = threading.Thread(
                target=writer,
                args=(i, total_rate / writers if (writers and total_rate) else 0),
                daemon=True)
            t.start()
            threads.append(t)
        time.sleep(0.5)                 # let the writers get going
        before = db.lock_stats()
        waits = []
        deadline = time.monotonic() + SECONDS
        reads = 0
        while time.monotonic() < deadline:
            started = time.perf_counter()
            fn()
            waits.append((time.perf_counter() - started) * 1000)
            reads += 1
        after = db.lock_stats()
        stop.set()
        for t in threads:
            t.join(timeout=5)
        waited = after["wait_s"] - before["wait_s"]
        acquired = after["acquisitions"] - before["acquisitions"]
        waits.sort()
        p95 = waits[int(len(waits) * 0.95)] if waits else 0.0
        print("  %-22s %-16s reads=%-6d p50=%6.2f ms p95=%7.2f ms "
              "max=%7.2f ms | lock wait %.1f ms over %d acquisitions (%.1f%% of read time)"
              % (label,
                 "idle" if not writers else
                 ("%d w unpaced" % writers if not total_rate
                  else "%d w @ %g/s" % (writers, total_rate)),
                 reads, statistics.median(waits), p95, max(waits),
                 waited * 1000, acquired,
                 100.0 * waited * 1000 / max(sum(waits), 1e-9)))

    print("\nweb-shaped reads against nodes.db, with and without a poller writing:")
    print("  (2,000 devices on a 120 s interval is ~17 record_poll commits a second;")
    print("   60 s is ~34; unpaced is as fast as the CPU allows, which no fleet does)")
    for label, fn in (("device_counts()", db.device_counts),
                      ("devices(limit=50)", lambda: db.devices(limit=50, offset=0))):
        for writers, rate in ((0, 0), (WRITERS, 17), (WRITERS, 34), (WRITERS, 0)):
            measure(label, fn, writers, rate)
    db.close()


if __name__ == "__main__":
    main()

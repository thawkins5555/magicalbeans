"""NodesDatabase.prune() passes series_db.prune() the fleet's fastest
effective poll interval, so the per-metric row cap can be skipped
when retention already keeps fewer rows than the cap allows. This pins that
the interval nodesdb computes is the true, conservative minimum over
enabled devices (device override, else group, else default_interval_s),
and that prune() actually threads it through.

House style: a plain script, FAILS collects failed check() names, exit 1 if
anything failed.
"""
import os
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase

TMPDIR = _paths.tmpdir("prune_fastest_interval_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ---------------------------------------------------------- no devices at all
nodes = NodesDatabase(os.path.join(TMPDIR, "empty.db"))
check("no enabled devices: None, so the cap keeps running unconditionally",
      nodes._fastest_poll_interval_s() is None, None)
nodes.close()


# --------------------------------------------------------- default only
nodes = NodesDatabase(os.path.join(TMPDIR, "default_only.db"))
gid = nodes.ensure_default_group()
nodes.add_device("10.95.0.1", "sw-1", group_id=gid)
nodes.add_device("10.95.0.2", "sw-2", group_id=gid)
check("no overrides anywhere: falls back to default_interval_s (120)",
      nodes._fastest_poll_interval_s() == 120.0, nodes._fastest_poll_interval_s())
nodes.close()


# ------------------------------------------------- device override wins
nodes = NodesDatabase(os.path.join(TMPDIR, "device_override.db"))
gid = nodes.ensure_default_group()
slow = nodes.add_device("10.95.1.1", "slow-sw", group_id=gid)
fast = nodes.add_device("10.95.1.2", "fast-sw", group_id=gid, poll_interval_s=30)
check("the fastest DEVICE override wins over the default",
      nodes._fastest_poll_interval_s() == 30.0, nodes._fastest_poll_interval_s())
nodes.close()


# --------------------------------------------------- group default, then override
nodes = NodesDatabase(os.path.join(TMPDIR, "group_default.db"))
fast_group = nodes.add_group("fast-group", poll_interval_s=60)
gid = nodes.ensure_default_group()
nodes.add_device("10.95.2.1", "default-sw", group_id=gid)
grouped = nodes.add_device("10.95.2.2", "grouped-sw", group_id=fast_group)
check("a group's own poll_interval_s beats the global default when no "
      "device override exists",
      nodes._fastest_poll_interval_s() == 60.0, nodes._fastest_poll_interval_s())
nodes.update_device(grouped, poll_interval_s=10)
check("...and a device override on top of that group still wins",
      nodes._fastest_poll_interval_s() == 10.0, nodes._fastest_poll_interval_s())
nodes.close()


# ---------------------------------------------------- disabled devices excluded
nodes = NodesDatabase(os.path.join(TMPDIR, "disabled.db"))
gid = nodes.ensure_default_group()
nodes.add_device("10.95.3.1", "normal-sw", group_id=gid)
disabled = nodes.add_device("10.95.3.2", "quarantined-sw", group_id=gid,
                            poll_interval_s=5)
nodes.update_device(disabled, enabled=0)
check("a disabled device's fast override is not counted (it is never really "
      "polled) -- falls back to the default",
      nodes._fastest_poll_interval_s() == 120.0, nodes._fastest_poll_interval_s())
nodes.close()


# ------------------------------------------ prune() actually threads it through
nodes = NodesDatabase(os.path.join(TMPDIR, "threaded.db"))
gid = nodes.ensure_default_group()
nodes.add_device("10.95.4.1", "sw-1", group_id=gid, poll_interval_s=15)

captured = {}
real_series_prune = nodes.series_db.prune


def spy_prune(**kwargs):
    captured.update(kwargs)
    return real_series_prune(**kwargs)


nodes.series_db.prune = spy_prune
try:
    nodes.prune(max_samples_per_metric=1000)
finally:
    nodes.series_db.prune = real_series_prune
check("prune() passes the fleet's fastest interval to series_db.prune()",
      captured.get("poll_interval_s") == 15.0, captured)
nodes.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

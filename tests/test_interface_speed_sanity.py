"""nodepoll's interface line-rate reading: an ifHighSpeed that cannot be the
Mbit/s the MIB says it is (a per-linecard agent quirk answering kbit/s, which
reported a 10 Gb/s port as "10.0 Tbps" and drove its utilization to ~0%) is
refused, while a genuine 400G port and ifSpeed's RFC 2863 sentinel are left
exactly as they were.

Reuses test_poller_behaviour's one-interface stub agent rather than growing a
second copy of it: the scenarios here differ only in the two speed columns."""
import os

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import tmpdir

from netpath.nodepoll import (
    IF_SPEED_SENTINEL, MAX_PLAUSIBLE_SPEED_BPS, NodePoller, interface_speed_bps,
)
import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase

from test_poller_behaviour import _OneInterfaceAgent, _force_dt, _poll_once

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------------ pure

# A 10G port on an agent answering ifHighSpeed in kbit/s: 10,000,000 instead
# of 10,000. x 1e6 is 1e13 -- "10.0 Tbps" on the map, three orders out.
# ifSpeed cannot arbitrate (any link over ~4.29 Gb/s saturates it), so the
# ceiling is the only thing standing between that reading and the database.
check("a kbit/s ifHighSpeed on a 10G port reads 10 Gb/s, not 10 Tb/s",
      interface_speed_bps(IF_SPEED_SENTINEL, 10_000_000) == 1e10,
      interface_speed_bps(IF_SPEED_SENTINEL, 10_000_000))

# The same quirk on a 1G port lands at 1e12 -- under the ceiling, so the
# ceiling alone would pass it. ifSpeed is exact below the sentinel and says
# 1e9: a factor of 1000 apart, and the device's own exact column wins.
check("a kbit/s ifHighSpeed contradicted by a non-sentinel ifSpeed loses to it",
      interface_speed_bps(1_000_000_000, 1_000_000) == 1e9,
      interface_speed_bps(1_000_000_000, 1_000_000))

check("a real 400G port is untouched",
      interface_speed_bps(IF_SPEED_SENTINEL, 400_000) == 4e11,
      interface_speed_bps(IF_SPEED_SENTINEL, 400_000))
check("a real 800G port -- the fastest shipping Ethernet -- is untouched",
      interface_speed_bps(IF_SPEED_SENTINEL, 800_000) == 8e11,
      interface_speed_bps(IF_SPEED_SENTINEL, 800_000))
check("the ceiling leaves a full doubling of headroom above 800G",
      MAX_PLAUSIBLE_SPEED_BPS >= 2 * 8e11, MAX_PLAUSIBLE_SPEED_BPS)

check("an ordinary 1G port still prefers ifHighSpeed",
      interface_speed_bps(1_000_000_000, 1000) == 1e9,
      interface_speed_bps(1_000_000_000, 1000))
check("no ifHighSpeed still falls back to the raw ifSpeed sentinel",
      interface_speed_bps(IF_SPEED_SENTINEL, None) == float(IF_SPEED_SENTINEL),
      interface_speed_bps(IF_SPEED_SENTINEL, None))
check("neither column answering leaves the speed unknown",
      interface_speed_bps(None, None) is None)


# ------------------------------------------------------------------ end to end

def _speed_and_util(prefix, *, if_speed, if_high_speed, bump_bytes):
    """Poll a stub agent twice across a known 1 s dt and return the stored
    (speed_bps, in_util_pct) for its single interface."""
    agent = _OneInterfaceAgent(if_speed=if_speed, if_high_speed=if_high_speed,
                               hc_out_answers=True)
    agent.start()
    tmp = tmpdir(prefix)
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port
    try:
        group_id = db.ensure_default_group()
        device_id = db.add_device("127.0.0.1", "speed-stub", group_id=group_id,
                                  snmp_version=1, community="public",
                                  ping_enabled=0, poll_interval_s=999,
                                  snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        _force_dt(db, device_id, 1, 1.0)
        agent.hc_in += bump_bytes
        _poll_once(poller, db, device_id)
        row = {r["if_index"]: r for r in db.interfaces(device_id)}[1]
        metrics = {m["key"]: m for m in db.metrics(device_id)}
        util = metrics.get("if_in_util_pct.1")
        return row["speed_bps"], util["last_value"] if util else None
    finally:
        agent.stop()
        db.close()


# 500 MB/s over 1 s is 4 Gb/s: 40% of a 10G port, and 0.04% of the 10 Tb/s
# the unfixed reading claimed -- the "near 0% util" half of the symptom.
speed, util = _speed_and_util("speed_quirk_10g_", if_speed=IF_SPEED_SENTINEL,
                              if_high_speed=10_000_000, bump_bytes=500_000_000)
check("end to end: the quirky 10G port stores 10 Gb/s", speed == 1e10, speed)
check("...and its utilization reads ~40%, not ~0%",
      util is not None and 38.0 < util < 42.0, util)

speed_400, util_400 = _speed_and_util("speed_real_400g_", if_speed=IF_SPEED_SENTINEL,
                                      if_high_speed=400_000, bump_bytes=500_000_000)
check("end to end: a genuine 400G port still stores 400 Gb/s",
      speed_400 == 4e11, speed_400)
check("...with a utilization to match (~1%)",
      util_400 is not None and 0.5 < util_400 < 1.5, util_400)


def main():
    print()
    if FAILS:
        print(f"{len(FAILS)} FAILURE(S): " + "; ".join(FAILS))
        raise SystemExit(1)
    print("all interface-speed checks passed")


main()

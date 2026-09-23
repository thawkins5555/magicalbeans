"""IPAM conflicts: resolve, then reopen, round-trips resolved_ts back to
NULL rather than only ever moving one way -- and both routes 404 for a
conflict id that was never opened."""
import os

import _paths  # noqa: F401

from netpath.ipamdb import IpamDatabase
from netpath.web import api
from netpath.web.api._shared import NotFound

TMP = _paths.tmpdir("ipam_conflict_reopen_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


ipam = IpamDatabase(os.path.join(TMP, "ipam.db"))
ipam.record_conflict("10.20.3.42", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "scan")
conflict_id = ipam.conflicts()[0]["id"]


class Service:
    ipam_db = ipam


service = Service()

api.post_ipam_conflict_resolve(service, {}, None, conflict_id)
check("resolve marks the conflict resolved",
      ipam.conflict(conflict_id)["resolved_ts"] is not None)
check("...and it drops out of the open list",
      not ipam.conflicts())

api.post_ipam_conflict_reopen(service, {}, None, conflict_id)
check("reopen clears resolved_ts",
      ipam.conflict(conflict_id)["resolved_ts"] is None)
check("...and it is back in the open list",
      [row["id"] for row in ipam.conflicts()] == [conflict_id])

for name, fn in (("resolve", api.post_ipam_conflict_resolve),
                  ("reopen", api.post_ipam_conflict_reopen)):
    try:
        fn(service, {}, None, conflict_id + 999)
        check(f"{name} 404s for an unknown conflict id", False)
    except NotFound:
        check(f"{name} 404s for an unknown conflict id", True)

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

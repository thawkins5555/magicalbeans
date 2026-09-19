"""get_wireless_aps used to call wireless_db.radios_for(ap_id) once per AP
(the classic N+1). radios_for_aps batches it; this pins that the batched
grouping is identical to the old per-AP loop, in the same per-AP order, and
that the route's own JSON is unaffected -- plus a query-count proof."""
import os
import sys
import types

import _paths
from _paths import tmpdir

TMPDIR = tmpdir("wireless_aps_batch_")

from netpath.wirelessdb import WirelessDatabase
from netpath.web.api import wireless as wireless_api

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


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


def _radio(radio_id, **fields):
    return {"radio_id": radio_id, **fields}


def main():
    db = WirelessDatabase(os.path.join(TMPDIR, "wireless.db"))
    controller_id = db.add_controller("Controller", "127.0.0.1",
                                      snmp_version=1, community="public")

    ap_ids = []
    for i in range(5):
        ap_id = db.upsert_ap(controller_id, f"AP{i:04d}", "root",
                             name=f"ap-{i}", status="online")
        ap_ids.append(ap_id)
        # Radios inserted out of radio_id order, so a batch query that forgot
        # ORDER BY would show it.
        db.replace_radios(ap_id, [_radio(2, channel="6"), _radio(1, channel="1")])
    # One AP with no radios at all -- radios_for_aps must still list it, empty.
    bare_id = db.upsert_ap(controller_id, "AP9999", "root", name="bare",
                           status="online")
    ap_ids.append(bare_id)

    # ------------------------------------- batched grouping matches the old loop

    old_by_ap = {ap_id: db.radios_for(ap_id) for ap_id in ap_ids}
    with StatementCounter(db._conn) as counter:
        new_by_ap = db.radios_for_aps(ap_ids)
    reads = [s for s in counter.statements if "FROM radios" in s]
    check(len(reads) == 1,
          f"radios_for_aps reads the radios table once for {len(ap_ids)} APs, "
          f"not once per AP (got {len(reads)} read(s))")
    for ap_id in ap_ids:
        old_ids = [r["radio_id"] for r in old_by_ap[ap_id]]
        new_ids = [r["radio_id"] for r in new_by_ap[ap_id]]
        check(new_ids == old_ids,
              f"ap {ap_id}: batched radio order {new_ids} matches "
              f"radios_for's own order {old_ids}")
    check(new_by_ap[bare_id] == [],
          "an AP with no radios still gets an (empty) entry")

    # --------------------------------------------- the route's JSON is unaffected

    service = types.SimpleNamespace(wireless_db=db, wireless_settings={})
    aps = db.access_points(controller_id=controller_id)
    old_json = [wireless_api._ap_json(service, r, db.radios_for(r["id"]))
               for r in aps]
    result = wireless_api.get_wireless_aps(service, {}, {})
    check(result["aps"] == old_json,
          "get_wireless_aps' batched result matches the old per-AP _ap_json path")

    db.close()

    print()
    if FAILURES:
        print(f"FAILURES: {len(FAILURES)}")
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

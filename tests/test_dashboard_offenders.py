"""'Most interface events (24 h)' dashboard tile: port transitions land in
interface_events (link_up/link_down, interface_id keyed), not device_events,
so the offender list needs its own query — count_interface_events_by_device
— joined through `interfaces` back to a device. Covers the NodesDB query
directly and the api list builder that feeds the tile.
"""
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase
from netpath.web import api as api_mod

TMPDIR = _paths.tmpdir("dashboard_offenders_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class _StubService:
    def __init__(self, nodes_db):
        self.nodes_db = nodes_db


def main():
    nodes = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
    device_id = nodes.add_device("10.0.0.1", "sw1")
    result = nodes.replace_interfaces(device_id, [{"if_index": 1, "descr": "Gi0/1"}])
    interface_id = result["ids"][1]

    since = time.time() - 3600
    nodes.record_interface_event(interface_id, "link_down")
    nodes.record_interface_event(interface_id, "link_up")
    nodes.record_interface_event(interface_id, "link_down")

    rows = nodes.count_interface_events_by_device(since)
    check("count_interface_events_by_device returns one device", len(rows) == 1, rows)
    if rows:
        check("device_id matches", rows[0]["device_id"] == device_id)
        check("n counts all three events", rows[0]["n"] == 3, rows[0]["n"])

    head, _tail = api_mod._offender_node_lists(_StubService(nodes), since, 10)
    interface_events_list = next(
        (entry for entry in head if entry["key"] == "interface_events"), None)
    check("interface_events list present", interface_events_list is not None)
    if interface_events_list is not None:
        check("interface_events list is non-empty",
              len(interface_events_list["rows"]) == 1, interface_events_list["rows"])

    print(f"\n{len(FAILS)} failing" if FAILS else "\nAll checks passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

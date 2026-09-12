"""Four store- and API-level fixes from the 5.11.0 review, each pinned by the
thing that was wrong rather than by the code that is now right:

  * ipamdb.conflicts() paged unstably over rows a single scan stamped with the
    same last_seen_ts;
  * an upgraded nodes.db carried the pre-5.10.0 `detail_fields` default, so
    the software version and image lines never appeared on any install that
    had ever opened Nodes -> Settings;
  * the neighbours pane resolved every unmanaged neighbour's address with its
    own queries -- 400 neighbours were 1,200 statements per request, on a pane
    the browser re-reads every tick;
  * the mute audit trail named a device+rule pair as one opaque string and
    threw away the device id the handler had already worked out.

Stores and handlers directly: none of these needs a socket, and three of them
are about how many statements reach SQLite.
"""
import os
import shutil
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import DEFAULTS as NODE_DEFAULTS, NodesDatabase

TMPDIR = _paths.tmpdir("review_fixes_f3_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


try:
    # -------------------------------------------------- conflicts() tie order
    #
    # One scan opens every conflict it finds inside the same second, so
    # `ORDER BY last_seen_ts DESC` alone left SQLite free to return the tied
    # rows in any order it liked -- and a caller paging over the list could
    # see one row twice and miss another entirely.
    ipam = IpamDatabase(os.path.join(TMPDIR, "ipam.db"))
    for index in range(12):
        ipam.record_conflict(f"198.51.100.{index}", "aa:bb:cc:00:00:01",
                             "aa:bb:cc:00:00:02", "scan")
    tied = time.time()
    with sqlite3.connect(ipam.path) as fixture:
        fixture.execute("UPDATE conflicts SET last_seen_ts = ?", (tied,))

    first = [row["id"] for row in ipam.conflicts()]
    check("every conflict in the fixture is tied on last_seen_ts",
          len({row["last_seen_ts"] for row in ipam.conflicts()}) == 1)
    check("conflicts() orders tied rows by id, newest first",
          first == sorted(first, reverse=True), first)
    check("...and the same question asked again gets the same answer",
          [row["id"] for row in ipam.conflicts()] == first)
    with_resolved = [row["id"] for row in ipam.conflicts(include_resolved=True)]
    check("...and include_resolved=True is ordered the same way",
          with_resolved == sorted(with_resolved, reverse=True), with_resolved)

    # Both halves of the list are still reachable across a page boundary:
    # the top 6 and the next 6 together are every row, each exactly once.
    page_one, page_two = first[:6], first[6:]
    check("paging over the tie sees each conflict exactly once",
          sorted(page_one + page_two) == sorted({*page_one, *page_two})
          and len(page_one + page_two) == 12, (page_one, page_two))
    ipam.close()

    # ----------------------------------------- detail_fields after an upgrade
    #
    # 5.10.0 widened this default to add the software version and image lines.
    # A stored value beats a default, so every install that had ever saved
    # Nodes -> Settings kept the old three-field string and never saw either
    # new line: the feature shipped invisible to exactly the configured
    # installs.
    OLD = "sys_descr,vendor,snmp_version"
    NEW = NODE_DEFAULTS["detail_fields"]
    check("the shipped default still carries both 5.10.0 lines",
          "sw_version" in NEW and "sw_image" in NEW, NEW)

    def open_nodes(name, stored=None, seen_migration=True):
        """A nodes.db with `stored` already in its settings table, opened the
        way the application opens it. `seen_migration=False` reproduces an
        install upgrading for the first time."""
        path = os.path.join(TMPDIR, name)
        if stored is not None:
            db = NodesDatabase(path)
            db.close()
            with sqlite3.connect(path) as fixture:
                fixture.execute(
                    "INSERT OR REPLACE INTO settings(key, value) VALUES"
                    " ('detail_fields', ?)", ('"%s"' % stored,))
                if not seen_migration:
                    fixture.execute("DELETE FROM settings WHERE key = ?",
                                    (NodesDatabase._DETAIL_FIELDS_MIGRATED,))
        return NodesDatabase(path)

    fresh = NodesDatabase(os.path.join(TMPDIR, "nodes-fresh.db"))
    check("a fresh install gets the 5.10.0 field list",
          fresh.settings()["detail_fields"] == NEW,
          fresh.settings()["detail_fields"])
    fresh.close()

    upgraded = open_nodes("nodes-upgraded.db", OLD, seen_migration=False)
    check("an install carrying the pre-5.10.0 default is rewritten to the new "
          "one on open",
          upgraded.settings()["detail_fields"] == NEW,
          upgraded.settings()["detail_fields"])
    upgraded.close()

    custom = open_nodes("nodes-custom.db", "vendor,location",
                        seen_migration=False)
    check("...while a list the operator chose is left exactly as it is",
          custom.settings()["detail_fields"] == "vendor,location",
          custom.settings()["detail_fields"])
    custom.close()

    # And it is a ONE-TIME rewrite: an operator who later picks those same
    # three fields keeps them through the next restart.
    rechosen = open_nodes("nodes-rechosen.db", OLD)
    check("an operator who picks those three fields after the upgrade keeps "
          "them",
          rechosen.settings()["detail_fields"] == OLD,
          rechosen.settings()["detail_fields"])
    rechosen.close()

    # ------------------------------------- one read for a pane of neighbours
    nodes = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
    group_id = nodes.ensure_default_group()
    switch = nodes.add_device("198.51.100.1", name="core-sw", group_id=group_id)
    aliased = nodes.add_device("198.51.100.2", name="dist-sw", group_id=group_id)
    nodes.record_device_addresses(aliased, ["203.0.113.9"], "arp")

    hits = nodes.devices_by_addresses(
        ["198.51.100.1", "203.0.113.9", "192.0.2.77", ""])
    check("devices_by_addresses finds a device by its primary address",
          hits.get("198.51.100.1") is not None
          and hits["198.51.100.1"]["id"] == switch, sorted(hits))
    check("...and by an address it is merely known to own",
          hits.get("203.0.113.9") is not None
          and hits["203.0.113.9"]["id"] == aliased, sorted(hits))
    check("...and an address that names nothing is simply absent",
          "192.0.2.77" not in hits and "" not in hits, sorted(hits))
    check("an empty request asks nothing", nodes.devices_by_addresses([]) == {})

    # The point of the method: the statement count does not grow with the
    # number of addresses. Counted at the connection, which is where the cost
    # actually lands.
    statements = []
    nodes._conn.set_trace_callback(statements.append)
    try:
        many = [f"192.0.2.{n}" for n in range(1, 51)] + ["198.51.100.1",
                                                         "203.0.113.9"]
        found = nodes.devices_by_addresses(many)
    finally:
        nodes._conn.set_trace_callback(None)
    check("52 addresses are three statements, not one per address",
          len(statements) <= 3, (len(statements), statements[:4]))
    check("...and it still finds both devices among them",
          sorted(found) == ["198.51.100.1", "203.0.113.9"], sorted(found))

    # The neighbours pane itself, through the API helper the route calls.
    from netpath.web import api as web_api

    class _Service:
        nodes_db = nodes

        class app_db:
            @staticmethod
            def hostnames(ips):
                return {}

    neighbors = [{"matched_device_id": None, "matched_device_name": "",
                  "resolved_name": "", "resolved_source": "",
                  "chassis_id": f"192.0.2.{n}", "remote_address": f"192.0.2.{n}",
                  "sys_name": ""} for n in range(1, 51)]
    neighbors.append({"matched_device_id": None, "matched_device_name": "",
                      "resolved_name": "", "resolved_source": "",
                      "chassis_id": "198.51.100.1",
                      "remote_address": "198.51.100.1", "sys_name": ""})
    statements = []
    nodes._conn.set_trace_callback(statements.append)
    try:
        web_api._resolve_neighbor_names(_Service, neighbors)
    finally:
        nodes._conn.set_trace_callback(None)
    check("51 unmanaged neighbours cost a small constant number of nodes.db "
          "statements, not three or four each",
          len(statements) <= 4, (len(statements), statements[:4]))
    check("...and the one neighbour that IS a managed device is still matched",
          neighbors[-1]["matched_device_id"] == switch
          and neighbors[-1]["resolved_source"] == "nodes", neighbors[-1])
    check("...while the other fifty are left unresolved, as before",
          all(n["matched_device_id"] is None for n in neighbors[:-1]))
    nodes.close()

    # ------------------------------------ the mute audit names the device id
    #
    # A per-rule mute's entity_id is the device and the rule key joined, so
    # the audit target alone did not say which device had been silenced --
    # in the one log that exists to answer exactly that. The handler already
    # had the id and threw it away.
    import inspect

    mute_source = inspect.getsource(web_api.post_alerts_mute)
    unmute_source = inspect.getsource(web_api.delete_alerts_mute)
    check("post_alerts_mute uses the device id _mute_entity returns",
          "_device_id" not in mute_source and "device {device_id}" in mute_source,
          mute_source)
    check("...and so does delete_alerts_mute",
          "_device_id" not in unmute_source
          and "device {device_id}" in unmute_source, unmute_source)
finally:
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)

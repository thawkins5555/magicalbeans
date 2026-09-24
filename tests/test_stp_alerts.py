"""Spanning-tree topology alerts (5.38.0): the interface events
nodesdb.update_interface_stp records when a port moves into or out of a
blocked state, the two built-in rules that read them, and the STP note the
poller puts on an ordinary link event for a port that was blocked.

Events, not a new table: a blocked uplink coming back is the same kind of
statement link_up makes, so it travels the channel the alert engine
already drains (alertengine._drain_interface_events).
"""
from _paths import tmpdir

TMP = tmpdir("stp_alerts_")

from netpath import alertrules
from netpath.alertsdb import _BUILTIN_RULES
from netpath.nodesdb import NodesDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


db = NodesDatabase(f"{TMP}/stp_alerts.db")
did = db.add_device("10.0.0.1", name="core-sw")
db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi1/0/1"},
                            {"if_index": 2, "descr": "Gi1/0/2"},
                            {"if_index": 3, "descr": "Gi1/0/3"}])
interface_id = {row["if_index"]: row["id"] for row in db.interfaces(did)}


def events(if_index):
    return [dict(row) for row in db.interface_events(interface_id[if_index])]


# --- first reading: a state arriving where none was stored is not a change
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "forwarding"},
                              {"if_index": 2, "stp_state": "blocking"}])
check("the first STP reading of a port records no event -- nothing changed, "
      "the port was simply never read before",
      events(1) == [] and events(2) == [], (events(1), events(2)))

# --- forwarding -> blocking
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "blocking"}])
blocked = events(1)
check("a port moving into blocking records one stp_blocking event",
      len(blocked) == 1 and blocked[0]["kind"] == "stp_blocking", blocked)
check("...whose detail names the port and both states",
      "Gi1/0/1" in blocked[0]["detail"]
      and "forwarding -> blocking" in blocked[0]["detail"], blocked[0])

# --- the same state again
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "blocking"}])
check("a poll that reads the same state again records nothing",
      len(events(1)) == 1, events(1))

# --- blocking -> forwarding
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "forwarding"}])
unblocked = events(1)
check("a port leaving blocking for forwarding records stp_unblocked",
      len(unblocked) == 2 and unblocked[0]["kind"] == "stp_unblocked",
      unblocked)

# --- a change between two states that are both "not blocked"
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "listening"}])
check("listening is a port coming up, not spanning tree holding it down, "
      "so forwarding -> listening records nothing",
      len(events(1)) == 2, events(1))
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "disabled"}])
check("...and neither does a port being disabled",
      len(events(1)) == 2, events(1))

# --- the per-VLAN detail rides along when there is one
db.update_interface_stp(did, [{"if_index": 1, "stp_state": "blocking",
                               "stp_blocking_vlans": "30,40"}])
check("a blocking event names the VLANs blocking on that port, where the "
      "per-VLAN read supplied them",
      "VLAN 30,40" in events(1)[0]["detail"], events(1)[0])

# --- RSTP's own spelling
db.update_interface_stp(did, [{"if_index": 2, "stp_state": "forwarding"}])
check("discarding counts as blocked, so an agent using RSTP's spelling "
      "raises and clears the same pair",
      [row["kind"] for row in events(2)] == ["stp_unblocked"], events(2))

# --- broken(6): a port errored out of forwarding is blocked too (5.62.0)
db.update_interface_stp(did, [{"if_index": 3, "stp_state": "forwarding"}])
db.update_interface_stp(did, [{"if_index": 3, "stp_state": "broken"}])
check("broken counts as blocked, so forwarding -> broken raises stp_blocking",
      [row["kind"] for row in events(3)] == ["stp_blocking"], events(3))
db.update_interface_stp(did, [{"if_index": 3, "stp_state": "forwarding"}])
check("...and broken -> forwarding clears it with stp_unblocked",
      [row["kind"] for row in events(3)] == ["stp_unblocked", "stp_blocking"],
      events(3))
db.close()

# --- the rules that read those events
rules = {row[0]: row for row in _BUILTIN_RULES}
check("a built-in rule reads stp_blocking as an interface event",
      rules["stp_blocking"][2:5] == ("interface_event", "stp_blocking", 4),
      rules.get("stp_blocking"))
check("...and its quieter counterpart reads stp_unblocked",
      rules["stp_unblocked"][2:5] == ("interface_event", "stp_unblocked", 6),
      rules.get("stp_unblocked"))
check("unblocking CLEARS the blocking alert, the pairing link_up makes "
      "with interface_down",
      alertrules.CLEARS[("interface_event", "stp_unblocked")] == "stp_blocking",
      alertrules.CLEARS.get(("interface_event", "stp_unblocked")))

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

import atexit
import os
import sys
import time

from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("timeout_accuracy_")

import netpath.nodepoll as nodepoll_mod
# The stub answers the system-group GET but drops every GETNEXT for the
# ifIndex table, so the identity lands and the table walk times out.
stub, STUB_PORT = spawn_stub("stub_agent_partial_timeout.py")
atexit.register(stub.kill)
nodepoll_mod.DEFAULT_SNMP_PORT = STUB_PORT

from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.eventlog import EventLog, NODES

nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
group_id = nodes_db.ensure_default_group()
device_id = nodes_db.add_device(
    "127.0.0.1", name="timeout-test", group_id=group_id,
    snmp_version=1, community="public", snmp_timeout_s=0.5, snmp_retries=1)

log = EventLog()
poller = NodePoller(nodes_db, log=log)

device = nodes_db.device(device_id)
config = nodes_db.effective_config(device)
started = time.time()
poller._poll_device(device, config)
elapsed = time.time() - started
print(f"poll took {elapsed:.2f}s")

device = nodes_db.device(device_id)
print(f"status={device['status']!r} snmp_ok={device['snmp_ok']!r} "
     f"snmp_error={device['snmp_error']!r}")
print(f"sys_name={device['sys_name']!r} (identity should still have been captured)")

assert device["sys_name"] == "timeout-stub-device", \
    "identity from the successful scalar GET should still be recorded"
assert device["snmp_ok"] == 0, "snmp_ok should be false: the ifIndex walk genuinely timed out"
assert "timed" in device["snmp_error"].lower() or "reply" in device["snmp_error"].lower(), \
    device["snmp_error"]
assert "cut short" in device["snmp_error"], \
    f"error text should mention the walk was cut short, got: {device['snmp_error']!r}"
print("PASS: genuine mid-walk timeout is now reported, not silently swallowed")

events = log.all()
node_events = [e for e in events if e.category == NODES]
print(f"{len(node_events)} NODES-category event(s) logged: "
     f"{[e.message for e in node_events]}")

nodes_db.close()
print("ALL TIMEOUT-ACCURACY ASSERTIONS PASSED")

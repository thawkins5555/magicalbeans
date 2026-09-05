"""mem_pct's new HOST-RESOURCES-MIB fallback (hrStorageRam), and the shared
hrStorageTable walk it now shares with disk_pct.

The gap: a Windows host, a printer, or most appliances answer none of
UCD-SNMP, a Fortinet scalar or the Cisco memory pool -- the only three
sources mem_pct ever had -- so a device correctly identified as `microsoft`
still reported cpu_pct and disk_pct (both already covered by HOST-RESOURCES-
MIB) and NO mem_pct at all, on a live 250-device campaign. hrStorageRam sits
in the exact table disk_pct already walks for hrStorageFixedDisk, so this is
new arithmetic on data the poller was already paying for -- not a new
request.

Three things this suite has to prove:
  1. mem_pct is produced for a device that answers none of the three
     existing sources, using hrStorageRam, and correctly EXCLUDES
     hrStorageVirtualMemory (deliberately given the worst-looking
     percentage in the fixture, so an accidental inclusion cannot pass by
     coincidence) the same way disk_pct already excludes it.
  2. hrStorageType/Size/Used is walked ONCE per poll for both disk_pct and
     mem_pct together, not once each -- the whole point of using data
     "already being walked" rather than adding a second walk beside it.
  3. A device with no HOST-RESOURCES-MIB support at all still reports
     nothing for any of the three metrics, rather than erroring.
"""
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("hr_mem_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def stub_stat(port: int, command: bytes) -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(command, ("127.0.0.1", port))
    try:
        return s.recv(256).decode("utf-8", "replace")
    finally:
        s.close()


def request_count(port: int) -> int:
    return int(stub_stat(port, b"STATS"))


def reset_count(port: int) -> None:
    stub_stat(port, b"RESET")


def device_against(db: NodesDatabase, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


# ---------------------------------------------------- a Windows-class host

stub, port = spawn_stub("stub_agent_host_resources.py", "windows")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("windows")
    did = device_against(db, "win-host-1")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, _uptime, _metrics = poller._poll_snmp_scalars(device, config)
    check("the device identifies as Microsoft (enterprise arc 311), which "
          "VENDOR_HEALTH has no entry for -- the generic fallback is what "
          "has to answer this device",
          identity.get("vendor_arc") == 311, identity)

    metrics = poller._poll_vendor_health(device, config, identity, already=set())
    values = {key: value for key, label, unit, kind, value in metrics}
    check("cpu_pct from hrProcessorLoad, averaged across both CPUs "
          "((30+40)/2 = 35.0)",
          values.get("cpu_pct") == 35.0, values)
    check("disk_pct from the hrStorageFixedDisk row alone (20%), not the "
          "worse-looking RAM or virtual-memory rows",
          values.get("disk_pct") == 20.0, values)
    check("mem_pct -- new -- from the hrStorageRam row alone (75%)",
          values.get("mem_pct") == 75.0, values)
    check("the 95%-used hrStorageVirtualMemory row is excluded from BOTH "
          "mem_pct and disk_pct, not just one of them",
          values.get("mem_pct") != 95.0 and values.get("disk_pct") != 95.0,
          values)

    # The request-count proof that hrStorageTable is walked ONCE for both
    # metrics: a lone call to the shared walk costs some number of
    # requests; _poll_vendor_health, which needs BOTH disk_pct and mem_pct
    # this poll, must cost roughly that same number again (the CPU walk is
    # the only other thing it does here) -- not twice as much, which is
    # what walking the table separately for each metric would cost.
    reset_count(port)
    types, sizes, used = poller._host_resources_storage_rows(device, config)
    check("the shared walk actually found the three storage rows",
          len(types) == 3, types)
    lone_walk_requests = request_count(port)

    reset_count(port)
    poller._poll_vendor_health(device, config, identity, already=set())
    full_requests = request_count(port)
    check(f"hrStorageTable is walked once for the whole poll, not once per "
          f"metric (one storage walk costs {lone_walk_requests} request(s); "
          f"the full poll, which also needs the separate CPU walk, cost "
          f"{full_requests})",
          lone_walk_requests < full_requests < 2 * lone_walk_requests,
          (lone_walk_requests, full_requests))
    db.close()
finally:
    stub.kill()

# --------------------------------------------- a device with no HOST-RESOURCES

stub, port = spawn_stub("stub_agent_host_resources.py", "no_hr")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("no_hr")
    did = device_against(db, "no-hr-device")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, _uptime, _metrics = poller._poll_snmp_scalars(device, config)
    metrics = poller._poll_vendor_health(device, config, identity, already=set())
    values = {key: value for key, label, unit, kind, value in metrics}
    check("a device with no HOST-RESOURCES-MIB support reports none of "
          "cpu_pct/disk_pct/mem_pct, rather than raising",
          "cpu_pct" not in values and "disk_pct" not in values
          and "mem_pct" not in values, values)
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

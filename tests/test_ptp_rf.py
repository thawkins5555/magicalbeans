"""PtP wireless RF metrics (Tier 1 #8): RSSI/SNR/capacity/remote-RSSI for
Ubiquiti airFiber and Cambium PTP, read via nodepoll._poll_rf_metrics and
stored through the ordinary metric-samples path so history/series charts
work for free; a non-radio vendor arc never sends a single packet for it;
wired end to end through _poll_snmp_scalars."""
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("ptp_rf_")

import netpath.nodepoll as nodepoll_mod
import netpath.nodeoids as nodeoids
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, port: int, name: str) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid)


# ------------------------------------------------------------- airFiber
stub, port = spawn_stub("stub_agent_l2.py", "airfiber")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("airfiber")
    did = device_against(db, port, "af-radio")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity = {"vendor_arc": 41112}
    metrics = poller._poll_rf_metrics(device, config, identity)
    got = {key: value for key, _label, _unit, _kind, value in metrics}
    check("airFiber's RSSI/SNR/capacity/remote-RSSI are all read",
          got == {"rf_rssi_dbm": -58.0, "rf_snr_db": 28.0,
                  "rf_capacity_bps": 700_000_000.0, "rf_remote_rssi_dbm": -61.0},
          got)

    # Wired end to end: a full scalar poll (which runs the identity read
    # AND the RF read together) stores the same numbers as ordinary
    # samples, current value included.
    identity2, _uptime, metrics2 = poller._poll_snmp_scalars(device, config)
    check("the vendor arc identified from sysObjectID gates the same walk",
          identity2.get("vendor_arc") == 41112, identity2.get("vendor_arc"))
    db.record_metric_samples(did, [
        (key, label, unit, kind, time.time(), value)
        for key, label, unit, kind, value in metrics2])
    stored = {m["key"]: m["last_value"] for m in db.metrics(did)}
    check("_poll_snmp_scalars' own RF read matches _poll_rf_metrics directly",
          stored.get("rf_rssi_dbm") == -58.0 and stored.get("rf_snr_db") == 28.0,
          stored)
    db.close()
finally:
    stub.kill()

# -------------------------------------------------------------- Cambium
stub, port = spawn_stub("stub_agent_l2.py", "cambium")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cambium")
    did = device_against(db, port, "cambium-radio")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity = {"vendor_arc": 17713}
    metrics = poller._poll_rf_metrics(device, config, identity)
    got = {key: value for key, _label, _unit, _kind, value in metrics}
    check("Cambium's receive level/path loss/capacity/vector error are all read",
          got == {"rf_rx_level_dbm": -52.0, "rf_path_loss_db": 112.0,
                  "rf_capacity_bps": 320_000_000.0, "rf_vector_error_db": -31.0},
          got)
    db.close()
finally:
    stub.kill()

# ---------------------------------------------------- non-radio: never walked
db = new_db("no_radio")
did = db.add_device("10.0.0.90", name="core-router",
                    group_id=db.ensure_default_group())
poller = NodePoller(db)
device = db.device(did)
config = db.effective_config(device)
# arc 9 (Cisco) has no RF_METRICS entry: this must return [] WITHOUT sending
# a single SNMP request — proven by there being no stub agent listening on
# this device's address at all, so any attempt would raise SnmpTimeout.
metrics = poller._poll_rf_metrics(device, config, {"vendor_arc": 9})
check("a non-radio vendor arc is never walked (no RF_METRICS entry, no request sent)",
      metrics == [], metrics)
check("RF_METRICS itself only names the two radio arcs this plan covers",
      set(nodeoids.RF_METRICS) == {41112, 17713}, set(nodeoids.RF_METRICS))
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

"""End-to-end DiscoveryJob test — plan section 6.4 — against the same stub
UDP agent used by test_nodepoll_e2e.py, plus a real loopback ping sweep."""
import os
import sys
import tempfile
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

import test_nodepoll_e2e as t
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.ipam_scan import SubnetTooLarge
import netpath.nodediscover as nodediscover_mod
from netpath.web import api as web_api


def main():
    tmp = tempfile.mkdtemp(prefix="nodes_disc_e2e_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))

    agent = t.StubAgent()
    agent.start()
    time.sleep(0.1)
    nodediscover_mod.DEFAULT_SNMP_PORT = agent.port

    poller = NodePoller(db)

    # --- device-kind discovery against the stub agent. Since discovery
    # picks a polling profile, the profile's v1/v2c communities arrive as
    # the discovery_communities override (api._discovery_communities_for_group)
    # and there is no fallback guess: without it no SNMP is attempted.
    job_id = poller.start_discovery("device", "127.0.0.1",
                                    overrides={"default_snmp_timeout_s": 1.0,
                                               "discovery_communities": "public"})
    for _ in range(50):
        job = db.discovery_job(job_id)
        if job["state"] != "running":
            break
        time.sleep(0.1)
    job = db.discovery_job(job_id)
    assert job["state"] == "done", job["state"]
    results = db.discovery_results(job_id)
    assert len(results) == 1, results
    result = results[0]
    assert result["snmp_ok"] == 1, "stub agent should have answered SNMP"
    assert result["sys_name"] == "stub-agent", result["sys_name"]
    assert result["vendor"] == "" or isinstance(result["vendor"], str)
    print("device-kind discovery: identified stub agent OK")

    # --- promote it into a real device
    device_ids = poller.promote(job_id, [result["id"]])
    assert len(device_ids) == 1
    device = db.device(device_ids[0])
    assert device["ip"] == "127.0.0.1"
    # promote() leaves the manual name as the IP on purpose (the display
    # name prefers sys_name on its own, so a later rename is not shadowed)
    # and seeds the identity instead.
    assert device["name"] == "127.0.0.1", device["name"]
    assert device["sys_name"] == "stub-agent", device["sys_name"]
    print("promote: device created from discovery result OK")

    # --- promoting the same result again is a no-op, not a duplicate error
    device_ids_2 = poller.promote(job_id, [result["id"]])
    assert device_ids_2 == device_ids
    assert db.device_count() == 1, "re-promoting must not create a duplicate device"
    print("promote: re-promoting the same result is idempotent OK")

    # --- a device already added independently (127.0.0.1, promoted above)
    # is found again by a fresh discovery job. The result must carry
    # existing_device_id/name (api._discovery_result_json, built from a
    # single ip->device map the way get_nodes_discovery_job does it) rather
    # than looking like a brand new find, and promoting it must resolve to
    # the existing device rather than creating a duplicate row.
    job_id_existing = poller.start_discovery("device", "127.0.0.1",
                                    overrides={"default_snmp_timeout_s": 1.0,
                                               "discovery_communities": "public"})
    for _ in range(50):
        job = db.discovery_job(job_id_existing)
        if job["state"] != "running":
            break
        time.sleep(0.1)
    job = db.discovery_job(job_id_existing)
    assert job["state"] == "done", job["state"]
    results_existing = db.discovery_results(job_id_existing)
    assert len(results_existing) == 1, results_existing
    result_existing = results_existing[0]
    assert result_existing["promoted_device_id"] is None

    device_by_ip = {d["ip"]: d for d in db.devices()}
    result_json = web_api._discovery_result_json(result_existing, device_by_ip=device_by_ip)
    assert result_json["existing_device_id"] == device_ids[0], result_json
    assert result_json["existing_device_name"] == device["name"], result_json
    print("_discovery_result_json: an already-added IP carries existing_device_id OK")

    before_count = db.device_count()
    device_ids_existing = poller.promote(job_id_existing, [result_existing["id"]])
    assert device_ids_existing == [device_ids[0]], device_ids_existing
    assert db.device_count() == before_count, \
        "promoting an already-monitored IP must not create a new device"
    print("promote: an independently-added IP resolves to the existing device, no duplicate OK")

    # --- subnet-kind discovery: a tiny real loopback-only subnet
    job_id2 = poller.start_discovery("subnet", "127.0.0.0/30",
                                     overrides={"default_snmp_timeout_s": 0.5,
                                               "max_scan_addresses": 1024,
                                               "discovery_communities": "public"})
    for _ in range(100):
        job = db.discovery_job(job_id2)
        if job["state"] != "running":
            break
        time.sleep(0.1)
    job = db.discovery_job(job_id2)
    assert job["state"] == "done", job["state"]
    assert job["total"] == 2, job["total"]  # /30 -> 2 usable addresses
    print(f"subnet-kind discovery: probed={job['probed']} responded={job['responded']} "
         f"identified={job['identified']} OK")

    # --- an oversized subnet must be refused before any packet is sent
    job_id3 = poller.start_discovery("subnet", "10.0.0.0/8",
                                     overrides={"max_scan_addresses": 1024})
    for _ in range(50):
        job = db.discovery_job(job_id3)
        if job["state"] != "running":
            break
        time.sleep(0.05)
    job = db.discovery_job(job_id3)
    assert job["state"] == "error", job["state"]
    assert "usable addresses" in (job["error"] or ""), job["error"]
    print("oversized subnet correctly refused with SubnetTooLarge OK")

    # --- cancellation mid-sweep. This sandbox has no `ping` binary at all
    # (confirmed: `which ping` finds nothing), so a real ping sweep always
    # reports every address dead and a subnet job would skip SNMP
    # entirely and finish instantly — nothing to cancel. Fake the ping
    # phase as all-alive so the SNMP phase (against the now-dark stub
    # agent, so every attempt times out) actually takes long enough to
    # cancel mid-flight, exercising the real code under test either way.
    # **kwargs: the real sweep() also takes probes_per_second and
    # never_scan, and this stand-in must not care which of them the caller
    # passes.
    nodediscover_mod.sweep = lambda addresses, timeout_ms=800, workers=64, **kw: {
        ip: True for ip in addresses}
    agent.alive = False  # every SNMP attempt now times out
    job_id4 = poller.start_discovery("subnet", "127.0.0.0/28",
                                     overrides={"default_snmp_timeout_s": 2.0,
                                               "max_scan_addresses": 1024,
                                               "discovery_communities": "public"})
    time.sleep(0.05)
    poller.cancel_discovery(job_id4)
    for _ in range(100):
        job = db.discovery_job(job_id4)
        if job["state"] != "running":
            break
        time.sleep(0.1)
    job = db.discovery_job(job_id4)
    assert job["state"] == "cancelled", job["state"]
    print("mid-sweep cancellation honoured OK")

    poller.shutdown()
    agent.stop()
    db.close()
    print("\nALL DISCOVERY END-TO-END TESTS PASSED")


if __name__ == "__main__":
    main()

import atexit
import os

from _paths import spawn_stub, tmpdir

from netpath.wirelessdb import WirelessDatabase  # noqa: E402
from netpath.fortipoll import WirelessPoller  # noqa: E402
import netpath.fortipoll as fortipoll_mod  # noqa: E402

DB_PATH = os.path.join(tmpdir("wireless_poller_"), "wireless.db")
# Two FortiAPs with their radios, served over v2c GETNEXT on a free port.
stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py")
atexit.register(stub.kill)

db = WirelessDatabase(DB_PATH)
controller_id = db.add_controller("Test Controller", "127.0.0.1", snmp_version=1,
                                  community="public")

poller = WirelessPoller(db)
controller = db.controller(controller_id)

poller._poll_controller(dict(controller))

aps = db.access_points(controller_id)
print(f"{len(aps)} AP(s) found")
for ap in aps:
    radios = db.radios_for(ap["id"])
    print(f"  {ap['wtp_id']}: name={ap['name']!r} status={ap['status']} "
         f"model={ap['model']} mac={ap['mac_address']} clients={ap['station_count']} "
         f"radios={len(radios)}")
    for r in radios:
        print(f"    radio {r['radio_id']}: channel={r['channel']} "
             f"power={r['operating_power_dbm']}dBm clients={r['station_count']}")

controller_row = db.controller(controller_id)
print(f"last_poll_ok={controller_row['last_poll_ok']} error={controller_row['last_poll_error']!r}")

assert len(aps) == 2, f"expected 2 APs, got {len(aps)}"
by_wtp = {ap["wtp_id"]: ap for ap in aps}
assert by_wtp["AP0001"]["name"] == "Lobby-AP"
assert by_wtp["AP0001"]["status"] == "online"
assert by_wtp["AP0001"]["mac_address"] == "00:11:93:00:aa:bb"
assert by_wtp["AP0001"]["model"] == "FAP231F"
assert by_wtp["AP0001"]["station_count"] == 14
assert by_wtp["AP0002"]["status"] == "offline"
lobby_radios = {r["radio_id"]: r for r in db.radios_for(by_wtp["AP0001"]["id"])}
assert len(lobby_radios) == 2
assert lobby_radios["1"]["channel"] == "6"
assert lobby_radios["1"]["operating_power_dbm"] == 17
assert lobby_radios["2"]["operating_power_dbm"] == 14
assert controller_row["last_poll_ok"] == 1
print("ALL ASSERTIONS PASSED")
db.close()

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
    print(f"    ip={ap['ip']} profile={ap['profile']} "
         f"uptime_ticks={ap['uptime_ticks']} session={ap['session_uptime_ticks']}")
    for r in radios:
        print(f"    radio {r['radio_id']}: channel={r['channel']} mode={r['mode']} "
             f"power={r['operating_power_dbm']}dBm clients={r['station_count']} "
             f"bssid={r['bssid']} width={r['channel_width']}")

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
# The columns the stub used not to serve at all, which is what let the poller
# walk past them unnoticed: IP, radio mode, uptime, profile, BSSID, width.
assert by_wtp["AP0001"]["ip"] == "127.0.0.1"
assert by_wtp["AP0002"]["ip"] == "10.20.30.42"
assert by_wtp["AP0001"]["uptime_ticks"] == 1_234_500
assert by_wtp["AP0001"]["session_uptime_ticks"] == 120_000
assert by_wtp["AP0001"]["uptime_ts"], "uptime_ts is stamped with the reading"
assert by_wtp["AP0001"]["profile"] == "FAP231F-default"
lobby_radios = {r["radio_id"]: r for r in db.radios_for(by_wtp["AP0001"]["id"])}
assert len(lobby_radios) == 2
assert lobby_radios["1"]["channel"] == "6"
assert lobby_radios["1"]["operating_power_dbm"] == 17
assert lobby_radios["2"]["operating_power_dbm"] == 14
assert lobby_radios["1"]["mode"] == "ap"
assert lobby_radios["1"]["bssid"] == "00:11:93:00:aa:c0"
assert lobby_radios["2"]["bssid"] == "00:11:93:00:aa:c1"
# Joined out of fgWcWtpProfileRadioTable by (vdom, profile, radio id).
assert lobby_radios["1"]["channel_width"] == "20 MHz"
assert lobby_radios["2"]["channel_width"] == "80 MHz"
warehouse_radios = {r["radio_id"]: r for r in db.radios_for(by_wtp["AP0002"]["id"])}
assert warehouse_radios["1"]["mode"] == "monitor"
assert warehouse_radios["1"]["channel_width"] == "40 MHz"
assert controller_row["last_poll_ok"] == 1
print("ALL ASSERTIONS PASSED")
db.close()

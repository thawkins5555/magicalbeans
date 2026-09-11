"""Radio channel/mode changes and AP reboots, end to end through the stub
controller. Nothing new is polled for either: the channel and mode columns
were already walked, and the reboot is read from the AP uptime column B1
added, so both are a diff against what the previous poll stored.

The stub is started with a mutation file; rewriting it between polls is how
the controller "changes its mind" about a channel or an uptime."""
import atexit
import os
import sys

from _paths import spawn_stub, tmpdir

from netpath.wirelessdb import WirelessDatabase  # noqa: E402
from netpath.fortipoll import WirelessPoller  # noqa: E402
import netpath.fortipoll as fortipoll_mod  # noqa: E402

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


WORK = tmpdir("wireless_events_")
STATE = os.path.join(WORK, "stub-state.txt")
open(STATE, "w", encoding="utf-8").close()

stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py", STATE)
atexit.register(stub.kill)

db = WirelessDatabase(os.path.join(WORK, "wireless.db"))
controller_id = db.add_controller("Test Controller", "127.0.0.1", snmp_version=1,
                                  community="public")
poller = WirelessPoller(db)


def poll():
    poller._poll_controller(dict(db.controller(controller_id)))


def mutate(text: str) -> None:
    with open(STATE, "w", encoding="utf-8") as handle:
        handle.write(text)


def events(kind: str, after_id: int = 0):
    return [row for row in db.ap_events_since(after_id) if row["kind"] == kind]


# ------------------------------------------------- 1. first poll is silent

poll()
check(not events("radio_channel_changed"),
      "the first sighting of an AP raises no radio_channel_changed "
      f"({len(events('radio_channel_changed'))} rows)")
check(not events("ap_rebooted"),
      f"…and no ap_rebooted ({len(events('ap_rebooted'))} rows)")

# ------------------------------------------- 2. an unchanged poll is silent

mark = db.max_ap_event_id()
poll()
check(not events("radio_channel_changed", mark),
      "a second poll that reports the same channels raises nothing")

# -------------------------------------------------- 3. the channel changes

mark = db.max_ap_event_id()
mutate("AP0001.2.channel=149\n")
poll()
changed = events("radio_channel_changed", mark)
details = [row["detail"] for row in changed]
print(f"  details: {details}")
check(len(changed) == 1,
      f"a changed channel raises exactly one radio_channel_changed ({len(changed)})")
check(changed and changed[0]["detail"] == "radio 2: channel 44 → 149",
      f"…naming the radio and both channels ({details})")
check(changed and changed[0]["wtp_id"] == "AP0001" and changed[0]["name"] == "Lobby-AP",
      "…carrying the AP the Alerts engine keys its dedup on")

# ------------------------------------------------------ 4. the mode changes

mark = db.max_ap_event_id()
mutate("AP0001.2.channel=149\nAP0001.1.mode=4\n")
poll()
changed = events("radio_channel_changed", mark)
details = [row["detail"] for row in changed]
check(len(changed) == 1 and details == ["radio 1: mode ap → monitor"],
      f"a mode flip raises one event of the same kind ({details})")

# ------------------------------------------------ 5. a radio that goes dark

BASE = "AP0001.2.channel=149\nAP0001.1.mode=4\n"

mark = db.max_ap_event_id()
mutate(BASE + "AP0002.1.channel=-1\n")
poll()
print(f"  going dark: {[r['detail'] for r in events('radio_channel_changed', mark)]}")
check(not events("radio_channel_changed", mark),
      "a radio that stops answering the channel column raises nothing "
      "— it is not a channel change")

mark = db.max_ap_event_id()
mutate(BASE + "AP0002.1.channel=36\n")
poll()
print(f"  coming back: {[r['detail'] for r in events('radio_channel_changed', mark)]}")
check(not events("radio_channel_changed", mark),
      "…and neither does its first channel after that (no '— → 36')")

# -------------------------------------------------------- 6. an AP reboots

mark = db.max_ap_event_id()
mutate(BASE + "AP0002.1.channel=36\n"
       "AP0001.uptime=25000\nAP0001.session_uptime=20000\n")
poll()
rebooted = events("ap_rebooted", mark)
print(f"  reboot: {[r['detail'] for r in rebooted]}")
check(len(rebooted) == 1, f"an uptime that fell raises one ap_rebooted ({len(rebooted)})")
check(rebooted and "03:25:45" in rebooted[0]["detail"]
      and "00:04:10" in rebooted[0]["detail"],
      f"…with both uptimes formatted as ticks, not as raw numbers "
      f"({[r['detail'] for r in rebooted]})")
check(rebooted and rebooted[0]["wtp_id"] == "AP0001",
      "…against the AP that rebooted")

mark = db.max_ap_event_id()
poll()
check(not events("ap_rebooted", mark),
      "a poll where the uptime keeps climbing raises nothing")

db.close()
print()
if FAILURES:
    print(f"FAILURES: {len(FAILURES)}")
    for item in FAILURES:
        print("  - " + item)
    sys.exit(1)
print("FAILURES: none")
print("ALL ASSERTIONS PASSED")

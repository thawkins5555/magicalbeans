"""The four faults behind "SNMP polling is failing to Palo Alto firewalls
after confirming L3 connectivity and correct SNMP v2c community string",
against tests/stubs/stub_agent_iftable.py's `palo_alto` mode.

  1. a mid-walk timeout failed the whole device rather than degrading its
     interface data, so a chassis with several hundred interfaces behind a
     3 s x 3 budget read as an SNMP failure with sysDescr populated;
  2. a walk error-status other than tooBig ended the walk silently, so a
     device whose ifTable answers genErr read as healthy with zero
     interfaces and an empty snmp_error;
  3. the GETBULK -> GETNEXT fallback was forgotten between walks, so an
     agent that refuses every GETBULK re-paid a wasted round trip on every
     column of every poll;
  4. the community was neither trimmed nor checked, so a pasted trailing
     space went on the wire verbatim and a comma-separated pair made
     discovery succeed and polling time out -- and a net-snmp agent drops a
     wrong-community datagram in silence, so both present as unreachable.

Plus the diagnostics that make the next occurrence self-explaining: the
Test button's real ifIndex walk, and _Session.dropped.
"""
import json
import os
import socket
import time

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase, clean_community
from netpath.nodepoll import NodePoller
from netpath.web import api

TMP = tmpdir("palo_alto_")
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class CaptureLog:
    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append(message)


class FakeService:
    """Just enough of web.Service for post_nodes_device_test: it reads
    nodes_db and nothing else."""

    def __init__(self, nodes_db):
        self.nodes_db = nodes_db


def _comma_error(fn, *args) -> bool:
    """Whether calling `fn` refuses a comma-bearing community by name."""
    try:
        fn(*args)
    except Exception as exc:
        return "comma" in str(exc)
    return False


def new_db(name: str, **overrides) -> tuple:
    db = NodesDatabase(os.path.join(TMP, f"{name}.db"))
    group_id = db.ensure_default_group()
    db.update_group(group_id, snmp_version=1, community="public",
                    ping_enabled=0, snmp_timeout_s=1.0, snmp_retries=0,
                    poll_interval_s=999)
    device_id = db.add_device("127.0.0.1", name, group_id=group_id, **overrides)
    return db, device_id


def poll_once(poller: NodePoller, db: NodesDatabase, device_id: int) -> None:
    device = db.device(device_id)
    poller._poll_device(device, db.effective_config(device))


def stub_counts(path: str) -> dict:
    with open(path) as handle:
        return json.load(handle)


# ============================== § 1 a mid-walk timeout degrades, not fails

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "400", "--reply-delay", "0.02",
                        "--dark-after-rows", "40")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, device_id = new_db("slow_walk")
    # Interfaces this poll will never reach: they must survive it.
    db.replace_interfaces(device_id, [{"if_index": 1, "descr": "ethernet1/1"},
                                      {"if_index": 399, "descr": "ethernet1/399"}])
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, device_id)
    row = db.device(device_id)

    check("a poll whose interface walk ran out of budget keeps snmp_ok "
          "true -- the scalars answered, so SNMP is not what failed",
          bool(row["snmp_ok"]), dict(row)["snmp_ok"])
    check("...and the device is not marked down",
          row["status"] != "down", row["status"])
    check("...and sysDescr is stored, which is what made the reported "
          "device look healthy and broken at the same time",
          "Palo Alto" in (row["sys_descr"] or ""), row["sys_descr"])
    check("...and snmp_error names what happened",
          bool(row["snmp_error"]), repr(row["snmp_error"]))
    stored = {r["if_index"] for r in db.interfaces(device_id)}
    check("...and the interfaces the walk never reached are still there: "
          "a walk cut short is not evidence of absence",
          399 in stored, sorted(stored)[:5])
    check("...and the incompleteness is logged",
          any("incomplete" in line for line in poller.log.lines),
          poller.log.lines[-3:])
    db.close()
finally:
    stub.kill()

# --- but a device that goes away entirely must still read as a failure ----

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "400", "--gen-err", IF_INDEX)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    # genErr on the ifIndex column: the agent IS answering, so this is a
    # degrade -- but with a reason, which is § 2 below. The "gone away"
    # boundary is proven separately, without a stub, in § 1b.
    db, device_id = new_db("gen_err")
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, device_id)
    row = db.device(device_id)
    check("an ifTable answered genErr no longer ends the walk in silence: "
          "the reason reaches the device row",
          "genErr" in (row["snmp_error"] or ""), repr(row["snmp_error"]))
    check("...naming the status rather than numbering it",
          "5" in (row["snmp_error"] or ""), repr(row["snmp_error"]))
    check("...and the device really did come back with zero interfaces, "
          "which is the reading that used to carry no explanation at all",
          db.interfaces(device_id) == [], db.interfaces(device_id))
    db.close()
finally:
    stub.kill()

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "8", "--no-such-name", IF_INDEX)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, device_id = new_db("no_such_name")
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, device_id)
    row = db.device(device_id)
    check("noSuchName reaches the device row the same way",
          "noSuchName" in (row["snmp_error"] or ""), repr(row["snmp_error"]))
    db.close()
finally:
    stub.kill()

# --- § 1b the boundary: nothing at all, and the device is gone ------------

stub, port = spawn_stub("stub_agent_iftable.py", "dark_after_walk",
                        "--interfaces", "2", "--dark-after", "0")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    # dark_after_walk answers the scalars and then stops answering GETs.
    # Its ifIndex walk still answers, so to get the "nothing at all" case
    # the walk is driven directly against a port nothing is listening on.
    db, device_id = new_db("gone_away")
    poller = NodePoller(db)
    device = db.device(device_id)
    config = db.effective_config(device)
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()
    nodepoll_mod.DEFAULT_SNMP_PORT = dead_port
    raised = ""
    try:
        poller._poll_interfaces(device, config)
    except Exception as exc:
        raised = f"{type(exc).__name__}: {exc}"
    check("an ifIndex walk that got NOTHING at all still raises -- a "
          "device that has gone away must not read as healthy",
          "SnmpTimeout" in raised, raised or "<nothing raised>")
    nodepoll_mod.DEFAULT_SNMP_PORT = port
    db.close()
finally:
    stub.kill()

# ================================= § 3 the GETBULK -> GETNEXT fallback

stats = os.path.join(TMP, "refuse_bulk.json")
stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "6", "--refuse-bulk",
                        "--stats", stats)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, device_id = new_db("refuse_bulk")
    db.update_group(db.ensure_default_group(), snmp_version=1)
    # v2c, so GETBULK is on the table at all.
    db.update_device(device_id, snmp_version=1)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poll_once(poller, db, device_id)
    first = stub_counts(stats)
    poll_once(poller, db, device_id)
    second = stub_counts(stats)
    refused_in_second = second["bulk_refused"] - first["bulk_refused"]
    check("an agent that refuses every GETBULK is asked with GETBULK on "
          "the first poll -- that is how the fallback is learned",
          first["bulk_refused"] >= 1, first)
    check("...and NOT again on the second: the fallback itself is "
          "remembered, not just the repetition count that failed",
          refused_in_second == 0, second)
    check("...and the interfaces still come back over GETNEXT",
          len(db.interfaces(device_id)) == 6,
          [r["if_index"] for r in db.interfaces(device_id)])
    db.close()
finally:
    stub.kill()

# ============================== § 4 the community: trimmed, comma refused

trim_db, trim_device = new_db("community")
try:
    trim_db.update_device(trim_device, community="  pa-ro  ")
    check("a community is trimmed on save, so a pasted trailing space is "
          "not transmitted verbatim to an agent that drops it in silence",
          trim_db.device(trim_device)["community"] == "pa-ro",
          repr(trim_db.device(trim_device)["community"]))

    refused = ""
    try:
        trim_db.update_device(trim_device, community="public,pa-ro")
    except ValueError as exc:
        refused = str(exc)
    check("a comma is refused rather than transmitted whole",
          "comma" in refused, refused or "<accepted>")
    check("...and the message points at the profile credential alternates, "
          "which is where several communities actually belong",
          "credential" in refused.lower(), refused)
    check("...and the refusal did not change the stored value",
          trim_db.device(trim_device)["community"] == "pa-ro",
          repr(trim_db.device(trim_device)["community"]))

    group_refused = ""
    try:
        trim_db.update_group(trim_db.ensure_default_group(),
                             community="public,pa-ro")
    except ValueError as exc:
        group_refused = str(exc)
    check("a profile's own community is refused the same way",
          "comma" in group_refused, group_refused or "<accepted>")

    cred_refused = ""
    try:
        trim_db.add_group_credential(trim_db.ensure_default_group(),
                                     label="alt", community="a,b")
    except ValueError as exc:
        cred_refused = str(exc)
    check("and so is a profile credential alternate's",
          "comma" in cred_refused, cred_refused or "<accepted>")
    check("clean_community trims without a database at all",
          clean_community(" public\t") == "public",
          repr(clean_community(" public\t")))
finally:
    trim_db.close()

# --- discovery and polling agree over the same stored value ---------------

from netpath.nodediscover import _candidate_communities  # noqa: E402
from netpath.nodepoll import credential_for  # noqa: E402

check("discovery's own split of a single stored community is the identity "
      "-- with the comma refused at save there is nothing left to disagree "
      "about",
      _candidate_communities("pa-ro") == ["pa-ro"],
      _candidate_communities("pa-ro"))
check("...and the poller resolves that same value to the same string",
      credential_for({"snmp_version": 1, "community": "pa-ro"})[0] == "pa-ro")
check("a community stored BEFORE the save-time check (an upgraded "
      "database) is refused at poll time with the same explanation "
      "instead of being sent and timing out",
      _comma_error(credential_for, {"snmp_version": 1,
                                    "community": "public,pa-ro"}))
check("and a legacy trailing space is stripped on the way to the wire",
      credential_for({"snmp_version": 1, "community": "pa-ro "})[0] == "pa-ro",
      repr(credential_for({"snmp_version": 1, "community": "pa-ro "})[0]))

# ================================= § 5 the Test button, and dropped

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "40", "--bulk-cap", "3",
                        "--stale-id", "3")
nodepoll_mod.DEFAULT_SNMP_PORT = port
api_module_port = port
try:
    db, device_id = new_db("test_button")
    service = FakeService(db)
    result = api.post_nodes_device_test(service, {}, {}, device_id)
    check("the Test button still reports ping and snmp the way it did",
          result["snmp"]["ok"] is True and "sys_descr" in result["snmp"],
          result["snmp"])
    phases = [p["name"] for p in result["snmp"].get("phases", [])]
    check("...and now reports a phase per stage, with the ifIndex walk "
          "among them -- six scalars alone reported OK on every one of the "
          "mechanisms above",
          phases == ["scalars", "ifIndex walk"], phases)
    check("...with a timing for each",
          bool(result["snmp"].get("phases"))
          and all(isinstance(p.get("ms"), float)
                  for p in result["snmp"]["phases"]),
          result["snmp"].get("phases"))
    walk = result["snmp"].get("walk") or {}
    check("...the walk actually walked the ifIndex column",
          walk.get("rows") == 40, walk)
    check("...and reports the repetition count the agent accepted",
          walk.get("max_repetitions", 0) > 0, walk)
    check("...and the error-status it got back",
          walk.get("error_status") == 0, walk)
    check("a non-zero dropped count is surfaced: replies that arrived and "
          "were rejected are a credential/duplicate-responder problem, not "
          "the firewall a bare timeout suggests",
          result["snmp"].get("dropped", 0) > 0, result["snmp"].get("dropped"))
    db.close()
finally:
    stub.kill()

# --- the walk phase reports the error-status, which is the whole point ----

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "8", "--gen-err", IF_INDEX)
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, device_id = new_db("test_button_generr")
    result = api.post_nodes_device_test(FakeService(db), {}, {}, device_id)
    walk = result["snmp"].get("walk") or {}
    check("the Test button reports genErr from the ifIndex walk, on a "
          "device whose scalars answer perfectly",
          walk.get("error_status_name") == "genErr", walk)
    check("...while the scalar phase still says ok, which is exactly the "
          "device that used to test clean and poll empty",
          result["snmp"]["ok"] is True, result["snmp"])
    db.close()
finally:
    stub.kill()

# ============================== § 6 the whole PA-shaped stub, end to end

stub, port = spawn_stub("stub_agent_iftable.py", "palo_alto",
                        "--interfaces", "300", "--bulk-cap", "5")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db, device_id = new_db("end_to_end")
    poller = NodePoller(db)
    poller.log = CaptureLog()
    poller._INTERFACE_BUDGET_FLOOR_S = 60.0
    poll_once(poller, db, device_id)
    row = db.device(device_id)
    interfaces = db.interfaces(device_id)
    check("a PA-shaped agent -- 300 interfaces, a truncating GETBULK, a "
          "sysObjectID under 1.3.6.1.4.1.25461 -- polls to snmp_ok",
          bool(row["snmp_ok"]), dict(row))
    check("...with every interface read",
          len(interfaces) == 300, len(interfaces))
    check("...and no error, because nothing went wrong",
          not row["snmp_error"], repr(row["snmp_error"]))
    check("...and the vendor arc identified",
          (row["sys_object_id"] or "").startswith("1.3.6.1.4.1.25461"),
          row["sys_object_id"])
    db.close()
finally:
    stub.kill()

print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

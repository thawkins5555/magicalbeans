"""Per-port media from ENTITY-MIB, and the optic that is dark rather than
failing (5.2.0).

Covers: _poll_environment resolving interfaces.media to 'optic' (DOM rows
present), 'sfp' (a cage holding a transceiver that reports no DOM at all)
and 'sfp_empty' (a cage with nothing in it) from entPhysicalClass, and
leaving a copper port an agent happens to model as container+port unbadged;
a multi-lane optic whose dark lane must not win the worst-of away from its
healthy one; an optic dark on every lane still recording the floor so the
port's chart keeps its continuity; alertrules.breaches refusing to alert on
that floor for the two optic power rules and nothing else; and
evaluate_threshold closing an alert already open on a port that goes dark.
"""
import time

from _paths import spawn_stub, tmpdir

import netpath.nodepoll as nodepoll_mod
from netpath.alertrules import (DARK_OPTIC_DBM, breaches, evaluate_threshold,
                               is_dark_optic)
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

TMP = tmpdir("sfp_media_")

FAILS = []

PORTS = [{"if_index": 1, "descr": "GigabitEthernet1/0/1"},
         {"if_index": 2, "descr": "GigabitEthernet1/0/2"},
         {"if_index": 3, "descr": "GigabitEthernet1/0/3"},
         {"if_index": 4, "descr": "GigabitEthernet1/0/4"},
         {"if_index": 5, "descr": "GigabitEthernet1/0/5"},
         {"if_index": 6, "descr": "GigabitEthernet1/0/6"}]


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_nodes_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, name: str) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid)


def rule(source_kind, threshold, clear_threshold, comparison):
    """The columns breaches() and evaluate_threshold() read off a rule row,
    as the plain dict alertrules' own contract says a caller may pass."""
    return {"source_kind": source_kind, "threshold": threshold,
            "clear_threshold": clear_threshold, "comparison": comparison,
            "for_polls": 1}


# ================================================ § 1 media from the walk

stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("media")
    did = device_against(db, "media-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}

    check("a port with DOM readings is 'optic' -- sensors outrank anything "
          "the entity table says about the cage they sit in",
          media.get(1) == "optic", media)
    check("a cage holding a transceiver that reports no DOM is 'sfp': the "
          "slot is identified even though nothing measurable is in it",
          media.get(2) == "sfp", media)
    check("a cage with nothing in it is 'sfp_empty', told apart from the "
          "occupied one only by what it contains",
          media.get(3) == "sfp_empty", media)
    check("a copper port the agent also models as container+port names no "
          "transceiver anywhere and stays unbadged",
          media.get(4) is None, media)
    db.close()
finally:
    stub.kill()

# --- a walk that answered nothing must never clear a badge ---------------
stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("media_keep")
    did = device_against(db, "quiet-sw")
    db.replace_interfaces(did, PORTS[:2])
    db.update_interface_media(did, [{"if_index": 1, "media": "sfp"},
                                    {"if_index": 2, "media": "sfp_empty"}])
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    media = {r["if_index"]: r["media"] for r in db.interfaces(did)}
    check("the new media kinds are kept through a walk that answered "
          "nothing, exactly as 'optic' already was",
          media == {1: "sfp", 2: "sfp_empty"}, media)
    db.close()
finally:
    stub.kill()

# ============================================== § 2 the dark optic's value

stub, port = spawn_stub("stub_agent_ups_env.py", "sfp_media")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("dark")
    did = device_against(db, "dark-sw")
    db.replace_interfaces(did, PORTS)
    poller = NodePoller(db)
    device = db.device(did)
    poller._poll_environment(did, device, db.effective_config(device), set(),
                             time.time())
    metrics = {m["key"]: m["last_value"] for m in db.metrics(did)}

    check("a healthy single-lane optic is recorded as it reads",
          metrics.get("sfp_rx_dbm.1") == -5.5, sorted(metrics))
    check("the dark lane of a two-lane optic does not win the worst-of: the "
          "healthy lane at -6 is what the port reports, not the -40",
          metrics.get("sfp_rx_dbm.5") == -6.0, metrics.get("sfp_rx_dbm.5"))
    check("an optic dark on every lane still records the floor, so the "
          "port's chart keeps its continuity and its history stays true",
          metrics.get("sfp_rx_dbm.6") == DARK_OPTIC_DBM,
          metrics.get("sfp_rx_dbm.6"))
    db.close()
finally:
    stub.kill()

# ======================================= § 3 what the floor may not alert

rx_low = rule("sfp_rx_dbm", -22.0, -20.0, "below")
tx_low = rule("sfp_tx_dbm", -12.0, -10.0, "below")

check("-25 dBm is a genuinely failing optic and still breaches",
      breaches(rx_low, -25.0))
check("-40 dBm raises nothing: the port is powered down or has no fiber "
      "in it, which is not a fault to alert on",
      not breaches(rx_low, -40.0))
check("...and the transmit rule is guarded the same way",
      not breaches(tx_low, -40.0) and breaches(tx_low, -15.0))
check("a reading just above the floor is still refused -- vendors do not "
      "all clamp to exactly -40.00",
      not breaches(rx_low, -39.8))
check("a 0 is an agent saying 'no light' in milliwatts, not a strong "
      "signal, and is refused too",
      not breaches(rx_low, 0.0))

# The guard is keyed off the rule's metric family, so nothing else can
# inherit it -- a 'below' rule on any other metric is untouched.
other_low = rule("ping_loss_pct", -22.0, -20.0, "below")
check("another 'below' rule reading -40 breaches as it always did: the "
      "guard is keyed to the two optic power families, not to the value",
      breaches(other_low, -40.0))
check("a rule row with no source_kind column at all (an older row, or a "
      "test's own dict) still evaluates rather than raising",
      breaches({"threshold": -22.0, "comparison": "below"}, -25.0))

check("is_dark_optic answers only for the optic power families",
      is_dark_optic("sfp_rx_dbm", -40.0) and is_dark_optic("sfp_tx_dbm", -40.0)
      and not is_dark_optic("sfp_temp_c", -40.0)
      and not is_dark_optic("sfp_volt", 0.0))
check("a non-finite reading is dark: an agent with no answer to give must "
      "not become an alert either",
      is_dark_optic("sfp_rx_dbm", float("-inf"))
      and is_dark_optic("sfp_rx_dbm", float("nan")))

# ==================================== § 4 what the floor has to close down

# breaches() refusing to open an alert says nothing about one already open:
# the sample is fresh every poll, so threshold_stale_s never expires it, and
# without a verdict of its own the row sits there for ever showing the -25
# that raised it.
check("-25 dBm opens the alert, as it did before",
      evaluate_threshold(rx_low, -25.0, 1) == "breach")
check("the optic going dark closes it: a port with no light is "
      "interface_down's business, not a low-light state",
      evaluate_threshold(rx_low, -40.0, 0) == "clear")
check("...and the transmit rule closes the same way",
      evaluate_threshold(tx_low, -40.0, 0) == "clear")
check("a reading just above the floor closes it too, on the same tolerance "
      "breaches() refuses to open on",
      evaluate_threshold(rx_low, -39.8, 0) == "clear")
check("a genuinely dim optic is untouched: -25 is still a breach, and the "
      "hysteresis gap still says nothing",
      evaluate_threshold(rx_low, -21.0, 3) == "")
check("another 'below' rule reading -40 is unaffected -- it breaches, and "
      "the dark verdict is keyed to the optic power families",
      evaluate_threshold(other_low, -40.0, 1) == "breach")

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

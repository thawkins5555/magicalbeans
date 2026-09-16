"""Cisco power-trap decoding: the six ENVMON/FRU OIDs resolve to names and
the severities the operator asked for, the two state varbinds render as
words, and TrapCollector's re-read hook fires poll_now on a managed source
and stays silent otherwise. Also covers the 5.32.0 CISCO-STACKWISE-MIB
notifications: kind "stackPower" for the nine fault OIDs vs. "stackPowerStatus"
for the informational link/oper-status pair, their specified severities, and
that every one of them but VersionMismatch (...0.0.9) forces a re-read.

Plain script, same style as tests/test_psu_state.py.
"""
import sys

import _paths  # noqa: F401  (repo root on sys.path)

from netpath.snmptrapd import POWER_TRAP_OIDS, TrapCollector
from netpath.trapdecode import Decoder, Trap, build_v2c_trap, enc_int

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------------- severity_for
d = Decoder()
d.configure({})

EXPECTED_SEVERITY = [
    ("1.3.6.1.4.1.9.9.13.3.0.1", 2),   # ciscoEnvMonShutdownNotification
    ("1.3.6.1.4.1.9.9.13.3.0.5", 2),   # ciscoEnvMonRedundantSupplyNotification
    ("1.3.6.1.4.1.9.9.13.3.0.9", 2),   # ciscoEnvMonSuppStatusChangeNotif
    ("1.3.6.1.4.1.9.9.117.2.0.2", 2),  # cefcPowerStatusChange
    ("1.3.6.1.4.1.9.9.117.2.0.4", 3),  # cefcFRURemoved
    ("1.3.6.1.4.1.9.9.117.2.0.3", 5),  # cefcFRUInserted
]
for oid, want in EXPECTED_SEVERITY:
    got = d.severity_for(oid)
    check(f"severity_for {oid} -> {want}", got == want, f"got {got}")

check("an unrelated Cisco OID still reads notice(5)",
      d.severity_for("1.3.6.1.4.1.9.9.41.2.0.1") == 5)

# --------------------------------------------------------- trap_name via decode
EXPECTED_NAME = {
    "1.3.6.1.4.1.9.9.13.3.0.1": "ciscoEnvMonShutdownNotification",
    "1.3.6.1.4.1.9.9.13.3.0.5": "ciscoEnvMonRedundantSupplyNotification",
    "1.3.6.1.4.1.9.9.13.3.0.9": "ciscoEnvMonSuppStatusChangeNotif",
    "1.3.6.1.4.1.9.9.117.2.0.2": "cefcPowerStatusChange",
    "1.3.6.1.4.1.9.9.117.2.0.3": "cefcFRUInserted",
    "1.3.6.1.4.1.9.9.117.2.0.4": "cefcFRURemoved",
}
for oid, name in EXPECTED_NAME.items():
    packet = build_v2c_trap("public", oid, 1000, [])
    trap = d.decode(packet, "127.0.0.1")
    check(f"trap_name for {oid} -> {name}",
          trap is not None and trap.trap_name == name,
          trap.trap_name if trap else "decode failed")

# --------------------------------------------------------- enum_text
text = d.decode(
    build_v2c_trap("public", "1.3.6.1.4.1.9.9.13.3.0.9", 1000,
                    [("1.3.6.1.4.1.9.9.13.1.5.1.3.1", enc_int(4))]),
    "127.0.0.1")
descr = [vb for vb in text.varbinds if vb["oid"] == "1.3.6.1.4.1.9.9.13.1.5.1.3.1"][0]
check("ciscoEnvMonSupplyState.1 = 4 reads as shutdown",
      "shutdown" in descr["text"], descr["text"])

# ---------------------------------------- CISCO-STACKWISE-MIB (5.32.0)
STACK_POWER_BASE = "1.3.6.1.4.1.9.9.500.0.0."
STACK_POWER_SEVERITY = {
    7: 5, 8: 5,            # link/oper status changed -> notice
    9: 4, 11: 4, 15: 4, 17: 4,     # version mismatch/budget warn/unbalanced/priority -> warning
    10: 3, 14: 3,          # invalid topology/under budget -> error
    12: 2, 13: 2, 16: 2, 18: 2,    # input/output current, insufficient power, under voltage -> critical
}
for n, want in STACK_POWER_SEVERITY.items():
    oid = STACK_POWER_BASE + str(n)
    got = d.severity_for(oid)
    check(f"severity_for stack power .0.0.{n} -> {want}", got == want, f"got {got}")

STACK_POWER_KIND = {n: ("stackPowerStatus" if n in (7, 8) else "stackPower")
                    for n in range(7, 19)}
for n, want_kind in STACK_POWER_KIND.items():
    trap = d.decode(build_v2c_trap("public", STACK_POWER_BASE + str(n), 1000, []),
                    "127.0.0.1")
    check(f"trap_kind for .0.0.{n} -> {want_kind}",
          trap is not None and trap.trap_kind == want_kind,
          trap.trap_kind if trap else "decode failed")

trap16 = d.decode(build_v2c_trap("public", STACK_POWER_BASE + "16", 1000, []), "127.0.0.1")
check("trap_name for .0.0.16 -> cswStackPowerInsufficientPower",
      trap16 is not None and trap16.trap_name == "cswStackPowerInsufficientPower",
      trap16.trap_name if trap16 else "decode failed")
trap11 = d.decode(build_v2c_trap("public", STACK_POWER_BASE + "11", 1000, []), "127.0.0.1")
check("trap_name for .0.0.11 uses the MIB's own misspelling",
      trap11 is not None and trap11.trap_name == "cscwStackPowerBudgetWarrning",
      trap11.trap_name if trap11 else "decode failed")

check("POWER_TRAP_OIDS carries every stack power OID but VersionMismatch (.0.0.9)",
      all(STACK_POWER_BASE + str(n) in POWER_TRAP_OIDS for n in range(7, 19) if n != 9)
      and STACK_POWER_BASE + "9" not in POWER_TRAP_OIDS)


# --------------------------------------------------------- TrapCollector re-read
class _FakeNodes:
    def __init__(self, mapping):
        self._mapping = mapping

    def device_id_for_address(self, ip):
        return self._mapping.get(ip)


class _Recorder:
    def __init__(self, raise_on_call=False):
        self.calls = []
        self._raise = raise_on_call

    def __call__(self, device_id):
        self.calls.append(device_id)
        if self._raise:
            raise RuntimeError("poll boom")


def collector(nodes, recorder):
    return TrapCollector(None, nodes_db=nodes, poll_now=recorder)


nodes = _FakeNodes({"10.0.0.1": 7})

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.4.1.9.9.13.3.0.5", source="10.0.0.1"))
check("a power trap from a managed device polls that device",
      rec.calls == [7], rec.calls)

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.6.3.1.1.5.3", source="10.0.0.1"))
check("linkDown does not trigger a re-read", rec.calls == [])

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.4.1.9.9.117.2.0.2", source="10.0.0.99"))
check("a power trap from an unmanaged source triggers nothing", rec.calls == [])

rec = _Recorder(raise_on_call=True)
try:
    collector(nodes, rec)._power_trap_reread(
        Trap(trap_oid="1.3.6.1.4.1.9.9.13.3.0.1", source="10.0.0.1"))
    raised = False
except Exception:
    raised = True
check("a poll_now that raises does not propagate",
      not raised and rec.calls == [7])

rec = _Recorder()
coll = collector(nodes, rec)
coll._power_trap_reread(Trap(trap_oid="1.3.6.1.4.1.9.9.13.3.0.9", source="10.0.0.1"))
coll._power_trap_reread(Trap(trap_oid="1.3.6.1.4.1.9.9.13.3.0.9", source="10.0.0.1"))
check("a second power trap inside POWER_TRAP_REREAD_S is debounced", rec.calls == [7], rec.calls)
coll._power_reread_ts[7] = 0.0
coll._power_trap_reread(Trap(trap_oid="1.3.6.1.4.1.9.9.117.2.0.4", source="10.0.0.1"))
check("...and fires again once the window has passed", rec.calls == [7, 7], rec.calls)

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.4.1.9.9.13.3.0.4", source="10.0.0.1"))
check("an ENVMON fan notification does not trigger a re-read", rec.calls == [], rec.calls)

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.4.1.9.9.500.0.0.16", source="10.0.0.1"))
check("a stack power fault trap (.0.0.16, kind stackPower) re-reads the device",
      rec.calls == [7], rec.calls)

rec = _Recorder()
collector(nodes, rec)._power_trap_reread(
    Trap(trap_oid="1.3.6.1.4.1.9.9.500.0.0.9", source="10.0.0.1"))
check("VersionMismatch (.0.0.9) does not trigger a re-read", rec.calls == [], rec.calls)

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

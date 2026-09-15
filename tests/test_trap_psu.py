"""Cisco power-trap decoding: the six ENVMON/FRU OIDs resolve to names and
the severities the operator asked for, the two state varbinds render as
words, and TrapCollector's re-read hook fires poll_now on a managed source
and stays silent otherwise.

Plain script, same style as tests/test_psu_state.py.
"""
import sys

import _paths  # noqa: F401  (repo root on sys.path)

from netpath.snmptrapd import TrapCollector
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

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")

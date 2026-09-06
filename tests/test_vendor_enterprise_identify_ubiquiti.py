"""Ubiquiti NanoBeam/NanoStation/LiteBeam/PowerBeam/airFiber radios were not
auto-recognised as "ubiquiti": airOS answers sysObjectID under enterprise
arc 10002 -- a PEN registered to Frogfoot Networks, whose agent airOS
reuses -- rather than Ubiquiti's own arc (41112, already mapped and
VERIFIED). Three things had to agree for identification to resolve these
to "ubiquiti": enterprises.py naming arc 10002 without corrupting the
display name 41112 already earns, vendorid.decide()'s sysObjectID branch
picking it up, and nodeoids.SYSDESCR_VENDORS catching the sysDescr text
("Linux NanoBeam 5AC ...", "Linux UBNT ...") for a device that answers a
generic sysObjectID instead. Pure-function tests only -- no socket, no
database, same style vendorid.py itself is written to (see its module
docstring).
"""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import configrx, enterprises, nodeoids, vendorid

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------- enterprises.py

print("enterprises.py: arc 10002 (Frogfoot's PEN, reused by airOS)")
hit = enterprises.lookup(10002)
check("resolves to the canonical 'ubiquiti' key", hit is not None and hit[0] == "ubiquiti", hit)
check("is NOT verified -- no live unit or bundled MIB cross-checked it in this build",
      enterprises.is_verified(10002) is False)
check("41112 (Ubiquiti's own PEN) is still verified, unaffected by adding 10002",
      enterprises.is_verified(41112) is True)
check("display_name('ubiquiti') is still plain 'Ubiquiti', not corrupted by the "
      "10002 entry's own tuple text",
      enterprises.display_name("ubiquiti") == "Ubiquiti",
      enterprises.display_name("ubiquiti"))
check("41112 and 10002 are not aliased to each other via VENDOR_ALIASES -- they "
      "already share the same canonical key directly",
      "ubiquiti" not in enterprises.VENDOR_ALIASES
      and "ubiquiti" not in enterprises.VENDOR_ALIASES.values())

# -------------------------------------------------------------- vendorid.py

print("vendorid.decide(): sysObjectID under arc 10002 names the device 'ubiquiti'")
d = vendorid.decide("1.3.6.1.4.1.10002.1", "Linux NanoBeam 5AC 8.7.11", [], [])
check("vendor == 'ubiquiti'", d.vendor == "ubiquiti", d.json())
check("source == 'sysObjectID' -- decided by the arc, not by sysDescr text",
      d.source == "sysObjectID", d.json())
check("vendor_arc == 10002 -- the arc actually answered, not remapped to 41112",
      d.vendor_arc == 10002, d.json())
check("confidence == 'medium' -- CURATED, not cross-checked against real hardware",
      d.confidence == "medium", d.json())

print("vendorid.decide(): sysDescr alone (a generic/unknown sysObjectID arc) "
      "still names Ubiquiti radios by product-family words")
GENERIC_OID = "1.3.6.1.4.1.8072.3.2.10"     # net-snmp's own arc -- GENERIC_ARCS
for descr in ("Linux NanoBeam 5AC 8.7.11", "Linux UBNT 8.7.11",
              "AirOS NanoStation M5", "Ubiquiti LiteBeam M5",
              "Ubiquiti PowerBeam AC Gen2", "Ubiquiti airFiber 24",
              "Ubiquiti AirMax M5", "EdgeOS EdgeRouter-X",
              "Ubiquiti UniFi Switch"):
    d = vendorid.decide(GENERIC_OID, descr, [], [])
    check(f"sysDescr {descr!r} -> ubiquiti (source sysDescr, no vendor arc)",
          d.vendor == "ubiquiti" and d.source == "sysDescr" and d.vendor_arc is None,
          d.json())

print("vendorid.decide(): sysObjectID still wins over sysDescr when both are present")
d = vendorid.decide("1.3.6.1.4.1.9.1.1208", "Ubiquiti UniFi Switch", [], [])
check("a real Cisco arc is not overridden by sysDescr text mentioning another vendor",
      d.vendor == "cisco" and d.source == "sysObjectID", d.json())

# ------------------------------------------------------- configrx / nodeoids

print("configrx.resolve('ubiquiti') matches the key vendorid.decide() names")
check("resolve() finds the vendor entry", configrx.resolve("ubiquiti") is not None)

print("nodeoids.RF_METRICS: arc 10002 still gets Ubiquiti's 41112 RF scalars")
check("RF_METRICS has an entry for arc 10002",
      10002 in nodeoids.RF_METRICS)
check("it is the SAME probes Ubiquiti's own arc (41112) uses -- same OIDs, "
      "since 10002 only affects how the device is NAMED, not what it answers",
      nodeoids.RF_METRICS.get(10002) == nodeoids.RF_METRICS.get(41112)
      and nodeoids.RF_METRICS.get(10002) is not None,
      (nodeoids.RF_METRICS.get(10002), nodeoids.RF_METRICS.get(41112)))
check("10002 is in the gate nodepoll actually checks before reading RF metrics",
      10002 in nodeoids.RF_VENDOR_ARCS)


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

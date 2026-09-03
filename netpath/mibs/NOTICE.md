# Third-party notices — bundled MIB modules

This directory ships twenty-one `.mib` files. Eighteen of them are other
people's work, redistributed here, and this file says whose and under what
terms. It is the MIB bundle's equivalent of
`netpath/web/static/vendor/LICENSE-xterm.txt`, which does the same job for the
vendored xterm.js.

Nothing here is modified. Each file is the module as published, byte for byte,
except where the table below says otherwise. They are bundled so that a vendor
MIB an operator uploads resolves its imports on the first try, and so that the
OIDs the poller already reads every cycle show real `DESCRIPTION` text in the
MIB browser instead of a bare numeric arc.

---

## IETF standards-track modules

Extracted from the RFCs named below. Copyright in the RFC text and in the MIB
modules within it is held by **the IETF Trust and the persons identified as the
document authors**, and the modules are redistributed here under the Simplified
BSD Licence set out in Section 4.c of the IETF Trust's Legal Provisions
Relating to IETF Documents (BCP 78, <https://trustee.ietf.org/license-info>).
That licence permits redistribution and use in source and binary forms, with or
without modification, provided the copyright notice, the list of conditions and
the disclaimer are retained.

| File | Module | Source |
| --- | --- | --- |
| `SNMPv2-SMI.mib` | `SNMPv2-SMI` | RFC 2578 — Structure of Management Information Version 2 |
| `SNMPv2-TC.mib` | `SNMPv2-TC` | RFC 2579 — Textual Conventions for SMIv2 |
| `SNMPv2-MIB.mib` | `SNMPv2-MIB` | RFC 3418 — MIB for SNMP |
| `IF-MIB.mib` | `IF-MIB` | RFC 2863 — The Interfaces Group MIB |
| `IP-MIB.mib` | `IP-MIB` | RFC 4293 — MIB for the Internet Protocol |
| `TCP-MIB.mib` | `TCP-MIB` | RFC 4022 — MIB for the Transmission Control Protocol |
| `UDP-MIB.mib` | `UDP-MIB` | RFC 4113 — MIB for the User Datagram Protocol |
| `INET-ADDRESS-MIB.mib` | `INET-ADDRESS-MIB` | RFC 4001 — Textual Conventions for Internet Network Addresses |
| `BRIDGE-MIB.mib` | `BRIDGE-MIB` | RFC 4188 — Bridge MIB |
| `P-BRIDGE-MIB.mib` | `P-BRIDGE-MIB` | RFC 4363 — Bridge MIB Extensions |
| `Q-BRIDGE-MIB.mib` | `Q-BRIDGE-MIB` | RFC 4363 — Bridge MIB Extensions (VLAN) |
| `HOST-RESOURCES-MIB.mib` | `HOST-RESOURCES-MIB` | RFC 2790 — Host Resources MIB |
| `ENTITY-MIB.mib` | `ENTITY-MIB` | RFC 4133 — Entity MIB (Version 3) |
| `ENTITY-SENSOR-MIB.mib` | `ENTITY-SENSOR-MIB` | RFC 3433 — Entity Sensor MIB |
| `POWER-ETHERNET-MIB.mib` | `POWER-ETHERNET-MIB` | RFC 3621 — Power Ethernet MIB |

`POWER-ETHERNET-MIB.mib` and `LLDP-MIB.mib` are the copies published by Cisco
Systems, which carry an additional `Copyright (c) 2006 by cisco Systems, Inc.
All rights reserved.` header on the extraction. The modules themselves are the
standards-track ones — RFC 3621 and IEEE Std 802.1AB respectively — and the
headers are retained in the files as shipped.

Three of the IETF files above (`SNMPv2-SMI.mib`, `SNMPv2-TC.mib` and the
Net-SNMP file below) carry no copyright block inside the file itself, because
the copies in circulation were extracted from the RFC without its boilerplate.
Their provenance is the RFC named in the table, and the licence above applies
to them exactly as it does to the rest.

## IEEE

| File | Module | Source |
| --- | --- | --- |
| `LLDP-MIB.mib` | `LLDP-MIB` | IEEE Std 802.1AB — Station and Media Access Control Connectivity Discovery |

Copyright in IEEE Std 802.1AB is held by the **Institute of Electrical and
Electronics Engineers, Inc.** The MIB module is published by the IEEE for
implementation of the standard; the copy bundled here is the widely
redistributed Cisco extraction, with its header intact.

## IANA

| File | Module | Source |
| --- | --- | --- |
| `IANAifType-MIB.mib` | `IANAifType-MIB` | The IANA-maintained `IANAifType-MIB` registry, <https://www.iana.org/assignments/ianaiftype-mib> |

Maintained by the **Internet Assigned Numbers Authority**. IANA publishes this
module for public use; it is redistributed unmodified.

## Net-SNMP

| File | Module | Source |
| --- | --- | --- |
| `UCD-SNMP-MIB.mib` | `UCD-SNMP-MIB` | The Net-SNMP project, <https://www.net-snmp.org> |

Copyright 1989, 1991, 1992 by **Carnegie Mellon University**; derivative work
copyright 1996, 1998–2000 **The Regents of the University of California**; and
portions copyright **Networks Associates Technology, Inc.**, **Cambridge
Broadband Ltd.**, **Sun Microsystems, Inc.** and **Fabasoft R&D Software GmbH &
Co KG**, per the Net-SNMP `COPYING` file. Net-SNMP is distributed under
BSD-style licences that permit redistribution in source form with the copyright
notice retained.

---

## Written for this application

These three are ours, not third-party, and carry no external licence. They are
listed so the count in this file matches the directory.

| File | Module | What it is |
| --- | --- | --- |
| `enterprise-roots.mib` | `SAPPIWHERE-ENTERPRISE-ROOTS` | Private Enterprise Number arcs under `1.3.6.1.4.1`, so a vendor MIB uploaded afterwards resolves its parent arc on the first try. Each arc is a public IANA assignment named as "this number belongs to this vendor" — not an extract of any vendor's MIB text. |
| `enterprise-roots-2.mib` | `SAPPIWHERE-ENTERPRISE-ROOTS-2` | A continuation of the above, kept as a separate file because bundled MIBs are seeded by filename and an already-seeded file is never re-read. |
| `if-mib-core.mib` | `IF-MIB-CORE` | A hand-written subset covering only the IF-MIB and ifXTable columns the poller reads, restated in this application's own words so the MIB browser shows description text without shipping a second copy of RFC 2863. |

---

## If you are auditing this

The bundle is a convenience, not a dependency: every one of these files can be
deleted from a running installation and the application keeps polling. What is
lost is description text in the MIB browser and first-try resolution of an
uploaded vendor MIB. `service._seed_default_mibs` records each filename it has
seeded in the `seeded_mib_files` setting and never re-reads a name it has seen,
so a module deleted deliberately stays deleted across restarts and upgrades.

`INTERNALS.md` describes how these files are parsed and what the parser does
and does not recognise — notably that `SNMPv2-TC.mib` contributes no objects,
because it is nothing but textual conventions, which the parser treats as out
of scope.

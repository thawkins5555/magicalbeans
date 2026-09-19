from __future__ import annotations


MAX_UDP = 65535

# Bounds on read_device_vlans' walk (see its own docstring): the number of
# distinct VLAN ids one walk will keep and write, the lowest-numbered ones
# kept when a device reports more. A device with a garbled or enormous VLAN
# range (a bad agent, or a trunk allow-list read as if every bit meant a
# real VLAN) must not turn one scheduled walk into an unbounded number of
# stored rows — the same "cap rather than fail" idiom the class-level
# _MAX_VLAN_CONTEXTS/_VLAN_WALK_BUDGET_S use for _cisco_vlan_fdb's per-VLAN-
# community sweep. Deliberately MODULE-level rather than a same-named class
# attribute: this walk has no per-VLAN SNMP context to size against (it
# bounds the OUTPUT of a handful of column walks, not a loop that opens one
# SNMP session per VLAN), and giving it its own class attribute of the same
# name as the existing one would silently shadow it in the class namespace.
# What a poll is assumed to cost before one has been measured, in seconds.
# Only ever used for a device the poller has not polled yet, and only until
# it has: a cold start must not size the pool to zero.
_DEFAULT_POLL_COST = 1.0

# The weight one poll carries in its device's mean. 0.3 settles within a
# handful of polls, which at a 120 s interval is minutes -- fast enough to
# follow a device going down, slow enough that one slow answer does not
# resize the pool on its own.
_POLL_COST_ALPHA = 0.3

# A poll longer than this is not a measurement. The interface read alone is
# bounded to half a poll interval and gives up after three timeouts, so
# nothing legitimate approaches it.
_POLL_COST_CEILING_S = 600.0

# Restart spread: long enough to flatten a large fleet, short enough that a
# device that died during the outage is still noticed inside half a minute.
_STARTUP_SPREAD_S = 30.0
# The first reschedule after a poll lands in [fraction, 1.0] x interval --
# earlier only, so no device is ever polled less often than configured.
_STAGGER_MIN_FRACTION = 0.5

_MAX_VLANS = 512
_VLAN_WALK_BUDGET_S = 20.0

# RFC 3414 §5's usmStats counters, the objects an agent names in the
# Report-PDU it answers a v3 request it would not process with. Reported by
# name, because "engine resync required" told an operator nothing about
# whether the password was wrong, the clock was out, or the security level
# was refused — three different problems with three different fixes.
USM_STATS = {
    "1.3.6.1.6.3.15.1.1.1": ("unsupportedSecLevels",
                             "the device refused this security level — its "
                             "user is provisioned at a different one (an "
                             "authPriv user needs a privacy password on this "
                             "credential; an authNoPriv user must not be "
                             "sent one)"),
    "1.3.6.1.6.3.15.1.1.2": ("notInTimeWindows",
                             "the device rejected the message's engine time"),
    "1.3.6.1.6.3.15.1.1.3": ("unknownUserNames",
                             "the device does not know this SNMPv3 user"),
    "1.3.6.1.6.3.15.1.1.4": ("unknownEngineIDs",
                             "the device did not recognise the engine id"),
    "1.3.6.1.6.3.15.1.1.5": ("wrongDigests",
                             "the authentication password or protocol is wrong"),
    "1.3.6.1.6.3.15.1.1.6": ("decryptionErrors",
                             "the device could not decrypt the message — the "
                             "privacy password or protocol is wrong (the "
                             "authentication password is not the problem: "
                             "the signature is checked first)"),
}

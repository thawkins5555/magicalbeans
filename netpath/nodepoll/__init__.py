"""NodePoller: the per-device SNMP/ping scheduler.

Monitor-shaped, not IpamWorker-shaped -- a hot-resizable ThreadPoolExecutor,
restart-safe per-device due-time seeding (from the device's own
last_poll_ts, with a bounded spread for whatever an outage left overdue),
reschedule-before-run, overrun logging, and a wrap-everything/finally
worker discipline, all copied from netpath/monitor.py's Monitor class.
Nodes will typically manage far more devices than IPAM manages subnets, so
the finer-grained, restart-safe scheduling Monitor already has is the
right shape, not IpamWorker's coarser "unseen = immediately due" one.
"""

from __future__ import annotations

from . import (_consts, _decode, _session, _jobs, discovery_mixin, poll_mixin,
               identify_mixin, environment_mixin, vendor_sensor_psu_mixin,
               arp_mixin, lldp_cdp_mixin, vlan_mixin, poller)

_MODULES = (_consts, _decode, _session, _jobs, discovery_mixin, poll_mixin,
            identify_mixin, environment_mixin, vendor_sensor_psu_mixin,
            arp_mixin, lldp_cdp_mixin, vlan_mixin, poller)
_MODULE_NAMES = {_mod.__name__.rsplit(".", 1)[-1] for _mod in _MODULES}

# Every submodule name is re-exported; a submodule's own name is never
# overwritten by something a header imported under the same name.
for _mod in _MODULES:
    globals().update({k: v for k, v in vars(_mod).items()
                      if not k.startswith("__") and k not in _MODULE_NAMES})
del _mod

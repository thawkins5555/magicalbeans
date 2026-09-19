"""JSON endpoints.

Each handler takes the service, the parsed query string and the decoded body,
and returns something json-serialisable. The HTTP plumbing is in server.py so
this file stays about the data.

One module per section; _shared holds what sections call across a file
boundary. Every module-level name is re-exported here, so `api.<name>`
resolves as it did against the single flat file.
"""
from . import _shared
from . import paths
from . import netflow
from . import relays
from . import debug
from . import settings
from . import syslog
from . import snmp
from . import ipam
from . import nodes
from . import nodes_series
from . import nodes_reports
from . import nodes_credentials
from . import alerts
from . import wireless
from . import configrx
from . import mapper
from . import auth
from . import dashboard

_MODULES = (_shared, paths, netflow, relays, debug, settings, syslog, snmp, ipam,
           nodes, nodes_series, nodes_reports, nodes_credentials, alerts,
           wireless, configrx, mapper, auth, dashboard)
_MODULE_NAMES = {_mod.__name__.rsplit(".", 1)[-1] for _mod in _MODULES}

# configrx.py and mapper.py import the top-level netpath module of the same
# name; the skip keeps `api.<submodule>` the submodule.
for _mod in _MODULES:
    globals().update({k: v for k, v in vars(_mod).items()
                      if not k.startswith("__") and k not in _MODULE_NAMES})
del _mod

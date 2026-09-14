"""5.18.0: the DHCP lease grid also carries "in use, not leased" rows — one
per `static_in_scope` host inside the requested scope's dynamic range that
holds no lease anywhere. A host still leased is not duplicated; the CSV
export and the summary's own `static_in_use` count agree with the number
of such rows the leases route hands back."""
import os
import time

import _paths  # noqa: F401

from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.web import api

TMP = _paths.tmpdir("ipam_dhcp_leases_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


nodes = NodesDatabase(os.path.join(TMP, "nodes.db"))
ipam = IpamDatabase(os.path.join(TMP, "ipam.db"))
now = time.time()

nodes.add_device("10.20.3.42", "printer-3rd-floor")

server = ipam.add_dhcp_server("dhcp.example.net", "Site A")
ipam.replace_dhcp_scopes(server, [
    {"scope_id": "10.20.3.0", "name": "Site A", "start_ip": "10.20.3.10",
     "end_ip": "10.20.3.200", "mask": "255.255.255.0", "state": "Active",
     "lease_duration_s": 86400, "description": "", "router": "10.20.3.1"}])
ipam.replace_dhcp_leases(server, [
    {"scope_id": "10.20.3.0", "ip": "10.20.3.99", "mac": "aa:bb:cc:00:00:99",
     "hostname": "laptop-99", "address_state": "Active",
     "lease_expires_ts": now + 3600, "is_reservation": False, "description": ""}])
ipam.record_observation("10.20.3.42", None, "aa:bb:cc:00:00:42",
                        "sweep", now, "ping sweep", True)
ipam.record_observation("10.20.3.99", None, "aa:bb:cc:00:00:99",
                        "sweep", now, "ping sweep", True)


class Service:
    ipam_db = ipam
    nodes_db = nodes
    ipam_settings = ipam.settings()

    class app_db:
        @staticmethod
        def hostnames(ips):
            return {}


service = Service()

payload = api.get_ipam_dhcp_leases(service, {"server_id": server, "scope_id": "10.20.3.0"}, None)
leases = payload["leases"]
by_ip = {r["ip"]: r for r in leases}

check("an alive host in range with no lease appears as an in-use-only row",
      "10.20.3.42" in by_ip and by_ip["10.20.3.42"]["in_use_only"] is True
      and by_ip["10.20.3.42"]["address_state"] == "in use, not leased", by_ip.get("10.20.3.42"))
check("...naming the Nodes device", by_ip["10.20.3.42"]["hostname"] == "printer-3rd-floor",
      by_ip["10.20.3.42"])
check("...carrying seen_source/seen_detail and no lease fields",
      by_ip["10.20.3.42"]["seen_source"] == "sweep"
      and by_ip["10.20.3.42"]["seen_detail"] == "ping sweep"
      and by_ip["10.20.3.42"]["lease_expires"] is None
      and by_ip["10.20.3.42"]["is_reservation"] is False, by_ip["10.20.3.42"])
check("a leased host is not duplicated as an in-use-only row",
      "10.20.3.99" in by_ip and by_ip["10.20.3.99"]["in_use_only"] is False,
      by_ip.get("10.20.3.99"))
check("exactly the leased row plus the one in-use-only row are returned",
      len(leases) == 2, leases)

import csv
import io

export = api.get_ipam_dhcp_leases_export(service, {"server_id": server, "scope_id": "10.20.3.0"}, None)
csv_rows = list(csv.reader(io.StringIO(export["csv"].lstrip("﻿"))))
header, csv_body = csv_rows[0], csv_rows[1:]
check("export carries in_use_only and seen_detail in the header",
      "in_use_only" in header and "seen_detail" in header, header)
export_rows = {row[header.index("ip")]: row for row in csv_body}
check("...and the in-use-only row's data",
      export_rows["10.20.3.42"][header.index("in_use_only")] == "True"
      and export_rows["10.20.3.42"][header.index("seen_detail")] == "ping sweep",
      export_rows.get("10.20.3.42"))

scopes = api.get_ipam_dhcp_scopes(service, {"server_id": server}, None)["scopes"]
scope_row = next(s for s in scopes if s["scope_id"] == "10.20.3.0")
in_use_only_count = sum(1 for r in leases if r["in_use_only"])
check("the scope summary's static_in_use count equals the number of in-use-only rows",
      scope_row["usage"]["static_in_use"] == in_use_only_count == 1, scope_row["usage"])

nodes.close()
ipam.close()
print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")

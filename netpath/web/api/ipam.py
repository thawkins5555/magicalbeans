"""Handlers: IPAM subnets, hosts and DHCP."""

from __future__ import annotations

import functools
import ipaddress

from ... import namelookup
from ...ipamdb import mac_search_digits, scope_size
from ...eventlog import IPAM as IPAM_CATEGORY

from ._shared import EXPORT_ROW_CAP, _audit, _audit_diff, _clear_credential, _csv_response, _encrypt_secret, _pick, _require, _window


# ---------------------------------------------------------------------- ipam

def get_ipam_search(service, params, body) -> dict:
    query = (params.get("q") or "").strip()
    if len(query) < 2:
        return {"results": []}
    return {"results": service.ipam_search(query)}


def get_ipam_dhcp_lease_search(service, params, body) -> dict:
    """DHCP leases and reservations matching a needle — IP, hostname,
    description, or a MAC in any spelling — as LEASE rows, for the global
    search's own DHCP group.

    /api/ipam/search cannot serve this: service.ipam_search merges every
    source into one record per address, and in folding a lease into a host
    it keeps the hostname and MAC and drops exactly the fields that make a
    lease hit worth reading — which scope, which server, when it expires
    and whether it was reserved. Two servers each holding a lease for one
    card (a laptop that moved sites) are one host there and two leases
    here, which is the difference the operator asked about.

    The same two-character floor get_ipam_search applies: a one-character
    LIKE matches most of the table and answers nothing.

    Two queries stand behind the one payload. A needle that is a whole MAC
    in any spelling is "where is this card", and goes to
    dhcp_leases_for_mac: an equality on the stored column, which
    ix_dhcp_leases_mac answers, against search_dhcp's unavoidable scan of
    every lease through a REPLACE expression. Anything else — a prefix,
    the four digits off a label, a hostname, an address — is a search and
    goes to search_dhcp. The rows are shaped by one function so the
    browser cannot tell which ran: dhcp_leases_for_mac also joins the
    scope's name, and it is deliberately left out here rather than sent
    on one branch and absent on the other; the payload names the scope by
    scope_id on both. The whole-MAC branch also skips the text clauses, so
    a MAC that appears only in another lease's description is a search
    hit and not a lookup hit — the lookup's answer is the leases the card
    holds, which is what a whole address asks."""
    query = (params.get("q") or "").strip()
    if len(query) < 2:
        return {"leases": []}
    if len(mac_search_digits(query)) == 12:
        rows = service.ipam_db.dhcp_leases_for_mac(query, limit=20)
    else:
        rows = service.ipam_db.search_dhcp(query, limit=20)
    return {"leases": [_dhcp_lease_search_json(r) for r in rows]}


def _dhcp_lease_search_json(r) -> dict:
    """One lease row as the lease search sends it — the same keys whichever
    of the two queries produced the row; see get_ipam_dhcp_lease_search."""
    return {"id": r["id"], "server_id": r["server_id"], "server_label": r["server_label"],
            "scope_id": r["scope_id"], "ip": r["ip"], "mac": r["mac"],
            "hostname": r["hostname"], "address_state": r["address_state"],
            "lease_expires": r["lease_expires_ts"],
            "is_reservation": bool(r["is_reservation"]),
            "description": r["description"], "polled": r["polled_ts"]}


def _subnet_json(row) -> dict:
    return {"id": row["id"], "cidr": row["cidr"], "label": row["label"],
            "vlan": row["vlan"], "enabled": bool(row["enabled"]),
            "created": row["created_ts"]}


def get_ipam_subnets(service, params, body) -> dict:
    from ...ipam_scan import subnet_size

    subnets = [_subnet_json(row) for row in service.ipam_db.subnets()]
    worker_state = service.ipam.state()
    # Only the most recent scan per subnet matters here; recent_scans()
    # returns newest-first across every subnet, so the first hit per id wins.
    latest: dict[int, dict] = {}
    for row in service.ipam_db.recent_scans(limit=1000):
        latest.setdefault(row["subnet_id"], dict(row))
    for subnet in subnets:
        subnet["scanning"] = subnet["id"] in worker_state["scanning"]
        # When the currently-running scan started, for "Scanning now... "
        # started N min ago" — the worker already tracks this for its own
        # debug page (IpamWorker.state()'s scan_started).
        subnet["scan_started"] = worker_state["scan_started"].get(subnet["id"])
        last = latest.get(subnet["id"])
        subnet["last_scan"] = {
            "started": last["started_ts"], "finished": last["finished_ts"],
            "addresses": last["addresses"], "alive": last["alive"],
            "conflicts": last["conflicts"], "status": last["status"],
            "error": last["error"],
        } if last else None

        # Alive / previously-seen-but-down / never-seen, for the utilization
        # pie chart. Never-seen is a subtraction rather than a count, since
        # an address nothing has ever answered on has no row in `hosts` to
        # count in the first place.
        counts = service.ipam_db.host_counts(subnet["id"])
        try:
            total = subnet_size(subnet["cidr"])
        except ValueError:
            total = None
        never_seen = (max(0, total - counts["alive"] - counts["seen_down"])
                      if total is not None else None)
        subnet["usage"] = {"alive": counts["alive"], "seen_down": counts["seen_down"],
                           "never_seen": never_seen, "total": total}
    return {"subnets": subnets}


def post_ipam_subnet(service, params, body) -> dict:
    from ...ipam_scan import usable_addresses, SubnetTooLarge

    cidr = str(body.get("cidr", "")).strip()
    if not cidr:
        raise ValueError("A subnet in CIDR form is required, e.g. 10.20.3.0/24")
    max_addresses = int(service.ipam_settings.get("max_scan_addresses", 1024))
    try:
        usable_addresses(cidr, max_addresses)
    except SubnetTooLarge as exc:
        raise ValueError(str(exc))
    subnet_id = service.ipam_db.add_subnet(
        cidr, label=body.get("label") or cidr, vlan=body.get("vlan") or None)
    service.log.add(IPAM_CATEGORY, f"Added subnet {cidr}")
    _audit(service, params, "ipam_subnet.create", target=cidr)
    return {"id": subnet_id}


def put_ipam_subnet(service, params, body, subnet_id) -> dict:
    # Fetched before the update — update_subnet itself never reads the row
    # it is about to change, so this is the only "before" available.
    before = service.ipam_db.subnet(subnet_id)
    fields = _pick(body, ("cidr", "label", "vlan", "enabled"))
    service.ipam_db.update_subnet(subnet_id, **fields)
    if before is not None and fields:
        detail = _audit_diff(before, fields) or "no change"
        _audit(service, params, "ipam_subnet.update", target=str(subnet_id), detail=detail)
    return {"ok": True}


def delete_ipam_subnet(service, params, body, subnet_id) -> dict:
    # Fetched before the delete — afterward there is no cidr left to name
    # this by at all.
    before = service.ipam_db.subnet(subnet_id)
    service.ipam_db.remove_subnet(subnet_id)
    service.log.add(IPAM_CATEGORY, f"Removed subnet #{subnet_id}")
    _audit(service, params, "ipam_subnet.delete", target=str(subnet_id),
          detail=f"cidr={before['cidr']}" if before is not None else "")
    return {"ok": True}


def post_ipam_subnet_scan(service, params, body, subnet_id) -> dict:
    _require(service.ipam_db.subnet(subnet_id), "subnet")
    service.ipam.scan_now(subnet_id)
    return {"ok": True}


def post_ipam_subnet_clear(service, params, body, subnet_id) -> dict:
    subnet = _require(service.ipam_db.subnet(subnet_id), "subnet")
    if subnet_id in service.ipam.state()["scanning"]:
        raise ValueError(
            "A scan of this subnet is running right now — wait for it to "
            "finish before clearing, so it doesn't write results back in "
            "behind the clear.")
    result = service.ipam_db.clear_subnet_data(subnet_id)
    service.log.add(IPAM_CATEGORY,
                    f"Cleared discovered hosts and scan history for "
                    f"{subnet['label']} ({result['hosts']} host(s), "
                    f"{result['scans']} scan record(s))")
    return {"ok": True, **result}


def get_ipam_hosts(service, params, body) -> dict:
    subnet_id = params.get("subnet_id")
    rows = service.ipam_db.hosts(int(subnet_id) if subnet_id else None)
    names = {}
    if service.ipam_settings.get("resolve_hosts", True):
        names = {ip: name for ip, name in
                 service.app_db.hostnames({r["ip"] for r in rows}).items() if name}
    dhcp_state = _ipam_dhcp_state_map(service)
    return {"hosts": [
        {"ip": r["ip"], "mac": r["mac"], "alive": bool(r["alive"]),
         "hostname": names.get(r["ip"], ""), "subnet_id": r["subnet_id"],
         "subnet_label": r["subnet_label"], "first_seen": r["first_seen"],
         "last_seen": r["last_seen"], "last_up": r["last_up"],
         "seen_source": r["seen_source"] or "", "seen_detail": r["seen_detail"] or "",
         "switch_device_id": r["switch_device_id"], "switch_if_index": r["switch_if_index"],
         "switch_port": r["switch_port"] or "", "switch_seen_ts": r["switch_seen_ts"],
         "dhcp": dhcp_state(r["ip"], bool(r["alive"]))}
        for r in rows]}


def _ipam_dhcp_state_map(service):
    """ip -> 'leased' / 'reserved' / 'static in scope' / '' for the hosts
    table: one read of the leases and scope ranges, then a lookup per row."""
    leases = {}
    for lease in service.ipam_db.dhcp_leases():
        leases[lease["ip"]] = "reserved" if lease["is_reservation"] else "leased"
    ranges = []
    for scope in service.ipam_db.dhcp_scopes():
        try:
            ranges.append((int(ipaddress.IPv4Address(scope["start_ip"])),
                           int(ipaddress.IPv4Address(scope["end_ip"]))))
        except (ValueError, TypeError):
            continue

    def state(ip: str, alive: bool) -> str:
        if ip in leases:
            return leases[ip]
        if not alive or not ranges:
            return ""
        try:
            number = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return ""
        return "static in scope" if any(low <= number <= high for low, high in ranges) else ""
    return state


def get_ipam_hosts_export(service, params, body) -> dict:
    """The SUBNETS & HOSTS table. `subnet_id` is the one filter the JSON
    route itself applies server-side; "Alive only" is a client-side
    checkbox (ipam.js drawHosts), so the export takes the same `alive_only`
    presence-flag the Devices "only offline" filter uses and applies it
    here — the export honours what is on screen even though the screen
    itself never sent that filter to the server before now."""
    hosts = get_ipam_hosts(service, params, body)["hosts"]
    if params.get("alive_only") is not None:
        hosts = [h for h in hosts if h["alive"]]
    truncated = len(hosts) > EXPORT_ROW_CAP
    hosts = hosts[:EXPORT_ROW_CAP]
    header = ["ip", "mac", "alive", "hostname", "subnet_label",
             "first_seen", "last_seen", "last_up",
             "seen_source", "seen_detail", "switch_port", "dhcp"]
    csv_rows = [[h.get(key) for key in header] for h in hosts]
    return _csv_response("ipam-hosts", header, csv_rows, truncated=truncated,
                         cap=EXPORT_ROW_CAP)


def get_ipam_conflicts(service, params, body) -> dict:
    include_resolved = params.get("resolved") == "1"
    rows = service.ipam_db.conflicts(include_resolved=include_resolved)
    return {"conflicts": [
        {"id": r["id"], "ip": r["ip"], "mac_a": r["mac_a"], "mac_b": r["mac_b"],
         "source": r["source"], "detail": r["detail"] or "", "detected": r["detected_ts"],
         "last_seen": r["last_seen_ts"], "resolved": r["resolved_ts"]}
        for r in rows]}


def post_ipam_conflict_resolve(service, params, body, conflict_id) -> dict:
    _require(service.ipam_db.conflict(conflict_id), "conflict")
    service.ipam_db.resolve_conflict(conflict_id)
    return {"ok": True}


def post_ipam_conflict_reopen(service, params, body, conflict_id) -> dict:
    _require(service.ipam_db.conflict(conflict_id), "conflict")
    service.ipam_db.reopen_conflict(conflict_id)
    return {"ok": True}


def _dhcp_server_json(row) -> dict:
    return {"id": row["id"], "address": row["address"], "label": row["label"],
            "enabled": bool(row["enabled"]), "last_poll": row["last_poll_ts"],
            "last_status": row["last_status"], "last_error": row["last_error"],
            "poll_failures": row["poll_failures"],
            # The username is not sensitive on its own and is shown so the
            # form can be prefilled; the password never appears in any
            # response, encrypted or not — only whether one is stored.
            "username": row["username"], "has_credential": bool(row["password_enc"]),
            "credential_ts": row["credential_ts"]}


def get_ipam_dhcp_servers(service, params, body) -> dict:
    servers = [_dhcp_server_json(row) for row in service.ipam_db.dhcp_servers()]
    worker_state = service.ipam.state()
    for server in servers:
        server["polling"] = server["id"] in worker_state["polling"]
    return {"servers": servers}


def post_ipam_dhcp_server(service, params, body) -> dict:
    address = str(body.get("address", "")).strip()
    if not address:
        raise ValueError("A hostname or address is required")
    server_id = service.ipam_db.add_dhcp_server(
        address, label=body.get("label") or address)
    service.log.add(IPAM_CATEGORY, f"Added DHCP server {address}")
    return {"id": server_id}


def put_ipam_dhcp_server(service, params, body, server_id) -> dict:
    existing = _require(service.ipam_db.dhcp_server(server_id), "DHCP server")
    fields = _pick(body, ("address", "label", "enabled"))
    # A stored credential belongs to the machine it was stored for. Pointing
    # the row at a different address and then pressing Test or Poll would
    # otherwise hand that account's password to whatever answers there —
    # the same retargeting the SMTP test allowed. Moving the row forgets the
    # credential; storing one again is a deliberate act naming the new host.
    moved = ("address" in fields
             and str(fields["address"]).strip() != str(existing["address"] or ""))
    service.ipam_db.update_dhcp_server(server_id, **fields)
    if moved and existing["password_enc"]:
        service.ipam_db.clear_dhcp_credential(server_id)
        service.log.add(IPAM_CATEGORY,
                        f"Cleared the stored credential for DHCP server "
                        f"{existing['label']}: its address changed from "
                        f"{existing['address']} to {fields['address']}")
        return {"ok": True, "credential_cleared": True}
    return {"ok": True}


def delete_ipam_dhcp_server(service, params, body, server_id) -> dict:
    service.ipam_db.remove_dhcp_server(server_id)
    service.log.add(IPAM_CATEGORY, f"Removed DHCP server #{server_id}")
    return {"ok": True}


def post_ipam_dhcp_server_poll(service, params, body, server_id) -> dict:
    _require(service.ipam_db.dhcp_server(server_id), "DHCP server")
    service.ipam.poll_dhcp_now(server_id)
    return {"ok": True}


def _text_or_none(value, field):
    """A credential field read straight out of the JSON body: str, or absent
    (None), never anything else -- a list or number here would otherwise
    reach os.environ[...] = value in ipam_dhcp._run and fail as a TypeError,
    a 500 for what is really a malformed request."""
    if value is None or isinstance(value, str):
        return value
    raise ValueError(f"{field} must be text")


def _test_dhcp_connection(service, address, username, password) -> dict:
    """The PowerShell round trip itself, shared by the id-based Test button
    (an already-saved server) and the Add dialog's Test connection (nothing
    saved yet, so only whatever the form currently holds)."""
    from ...ipam_dhcp import DhcpUnavailable, test_connection

    try:
        result = test_connection(
            address,
            timeout_s=float(service.ipam_settings.get("dhcp_timeout_s", 30)),
            username=username or None, password=password or None)
    except (DhcpUnavailable, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        username = password = None
    return result


def post_ipam_dhcp_server_test(service, params, body, server_id) -> dict:
    from ...ipam_worker import credential_for_server

    server = _require(service.ipam_db.dhcp_server(server_id), "DHCP server")

    # Testing an in-progress edit checks whatever is currently typed, before
    # it is saved; otherwise fall back to whatever credential already exists.
    username = _text_or_none(body.get("username"), "username")
    password = _text_or_none(body.get("password"), "password")
    if username is None:
        username, password = credential_for_server(server)
    return _test_dhcp_connection(service, server["address"], username, password)


def post_ipam_dhcp_server_test_unsaved(service, params, body) -> dict:
    """The Add DHCP server dialog's own Test connection: the same round
    trip, before there is a row (or a stored credential) to fall back to --
    exactly the address/username/password the form currently holds."""
    address = str(body.get("address", "")).strip()
    if not address:
        raise ValueError("A hostname or address is required")
    username = _text_or_none(body.get("username"), "username")
    password = _text_or_none(body.get("password"), "password")
    return _test_dhcp_connection(service, address, username, password)


def post_ipam_dhcp_server_credential(service, params, body, server_id) -> dict:
    server = _require(service.ipam_db.dhcp_server(server_id), "DHCP server")
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password:
        raise ValueError("A username and password are both required")
    try:
        encrypted = _encrypt_secret(password, (
            "This machine cannot encrypt a stored credential — DPAPI is "
            "Windows-only. Use Windows Credential Manager instead: "
            f"cmdkey /add:{server['address']} /user:<account> /pass:<password>"))
    finally:
        password = None
    service.ipam_db.set_dhcp_credential(server_id, username, encrypted)
    service.log.add(IPAM_CATEGORY,
                    f"Stored a credential for DHCP server {server['label']}")
    _audit(service, params, "credential.store",
           target=f"dhcp:{server['address']}", detail=f"username {username}")
    return {"ok": True}


def delete_ipam_dhcp_server_credential(service, params, body, server_id) -> dict:
    server = _require(service.ipam_db.dhcp_server(server_id), "DHCP server")
    return _clear_credential(
        service, params,
        clear=functools.partial(service.ipam_db.clear_dhcp_credential, server_id),
        category=IPAM_CATEGORY,
        message=f"Cleared the stored credential for DHCP server {server['label']}",
        target=f"dhcp:{server['address']}")


def _scope_subnet(scope_id: str, mask: str) -> str | None:
    """The scope's own network, in CIDR form — its ScopeId is the network
    address and SubnetMask its mask, which together describe the subnet the
    scope belongs to. Deliberately not derived from start_ip/end_ip: those
    mark the dynamic range, which is often narrower than the full subnet
    once exclusions and static reservations are accounted for."""
    import ipaddress
    if not scope_id or not mask:
        return None
    try:
        return str(ipaddress.ip_network(f"{scope_id}/{mask}", strict=False))
    except ValueError:
        return None


def get_ipam_dhcp_scopes(service, params, body) -> dict:
    server_id = params.get("server_id")
    rows = service.ipam_db.dhcp_scopes(int(server_id) if server_id else None)

    # Grouped by (server_id, scope_id) rather than scope_id alone: two
    # different DHCP servers can each have a scope named the same thing
    # (10.20.3.0 is a popular choice everywhere), and this runs across
    # every server's leases at once when no server_id filter is given.
    by_scope: dict[tuple, list] = {}
    for lease in service.ipam_db.dhcp_leases(int(server_id) if server_id else None):
        by_scope.setdefault((lease["server_id"], lease["scope_id"]), []).append(lease)

    static_by_scope = service.ipam_db.static_in_scope(
        max(float(service.ipam_settings.get("dhcp_poll_interval_minutes", 15)) * 60 * 3, 3600))
    scopes = []
    for r in rows:
        leases = by_scope.get((r["server_id"], r["scope_id"]), [])
        static_ips = static_by_scope.get((r["server_id"], r["scope_id"]), [])
        reserved = sum(1 for row in leases if row["is_reservation"])
        leased = len(leases) - reserved
        total = scope_size(r["start_ip"], r["end_ip"])
        available = max(0, total - leased - reserved) if total is not None else None
        scopes.append({
            "id": r["id"], "server_id": r["server_id"], "server_label": r["server_label"],
            "scope_id": r["scope_id"], "name": r["name"], "start_ip": r["start_ip"],
            "end_ip": r["end_ip"], "mask": r["mask"], "state": r["state"],
            "lease_duration_s": r["lease_duration_s"], "description": r["description"],
            "router": r["router"], "subnet": _scope_subnet(r["scope_id"], r["mask"]),
            "polled": r["polled_ts"],
            "usage": {"leased": leased, "reserved": reserved,
                     "available": available, "total": total,
                     "static_in_use": len(static_ips)},
            "static_ips": static_ips,
        })
    return {"scopes": scopes}


def _ipam_static_in_use_rows(service, server_id: int | None, scope_id: str | None) -> list[dict]:
    """One lease-shaped row per `static_in_scope` host for the requested
    (server_id, scope_id): an address the poller sees answering inside a
    scope's dynamic range that holds no lease anywhere — "in use" the DHCP
    server never recorded. Same freshness argument get_ipam_dhcp_scopes
    uses, so the summary count and these rows never disagree."""
    fresh_s = max(
        float(service.ipam_settings.get("dhcp_poll_interval_minutes", 15)) * 60 * 3, 3600)
    static_by_scope = service.ipam_db.static_in_scope(fresh_s)
    labels = {(r["server_id"], r["scope_id"]): r["server_label"]
              for r in service.ipam_db.dhcp_scopes(server_id)}
    selected = []
    for (s_id, sc_id), hosts in static_by_scope.items():
        if server_id is not None and s_id != server_id:
            continue
        if scope_id and sc_id != scope_id:
            continue
        selected.extend((s_id, sc_id, host) for host in hosts)
    devices = (service.nodes_db.devices_by_addresses({h["ip"] for _, _, h in selected})
               if selected and service.nodes_db is not None else {})
    entries = [(s_id, sc_id, host,
                namelookup.device_name(devices.get(host["ip"])) or None)
               for s_id, sc_id, host in selected]

    unnamed_ips = {host["ip"] for _, _, host, name in entries if not name}
    dns_names = service.app_db.hostnames(unnamed_ips) if unnamed_ips else {}

    rows = []
    for s_id, sc_id, host, name in entries:
        hostname = name or dns_names.get(host["ip"])
        rows.append({
            "id": None, "server_id": s_id, "server_label": labels.get((s_id, sc_id)),
            "scope_id": sc_id, "ip": host["ip"], "mac": host["mac"],
            "hostname": hostname, "address_state": "in use, not leased",
            "lease_expires": None, "is_reservation": False,
            "in_use_only": True, "seen_source": host["seen_source"],
            "seen_detail": host["seen_detail"], "description": "",
            "polled": host["last_up"]})
    return rows


def get_ipam_dhcp_leases(service, params, body) -> dict:
    server_id = params.get("server_id")
    scope_id = params.get("scope_id")
    server_id_int = int(server_id) if server_id else None
    scope_id = scope_id or None
    rows = service.ipam_db.dhcp_leases(server_id_int, scope_id)
    leases = [
        {"id": r["id"], "server_id": r["server_id"], "server_label": r["server_label"],
         "scope_id": r["scope_id"], "ip": r["ip"], "mac": r["mac"],
         "hostname": r["hostname"], "address_state": r["address_state"],
         "lease_expires": r["lease_expires_ts"],
         "is_reservation": bool(r["is_reservation"]),
         "in_use_only": False, "seen_source": None, "seen_detail": None,
         "description": r["description"], "polled": r["polled_ts"]}
        for r in rows]
    leases.extend(_ipam_static_in_use_rows(service, server_id_int, scope_id))
    return {"leases": leases}


def get_ipam_dhcp_leases_export(service, params, body) -> dict:
    leases = get_ipam_dhcp_leases(service, params, body)["leases"]
    truncated = len(leases) > EXPORT_ROW_CAP
    leases = leases[:EXPORT_ROW_CAP]
    header = ["server_label", "scope_id", "ip", "mac", "hostname",
             "address_state", "lease_expires", "is_reservation",
             "in_use_only", "seen_detail", "description", "polled"]
    csv_rows = [[lease.get(key) for key in header] for lease in leases]
    return _csv_response("ipam-dhcp-leases", header, csv_rows, truncated=truncated,
                         cap=EXPORT_ROW_CAP)


def get_ipam_dhcp_scope_history(service, params, body) -> dict:
    """Leased/reserved/total over time for one scope, for the trend chart
    above its lease table. One point per DHCP poll that landed in the
    window — usually tens to a few hundred, never enough to need bucketing."""
    server_id = params.get("server_id")
    scope_id = params.get("scope_id", "")
    if not server_id or not scope_id:
        return {"points": []}
    t0, t1 = _window(params)
    rows = service.ipam_db.scope_usage_history(int(server_id), scope_id, t0, t1)
    return {"points": [
        {"ts": r["polled_ts"], "leased": r["leased"], "reserved": r["reserved"],
         "total": r["total"]}
        for r in rows]}

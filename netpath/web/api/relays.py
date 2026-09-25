"""Handlers: the SSH, WEB and wireless-AP device relays."""

from __future__ import annotations


from ... import configrx
from ... import sshterm, webrelay
from ... import permissions as _permissions

from ._shared import _audit, _is_admin, _require, _ssh_device_host


# ---------------------------------------------------------------------- SSH


def get_ssh_device(service, params, body, device_id) -> dict:
    """What the terminal window needs before it opens its socket: which
    device this is, whether it can log in without asking, and what is known
    about the device's host key. Gated on ("ssh", W) like the socket itself
    — there is no read-only half of "open a shell"."""
    device, host, port = _ssh_device_host(service, device_id)
    # nodes.js's displayName() precedence, the same one ConfigRX's device
    # list uses: the SNMP hostname wins unless the device is pinned to its
    # manual name, with the IP as the last resort. Resolved here, once — the
    # page shows what it is given rather than recomputing it.
    name = ((device["name"] if device["display_name_source"] == "manual" else None)
            or device["sys_name"] or device["name"] or device["ip"])
    available = configrx.paramiko_available()
    user_ssh = service.app_db.user_ssh(params.get("_username", ""))
    return {
        "device": {"id": device["id"], "ip": host, "name": name},
        "has_credential": bool(user_ssh and user_ssh["ssh_username"]
                               and user_ssh["ssh_password_enc"]),
        "ssh_port": port,
        "paramiko": {"available": available,
                     "message": "" if available else configrx.PARAMIKO_MISSING},
        "host_key": sshterm.stored_host_key(service, host, port),
    }


def ws_ssh_device(websocket, service, params, device_id) -> None:
    """The terminal's WebSocket. Hijacking: the connection is held for the
    whole session, so this takes the socket server.py already upgraded
    rather than a body, and returns nothing to serialise. server.py's
    _route has already established who is asking, that the page asking is
    this one (Origin), and that they hold ("ssh", W); the session token
    goes with them so the session can be ended the moment that sign-in is."""
    service.ssh_sessions.open(websocket, device_id,
                              params.get("_username", ""),
                              params.get("_client", ""),
                              params.get("_token", ""))


ws_ssh_device.hijack = True


# --------------------------------------------------------------- WEB relays
#
# These three routes open, list and close a short-lived TCP relay on this
# host to a device's web interface. Reasoning lives in netpath/webrelay.py;
# what matters here is that a caller never names the destination.


def _web_device_target(service, device_id):
    """(device row, address, scheme, port) for a relay, from the device row
    and nothing else — a body carrying a host and port would turn an
    account holding `web` into a general outbound proxy from this server.
    """
    device = _require(service.nodes_db.device(device_id), "device")
    address, scheme, port = webrelay.device_web_target(device)
    return device, address, scheme, port


def post_web_device_relay(service, params, body, device_id) -> dict:
    """Open a relay to one device's web interface and hand back its URL."""
    device, address, scheme, port = _web_device_target(service, device_id)
    relay = service.web_relays.open(
        device_id, params.get("_username", ""), params.get("_client", ""),
        params.get("_token", ""), params.get("_host", ""))
    _audit(service, params, "web.relay.open", target=f"device:{device['ip']}",
           detail=f"port {relay['port']} -> {address}:{port} ({scheme}), "
                  f"admitting {relay['client_ip']} only")
    return relay


def post_wireless_ap_relay(service, params, body, ap_id) -> dict:
    """Open a relay to one FortiAP's own web interface — the WIRELESS
    module's WEB button, gated on `web` rather than `wireless` for the
    same reason post_web_device_relay is: opening a listening port on this
    host is that module's business. The target is the AP's own IP, as its
    controller reports it, and the scheme/port from the wireless module's
    settings; nothing a caller sends can name a different address."""
    ap = _require(service.wireless_db.access_point(int(ap_id)), "access point")
    if not ap["ip"]:
        raise ValueError(
            "This access point has no IP address reported by its "
            "controller, so there is nowhere for a web tunnel to reach.")
    scheme = service.wireless_settings.get("ap_web_scheme", "https")
    if scheme not in webrelay.WEB_SCHEMES:
        scheme = "https"
    port = int(service.wireless_settings.get("ap_web_port")
              or webrelay.DEFAULT_WEB_PORTS[scheme])
    relay = service.web_relays.open_target(
        ap["ip"], scheme, port, params.get("_username", ""),
        params.get("_client", ""), params.get("_token", ""),
        params.get("_host", ""), ap_id=ap["id"], subject=ap["name"] or ap["wtp_id"])
    _audit(service, params, "web.relay.open", target=f"ap:{ap['ip']}",
          detail=f"port {relay['port']} -> {ap['ip']}:{port} ({scheme}), "
                 f"admitting {relay['client_ip']} only")
    return relay


def get_web_relays(service, params, body) -> dict:
    """Every relay this account has open. An administrator sees all of
    them, since they answer for a port being open on this host; everyone
    else sees only their own."""
    mine = None if _is_admin(service, params) else params.get("_username", "")
    return {"relays": service.web_relays.status(mine)}


def delete_web_relay(service, params, body, session_id) -> dict:
    """Close one relay. Its owner or an administrator — closing a port
    somebody else opened on this host is an administrator's business, and
    leaving one open that nobody can close is nobody's."""
    relay = service.web_relays.get(session_id)
    if relay is None:
        raise ValueError("That tunnel is not open")
    username = params.get("_username", "")
    if relay.app_user != username and not _is_admin(service, params):
        raise _permissions.Forbidden(
            "That web tunnel belongs to another account.")
    info = relay.info()
    service.web_relays.close(session_id, f"closed by {username}")
    _audit(service, params, "web.relay.close",
           target=f"device:{info['device_ip']}",
           detail=f"port {info['port']}, {info['connections']} connection(s), "
                  f"{info['bytes_to_device']} bytes to the device and "
                  f"{info['bytes_from_device']} back")
    return {"ok": True, "closed": info["session_id"]}

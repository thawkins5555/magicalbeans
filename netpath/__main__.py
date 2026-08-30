"""SappiWhere entry point.

The interface is in a browser. This starts the service and serves it.

    python -m netpath                    service console window
    python -m netpath --headless         no window, for a service manager

The console shows whether the server is up, who is connected, and lets you
change the port or restart it. Closing it stops the service.
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def default_db_path() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    folder = os.path.join(base, "netpath-monitor")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "netpath.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpath", description=__doc__)
    parser.add_argument("--db", default=default_db_path(),
                        help="path to the trace SQLite file")
    parser.add_argument("--flow-db", default=None,
                        help="path to the flow SQLite file (defaults next to --db)")
    parser.add_argument("--syslog-db", default=None,
                        help="path to the syslog SQLite file (defaults next to --db)")
    parser.add_argument("--app-db", default=None,
                        help="path to the application SQLite file holding "
                             "settings and accounts (defaults next to --db)")
    parser.add_argument("--ipam-db", default=None,
                        help="path to the IPAM SQLite file (defaults next to --db)")
    parser.add_argument("--snmp-db", default=None,
                        help="path to the SNMP trap SQLite file (defaults next to --db)")
    parser.add_argument("--nodes-db", default=None,
                        help="path to the Nodes SQLite file (defaults next to --db)")
    parser.add_argument("--alerts-db", default=None,
                        help="path to the Alerts SQLite file (defaults next to --db)")
    parser.add_argument("--add", action="append", default=[], metavar="HOST",
                        help="add a destination on startup (repeatable)")

    web = parser.add_argument_group("web server")
    web.add_argument("--headless", "--web", dest="headless", action="store_true",
                     help="run with no window, for a service manager")
    web.add_argument("--host", default=None,
                     help="interface to bind (default: the saved setting, or all)")
    web.add_argument("--port", type=int, default=None,
                     help="web server port (default: the saved setting, or 8443)")
    web.add_argument("--cert", default=None,
                     help="TLS certificate file; without it the server is plain HTTP")
    web.add_argument("--key", default=None,
                     help="TLS private key file (defaults to --cert)")
    return parser


def flow_path_for(args) -> str:
    if args.flow_db:
        return args.flow_db
    return os.path.join(os.path.dirname(args.db) or ".", "flows.db")


def syslog_path_for(args) -> str:
    if args.syslog_db:
        return args.syslog_db
    return os.path.join(os.path.dirname(args.db) or ".", "syslog.db")


def app_path_for(args) -> str:
    if args.app_db:
        return args.app_db
    return os.path.join(os.path.dirname(args.db) or ".", "app.db")


def ipam_path_for(args) -> str:
    if args.ipam_db:
        return args.ipam_db
    return os.path.join(os.path.dirname(args.db) or ".", "ipam.db")


def snmp_path_for(args) -> str:
    if args.snmp_db:
        return args.snmp_db
    return os.path.join(os.path.dirname(args.db) or ".", "snmptraps.db")


def nodes_path_for(args) -> str:
    if args.nodes_db:
        return args.nodes_db
    return os.path.join(os.path.dirname(args.db) or ".", "nodes.db")


def alerts_path_for(args) -> str:
    if args.alerts_db:
        return args.alerts_db
    return os.path.join(os.path.dirname(args.db) or ".", "alerts.db")


def build_service(args):
    """Open the databases, seed any destinations, and start the collectors."""
    from .web import Service

    service = Service(args.db, flow_path_for(args), syslog_path_for(args),
                      app_path_for(args), ipam_path_for(args),
                      snmp_path_for(args), nodes_path_for(args),
                      alerts_path_for(args))
    existing = {row["host"] for row in service.db.targets()}
    for host in args.add:
        if host not in existing:
            service.db.add_target(host)
    service.start()
    return service


def listener_for(service, args):
    """Command line wins for this run; otherwise the saved settings."""
    settings = service.settings
    host = args.host if args.host is not None else settings.get("web_host", "0.0.0.0")
    port = args.port if args.port is not None else int(settings.get("web_port", 8443))
    cert = args.cert if args.cert is not None else settings.get("web_cert", "") or None
    key = args.key if args.key is not None else settings.get("web_key", "") or None

    # Remember what was asked for, so the console and the next run agree.
    service.save_listener_settings(
        {"web_host": host, "web_port": port,
         "web_cert": cert or "", "web_key": key or ""})
    return host, port, cert, key


def run_headless(args) -> int:
    from . import selfupdate
    from .web import WebServer

    service = build_service(args)
    host, port, cert, key = listener_for(service, args)
    server = WebServer(service, host=host, port=port, certfile=cert, keyfile=key)
    # So a self-update releases the port and closes the databases before
    # spawning its replacement, not after — see schedule_restart()'s note.
    selfupdate.set_before_restart_hook(
        lambda: (server.stop(), service.shutdown()))

    if not server.start(block=False):
        print(server.error)
        service.shutdown()
        return 1

    print(f"SappiWhere serving on {server.url}")
    if not cert:
        print("  No certificate given, so this is plain HTTP. Pass --cert and "
              "--key to serve TLS.")
    print("  There is no authentication yet: bind somewhere you trust.")
    print("  Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        server.stop()
        service.shutdown()
    return 0


def run_console(args) -> int:
    """The service console: a window showing the server and who is on it."""
    from PySide6.QtWidgets import QApplication

    from . import selfupdate, theme
    from .console import ConsoleWindow, OutputCapture
    from .web import WebServer

    # Launched with pythonw.exe there is no terminal and both streams are None,
    # so capture them before anything can print into the void.
    capture = OutputCapture()
    capture.install()

    service = build_service(args)
    host, port, cert, key = listener_for(service, args)
    server = WebServer(service, host=host, port=port, certfile=cert, keyfile=key)
    # So a self-update releases the port and closes the databases before
    # spawning its replacement, not after — see schedule_restart()'s note.
    selfupdate.set_before_restart_hook(
        lambda: (server.stop(), service.shutdown()))
    server.start(block=False)          # the console reports a failure to bind

    app = QApplication(sys.argv)
    app.setApplicationName("SappiWhere")
    app.setStyleSheet(theme.STYLESHEET)
    app.setFont(theme.ui_font(10))

    window = ConsoleWindow(service, server, capture=capture)
    window.show()
    return app.exec()


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return run_headless(args) if args.headless else run_console(args)


if __name__ == "__main__":
    raise SystemExit(main())

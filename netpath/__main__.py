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
import signal
import sys
import threading


def default_db_path() -> str:
    """The data folder, created owner-only.

    Everything this application stores lives in one folder: the scrypt
    password hashes, the SNMP communities, the DPAPI blobs, every captured
    device config and the syslog history. It was being created 0755 with
    0644 files inside it, so any local account could read all of it. The
    mode is applied to a folder that already exists as well as to a new
    one — the whole point is the upgrade case, where the folder was made
    before this line existed. Windows has no meaningful POSIX mode and
    inherits its ACL from the profile directory, so it is left alone.
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    folder = os.path.join(base, "netpath-monitor")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.name != "nt":
        try:
            if os.stat(folder).st_mode & 0o077:
                os.chmod(folder, 0o700)
        except OSError:
            pass          # a folder someone deliberately shared; not ours to fight
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
    parser.add_argument("--wireless-db", default=None,
                        help="path to the Wireless SQLite file (defaults next to --db)")
    parser.add_argument("--configrx-db", default=None,
                        help="path to the ConfigRX SQLite file (defaults next to --db)")
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


def wireless_path_for(args) -> str:
    if args.wireless_db:
        return args.wireless_db
    return os.path.join(os.path.dirname(args.db) or ".", "wireless.db")


def configrx_path_for(args) -> str:
    if args.configrx_db:
        return args.configrx_db
    return os.path.join(os.path.dirname(args.db) or ".", "configrx.db")


def build_service(args):
    """Open the databases, seed any destinations, and start the collectors."""
    from .web import Service

    service = Service(args.db, flow_path_for(args), syslog_path_for(args),
                      app_path_for(args), ipam_path_for(args),
                      snmp_path_for(args), nodes_path_for(args),
                      alerts_path_for(args), wireless_path_for(args),
                      configrx_path_for(args))
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
        if host not in ("127.0.0.1", "localhost", "::1"):
            # Said plainly because it is true of every credential typed into
            # the UI and of the session cookie itself, and because the line
            # this replaces claimed the opposite — that there was no
            # authentication at all, which stopped being true in 4.22.
            print(f"  WARNING: serving on {host} without TLS. Sign-ins, "
                  f"session cookies and every credential typed into the "
                  f"interface cross the network in the clear.")
    print("  Sign in with an account; the seeded admin must change its "
          "password before it can do anything else.")
    print("  Ctrl+C to stop.")

    stop_event = threading.Event()

    def _request_stop(signum, frame) -> None:
        # Only sets a flag. The actual cleanup runs below, on the normal
        # control flow once the wait returns — not inside a signal handler,
        # which can land while the interpreter is anywhere at all.
        stop_event.set()

    # SIGTERM (systemctl stop / nssm stop) defaults to killing the process
    # outright, skipping the `finally` below — SIGBREAK is what NSSM actually
    # sends on Windows. Guarded: signal.signal raises off the main thread, so
    # that degrades to Ctrl+C-only rather than crashing on startup.
    for _sig_name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        _sig = getattr(signal, _sig_name, None)
        if _sig is None:
            continue          # SIGBREAK only exists on Windows
        try:
            signal.signal(_sig, _request_stop)
        except (ValueError, OSError):
            pass

    try:
        stop_event.wait()
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
    # The console accepts its close immediately and tears down on a thread of
    # its own (see ConsoleWindow.closeEvent), so the last window closing must
    # not end app.exec() — that would drop into interpreter shutdown while the
    # teardown is still running. The teardown's own completion ends the
    # process instead.
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("SappiWhere")
    app.setStyleSheet(theme.STYLESHEET)
    app.setFont(theme.ui_font(10))

    window = ConsoleWindow(service, server, capture=capture)
    window.show()
    return app.exec()


def _line_buffer_stdio() -> None:
    """Make stdout and stderr flush on every newline, not just when full.

    CPython only line-buffers a stream connected to a terminal; redirected to
    a file or a pipe — exactly what a service manager gives it — it switches
    to block buffering and can hold output for hours with the server already
    answering requests, including the "serving ... without TLS" warning that
    exists to reach someone before they type a password into an unencrypted
    page. Reconfigured once, here, rather than chasing flush=True per call site.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue          # pythonw.exe leaves this None; nothing to buffer
        try:
            reconfigure(line_buffering=True)
        except (AttributeError, ValueError, OSError):
            pass               # already detached or replaced; leave it alone


def main(argv=None) -> int:
    _line_buffer_stdio()
    args = build_parser().parse_args(argv)
    code = run_headless(args) if args.headless else run_console(args)
    # os._exit, not a return into interpreter shutdown.
    #
    # Two things there are unbounded. concurrent.futures joins every
    # ThreadPoolExecutor thread with no timeout — they are not daemons, and
    # cancel_futures only drops work that had not started — so a poll,
    # traceroute or subnet sweep still in flight held the process open long
    # after the service had stopped and the window had gone. And the
    # self-updater's own threads are deliberately not daemons either. That is
    # the no-window-but-still-running state operators end from Task Manager,
    # and a service manager's "stop" that never completes.
    #
    # Both callers above have already closed every store by the time they
    # return, so there is nothing left to flush but the streams. It is at
    # this layer rather than inside run_headless/run_console so both stay
    # drivable from a test.
    #
    # Except underneath a self-update: its restart thread is deliberately
    # not a daemon and sleeps a moment before spawning the replacement, and
    # exiting inside that window would install the update and leave nothing
    # running. That thread ends in os._exit/execv itself, so waiting on it
    # is waiting for the right exit.
    from . import selfupdate
    if not selfupdate.wait_for_job(300.0):
        selfupdate._log_restart("main() exiting with an update still in flight")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    raise SystemExit(main())

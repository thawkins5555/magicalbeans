#!/usr/bin/env python3
"""Drives ConfigRX's capture functions directly against demo/fake_ssh.py.

On Linux the ConfigRX worker never reaches its SSH code: the stored
password is DPAPI-only (netpath/dpapi.py), so backup_now() always records
"No SSH credential stored". This probe bypasses that gate and calls the
same _pull_config / _clean_output / _capture_problem chain the worker
would, so the capture logic itself can be reviewed on a non-Windows host.

    python3 demo/fake_ssh.py &        # then
    python3 demo/configrx_probe.py [--base-port 2201] [--max-s 20]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko  # noqa: E402

from netpath import configrx, configrx_vendors  # noqa: E402
from demo.fake_ssh import PERSONAS  # noqa: E402

VENDOR_FOR = {"cisco": "cisco", "cisco-pager": "cisco", "cisco-truncate": "cisco",
              "fortinet": "fortinet", "mikrotik": "mikrotik", "menu": "cisco",
              "unprivileged": "cisco", "cisco-nxos": "cisco-nxos",
              "cisco-iosxr": "cisco-iosxr",
              "cisco-sb-reject-then-page": "cisco-sb", "cisco-asa": "cisco-asa",
              "cisco-wlc": "cisco-wlc"}
# The one persona whose vendor needs an enable secret at all — everyone
# else's _pull_config call below passes "" and never uses it.
ENABLE_SECRET_FOR = {"cisco-asa": "demo"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-port", type=int, default=2201)
    ap.add_argument("--max-s", type=float, default=20.0)
    args = ap.parse_args()
    rows = []
    for i, name in enumerate(PERSONAS):
        port = args.base_port + i
        vendor = configrx_vendors.resolve(VENDOR_FOR[name])
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        t0 = time.time()
        try:
            client.connect("127.0.0.1", port=port, username="admin", password="demo",
                           timeout=10, look_for_keys=False, allow_agent=False)
            raw, ended = configrx._pull_config(
                client, vendor, max_s=args.max_s,
                enable_secret=ENABLE_SECRET_FOR.get(name, ""))
        except Exception as exc:
            rows.append((name, "connect/pull error", str(exc)[:80], 0, round(time.time() - t0, 1)))
            continue
        finally:
            client.close()
        cleaned = configrx._clean_output(raw)
        problem = configrx._capture_problem(cleaned, ended)
        rows.append((name, ended, problem or "STORED", len(cleaned.strip()),
                     round(time.time() - t0, 1)))
    print(f"{'persona':16} {'ended':11} {'chars':>6} {'secs':>5}  verdict")
    for name, ended, verdict, chars, secs in rows:
        print(f"{name:16} {ended:11} {chars:>6} {secs:>5}  {verdict}")


if __name__ == "__main__":
    main()

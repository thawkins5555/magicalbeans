"""Test that app.db, wireless.db, and configrx.db reclaim space after pruning.

Pattern of test_alert_engine_fixes.py lines 1113-1155: each database that
implements incremental auto-vacuum via dbmaint should shrink after its prune
method deletes rows, without needing an explicit VACUUM statement.
"""
import json
import os
import sqlite3
import tempfile
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.appdb import AppDatabase
from netpath.wirelessdb import WirelessDatabase
from netpath.configrxdb import ConfigRxDatabase
from netpath.nodesdb import NodesDatabase

TMPDIR = tempfile.mkdtemp(prefix="db_reclaim_")
PASSED = []


def ok(message: str):
    PASSED.append(message)
    print(f"✓ {message}")


# ================================================================= AppDatabase
print("\nAppDatabase reclaims space after prune")

folder = os.path.join(TMPDIR, "app")
os.makedirs(folder, exist_ok=True)
app_path = os.path.join(folder, "app.db")
app_db = AppDatabase(app_path)

assert app_db._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
ok("a fresh app.db is in incremental auto-vacuum mode")

# Insert many hostnames to grow the file
# Use an old timestamp so they'll be pruned
old_time = time.time() - 100000  # Very old entries
padding = "x" * 400
for i in range(5000):
    # Insert directly with old timestamp, using unique IPs
    app_db._conn.execute(
        "INSERT INTO hostnames(ip, hostname, resolved_ts) VALUES (?,?,?)",
        (f"192.0.{(i // 256) % 256}.{i % 256}", f"host-{i}-{padding}", old_time))
app_db._conn.commit()

before = app_db.size_bytes()
assert before > 300_000, before
ok(f"hostnames table grew to {before // 1024} KiB")

# Prune everything (entries are ~27 hours old, so use 1 day retention)
removed = app_db.prune_hostnames(older_than_days=1.0)
assert removed > 0, removed
ok(f"prune_hostnames removed {removed} rows")

after = app_db.size_bytes()
assert after < before, (before, after)
ok(f"file shrank from {before // 1024} KiB to {after // 1024} KiB without VACUUM")

app_db.close()

# Test asn_cache prune as well
app_db2 = AppDatabase(app_path)
assert app_db2._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2

# Insert many ASN entries with old timestamp
old_time = time.time() - 100000
for i in range(5000):
    # Insert directly with old timestamp
    app_db2._conn.execute(
        "INSERT INTO asn_cache(ip, asn, org, resolved_ts) VALUES (?,?,?,?)",
        (f"10.0.{(i // 256) % 256}.{i % 256}", 65000 + i, f"org-{i}-" + "x" * 400, old_time))
app_db2._conn.commit()

before2 = app_db2.size_bytes()
assert before2 > 300_000, before2
ok(f"asn_cache table grew to {before2 // 1024} KiB")
removed2 = app_db2.prune_asn_cache(older_than_days=1.0)
assert removed2 > 0, removed2
after2 = app_db2.size_bytes()
assert after2 < before2, (before2, after2)
ok(f"prune_asn_cache shrank the file ({before2 // 1024} KiB -> {after2 // 1024} KiB)")

app_db2.close()


# ============================================================ WirelessDatabase
print("\nWirelessDatabase reclaims space after prune_ap_events")

folder = os.path.join(TMPDIR, "wireless")
os.makedirs(folder, exist_ok=True)
wireless_path = os.path.join(folder, "wireless.db")
wireless_db = WirelessDatabase(wireless_path)

assert wireless_db._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
ok("a fresh wireless.db is in incremental auto-vacuum mode")

# Insert a controller
controller_id = wireless_db.add_controller("TestController", "192.0.2.1")

# Insert many AP events to grow the file with old timestamp
old_time = time.time() - 100000
for i in range(4000):
    # Insert directly with old timestamp
    wireless_db._conn.execute(
        "INSERT INTO ap_events(ts, controller_id, wtp_id, vdom, name, kind, detail)"
        " VALUES (?,?,?,?,?,?,?)",
        (old_time, controller_id, f"wtp-{i}", "vdom0", f"AP-{i}", "ap_online", "x" * 400)
    )
wireless_db._conn.commit()

before = wireless_db.size_bytes()
assert before > 300_000, before
ok(f"ap_events table grew to {before // 1024} KiB")

# Prune all events (entries are ~27 hours old)
removed = wireless_db.prune_ap_events(retention_days=1.0)
assert removed > 0, removed
ok(f"prune_ap_events removed {removed} rows")

after = wireless_db.size_bytes()
assert after < before, (before, after)
ok(f"file shrank from {before // 1024} KiB to {after // 1024} KiB without VACUUM")

wireless_db.close()

# Reopen to verify mode survives
reopened = WirelessDatabase(wireless_path)
assert reopened._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
reopened.close()
ok("incremental auto-vacuum mode survives a reopen")


# ============================================================ ConfigRxDatabase
print("\nConfigRxDatabase reclaims space after prune")

folder = os.path.join(TMPDIR, "configrx")
os.makedirs(folder, exist_ok=True)
configrx_path = os.path.join(folder, "configrx.db")
configrx_db = ConfigRxDatabase(configrx_path)

assert configrx_db._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
ok("a fresh configrx.db is in incremental auto-vacuum mode")

# Insert many backups to grow the file with old timestamp
import hashlib
import zlib
old_time = time.time() - 100000
payload = "x" * 10000  # Large backup payload
for i in range(300):
    device_id = i + 1
    for j in range(10):
        content = f"{payload}-{i}-{j}".encode("utf-8")
        raw = content
        digest = hashlib.sha256(raw).hexdigest()
        compressed = zlib.compress(raw)
        configrx_db._conn.execute(
            "INSERT INTO backups(device_id, ts, content_gz, sha256, size_bytes, redacted)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, old_time, compressed, digest, len(raw), 0)
        )
configrx_db._conn.commit()

before = configrx_db.size_bytes()
assert before > 300_000, before
ok(f"backups table grew to {before // 1024} KiB")

# Prune with retention_days=1 so everything old is gone
removed = configrx_db.prune(retention_days=1.0, retention_count_per_device=0)
assert removed > 0, removed
ok(f"prune removed {removed} rows")

after = configrx_db.size_bytes()
assert after < before, (before, after)
ok(f"file shrank from {before // 1024} KiB to {after // 1024} KiB without VACUUM")

configrx_db.close()

# Reopen to verify mode survives
reopened = ConfigRxDatabase(configrx_path)
assert reopened._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
reopened.close()
ok("incremental auto-vacuum mode survives a reopen")


print(f"\nALL {len(PASSED)} DB-RECLAIM ASSERTIONS PASSED")

"""A credential the operator was told was saved has to survive a power cut.

Four of the stores holding operator-entered secrets run WAL with
`synchronous=NORMAL`, which never corrupts the file but does not fsync at
commit: an OS crash can lose transactions SQLite already reported committed.
That is the right trade for nodes.db's per-poll `record_poll` (≈17 commits a
second at the shipped fleet size) and the wrong one for the handful of writes
a year that store an SSH password, an SNMPv3 passphrase or the SMTP
credential — after which ConfigRX quietly stops backing a device up, or the
alert about the mail relay failing cannot be mailed.

So the credential writers, and only they, commit durably:
`SqliteStore._commit_durable` commits and then runs
`PRAGMA wal_checkpoint(FULL)`, which forces the log back into the database
file and syncs it.

How that is checked here: the `.db` file is copied on its own, without its
`-wal` companion, and opened. What that copy can see is what has actually
reached the database file. An ordinary write is invisible in it (it is still
only in the log, which is the shipped behaviour and not a defect); a
credential write is there.

The last section is the same question asked under load: a FULL checkpoint
cannot run past another connection's read lock, and says so in the first
column of its result row rather than raising. That answer used to be dropped,
so a credential save under a concurrent reader reported success with the row
still only in the log.
"""
import logging
import os
import shutil
import sqlite3
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.configrxdb import ConfigRxDatabase
from netpath.nodesdb import NodesDatabase
from netpath.wirelessdb import WirelessDatabase

TMP = _paths.tmpdir("credential_durability_")
FAILS = []
SEQ = [0]


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def settled(store):
    """Open the store, then close and reopen it so the schema and seeding are
    already in the database file — closing the last connection checkpoints
    and truncates the WAL. Without this every query below would be answered
    out of the log and prove nothing."""
    store.close()
    return type(store)(store.path)


def in_database_file(store, sql, params=()):
    """What a reader that has only the `.db` file can see — i.e. what the
    writer has actually pushed out of the WAL."""
    SEQ[0] += 1
    copy = os.path.join(TMP, f"snapshot{SEQ[0]}.db")
    shutil.copyfile(store.path, copy)
    conn = sqlite3.connect(copy)
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


SECRET = b"\x01encrypted-blob\x02"


def holds(row, index=0) -> bool:
    """Whether that column of the copied row is the secret. Tolerant of a
    missing row and a NULL, which is what a lost transaction looks like."""
    return bool(row) and row[index] is not None and bytes(row[index]) == SECRET


# ------------------------------------------------- nodes.db (three writers)

nodes = NodesDatabase(os.path.join(TMP, "nodes.db"))
group_id = nodes.ensure_default_group()
device_id = nodes.add_device("10.0.0.1", "core-sw-1", group_id=group_id)
credential_id = nodes.add_group_credential(group_id, label="second",
                                           snmp_version=3, v3_user="noc")
nodes = settled(nodes)

# The control: an ordinary write is NOT forced out, which is the behaviour
# the poller's hot path depends on. If this ever starts passing, the whole
# store has been flipped to synchronous=FULL and the trade-off has changed.
nodes.update_device(device_id, name="renamed-in-the-log")
row = in_database_file(nodes, "SELECT name FROM devices WHERE id = ?",
                       (device_id,))
check("an ordinary device write is still only in the log (the cheap commit"
      " the poller needs is unchanged)",
      row[0] == "core-sw-1", row)

nodes.set_device_credential(device_id, "noc", "SHA", SECRET,
                            priv_proto="AES", priv_enc=SECRET)
row = in_database_file(
    nodes, "SELECT v3_auth_pass_enc, v3_priv_pass_enc FROM devices WHERE id = ?",
    (device_id,))
check("a device credential has reached the database file by the time"
      " set_device_credential returns",
      holds(row, 0) and holds(row, 1), row)

nodes.set_group_credential(group_id, "noc", "SHA", SECRET)
row = in_database_file(nodes, "SELECT v3_auth_pass_enc FROM groups WHERE id = ?",
                       (group_id,))
check("...and a polling profile's credential", holds(row), row)

nodes.set_group_credential_password(credential_id, "noc2", "SHA", SECRET)
row = in_database_file(
    nodes, "SELECT v3_auth_pass_enc FROM group_credentials WHERE id = ?",
    (credential_id,))
check("...and an additional credential on a profile", holds(row), row)

# The durable commit is a commit: the ordinary write that was waiting in the
# log goes out with it, and the store reads the same either way.
pending = in_database_file(nodes, "SELECT name FROM devices WHERE id = ?",
                           (device_id,))
check("the write that was pending in the log went out with it, not lost",
      bool(pending) and pending[0] == "renamed-in-the-log", pending)
check("and the store itself reads back what was written",
      nodes.device(device_id)["name"] == "renamed-in-the-log")
nodes.close()


# ---------------------------------------------- configrx.db (two writers)

configrx = settled(ConfigRxDatabase(os.path.join(TMP, "configrx.db")))
configrx.set_credential(7, "admin", SECRET)
row = in_database_file(
    configrx, "SELECT ssh_username, ssh_password_enc FROM device_config"
              " WHERE device_id = ?", (7,))
check("an SSH password has reached configrx.db by the time set_credential"
      " returns",
      bool(row) and row[0] == "admin" and holds(row, 1), row)

configrx.set_enable_secret(7, SECRET)
row = in_database_file(
    configrx, "SELECT enable_secret_enc FROM device_config WHERE device_id = ?",
    (7,))
check("...and an enable secret set on its own", holds(row), row)
configrx.close()


# ------------------------------------------------------------ wireless.db

wireless = WirelessDatabase(os.path.join(TMP, "wireless.db"))
controller_id = wireless.add_controller("wlc-1", "10.0.0.9", snmp_version=3,
                                        v3_user="noc")
wireless = settled(wireless)
wireless.set_credential(controller_id, SECRET)
row = in_database_file(
    wireless, "SELECT v3_auth_pass_enc FROM controllers WHERE id = ?",
    (controller_id,))
check("a wireless controller's credential has reached wireless.db",
      holds(row), row)
wireless.close()


# -------------------------------------------------------------- alerts.db

alerts = settled(AlertsDatabase(os.path.join(TMP, "alerts.db")))
alerts.set_smtp_credential(SECRET)
row = in_database_file(alerts,
                       "SELECT password_enc FROM smtp_credential WHERE id = 1")
check("the SMTP password has reached alerts.db", holds(row), row)
check("...and the store still reports it holds one",
      alerts.smtp_password_enc() == SECRET)
alerts.close()

# ------------------------------------- nodes.db, with a reader on the file
#
# `PRAGMA wal_checkpoint(FULL)` returns (busy, log_frames, backfilled) and
# does not raise: a 1 in the first column means another connection's read
# lock stopped it and the frames it could not copy are still in the log
# alone. _commit_durable ignored that row entirely, so this -- a poll or a
# search running while somebody saves an SSH password, which is the ordinary
# state of a busy install -- returned success having stored nothing in the
# database file.
#
# The store's busy_timeout is wound down for these two cases. At the shipped
# 5 s the first attempt blocks for the whole of it before reporting busy,
# which would make this section a ten-second test and would hide the retry
# behind a timeout long enough to outlast any reader a test can hold.


class Reader:
    """A second connection holding an open read transaction on the store."""

    def __init__(self, path):
        self.path = path
        self.holding = threading.Event()
        self.release = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        assert self.holding.wait(5), "the reader never took its lock"

    def _run(self):
        conn = sqlite3.connect(self.path)
        conn.execute("BEGIN")
        conn.execute("SELECT name FROM devices").fetchall()
        self.holding.set()
        self.release.wait(30)
        conn.execute("ROLLBACK")
        conn.close()

    def let_go(self):
        self.release.set()
        self._thread.join(5)


busy_nodes = NodesDatabase(os.path.join(TMP, "nodes_busy.db"))
busy_group = busy_nodes.ensure_default_group()
busy_device = busy_nodes.add_device("10.0.0.2", "core-sw-2", group_id=busy_group)
busy_nodes = settled(busy_nodes)
with busy_nodes._lock:
    busy_nodes._conn.execute("PRAGMA busy_timeout=50")

# 1. A reader that lets go while the retries are still running. The write
#    must reach the database file, which is what the caller was promised.
reader = Reader(busy_nodes.path)


def release_shortly():
    # Long enough that the first attempt is certainly refused (the store's
    # busy_timeout is 50 ms here), short enough that the retry window still
    # covers it.
    time.sleep(0.15)
    reader.let_go()


threading.Thread(target=release_shortly, daemon=True).start()
started = time.monotonic()
busy_nodes.set_device_credential(busy_device, "noc", "SHA", SECRET,
                                 priv_proto="AES", priv_enc=SECRET)
elapsed = time.monotonic() - started
row = in_database_file(
    busy_nodes,
    "SELECT v3_auth_pass_enc FROM devices WHERE id = ?", (busy_device,))
check("a credential saved while another connection holds a read lock still "
      "reaches the database file, once that reader lets go",
      holds(row), row)
check("...and the retry is bounded, not a wait on the reader",
      elapsed < 3.0, f"{elapsed:.2f}s")

# 2. A reader that never lets go. The checkpoint genuinely cannot run, and
#    the point of the fix is that this is now said rather than swallowed.
stubborn = Reader(busy_nodes.path)
records = []


class Capture(logging.Handler):
    def emit(self, record):
        records.append(record)


sqlitebase_log = logging.getLogger("netpath.sqlitebase")
handler = Capture()
sqlitebase_log.addHandler(handler)
previous_level = sqlitebase_log.level
sqlitebase_log.setLevel(logging.WARNING)
try:
    started = time.monotonic()
    busy_nodes.set_group_credential(busy_group, "noc", "SHA", SECRET)
    stuck_elapsed = time.monotonic() - started
finally:
    sqlitebase_log.removeHandler(handler)
    sqlitebase_log.setLevel(previous_level)
    stubborn.let_go()

warnings = [r for r in records if r.levelno >= logging.WARNING]
check("a checkpoint that could not run at all is logged, not swallowed",
      len(warnings) == 1, [r.getMessage() for r in records])
check("...and the line names the file and says the row is readable but not "
      "yet safe from a power loss",
      bool(warnings) and "nodes_busy.db" in warnings[0].getMessage()
      and "write-ahead log" in warnings[0].getMessage(),
      warnings[0].getMessage() if warnings else None)
check("...and it still returns promptly rather than blocking on the reader",
      stuck_elapsed < 3.0, f"{stuck_elapsed:.2f}s")
check("...and the row is readable through the store all the same",
      busy_nodes.group(busy_group)["v3_auth_pass_enc"] == SECRET)
busy_nodes.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

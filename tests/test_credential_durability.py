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
"""
import os
import shutil
import sqlite3

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
      row is not None and bytes(row[0]) == SECRET and bytes(row[1]) == SECRET,
      row)

nodes.set_group_credential(group_id, "noc", "SHA", SECRET)
row = in_database_file(nodes, "SELECT v3_auth_pass_enc FROM groups WHERE id = ?",
                       (group_id,))
check("...and a polling profile's credential",
      row is not None and bytes(row[0]) == SECRET, row)

nodes.set_group_credential_password(credential_id, "noc2", "SHA", SECRET)
row = in_database_file(
    nodes, "SELECT v3_auth_pass_enc FROM group_credentials WHERE id = ?",
    (credential_id,))
check("...and an additional credential on a profile",
      row is not None and bytes(row[0]) == SECRET, row)

# The durable commit is a commit: the ordinary write that was waiting in the
# log goes out with it, and the store reads the same either way.
check("the write that was pending in the log went out with it, not lost",
      in_database_file(nodes, "SELECT name FROM devices WHERE id = ?",
                       (device_id,))[0] == "renamed-in-the-log")
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
      row is not None and row[0] == "admin" and bytes(row[1]) == SECRET, row)

configrx.set_enable_secret(7, SECRET)
row = in_database_file(
    configrx, "SELECT enable_secret_enc FROM device_config WHERE device_id = ?",
    (7,))
check("...and an enable secret set on its own",
      row is not None and bytes(row[0]) == SECRET, row)
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
      row is not None and bytes(row[0]) == SECRET, row)
wireless.close()


# -------------------------------------------------------------- alerts.db

alerts = settled(AlertsDatabase(os.path.join(TMP, "alerts.db")))
alerts.set_smtp_credential(SECRET)
row = in_database_file(alerts,
                       "SELECT password_enc FROM smtp_credential WHERE id = 1")
check("the SMTP password has reached alerts.db",
      row is not None and bytes(row[0]) == SECRET, row)
check("...and the store still reports it holds one",
      alerts.smtp_password_enc() == SECRET)
alerts.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

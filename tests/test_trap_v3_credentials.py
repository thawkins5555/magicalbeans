"""Where the trap receiver's SNMPv3 authentication passwords live.

The password used to be an ordinary line of the `v3_users` settings row —
plain JSON in snmp.db, and handed to the browser by /api/config for every
account holding `snmp: read`. It now lives encrypted in `trap_v3_users`,
and the settings value carries only "name / SHA".

What this pins:

  1. a save through SnmpTrapDatabase puts no passphrase in the database
     file and none in settings() — the dict /api/config serves;
  2. the receiver still verifies a real signed v3 trap after a restart, so
     the credential survives the round trip through encryption;
  3. a save whose line carries no password keeps the stored one, and a
     name dropped from the textarea loses its password with its line;
  4. a database still holding a plaintext password is migrated on open,
     once, and the receiver goes on verifying that user's traps.

Plain script, no pytest. One real UDP datagram on a free loopback port for
step 2, everything else against the store and the decoder directly.
"""
import hmac
import os
import shutil
import socket
import sqlite3
import stat
import sys
import time

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import free_udp_port, tmpdir

TMPDIR = tmpdir("trap_v3_credentials_")

# A credential store of this suite's own, before anything imports dpapi:
# the file source, since that is the one an unattended service is meant to
# use, and a salt inside TMPDIR so the run leaves nothing in the real data
# directory.
_PASSPHRASE_PATH = os.path.join(TMPDIR, "passphrase.txt")
with open(_PASSPHRASE_PATH, "w", encoding="utf-8") as _fh:
    _fh.write("trap v3 credentials suite passphrase, not used anywhere else\n")
os.chmod(_PASSPHRASE_PATH, stat.S_IRUSR | stat.S_IWUSR)
os.environ["NETPATH_SECRET_PASSPHRASE_FILE"] = _PASSPHRASE_PATH
os.environ.pop("NETPATH_SECRET_PASSPHRASE", None)

import netpath.secretstore as secretstore  # noqa: E402

secretstore._salt_path = lambda: os.path.join(TMPDIR, "install.salt")
secretstore._key_cache.clear()

from netpath import dpapi  # noqa: E402
from netpath.snmptrapd import TrapCollector  # noqa: E402
from netpath.snmptrapdb import SnmpTrapDatabase  # noqa: E402
from netpath.trapdecode import AUTH_PROTOCOLS, Decoder, localized_key  # noqa: E402

PASSPHRASE = "correcthorsebatterystaple"
ENGINE = b"\x80\x00\x1f\x88\x80" + b"engine"

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILURES.append(message)


def db_path(name: str) -> str:
    return os.path.join(TMPDIR, name)


def file_bytes(path: str) -> bytes:
    """The store's whole on-disk footprint: a value that is only out of the
    main file because it is still in the write-ahead log is still on the
    disk somebody walks off with."""
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        try:
            with open(path + suffix, "rb") as fh:
                blob += fh.read()
        except FileNotFoundError:
            pass
    return blob


def wait_for(predicate, timeout_s: float = 8.0, step_s: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step_s)
    return False


def send_udp(port: int, payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
    finally:
        sock.close()


# ------------------------------------------------------------ a signed trap

def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _int_tlv(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(length, "big"))


def _oid_tlv(oid: str) -> bytes:
    arcs = [int(part) for part in oid.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def v3_trap(user: str, engine_id: bytes, digest: bytes) -> bytes:
    """An SNMPv3 authNoPriv snmpV2-Trap carrying `digest` as its
    msgAuthenticationParameters — test_collectors_hardening's builder."""
    header = _tlv(0x30, _int_tlv(1) + _int_tlv(65507)
                  + _tlv(0x04, b"\x01") + _int_tlv(3))     # msgFlags: auth
    usm = _tlv(0x30,
               _tlv(0x04, engine_id) + _int_tlv(1) + _int_tlv(100)
               + _tlv(0x04, user.encode()) + _tlv(0x04, digest) + _tlv(0x04, b""))
    varbinds = _tlv(0x30,
                    _tlv(0x30, _oid_tlv("1.3.6.1.2.1.1.3.0")
                         + _tlv(0x43, b"\x00\x01\x00\x00"))
                    + _tlv(0x30, _oid_tlv("1.3.6.1.6.3.1.1.4.1.0")
                           + _oid_tlv("1.3.6.1.6.3.1.1.5.3")))
    pdu = _tlv(0xA7, _int_tlv(1) + _int_tlv(0) + _int_tlv(0) + varbinds)
    scoped = _tlv(0x30, _tlv(0x04, engine_id) + _tlv(0x04, b"") + pdu)
    return _tlv(0x30, _int_tlv(3) + header + _tlv(0x04, usm) + scoped)


def signed_v3_trap(user: str, proto: str, password: str) -> bytes:
    """The same trap, signed the way a real agent signs one: the digest
    computed over the message with the digest field blanked, then spliced
    back into that field."""
    ctor, digest_len = AUTH_PROTOCOLS[proto]
    blank = v3_trap(user, ENGINE, b"\x00" * digest_len)
    marker = bytes([0x04, digest_len]) + b"\x00" * digest_len
    at = blank.find(marker)
    assert at != -1 and blank.find(marker, at + 1) == -1, "digest field not unique"
    start = at + 2
    key = localized_key(proto, password, ENGINE)
    digest = hmac.new(key, blank, ctor).digest()[:digest_len]
    return blank[:start] + digest + blank[start + digest_len:]


# --------------------------------------------------------------------- V1

def test_v1_a_saved_password_never_reaches_the_file_or_the_api() -> None:
    """The finding, reproduced: settings() returned 'noc / SHA / <pass>' and
    snmp.db held the passphrase in a plain JSON settings row, which
    /api/config then handed to every account with `snmp: read`."""
    print("V1: a saved v3 password is in neither the database file nor settings()")

    path = db_path("v1.db")
    db = SnmpTrapDatabase(path)
    try:
        db.save_settings({"v3_users": f"noc / SHA / {PASSPHRASE}\n",
                          "accept_v3": True})
        settings = db.settings()
        check(PASSPHRASE not in settings["v3_users"],
              f"settings()['v3_users'] carries no password ({settings['v3_users']!r})")
        check(settings["v3_users"] == "noc / SHA",
              "just the name and the protocol, in the textarea's own format")
        check(not any(PASSPHRASE in str(value) for value in settings.values()),
              "and no other settings value carries it either")
        check(settings["v3_users_stored"] == 1,
              "v3_users_stored says one password is on file")
        check(db.v3_user_secret("noc") == PASSPHRASE,
              "the receiver can still read it back by name")
        check(db.v3_user_secret("nobody") is None,
              "and gets None for a user that has none")
    finally:
        db.close()

    check(PASSPHRASE.encode() not in file_bytes(path),
          "the passphrase is nowhere in snmp.db's bytes")
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'v3_users'").fetchone()
        check(row is not None and PASSPHRASE not in row[0],
              f"the settings row itself holds only names ({row and row[0]!r})")
        stored = conn.execute(
            "SELECT name, auth_proto, auth_pass_enc FROM trap_v3_users").fetchall()
        check(len(stored) == 1 and stored[0][0] == "noc" and stored[0][1] == "SHA",
              "trap_v3_users holds the user")
        check(bool(stored[0][2]) and PASSPHRASE.encode() not in bytes(stored[0][2]),
              "with the password as an encrypted blob")
        check(dpapi.unprotect(bytes(stored[0][2])).decode() == PASSPHRASE,
              "that decrypts back to what was typed")
    finally:
        conn.close()


# --------------------------------------------------------------------- V2

def test_v2_a_real_trap_still_verifies_after_a_restart() -> None:
    """The credential is only worth encrypting if the receiver can still use
    it: a second TrapCollector over the same database, configured from
    settings() alone (which has no password in it), must verify a genuinely
    signed trap."""
    print("V2: a signed v3 trap still authenticates after a restart")

    path = db_path("v2.db")
    db = SnmpTrapDatabase(path)
    db.save_settings({"v3_users": f"noc / SHA / {PASSPHRASE}"})
    db.close()

    db = SnmpTrapDatabase(path)
    traps = TrapCollector(db)
    port = free_udp_port()
    settings = {**db.settings(), "bind_address": "127.0.0.1", "port": port}
    check(PASSPHRASE not in str(settings),
          "the settings the collector is started with carry no password")
    assert traps.start(settings)
    try:
        send_udp(port, signed_v3_trap("noc", "SHA", PASSPHRASE))
        check(wait_for(lambda: db.max_id() == 1),
              "the trap is stored")
        row = db.traps_since(0)[0]
        check(row["auth_state"] == "ok",
              f"and its authentication verified (auth_state={row['auth_state']!r})")
        check(traps.counters["bad_auth"] == 0,
              "with nothing counted as a failed authentication")

        send_udp(port, v3_trap("noc", ENGINE, b"\x00" * 12))
        check(wait_for(lambda: traps.counters["bad_auth"] == 1),
              "a forged trap for the same user is still rejected")
    finally:
        traps.stop()
        db.close()


# --------------------------------------------------------------------- V3

def test_v3_a_save_without_the_password_keeps_it() -> None:
    """What the Settings dialog posts back when nobody retyped the password:
    the "name / SHA" lines settings() gave it."""
    print("V3: a save with no password keeps the stored one")

    path = db_path("v3.db")
    db = SnmpTrapDatabase(path)
    try:
        db.save_settings({"v3_users": f"noc / SHA / {PASSPHRASE}\n"
                                      f"ops / SHA256 / {PASSPHRASE}-ops"})
        db.save_settings({"v3_users": "noc / SHA\nops / SHA256", "port": 1162})
        check(db.v3_user_secret("noc") == PASSPHRASE,
              "the first user's password survives a save that did not carry it")
        check(db.v3_user_secret("ops") == f"{PASSPHRASE}-ops",
              "and so does the second's")

        db.save_settings({"v3_users": "noc / SHA / a-new-passphrase\nops / SHA256"})
        check(db.v3_user_secret("noc") == "a-new-passphrase",
              "a line that does carry one replaces it")
        check(db.v3_user_secret("ops") == f"{PASSPHRASE}-ops",
              "without touching the user beside it")

        db.save_settings({"v3_users": "noc / SHA / ********"})
        check(db.v3_user_secret("noc") == "a-new-passphrase",
              "a line retyped as the mask keeps the password too")
        check(db.v3_user_secret("ops") is None,
              "and the user dropped from the textarea loses theirs")
        check(db.settings()["v3_users_stored"] == 1,
              "leaving one password on file")
    finally:
        db.close()


# --------------------------------------------------------------------- V4

def test_v4_a_plaintext_database_is_migrated_once() -> None:
    """Every install that has ever configured a v3 trap user has the
    password sitting in its settings row. Opening the store moves it."""
    print("V4: a database still holding a plaintext password is migrated on open")

    path = db_path("v4.db")
    db = SnmpTrapDatabase(path)
    db.close()
    # Written the way the shipped version wrote it, under the store's own
    # back: a JSON string in the settings row, password and all.
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO settings(key, value) VALUES ('v3_users', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (f'"noc / SHA / {PASSPHRASE}"',))
    conn.commit()
    conn.close()
    check(PASSPHRASE.encode() in file_bytes(path),
          "the passphrase starts out in the file, as it does on every "
          "install that configured one")

    db = SnmpTrapDatabase(path)
    try:
        check(db.settings()["v3_users"] == "noc / SHA",
              "after one open the settings value holds only the name")
        check(db.v3_user_secret("noc") == PASSPHRASE,
              "the password is still readable by the receiver")
        check(db.settings()["v3_users_stored"] == 1,
              "and counted as stored")
        with db._lock:
            blob = db._conn.execute(
                "SELECT auth_pass_enc FROM trap_v3_users WHERE name = 'noc'"
            ).fetchone()[0]
        check(bool(blob) and PASSPHRASE.encode() not in bytes(blob),
              "encrypted in trap_v3_users")
    finally:
        db.close()

    first = bytes(blob)
    db = SnmpTrapDatabase(path)
    try:
        with db._lock:
            again = db._conn.execute(
                "SELECT auth_pass_enc FROM trap_v3_users WHERE name = 'noc'"
            ).fetchone()[0]
        check(bytes(again) == first,
              "a second open re-encrypts nothing: the migration has already run")
        check(db.settings()["v3_users"] == "noc / SHA",
              "and the settings value is unchanged")
    finally:
        db.close()

    # The decoder configured from the migrated settings still knows the user,
    # which is the whole point of the secret source.
    db = SnmpTrapDatabase(path)
    try:
        decoder = Decoder()
        decoder.secret_source = db.v3_user_secret
        decoder.configure(db.settings())
        check(decoder.users.get("noc") == ("SHA", PASSPHRASE),
              "a decoder configured from settings() resolves the password "
              "through the receiver's secret source")

        plain = Decoder()
        plain.configure(db.settings())
        check(plain.users == {},
              "a decoder with no secret source configures no user from those "
              "lines — there is no password in them to leak")
    finally:
        db.close()


TESTS = [
    test_v1_a_saved_password_never_reaches_the_file_or_the_api,
    test_v2_a_real_trap_still_verifies_after_a_restart,
    test_v3_a_save_without_the_password_keeps_it,
    test_v4_a_plaintext_database_is_migrated_once,
]


def main() -> int:
    try:
        for test in TESTS:
            test()
            print()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED:")
        for item in FAILURES:
            print(f"  - {item}")
        return 1
    print("ALL TRAP v3 CREDENTIAL ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

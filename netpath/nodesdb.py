"""Storage for the Nodes module: devices, polling groups ("profiles"),
interfaces, polled metrics and their samples, device/interface state
events, uploaded vendor MIBs, and discovery jobs.

Two tables are genuinely unbounded and pruned by age/size: `samples` (raw
metric points) and `device_events`/`interface_events` (state transitions).
Everything else — `devices`, `groups`, `interfaces`, `mib_files`/
`mib_objects` — describes the network as it is configured and currently
known, not a log, and is never trimmed by age or size; only explicit
deletion removes a row from those tables. This mirrors the same bounded/
unbounded split `ipamdb.py`'s `scans` (pruned) vs. `subnets`/`hosts`
(never pruned by age) already established in this codebase.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (               -- "polling profiles"
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    snmp_version    INTEGER NOT NULL DEFAULT 1,    -- 0=v1, 1=v2c, 3=v3
    community       TEXT,                          -- v1/v2c
    v3_user         TEXT,                          -- v3
    v3_auth_proto   TEXT,                           -- MD5/SHA/SHA224/256/384/512
    v3_auth_pass_enc BLOB,                          -- DPAPI-encrypted; NULL = none stored
    poll_interval_s INTEGER NOT NULL DEFAULT 120,
    snmp_timeout_s  REAL NOT NULL DEFAULT 3.0,
    snmp_retries    INTEGER NOT NULL DEFAULT 2,
    ping_enabled    INTEGER NOT NULL DEFAULT 1,
    snmp_enabled    INTEGER NOT NULL DEFAULT 1,
    oid_set         TEXT NOT NULL DEFAULT 'auto',  -- 'auto' | comma-separated metric keys
    is_default      INTEGER NOT NULL DEFAULT 0,
    created_ts      REAL NOT NULL
);

-- A group's own snmp_version/community/v3_* columns above are its
-- "primary" credential — unconditionally always present and always tried
-- first, exactly as before this table existed, so a single-credential
-- profile (still the common case) needs no migration and no behavior
-- change at all. This table holds only the ADDITIONAL alternates a
-- profile wants tried after the primary — a mixed-vendor subnet where
-- some devices answer the primary community/version and others need a
-- different one entirely. Tried in id order (insertion order); the
-- poller caches whichever candidate last worked for a given device, so a
-- profile with several alternates does not cost extra requests on every
-- poll — only on a device's first poll, or after its cached credential
-- stops working.
CREATE TABLE IF NOT EXISTS group_credentials (
    id              INTEGER PRIMARY KEY,
    group_id        INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    label           TEXT,                            -- optional, e.g. "Cisco gear"
    snmp_version    INTEGER NOT NULL DEFAULT 1,       -- 0=v1, 1=v2c, 3=v3
    community       TEXT,
    v3_user         TEXT,
    v3_auth_proto   TEXT,
    v3_auth_pass_enc BLOB,
    created_ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_group_credentials_group ON group_credentials(group_id, id);

-- Purely organizational — "which folder is this device in" (e.g. "Core
-- Switches", "Branch A"), completely unrelated to a polling profile
-- (which controls credentials/interval/etc). Deliberately a separate
-- table rather than another column on `groups`: conflating "which
-- credentials" with "which folder" would make every future profile
-- change also have to think about an unrelated organizational concept.
CREATE TABLE IF NOT EXISTS device_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_ts  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    ip              TEXT NOT NULL UNIQUE,
    name            TEXT,                          -- display name, defaults to ip
    group_id        INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    device_group_id INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
    display_name_source TEXT NOT NULL DEFAULT 'auto', -- 'auto' (sysName first) | 'manual'
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- per-device overrides; NULL means "use the group's value"
    snmp_version    INTEGER,
    community       TEXT,
    v3_user         TEXT,
    v3_auth_proto   TEXT,
    v3_auth_pass_enc BLOB,
    poll_interval_s INTEGER,
    snmp_timeout_s  REAL,
    snmp_retries    INTEGER,
    ping_enabled    INTEGER,
    snmp_enabled    INTEGER,
    oid_set         TEXT,
    -- discovered/learned identity, refreshed by every successful poll
    sys_descr       TEXT,
    sys_name        TEXT,
    sys_object_id   TEXT,
    sys_contact     TEXT,
    sys_location    TEXT,
    vendor          TEXT,
    -- live state
    status          TEXT NOT NULL DEFAULT 'unknown', -- unknown|up|down|unsupported|auth
    ping_ok         INTEGER,
    ping_rtt_ms     REAL,
    snmp_ok         INTEGER,
    snmp_error      TEXT,
    consecutive_fail INTEGER NOT NULL DEFAULT 0,
    last_poll_ts    REAL,
    last_up_ts      REAL,
    last_down_ts    REAL,
    last_uptime_ticks INTEGER,                      -- sysUpTime.0, for reboot detection
    last_uptime_ts  REAL,
    created_ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS ix_devices_status ON devices(status);

CREATE TABLE IF NOT EXISTS interfaces (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    descr           TEXT,
    alias           TEXT,
    phys_addr       TEXT,
    speed_bps       INTEGER,
    admin_status    TEXT,
    oper_status     TEXT,
    last_in_octets  INTEGER,
    last_out_octets INTEGER,
    last_in_errors  INTEGER,
    last_out_errors INTEGER,
    last_sample_ts  REAL,
    in_bps          REAL,
    out_bps         REAL,
    in_error_rate   REAL,
    out_error_rate  REAL,
    last_seen_ts    REAL NOT NULL,
    UNIQUE(device_id, if_index)
);
CREATE INDEX IF NOT EXISTS ix_interfaces_device ON interfaces(device_id);

-- Forwarding-database entries: which MAC addresses each switch port has
-- learned. Stored so "find the port this MAC is on" is a query rather than
-- a live walk of every switch in the estate — the same address can sit on
-- every switch between here and the host, so a search has to be able to
-- see them all at once.
--
-- Filled on its own schedule (mac_table_interval_s, 0 = off, off by
-- default), never on the poll cycle: a forwarding table is a walk of
-- hundreds to thousands of rows per switch and belongs nowhere near a
-- 60-second poll. `mac` is stored normalised — lowercase hex, no
-- separators — so one stored form answers ':', '-', '.' and bare-hex
-- searches alike; see normalize_mac.
CREATE TABLE IF NOT EXISTS mac_entries (
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    mac             TEXT NOT NULL,
    vlan            TEXT NOT NULL DEFAULT '',
    seen_ts         REAL NOT NULL,
    PRIMARY KEY (device_id, if_index, mac, vlan)
);
CREATE INDEX IF NOT EXISTS ix_mac_entries_mac ON mac_entries(mac);
CREATE INDEX IF NOT EXISTS ix_mac_entries_seen ON mac_entries(seen_ts);

CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    label           TEXT NOT NULL,
    unit            TEXT NOT NULL,
    kind            TEXT NOT NULL,                  -- 'gauge'|'counter_rate'
    last_value      REAL,
    last_ts         REAL,
    UNIQUE(device_id, key)
);

CREATE TABLE IF NOT EXISTS samples (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    value           REAL,
    PRIMARY KEY (metric_id, ts)
);
CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
);

CREATE TABLE IF NOT EXISTS device_events (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    kind            TEXT NOT NULL,   -- down|up|rebooted|auth_fail|poll_overrun|unsupported
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS ix_device_events_device_ts ON device_events(device_id, ts);
CREATE INDEX IF NOT EXISTS ix_device_events_ts ON device_events(ts);

CREATE TABLE IF NOT EXISTS interface_events (
    id              INTEGER PRIMARY KEY,
    interface_id    INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    kind            TEXT NOT NULL,    -- link_down|link_up
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS ix_interface_events_ts ON interface_events(ts);

CREATE TABLE IF NOT EXISTS mib_files (
    id              INTEGER PRIMARY KEY,
    filename        TEXT NOT NULL,
    module          TEXT,
    uploaded_ts     REAL NOT NULL,
    object_count    INTEGER NOT NULL DEFAULT 0,
    unresolved      TEXT NOT NULL DEFAULT '[]',
    parse_notes     TEXT,
    -- The original text, kept so "resolve again" can re-parse from
    -- scratch: mib_objects only stores the final oid (or NULL), not the
    -- parent/last_arc an unresolved object would need to retry against.
    content         TEXT
);
CREATE TABLE IF NOT EXISTS mib_objects (
    id              INTEGER PRIMARY KEY,
    mib_file_id     INTEGER REFERENCES mib_files(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    oid             TEXT,
    description     TEXT,
    syntax          TEXT,
    enums           TEXT,
    is_notification INTEGER NOT NULL DEFAULT 0,
    edited          INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mib_file_id, name)
);
CREATE INDEX IF NOT EXISTS ix_mib_objects_oid ON mib_objects(oid);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL,        -- 'device'|'subnet'
    target          TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'running',  -- running|done|cancelled|error
    total           INTEGER NOT NULL DEFAULT 0,
    probed          INTEGER NOT NULL DEFAULT 0,
    responded       INTEGER NOT NULL DEFAULT 0,
    identified      INTEGER NOT NULL DEFAULT 0,
    allow_ping_only INTEGER NOT NULL DEFAULT 0, -- ping-only results may be approved
    reviewed        INTEGER NOT NULL DEFAULT 0, -- the approve/deny dialog was answered
    started_ts      REAL NOT NULL,
    finished_ts     REAL,
    error           TEXT
);
CREATE TABLE IF NOT EXISTS discovery_results (
    id              INTEGER PRIMARY KEY,
    job_id          INTEGER NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    ping_ok         INTEGER NOT NULL DEFAULT 0,
    snmp_ok         INTEGER NOT NULL DEFAULT 0,
    community_or_user TEXT,
    snmp_version    INTEGER,
    sys_descr       TEXT,
    sys_name        TEXT,
    sys_object_id   TEXT,
    vendor          TEXT,
    suggested_group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    promoted_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_discovery_results_job ON discovery_results(job_id);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    "enabled": True,
    "poll_workers": 16,
    "default_interval_s": 120,
    "focus_poll_interval_s": 3,     # selected-device fast poll; 0 disables
    "default_snmp_timeout_s": 3.0,
    "default_snmp_retries": 2,
    "down_after_failures": 3,        # consecutive poll failures before status -> down
    # A device is DOWN only when ping AND SNMP both fail. Defaults to True
    # since 4.25: a switch answering ICMP with a broken community string is
    # reachable and misconfigured, not down, and calling it down buries the
    # SNMP error under an outage. Overridable per device and per profile for
    # the case where SNMP failing genuinely is an outage.
    "unreachable_ping_only": True,
    # Ping probing, used both for reachability and for the packet-loss
    # metric. ping_count > 1 is what makes loss measurable at all: one probe
    # can only ever say 0% or 100%.
    "ping_count": 3,
    "ping_timeout_ms": 1000,
    # Seconds between ping probes; 0 pings on every SNMP poll. Raise it to
    # keep loss sampling steady on a device polled rarely, or to ping less
    # often than a fast focus poll would.
    "ping_interval_s": 0,
    "sample_retention_days": 400,    # raw samples; hourly rollups are never pruned by age
    "sample_row_cap_per_metric": 50_000,
    "event_retention_days": 180,
    "discovery_retention_days": 30,
    "max_mib_bytes": 8 * 1024 * 1024,
    # Installing a MIB bundle from the catalog. The per-file cap is
    # max_mib_bytes above; these bound the rest of the operation so a bad
    # upstream cannot fill the disk or hang a worker thread indefinitely.
    "mib_download_timeout_s": 30.0,
    "max_mib_zip_files": 400,
    "max_mib_bundle_bytes": 64 * 1024 * 1024,
    "resolve_addresses": True,
    "max_scan_addresses": 1024,
    "rollup_enabled": True,
    "detail_fields": "sys_descr,vendor,snmp_version",  # identity fields shown in
                                                       # the device detail header
    "seeded_mib_files": "",  # CSV of bundled netpath/mibs/*.mib filenames ever
                              # auto-loaded, so a deliberate delete is never
                              # silently redone on the next restart
    # Comma-joined column keys the device table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
    # Comma-joined column keys the interface table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns_ifaces": "",
    # Bounds on "download the entire SNMP walk" from the OID browser. Far
    # larger than the browser's own subtree caps because this one runs as a
    # background job with a progress count and a cancel, not in a dialog
    # somebody is waiting on — but still real bounds, so a device with a
    # looping agent cannot walk forever. The downloaded file states which
    # bound stopped it, if either did.
    "oid_walk_max_rows": 100_000,
    "oid_walk_budget_s": 600.0,
    # How long a learned MAC stays searchable after the last walk that saw
    # it. A device dropped from the walk schedule stops refreshing its
    # entries, and after this they are dropped rather than answering
    # searches with a table nobody has confirmed since.
    "mac_table_retention_days": 7.0,
}

_OVERRIDE_COLUMNS = ("snmp_version", "community", "v3_user", "v3_auth_proto",
                     "v3_auth_pass_enc", "poll_interval_s", "snmp_timeout_s",
                     "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                     "mib_file_id", "ping_count", "ping_timeout_ms",
                     "unreachable_ping_only", "vendor_oid", "location_oid",
                     "mac_table_interval_s")

_GROUP_EDITABLE = ("name", "snmp_version", "community", "v3_user",
                   "v3_auth_proto", "poll_interval_s", "snmp_timeout_s",
                   "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                   "mib_file_id", "ping_count", "ping_timeout_ms",
                   "unreachable_ping_only", "vendor_oid", "location_oid",
                   "mac_table_interval_s")

_DEVICE_EDITABLE = ("name", "group_id", "device_group_id", "display_name_source",
                    "enabled") + _OVERRIDE_COLUMNS


# The separators a MAC address is written with in the wild. '.' covers the
# Cisco aabb.ccdd.eeff form; space covers a paste out of a spreadsheet.
_MAC_SEPARATORS = ":-. \t"
_HEX = set("0123456789abcdefABCDEF")


def normalize_mac(text) -> str:
    """A MAC (or the start of one) as stored: lowercase hex, no separators.

    Accepts every form the field sees — AA-BB-CC-DD-EE-FF, aa:bb:cc:dd:ee:ff,
    aabb.ccdd.eeff, aabbccddeeff — and returns "" for anything that is not a
    MAC or a prefix of one, so a caller can use the empty string to mean
    "that was not a MAC". Prefixes are deliberately allowed: searching for
    the first three octets of a vendor's OUI is a normal thing to want.
    """
    cleaned = "".join(c for c in str(text or "") if c not in _MAC_SEPARATORS)
    if not cleaned or len(cleaned) > 12:
        return ""
    if any(c not in _HEX for c in cleaned):
        return ""
    return cleaned.lower()


def looks_like_mac_search(text) -> str:
    """normalize_mac, but refusing text that is plainly an IP address.

    "10.0.0.5" normalises to "10005", which is valid hex and would quietly
    turn an address search into a MAC-prefix search. Digits-and-dots only is
    an address in every case that matters here; a genuinely all-numeric MAC
    typed with dots is rare enough to be worth losing next to searching by
    IP, which people do constantly.
    """
    raw = str(text or "").strip()
    if raw and all(c.isdigit() or c == "." for c in raw):
        return ""
    return normalize_mac(raw)


def detected_vendor(device_row) -> str:
    """The vendor SNMP identification worked out, never a custom one.

    Every reader that *behaves* differently per vendor must call this rather
    than reading `vendor` directly: ConfigRX picks its show-config command by
    exact vendor key, the Cisco per-VLAN MAC read is gated on the string
    "cisco", and discovery suggests a profile by exact name match. A device
    whose vendor_oid answers "Cisco Systems, Inc." must not lose any of those.

    Falls back to `vendor` for a row polled before 4.30.0 added the column,
    where the two were by definition the same value.
    """
    if device_row is None:
        return ""
    keys = device_row.keys() if hasattr(device_row, "keys") else device_row
    detected = device_row["vendor_detected"] if "vendor_detected" in keys else None
    if detected:
        return detected
    return (device_row["vendor"] if "vendor" in keys else "") or ""

class NodesDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()
        self._seed()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an existing table alone,
        so a column added to devices/groups after some installs already
        have a nodes.db has to be added explicitly or an upgraded install
        fails the moment anything queries it — the same convention `db.py`
        and `ipamdb.py` already use for their own post-release columns.
        """
        devices = {row["name"] for row in
                   self._conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "device_group_id" not in devices:
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN device_group_id INTEGER"
                " REFERENCES device_groups(id) ON DELETE SET NULL")
        if "display_name_source" not in devices:
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN display_name_source TEXT"
                " NOT NULL DEFAULT 'auto'")
        if "mib_file_id" not in devices:
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN mib_file_id INTEGER"
                " REFERENCES mib_files(id) ON DELETE SET NULL")
        # Per-device ping tuning and down-logic override, all nullable so
        # NULL keeps meaning "inherit the profile, then the global setting".
        for column in ("ping_count", "ping_timeout_ms", "unreachable_ping_only"):
            if column not in devices:
                self._conn.execute(
                    f"ALTER TABLE devices ADD COLUMN {column} INTEGER")
        # Seconds between forwarding-table walks; 0 (the shipped default)
        # means never. NULL keeps meaning "inherit the profile".
        if "mac_table_interval_s" not in devices:
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN mac_table_interval_s INTEGER")
        # Identity OIDs: when set, the poller reads the device's vendor and
        # location from these instead of deriving vendor from sysObjectID and
        # reading sysLocation. NULL/"" keeps today's behaviour exactly, which
        # is the whole backward-compatibility story for this feature.
        for column in ("vendor_oid", "location_oid"):
            if column not in devices:
                self._conn.execute(
                    f"ALTER TABLE devices ADD COLUMN {column} TEXT")
        if "vendor_detected" not in devices:
            # What identify_vendor() worked out from sysObjectID/sysDescr,
            # kept separately from `vendor` (which a custom OID may have
            # replaced for display). ConfigRX's command choice, the Cisco
            # MAC-table gate and discovery's profile suggestion all read this
            # one, so naming a device "Acme Networks Ltd" cannot quietly stop
            # its backups working.
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN vendor_detected TEXT")
        if "vendor_source" not in devices:
            # 'sysObjectID' | 'sysDescr' | 'oid' | '' — which of the three
            # spoke. It was computed on every poll and thrown away; an
            # operator looking at a vendor name deserves to know whether it
            # is an IANA arc assignment or a substring guess.
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN vendor_source TEXT")
        if "mib_covered" not in devices:
            # Last vendor-MIB coverage verdict for this device: NULL =
            # never evaluated (or not applicable), 0/1 = uncovered/covered.
            # Persisted so the poller records mib_missing/mib_present on
            # *transitions* only, however coverage changed (a MIB uploaded
            # or deleted), rather than keying off sysObjectID changes.
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN mib_covered INTEGER")
        # Not in SCHEMA's own CREATE INDEX block: that script runs before this
        # method, so an index on a column added just above would fail on an
        # upgraded install the same way querying the column itself would.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_devices_device_group"
            " ON devices(device_group_id)")

        groups = {row["name"] for row in
                  self._conn.execute("PRAGMA table_info(groups)").fetchall()}
        if "mib_file_id" not in groups:
            self._conn.execute(
                "ALTER TABLE groups ADD COLUMN mib_file_id INTEGER"
                " REFERENCES mib_files(id) ON DELETE SET NULL")
        for column in ("ping_count", "ping_timeout_ms", "unreachable_ping_only",
                       "mac_table_interval_s"):
            if column not in groups:
                self._conn.execute(
                    f"ALTER TABLE groups ADD COLUMN {column} INTEGER")
        for column in ("vendor_oid", "location_oid"):
            if column not in groups:
                self._conn.execute(
                    f"ALTER TABLE groups ADD COLUMN {column} TEXT")

        interfaces = {row["name"] for row in
                      self._conn.execute("PRAGMA table_info(interfaces)").fetchall()}
        for column in ("last_in_errors", "last_out_errors"):
            if column not in interfaces:
                self._conn.execute(
                    f"ALTER TABLE interfaces ADD COLUMN {column} INTEGER")

        jobs = {row["name"] for row in
                self._conn.execute("PRAGMA table_info(discovery_jobs)").fetchall()}
        if "allow_ping_only" not in jobs:
            self._conn.execute(
                "ALTER TABLE discovery_jobs ADD COLUMN allow_ping_only INTEGER"
                " NOT NULL DEFAULT 0")
        if "reviewed" not in jobs:
            # Pre-upgrade jobs count as already reviewed, or every old
            # finished job would pop an approval dialog on first open.
            self._conn.execute(
                "ALTER TABLE discovery_jobs ADD COLUMN reviewed INTEGER"
                " NOT NULL DEFAULT 1")

    def _seed(self) -> None:
        """Creates a `Default` polling profile if none exists yet. Idempotent
        on every open — a device with no group falls back to this one, and
        every device created before any profile exists gets it."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO groups(name, snmp_version, community,"
                    " poll_interval_s, snmp_timeout_s, snmp_retries,"
                    " ping_enabled, snmp_enabled, oid_set, is_default, created_ts)"
                    " VALUES ('Default', 1, 'public', 120, 3.0, 2, 1, 1, 'auto', 1, ?)",
                    (time.time(),))
                self._conn.commit()

    def ensure_default_group(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
        if row:
            return row["id"]
        self._seed()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
        return row["id"]

    # --------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        return values

    def save_settings(self, values: dict) -> None:
        with self._lock:
            for key, value in values.items():
                if key not in DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)))
            self._conn.commit()

    # ----------------------------------------------------------------- groups

    def groups(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM groups ORDER BY is_default DESC, name COLLATE NOCASE"
            ).fetchall()

    def group(self, group_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()

    def add_group(self, name: str, **fields) -> int:
        cols = ["name", "created_ts"]
        vals = [name, time.time()]
        for key in _GROUP_EDITABLE:
            if key in fields and key != "name":
                cols.append(key)
                vals.append(fields[key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO groups({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_group(self, group_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in _GROUP_EDITABLE}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE groups SET {clauses} WHERE id = ?",
                (*allowed.values(), group_id))
            self._conn.commit()

    def set_group_credential(self, group_id: int, user: str, auth_proto: str,
                             password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, group_id))
            self._conn.commit()

    def clear_group_credential(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_auth_pass_enc=NULL WHERE id=?", (group_id,))
            self._conn.commit()

    def device_count_for_group(self, group_id: int) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM devices WHERE group_id = ?",
                (group_id,)).fetchone()["n"]

    def remove_group(self, group_id: int) -> None:
        """Deletes a profile unconditionally — callers (api.py) are
        expected to have already refused this via device_count_for_group()
        if the profile is still in use, the same "read state, validate,
        then mutate" split every other delete endpoint in this app
        follows. If the profile being removed is the current default,
        promotes the next remaining profile (lowest id, i.e. oldest) to
        default in the same transaction, so "exactly one profile is
        default, or zero if none remain" never breaks even for a moment.
        A caller with zero profiles left falls back to
        ensure_default_group()'s existing lazy reseed the next time one
        is actually needed — the same behavior a brand-new install
        already relies on."""
        with self._lock:
            row = self._conn.execute(
                "SELECT is_default FROM groups WHERE id = ?", (group_id,)).fetchone()
            self._conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            if row and row["is_default"]:
                successor = self._conn.execute(
                    "SELECT id FROM groups ORDER BY id LIMIT 1").fetchone()
                if successor:
                    self._conn.execute(
                        "UPDATE groups SET is_default = 1 WHERE id = ?",
                        (successor["id"],))
            self._conn.commit()

    def set_default_group(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE groups SET is_default = 0 WHERE is_default = 1")
            self._conn.execute("UPDATE groups SET is_default = 1 WHERE id = ?",
                               (group_id,))
            self._conn.commit()

    # ----------------------------------------------------- group credentials

    def group_credentials(self, group_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM group_credentials WHERE group_id = ? ORDER BY id",
                (group_id,)).fetchall()

    def group_credential(self, credential_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM group_credentials WHERE id = ?",
                (credential_id,)).fetchone()

    def add_group_credential(self, group_id: int, *, label: str = "",
                             snmp_version: int = 1, community: str | None = None,
                             v3_user: str | None = None,
                             v3_auth_proto: str | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO group_credentials(group_id, label, snmp_version,"
                " community, v3_user, v3_auth_proto, created_ts)"
                " VALUES (?,?,?,?,?,?,?)",
                (group_id, label, snmp_version, community, v3_user, v3_auth_proto,
                 time.time()))
            self._conn.commit()
            return cur.lastrowid

    def update_group_credential(self, credential_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in
                  ("label", "snmp_version", "community", "v3_user", "v3_auth_proto")}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE group_credentials SET {clauses} WHERE id = ?",
                (*allowed.values(), credential_id))
            self._conn.commit()

    def set_group_credential_password(self, credential_id: int, user: str,
                                      auth_proto: str, password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE group_credentials SET v3_user=?, v3_auth_proto=?,"
                " v3_auth_pass_enc=? WHERE id=?",
                (user, auth_proto, password_enc, credential_id))
            self._conn.commit()

    def clear_group_credential_password(self, credential_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE group_credentials SET v3_auth_pass_enc=NULL WHERE id=?",
                (credential_id,))
            self._conn.commit()

    def remove_group_credential(self, credential_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM group_credentials WHERE id = ?", (credential_id,))
            self._conn.commit()

    # ---------------------------------------------------------- device groups
    #
    # Purely organizational folders a device can optionally belong to —
    # unrelated to `groups` (polling profiles) above. No in-use guard on
    # removal: unlike deleting a polling profile (which would leave a
    # device without credentials to poll with), losing an organizational
    # folder is harmless — a device just becomes ungrouped, the same
    # nullable-FK shape `devices.group_id` already uses.

    def device_groups(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_groups ORDER BY name COLLATE NOCASE").fetchall()

    def device_group(self, device_group_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_groups WHERE id = ?", (device_group_id,)).fetchone()

    def add_device_group(self, name: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO device_groups(name, created_ts) VALUES (?,?)",
                (name, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def rename_device_group(self, device_group_id: int, name: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE device_groups SET name = ? WHERE id = ?", (name, device_group_id))
            self._conn.commit()

    def remove_device_group(self, device_group_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM device_groups WHERE id = ?", (device_group_id,))
            self._conn.commit()

    # ---------------------------------------------------------------- devices

    def devices(self, group_id: int | None = None, status: str | None = None,
               text: str | None = None, device_group_id: int | None = None,
               exclude_up: bool = False) -> list[sqlite3.Row]:
        clauses, params = [], []
        if group_id is not None:
            clauses.append("group_id = ?")
            params.append(group_id)
        if device_group_id is not None:
            clauses.append("device_group_id = ?")
            params.append(device_group_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if exclude_up:
            # "Offline" as a concept, not the literal status string:
            # down, unknown, unsupported and auth-failed all mean "not
            # currently confirmed working" — genuinely broader than
            # picking 'down' alone from the status filter above, and the
            # two are meant to be layerable rather than redundant.
            clauses.append("status != 'up'")
        if text:
            # A MAC search matches the stored forwarding tables as well as
            # the device's own fields, so typing an address a switch has
            # learned filters the list down to the switches that see it.
            # Only from four hex digits: fewer would match half the estate
            # and turn a search into a shuffle.
            mac = looks_like_mac_search(text)
            if len(mac) >= 4:
                clauses.append(
                    "(ip LIKE ? OR name LIKE ? OR sys_name LIKE ?"
                    " OR id IN (SELECT device_id FROM mac_entries"
                    "           WHERE mac LIKE ?))")
                params.extend([f"%{text}%"] * 3 + [f"{mac}%"])
            else:
                clauses.append("(ip LIKE ? OR name LIKE ? OR sys_name LIKE ?)")
                params.extend([f"%{text}%"] * 3)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM devices{where} ORDER BY name COLLATE NOCASE, ip",
                params).fetchall()

    def device(self, device_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def device_by_ip(self, ip: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()

    def device_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM devices").fetchone()["n"]

    def device_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM devices GROUP BY status").fetchall()
        counts = {"total": 0, "up": 0, "down": 0, "unknown": 0,
                 "unsupported": 0, "auth": 0}
        for row in rows:
            counts["total"] += row["n"]
            counts[row["status"]] = counts.get(row["status"], 0) + row["n"]
        return counts

    def add_device(self, ip: str, name: str | None = None,
                   group_id: int | None = None, device_group_id: int | None = None,
                   **overrides) -> int:
        cols = ["ip", "name", "group_id", "device_group_id", "created_ts"]
        vals = [ip, name or ip, group_id, device_group_id, time.time()]
        for key in _OVERRIDE_COLUMNS:
            if key in overrides:
                cols.append(key)
                vals.append(overrides[key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO devices({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def seed_identity(self, device_id: int, *, sys_descr: str = "",
                      sys_name: str = "", sys_object_id: str = "",
                      vendor: str = "") -> None:
        """Pre-fills the identity columns from a discovery result so a
        just-promoted device shows its sysName immediately instead of a
        bare IP until its first poll (which overwrites these with the same
        values anyway)."""
        with self._lock:
            # vendor_detected too: discovery identified this from SNMP, so it
            # is a detected value by definition, and leaving it NULL until the
            # first poll would make ConfigRX and the Cisco MAC read fall back
            # to a blank vendor on a device that was just identified.
            self._conn.execute(
                "UPDATE devices SET sys_descr = ?, sys_name = ?,"
                " sys_object_id = ?, vendor = ?, vendor_detected = ?"
                " WHERE id = ?",
                (sys_descr, sys_name, sys_object_id, vendor, vendor, device_id))
            self._conn.commit()

    def update_device(self, device_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in _DEVICE_EDITABLE}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE devices SET {clauses} WHERE id = ?",
                (*allowed.values(), device_id))
            self._conn.commit()

    def bulk_update_devices(self, device_ids: list[int], **fields) -> None:
        """The same field allow-list as update_device, applied to many rows
        in one statement/transaction rather than one round trip per
        device — the shape post_nodes_discovery_promote's device_ids list
        already established for "operate on many ids from one request"."""
        allowed = {k: v for k, v in fields.items() if k in _DEVICE_EDITABLE}
        if not allowed or not device_ids:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        marks = ",".join("?" * len(device_ids))
        with self._lock:
            self._conn.execute(
                f"UPDATE devices SET {clauses} WHERE id IN ({marks})",
                (*allowed.values(), *device_ids))
            self._conn.commit()

    def bulk_remove_devices(self, device_ids: list[int]) -> int:
        if not device_ids:
            return 0
        marks = ",".join("?" * len(device_ids))
        with self._lock:
            cursor = self._conn.execute(
                f"DELETE FROM devices WHERE id IN ({marks})", device_ids)
            self._conn.commit()
            return cursor.rowcount or 0

    def set_device_credential(self, device_id: int, user: str, auth_proto: str,
                              password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, device_id))
            self._conn.commit()

    def clear_device_credential(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_auth_pass_enc=NULL WHERE id=?", (device_id,))
            self._conn.commit()

    def remove_device(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            self._conn.commit()

    def effective_config(self, device_row: sqlite3.Row) -> dict:
        """Merges a device's own non-NULL override columns over its group's
        row (or DEFAULTS if the device has no group). This is the single
        place "per device or per device group" is actually resolved."""
        group_row = self.group(device_row["group_id"]) if device_row["group_id"] else None
        config = {}
        for key in _OVERRIDE_COLUMNS:
            value = device_row[key] if key in device_row.keys() else None
            if value is None and group_row is not None and key in group_row.keys():
                value = group_row[key]
            config[key] = value
        if config.get("snmp_version") is None:
            config["snmp_version"] = 1
        if config.get("poll_interval_s") is None:
            config["poll_interval_s"] = self.settings().get("default_interval_s", 120)
        if config.get("snmp_timeout_s") is None:
            config["snmp_timeout_s"] = self.settings().get("default_snmp_timeout_s", 3.0)
        if config.get("snmp_retries") is None:
            config["snmp_retries"] = self.settings().get("default_snmp_retries", 2)
        if config.get("ping_enabled") is None:
            config["ping_enabled"] = 1
        if config.get("snmp_enabled") is None:
            config["snmp_enabled"] = 1
        if config.get("oid_set") is None:
            config["oid_set"] = "auto"
        settings = self.settings()
        if config.get("ping_count") is None:
            config["ping_count"] = settings.get("ping_count", 3)
        if config.get("ping_timeout_ms") is None:
            config["ping_timeout_ms"] = settings.get("ping_timeout_ms", 1000)
        if config.get("unreachable_ping_only") is None:
            config["unreachable_ping_only"] = \
                1 if settings.get("unreachable_ping_only", True) else 0
        # 0, not a global setting, is the fallback: learning forwarding
        # tables is opt-in per profile, so an upgrade adds no SNMP load
        # anywhere until somebody asks for it.
        if config.get("mac_table_interval_s") is None:
            config["mac_table_interval_s"] = 0
        return config

    _CREDENTIAL_KEYS = ("snmp_version", "community", "v3_user", "v3_auth_proto",
                       "v3_auth_pass_enc")

    def credential_candidates(self, device_row: sqlite3.Row) -> list[dict]:
        """The ordered list of SNMP credentials to try polling this device
        with. A device that has any of its own credential override columns
        set is a human saying "I know this device's real credentials" —
        exactly one candidate, tried alone, the same single-credential
        behavior this had before profiles could hold more than one. A
        device with no override defers entirely to its profile: the
        profile's own primary credential (its snmp_version/community/v3_*
        columns — always present, unconditionally tried first) followed by
        every row in group_credentials, in the order they were added. A
        device with no profile at all falls back to a bare v2c/public
        guess, matching the Default profile's own seeded values."""
        keys = self._CREDENTIAL_KEYS
        if any(device_row[k] is not None for k in keys if k in device_row.keys()):
            return [{k: device_row[k] if k in device_row.keys() else None for k in keys}]
        group_row = self.group(device_row["group_id"]) if device_row["group_id"] else None
        if group_row is None:
            return [{"snmp_version": 1, "community": "public", "v3_user": None,
                     "v3_auth_proto": None, "v3_auth_pass_enc": None}]
        candidates = [{k: group_row[k] for k in keys}]
        candidates.extend({k: row[k] for k in keys}
                          for row in self.group_credentials(group_row["id"]))
        return candidates

    def record_poll(self, device_id: int, *, ping_ok, ping_rtt_ms, snmp_ok,
                    snmp_error, identity: dict | None,
                    uptime_ticks: int | None, status: str,
                    reachable: bool) -> sqlite3.Row | None:
        """Updates the device row's live-state columns. Returns the previous
        row first so the poller can diff old vs. new status without a
        second read.

        `reachable` is whether THIS poll actually succeeded — distinct from
        `status`, the display label, because the caller may deliberately
        keep showing the last-known "up"/"down" label during a grace
        window (down_after_failures) rather than flapping to "unknown" on
        every missed poll. consecutive_fail must track `reachable`, not the
        literal status string: tying it to status=="up" would let the
        grace window's own preserved "up" label reset the failure streak
        back to zero on every poll, and a failing device could never
        actually reach "down"."""
        with self._lock:
            previous = self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            if previous is None:
                return None
            now = time.time()
            fields = {
                "ping_ok": 1 if ping_ok else (0 if ping_ok is False else None),
                "ping_rtt_ms": ping_rtt_ms,
                "snmp_ok": 1 if snmp_ok else (0 if snmp_ok is False else None),
                "snmp_error": snmp_error,
                "status": status,
                "last_poll_ts": now,
            }
            if identity:
                fields.update({
                    "sys_descr": identity.get("sys_descr"),
                    "sys_name": identity.get("sys_name"),
                    "sys_object_id": identity.get("sys_object_id"),
                    "sys_contact": identity.get("sys_contact"),
                    "sys_location": identity.get("sys_location"),
                    # `vendor` is what the operator sees and a custom
                    # vendor_oid may have supplied it; `vendor_detected` is
                    # always what SNMP identification worked out, and is what
                    # every behavioural reader uses. Keeping both is what lets
                    # a custom vendor name be display-only.
                    "vendor": identity.get("vendor"),
                    "vendor_detected": identity.get("vendor_detected"),
                    "vendor_source": identity.get("vendor_source"),
                })
            if uptime_ticks is not None:
                fields["last_uptime_ticks"] = uptime_ticks
                fields["last_uptime_ts"] = now
            if status == "up":
                fields["last_up_ts"] = now
            elif status == "down":
                fields["last_down_ts"] = now
            fields["consecutive_fail"] = (
                0 if reachable else (previous["consecutive_fail"] or 0) + 1)
            clauses = ", ".join(f"{key} = ?" for key in fields)
            self._conn.execute(
                f"UPDATE devices SET {clauses} WHERE id = ?",
                (*fields.values(), device_id))
            self._conn.commit()
            return previous

    # ------------------------------------------------------------- interfaces

    def interfaces(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index",
                (device_id,)).fetchall()

    # ------------------------------------------------ forwarding tables

    def replace_mac_entries(self, device_id: int, entries: list[dict]) -> int:
        """Replace everything this device has learned with `entries`
        ({if_index, mac, vlan}). Wholesale rather than merged, because a MAC
        that has aged out of the switch must age out here too — a stale row
        would send somebody to the wrong port, which is worse than having no
        answer at all. The MAC is normalised on the way in, so every stored
        row is in one form regardless of how the source spelled it."""
        now = time.time()
        rows = []
        for entry in entries:
            mac = normalize_mac(entry.get("mac"))
            if len(mac) != 12:
                continue
            rows.append((device_id, int(entry["if_index"]), mac,
                         str(entry.get("vlan") or ""), now))
        with self._lock:
            self._conn.execute("DELETE FROM mac_entries WHERE device_id = ?",
                               (device_id,))
            self._conn.executemany(
                "INSERT OR REPLACE INTO mac_entries(device_id, if_index, mac,"
                " vlan, seen_ts) VALUES (?,?,?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def mac_locations(self, mac_prefix: str, limit: int = 200) -> list[sqlite3.Row]:
        """Every (device, port) a MAC starting with this prefix was learned
        on, newest first. A MAC on an uplink is on every switch between here
        and the host, so this returns them all and lets the caller decide —
        picking one silently is how you send an engineer to the core switch
        for a problem on an access port."""
        prefix = normalize_mac(mac_prefix)
        if len(prefix) < 4:
            return []
        with self._lock:
            return self._conn.execute(
                "SELECT m.*, i.descr AS if_descr FROM mac_entries m"
                " LEFT JOIN interfaces i ON i.device_id = m.device_id"
                "   AND i.if_index = m.if_index"
                " WHERE m.mac LIKE ? ORDER BY m.seen_ts DESC, m.device_id,"
                " m.if_index LIMIT ?", (f"{prefix}%", int(limit))).fetchall()

    def mac_entries_for(self, device_id: int,
                        if_index: int | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM mac_entries WHERE device_id = ?"
        args: list = [device_id]
        if if_index is not None:
            sql += " AND if_index = ?"
            args.append(if_index)
        with self._lock:
            return self._conn.execute(sql + " ORDER BY mac, vlan", args).fetchall()

    def prune_mac_entries(self, older_than_s: float) -> int:
        """Drop entries nothing has refreshed for this long. A device taken
        out of the walk schedule (or out of service) would otherwise keep
        answering searches with a forwarding table nobody has confirmed
        since."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM mac_entries WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    def replace_interfaces(self, device_id: int, rows: list[dict]) -> dict:
        """Wholesale replace of a device's interface table each poll cycle.
        Matches existing rows by if_index to carry forward
        last_in_octets/last_out_octets/last_sample_ts so a rate calc isn't
        lost across a routine poll; inserts new ones; deletes vanished
        ones."""
        now = time.time()
        with self._lock:
            existing = {row["if_index"]: row for row in self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ?", (device_id,)).fetchall()}
            seen_indexes = set()
            added, removed, reindexed = [], [], []
            for row in rows:
                if_index = row["if_index"]
                seen_indexes.add(if_index)
                prior = existing.get(if_index)
                if prior is None:
                    added.append(if_index)
                    self._conn.execute(
                        "INSERT INTO interfaces(device_id, if_index, descr, alias,"
                        " phys_addr, speed_bps, admin_status, oper_status,"
                        " last_seen_ts) VALUES (?,?,?,?,?,?,?,?,?)",
                        (device_id, if_index, row.get("descr"), row.get("alias"),
                         row.get("phys_addr"), row.get("speed_bps"),
                         row.get("admin_status"), row.get("oper_status"), now))
                else:
                    if prior["descr"] != row.get("descr"):
                        reindexed.append(if_index)
                    self._conn.execute(
                        "UPDATE interfaces SET descr=?, alias=?, phys_addr=?,"
                        " speed_bps=?, admin_status=?, oper_status=?, last_seen_ts=?"
                        " WHERE device_id=? AND if_index=?",
                        (row.get("descr"), row.get("alias"), row.get("phys_addr"),
                         row.get("speed_bps"), row.get("admin_status"),
                         row.get("oper_status"), now, device_id, if_index))
            for if_index in existing:
                if if_index not in seen_indexes:
                    removed.append(if_index)
            if removed:
                marks = ",".join("?" * len(removed))
                self._conn.execute(
                    f"DELETE FROM interfaces WHERE device_id=? AND if_index IN ({marks})",
                    (device_id, *removed))
            self._conn.commit()
        return {"added": added, "removed": removed, "reindexed": reindexed}

    def update_interface_rate(self, device_id: int, if_index: int, *,
                              in_octets: int | None, out_octets: int | None,
                              in_errors: int | None = None,
                              out_errors: int | None = None,
                              in_bps: float | None, out_bps: float | None,
                              in_error_rate: float | None, out_error_rate: float | None,
                              ts: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE interfaces SET last_in_octets=?, last_out_octets=?,"
                " last_in_errors=?, last_out_errors=?,"
                " last_sample_ts=?, in_bps=?, out_bps=?, in_error_rate=?,"
                " out_error_rate=? WHERE device_id=? AND if_index=?",
                (in_octets, out_octets, in_errors, out_errors, ts, in_bps,
                 out_bps, in_error_rate, out_error_rate, device_id, if_index))
            self._conn.commit()

    # ---------------------------------------------------------------- metrics

    def record_metric_sample(self, device_id: int, key: str, label: str,
                             unit: str, kind: str, ts: float, value: float | None) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM metrics WHERE device_id=? AND key=?",
                (device_id, key)).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO metrics(device_id, key, label, unit, kind,"
                    " last_value, last_ts) VALUES (?,?,?,?,?,?,?)",
                    (device_id, key, label, unit, kind, value, ts))
                metric_id = cur.lastrowid
            else:
                metric_id = row["id"]
                self._conn.execute(
                    "UPDATE metrics SET last_value=?, last_ts=?, label=?, unit=?"
                    " WHERE id=?", (value, ts, label, unit, metric_id))
            if value is not None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                    " VALUES (?,?,?)", (metric_id, ts, value))
            self._conn.commit()
            return metric_id

    def metrics(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY label",
                (device_id,)).fetchall()

    def metric(self, metric_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE id = ?", (metric_id,)).fetchone()

    def series(self, device_id: int, metric_id: int, t0: float, t1: float) -> list[dict]:
        """Raw-vs-hourly selection: a wide window reads the rollup table
        instead of scanning months of raw points.

        `device_id` is enforced, not decorative. Metric ids are global, so
        without the join a caller passing another device's metric id got that
        device's data back under this device's name — which is exactly what a
        stale dialog does when the selected device changes underneath it. A
        mismatch now returns nothing, which reads as "no samples" rather than
        as somebody else's traffic.
        """
        with self._lock:
            if not self._conn.execute(
                    "SELECT 1 FROM metrics WHERE id = ? AND device_id = ?",
                    (metric_id, device_id)).fetchone():
                return []
            if (t1 - t0) <= 86400 * 3:
                rows = self._conn.execute(
                    "SELECT ts, value FROM samples WHERE metric_id = ?"
                    " AND ts >= ? AND ts <= ? ORDER BY ts",
                    (metric_id, t0, t1)).fetchall()
                return [{"ts": row["ts"], "value": row["value"]} for row in rows]
            rows = self._conn.execute(
                "SELECT hour, n, vmin, vavg, vmax FROM samples_hourly"
                " WHERE metric_id = ? AND hour >= ? AND hour <= ? ORDER BY hour",
                (metric_id, t0, t1)).fetchall()
            return [{"ts": row["hour"], "min": row["vmin"], "avg": row["vavg"],
                    "max": row["vmax"], "n": row["n"]} for row in rows]

    def compact_rollup(self) -> int:
        """Aggregates any raw samples older than one hour into
        samples_hourly, min/avg/max per (metric, hour), then deletes the
        raw rows that were just rolled up. Idempotent: an hour already
        fully rolled up produces nothing new to aggregate."""
        cutoff_hour = int(time.time() // 3600) * 3600 - 3600
        with self._lock:
            rows = self._conn.execute(
                "SELECT metric_id, CAST(ts / 3600 AS INTEGER) * 3600 AS hour,"
                " COUNT(*) AS n, MIN(value) AS vmin, AVG(value) AS vavg,"
                " MAX(value) AS vmax FROM samples WHERE ts < ?"
                " GROUP BY metric_id, hour", (cutoff_hour,)).fetchall()
            for row in rows:
                self._conn.execute(
                    "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
                    " VALUES (?,?,?,?,?,?) ON CONFLICT(metric_id, hour) DO UPDATE SET"
                    " n=excluded.n, vmin=excluded.vmin, vavg=excluded.vavg,"
                    " vmax=excluded.vmax",
                    (row["metric_id"], row["hour"], row["n"], row["vmin"],
                     row["vavg"], row["vmax"]))
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (cutoff_hour,))
            self._conn.commit()
            return cursor.rowcount or 0

    # ----------------------------------------------------------------- events

    def record_device_event(self, device_id: int, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_events(device_id, ts, kind, detail)"
                " VALUES (?,?,?,?)", (device_id, time.time(), kind, detail))
            self._conn.commit()

    def device_events(self, device_id: int | None = None, since_s: float | None = None,
                      kinds: list[str] | None = None, limit: int = 300) -> list[sqlite3.Row]:
        clauses, params = [], []
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)
        if since_s is not None:
            clauses.append("ts >= ?")
            params.append(time.time() - since_s)
        if kinds:
            marks = ",".join("?" * len(kinds))
            clauses.append(f"kind IN ({marks})")
            params.extend(kinds)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM device_events{where} ORDER BY ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    # kind -> the small display-status vocabulary devices.status already
    # uses (up|down|unsupported|auth|unknown). rebooted/poll_overrun are
    # informational, not status transitions, so they don't start a new
    # segment — a device that reboots while staying up shouldn't show a
    # gap in an "up" segment.
    _SEGMENT_STATUS = {"up": "up", "down": "down", "unsupported": "unsupported",
                       "auth_fail": "auth"}

    def device_status_segments(self, device_id: int, t0: float, t1: float) -> list[dict]:
        """Turns the device's sparse up/down/etc. transition log into
        [ts_start, ts_end) status segments covering [t0, t1] — one row per
        real status change, not one row per poll the way NetPath's own
        traces-based timeline is built from, since Nodes has no per-poll
        sample log to bucket."""
        kinds = tuple(self._SEGMENT_STATUS)
        marks = ",".join("?" * len(kinds))
        with self._lock:
            prior = self._conn.execute(
                f"SELECT kind FROM device_events WHERE device_id = ? AND ts < ?"
                f" AND kind IN ({marks}) ORDER BY ts DESC LIMIT 1",
                (device_id, t0, *kinds)).fetchone()
            rows = self._conn.execute(
                f"SELECT kind, ts FROM device_events WHERE device_id = ?"
                f" AND ts >= ? AND ts <= ? AND kind IN ({marks}) ORDER BY ts ASC",
                (device_id, t0, t1, *kinds)).fetchall()
            current = self._conn.execute(
                "SELECT status FROM devices WHERE id = ?", (device_id,)).fetchone()

        status = self._SEGMENT_STATUS.get(prior["kind"], "unknown") if prior else "unknown"
        segments = []
        cursor = t0
        for row in rows:
            ts = max(t0, min(row["ts"], t1))
            if ts > cursor:
                segments.append({"ts_start": cursor, "ts_end": ts, "status": status})
            status = self._SEGMENT_STATUS.get(row["kind"], status)
            cursor = ts
        end_status = current["status"] if current else status
        if cursor < t1:
            segments.append({"ts_start": cursor, "ts_end": t1, "status": end_status})
        return segments

    def device_events_since(self, last_id: int, limit: int = 2000) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first — the same cursor-read
        contract SnmpTrapDatabase.traps_since/SyslogDatabase.rows_since
        use, so the alert engine's drain functions are uniform across
        every source."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_device_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS m FROM device_events").fetchone()
        return int(row["m"] or 0)

    def record_interface_event(self, interface_id: int, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO interface_events(interface_id, ts, kind, detail)"
                " VALUES (?,?,?,?)", (interface_id, time.time(), kind, detail))
            self._conn.commit()

    def interface_events(self, interface_id: int | None = None,
                         since_s: float | None = None, limit: int = 300) -> list[sqlite3.Row]:
        clauses, params = [], []
        if interface_id is not None:
            clauses.append("interface_id = ?")
            params.append(interface_id)
        if since_s is not None:
            clauses.append("ts >= ?")
            params.append(time.time() - since_s)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM interface_events{where} ORDER BY ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    def interface_events_since(self, last_id: int, limit: int = 2000) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interface_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_interface_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS m FROM interface_events").fetchone()
        return int(row["m"] or 0)

    def interface_by_id(self, interface_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interfaces WHERE id = ?", (interface_id,)).fetchone()

    def recent_interface_events_for(self, interface_id: int, since_s: float = 900,
                                    limit: int = 50) -> list[sqlite3.Row]:
        cutoff = time.time() - since_s
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interface_events WHERE interface_id = ? AND ts >= ?"
                " ORDER BY ts DESC LIMIT ?", (interface_id, cutoff, limit)).fetchall()

    def interface_id_for(self, device_id: int, if_index: int) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM interfaces WHERE device_id=? AND if_index=?",
                (device_id, if_index)).fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------------- MIBs

    def add_mib_file(self, filename: str, module: str, object_count: int,
                     unresolved: list[str], parse_notes: str,
                     content: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO mib_files(filename, module, uploaded_ts, object_count,"
                " unresolved, parse_notes, content) VALUES (?,?,?,?,?,?,?)",
                (filename, module, time.time(), object_count,
                 json.dumps(unresolved), parse_notes, content))
            self._conn.commit()
            return cur.lastrowid

    def update_mib_file(self, mib_file_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("module", "object_count", "unresolved", "parse_notes")}
        if not allowed:
            return
        if "unresolved" in allowed:
            allowed["unresolved"] = json.dumps(allowed["unresolved"])
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE mib_files SET {clauses} WHERE id = ?",
                (*allowed.values(), mib_file_id))
            self._conn.commit()

    def replace_mib_objects(self, mib_file_id: int, objects: list[dict]) -> None:
        """Deletes and re-inserts every non-edited object; rows with
        edited=1 are left untouched so an admin's manual correction
        survives a re-resolve."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM mib_objects WHERE mib_file_id = ? AND edited = 0",
                (mib_file_id,))
            for obj in objects:
                self._conn.execute(
                    "INSERT INTO mib_objects(mib_file_id, name, oid, description,"
                    " syntax, enums, is_notification) VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(mib_file_id, name) DO UPDATE SET"
                    " oid=excluded.oid, description=excluded.description,"
                    " syntax=excluded.syntax, enums=excluded.enums,"
                    " is_notification=excluded.is_notification"
                    " WHERE mib_objects.edited = 0",
                    (mib_file_id, obj["name"], obj.get("oid"), obj.get("description"),
                     obj.get("syntax"), json.dumps(obj["enums"]) if obj.get("enums") else None,
                     1 if obj.get("is_notification") else 0))
            self._conn.commit()

    def mib_files(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files ORDER BY uploaded_ts DESC").fetchall()

    def mib_file(self, mib_file_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files WHERE id = ?", (mib_file_id,)).fetchone()

    def mib_objects(self, mib_file_id: int | None = None,
                    resolved_only: bool = False) -> list[sqlite3.Row]:
        clauses, params = [], []
        if mib_file_id is not None:
            clauses.append("mib_file_id = ?")
            params.append(mib_file_id)
        if resolved_only:
            clauses.append("oid IS NOT NULL")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM mib_objects{where} ORDER BY name", params).fetchall()

    def set_mib_covered(self, device_id: int, covered: bool | None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET mib_covered = ? WHERE id = ?",
                (None if covered is None else (1 if covered else 0), device_id))
            self._conn.commit()

    def has_mib_covering(self, sys_object_id: str) -> bool:
        """Whether any uploaded MIB actually describes objects belonging to
        this device's vendor, given its sysObjectID.

        "Covering" deliberately means *deeper than the bare enterprise
        arc*: this app ships enterprise-number roots for ~20 vendors, so a
        plain prefix test would match every common vendor out of the box
        and could never report anything as missing. A root-only entry
        (1.3.6.1.4.1.9, six arcs) names the vendor; it decodes nothing. An
        object below it (1.3.6.1.4.1.9.9.13.1.3.1.3, say) is a real
        description, and that is what this looks for."""
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return False
        # Strictly below the enterprise arc — an object AT the arc is the
        # bundled root-only entry, which names the vendor but describes
        # nothing, so it deliberately does not count as coverage.
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mib_objects WHERE oid IS NOT NULL"
                " AND oid LIKE ? LIMIT 1", (prefix + ".%",)).fetchone()
        return row is not None

    def mib_file_covering(self, sys_object_id: str) -> int | None:
        """Which uploaded MIB describes this vendor's objects, for the
        auto-assignment in nodepoll._check_vendor_mib.

        has_mib_covering() answers "is there one"; this answers "which one",
        and picks the file with the most resolved objects under the vendor's
        arc when several qualify — a vendor bundle is usually several files,
        of which one carries the bulk of the real objects and the rest are
        type or registration modules that would poll nothing.
        """
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT mib_file_id, COUNT(*) AS n FROM mib_objects"
                " WHERE oid IS NOT NULL AND oid LIKE ?"
                " GROUP BY mib_file_id ORDER BY n DESC LIMIT 1",
                (prefix + ".%",)).fetchone()
        return row["mib_file_id"] if row else None

    def all_known_oids(self) -> dict[str, str]:
        """Every resolved mib_objects name -> OID, across every uploaded
        file — fed into mibparse.resolve()'s `known` dict so a later
        upload can resolve against an earlier one's objects."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, oid FROM mib_objects WHERE oid IS NOT NULL").fetchall()
        return {row["name"]: row["oid"] for row in rows}

    def update_mib_object(self, object_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("name", "oid", "description", "syntax", "enums")}
        if not allowed:
            return
        if "enums" in allowed and allowed["enums"] is not None:
            allowed["enums"] = json.dumps(allowed["enums"])
        allowed["edited"] = 1
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE mib_objects SET {clauses} WHERE id = ?",
                (*allowed.values(), object_id))
            self._conn.commit()

    def remove_mib_file(self, mib_file_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM mib_files WHERE id = ?", (mib_file_id,))
            self._conn.commit()

    def oid_name_lines(self) -> str:
        """Every resolved mib_objects OID -> name pair, rendered as
        'OID = name' lines — feeds Service._snmp_settings_with_mibs() and
        Nodes' own OID name resolution."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT oid, name FROM mib_objects WHERE oid IS NOT NULL"
            ).fetchall()
        return "\n".join(f"{row['oid']} = {row['name']}" for row in rows)

    # ------------------------------------------------------------- discovery

    def add_discovery_job(self, kind: str, target: str,
                          allow_ping_only: bool = False) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO discovery_jobs(kind, target, allow_ping_only,"
                " started_ts) VALUES (?,?,?,?)",
                (kind, target, 1 if allow_ping_only else 0, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def mark_job_reviewed(self, job_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE discovery_jobs SET reviewed = 1 WHERE id = ?", (job_id,))
            self._conn.commit()

    def remove_discovery_job(self, job_id: int) -> None:
        """Deletes the job and (via the FK cascade) its results. Devices
        already promoted from those results are untouched — promotion
        copies what it needs onto the devices row."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM discovery_jobs WHERE id = ?", (job_id,))
            self._conn.commit()

    def update_discovery_job(self, job_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in
                  ("state", "total", "probed", "responded", "identified",
                   "finished_ts", "error")}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE discovery_jobs SET {clauses} WHERE id = ?",
                (*allowed.values(), job_id))
            self._conn.commit()

    def discovery_jobs(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_jobs ORDER BY started_ts DESC LIMIT ?",
                (limit,)).fetchall()

    def discovery_job(self, job_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_jobs WHERE id = ?", (job_id,)).fetchone()

    def add_discovery_result(self, job_id: int, **fields) -> int:
        cols = ["job_id"] + list(fields.keys())
        vals = [job_id] + list(fields.values())
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO discovery_results({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def discovery_results(self, job_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_results WHERE job_id = ? ORDER BY ip",
                (job_id,)).fetchall()

    def discovery_result(self, result_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_results WHERE id = ?", (result_id,)).fetchone()

    def mark_promoted(self, result_id: int, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE discovery_results SET promoted_device_id = ? WHERE id = ?",
                (device_id, result_id))
            self._conn.commit()

    # -------------------------------------------------------------- storage

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def prune(self, *, sample_days: float = 400, rollup_days: float = 0,
             event_days: float = 180, poll_days: float = 0,
             discovery_days: float = 30, max_samples: int = 0) -> int:
        """Trims the unbounded tables only: samples, device/interface
        events, discovery jobs. Devices, groups, interfaces and MIBs are
        current-state tables, never pruned by age here."""
        removed = 0
        now = time.time()
        with self._lock:
            # Unconditional, like every other module's prune() — a caller
            # that wants "delete everything now" (the Settings page's
            # maintenance button) passes 0, which computes a cutoff of
            # "now" and so matches every existing row; a 0 that instead
            # skipped the DELETE entirely would make that button silently
            # do nothing, as it originally did before this fix.
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (now - sample_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM device_events WHERE ts < ?", (now - event_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM interface_events WHERE ts < ?", (now - event_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM discovery_jobs WHERE started_ts < ? AND state != 'running'",
                (now - discovery_days * 86400,))
            removed += cursor.rowcount or 0
            if max_samples:
                cursor = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples")
                total = cursor.fetchone()["n"]
                if total > max_samples:
                    cursor = self._conn.execute(
                        "DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples"
                        " ORDER BY ts ASC LIMIT ?)", (total - max_samples,))
                    removed += cursor.rowcount or 0
            self._conn.commit()
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
                if total <= 5000:
                    break
                chunk = max(int(total * 0.15), 5000)
                cursor = self._conn.execute(
                    "DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples"
                    " ORDER BY ts ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed

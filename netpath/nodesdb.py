"""Storage for the Nodes module: devices, polling groups ("profiles"),
interfaces, polled metrics and their samples, state events, vendor MIBs and
discovery jobs. Only `samples` and the two event tables are unbounded and
pruned by age or size; the rest describe the network as configured.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from .sqlitebase import SqliteStore, reclaim

log = logging.getLogger(__name__)

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
-- devices() always orders by this pair (with or without a WHERE clause), so
-- this index lets SQLite satisfy the ORDER BY directly instead of a
-- full-table sort on every Nodes page load.
CREATE INDEX IF NOT EXISTS ix_devices_name_ip ON devices(name COLLATE NOCASE, ip);

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
-- Filled on its own schedule (mac_table_interval_s, 0 = off; shipped
-- default 3600s, see effective_config), never on the poll cycle: a
-- forwarding table is a walk of
-- hundreds to thousands of rows per switch and belongs nowhere near a
-- 60-second poll. `mac` is stored normalised — lowercase hex, no
-- separators — so one stored form answers ':', '-', '.' and bare-hex
-- searches alike; see normalize_mac.
-- present distinguishes "this walk still sees it" (1) from "the last walk
-- that saw it was some time ago" (0) — a MAC that steps off a port for one
-- walk cycle used to vanish outright (DELETE-then-INSERT every walk);
-- now the row survives with present=0 and its last seen_ts, so a search
-- can still say where it was, until prune_mac_entries drops it. seen_ts is
-- refreshed on every walk that still sees the row; first_seen_ts is
-- stamped once, when the (device, port, mac, vlan) key is first stored,
-- and never overwritten after.
CREATE TABLE IF NOT EXISTS mac_entries (
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    mac             TEXT NOT NULL,
    vlan            TEXT NOT NULL DEFAULT '',
    seen_ts         REAL NOT NULL,
    first_seen_ts   REAL,
    present         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, if_index, mac, vlan)
);
CREATE INDEX IF NOT EXISTS ix_mac_entries_mac ON mac_entries(mac);
CREATE INDEX IF NOT EXISTS ix_mac_entries_seen ON mac_entries(seen_ts);
-- ix_mac_entries_mac_present (mac, present, seen_ts) is created in _migrate,
-- NOT here: this script runs before the migration, and on a database from
-- before 4.34 the `present` column does not exist yet when it runs.

-- LLDP/CDP neighbour table: what is plugged into what. Its own walk
-- schedule (lldp_interval_s, 0 = off; shipped default 3600s, mirroring
-- mac_table_interval_s exactly — see _merge_config), never the poll cycle,
-- for the same reason the MAC table isn't: this is hundreds of rows on a
-- core switch, not a handful of scalars.
--
-- `protocol` is 'lldp' or 'cdp' and is part of the primary key rather than
-- one row per port: a Cisco box that answers both is not a conflict to
-- resolve, it is two independent views of the same cable and both are kept
-- (nodepoll._run_lldp_table merges them). `rem_index` is the remote row's
-- own index suffix from whichever table produced it (LLDP's
-- lldpRemIndex, CDP's cdpCacheDeviceIndex) — stable across polls for the
-- same neighbour on the same protocol, which is what makes an UPSERT here
-- mean the same thing replace_mac_entries' does.
--
-- present/seen_ts/first_seen_ts are exactly mac_entries' ageing scheme: a
-- neighbour a walk no longer sees is marked present=0 and keeps its last
-- seen_ts rather than vanishing outright, so a link that flaps between
-- lldp_interval_s cycles reads as "last seen 20 minutes ago", not as a
-- topology change that never happened. prune_neighbors is what eventually
-- drops a row nothing has confirmed in a long time, the same shape
-- prune_mac_entries already has.
CREATE TABLE IF NOT EXISTS neighbors (
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    protocol        TEXT NOT NULL,               -- 'lldp' | 'cdp'
    rem_index       TEXT NOT NULL,
    chassis_id      TEXT NOT NULL DEFAULT '',
    chassis_id_subtype INTEGER,
    port_id         TEXT NOT NULL DEFAULT '',
    port_id_subtype INTEGER,
    port_descr      TEXT NOT NULL DEFAULT '',
    sys_name        TEXT NOT NULL DEFAULT '',
    sys_descr       TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT '',    -- CDP cdpCachePlatform; '' for LLDP
    remote_address  TEXT NOT NULL DEFAULT '',    -- CDP cdpCacheAddress; '' for LLDP
    seen_ts         REAL NOT NULL,
    first_seen_ts   REAL,
    present         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, if_index, protocol, rem_index)
);
CREATE INDEX IF NOT EXISTS ix_neighbors_device ON neighbors(device_id);
-- The best-effort join to a known device: exact case-insensitive sysName
-- match, or a chassis id that is a MAC address matching a known interface's
-- phys_addr — both done at read time (see neighbours_of/all_neighbours),
-- so an index on the columns those joins filter by is worth having on any
-- fleet-wide topology read.
CREATE INDEX IF NOT EXISTS ix_neighbors_sys_name ON neighbors(sys_name);
CREATE INDEX IF NOT EXISTS ix_neighbors_chassis_id ON neighbors(chassis_id);

-- Per-port VLAN membership, for MAPPER's per-VLAN trunk strands (a link
-- carrying N VLANs draws as N coloured strands below the configured
-- threshold). Three tables rather than one because they answer three
-- different questions and age independently: which VLANs this device
-- knows about at all (`vlans`), which of its ports are trunk vs. access and
-- what a trunk's native VLAN is (`vlan_ports`), and which VLANs actually
-- cross which port (`port_vlans` — the many-to-many the map draws). Same
-- present-flag ageing scheme as `neighbors`/`mac_entries` throughout: a
-- VLAN or membership row a walk no longer sees is marked present=0 and
-- keeps its last seen_ts rather than vanishing outright, because a trunk
-- that stops carrying a VLAN for one vlan_interval_s cycle should read as
-- "not seen recently", not as a topology change that never happened; the
-- three prune_vlans*/prune_vlan_ports/prune_port_vlans functions are what
-- eventually drop a row nothing has confirmed in a long time.
--
-- vlans: (device_id, vlan) is the key rather than adding an id column —
-- exactly mac_entries' and neighbors' own reasoning: nothing outside this
-- table ever needs to reference one of these rows by a surrogate id, and a
-- natural key makes the present-flag UPSERT a single ON CONFLICT clause.
CREATE TABLE IF NOT EXISTS vlans (
    device_id     INTEGER NOT NULL,
    vlan          INTEGER NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    seen_ts       REAL NOT NULL,
    first_seen_ts REAL NOT NULL,
    present       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, vlan)
);
-- vlan_ports: one row per port this device reports as VLAN-aware at all
-- (mode 'trunk'/'access'/'' — '' meaning "seen in a membership below but
-- neither table said which"), keyed by (device_id, if_index) since a port
-- has exactly one mode and (for a trunk) one native VLAN at a time. Read by
-- vlan_ports_for_devices for MAPPER's link detail (a_port_mode/
-- a_native_vlan and their b_ counterparts in get_mapper_map) — the
-- device's own reported native VLAN, a stronger source than the `native_vlan`
-- mapper.assemble_links derives from port_vlans.tagged.
CREATE TABLE IF NOT EXISTS vlan_ports (
    device_id     INTEGER NOT NULL,
    if_index      INTEGER NOT NULL,
    mode          TEXT NOT NULL DEFAULT '',   -- 'trunk' | 'access' | ''
    native_vlan   INTEGER,
    seen_ts       REAL NOT NULL,
    first_seen_ts REAL NOT NULL,
    present       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, if_index)
);
-- port_vlans: the actual membership — this VLAN crosses this port, tagged
-- or not. Keyed by all three of (device_id, if_index, vlan) because that
-- triple is the fact being recorded; `tagged` is not part of the key
-- (unlike mac_entries' vlan column, which can legitimately see the same
-- MAC on two VLANs) since a port carries a given VLAN exactly one way at
-- a time — a trunk that somehow answered both tagged and untagged for the
-- same VLAN would just have its second answer win the UPSERT, same as any
-- other re-observed fact.
CREATE TABLE IF NOT EXISTS port_vlans (
    device_id     INTEGER NOT NULL,
    if_index      INTEGER NOT NULL,
    vlan          INTEGER NOT NULL,
    tagged        INTEGER NOT NULL DEFAULT 1, -- 0 = untagged/native on this port
    seen_ts       REAL NOT NULL,
    first_seen_ts REAL NOT NULL,
    present       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, if_index, vlan)
);
-- The map reads none of these three tables fleet-wide: vlans_for_devices/
-- vlan_ports_for_devices/port_vlans_for_devices (MAPPER's own bounded shape,
-- devices_by_ids' "many known ids, one indexed read" applied to each table)
-- and the single-device vlans_for/port_vlans_for all filter by device_id,
-- one id or a handful via IN(...) — never nothing. Each of the three PRIMARY
-- KEYs above already LEADS with device_id, and SQLite implements a
-- non-INTEGER primary key as an index, so that lookup is served already: the
-- separate ix_vlans_device/ix_vlan_ports_device/ix_port_vlans_device this
-- block used to declare duplicated it exactly, and were three more B-trees
-- to write on every VLAN walk for nothing. _migrate drops them.

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
-- The primary key leads on metric_id, so the two queries that ask about
-- time across every metric — compact_rollup's per-hour aggregate and
-- prune's delete by age — scanned the whole table without this. On the
-- largest table in the database that was seconds of held lock per pass.
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
);
-- The primary key leads on metric_id, so "every rollup row older than N
-- days" — what prune() asks once per maintenance pass — would scan the
-- whole table without this.
CREATE INDEX IF NOT EXISTS ix_samples_hourly_hour ON samples_hourly(hour);

-- Every address a device is known to answer on, beside its primary `ip`.
-- A switch sends its traps from a loopback and its syslog from a
-- management VRF, and both are addresses the devices table has never
-- heard of, so the alert engine could not tell whose they were. Filled
-- best-effort from each poll's ipAddrTable read (source 'ipAddrTable');
-- `source` is kept so a later manual or protocol-learned entry can be
-- told apart from a polled one. The device's own `ip` is deliberately NOT
-- mirrored here — device_id_for_address falls back to devices.ip — so
-- there is one place a primary address is stored.
CREATE TABLE IF NOT EXISTS device_addresses (
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT '',
    seen_ts         REAL NOT NULL,
    PRIMARY KEY (device_id, ip)
);
CREATE INDEX IF NOT EXISTS ix_device_addresses_ip ON device_addresses(ip);

CREATE TABLE IF NOT EXISTS device_events (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    -- down|up|rebooted|auth_fail|auth_ok|poll_overrun|unsupported|snmp_error|
    -- snmp_up|snmp_down|ping_up|ping_down. The last four are per-method
    -- transitions (see nodepoll._poll_device) that back the split SNMP/ping
    -- status timeline lanes — separate from up/down, which stay the
    -- overall-reachability events every other reader (alerts, reports)
    -- already depends on.
    kind            TEXT NOT NULL,
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
-- The interface_id counterpart to ix_device_events_device_ts above. Every
-- per-interface read (interface_events(interface_id=...),
-- recent_interface_events_for, interface_events_for_device's join) is
-- keyed on it; without this SQLite scans or auto-indexes the whole table
-- on each call, growing with the fleet's total history rather than the
-- one device's.
CREATE INDEX IF NOT EXISTS ix_interface_events_iface_ts
    ON interface_events(interface_id, ts);

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

-- Fleet learning: an operator's manual vendor override, remembered against
-- the device's sysObjectID so every other device answering the same
-- sysObjectID is classified the same way on its next poll. Never written
-- for a generic-agent sysObjectID (net-snmp's 8072.x is shared by every
-- Linux box) — see set_vendor_override.
CREATE TABLE IF NOT EXISTS vendor_learned (
    sys_object_id    TEXT PRIMARY KEY,
    vendor           TEXT NOT NULL,
    set_by           TEXT,
    set_ts           REAL NOT NULL,
    source_device_id INTEGER
);

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
    # Consecutive failing SNMP polls (with ping OK — the "reachable but
    # broken" case) before the snmp_error device event fires, so a single
    # blip does not open the snmp_failing_ping_ok alert. Tracked in memory
    # by the poller (NodePoller._snmp_failing_count), reset the moment SNMP
    # succeeds again.
    "snmp_fail_alert_after": 3,
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
    # Raw samples are the expensive table and are what series() reads for a
    # window up to three days wide; anything wider reads samples_hourly.
    "sample_retention_days": 3,
    "rollup_retention_days": 400,    # hourly rollups; what a year-wide chart reads
    # Per metric, not across the whole table: the old whole-table 50,000
    # left a 2,000-device fleet with a third of a sample per metric. At the
    # shipped 120 s interval this is about seven days of raw points for one
    # metric, well past sample_retention_days, so it is a safety net rather
    # than the thing that decides retention.
    "sample_row_cap_per_metric": 5_000,
    "event_retention_days": 180,
    "discovery_retention_days": 30,
    "max_mib_bytes": 8 * 1024 * 1024,  # most uploaded MIB modules are tens
    # of KB, but a real vendor file can run to a few MB — the catalog's own
    # apc-ups (PowerNet-MIB, ~2.7 MiB) and cisco-core
    # (CISCO-ENTITY-VENDORTYPE-OID-MIB, ~1.4 MiB) both need headroom above
    # 1 MiB, the old cap, which refused them outright: a catalog entry the
    # app ships has to be installable by its own installer. 8 MiB clears
    # every shipped entry with room to grow. The cap still exists so one
    # upload cannot occupy a parser thread, and it also bounds the bundle
    # path, which multiplies it by the member count.
    # Installing a MIB bundle from the catalog. The per-file cap is
    # max_mib_bytes above; these bound the rest of the operation so a bad
    # upstream cannot fill the disk or hang a worker thread indefinitely.
    "mib_download_timeout_s": 30.0,
    "max_mib_zip_files": 400,
    "max_mib_bundle_bytes": 64 * 1024 * 1024,
    "resolve_addresses": True,
    "max_scan_addresses": 1024,
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
    # Every table walk (interfaces, MAC forwarding tables, DOM sensors, the
    # OID browser's per-subtree helpers) goes through nodepoll._walk_column,
    # which uses GETBULK on v2c/v3: one request answers up to this many rows
    # instead of one GETNEXT per row. 0 falls back to plain GETNEXT for a
    # device whose agent mishandles GetBulk; v1 always uses GETNEXT since
    # the PDU does not exist in that version of the protocol. A tooBig
    # reply from the device halves the request's own repetitions and
    # retries, independent of this setting.
    "snmp_bulk_max_repetitions": 40,
    # Safety cap on a single _walk_column call, replacing the old hardcoded
    # 512 — high enough that no real switch's forwarding table or ifTable
    # hits it, low enough that a looping agent cannot walk forever.
    "snmp_walk_max_rows": 16384,
    # How long a learned MAC stays searchable after the last walk that saw
    # it. A device dropped from the walk schedule stops refreshing its
    # entries, and after this they are dropped rather than answering
    # searches with a table nobody has confirmed since.
    "mac_table_retention_days": 7.0,
    # Vendor identification (vendorid.py). The bounded enterprises-only walk
    # that runs once per device on its first successful poll, again when its
    # sysObjectID changes, and behind Re-identify — never on the steady-state
    # poll cycle. The arc hop in a discovery sweep is separate and cheap
    # ((arcs + 1) GETNEXTs per device that answers SNMP).
    "vendor_walk_enabled": True,
    "vendor_walk_max_objects": 500,
    "vendor_walk_budget_s": 20.0,
    "vendor_walk_parallel": 4,
    "discovery_arc_hop": True,
    # A bounded ipAdEntAddr walk per identified address, so a sweep that
    # reaches one router on two of its L3 addresses can tell it is one
    # router rather than offering it twice. Off makes a sweep exactly
    # 4.54's: one row per address, nothing folded.
    "discovery_addresses": True,
}

# How wide a chart window still reads raw samples. Wider than this reads
# samples_hourly instead — which is why sample_retention_days defaults to
# the same three days: raw points older than the widest raw window can
# answer nothing a rollup does not.
RAW_WINDOW_S = 3 * 86400

_OVERRIDE_COLUMNS = ("snmp_version", "community", "v3_user", "v3_auth_proto",
                     "v3_auth_pass_enc", "poll_interval_s", "snmp_timeout_s",
                     "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                     "mib_file_id", "ping_count", "ping_timeout_ms",
                     "unreachable_ping_only", "vendor_oid", "location_oid",
                     "mac_table_interval_s", "lldp_interval_s", "poe_enabled",
                     "stp_enabled", "vlan_interval_s")

_GROUP_EDITABLE = ("name", "snmp_version", "community", "v3_user",
                   "v3_auth_proto", "poll_interval_s", "snmp_timeout_s",
                   "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set",
                   "mib_file_id", "ping_count", "ping_timeout_ms",
                   "unreachable_ping_only", "vendor_oid", "location_oid",
                   "mac_table_interval_s", "lldp_interval_s", "poe_enabled",
                   "stp_enabled", "vlan_interval_s")

# vendor_override is deliberately NOT an _OVERRIDE_COLUMNS entry: a vendor is a
# fact about one box, not something a polling profile should hand down.
_DEVICE_EDITABLE = ("name", "group_id", "device_group_id", "display_name_source",
                    "enabled", "vendor_override", "upstream_id") + _OVERRIDE_COLUMNS


# The separators a MAC address is written with in the wild. '.' covers the
# Cisco aabb.ccdd.eeff form; space covers a paste out of a spreadsheet.
_MAC_SEPARATORS = ":-. \t"
_HEX = set("0123456789abcdefABCDEF")


# One SQLite statement can bind at most SQLITE_MAX_VARIABLE_NUMBER
# parameters, and the bulk device routes bind one per id in a
# "WHERE id IN (?,?,…)". That ceiling is 32766 on SQLite 3.32 and newer
# (3.45 here) but 999 on anything older, and this application does not
# choose which SQLite its Python was linked against — so the number is not
# knowable at the call site, and a request that works on one operator's
# install would fail on another's with "too many SQL variables", an
# OperationalError the route would answer as a 500.
#
# Splitting the ids rather than capping them keeps the shipped workflow
# whole: the Devices page offers a 1000-row page size and a select-all that
# checks every row on it, so any cap below 1000 breaks bulk delete or bulk
# poll for an operator doing the obvious thing. Every chunk runs inside the
# caller's single `with self._lock:` and one commit, so the operation stays
# atomic — the split is a statement-size detail, not a transaction boundary.
_ID_CHUNK = 500


def _id_chunks(ids: list[int], size: int = _ID_CHUNK):
    for start in range(0, len(ids), size):
        yield ids[start:start + size]


_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def alias_candidate(ip) -> str:
    """The address as it would be stored in device_addresses, or "" for one
    that must never be: every device reports 127.0.0.1 in its ipAddrTable,
    and storing that would make one arbitrary device the owner of
    everything sent from localhost. Shared by record_device_addresses and
    by discovery, so identity folding and alias storage can never disagree
    about which addresses count."""
    text = str(ip or "").strip()
    if not text or text.startswith("127.") or text in ("0.0.0.0", "::1", "::"):
        return ""
    return text


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


def _upstream_confidence(match_kind: str, present: bool) -> tuple[str, int]:
    """A sort/filter handle for one upstream-suggestion candidate's
    evidence quality — never a threshold anything here uses to apply a
    suggestion by itself, only a hint for which one an operator should
    look at first. A chassis-MAC match is weighted over a sysName match:
    _NEIGHBOR_MATCH_SQL's own comment notes sysName can collide (two sites
    both naming a switch "core-sw-1"), where a MAC address collision is
    far rarer. A stale row (present=0 — nothing has confirmed this
    neighbour since an earlier walk) is weighted down regardless of match
    kind, because the physical link it describes may no longer exist.
    """
    if match_kind == "chassis_mac":
        return ("high", 3) if present else ("medium", 2)
    return ("medium", 2) if present else ("low", 1)


def _group_upstream_candidates(rows) -> dict[int, dict]:
    """Raw `_UPSTREAM_CANDIDATE_SQL` rows, one per observing device's own
    matched neighbour row, folded into one entry per device with its
    distinct matched devices deduplicated, keyed by matched device alone
    (a suggestion is "which device", not "which two ports").

    A device whose neighbour rows resolve to two or more DIFFERENT matched
    devices comes back `ambiguous`, with every candidate listed rather than
    one chosen — a two-candidate device an operator resolves is useful,
    a confident wrong pick is the failure alertrules.py's ROLLED_UP_BY
    comment warns a rollup based on an unconfirmed guess would produce.
    """
    by_device: dict[int, dict[int, dict]] = {}
    for row in rows:
        device_id = int(row["device_id"])
        matched_id = int(row["matched_device_id"])
        # "chassis_mac" whenever the MAC join independently agrees with the
        # winning id — including when the sysName join also fired for the
        # SAME device, which is the ordinary case for a device Nodes named
        # after its own sysName and deserves the stronger tier, not a
        # downgrade to "sys_name" just because COALESCE happens to read
        # byname first. Only when the MAC join found nothing for this id
        # (either it did not fire, or it fired for a DIFFERENT device) does
        # the sysName join get to name the match kind on its own.
        mac_id = row["matched_by_mac_id"]
        mac_agrees = mac_id is not None and int(mac_id) == matched_id
        if mac_agrees or row["matched_by_name_id"] is None:
            match_kind = "chassis_mac"
        else:
            match_kind = "sys_name"
        present = bool(row["present"])
        confidence, rank = _upstream_confidence(match_kind, present)
        candidates = by_device.setdefault(device_id, {})
        existing = candidates.get(matched_id)
        if existing is None:
            candidates[matched_id] = {
                "matched_device_id": matched_id,
                "matched_device_name": row["matched_device_name"],
                "match_kind": match_kind,
                "protocols": [row["protocol"]],
                "if_index": row["if_index"],
                "present": present,
                "seen_ts": row["seen_ts"],
                "first_seen_ts": row["first_seen_ts"],
                "confidence": confidence,
                "confidence_rank": rank,
            }
            continue
        if row["protocol"] not in existing["protocols"]:
            existing["protocols"].append(row["protocol"])
        # Several rows can name the same candidate (two uplinks to the same
        # core switch, or LLDP and CDP both reporting it) — keep the single
        # best-evidenced one: present beats stale, then the higher
        # confidence tier, then the most recently seen, so a candidate
        # backed by one fresh port and one long-stale one reads as fresh.
        if (present, rank, row["seen_ts"]) > (
                existing["present"], existing["confidence_rank"], existing["seen_ts"]):
            existing.update({
                "match_kind": match_kind, "if_index": row["if_index"],
                "present": present, "seen_ts": row["seen_ts"],
                "first_seen_ts": row["first_seen_ts"],
                "confidence": confidence, "confidence_rank": rank,
            })
    result = {}
    for device_id, candidates in by_device.items():
        ordered = sorted(candidates.values(),
                         key=lambda c: (-c["confidence_rank"], -c["seen_ts"]))
        result[device_id] = {"device_id": device_id, "candidates": ordered,
                             "ambiguous": len(ordered) > 1}
    return result


# device_events kinds that exist only to back the status timeline's split
# SNMP/ping lanes (see NodesDatabase.device_method_segments) and mean
# nothing on their own to any other reader — snmp_ok/ping_ok flipping is
# already covered by `down`/`up`/`snmp_error`/`auth_fail`. One name for the
# set, so the alert engine (which would otherwise turn each into an
# Occurrence no rule matches) and the overview histogram (which would count
# every outage three times: down + snmp_down + ping_down) skip the same four
# kinds by construction rather than by two lists agreeing.
TIMELINE_ONLY_EVENT_KINDS = frozenset(
    {"snmp_up", "snmp_down", "ping_up", "ping_down"})


class NodesDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "nodes"

    def __init__(self, path: str):
        # Bumped by every write that could change what or how a device is
        # polled. The scheduler holds one merged config per device and
        # rebuilds it only when this moves — see config_generation().
        self._config_generation = 0
        self._warned_no_window = False
        super().__init__(path)

    def _after_open(self) -> None:
        self._seed()

    def _migrate(self) -> None:
        # All nullable unless stated: NULL means "inherit the profile, then
        # the global setting", which is what _merge_config reads.
        self.ensure_columns("devices", {
            "device_group_id":
                "INTEGER REFERENCES device_groups(id) ON DELETE SET NULL",
            "display_name_source": "TEXT NOT NULL DEFAULT 'auto'",
            "mib_file_id": "INTEGER REFERENCES mib_files(id) ON DELETE SET NULL",
            "ping_count": "INTEGER",
            "ping_timeout_ms": "INTEGER",
            "unreachable_ping_only": "INTEGER",
            # Seconds between forwarding-table walks; 0 means never.
            "mac_table_interval_s": "INTEGER",
            # When set, the poller reads vendor and location from these
            # instead of deriving them from sysObjectID/sysLocation.
            "vendor_oid": "TEXT",
            "location_oid": "TEXT",
            # What identify_vendor() worked out, kept apart from `vendor`
            # (which a custom OID may have replaced for display): ConfigRX,
            # the Cisco MAC-table gate and discovery all read this one.
            "vendor_detected": "TEXT",
            # 'sysObjectID' | 'sysDescr' | 'oid' | '' — which of the three spoke.
            "vendor_source": "TEXT",
            # The enterprise arc, or NULL. Not the same fact as
            # vendor_source: a device named from sysDescr may still sit
            # under a real arc, and vendor-health tables key on this.
            "vendor_arc": "INTEGER",
            # NULL = never evaluated, 0/1 = uncovered/covered. Persisted so
            # the poller records mib_missing/mib_present on transitions only.
            "mib_covered": "INTEGER",
            # The operator's own answer, how sure the automatic one is, its
            # explanation, and which sysObjectID it was worked out for — so
            # the walk runs again only when the identity changes.
            "vendor_override": "TEXT",
            "vendor_confidence": "TEXT",
            "vendor_evidence": "TEXT",
            "identified_ts": "REAL",
            "identified_sys_object_id": "TEXT",
        })
        # Not in SCHEMA's own CREATE INDEX block: that script runs before this
        # method, so an index on a column added just above would fail on an
        # upgraded install the same way querying the column itself would.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_devices_device_group"
            " ON devices(device_group_id)")

        self.ensure_columns("groups", {
            "mib_file_id": "INTEGER REFERENCES mib_files(id) ON DELETE SET NULL",
            "ping_count": "INTEGER",
            "ping_timeout_ms": "INTEGER",
            "unreachable_ping_only": "INTEGER",
            "mac_table_interval_s": "INTEGER",
            "vendor_oid": "TEXT",
            "location_oid": "TEXT",
        })

        self.ensure_columns("interfaces", {
            "last_in_errors": "INTEGER",
            "last_out_errors": "INTEGER",
            # ifInDiscards/ifOutDiscards: congested rather than broken.
            "last_in_discards": "INTEGER",
            "last_out_discards": "INTEGER",
            "in_discard_rate": "REAL",
            "out_discard_rate": "REAL",
            # ifCounterDiscontinuityTime (RFC 2863), so a rate is never
            # computed across a counter reset — that reads as one huge burst.
            "discontinuity_ts": "REAL",
        })

        self.ensure_columns("discovery_jobs", {
            "allow_ping_only": "INTEGER NOT NULL DEFAULT 0",
            # Pre-upgrade jobs count as already reviewed, or every old
            # finished job would pop an approval dialog on first open.
            "reviewed": "INTEGER NOT NULL DEFAULT 1",
        })
        # What the sweep's arc hop found, carried into the device on
        # promotion so its first poll starts from the same evidence.
        self.ensure_columns("discovery_results", {
            "arcs": "TEXT", "vendor_source": "TEXT", "vendor_confidence": "TEXT",
            "suggest_bundle": "TEXT", "vendor_evidence": "TEXT",
        })

        # A MAC entry survives a walk that no longer sees it (present=0)
        # rather than being deleted outright.
        added = self.ensure_columns("mac_entries", {
            "first_seen_ts": "REAL",
            "present": "INTEGER NOT NULL DEFAULT 1",
        })
        if "first_seen_ts" in added:
            # Nothing is known about a pre-existing row beyond its seen_ts.
            self._conn.execute(
                "UPDATE mac_entries SET first_seen_ts = seen_ts WHERE first_seen_ts IS NULL")
        # Here and not in SCHEMA's CREATE INDEX block: that script runs
        # before this, and on a pre-4.34 database `present` only exists once
        # the ALTER above has run.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_mac_entries_mac_present"
            " ON mac_entries(mac, present, seen_ts)")
        # The alert engine asks for one metric key across the whole fleet
        # twelve times a minute (metrics_for_keys); the UNIQUE(device_id, key)
        # index leads with device_id and cannot serve a key-first query.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key)")
        # The device this one sits behind. Operator-set, nullable and
        # self-referential without a foreign key on purpose: the alert engine
        # treats an id that no longer exists as no upstream at all, which is
        # the same outcome ON DELETE SET NULL would give.
        self.ensure_columns("devices", {"upstream_id": "INTEGER"})
        # Walked downwards ("what is behind this outage") far more often than
        # upwards, and the upward walk is by primary key anyway.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_devices_upstream"
            " ON devices(upstream_id)")

        self.ensure_columns("devices", {
            # LLDP/CDP walk interval, inheritable like mac_table_interval_s.
            "lldp_interval_s": "INTEGER",
            # Per-port VLAN membership walk interval, inheritable the same
            # way — its own cadence (see _merge_config), not the poll cycle.
            "vlan_interval_s": "INTEGER",
            # PoE and STP ride the regular poll cycle, so they need only an
            # on/off switch; defaulted on in _merge_config because the
            # capability probe makes the walk free on a device without them.
            "poe_enabled": "INTEGER",
            "stp_enabled": "INTEGER",
            # The capability probe's memory: NULL = not yet probed, 0/1 =
            # probed once and remembered. Never inherited — whether a
            # specific box answers is a fact about that box, so these are
            # deliberately absent from _OVERRIDE_COLUMNS.
            "poe_capable": "INTEGER",
            "stp_capable": "INTEGER",
            "ups_capable": "INTEGER",
            "sensor_capable": "INTEGER",
            # Bridge-wide STP state (BRIDGE-MIB dot1dStp), refreshed every
            # poll once stp_capable is true. Device state, not a time series;
            # the topology-change counter goes through metrics/samples.
            "stp_protocol_spec": "TEXT",
            "stp_priority": "INTEGER",
            "stp_root_id": "TEXT",
            "stp_root_cost": "INTEGER",
            "stp_root_port": "INTEGER",
            "stp_time_since_change_s": "REAL",
        })
        self.ensure_columns("groups", {
            "lldp_interval_s": "INTEGER", "poe_enabled": "INTEGER",
            "stp_enabled": "INTEGER", "vlan_interval_s": "INTEGER",
        })
        # Per-port PoE and STP state, the same kind of fact as oper_status
        # and refreshed by the same poll cycle rather than a table of its own.
        self.ensure_columns("interfaces", {
            "poe_admin": "TEXT", "poe_detect_status": "TEXT",
            "stp_state": "TEXT", "poe_power_mw": "INTEGER",
        })

        # Every L3 address a sweep reached one device on, as JSON, and the
        # result this one was folded into when two probed addresses turned
        # out to be the same box.
        self.ensure_columns("discovery_results", {
            "ip_addresses": "TEXT", "folded_into_result_id": "INTEGER",
        })
        # What the hourly ipAddrTable walk reads beside the address itself,
        # so an alias can be shown as the interface and subnet it belongs to
        # rather than a bare address.
        self.ensure_columns("device_addresses", {
            "if_index": "INTEGER", "netmask": "TEXT",
        })
        # _NEIGHBOR_MATCH_SQL's two case-insensitive joins, which every
        # neighbour read and every map GET runs. Declared NOCASE because a
        # collated comparison can only use an index of the SAME collation:
        # devices(name COLLATE NOCASE, ip) already existed for the sysName
        # join's first half, these two are the other half and the chassis-MAC
        # join. In _migrate rather than SCHEMA only so the three DROPs below
        # sit with them; on a fresh file both are created on the first open
        # exactly as a SCHEMA line would have been.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_devices_sys_name_nocase"
            " ON devices(sys_name COLLATE NOCASE)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_interfaces_phys_addr_nocase"
            " ON interfaces(phys_addr COLLATE NOCASE)")
        # Duplicates of the three PRIMARY KEYs they sat beside (each leads
        # with device_id), so they answered nothing the table's own index did
        # not and cost a write per VLAN row walked. Dropped rather than left
        # in place: an upgraded database keeps them until this runs.
        for name in ("ix_vlans_device", "ix_vlan_ports_device", "ix_port_vlans_device"):
            self._conn.execute(f"DROP INDEX IF EXISTS {name}")

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

    def _private_setting(self, key: str, default=None):
        """A settings row this module keeps for itself. Not in DEFAULTS, so
        settings() never returns it and save_settings() cannot be made to
        overwrite it from the settings dialog — it is bookkeeping, not a
        preference."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (ValueError, TypeError):
            return default

    def _set_private_setting(self, key: str, value) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES (?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))
            self._conn.commit()

    def save_settings(self, values: dict) -> None:
        super().save_settings(values)
        with self._lock:
            self._config_generation += 1

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
            self._config_generation += 1
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
            self._config_generation += 1

    def set_group_credential(self, group_id: int, user: str, auth_proto: str,
                             password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, group_id))
            self._conn.commit()
            self._config_generation += 1

    def clear_group_credential(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_auth_pass_enc=NULL WHERE id=?", (group_id,))
            self._conn.commit()
            self._config_generation += 1

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
            self._config_generation += 1

    def set_default_group(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE groups SET is_default = 0 WHERE is_default = 1")
            self._conn.execute("UPDATE groups SET is_default = 1 WHERE id = ?",
                               (group_id,))
            self._conn.commit()
            self._config_generation += 1

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
            self._config_generation += 1
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
            self._config_generation += 1

    def set_group_credential_password(self, credential_id: int, user: str,
                                      auth_proto: str, password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE group_credentials SET v3_user=?, v3_auth_proto=?,"
                " v3_auth_pass_enc=? WHERE id=?",
                (user, auth_proto, password_enc, credential_id))
            self._conn.commit()
            self._config_generation += 1

    def clear_group_credential_password(self, credential_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE group_credentials SET v3_auth_pass_enc=NULL WHERE id=?",
                (credential_id,))
            self._conn.commit()
            self._config_generation += 1

    def remove_group_credential(self, credential_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM group_credentials WHERE id = ?", (credential_id,))
            self._conn.commit()
            self._config_generation += 1

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

    def _device_filter_clause(self, group_id: int | None, status: str | None,
                              text: str | None, device_group_id: int | None,
                              exclude_up: bool) -> tuple[str, list]:
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
            # Also searched: sys_location, sys_descr (model/description),
            # sys_contact and vendor — an operator hunting "the Moxa in
            # Site-B" knows those facts about a device, not necessarily its
            # name or IP. Measured at 2000 devices (demo/out/tierC1/data-2000):
            # a full-table-scan LIKE over all seven columns runs ~13ms mean
            # vs ~9ms for the three it replaces — still far under anything
            # an operator would notice, so no index/FTS table is warranted
            # at this scale.
            #
            # A MAC search matches the stored forwarding tables as well as
            # the device's own fields, so typing an address a switch has
            # learned filters the list down to the switches that see it.
            # Only from four hex digits: fewer would match half the estate
            # and turn a search into a shuffle.
            text_cols = ("ip", "name", "sys_name", "sys_location",
                         "sys_descr", "sys_contact", "vendor")
            text_sql = " OR ".join(f"{col} LIKE ?" for col in text_cols)
            mac = looks_like_mac_search(text)
            if len(mac) >= 4:
                clauses.append(
                    f"({text_sql}"
                    " OR id IN (SELECT device_id FROM mac_entries"
                    "           WHERE mac LIKE ?))")
                params.extend([f"%{text}%"] * len(text_cols) + [f"{mac}%"])
            else:
                clauses.append(f"({text_sql})")
                params.extend([f"%{text}%"] * len(text_cols))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def devices(self, group_id: int | None = None, status: str | None = None,
               text: str | None = None, device_group_id: int | None = None,
               exclude_up: bool = False, limit: int | None = None,
               offset: int = 0) -> list[sqlite3.Row]:
        # `limit=None` runs no LIMIT clause at all, so an unpaged caller
        # gets the whole matching set back.
        where, params = self._device_filter_clause(
            group_id, status, text, device_group_id, exclude_up)
        query = f"SELECT * FROM devices{where} ORDER BY name COLLATE NOCASE, ip"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params = [*params, limit, offset]
        with self._lock:
            return self._conn.execute(query, params).fetchall()

    def devices_count(self, group_id: int | None = None, status: str | None = None,
                      text: str | None = None, device_group_id: int | None = None,
                      exclude_up: bool = False) -> int:
        """How many devices match, ignoring `limit`/`offset` — the same
        shape alertsdb.count_alerts already established for "how many
        pages is this", asked with the identical filter clause devices()
        itself builds so the two can never disagree about what matched."""
        where, params = self._device_filter_clause(
            group_id, status, text, device_group_id, exclude_up)
        with self._lock:
            return int(self._conn.execute(
                f"SELECT COUNT(*) FROM devices{where}", params).fetchone()[0])

    def device(self, device_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def device_by_ip(self, ip: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()

    # How many ids go into one IN (...) list. SQLite builds before 3.32 cap
    # SQLITE_MAX_VARIABLE_NUMBER at 999 bind parameters, and the callers here
    # are page-sized rather than small: an alert list is up to 2000 rows, each
    # of which can name a device. 500 keeps every statement well inside the
    # oldest limit and still asks at most a handful of questions.
    _IDS_PER_QUERY = 500

    def devices_by_ids(self, device_ids) -> list[sqlite3.Row]:
        """device() for many ids, in as few queries as the bind-parameter
        limit allows. Order is unspecified — callers needing a particular
        order build a dict keyed by id from the result. Duplicate ids are
        collapsed, so a caller may hand this a list straight off its rows."""
        ids = list(dict.fromkeys(device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    f"SELECT * FROM devices WHERE id IN ({marks})", chunk).fetchall()
        return rows

    def upstream_chain(self, device_id: int, max_depth: int = 8) -> list[int]:
        """Device ids above this one, nearest first.

        Cycle-safe and depth-capped, because upstream_id is a free-text-ish
        operator field with no constraint stopping A -> B -> A: a walk that
        trusted it would spin forever on the alert engine's tick thread. A
        cycle simply ends the walk at the repeat, and eight levels is deeper
        than any real access/distribution/core/edge chain.
        """
        chain: list[int] = []
        seen = {int(device_id)}
        current = int(device_id)
        with self._lock:
            for _ in range(max(0, int(max_depth))):
                row = self._conn.execute(
                    "SELECT upstream_id FROM devices WHERE id = ?",
                    (current,)).fetchone()
                if row is None or row["upstream_id"] is None:
                    break
                parent = int(row["upstream_id"])
                if parent in seen:
                    break
                seen.add(parent)
                chain.append(parent)
                current = parent
        return chain

    def downstream_ids(self, device_id: int, max_total: int = 2000) -> list[int]:
        """Every device beneath this one, transitively, nearest level first.

        Breadth-first a level at a time rather than one query per device: a
        site outage asks this once for a core switch with hundreds of access
        switches behind it. Cycle-safe by the same `seen` set as
        upstream_chain, and capped so a mis-typed topology cannot turn one
        outage into an unbounded query.
        """
        out: list[int] = []
        seen = {int(device_id)}
        frontier = [int(device_id)]
        with self._lock:
            while frontier and len(out) < max_total:
                found: list[int] = []
                # Chunked: SQLite's bound-variable limit is generous but not
                # infinite, and a wide level can be thousands of ids.
                for start in range(0, len(frontier), 500):
                    batch = frontier[start:start + 500]
                    marks = ",".join("?" * len(batch))
                    for row in self._conn.execute(
                            f"SELECT id FROM devices WHERE upstream_id IN ({marks})"
                            " ORDER BY id", batch).fetchall():
                        child = int(row["id"])
                        if child in seen:
                            continue
                        seen.add(child)
                        out.append(child)
                        found.append(child)
                        if len(out) >= max_total:
                            break
                    if len(out) >= max_total:
                        break
                frontier = found
        return out

    def metrics_for_keys(self, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key, fleet-wide, in one query.

        The alert engine used to read `SELECT * FROM metrics WHERE device_id
        = ?` once per device per tick — at 2,000 devices and ~90 metrics
        each, 400,000 full rows every five seconds through the same
        connection and lock the poller writes with, to evaluate a handful of
        threshold rules. It reads four columns for the keys that have a rule
        instead.

        Disabled devices are excluded here rather than by the caller: a
        device somebody turned off is not being polled, so its last value is
        by definition stale and must not hold an alert open.
        """
        keys = [str(k) for k in keys if k]
        if not keys:
            return []
        marks = ",".join("?" * len(keys))
        with self._lock:
            return self._conn.execute(
                "SELECT m.device_id, m.key, m.label, m.last_value, m.last_ts"
                f" FROM metrics m JOIN devices d ON d.id = m.device_id"
                f" WHERE d.enabled = 1 AND m.key IN ({marks})", keys).fetchall()

    # ------------------------------------------------- bounded fleet reads
    #
    # metrics_for_keys above is the RIGHT read for the alert engine, which
    # genuinely evaluates every device. It is the wrong one for a caller
    # that already knows which handful of devices it is drawing — MAPPER's
    # map GET reads two metric keys and a port count for the devices one
    # map places, and used to pull the whole fleet's rows for the first and
    # run one interfaces() query per node for the second. These four are
    # the "many known ids, one indexed read" shape devices_by_ids
    # established, applied to the four things that route asks for. Each
    # chunks by _IDS_PER_QUERY for the same bind-parameter reason, and each
    # returns an empty result for empty input without touching the database.

    def metrics_for_devices(self, device_ids, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key, for named devices only.

        Disabled devices are excluded exactly as metrics_for_keys excludes
        them, and for the same reason: a device nobody is polling has no
        current reading, whoever is asking."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        keys = [str(k) for k in keys if k]
        if not ids or not keys:
            return []
        key_marks = ",".join("?" * len(keys))
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    "SELECT m.device_id, m.key, m.label, m.last_value, m.last_ts"
                    " FROM metrics m JOIN devices d ON d.id = m.device_id"
                    f" WHERE d.enabled = 1 AND m.device_id IN ({marks})"
                    f" AND m.key IN ({key_marks})", [*chunk, *keys]).fetchall()
        return rows

    def interface_counts(self, device_ids) -> dict:
        """{device_id: how many interface rows it has}, for named devices.

        A device with no interface rows at all is absent from the result
        rather than present with 0 — "never polled" and "polled, has no
        ports" are different facts, and only the caller knows which of the
        two it wants to draw."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return {}
        counts: dict = {}
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                for row in self._conn.execute(
                        "SELECT device_id, COUNT(*) AS n FROM interfaces"
                        f" WHERE device_id IN ({marks}) GROUP BY device_id",
                        chunk).fetchall():
                    counts[row["device_id"]] = row["n"]
        return counts

    def interface_port_labels_for_devices(self, device_ids) -> list[sqlite3.Row]:
        """(device_id, if_index, descr, alias) for named devices — the four
        columns a port LABEL needs, not the whole interface row. What
        api._neighbor_local_port_labeler prefills its cache from, so a map
        GET asks once for every device it places instead of once per
        device as each first neighbour row reaches the closure."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    "SELECT device_id, if_index, descr, alias FROM interfaces"
                    f" WHERE device_id IN ({marks}) ORDER BY device_id, if_index",
                    chunk).fetchall()
        return rows

    def interface_port_labels(self, device_id: int) -> list[sqlite3.Row]:
        """interface_port_labels_for_devices for one device."""
        return self.interface_port_labels_for_devices([device_id])

    def device_summaries(self) -> list[sqlite3.Row]:
        """Every device, but only the seven columns a picker needs: id, ip,
        status, vendor, and the three namelookup.device_name reads
        (name, sys_name, display_name_source).

        devices() returns SELECT * — around forty columns including
        sysDescr and the vendor-evidence text — which is what MAPPER's
        "Add device" list was paying for a name, an address and a vendor
        per row."""
        with self._lock:
            return self._conn.execute(
                "SELECT id, name, ip, status, vendor, sys_name, display_name_source"
                " FROM devices ORDER BY name COLLATE NOCASE, ip").fetchall()

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
            self._config_generation += 1
            return cur.lastrowid

    def seed_identity(self, device_id: int, *, sys_descr: str = "",
                      sys_name: str = "", sys_object_id: str = "",
                      vendor: str = "", vendor_source: str = "",
                      vendor_confidence: str = "",
                      vendor_evidence: str | None = None) -> None:
        """Pre-fills the identity columns from a discovery result so a
        just-promoted device shows its sysName immediately instead of a
        bare IP until its first poll (which overwrites these with the same
        values anyway).

        identified_ts is deliberately left NULL: the sweep's arc hop names a
        vendor, but scoring the MIB corpus and assigning a MIB need the
        poller, so the first poll still runs the full fingerprint."""
        with self._lock:
            # vendor_detected too: discovery identified this from SNMP, so it
            # is a detected value by definition, and leaving it NULL until the
            # first poll would make ConfigRX and the Cisco MAC read fall back
            # to a blank vendor on a device that was just identified.
            self._conn.execute(
                "UPDATE devices SET sys_descr = ?, sys_name = ?,"
                " sys_object_id = ?, vendor = ?, vendor_detected = ?,"
                " vendor_source = ?, vendor_confidence = ?, vendor_evidence = ?"
                " WHERE id = ?",
                (sys_descr, sys_name, sys_object_id, vendor, vendor,
                 vendor_source or "", vendor_confidence or "", vendor_evidence,
                 device_id))
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
            self._config_generation += 1

    def bulk_update_devices(self, device_ids: list[int], **fields) -> None:
        # (see _id_chunks below for why the id list is split)
        """The same field allow-list as update_device, applied to many rows
        in one statement/transaction rather than one round trip per
        device — the shape post_nodes_discovery_promote's device_ids list
        already established for "operate on many ids from one request"."""
        allowed = {k: v for k, v in fields.items() if k in _DEVICE_EDITABLE}
        if not allowed or not device_ids:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            for chunk in _id_chunks(device_ids):
                marks = ",".join("?" * len(chunk))
                self._conn.execute(
                    f"UPDATE devices SET {clauses} WHERE id IN ({marks})",
                    (*allowed.values(), *chunk))
            self._conn.commit()
            self._config_generation += 1

    def add_devices_bulk(self, rows: list[dict]) -> list[int]:
        """Insert many devices in one transaction — all of them or none.

        Every row here has already been validated, address-checked and
        de-duplicated by the caller (post_nodes_devices_bulk_import in
        api.py); this method's only job is the insert, atomically, so a
        conflict partway through a 2,000-row paste cannot leave the fleet
        half-imported while the per-row disposition list the API returns
        says otherwise. Each row is
        {"ip": str, "name": str|None, "group_id": int|None,
         "device_group_id": int|None, "overrides": {col: value, ...}} —
         the same shape add_device's own arguments take, just pre-bundled
        so this can loop without a second round of keyword handling.
        """
        if not rows:
            return []
        ids = []
        with self._lock:
            try:
                for row in rows:
                    cols = ["ip", "name", "group_id", "device_group_id", "created_ts"]
                    vals = [row["ip"], row.get("name") or row["ip"],
                           row.get("group_id"), row.get("device_group_id"), time.time()]
                    for key in _OVERRIDE_COLUMNS:
                        if key in (row.get("overrides") or {}):
                            cols.append(key)
                            vals.append(row["overrides"][key])
                    marks = ",".join("?" * len(vals))
                    cur = self._conn.execute(
                        f"INSERT INTO devices({','.join(cols)}) VALUES ({marks})", vals)
                    ids.append(cur.lastrowid)
            except Exception:
                self._conn.rollback()
                raise
            self._conn.commit()
            self._config_generation += 1
        return ids

    def bulk_remove_devices(self, device_ids: list[int]) -> int:
        if not device_ids:
            return 0
        removed = 0
        with self._lock:
            for chunk in _id_chunks(device_ids):
                marks = ",".join("?" * len(chunk))
                cursor = self._conn.execute(
                    f"DELETE FROM devices WHERE id IN ({marks})", chunk)
                removed += cursor.rowcount or 0
            self._conn.commit()
            self._config_generation += 1
            return removed

    def set_device_credential(self, device_id: int, user: str, auth_proto: str,
                              password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, device_id))
            self._conn.commit()
            self._config_generation += 1

    def clear_device_credential(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_auth_pass_enc=NULL WHERE id=?", (device_id,))
            self._conn.commit()
            self._config_generation += 1

    def remove_device(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            self._conn.commit()
            self._config_generation += 1

    def config_generation(self) -> int:
        """A counter that moves whenever a settings, profile, credential or
        device write could change how something is polled.

        The scheduler used to re-read the whole device table and call
        effective_config() — itself four settings reads and a group read —
        once per device per second: 4,001 statements a second at 2,000
        devices, under the same lock every poll worker needs. It now holds
        the merged configs and rebuilds them only when this number changes.
        A plain in-memory counter, not a stored value: it only has to be
        comparable within one process, and the poller lives in the same
        process as every writer.
        """
        return self._config_generation

    def schedule_rows(self) -> list[sqlite3.Row]:
        """Just the columns the scheduling loop reads, for enabled devices
        only. `SELECT *` pulled sys_descr and every credential blob for
        every device once a second to look at four integers."""
        with self._lock:
            return self._conn.execute(
                "SELECT id, name, ip, status, consecutive_fail, last_poll_ts"
                " FROM devices WHERE enabled = 1").fetchall()

    def effective_configs(self) -> dict:
        """effective_config() for every enabled device, with the settings
        and groups tables read once between them all rather than once (four
        times, in settings()' case) per device."""
        settings = self.settings()
        with self._lock:
            groups = {row["id"]: row for row in
                      self._conn.execute("SELECT * FROM groups").fetchall()}
            devices = self._conn.execute(
                "SELECT * FROM devices WHERE enabled = 1").fetchall()
        return {row["id"]: self._merge_config(
                    row, groups.get(row["group_id"]), settings)
                for row in devices}

    def effective_config(self, device_row: sqlite3.Row) -> dict:
        """Merges a device's own non-NULL override columns over its group's
        row (or DEFAULTS if the device has no group). This is the single
        place "per device or per device group" is actually resolved."""
        group_row = self.group(device_row["group_id"]) if device_row["group_id"] else None
        return self._merge_config(device_row, group_row, self.settings())

    def _merge_config(self, device_row, group_row, settings: dict) -> dict:
        """The merge itself, given rows already read. Split out so
        effective_configs() can do the reads once for a whole fleet."""
        config = {}
        for key in _OVERRIDE_COLUMNS:
            value = device_row[key] if key in device_row.keys() else None
            if value is None and group_row is not None and key in group_row.keys():
                value = group_row[key]
            config[key] = value
        if config.get("snmp_version") is None:
            config["snmp_version"] = 1
        if config.get("poll_interval_s") is None:
            config["poll_interval_s"] = settings.get("default_interval_s", 120)
        if config.get("snmp_timeout_s") is None:
            config["snmp_timeout_s"] = settings.get("default_snmp_timeout_s", 3.0)
        if config.get("snmp_retries") is None:
            config["snmp_retries"] = settings.get("default_snmp_retries", 2)
        if config.get("ping_enabled") is None:
            config["ping_enabled"] = 1
        if config.get("snmp_enabled") is None:
            config["snmp_enabled"] = 1
        if config.get("oid_set") is None:
            config["oid_set"] = "auto"
        if config.get("ping_count") is None:
            config["ping_count"] = settings.get("ping_count", 3)
        if config.get("ping_timeout_ms") is None:
            config["ping_timeout_ms"] = settings.get("ping_timeout_ms", 1000)
        if config.get("unreachable_ping_only") is None:
            config["unreachable_ping_only"] = \
                1 if settings.get("unreachable_ping_only", True) else 0
        # 3600 (one hour), not a global setting, is the fallback: fleet-wide
        # MAC-to-port search is the product's best feature, and shipping it
        # invisible (the old 0 = off default) means most installs never see
        # it. An hour keeps the walk far from the poll cycle's cost profile
        # (thousands of rows per switch, see the mac_entries comment above)
        # while still filling the table on the first day. A group or device
        # that explicitly stores 0 to opt back out keeps that choice on
        # every upgrade — this fallback only fires for NULL ("inherit"),
        # so an existing install with no explicit override picks up the new
        # default the same as a fresh one; there is no separate migration
        # path, deliberately, since 0 was never distinguishable from "never
        # configured" for any row that did not set it on purpose.
        if config.get("mac_table_interval_s") is None:
            config["mac_table_interval_s"] = 3600
        # LLDP/CDP: same fallback, same reasoning, as mac_table_interval_s
        # immediately above — an hour keeps the walk far from the poll
        # cycle's cost profile while still filling the topology table on the
        # first day, and a device or group that stores 0 on purpose keeps
        # that choice on every upgrade.
        if config.get("lldp_interval_s") is None:
            config["lldp_interval_s"] = 3600
        # VLAN membership: an hour like the two above, EXCEPT on a device or
        # group that has turned the LLDP/CDP walk off. Per-port VLAN data
        # exists to colour the strands on a MAPPER link, and a link is drawn
        # from an LLDP or CDP neighbour row — so with that walk off there are
        # no links to colour, and walking up to thirteen more columns hourly
        # would buy an operator who already said "do not table-walk this
        # profile" precisely nothing. Following lldp_interval_s makes the
        # existing opt-out carry to the new setting instead of every device
        # in the fleet quietly starting an hourly walk the moment 4.54
        # starts; an explicit non-zero vlan_interval_s still wins, so a site
        # that genuinely wants VLAN data without neighbour discovery can say
        # so. Deliberately keyed on lldp_interval_s and not on
        # mac_table_interval_s: 0 is the SHIPPED value there, so most
        # profiles carry it without anyone having decided anything, and
        # reading intent into it would be a guess.
        if config.get("vlan_interval_s") is None:
            config["vlan_interval_s"] = 3600 if config["lldp_interval_s"] else 0
        # PoE and STP ride the poll cycle rather than a walk of their own
        # (see the devices.poe_capable/stp_capable migration comment), so
        # there is no cost to default them on — a device that does not
        # answer either table is probed once and never asked again.
        if config.get("poe_enabled") is None:
            config["poe_enabled"] = 1
        if config.get("stp_enabled") is None:
            config["stp_enabled"] = 1
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
                    "vendor_confidence": identity.get("vendor_confidence") or "",
                    "vendor_arc": identity.get("vendor_arc"),
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

    # ------------------------------------------------------- device addresses

    def record_device_addresses(self, device_id: int, ips, source: str,
                                details: dict | None = None) -> int:
        """Remember the addresses a device answers on besides its primary
        `ip`, so a trap or syslog message from its loopback or its
        management VRF correlates to the device that sent it.

        An upsert per (device_id, ip) rather than delete-and-insert: an
        address the device stopped advertising is still the address last
        seen for it, and dropping it would silently un-correlate whatever
        is still sending from there. Rows for the device's own primary
        address are skipped — that one lives in `devices.ip` and
        device_id_for_address already falls back to it. Which addresses
        may be stored at all is alias_candidate's decision.

        `details` is {ip: {"if_index": int, "netmask": str}} where the
        walk read them. COALESCEd rather than overwritten, so a source
        that knows only the address (a trap, or a discovery fold) never
        erases what the poller's fuller walk already learned.
        """
        now = time.time()
        details = details or {}
        rows = []
        for ip in ips or ():
            text = alias_candidate(ip)
            if not text:
                continue
            extra = details.get(text) or {}
            rows.append((device_id, text, source or "", now,
                         extra.get("if_index"), extra.get("netmask")))
        if not rows:
            return 0
        with self._lock:
            # The device's own address is not stored twice; a row that was
            # previously learned for another device moves here, because the
            # newest evidence is what an address currently belongs to.
            primary = self._conn.execute(
                "SELECT ip FROM devices WHERE id = ?", (device_id,)).fetchone()
            primary_ip = primary["ip"] if primary else ""
            rows = [row for row in rows if row[1] != primary_ip]
            if not rows:
                return 0
            self._conn.executemany(
                "INSERT INTO device_addresses(device_id, ip, source, seen_ts,"
                " if_index, netmask) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(device_id, ip) DO UPDATE SET"
                " source=excluded.source, seen_ts=excluded.seen_ts,"
                " if_index=COALESCE(excluded.if_index, device_addresses.if_index),"
                " netmask=COALESCE(excluded.netmask, device_addresses.netmask)", rows)
            self._conn.commit()
        return len(rows)

    def device_id_for_address(self, ip: str) -> int | None:
        """Which device answers on this address: its primary `ip` first,
        then any alias learned for it. Primary first because that is the
        address the operator configured, and an alias is only ever
        supporting evidence."""
        text = str(ip or "").strip()
        if not text:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM devices WHERE ip = ?", (text,)).fetchone()
            if row is not None:
                return row["id"]
            row = self._conn.execute(
                "SELECT device_id FROM device_addresses WHERE ip = ?"
                " ORDER BY seen_ts DESC LIMIT 1", (text,)).fetchone()
        return row["device_id"] if row else None

    def device_addresses(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_addresses WHERE device_id = ? ORDER BY ip",
                (device_id,)).fetchall()

    # ------------------------------------------- identity, duplicates, merge

    def address_owners(self) -> dict[str, int]:
        """Every alias address in the fleet -> the device that answers on
        it. One read rather than a device_id_for_address() per candidate:
        discovery asks this once per sweep and then tests every address it
        walked against the answer."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, device_id FROM device_addresses"
                " ORDER BY seen_ts").fetchall()
        return {row["ip"]: row["device_id"] for row in rows}

    def devices_by_identity(self) -> dict[tuple, sqlite3.Row]:
        """(sys_name lowercased, sysObjectID) -> the lowest-id device that
        answers with both. Only ever a hint — two switches out of the same
        box with the same default hostname share this key honestly — which
        is why nothing folds on it without an address to agree."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM devices WHERE sys_name <> '' AND"
                " sys_object_id IS NOT NULL AND sys_object_id <> ''"
                " ORDER BY id").fetchall()
        index: dict[tuple, sqlite3.Row] = {}
        for row in rows:
            index.setdefault(
                ((row["sys_name"] or "").lower(), row["sys_object_id"] or ""), row)
        return index

    # A MAC every member of an HSRP/VRRP group answers with. Two routers
    # sharing one of these are a working redundant pair, which is the
    # opposite of the same device twice, so a match on one is no evidence
    # at all rather than weak evidence.
    _VIRTUAL_MAC_PREFIXES = ("00005e0001", "00005e0002", "00000c07ac")

    def duplicate_candidates(self, limit: int = 200) -> list[dict]:
        """Pairs of devices that look like one device entered twice, newest
        evidence first. Never acts: every pair here is something an
        operator is asked about, because the three sources below are each
        wrong in a way only a human can see — a NAT'd management address, a
        chassis MAC reused across a stack, a hostname a template set on
        forty switches.

        Confidence is what the evidence can carry on its own: an address
        two devices both claim is one device answering twice (high); a
        shared chassis MAC is high with a second MAC or a matching hostname
        behind it and medium alone; hostname plus sysObjectID is medium;
        hostname alone is low.
        """
        pairs: dict[tuple, dict] = {}

        def entry(a_id: int, b_id: int) -> dict:
            lo, hi = (a_id, b_id) if a_id < b_id else (b_id, a_id)
            return pairs.setdefault((lo, hi), {
                "a_id": lo, "b_id": hi, "reasons": [], "shared_macs": 0,
                "suggested_winner_id": lo, "confidence": "low",
            })

        with self._lock:
            alias_primary = self._conn.execute(
                "SELECT da.device_id AS a_id, d.id AS b_id, da.ip AS ip"
                " FROM device_addresses da JOIN devices d ON d.ip = da.ip"
                " WHERE d.id <> da.device_id").fetchall()
            alias_alias = self._conn.execute(
                "SELECT a.device_id AS a_id, b.device_id AS b_id, a.ip AS ip"
                " FROM device_addresses a JOIN device_addresses b"
                " ON a.ip = b.ip AND a.device_id < b.device_id").fetchall()
            macs = self._conn.execute(
                "SELECT i1.device_id AS a_id, i2.device_id AS b_id,"
                " i1.phys_addr AS mac FROM interfaces i1 JOIN interfaces i2"
                " ON i1.phys_addr = i2.phys_addr COLLATE NOCASE"
                " AND i1.device_id < i2.device_id"
                " WHERE i1.phys_addr IS NOT NULL AND i1.phys_addr <> ''"
                " AND i1.phys_addr <> '000000000000'"
                " AND i1.phys_addr <> 'ffffffffffff'").fetchall()
            names = self._conn.execute(
                "SELECT d1.id AS a_id, d2.id AS b_id, d1.sys_name AS sys_name,"
                " (d1.sys_object_id = d2.sys_object_id AND d1.sys_object_id <> '')"
                " AS same_oid FROM devices d1 JOIN devices d2"
                " ON d1.sys_name = d2.sys_name COLLATE NOCASE AND d1.id < d2.id"
                " WHERE d1.sys_name <> ''").fetchall()

        for row in list(alias_primary) + list(alias_alias):
            item = entry(row["a_id"], row["b_id"])
            reason = f"both answer on {row['ip']}"
            if reason not in item["reasons"]:
                item["reasons"].append(reason)
            item["confidence"] = "high"

        mac_pairs: dict[tuple, set] = {}
        for row in macs:
            mac = normalize_mac(row["mac"])
            if not mac or any(mac.startswith(p) for p in self._VIRTUAL_MAC_PREFIXES):
                continue
            key = (row["a_id"], row["b_id"])
            mac_pairs.setdefault(key, set()).add(mac)
        name_pairs = {(row["a_id"], row["b_id"]): row for row in names}
        for (a_id, b_id), shared in mac_pairs.items():
            item = entry(a_id, b_id)
            item["shared_macs"] = len(shared)
            item["reasons"].append(
                f"{len(shared)} shared interface MAC(s), including {sorted(shared)[0]}")
            if item["confidence"] != "high":
                item["confidence"] = "high" if (
                    len(shared) >= 2 or (a_id, b_id) in name_pairs) else "medium"

        for (a_id, b_id), row in name_pairs.items():
            item = entry(a_id, b_id)
            item["reasons"].append(
                f"both call themselves {row['sys_name']}"
                + (" with the same sysObjectID" if row["same_oid"] else ""))
            if item["confidence"] == "low":
                item["confidence"] = "medium" if row["same_oid"] else "low"

        ordered = sorted(pairs.values(),
                         key=lambda item: (_CONFIDENCE_ORDER.get(item["confidence"], 3),
                                           item["a_id"], item["b_id"]))
        return ordered[:max(1, int(limit))]

    _MERGE_COUNT_QUERIES = (
        ("addresses", "SELECT COUNT(*) FROM device_addresses WHERE device_id = ?"),
        ("interfaces", "SELECT COUNT(*) FROM interfaces WHERE device_id = ?"),
        ("events", "SELECT COUNT(*) FROM device_events WHERE device_id = ?"),
        ("metrics", "SELECT COUNT(*) FROM metrics WHERE device_id = ?"),
        ("neighbours", "SELECT COUNT(*) FROM neighbors WHERE device_id = ?"),
        ("mac_entries", "SELECT COUNT(*) FROM mac_entries WHERE device_id = ?"),
        ("vlans", "SELECT COUNT(*) FROM vlans WHERE device_id = ?"),
        ("port_vlans", "SELECT COUNT(*) FROM port_vlans WHERE device_id = ?"),
        ("upstream_children", "SELECT COUNT(*) FROM devices WHERE upstream_id = ?"),
    )

    def merge_plan(self, loser_id: int, winner_id: int) -> dict:
        """What merging would move and what it would discard, counted
        without writing anything — the dialog shows this before the
        operator presses Merge, because a merge cannot be undone."""
        loser = self.device(loser_id)
        winner = self.device(winner_id)
        if loser is None or winner is None:
            raise ValueError("Both devices must exist")
        if loser_id == winner_id:
            raise ValueError("A device cannot be merged into itself")
        counts = {}
        with self._lock:
            for name, query in self._MERGE_COUNT_QUERIES:
                counts[name] = int(
                    self._conn.execute(query, (loser_id,)).fetchone()[0])
        return {"loser_id": loser_id, "winner_id": winner_id, "counts": counts}

    def merge_devices(self, loser_id: int, winner_id: int) -> dict:
        """Fold the loser into the winner: one transaction, and the loser's
        row is gone at the end of it.

        What moves is what belongs to the box rather than to the row — its
        addresses (its own primary among them, now an alias saying where it
        used to be reachable), the events that are its history, and
        anything pointing at it. What does NOT move is the polled state
        both rows hold twice over: interfaces, metrics, MAC and neighbour
        tables are the same physical ports read through a second address,
        and the winner is already refreshing them. Those go with the loser
        through the FK cascade, except vlans/vlan_ports/port_vlans, which
        have no foreign key and are deleted here by hand.
        """
        plan = self.merge_plan(loser_id, winner_id)
        now = time.time()
        with self._lock:
            loser = self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (loser_id,)).fetchone()
            winner = self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (winner_id,)).fetchone()
            try:
                self._conn.execute(
                    "UPDATE OR IGNORE device_addresses SET device_id = ?"
                    " WHERE device_id = ?", (winner_id, loser_id))
                # An alias whose address the winner already answers on
                # primarily is not an alias at all any more.
                self._conn.execute(
                    "DELETE FROM device_addresses WHERE device_id = ? AND ip = ?",
                    (winner_id, winner["ip"]))
                if loser["ip"] and loser["ip"] != winner["ip"]:
                    self._conn.execute(
                        "INSERT INTO device_addresses(device_id, ip, source,"
                        " seen_ts) VALUES (?,?,?,?)"
                        " ON CONFLICT(device_id, ip) DO UPDATE SET"
                        " source=excluded.source, seen_ts=excluded.seen_ts",
                        (winner_id, loser["ip"], "merge", now))
                self._conn.execute(
                    "UPDATE devices SET upstream_id = ? WHERE upstream_id = ?"
                    " AND id <> ?", (winner_id, loser_id, winner_id))
                self._conn.execute(
                    "UPDATE devices SET upstream_id = NULL WHERE id = ?"
                    " AND upstream_id = ?", (winner_id, loser_id))
                self._conn.execute(
                    "UPDATE device_events SET device_id = ? WHERE device_id = ?",
                    (winner_id, loser_id))
                for table in ("vlans", "vlan_ports", "port_vlans"):
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE device_id = ?", (loser_id,))
                self._conn.execute(
                    "UPDATE discovery_results SET promoted_device_id = ?"
                    " WHERE promoted_device_id = ?", (winner_id, loser_id))
                self._conn.execute(
                    "UPDATE vendor_learned SET source_device_id = ?"
                    " WHERE source_device_id = ?", (winner_id, loser_id))
                self._conn.execute("DELETE FROM devices WHERE id = ?", (loser_id,))
            except Exception:
                self._conn.rollback()
                raise
            self._conn.commit()
            self._config_generation += 1
        return plan

    # ------------------------------------------------------------- interfaces

    def interfaces(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index",
                (device_id,)).fetchall()

    # ------------------------------------------------ forwarding tables

    def replace_mac_entries(self, device_id: int, entries: list[dict],
                            now: float | None = None) -> int:
        """Merge this walk's rows into the device's history rather than
        replacing it outright: every row already stored for this device is
        marked present=0 first, then each of this walk's rows is upserted
        with present=1 and a fresh seen_ts — first_seen_ts is carried
        forward on an existing (device, port, mac, vlan) key and stamped
        fresh only the first time that key is ever stored. A MAC that has
        aged out of the switch since the last walk keeps its row, its last
        seen_ts, and present=0, rather than being deleted outright — a
        stale answer that says when and where a MAC was last seen is more
        useful than no answer at all, and prune_mac_entries is what
        eventually drops it. The MAC is normalised on the way in, so every
        stored row is in one form regardless of how the source spelled it.

        `entries` being an empty list is a genuine "this switch has learned
        nothing right now" and marks every row absent; a failed walk must
        never reach here at all (`entries is None`) — the caller leaves
        storage alone in that case."""
        now = now if now is not None else time.time()
        rows = []
        for entry in entries:
            mac = normalize_mac(entry.get("mac"))
            if len(mac) != 12:
                continue
            rows.append((device_id, int(entry["if_index"]), mac,
                         str(entry.get("vlan") or ""), now, now))
        with self._lock:
            self._conn.execute(
                "UPDATE mac_entries SET present = 0 WHERE device_id = ?",
                (device_id,))
            self._conn.executemany(
                "INSERT INTO mac_entries(device_id, if_index, mac, vlan,"
                " seen_ts, first_seen_ts, present) VALUES (?,?,?,?,?,?,1)"
                " ON CONFLICT(device_id, if_index, mac, vlan) DO UPDATE SET"
                " seen_ts = excluded.seen_ts, present = 1", rows)
            self._conn.commit()
        return len(rows)

    def mac_walk_enabled_count(self) -> int:
        """How many enabled devices are configured to learn MAC addresses.

        One query rather than effective_config() per device: this is asked
        on every MAC search, and effective_config re-reads the whole
        settings table up to four times per call, which on a large estate
        turns one keystroke into thousands of queries for a count used only
        to choose between two sentences. COALESCE mirrors that function's
        own merge exactly — the device's own value, then its profile's,
        then 0.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM devices d"
                " LEFT JOIN groups g ON g.id = d.group_id"
                " WHERE d.enabled = 1"
                "   AND COALESCE(d.mac_table_interval_s,"
                "                g.mac_table_interval_s, 0) > 0").fetchone()
        return row["n"] if row else 0

    def mac_locations(self, mac_prefix: str, limit: int = 200) -> list[sqlite3.Row]:
        """Every (device, port) a MAC starting with this prefix was learned
        on — present (still seen on the last walk) first, then stale (not
        seen on the last walk, but not pruned yet) newest-seen first. A MAC
        on an uplink is on every switch between here and the host, so this
        returns them all and lets the caller decide — picking one silently
        is how you send an engineer to the core switch for a problem on an
        access port. Each row carries present/seen_ts/first_seen_ts so the
        caller can tell "here now" from "last seen here"."""
        prefix = normalize_mac(mac_prefix)
        if len(prefix) < 4:
            return []
        with self._lock:
            return self._conn.execute(
                "SELECT m.*, i.descr AS if_descr FROM mac_entries m"
                " LEFT JOIN interfaces i ON i.device_id = m.device_id"
                "   AND i.if_index = m.if_index"
                " WHERE m.mac LIKE ? ORDER BY m.present DESC, m.seen_ts DESC,"
                " m.device_id, m.if_index LIMIT ?",
                (f"{prefix}%", int(limit))).fetchall()

    def mac_entries_for(self, device_id: int,
                        if_index: int | None = None) -> list[sqlite3.Row]:
        """Every row stored for this device (optionally one port), present
        and stale alike — each carries `present`/`seen_ts`/`first_seen_ts`."""
        sql = "SELECT * FROM mac_entries WHERE device_id = ?"
        args: list = [device_id]
        if if_index is not None:
            sql += " AND if_index = ?"
            args.append(if_index)
        with self._lock:
            return self._conn.execute(sql + " ORDER BY mac, vlan", args).fetchall()

    def prune_mac_entries(self, older_than_s: float) -> int:
        """Drop entries nothing has refreshed for this long, present or
        stale alike. Now that replace_mac_entries keeps a stale row around
        (present=0) instead of deleting it on the spot, this is what
        actually reclaims it, once no walk has confirmed it for the
        retention window — the common case being a MAC that genuinely left
        the port. A present row's seen_ts is refreshed on every walk that
        still sees it, so this only reaches one of those when the device
        itself has stopped being walked (dropped from the schedule, or out
        of service) and nothing is refreshing it any more; either way, the
        rule is the same DELETE by age, not a present/absent branch."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM mac_entries WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------ LLDP/CDP neighbours

    def replace_neighbors(self, device_id: int, entries: list[dict],
                          now: float | None = None) -> int:
        """Merge one LLDP/CDP walk's rows into the device's neighbour
        history — replace_mac_entries' own present-flag ageing, applied to
        `neighbors` instead of `mac_entries`: every row already stored for
        this device is marked present=0 first, then each of this walk's
        rows is upserted with present=1 and a fresh seen_ts. A neighbour
        that has dropped off the wire since the last walk (a cable pulled,
        a device rebooted mid-cycle) keeps its row and its last seen_ts
        rather than vanishing outright — see the CREATE TABLE comment.

        `entries` is a list of dicts: if_index, protocol ('lldp'|'cdp'),
        rem_index, and whichever of chassis_id/chassis_id_subtype/port_id/
        port_id_subtype/port_descr/sys_name/sys_descr/platform/
        remote_address the protocol produced (missing keys default to ''/
        None the same way replace_mac_entries defaults a missing vlan).
        `entries` being empty is a genuine "this walk heard nothing" and
        marks every row for this device absent; a failed walk must never
        reach here at all, the same contract read_device_mac_table's
        None-vs-empty-list return already established."""
        now = now if now is not None else time.time()
        rows = []
        for entry in entries:
            try:
                if_index = int(entry["if_index"])
            except (KeyError, TypeError, ValueError):
                continue
            protocol = str(entry.get("protocol") or "").strip().lower()
            rem_index = str(entry.get("rem_index") or "").strip()
            if protocol not in ("lldp", "cdp") or not rem_index:
                continue
            rows.append((
                device_id, if_index, protocol, rem_index,
                str(entry.get("chassis_id") or ""), entry.get("chassis_id_subtype"),
                str(entry.get("port_id") or ""), entry.get("port_id_subtype"),
                str(entry.get("port_descr") or ""), str(entry.get("sys_name") or ""),
                str(entry.get("sys_descr") or ""), str(entry.get("platform") or ""),
                str(entry.get("remote_address") or ""), now, now))
        with self._lock:
            self._conn.execute(
                "UPDATE neighbors SET present = 0 WHERE device_id = ?", (device_id,))
            self._conn.executemany(
                "INSERT INTO neighbors(device_id, if_index, protocol, rem_index,"
                " chassis_id, chassis_id_subtype, port_id, port_id_subtype,"
                " port_descr, sys_name, sys_descr, platform, remote_address,"
                " seen_ts, first_seen_ts, present)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)"
                " ON CONFLICT(device_id, if_index, protocol, rem_index) DO UPDATE SET"
                " chassis_id=excluded.chassis_id,"
                " chassis_id_subtype=excluded.chassis_id_subtype,"
                " port_id=excluded.port_id, port_id_subtype=excluded.port_id_subtype,"
                " port_descr=excluded.port_descr, sys_name=excluded.sys_name,"
                " sys_descr=excluded.sys_descr, platform=excluded.platform,"
                " remote_address=excluded.remote_address,"
                " seen_ts=excluded.seen_ts, present=1", rows)
            self._conn.commit()
        return len(rows)

    # The best-effort device match a neighbour row joins to: an exact,
    # case-insensitive sysName match against a known device's own name or
    # sysName, or — when the chassis id is a MAC address (subtype 4) — a
    # match against any of that device's own interface phys_addr values.
    # Either half can misfire (two sites reusing "core-sw-1", a NIC's MAC
    # reported instead of a bridge's), so this is offered as a suggestion
    # for the future topology-assembly wave to weigh alongside an operator's
    # own manual upstream_id, never as the sole source of truth.
    # matched_if_index rides along only for the MAC-matched half (a sysName
    # match has no interface to point at, and stays NULL): it is the
    # matched device's OWN port — the one whose phys_addr answered — which
    # is what lets a topology assembly pair this row against that device's
    # reciprocal one (its own neighbour row back at the observer, if it
    # also walked LLDP/CDP) by comparing (device_id, if_index) endpoint
    # pairs, instead of guessing from device ids alone and drawing a link
    # twice or collapsing two different physical links into one.
    # matched_by_name_id/matched_by_mac_id: the two joins' own ids,
    # ungrouped, alongside the COALESCE this always returned — for
    # upstream_suggestions()'s confidence scoring, which needs to know
    # whether the chassis-MAC join independently agrees with whichever id
    # COALESCE picked (COALESCE alone cannot say that once it has made its
    # choice: byname wins whenever it fires, even on a row where bymac also
    # matched, possibly to a different device entirely — see
    # _group_upstream_candidates). Existing callers (neighbours_of,
    # all_neighbours, and everything in api.py built on them) are unaffected
    # by two extra selected columns they never asked for.
    _NEIGHBOR_MATCH_SQL = (
        "SELECT n.*,"
        " COALESCE(byname.id, bymac.id) AS matched_device_id,"
        " COALESCE(byname.name, bymac.name) AS matched_device_name,"
        " iface.if_index AS matched_if_index,"
        " byname.id AS matched_by_name_id,"
        " bymac.id AS matched_by_mac_id"
        " FROM neighbors n"
        # COLLATE NOCASE, not LOWER() on both sides: the two mean the same
        # thing to SQLite (NOCASE folds the same ASCII range LOWER does),
        # but LOWER(column) is an expression, so every one of these three
        # joins had to read and fold every row of the table it joins —
        # devices twice and interfaces once, per neighbour row. As a plain
        # collated comparison they are index lookups instead
        # (ix_devices_name_ip, ix_devices_sys_name_nocase,
        # ix_interfaces_phys_addr_nocase, all declared NOCASE so the
        # planner may use them for exactly this comparison).
        " LEFT JOIN devices byname"
        "   ON byname.enabled = 1 AND n.sys_name != ''"
        "   AND (byname.name = n.sys_name COLLATE NOCASE"
        "        OR byname.sys_name = n.sys_name COLLATE NOCASE)"
        " LEFT JOIN interfaces iface"
        "   ON n.chassis_id_subtype = 4 AND n.chassis_id != ''"
        "   AND iface.phys_addr = n.chassis_id COLLATE NOCASE"
        " LEFT JOIN devices bymac ON bymac.id = iface.device_id AND bymac.enabled = 1")

    def neighbours_of(self, device_id: int) -> list[sqlite3.Row]:
        """Every LLDP/CDP neighbour row stored for this device's ports,
        present and stale alike, with the best-effort device match (see
        _NEIGHBOR_MATCH_SQL) joined in as matched_device_id/
        matched_device_name — the accessor the device detail page's
        NEIGHBOURS subtab reads."""
        with self._lock:
            return self._conn.execute(
                self._NEIGHBOR_MATCH_SQL + " WHERE n.device_id = ?"
                " ORDER BY n.if_index, n.protocol, n.rem_index",
                (device_id,)).fetchall()

    def all_neighbours(self) -> list[sqlite3.Row]:
        """Every neighbour row in the fleet, present and stale alike, with
        the same device-match join as neighbours_of — the accessor a
        fleet-wide topology assembly (the future API/UI wave) reads once
        rather than calling neighbours_of per device."""
        with self._lock:
            return self._conn.execute(
                self._NEIGHBOR_MATCH_SQL +
                " ORDER BY n.device_id, n.if_index, n.protocol, n.rem_index"
                ).fetchall()

    def neighbours_for_devices(self, device_ids) -> list[sqlite3.Row]:
        """all_neighbours(), restricted to neighbour rows OBSERVED BY one of
        `device_ids` — devices_by_ids' own "many known ids, one indexed
        read" shape, applied here so MAPPER's map GET can read the handful
        of devices actually placed instead of the whole fleet. This is
        sound for MAPPER specifically because a link needs BOTH ends placed
        (mapper.assemble_links's own on_map(device_id) check drops any row
        whose observing device is not on the map before it ever looks at
        the far end), and a peer "Add neighbours" can offer is by
        definition a neighbour of some device already placed — so every row
        that could matter to a map of `device_ids` has its device_id among
        them; nothing reachable through n.device_id being excluded is ever
        lost.

        Same IN-clause chunking as devices_by_ids, for the same reason: a
        map's device list is a handful of ids out of a fleet that can run
        to thousands, but a page-sized bulk selection could still be
        hundreds wide, so this stays chunked rather than assuming "a map is
        always small". Order is unspecified across chunks (each chunk is
        ordered like all_neighbours(), but a caller with thousands of ids
        gets more than one chunk) — see devices_by_ids' own docstring.
        Empty `device_ids` returns [] without touching the database."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    self._NEIGHBOR_MATCH_SQL + f" WHERE n.device_id IN ({marks})"
                    " ORDER BY n.device_id, n.if_index, n.protocol, n.rem_index",
                    chunk).fetchall()
        return rows

    # ---------------------------------------------------- upstream suggestions
    #
    # alertrules.py's ROLLED_UP_BY comment (~250-266) explains why the L2
    # neighbour match above is never allowed to drive alert suppression on
    # its own: it is a best-effort guess, not a fact an operator has
    # confirmed, and driving suppression off a wrong guess would hide a real
    # port fault. What that comment leaves as future work is the MEANS for
    # an operator to turn a guess into devices.upstream_id by hand at fleet
    # scale — reviewing 2,000 devices one Edit dialog at a time is not a
    # realistic path. upstream_suggestions() is that means: it surfaces the
    # same matches _NEIGHBOR_MATCH_SQL already computes, for devices that
    # have no upstream_id yet, with enough evidence for an operator (or the
    # UI built on this) to accept or reject each one — never to apply one
    # automatically, which would recreate exactly the failure mode the
    # comment warns against.

    _UPSTREAM_CANDIDATE_SQL = (
        _NEIGHBOR_MATCH_SQL +
        " JOIN devices self ON self.id = n.device_id AND self.enabled = 1"
        " WHERE self.upstream_id IS NULL"
        " AND COALESCE(byname.id, bymac.id) IS NOT NULL"
        " AND COALESCE(byname.id, bymac.id) != n.device_id"
        " ORDER BY n.device_id, n.if_index, n.protocol, n.rem_index")

    def _upstream_candidate_rows(self) -> list[sqlite3.Row]:
        """Every matched neighbour row that could suggest an upstream_id:
        the observing device has none set yet, and the match did not
        resolve to the device itself (a device cannot be its own upstream,
        the same rule _clean_upstream_id enforces on a manual edit)."""
        with self._lock:
            return self._conn.execute(self._UPSTREAM_CANDIDATE_SQL).fetchall()

    def upstream_suggestions_count(self) -> int:
        """How many devices have at least one upstream suggestion — the
        same count/list split devices_count()/devices() already establish,
        so a paged read can show a total without materialising every
        candidate first."""
        return len(_group_upstream_candidates(self._upstream_candidate_rows()))

    def upstream_suggestions(self, limit: int | None = None,
                             offset: int = 0) -> list[dict]:
        """One entry per enabled device with no upstream_id whose own
        LLDP/CDP neighbour rows matched at least one other enabled device,
        ordered by device id. Each entry is
        {"device_id", "ambiguous", "candidates": [...]}; a candidate is
        {"matched_device_id", "matched_device_name", "match_kind"
         ("chassis_mac"|"sys_name"), "protocols", "if_index", "present",
         "seen_ts", "first_seen_ts", "confidence", "confidence_rank"}.
        Two or more distinct matched devices for the same observer come
        back as one entry with `ambiguous` true and every candidate listed,
        rather than this method picking one — see the module comment above.
        `limit`/`offset` page the device list the same way devices()'s do,
        with the same "no params means everything" default."""
        grouped = _group_upstream_candidates(self._upstream_candidate_rows())
        device_ids = sorted(grouped)
        if limit is not None:
            device_ids = device_ids[offset:offset + max(0, limit)]
        return [grouped[device_id] for device_id in device_ids]

    def set_upstream_ids(self, assignments: dict[int, int | None]) -> None:
        """Apply many (device_id -> upstream_id) pairs in one transaction —
        the write behind accepting a batch of upstream suggestions (or any
        other per-device batch edit of the same field). Unlike
        bulk_update_devices, which broadcasts ONE value to many ids, every
        device here gets its own value, so this is executemany rather than
        a single UPDATE ... WHERE id IN (...). Callers are expected to have
        already validated every value (see api._clean_upstream_id and
        api._find_upstream_cycle) — this method only writes."""
        if not assignments:
            return
        with self._lock:
            self._conn.executemany(
                "UPDATE devices SET upstream_id = ? WHERE id = ?",
                [(upstream_id, device_id)
                 for device_id, upstream_id in assignments.items()])
            self._conn.commit()
            self._config_generation += 1

    def prune_neighbors(self, older_than_s: float) -> int:
        """Drop neighbour rows nothing has refreshed for this long, present
        or stale alike — prune_mac_entries' own by-age rule, applied to
        `neighbors`."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM neighbors WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------- VLAN membership

    def replace_vlans(self, device_id: int, entries: list[dict],
                      now: float | None = None) -> int:
        """Merge one VLAN walk's id/name list into the device's history —
        replace_neighbors' present-flag ageing, applied to `vlans`: every
        row already stored for this device is marked present=0 first, then
        each of this walk's rows is upserted with present=1 and a fresh
        seen_ts. A VLAN nothing described this walk (retired, or a device
        that stopped answering the name table) keeps its row and last
        seen_ts rather than vanishing outright, for the same reason a
        dropped neighbour does.

        `entries` is a list of {"vlan": int, "name": str}. Empty is a
        genuine "this device names no VLANs right now" and ages every row;
        read_device_vlans returning None (not this method being called with
        []) is what leaves storage untouched — see its own docstring."""
        now = now if now is not None else time.time()
        rows = []
        for entry in entries:
            try:
                vlan = int(entry["vlan"])
            except (KeyError, TypeError, ValueError):
                continue
            rows.append((device_id, vlan, str(entry.get("name") or ""), now, now))
        with self._lock:
            self._conn.execute(
                "UPDATE vlans SET present = 0 WHERE device_id = ?", (device_id,))
            self._conn.executemany(
                "INSERT INTO vlans(device_id, vlan, name, seen_ts, first_seen_ts,"
                " present) VALUES (?,?,?,?,?,1)"
                " ON CONFLICT(device_id, vlan) DO UPDATE SET"
                " name = excluded.name, seen_ts = excluded.seen_ts, present = 1",
                rows)
            self._conn.commit()
        return len(rows)

    def replace_vlan_ports(self, device_id: int, entries: list[dict],
                           now: float | None = None) -> int:
        """replace_vlans' own ageing UPSERT, applied to `vlan_ports`:
        entries is [{"if_index": int, "mode": str, "native_vlan": int|None}]."""
        now = now if now is not None else time.time()
        rows = []
        for entry in entries:
            try:
                if_index = int(entry["if_index"])
            except (KeyError, TypeError, ValueError):
                continue
            native_vlan = entry.get("native_vlan")
            rows.append((device_id, if_index, str(entry.get("mode") or ""),
                        int(native_vlan) if native_vlan is not None else None,
                        now, now))
        with self._lock:
            self._conn.execute(
                "UPDATE vlan_ports SET present = 0 WHERE device_id = ?", (device_id,))
            self._conn.executemany(
                "INSERT INTO vlan_ports(device_id, if_index, mode, native_vlan,"
                " seen_ts, first_seen_ts, present) VALUES (?,?,?,?,?,?,1)"
                " ON CONFLICT(device_id, if_index) DO UPDATE SET"
                " mode = excluded.mode, native_vlan = excluded.native_vlan,"
                " seen_ts = excluded.seen_ts, present = 1", rows)
            self._conn.commit()
        return len(rows)

    def replace_port_vlans(self, device_id: int, entries: list[dict],
                           now: float | None = None) -> int:
        """replace_vlans' own ageing UPSERT, applied to `port_vlans`:
        entries is [{"if_index": int, "vlan": int, "tagged": bool}]."""
        now = now if now is not None else time.time()
        rows = []
        for entry in entries:
            try:
                if_index = int(entry["if_index"])
                vlan = int(entry["vlan"])
            except (KeyError, TypeError, ValueError):
                continue
            rows.append((device_id, if_index, vlan,
                        1 if entry.get("tagged", True) else 0, now, now))
        with self._lock:
            self._conn.execute(
                "UPDATE port_vlans SET present = 0 WHERE device_id = ?", (device_id,))
            self._conn.executemany(
                "INSERT INTO port_vlans(device_id, if_index, vlan, tagged,"
                " seen_ts, first_seen_ts, present) VALUES (?,?,?,?,?,?,1)"
                " ON CONFLICT(device_id, if_index, vlan) DO UPDATE SET"
                " tagged = excluded.tagged, seen_ts = excluded.seen_ts,"
                " present = 1", rows)
            self._conn.commit()
        return len(rows)

    def vlans_for(self, device_id: int) -> list[sqlite3.Row]:
        """Every VLAN this device has ever named, present and stale alike —
        the device-detail counterpart of neighbours_of."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM vlans WHERE device_id = ? ORDER BY vlan",
                (device_id,)).fetchall()

    def vlans_for_devices(self, device_ids) -> list[sqlite3.Row]:
        """vlans_for(), restricted to `device_ids` — devices_by_ids' "many
        known ids, one indexed read" shape, applied here so MAPPER's map GET
        only reads the VLAN names of devices it actually places instead of
        the whole fleet's `vlans` table. Sound for the same reason
        neighbours_for_devices/port_vlans_for_devices are: a VLAN only
        matters to a map if some link on that map carries it, and every
        such VLAN was named by a device the map places (see
        _mapper_vlans_json) — a VLAN named only by a device nowhere near
        this map was never going to be shown regardless of which rows this
        read could see.

        Same IN-clause chunking as devices_by_ids/neighbours_for_devices/
        port_vlans_for_devices, for the same SQLITE_MAX_VARIABLE_NUMBER
        reason. Empty `device_ids` returns [] without touching the
        database."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    f"SELECT * FROM vlans WHERE device_id IN ({marks})"
                    " ORDER BY device_id, vlan", chunk).fetchall()
        return rows

    def port_vlans_for(self, device_id: int,
                       if_index: int | None = None) -> list[sqlite3.Row]:
        """Every VLAN membership row stored for this device (optionally one
        port), present and stale alike — mac_entries_for's own shape."""
        sql = "SELECT * FROM port_vlans WHERE device_id = ?"
        args: list = [device_id]
        if if_index is not None:
            sql += " AND if_index = ?"
            args.append(if_index)
        with self._lock:
            return self._conn.execute(sql + " ORDER BY if_index, vlan", args).fetchall()

    def vlan_ports_for_devices(self, device_ids) -> list[sqlite3.Row]:
        """Every `vlan_ports` row (a port's trunk/access mode and, for a
        trunk, its device-reported native VLAN) for one of `device_ids` —
        port_vlans_for_devices' own shape, applied to the sibling table so
        MAPPER can show a link end's mode and native VLAN the way an
        operator reading a trunk diagram expects, without a fleet-wide read.
        Sound for the same reason port_vlans_for_devices is: a link end's
        mode/native VLAN is read from that end's OWN (device_id, if_index),
        never the far end's, so a map only ever needs vlan_ports for the
        devices it places.

        Same IN-clause chunking as the other *_for_devices accessors, for
        the same reason. Empty `device_ids` returns [] without touching the
        database."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    f"SELECT * FROM vlan_ports WHERE device_id IN ({marks})"
                    " ORDER BY device_id, if_index", chunk).fetchall()
        return rows

    def port_vlans_for_devices(self, device_ids) -> list[sqlite3.Row]:
        """Every `port_vlans` row for one of `device_ids` — devices_by_ids'
        "many known ids, one indexed read" shape, applied here so MAPPER's
        map GET only reads the ports of devices actually placed. Sound for
        the same reason neighbours_for_devices is: a link's VLAN strands
        are drawn from each row's OWN (device_id, if_index) local port (see
        mapper._port_vlans), never the far end's, so a map only ever needs
        port_vlans for the devices it places — the far end's membership, if
        it has any, is read when that device's own map places IT.

        Same IN-clause chunking as devices_by_ids/neighbours_for_devices,
        for the same SQLITE_MAX_VARIABLE_NUMBER reason. Empty `device_ids`
        returns [] without touching the database."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        if not ids:
            return []
        rows: list[sqlite3.Row] = []
        with self._lock:
            for start in range(0, len(ids), self._IDS_PER_QUERY):
                chunk = ids[start:start + self._IDS_PER_QUERY]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    f"SELECT * FROM port_vlans WHERE device_id IN ({marks})"
                    " ORDER BY device_id, if_index, vlan", chunk).fetchall()
        return rows

    def prune_vlans(self, older_than_s: float) -> int:
        """Drop VLAN rows nothing has refreshed for this long — prune_
        neighbors' own by-age rule, applied to `vlans`."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM vlans WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    def prune_vlan_ports(self, older_than_s: float) -> int:
        """Drop vlan_ports rows nothing has refreshed for this long."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM vlan_ports WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    def prune_port_vlans(self, older_than_s: float) -> int:
        """Drop port_vlans rows nothing has refreshed for this long."""
        if older_than_s <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM port_vlans WHERE seen_ts < ?",
                                     (time.time() - older_than_s,))
            self._conn.commit()
        return cur.rowcount or 0

    # --------------------------------------------------------- PoE / STP

    def set_poe_capable(self, device_id: int, capable: bool | None) -> None:
        """The capability probe's verdict: True once pethMainPseTable/
        pethPsePortTable has answered anything, False once a probe has come
        back with neither, None to clear (a re-identify, so the next poll
        probes again rather than trusting a verdict from a different
        device). Never bumps config_generation — this is the poller's own
        observation about one box, not a setting a human changed."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET poe_capable = ? WHERE id = ?",
                (None if capable is None else (1 if capable else 0), device_id))
            self._conn.commit()

    def set_stp_capable(self, device_id: int, capable: bool | None) -> None:
        """set_poe_capable's own counterpart for dot1dStp."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET stp_capable = ? WHERE id = ?",
                (None if capable is None else (1 if capable else 0), device_id))
            self._conn.commit()

    # ------------------------------------------------------ UPS / sensors

    def set_ups_capable(self, device_id: int, capable: bool | None) -> None:
        """set_poe_capable's own counterpart for UPS-MIB: True once its
        scalar batch has answered anything, False once it has answered
        nothing, so a device confirmed not a UPS stops paying for even the
        one small scalar GET nodepoll._poll_ups_health otherwise sends
        every poll forever."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET ups_capable = ? WHERE id = ?",
                (None if capable is None else (1 if capable else 0), device_id))
            self._conn.commit()

    def set_sensor_capable(self, device_id: int, capable: bool | None) -> None:
        """set_poe_capable's own counterpart for the device-level ENTITY-
        SENSOR-MIB scan: True once entPhySensorValue has answered anything,
        False once it has answered nothing, so a device confirmed to have
        no sensors stops paying for the walk nodepoll._poll_environment
        otherwise retries every _SENSOR_REFRESH_S forever."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET sensor_capable = ? WHERE id = ?",
                (None if capable is None else (1 if capable else 0), device_id))
            self._conn.commit()

    def update_stp_bridge(self, device_id: int, *, protocol_spec: str | None,
                          priority: int | None, root_id: str | None,
                          root_cost: int | None, root_port: int | None,
                          time_since_change_s: float | None) -> None:
        """The bridge-wide dot1dStp scalars for one poll — descriptive
        device state, refreshed in place like sys_name/vendor, not a
        sample series (see the schema migration comment)."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET stp_protocol_spec=?, stp_priority=?,"
                " stp_root_id=?, stp_root_cost=?, stp_root_port=?,"
                " stp_time_since_change_s=? WHERE id=?",
                (protocol_spec, priority, root_id, root_cost, root_port,
                 time_since_change_s, device_id))
            self._conn.commit()

    def update_interface_poe(self, device_id: int, rows: list[dict]) -> None:
        """Per-port PoE admin/detection state and Cisco's per-port
        milliwatt reading, one statement for the whole poll — the same
        batching update_interface_rates uses and for the same reason (one
        UPDATE per port is one transaction per port on a 48-port PoE
        switch). Rows for a port this device does not have (removed since
        the last interface poll) simply update nothing; the WHERE clause
        makes that a no-op rather than an error."""
        if not rows:
            return
        params = [(row.get("poe_admin"), row.get("poe_detect_status"),
                   row.get("poe_power_mw"), device_id, row["if_index"])
                  for row in rows]
        with self._lock:
            try:
                self._conn.executemany(
                    "UPDATE interfaces SET poe_admin=?, poe_detect_status=?,"
                    " poe_power_mw=? WHERE device_id=? AND if_index=?", params)
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise

    def update_interface_stp(self, device_id: int, rows: list[dict]) -> None:
        """update_interface_poe's own counterpart for per-port STP state."""
        if not rows:
            return
        params = [(row.get("stp_state"), device_id, row["if_index"])
                  for row in rows]
        with self._lock:
            try:
                self._conn.executemany(
                    "UPDATE interfaces SET stp_state=?"
                    " WHERE device_id=? AND if_index=?", params)
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise

    def replace_interfaces(self, device_id: int, rows: list[dict],
                           allow_delete: bool = True) -> dict:
        """Wholesale replace of a device's interface table each poll cycle.
        Matches existing rows by if_index to carry forward
        last_in_octets/last_out_octets/last_sample_ts so a rate calc isn't
        lost across a routine poll; inserts new ones; deletes vanished
        ones.

        `allow_delete=False` keeps every stored row the walk did not see.
        A walk that was cut short — a timeout half way down the ifTable —
        is not evidence that the interfaces it never reached are gone, and
        deleting them takes their link-event history with them (the FK
        cascade) and re-creates them with no counters on the next poll.

        The returned dict carries `ids`: {if_index: interfaces.id} for
        every row this device now has, because the caller needs those ids
        to record link events and every row is already read here — one
        SELECT per interface afterwards was pure duplication.
        """
        now = time.time()
        with self._lock:
            existing = {row["if_index"]: row for row in self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ?", (device_id,)).fetchall()}
            seen_indexes = set()
            added, removed, reindexed = [], [], []
            inserts, updates = [], []
            for row in rows:
                if_index = row["if_index"]
                seen_indexes.add(if_index)
                prior = existing.get(if_index)
                if prior is None:
                    added.append(if_index)
                    inserts.append(
                        (device_id, if_index, row.get("descr"), row.get("alias"),
                         row.get("phys_addr"), row.get("speed_bps"),
                         row.get("admin_status"), row.get("oper_status"), now))
                else:
                    if prior["descr"] != row.get("descr"):
                        reindexed.append(if_index)
                    updates.append(
                        (row.get("descr"), row.get("alias"), row.get("phys_addr"),
                         row.get("speed_bps"), row.get("admin_status"),
                         row.get("oper_status"), now, device_id, if_index))
            if inserts:
                self._conn.executemany(
                    "INSERT INTO interfaces(device_id, if_index, descr, alias,"
                    " phys_addr, speed_bps, admin_status, oper_status,"
                    " last_seen_ts) VALUES (?,?,?,?,?,?,?,?,?)", inserts)
            if updates:
                self._conn.executemany(
                    "UPDATE interfaces SET descr=?, alias=?, phys_addr=?,"
                    " speed_bps=?, admin_status=?, oper_status=?, last_seen_ts=?"
                    " WHERE device_id=? AND if_index=?", updates)
            if allow_delete:
                for if_index in existing:
                    if if_index not in seen_indexes:
                        removed.append(if_index)
            if removed:
                marks = ",".join("?" * len(removed))
                self._conn.execute(
                    f"DELETE FROM interfaces WHERE device_id=? AND if_index IN ({marks})",
                    (device_id, *removed))
            ids = {row["if_index"]: row["id"] for row in self._conn.execute(
                "SELECT id, if_index FROM interfaces WHERE device_id = ?",
                (device_id,)).fetchall()}
            self._conn.commit()
        return {"added": added, "removed": removed, "reindexed": reindexed,
                "ids": ids}

    def update_interface_rate(self, device_id: int, if_index: int, *,
                              in_octets: int | None, out_octets: int | None,
                              in_errors: int | None = None,
                              out_errors: int | None = None,
                              in_bps: float | None, out_bps: float | None,
                              in_error_rate: float | None, out_error_rate: float | None,
                              ts: float) -> None:
        """One interface's counters and rates. A one-row wrapper around
        update_interface_rates for callers outside the poll loop."""
        self.update_interface_rates(device_id, [{
            "if_index": if_index, "in_octets": in_octets, "out_octets": out_octets,
            "in_errors": in_errors, "out_errors": out_errors,
            "in_bps": in_bps, "out_bps": out_bps,
            "in_error_rate": in_error_rate, "out_error_rate": out_error_rate,
            "ts": ts}])

    _RATE_COLUMNS = ("last_in_octets", "last_out_octets", "last_in_errors",
                     "last_out_errors", "last_in_discards", "last_out_discards",
                     "last_sample_ts", "in_bps", "out_bps", "in_error_rate",
                     "out_error_rate", "in_discard_rate", "out_discard_rate",
                     "discontinuity_ts")

    def update_interface_rates(self, device_id: int, rows: list[dict]) -> None:
        """Every interface's counters and computed rates for one poll, in
        one statement and one commit.

        One UPDATE per interface with its own commit is what made a
        500-port chassis cost hundreds of transactions per poll; the values
        are all known at the same moment, so they belong in one.
        """
        if not rows:
            return
        columns = self._RATE_COLUMNS
        clauses = ", ".join(f"{name}=?" for name in columns)
        params = [tuple([row.get("in_octets"), row.get("out_octets"),
                         row.get("in_errors"), row.get("out_errors"),
                         row.get("in_discards"), row.get("out_discards"),
                         row.get("ts"), row.get("in_bps"), row.get("out_bps"),
                         row.get("in_error_rate"), row.get("out_error_rate"),
                         row.get("in_discard_rate"), row.get("out_discard_rate"),
                         row.get("discontinuity_ts"),
                         device_id, row["if_index"]])
                  for row in rows]
        with self._lock:
            try:
                self._conn.executemany(
                    f"UPDATE interfaces SET {clauses}"
                    f" WHERE device_id=? AND if_index=?", params)
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise

    # ---------------------------------------------------------------- metrics

    def record_metric_samples(self, device_id: int, rows: list) -> dict:
        """Every metric one poll produced, in one transaction.

        `rows` is a sequence of (key, label, unit, kind, ts, value). One
        SELECT of the device's existing metric ids, one INSERT for keys never
        seen before, one UPDATE of the current values, one INSERT for the
        samples — a per-sample commit is ~2,000 fsyncs on a 500-port chassis.

        `kind` is written only when the metric row is created. Changing a
        metric's kind under a chart that has months of history in the other
        unit is not something a poll should do silently, and the poller
        never means to: the kind is a property of the OID, not of a
        reading. A value of None updates last_ts and stores no sample —
        "polled, no answer" is not a zero.

        Returns {key: metric_id} for every row, so a caller that needs an
        id (a chart link, a threshold) does not have to read them back.
        """
        latest: dict[str, tuple] = {}
        for row in rows or ():
            key, label, unit, kind, ts, value = row
            latest[key] = (label, unit, kind, ts, value)
        if not latest:
            return {}
        with self._lock:
            try:
                ids = {r["key"]: r["id"] for r in self._conn.execute(
                    "SELECT id, key FROM metrics WHERE device_id = ?",
                    (device_id,)).fetchall()}
                missing = [(device_id, key, label, unit, kind)
                           for key, (label, unit, kind, _ts, _value) in latest.items()
                           if key not in ids]
                if missing:
                    self._conn.executemany(
                        "INSERT OR IGNORE INTO metrics(device_id, key, label, unit,"
                        " kind) VALUES (?,?,?,?,?)", missing)
                    marks = ",".join("?" * len(missing))
                    for r in self._conn.execute(
                            f"SELECT id, key FROM metrics WHERE device_id = ?"
                            f" AND key IN ({marks})",
                            (device_id, *[m[1] for m in missing])).fetchall():
                        ids[r["key"]] = r["id"]
                self._conn.executemany(
                    "UPDATE metrics SET last_value=?, last_ts=?, label=?, unit=?"
                    " WHERE id=?",
                    [(value, ts, label, unit, ids[key])
                     for key, (label, unit, _kind, ts, value) in latest.items()
                     if key in ids])
                samples = [(ids[key], ts, value)
                           for key, (_label, _unit, _kind, ts, value) in latest.items()
                           if value is not None and key in ids]
                if samples:
                    self._conn.executemany(
                        "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                        " VALUES (?,?,?)", samples)
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise
        return {key: ids[key] for key in latest if key in ids}

    def record_metric_sample(self, device_id: int, key: str, label: str,
                             unit: str, kind: str, ts: float,
                             value: float | None) -> int:
        """One metric sample — a one-row wrapper around
        record_metric_samples, kept for the callers (tests, on-demand
        reads) that genuinely have exactly one."""
        ids = self.record_metric_samples(
            device_id, [(key, label, unit, kind, ts, value)])
        return ids[key]

    def metrics(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY label",
                (device_id,)).fetchall()

    def metric(self, metric_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE id = ?", (metric_id,)).fetchone()

    def top_metric(self, key: str, n: int = 10, *,
                   ascending: bool = False) -> list[sqlite3.Row]:
        """The n enabled devices with the highest (or lowest) current value
        of one metric key — "worst packet loss", "slowest to answer" — in
        one query rather than a metrics() call per device. NULL last_value
        rows are excluded: a metric that has never produced a sample is not
        a zero, and sorting it as one puts silent devices at the top of a
        "best" list and hides real ones."""
        order = "ASC" if ascending else "DESC"
        with self._lock:
            return self._conn.execute(
                f"SELECT m.device_id AS device_id, d.name AS name, d.ip AS ip,"
                f" m.id AS metric_id, m.key AS key, m.label AS label,"
                f" m.unit AS unit, m.last_value AS last_value, m.last_ts AS last_ts"
                f" FROM metrics m JOIN devices d ON d.id = m.device_id"
                f" WHERE m.key = ? AND m.last_value IS NOT NULL AND d.enabled = 1"
                f" ORDER BY m.last_value {order} LIMIT ?",
                (key, int(n))).fetchall()

    def series(self, device_id: int, metric_id: int, t0: float, t1: float,
               bucket_s: float = 0) -> list[dict]:
        """Raw-vs-hourly selection: a wide window reads the rollup table
        instead of scanning months of raw points.

        `device_id` is enforced, not decorative. Metric ids are global, so
        without the join a caller passing another device's metric id got that
        device's data back under this device's name — which is exactly what a
        stale dialog does when the selected device changes underneath it. A
        mismatch now returns nothing, which reads as "no samples" rather than
        as somebody else's traffic.

        `bucket_s > 0` buckets raw samples server-side into fixed-width
        windows aligned to epoch time (`floor(ts / bucket_s) * bucket_s`),
        returning the same `{ts, avg, min, max}` shape the hourly rollup
        uses so `drawSeriesChart` renders either one unchanged. Bucketing
        only applies within the raw-sample window (<= 3 days); a wider
        window already reads the hourly rollup and ignores `bucket_s`.
        """
        with self._lock:
            if not self._conn.execute(
                    "SELECT 1 FROM metrics WHERE id = ? AND device_id = ?",
                    (metric_id, device_id)).fetchone():
                return []
            if (t1 - t0) <= RAW_WINDOW_S:
                if bucket_s and bucket_s > 0:
                    rows = self._conn.execute(
                        "SELECT (CAST(ts / ? AS INTEGER)) * ? AS bucket_ts,"
                        " AVG(value) AS avg, MIN(value) AS min, MAX(value) AS max,"
                        " COUNT(*) AS n FROM samples WHERE metric_id = ?"
                        " AND ts >= ? AND ts <= ? GROUP BY 1 ORDER BY 1",
                        (bucket_s, bucket_s, metric_id, t0, t1)).fetchall()
                    return [{"ts": row["bucket_ts"], "avg": row["avg"],
                            "min": row["min"], "max": row["max"], "n": row["n"]}
                            for row in rows]
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

    _ROLLUP_WATERMARK = "rollup_watermark_hour"
    # Hours already rolled up that are aggregated again on the next pass, so
    # a sample that arrived after its hour was summarised is not lost. Two
    # covers a poll that started before the hour ended and a clock that is a
    # little behind.
    _ROLLUP_REDO_HOURS = 2

    def compact_rollup(self, max_hours: int = 48) -> int:
        """Summarise complete hours of raw samples into samples_hourly.

        Two things were wrong with the first version. It deleted every raw
        sample older than an hour, so the raw window a chart reads (three
        days) could never contain anything — and it was never called, which
        is the only reason that did not destroy every short-window chart.
        And it re-aggregated the whole history on each call.

        Now: raw rows are left alone (prune and the per-metric cap own
        their lifetime), work starts from a private watermark rather than
        from the beginning of time, and each hour is its own transaction so
        the lock is never held across more than one. `max_hours` bounds a
        single pass; the watermark makes the next pass continue where this
        one stopped, so a long backlog is worked off over several passes
        instead of in one stall.

        Returns the number of (metric, hour) rows written.
        """
        now = time.time()
        # The last hour that has fully elapsed. The current hour is still
        # collecting samples and would be summarised wrong.
        latest_complete = int(now // 3600) * 3600 - 3600
        watermark = self._private_setting(self._ROLLUP_WATERMARK)
        if watermark is None:
            with self._lock:
                row = self._conn.execute(
                    "SELECT MIN(ts) AS oldest FROM samples").fetchone()
            oldest = row["oldest"] if row else None
            if oldest is None:
                self._set_private_setting(self._ROLLUP_WATERMARK,
                                          latest_complete + 3600)
                return 0
            hour = int(float(oldest) // 3600) * 3600
        else:
            hour = int(watermark) - self._ROLLUP_REDO_HOURS * 3600
        written = 0
        processed = 0
        while hour <= latest_complete and processed < max_hours:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT metric_id, COUNT(*) AS n, MIN(value) AS vmin,"
                    " AVG(value) AS vavg, MAX(value) AS vmax FROM samples"
                    " WHERE ts >= ? AND ts < ? AND value IS NOT NULL"
                    " GROUP BY metric_id", (hour, hour + 3600)).fetchall()
                if rows:
                    self._conn.executemany(
                        "INSERT INTO samples_hourly(metric_id, hour, n, vmin,"
                        " vavg, vmax) VALUES (?,?,?,?,?,?)"
                        " ON CONFLICT(metric_id, hour) DO UPDATE SET"
                        " n=excluded.n, vmin=excluded.vmin, vavg=excluded.vavg,"
                        " vmax=excluded.vmax",
                        [(row["metric_id"], hour, row["n"], row["vmin"],
                          row["vavg"], row["vmax"]) for row in rows])
                    written += len(rows)
                self._conn.commit()
            hour += 3600
            processed += 1
        self._set_private_setting(self._ROLLUP_WATERMARK, hour)
        return written

    # ----------------------------------------------------------------- events

    def record_device_event(self, device_id: int, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_events(device_id, ts, kind, detail)"
                " VALUES (?,?,?,?)", (device_id, time.time(), kind, detail))
            self._conn.commit()

    def device_events(self, device_id: int | None = None, since_s: float | None = None,
                      kinds: list[str] | None = None, limit: int = 300,
                      exclude_kinds=()) -> list[sqlite3.Row]:
        """`exclude_kinds` is applied in the query, not by the caller over
        the result: the LIMIT is what a reader relies on to bound the read,
        and rows filtered out afterwards would still have spent it."""
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
        if exclude_kinds:
            marks = ",".join("?" * len(exclude_kinds))
            clauses.append(f"kind NOT IN ({marks})")
            params.extend(exclude_kinds)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM device_events{where} ORDER BY ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    def last_device_event_before(self, device_id: int, kind: str,
                                 ts: float) -> sqlite3.Row | None:
        """The newest event of this kind STRICTLY before `ts`, or None.

        The bound is the point. "The most recent `down`" is not the same
        question as "the `down` this `up` ended": a drain processes a batch of
        events at once, and a device that flapped can already have recorded a
        later outage by the time the earlier recovery is read — which would
        pair a recovery with an outage that started after it and report a
        negative duration.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_events WHERE device_id = ? AND kind = ?"
                " AND ts < ? ORDER BY ts DESC LIMIT 1",
                (device_id, kind, ts)).fetchone()

    # kind -> the small display-status vocabulary devices.status already
    # uses (up|down|unsupported|auth|unknown). rebooted/poll_overrun are
    # informational, not status transitions, so they don't start a new
    # segment — a device that reboots while staying up shouldn't show a
    # gap in an "up" segment.
    _SEGMENT_STATUS = {"up": "up", "down": "down", "unsupported": "unsupported",
                       "auth_fail": "auth"}

    # The per-method counterparts device_method_segments walks — see
    # nodepoll._poll_device for where snmp_up/snmp_down/ping_up/ping_down
    # are recorded (transitions only, seeded on first observation).
    _SNMP_SEGMENT_STATUS = {"snmp_up": "up", "snmp_down": "down"}
    _PING_SEGMENT_STATUS = {"ping_up": "up", "ping_down": "down"}

    def device_status_segments(self, device_id: int, t0: float, t1: float) -> list[dict]:
        """Turns the device's sparse up/down/etc. transition log into
        [ts_start, ts_end) status segments covering [t0, t1] — one row per
        real status change, not one row per poll the way NetPath's own
        traces-based timeline is built from, since Nodes has no per-poll
        sample log to bucket."""
        with self._lock:
            current = self._conn.execute(
                "SELECT status FROM devices WHERE id = ?", (device_id,)).fetchone()
        end_status = current["status"] if current else None
        return self._event_segments(device_id, t0, t1, self._SEGMENT_STATUS, end_status)

    def has_method_events(self, device_id: int) -> bool:
        """Whether this device has ever recorded a per-method lane event
        (TIMELINE_ONLY_EVENT_KINDS). The poller asks once per device per
        process so an install upgraded from before the split can seed its
        first snmp_*/ping_* events from the state it already knows, rather
        than waiting for the next flap to populate one lane and leaving the
        other reading "no history" for a device pinged for months."""
        marks = ",".join("?" * len(TIMELINE_ONLY_EVENT_KINDS))
        with self._lock:
            row = self._conn.execute(
                f"SELECT 1 FROM device_events WHERE device_id = ? AND kind IN ({marks}) LIMIT 1",
                (device_id, *TIMELINE_ONLY_EVENT_KINDS)).fetchone()
        return row is not None

    def device_method_segments(self, device_id: int, t0: float, t1: float) -> dict:
        """The SNMP/ping counterpart to device_status_segments, for a device
        polled by both: the overall status column follows whichever the
        poller's unreachable_ping_only rule picks (ping, by default), which
        hides a dead SNMP agent behind a healthy ping. Walks the same
        sparse-transition-log logic (see _event_segments) over the
        snmp_up/snmp_down and ping_up/ping_down events nodepoll records,
        once per method.

        Returns {"snmp": [segments], "ping": [segments]}, with None in
        place of a method's list when it has never once recorded a
        transition event in or before the window — a device never polled
        by that method, or history predating this split (upgraded from a
        version that only ever wrote up/down) — so the UI can fall back to
        the single combined lane instead of drawing an empty one."""
        with self._lock:
            current = self._conn.execute(
                "SELECT snmp_ok, ping_ok FROM devices WHERE id = ?",
                (device_id,)).fetchone()
        result = {}
        for method, status_map, ok_col in (
                ("snmp", self._SNMP_SEGMENT_STATUS, "snmp_ok"),
                ("ping", self._PING_SEGMENT_STATUS, "ping_ok")):
            kinds = tuple(status_map)
            marks = ",".join("?" * len(kinds))
            with self._lock:
                seen = self._conn.execute(
                    f"SELECT 1 FROM device_events WHERE device_id = ? AND ts <= ?"
                    f" AND kind IN ({marks}) LIMIT 1",
                    (device_id, t1, *kinds)).fetchone()
            if seen is None:
                result[method] = None
                continue
            ok = current[ok_col] if current else None
            end_status = "unknown" if ok is None else ("up" if ok else "down")
            result[method] = self._event_segments(device_id, t0, t1, status_map, end_status)
        return result

    def _event_segments(self, device_id: int, t0: float, t1: float,
                        status_map: dict, end_status: str | None) -> list[dict]:
        """The sparse-transition-log walk shared by device_status_segments
        (the overall up/down/etc. log) and device_method_segments (the
        per-method snmp/ping logs): `status_map` picks which event kinds
        count and what status each one means, `end_status` is what the
        final segment (from the last event to t1) reports — the device's
        (or method's) CURRENT state, since that is fresher evidence than
        whatever the last event in the window said. None (no device row to
        read a current state from) keeps whatever the last event said."""
        kinds = tuple(status_map)
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

        status = status_map.get(prior["kind"], "unknown") if prior else "unknown"
        segments = []
        cursor = t0
        for row in rows:
            ts = max(t0, min(row["ts"], t1))
            if ts > cursor:
                segments.append({"ts_start": cursor, "ts_end": ts, "status": status})
            status = status_map.get(row["kind"], status)
            cursor = ts
        if end_status is None:
            end_status = status
        if cursor < t1:
            segments.append({"ts_start": cursor, "ts_end": t1, "status": end_status})
        return segments

    def device_events_since(self, last_id: int,
                            limit: int | None = 2000) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first — the same cursor-read
        contract SnmpTrapDatabase.traps_since/SyslogDatabase.rows_since
        use, so the alert engine's drain functions are uniform across
        every source.

        `limit=None` means "no cap": a drain that loops until it reaches
        max_event_id() sets its own per-tick budget and does not want a
        second, invisible one here."""
        sql = "SELECT * FROM device_events WHERE id > ? ORDER BY id ASC"
        args: list = [int(last_id)]
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def max_device_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS m FROM device_events").fetchone()
        return int(row["m"] or 0)

    # The name every other source the alert engine drains uses for this
    # (SnmpTrapDatabase.max_id, SyslogDatabase.max_id), so a drain loop can
    # ask each source the same question instead of special-casing this one.
    def max_event_id(self) -> int:
        return self.max_device_event_id()

    def count_events_by_device(self, since: float,
                               kinds: list[str] | None = None) -> list[sqlite3.Row]:
        """(device_id, name, ip, n) for the devices with the most events
        since a wall-clock timestamp, busiest first — the "top offenders"
        question a dashboard asks once, rather than one query per device."""
        clauses = ["e.ts >= ?"]
        params: list = [float(since)]
        if kinds:
            marks = ",".join("?" * len(kinds))
            clauses.append(f"e.kind IN ({marks})")
            params.extend(kinds)
        where = " AND ".join(clauses)
        with self._lock:
            return self._conn.execute(
                f"SELECT e.device_id AS device_id, d.name AS name, d.ip AS ip,"
                f" COUNT(*) AS n FROM device_events e"
                f" JOIN devices d ON d.id = e.device_id"
                f" WHERE {where} GROUP BY e.device_id"
                f" ORDER BY n DESC, d.name COLLATE NOCASE", params).fetchall()

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

    def interface_events_for_device(self, device_id: int, since_s: float | None = None,
                                    per_interface: int = 300) -> list[sqlite3.Row]:
        """interface_events() for every interface of a device in one query,
        joined against `interfaces` (whose if_index/descr the caller wants
        alongside each event) so the per-interface fan-out of one
        interface_events() call per port is a single round trip instead.

        The cap is per interface, not per device, on purpose: it keeps the
        contract the fan-out had (interface_events()'s own default of the
        newest 300 per port). A single flat LIMIT would let one port that
        flaps continuously fill the whole result and erase every other
        port's link history from the detail pane."""
        clauses = ["i.device_id = ?"]
        params: list = [device_id]
        if since_s is not None:
            clauses.append("e.ts >= ?")
            params.append(time.time() - since_s)
        where = " AND ".join(clauses)
        with self._lock:
            return self._conn.execute(
                f"SELECT id, interface_id, ts, kind, detail, if_index, descr FROM ("
                f"SELECT e.id, e.interface_id, e.ts, e.kind, e.detail,"
                f" i.if_index, i.descr,"
                f" ROW_NUMBER() OVER (PARTITION BY e.interface_id ORDER BY e.ts DESC) AS rn"
                f" FROM interface_events e"
                f" JOIN interfaces i ON i.id = e.interface_id"
                f" WHERE {where}"
                f") WHERE rn <= ? ORDER BY ts DESC",
                (*params, per_interface)).fetchall()

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

    def enterprise_objects(self) -> list[tuple[int, str]]:
        """(mib_file_id, oid) for every resolved object under `enterprises`,
        for vendorid.build_mib_index. A range predicate rather than LIKE:
        SQLite's LIKE is case-insensitive by default and does not use
        ix_mib_objects_oid, which is fine for has_mib_covering's single row
        and not for the tens of thousands this returns."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT mib_file_id, oid FROM mib_objects"
                " WHERE oid >= '1.3.6.1.4.1.' AND oid < '1.3.6.1.4.1/'").fetchall()
        return [(row["mib_file_id"], row["oid"]) for row in rows]

    def mib_generation(self) -> tuple:
        """Changes whenever the MIB corpus does — an upload, a delete, a
        catalog install or a resolve-all rewrite — so the poller can keep
        one built index until it is actually stale."""
        with self._lock:
            row = self._conn.execute(
                "SELECT (SELECT MAX(id) FROM mib_objects) AS top,"
                " (SELECT COUNT(*) FROM mib_objects) AS n_objects,"
                " (SELECT COUNT(*) FROM mib_files) AS n_files").fetchone()
        return (row["top"], row["n_objects"], row["n_files"])

    # ------------------------------------------------ vendor identification

    def record_identification(self, device_id: int, decision, evidence: dict,
                              sys_object_id: str) -> None:
        """Persist what vendorid decided for a device, and that it was decided
        for THIS sysObjectID, so the walk is not repeated until the identity
        changes. `vendor`/`vendor_source`/`vendor_confidence` are left alone
        while a custom vendor OID owns the display value (source 'oid');
        vendor_detected is always written, because it is what ConfigRX and
        the Cisco MAC read act on."""
        with self._lock:
            row = self._conn.execute(
                "SELECT vendor_source FROM devices WHERE id = ?", (device_id,)).fetchone()
            if row is None:
                return
            fields = {
                "vendor_detected": decision.vendor,
                "vendor_evidence": json.dumps(evidence),
                "identified_ts": time.time(),
                "identified_sys_object_id": sys_object_id or "",
            }
            if (row["vendor_source"] or "") != "oid":
                fields.update({"vendor": decision.vendor,
                               "vendor_source": decision.source,
                               "vendor_confidence": decision.confidence})
            clauses = ", ".join(f"{key} = ?" for key in fields)
            self._conn.execute(f"UPDATE devices SET {clauses} WHERE id = ?",
                               (*fields.values(), device_id))
            self._conn.commit()

    def clear_identification(self, device_id: int) -> None:
        """Forget that a device was identified, so its next poll walks it
        again — Re-identify's first step."""
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET identified_ts = NULL,"
                " identified_sys_object_id = NULL WHERE id = ?", (device_id,))
            self._conn.commit()

    def learned_vendor(self, sys_object_id: str) -> str:
        if not sys_object_id:
            return ""
        with self._lock:
            row = self._conn.execute(
                "SELECT vendor FROM vendor_learned WHERE sys_object_id = ?",
                (sys_object_id,)).fetchone()
        return (row["vendor"] if row else "") or ""

    def learned_row(self, sys_object_id: str) -> sqlite3.Row | None:
        if not sys_object_id:
            return None
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM vendor_learned WHERE sys_object_id = ?",
                (sys_object_id,)).fetchone()

    def learn_vendor(self, sys_object_id: str, vendor: str, set_by: str = "",
                     device_id: int | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO vendor_learned(sys_object_id, vendor, set_by, set_ts,"
                " source_device_id) VALUES (?,?,?,?,?)"
                " ON CONFLICT(sys_object_id) DO UPDATE SET vendor=excluded.vendor,"
                " set_by=excluded.set_by, set_ts=excluded.set_ts,"
                " source_device_id=excluded.source_device_id",
                (sys_object_id, vendor, set_by, time.time(), device_id))
            self._conn.commit()

    def forget_learned(self, sys_object_id: str,
                       only_from_device: int | None = None) -> bool:
        sql = "DELETE FROM vendor_learned WHERE sys_object_id = ?"
        args: list = [sys_object_id]
        if only_from_device is not None:
            sql += " AND source_device_id = ?"
            args.append(only_from_device)
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
        return bool(cur.rowcount)

    @staticmethod
    def _learnable(sys_object_id: str) -> tuple[bool, str]:
        """Whether a manual vendor on a device with this sysObjectID should
        teach the fleet. A generic-agent arc (net-snmp, UCD) is shared by
        every Linux box ever built, and a sysObjectID outside enterprises
        says nothing about the maker — learning either would mislabel
        every unrelated device that shares it."""
        from . import nodeoids, vendorid
        if not sys_object_id:
            return False, "the device has no sysObjectID yet"
        arc = nodeoids.enterprise_arc(sys_object_id)
        if arc is None:
            return False, "its sysObjectID is outside the enterprises tree"
        if arc in vendorid.GENERIC_ARCS:
            return False, ("its sysObjectID names only the SNMP agent, which "
                           "every device running that agent shares")
        return True, ""

    def set_vendor_override(self, device_id: int, vendor: str | None,
                            set_by: str = "") -> dict:
        """Set or clear an operator's vendor for one device.

        Set: the device shows and *acts* on this vendor (vendor_detected is
        written too — the operator is asserting the real maker, unlike a
        display-only custom vendor OID), and, when the sysObjectID is
        specific enough, the pairing is learned so every device answering
        the same sysObjectID follows on its next poll.

        Clear: the override goes, the learned row goes too when this device
        was its source, and the row is re-decided at once from what is
        stored so it does not sit on a stale 'manual' until the next poll.
        """
        from . import vendorid
        device = self.device(device_id)
        if device is None:
            raise ValueError("No such device")
        sys_object_id = device["sys_object_id"] or ""
        vendor = (vendor or "").strip()
        result = {"vendor": vendor, "learned": False, "learn_reason": ""}
        if vendor:
            learnable, why = self._learnable(sys_object_id)
            with self._lock:
                self._conn.execute(
                    "UPDATE devices SET vendor_override = ?, vendor = ?,"
                    " vendor_detected = ?, vendor_source = 'manual',"
                    " vendor_confidence = 'high' WHERE id = ?",
                    (vendor, vendor, vendor, device_id))
                self._conn.commit()
            if learnable:
                self.learn_vendor(sys_object_id, vendor, set_by, device_id)
                result["learned"] = True
            else:
                result["learn_reason"] = why
            self.record_device_event(
                device_id, "vendor_set",
                f"Vendor set to {vendor} by {set_by or 'an operator'}"
                + (f"; devices with sysObjectID {sys_object_id} will follow"
                   if learnable else f" (this device only: {why})"))
        elif device["vendor_override"] is None:
            # Nothing to clear: an edit form that never had an override must
            # not record a "cleared" event or re-decide anything.
            result.update({"vendor": device["vendor"] or "",
                           "source": device["vendor_source"] or ""})
        else:
            forgot = self.forget_learned(sys_object_id, only_from_device=device_id)
            fresh = self.device(device_id)
            detected, source, confidence, _arc = vendorid.poll_decision(
                sys_object_id, fresh["sys_descr"] or "",
                dict(fresh, vendor_override=""), self.learned_vendor(sys_object_id))
            keeps_display = (fresh["vendor_source"] or "") == "oid"
            with self._lock:
                self._conn.execute(
                    "UPDATE devices SET vendor_override = NULL, vendor_detected = ?,"
                    " vendor = CASE WHEN ? THEN vendor ELSE ? END,"
                    " vendor_source = CASE WHEN ? THEN vendor_source ELSE ? END,"
                    " vendor_confidence = ? WHERE id = ?",
                    (detected, keeps_display, detected, keeps_display, source,
                     confidence, device_id))
                self._conn.commit()
            self.record_device_event(
                device_id, "vendor_cleared",
                f"Manual vendor cleared by {set_by or 'an operator'}; now "
                f"{detected or 'unidentified'}"
                + (f" via {source}" if source else "")
                + ("; the learned pairing was forgotten" if forgot else ""))
            result.update({"vendor": detected, "source": source})
        return result

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

    _CAP_MIN_SQLITE = (3, 25, 0)   # window functions

    def cap_samples_per_metric(self, n: int, chunk: int = 200) -> int:
        """Keep at most the newest `n` raw samples of EACH metric.

        Per metric with a window function, in chunks of `chunk` metrics,
        taking the lock for each chunk and releasing it in between, so a poll
        worker waits for one chunk at most. Window functions need SQLite
        3.25; on anything older this does nothing and says so once.
        """
        if n <= 0:
            return 0
        if sqlite3.sqlite_version_info < self._CAP_MIN_SQLITE:
            if not self._warned_no_window:
                self._warned_no_window = True
                log.warning(
                    "nodes: SQLite %s cannot cap samples per metric (needs "
                    "%s); raw samples are bounded by sample_retention_days "
                    "alone", sqlite3.sqlite_version,
                    ".".join(str(part) for part in self._CAP_MIN_SQLITE))
            return 0
        with self._lock:
            metric_ids = [row["id"] for row in
                          self._conn.execute("SELECT id FROM metrics").fetchall()]
        removed = 0
        for start in range(0, len(metric_ids), max(1, chunk)):
            batch = metric_ids[start:start + max(1, chunk)]
            marks = ",".join("?" * len(batch))
            with self._lock:
                cursor = self._conn.execute(
                    f"DELETE FROM samples WHERE rowid IN ("
                    f" SELECT rowid FROM ("
                    f"  SELECT rowid, ROW_NUMBER() OVER ("
                    f"   PARTITION BY metric_id ORDER BY ts DESC) AS rn"
                    f"  FROM samples WHERE metric_id IN ({marks})"
                    f" ) WHERE rn > ?)", (*batch, int(n)))
                removed += cursor.rowcount or 0
                self._conn.commit()
        return removed

    def prune(self, *, sample_days: float = 3, rollup_days: float = 400,
             event_days: float = 180, poll_days: float = 0,
             discovery_days: float = 30,
             max_samples_per_metric: int = 0) -> int:
        """Trims the unbounded tables only: samples, device/interface
        events, discovery jobs. Devices, groups, interfaces and MIBs are
        current-state tables, never pruned by age here.

        The per-metric row cap runs after this method's own transaction,
        in its own chunked pass — see cap_samples_per_metric."""
        removed = 0
        now = time.time()
        with self._lock:
            # Unconditional: a caller that wants "delete everything now" (the
            # Settings page's maintenance button) passes 0, which computes a
            # cutoff of "now" and so matches every existing row.
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (now - sample_days * 86400,))
            removed += cursor.rowcount or 0
            # The hourly rollups are the long history now, so they are
            # bounded by their own retention rather than kept forever.
            cursor = self._conn.execute(
                "DELETE FROM samples_hourly WHERE hour < ?",
                (now - rollup_days * 86400,))
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
            self._conn.commit()
        removed += self.cap_samples_per_metric(max_samples_per_metric)
        if removed:
            # Freed pages go back in short steps with the lock released
            # between them, not through a whole-file VACUUM.
            reclaim(self._conn, self._lock, label="nodes")
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest raw samples until the file is back under its cap.

        Incremental reclaim rather than VACUUM: a whole-file rewrite under
        the module lock stalls every poll worker and HTTP handler.
        """
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
            reclaim(self._conn, self._lock, label="nodes")
        return removed

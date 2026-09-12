"""Where the bytes in each database actually are, per table.

    py -m netpath.dbreport <data_dir>

Read-only, and safe against a running service: every store is opened
`file:...?mode=ro` so the write-ahead log is read along with the file. A
store whose file is not there is skipped with a note rather than failing the
run, and one whose WAL cannot be read read-only falls back to `immutable=1`
with a note saying the WAL was not counted.

Row counts are exact. Bytes are exact too where `dbstat` is compiled in
(`basis` is then "measured"); where it is not -- which is the common case,
including the sqlite3 shipped with CPython -- they are `rows *
BYTES_PER_ROW` and `basis` is "estimated". Each report ends with an
`unaccounted` line reconciling the sum against `page_count * page_size`, so
the column adds up to the file and nobody has to trust an estimate
silently.

Not on the /api/state path, ever: COUNT(*) over a hundred-million-row
`samples` is seconds, and /api/state is polled every two seconds by every
open tab. The route that serves this (GET /api/db/report) is cached for
five minutes.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from urllib.parse import quote

# The filename each store keeps in the data folder. One dict because
# __main__.py's *_path_for helpers each had the name written into them and
# Store.name is not the filename, so a tool that wanted the files had no way
# to ask for them.
STORE_FILENAMES = {
    "app": "app.db",
    "trace": "netpath.db",
    "flow": "flows.db",
    "snmp": "snmptraps.db",
    "syslog": "syslog.db",
    "ipam": "ipam.db",
    "nodes": "nodes.db",
    "nodes_series": "nodes_series.db",
    "nodes_mibs": "nodes_mibs.db",
    "alerts": "alerts.db",
    "wireless": "wireless.db",
    "configrx": "configrx.db",
    "mapper": "mapper.db",
}

# Bytes per row including the table's own indexes, measured rather than
# guessed: each layout was built in an in-memory database at fleet shape
# (250 devices, 48 ports each, 49,607 metrics of which 46,748 are per-port,
# half the per-port values exactly 0.0) and `page_count * page_size` divided
# by the row count. 2.0 M rows for samples, 1.5 M for samples_hourly,
# 200-400 k for the walk tables. sqlite3 3.45.3, page_size 4096.
#
# The live install corroborates the first two: its own nodes_series.db is
# 4030 pages over 229,018 samples and 14,709 metrics, about 65 B/sample.
# Re-measured for the WITHOUT ROWID shape: samples 66.2 -> 23.8, having lost
# the rowid, its automatic (metric_id, ts) index and the index on ts;
# samples_hourly 66.3 -> 47.5, keeping its index on hour.
BYTES_PER_ROW = {
    "samples": 23.8,
    "samples_hourly": 47.5,
    "mac_entries": 139.4,
    "arp_entries": 157.1,
    "neighbors": 344.8,
    "vlans": 68.0,
    "vlan_ports": 59.9,
    "port_vlans": 56.4,
    "device_addresses": 91.5,
}
# Everything unmeasured. A row with a few integers and a timestamp lands
# near here; a row carrying a device config or a MIB does not, which is what
# the `unaccounted` line exists to make visible.
DEFAULT_BYTES_PER_ROW = 64


def _uri(path: str) -> str:
    """`C:\\x\\y.db` -> `file:C:/x/y.db`, escaped. Not `immutable=1`: that
    skips the WAL, which under-reports against a running install by however
    much has not been checkpointed."""
    absolute = os.path.abspath(path).replace("\\", "/")
    return "file:" + quote(absolute, safe="/:")


def _connect(path: str) -> tuple[sqlite3.Connection, str]:
    """Read-only, and a note if that had to be weakened.

    A read-only open of a WAL database needs its -shm, which a stopped
    service may have taken with it and a locked one may not let us make. The
    fallback still answers, and says what it left out."""
    try:
        return sqlite3.connect(_uri(path) + "?mode=ro", uri=True), ""
    except sqlite3.Error as exc:
        conn = sqlite3.connect(_uri(path) + "?immutable=1", uri=True)
        return conn, (f"opened immutable ({exc}); anything still in the "
                      f"write-ahead log is not counted")


def _measured(conn: sqlite3.Connection) -> dict[str, int] | None:
    """Per-table bytes from `dbstat`, each index folded into its own table so
    the column means the same thing on both bases. None where dbstat is not
    compiled in."""
    try:
        rows = conn.execute(
            "SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name"
        ).fetchall()
    except sqlite3.Error:
        return None
    owner = {name: tbl for name, tbl in conn.execute(
        "SELECT name, tbl_name FROM sqlite_master")}
    out: dict[str, int] = {}
    for name, size in rows:
        table = owner.get(name)
        if table:
            out[table] = out.get(table, 0) + int(size or 0)
    return out


# nodesseriesdb writes these while it rewrites a table into its WITHOUT
# ROWID shape, band of metric ids at a time. Surfaced in the note because a
# store mid-rewrite holds two half-tables, which is otherwise an operator
# looking at a `samples_new` line and a row count that does not match
# retention with nothing telling them why.
_REWRITE_TABLES = ("samples", "samples_hourly")


def _rewrite_note(conn: sqlite3.Connection) -> str:
    try:
        rows = dict(conn.execute(
            "SELECT key, value FROM settings WHERE key LIKE '%\\_rewrite\\_%'"
            " ESCAPE '\\'").fetchall())
    except sqlite3.Error:
        return ""
    notes = []
    for table in _REWRITE_TABLES:
        if rows.get(f"{table}_rewrite_state", "") != '"rewriting"':
            continue
        cursor = rows.get(f"{table}_rewrite_cursor", "0")
        end = rows.get(f"{table}_rewrite_end", "0")
        notes.append(f"{table}: rewriting WITHOUT ROWID, band at metric id "
                     f"{cursor} of {end}")
    return "; ".join(notes)


def _file_bytes(path: str) -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(path + suffix)
        except OSError:
            pass
    return total


def report(paths: dict[str, str]) -> list[dict]:
    """One entry per store in `paths`, in the order given."""
    out = []
    for name, path in paths.items():
        if not os.path.exists(path):
            out.append({"name": name, "path": path, "missing": True,
                        "tables": [], "basis": "none",
                        "note": "no file on disk; this store has never been "
                                "opened here"})
            continue
        out.append(_report_store(name, path))
    return out


def _report_store(name: str, path: str) -> dict:
    conn, note = _connect(path)
    try:
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        page_count = conn.execute("PRAGMA page_count").fetchone()[0]
        freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
        names = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
            " AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        exact = _measured(conn)
        tables = []
        for table in names:
            rows = conn.execute(
                f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            if exact is not None:
                size = exact.get(table, 0)
            else:
                # A `<table>_new` mid-rewrite costs what its finished form
                # will, not the unmeasured default.
                measured = BYTES_PER_ROW.get(
                    table[:-4] if table.endswith("_new") else table,
                    DEFAULT_BYTES_PER_ROW)
                size = int(rows * measured)
            tables.append({"name": table, "type": "table", "rows": rows,
                           "bytes": size})
        note = "; ".join(filter(None, [note, _rewrite_note(conn)]))
    finally:
        conn.close()
    tables.sort(key=lambda row: (-row["bytes"], row["name"]))
    accounted = sum(row["bytes"] for row in tables)
    slack = page_count * page_size - accounted
    if slack < 0:
        note = "; ".join(filter(None, [
            note, f"the estimate overshoots the file by {-slack:,} bytes"]))
    tables.append({"name": "unaccounted", "type": "reconciliation",
                   "rows": None, "bytes": max(0, slack)})
    return {
        "name": name,
        "path": path,
        "file_bytes": _file_bytes(path),
        "page_count": page_count,
        "page_size": page_size,
        "freelist_pages": freelist,
        "basis": "measured" if exact is not None else "estimated",
        "tables": tables,
        "note": note,
        "missing": False,
    }


# ---------------------------------------------------------------- the command


def paths_in(data_dir: str) -> dict[str, str]:
    return {name: os.path.join(data_dir, filename)
            for name, filename in STORE_FILENAMES.items()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpath.dbreport",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("data_dir",
                        help="the folder holding the .db files (the same one "
                             "Settings -> Data & Retention lists)")
    parser.add_argument("--store", action="append", default=None,
                        help="only this store; repeatable. Default: all of "
                             + ", ".join(STORE_FILENAMES))
    return parser


def _print_store(entry: dict) -> None:
    print()
    print(f"{entry['name']}  {entry['path']}")
    if entry.get("missing"):
        print(f"  -- {entry['note']}")
        return
    # Two figures, because they answer different questions: the file plus
    # its write-ahead log is what the disk is holding, and the pages are
    # what the column below adds up to.
    print(f"  {entry['file_bytes'] / (1024 * 1024):,.1f} MiB on disk with its"
          f" write-ahead log; {entry['page_count'] * entry['page_size'] / (1024 * 1024):,.1f}"
          f" MiB in {entry['page_count']:,} pages of {entry['page_size']:,}"
          f" ({entry['freelist_pages']:,} free), which is what the rows below"
          f" account for. Bytes are {entry['basis']}.")
    if entry["note"]:
        print(f"  -- {entry['note']}")
    print(f"  {'table':<26}{'rows':>14}{'MiB':>10}")
    for row in entry["tables"]:
        rows = "" if row["rows"] is None else f"{row['rows']:,}"
        print(f"  {row['name']:<26}{rows:>14}"
              f"{row['bytes'] / (1024 * 1024):>10,.1f}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    wanted = paths_in(args.data_dir)
    if args.store:
        unknown = [s for s in args.store if s not in wanted]
        if unknown:
            print(f"no such store: {', '.join(unknown)}", file=sys.stderr)
            return 2
        wanted = {name: wanted[name] for name in args.store}
    entries = report(wanted)
    print(f"{args.data_dir}")
    for entry in entries:
        _print_store(entry)
    total = sum(e.get("file_bytes", 0) for e in entries)
    print()
    print(f"{total / (1024 * 1024):,.1f} MiB on disk in total (files and "
          f"write-ahead logs),"
          f" across {sum(1 for e in entries if not e.get('missing'))}"
          f" of {len(entries)} stores")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

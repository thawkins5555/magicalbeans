"""Tier 0 fix T0-3: every entry in the shipped MIB catalog must be
installable by its own installer -- fetch_file()'s per-file size cap
(max_mib_bytes) has to clear the largest real vendor file the catalog
names, or the one-click Install button fails on a file nobody uploaded
themselves.

No network access here (offline like every other suite): rather than
fetching upstream and measuring, this pins the largest sizes actually
observed for the catalog's files (recorded below, at the time this suite
was written) as a documented floor, and asserts the enforced cap clears
that floor with real headroom. That keeps the invariant checkable without
depending on GitHub being reachable, while still catching the exact bug
this fixes: a shipped entry whose real file is bigger than the cap."""
from _paths import tmpdir  # noqa: F401  (repo root on sys.path)

from netpath import mibcatalog
from netpath import nodesdb

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


CAP = nodesdb.DEFAULTS["max_mib_bytes"]

# Largest real per-file sizes on record for files the shipped CATALOG names
# (bytes, measured against the upstream URLs in netpath/mibcatalog.py). The
# old 1 MiB cap refused every one of these outright.
KNOWN_LARGE = {
    "apc-ups": 2_849_352,          # PowerNet-MIB.mib
    "f5": 1_404_195,               # F5-BIGIP-LOCAL-MIB.mib
    "cisco-core": 1_487_236,       # CISCO-ENTITY-VENDORTYPE-OID-MIB.my
    "raritan": 714_818,            # PDU2-MIB.mib
    "citrix": 674_813,             # NS-ROOT-MIB.mib
    "cisco-wireless": 673_900,     # AIRESPACE-WIRELESS-MIB.mib
    "checkpoint": 670_917,         # CHECKPOINT-MIB.mib
}
# A generous ceiling above the largest of those, so a future vendor file
# growing somewhat is still covered without this suite needing an update
# every time upstream edits a MIB.
GENEROUS_FLOOR = max(KNOWN_LARGE.values()) * 1.4  # ~3.99 MB

catalog_keys = {b.key for b in mibcatalog.CATALOG}
check("every KNOWN_LARGE bundle is still in the shipped catalog"
      " (or this table is stale)",
      set(KNOWN_LARGE) <= catalog_keys, set(KNOWN_LARGE) - catalog_keys)

check(f"the enforced per-file cap ({CAP:,} bytes) clears the largest known"
      f" shipped-catalog file with headroom (floor {GENEROUS_FLOOR:,.0f})",
      CAP >= GENEROUS_FLOOR, (CAP, GENEROUS_FLOOR))

for key, size in KNOWN_LARGE.items():
    check(f"cap clears {key}'s largest known file ({size:,} bytes)",
          CAP >= size, (CAP, size))

# The regression itself: the old 1 MiB cap is exactly what refused
# cisco-core's CISCO-ENTITY-VENDORTYPE-OID-MIB. Confirm the new cap does not
# repeat that -- and that fetch_file's own boundary check (max_bytes+1 read)
# still refuses something one byte over whatever cap is configured, so this
# is a cap raise, not a cap removed.
OLD_CAP = 1024 * 1024
check("the old 1 MiB cap really would have refused cisco-core's largest file"
      " (why this fix was needed)",
      KNOWN_LARGE["cisco-core"] > OLD_CAP, KNOWN_LARGE["cisco-core"])


class _FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _sized_fetch(size: int, max_bytes: int):
    real_urlopen = mibcatalog.urllib.request.urlopen
    mibcatalog.urllib.request.urlopen = lambda *a, **k: _FakeResponse(
        b"X" * size)
    try:
        return mibcatalog.fetch_file("https://example/BIG-MIB", 5, max_bytes)
    finally:
        mibcatalog.urllib.request.urlopen = real_urlopen


try:
    _sized_fetch(KNOWN_LARGE["cisco-core"], CAP)
    ok = True
except mibcatalog.DownloadError as exc:
    ok = False
check("fetch_file accepts a file the size of cisco-core's largest MIB"
      " under the new cap", ok)

try:
    _sized_fetch(KNOWN_LARGE["cisco-core"], OLD_CAP)
    ok = False
except mibcatalog.DownloadError:
    ok = True
check("...and the same file was genuinely refused under the old 1 MiB cap"
      " (the bug this fix removes)", ok)

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

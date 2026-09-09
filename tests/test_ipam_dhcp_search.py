"""IPAM's MAC search: a DHCP lease stored the way Windows spells its ClientId
(`AA-BB-CC-DD-EE-FF`) is found by every spelling an operator might type,
and so is a swept host; an IP is never misread as a hex prefix; the other
clauses of both searches are untouched; dhcp_leases_for_mac answers
across servers freshest first; ipam_search consumes it all unchanged;
and — the reason the change exists — an ipam.db written before the
ingest normalised anything is rewritten on open and searchable at once.

No PowerShell here: ipam_dhcp._run is replaced with a function returning
the JSON shape the DhcpServer script would have, which is the boundary
this module's own parsing starts at."""
import os
import sqlite3
import time

from _paths import tmpdir

import netpath.ipam_dhcp as ipam_dhcp
from netpath.ipamdb import IpamDatabase, mac_search_digits
from netpath.web import api
from netpath.web.service import Service

TMP = tmpdir("ipam_dhcp_search_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> IpamDatabase:
    return IpamDatabase(os.path.join(TMP, f"{name}.db"))


# Every spelling of one address a search box realistically receives: what
# Windows prints, what Linux prints, what a Cisco console prints, what a
# label on the device prints, and each of those in the other case.
MAC = "aa:bb:cc:dd:ee:ff"
SPELLINGS = ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF",
             "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AABB.CCDD.EEFF",
             "aabbccddeeff", "AABBCCDDEEFF")
OUI_SPELLINGS = ("aa:bb:cc", "AA-BB-CC", "aabbcc", "aabb.cc")


# --------------------------------------------- 1. the needle reduction
check("colon/dash/dot/bare and either case reduce to the same digits",
      {mac_search_digits(s) for s in SPELLINGS} == {"aabbccddeeff"},
      {s: mac_search_digits(s) for s in SPELLINGS})
check("an OUI prefix reduces too — a prefix is a normal search",
      {mac_search_digits(s) for s in OUI_SPELLINGS} == {"aabbcc"},
      {s: mac_search_digits(s) for s in OUI_SPELLINGS})
check("a dotted-decimal IP is refused rather than read as hex",
      mac_search_digits("10.0.0.5") == "" and mac_search_digits("10.20") == "")
check("text that is not hex is refused",
      mac_search_digits("printer-3") == "" and mac_search_digits("zz:zz") == "")
check("longer than a MAC is refused",
      mac_search_digits("aa:bb:cc:dd:ee:ff:00") == "")


# ------------------------------------------ 2. ingest through poll()
def fake_run(payload):
    def _run(script, server, timeout_s, username, password):
        return payload
    return _run


original_run = ipam_dhcp._run
ipam_dhcp._run = fake_run({
    "scopes": [{"scope_id": "10.20.3.0", "name": "Third floor",
                "start_ip": "10.20.3.10", "end_ip": "10.20.3.250",
                "mask": "255.255.255.0", "state": "Active",
                "lease_duration_s": 691200}],
    "leases": [
        {"scope_id": "10.20.3.0", "ip": "10.20.3.42", "mac": "AA-BB-CC-DD-EE-FF",
         "hostname": "printer-3rd-floor", "address_state": "Active",
         "lease_expires": "2030-01-01T00:00:00"},
        # Not a MAC at all — a hardware-type-prefixed id — must survive as
        # the server said it rather than vanish from the lease table.
        {"scope_id": "10.20.3.0", "ip": "10.20.3.43", "mac": "01-12-34-56-78-9A-BC",
         "hostname": "bootp-thing", "address_state": "Active",
         "lease_expires": "2030-01-01T00:00:00"},
        {"scope_id": "10.20.3.0", "ip": "10.20.3.44", "mac": None,
         "hostname": None, "address_state": "Active", "lease_expires": None},
    ],
    "reservations": [
        {"scope_id": "10.20.3.0", "ip": "10.20.3.200", "mac": "11-22-33-44-55-66",
         "name": "Door controller"},
    ],
})
try:
    snapshot = ipam_dhcp.poll("dhcp01")
finally:
    ipam_dhcp._run = original_run
by_ip = {l["ip"]: l for l in snapshot.leases}
check("a lease's ClientId is stored in the colon form hosts.mac uses",
      by_ip["10.20.3.42"]["mac"] == MAC, by_ip["10.20.3.42"])
check("an unclaimed reservation's MAC is stored the same way",
      by_ip["10.20.3.200"]["mac"] == "11:22:33:44:55:66"
      and by_ip["10.20.3.200"]["is_reservation"], by_ip["10.20.3.200"])
check("a ClientId that is not a MAC is kept as the server reported it",
      by_ip["10.20.3.43"]["mac"] == "01-12-34-56-78-9A-BC", by_ip["10.20.3.43"])
check("no ClientId stays None", by_ip["10.20.3.44"]["mac"] is None, by_ip["10.20.3.44"])


# --------------------------------------- 3. search_dhcp, every spelling
db = new_db("search")
srv_a = db.add_dhcp_server("dhcp-a.example", label="Site A")
srv_b = db.add_dhcp_server("dhcp-b.example", label="Site B")
db.replace_dhcp_scopes(srv_a, snapshot.scopes)
db.replace_dhcp_leases(srv_a, snapshot.leases)
# A second server that has seen the same card on a different scope, plus an
# unrelated lease whose hostname, description and IP the text clauses must
# still find, and one whose hostname happens to contain four hex letters.
db.replace_dhcp_scopes(srv_b, [{"scope_id": "10.30.0.0", "name": "Site B users",
                                "start_ip": "10.30.0.10", "end_ip": "10.30.0.250",
                                "mask": "255.255.255.0", "state": "Active",
                                "lease_duration_s": 86400}])
db.replace_dhcp_leases(srv_b, [
    {"scope_id": "10.30.0.0", "ip": "10.30.0.77", "mac": MAC,
     "hostname": "laptop-roaming", "address_state": "Active",
     "lease_expires_ts": time.time() + 3600, "is_reservation": False,
     "description": None},
    {"scope_id": "10.30.0.0", "ip": "10.30.0.5", "mac": "de:ad:be:ef:00:01",
     "hostname": "cafe-till", "address_state": "Active",
     "lease_expires_ts": time.time() + 3600, "is_reservation": True,
     "description": "Coffee bar point of sale"},
])

for spelling in SPELLINGS:
    rows = db.search_dhcp(spelling)
    check(f"search_dhcp finds the lease by {spelling!r}",
          {r["ip"] for r in rows} == {"10.20.3.42", "10.30.0.77"},
          [dict(r) for r in rows])
for spelling in OUI_SPELLINGS:
    rows = db.search_dhcp(spelling)
    check(f"search_dhcp finds the lease by the OUI prefix {spelling!r}",
          {r["ip"] for r in rows} == {"10.20.3.42", "10.30.0.77"},
          [dict(r) for r in rows])
rows = db.search_dhcp("eeff")
check("search_dhcp finds the lease by the four digits printed on its label",
      {r["ip"] for r in rows} == {"10.20.3.42", "10.30.0.77"}, [dict(r) for r in rows])
rows = db.search_dhcp("11:22:33:44:55:66")
check("search_dhcp finds the reservation by its MAC, flagged as one",
      len(rows) == 1 and rows[0]["ip"] == "10.20.3.200" and rows[0]["is_reservation"] == 1,
      [dict(r) for r in rows])
check("search_dhcp joins the server label",
      rows and rows[0]["server_label"] == "Site A", [dict(r) for r in rows])

rows = db.search_dhcp("10.20.3")
check("a dotted-decimal query searches addresses, not a hex prefix",
      {r["ip"] for r in rows} == {"10.20.3.42", "10.20.3.43", "10.20.3.44", "10.20.3.200"},
      [dict(r) for r in rows])
rows = db.search_dhcp("10.30.0.5")
check("...and an exact address finds only that address",
      [r["ip"] for r in rows] == ["10.30.0.5"], [dict(r) for r in rows])
rows = db.search_dhcp("printer")
check("hostname search is unchanged",
      [r["ip"] for r in rows] == ["10.20.3.42"], [dict(r) for r in rows])
rows = db.search_dhcp("point of sale")
check("description search is unchanged",
      [r["ip"] for r in rows] == ["10.30.0.5"], [dict(r) for r in rows])
rows = db.search_dhcp("cafe")
check("four hex letters that are also a hostname fragment find the hostname"
      " (and no MAC happens to contain them)",
      [r["ip"] for r in rows] == ["10.30.0.5"], [dict(r) for r in rows])
rows = db.search_dhcp("beef")
check("...and the same shape finds a MAC that does contain them",
      [r["ip"] for r in rows] == ["10.30.0.5"], [dict(r) for r in rows])
rows = db.search_dhcp("lap")
check("a hostname prefix sorts first, as before",
      rows and rows[0]["hostname"] == "laptop-roaming", [dict(r) for r in rows])
check("search_dhcp honours limit",
      len(db.search_dhcp("10.", limit=2)) == 2)
check("a query nothing matches is empty, not an error",
      db.search_dhcp("no-such-thing") == [])


# ------------------------------------- 4. search_hosts, every spelling
sub = db.add_subnet("10.20.3.0/24", label="Third floor")
db.record_host("10.20.3.42", sub, True, MAC)
db.record_host("10.20.3.99", sub, True, "de:ad:be:ef:00:02")
db.record_host("10.20.3.100", sub, False, None)
for spelling in SPELLINGS + OUI_SPELLINGS:
    rows = db.search_hosts(spelling)
    check(f"search_hosts finds the host by {spelling!r}",
          [r["ip"] for r in rows] == ["10.20.3.42"], [dict(r) for r in rows])
rows = db.search_hosts("10.20.3.")
check("search_hosts by address is unchanged, with the subnet joined",
      [r["ip"] for r in rows] == ["10.20.3.100", "10.20.3.42", "10.20.3.99"]
      and all(r["subnet_cidr"] == "10.20.3.0/24" for r in rows), [dict(r) for r in rows])
rows = db.search_hosts("10.20.3.4")
check("a dotted-decimal host query is never a hex prefix",
      [r["ip"] for r in rows] == ["10.20.3.42"], [dict(r) for r in rows])
check("search_hosts: nothing for text that is neither address nor MAC",
      db.search_hosts("printer") == [])


# ------------------------------------------ 5. dhcp_leases_for_mac
for spelling in SPELLINGS:
    rows = db.dhcp_leases_for_mac(spelling)
    check(f"dhcp_leases_for_mac({spelling!r}) finds both servers' rows",
          {(r["server_label"], r["ip"]) for r in rows}
          == {("Site A", "10.20.3.42"), ("Site B", "10.30.0.77")},
          [dict(r) for r in rows])
rows = db.dhcp_leases_for_mac(MAC)
check("...freshest poll first (Site B was polled after Site A)",
      [r["server_label"] for r in rows] == ["Site B", "Site A"], [dict(r) for r in rows])
check("...carrying scope, hostname, expiry and the reservation flag",
      rows and rows[0]["scope_id"] == "10.30.0.0" and rows[0]["scope_name"] == "Site B users"
      and rows[0]["hostname"] == "laptop-roaming" and rows[0]["lease_expires_ts"]
      and rows[0]["is_reservation"] == 0
      and rows[1]["scope_name"] == "Third floor" and rows[1]["hostname"] == "printer-3rd-floor",
      [dict(r) for r in rows])
check("dhcp_leases_for_mac honours limit",
      len(db.dhcp_leases_for_mac(MAC, limit=1)) == 1)
check("a prefix is not a MAC: dhcp_leases_for_mac refuses it",
      db.dhcp_leases_for_mac("aa:bb:cc") == [])
check("...and so is an IP", db.dhcp_leases_for_mac("10.20.3.42") == [])
check("an unknown MAC is simply empty",
      db.dhcp_leases_for_mac("00:00:00:00:00:01") == [])
plan = db._conn.execute(
    "EXPLAIN QUERY PLAN SELECT * FROM dhcp_leases l WHERE l.mac = ?", (MAC,)).fetchall()
check("the exact lookup is what ix_dhcp_leases_mac is for",
      any("ix_dhcp_leases_mac" in row[-1] for row in plan), [tuple(r) for r in plan])


# ------------------------- 6. a row left in the old spelling is still found
# Written straight into the table, past both the ingest conversion and the
# open-time rewrite: this is what proves the query-time half of the fix
# earns its place on its own.
conn = sqlite3.connect(db.path)
conn.execute(
    "INSERT INTO dhcp_leases(server_id, scope_id, ip, mac, hostname, address_state,"
    " lease_expires_ts, is_reservation, description, polled_ts)"
    " VALUES (?,?,?,?,?,?,?,?,?,?)",
    (srv_a, "10.20.3.0", "10.20.3.150", "0C-0D-0E-0F-10-11", "legacy-spelling",
     "Active", None, 0, None, time.time()))
conn.commit()
conn.close()
for spelling in ("0c:0d:0e:0f:10:11", "0C-0D-0E-0F-10-11", "0c0d.0e0f.1011", "0c0d0e"):
    rows = db.search_dhcp(spelling)
    check(f"a row still in Windows' spelling is found by {spelling!r}",
          [r["ip"] for r in rows] == ["10.20.3.150"], [dict(r) for r in rows])


# ---------------------------------------- 7. service.ipam_search unchanged
class Stub:
    """Just enough of Service for its ipam_search method, which reads only
    ipam_db and app_db.search_hostnames — the real thing stands up ten
    databases and every worker."""
    ipam_db = db

    class app_db:
        @staticmethod
        def search_hostnames(query, limit):
            return []


for spelling in SPELLINGS:
    results = Service.ipam_search(Stub(), spelling)
    found = {r["ip"]: r for r in results}
    check(f"ipam_search({spelling!r}) reaches the lease and the swept host",
          set(found) == {"10.20.3.42", "10.30.0.77"}
          and found["10.20.3.42"]["mac"] == MAC
          and found["10.20.3.42"]["hostname"] == "printer-3rd-floor"
          and "DHCP lease (Site A)" in found["10.20.3.42"]["sources"]
          and "discovered by SappiWhere's own sweep" in found["10.20.3.42"]["sources"]
          and found["10.20.3.42"]["subnet"] == "10.20.3.0/24"
          and found["10.20.3.42"]["alive"] is True,
          results)
results = Service.ipam_search(Stub(), "11:22:33:44:55:66")
check("ipam_search labels a reservation as one",
      len(results) == 1 and results[0]["sources"] == ["DHCP reservation (Site A)"], results)
results = Service.ipam_search(Stub(), "10.20.3")
check("ipam_search by address is unchanged",
      {r["ip"] for r in results} >= {"10.20.3.42", "10.20.3.99", "10.20.3.200"}, results)


# --------------------------- 7b. the global search's own lease endpoint
# ipam_search above folds both of the card's leases into ONE host record
# and drops the scope, server, expiry and reservation flag on the way; the
# lease-search handler returns them as the two leases they are.
payload = api.get_ipam_dhcp_lease_search(Stub(), {"q": "AABB.CCDD.EEFF"}, None)
leases = {l["ip"]: l for l in payload["leases"]}
check("lease-search finds both leases for a MAC in a spelling nobody stored",
      set(leases) == {"10.20.3.42", "10.30.0.77"}, payload)
lease = leases.get("10.20.3.42", {})
check("...each carrying ip, mac, hostname, scope, server, state, expiry, reservation flag",
      lease.get("mac") == MAC and lease.get("hostname") == "printer-3rd-floor"
      and lease.get("scope_id") == "10.20.3.0" and lease.get("server_label") == "Site A"
      and lease.get("address_state") == "Active"
      and isinstance(lease.get("lease_expires"), (int, float))
      and lease.get("is_reservation") is False and "description" in lease, lease)
check("...and the other lease names ITS server, which is the point of not merging them",
      leases.get("10.30.0.77", {}).get("server_label") == "Site B", leases)
reservation = api.get_ipam_dhcp_lease_search(Stub(), {"q": "coffee"}, None)["leases"]
check("lease-search by description flags a reservation as one",
      [(l["ip"], l["is_reservation"]) for l in reservation] == [("10.30.0.5", True)],
      reservation)
check("a needle under two characters answers an empty list, never the whole table",
      api.get_ipam_dhcp_lease_search(Stub(), {"q": "1"}, None) == {"leases": []}
      and api.get_ipam_dhcp_lease_search(Stub(), {}, None) == {"leases": []})
db.close()


# ------------------------------------------------ 8. the migration
# An ipam.db from before ipam_dhcp normalised anything: same tables, rows
# holding exactly what the DhcpServer module printed. Opening it with the
# current code must rewrite them and find them at once, must leave a
# ClientId that is not a MAC alone, must not trip on NULL or empty, and
# must be a no-op the second time.
legacy_path = os.path.join(TMP, "legacy.db")
legacy = IpamDatabase(legacy_path)
legacy_srv = legacy.add_dhcp_server("old-dhcp", label="Old")
legacy.close()
conn = sqlite3.connect(legacy_path)
legacy_rows = [
    ("10.9.0.10", "AA-BB-CC-DD-EE-FF", "old-printer"),
    ("10.9.0.11", "11-22-33-44-55-66", "old-door"),
    ("10.9.0.12", "01-12-34-56-78-9A-BC", "old-bootp"),   # not a MAC: untouched
    ("10.9.0.13", None, "old-no-mac"),
    ("10.9.0.14", "", "old-empty-mac"),
    ("10.9.0.15", "de:ad:be:ef:00:03", "already-colon"),
]
conn.executemany(
    "INSERT INTO dhcp_leases(server_id, scope_id, ip, mac, hostname, address_state,"
    " lease_expires_ts, is_reservation, description, polled_ts)"
    " VALUES (?,?,?,?,?,?,?,?,?,?)",
    [(legacy_srv, "10.9.0.0", ip, mac, host, "Active", None, 0, None, time.time())
     for ip, mac, host in legacy_rows])
conn.commit()
stored = dict(conn.execute("SELECT ip, mac FROM dhcp_leases").fetchall())
conn.close()
check("the fixture really holds Windows' spelling",
      stored["10.9.0.10"] == "AA-BB-CC-DD-EE-FF", stored)

try:
    legacy = IpamDatabase(legacy_path)
except sqlite3.OperationalError as exc:
    check("a pre-normalisation ipam.db opens with the current code", False, exc)
    legacy = None
if legacy is not None:
    check("a pre-normalisation ipam.db opens with the current code", True)
    stored = {r["ip"]: r["mac"] for r in legacy.dhcp_leases(legacy_srv)}
    check("...and the open rewrote the dash/upper rows into the colon form",
          stored["10.9.0.10"] == MAC and stored["10.9.0.11"] == "11:22:33:44:55:66", stored)
    check("...left a ClientId that is not a MAC exactly as stored",
          stored["10.9.0.12"] == "01-12-34-56-78-9A-BC", stored)
    check("...and did not trip on NULL, empty or already-colon rows",
          stored["10.9.0.13"] is None and stored["10.9.0.14"] == ""
          and stored["10.9.0.15"] == "de:ad:be:ef:00:03", stored)
    for spelling in SPELLINGS:
        rows = legacy.search_dhcp(spelling)
        check(f"the migrated row is found by {spelling!r}",
              [r["ip"] for r in rows] == ["10.9.0.10"], [dict(r) for r in rows])
    rows = legacy.dhcp_leases_for_mac("AA-BB-CC-DD-EE-FF")
    check("dhcp_leases_for_mac finds the migrated row through the index",
          [r["ip"] for r in rows] == ["10.9.0.10"], [dict(r) for r in rows])
    check("conflict detection's cross-check now compares equal without help",
          legacy.dhcp_lease_for_ip("10.9.0.10")["mac"] == MAC)
    legacy.close()
    legacy = IpamDatabase(legacy_path)      # a second open must be a no-op rewrite
    again = {r["ip"]: r["mac"] for r in legacy.dhcp_leases(legacy_srv)}
    check("reopening an already-migrated database changes nothing",
          again == stored, (again, stored))
    legacy.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)

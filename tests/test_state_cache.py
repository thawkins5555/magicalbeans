"""The caches the web tier gained in 5.4.1, and the thing each one must not
break.

Three server-side caches, each with a way of being wrong that a bench would
never show:

* /api/state's fleet counts are computed once per two-second window and
  shared by every open tab. `_drop_unreadable` MUTATES the dict it is given,
  so the moment a cached structure reaches it, one account's redaction would
  become everybody's — permanently, for every tab, until the process
  restarted. Two accounts with different grants poll alternately here, over
  and over inside one window, and neither may ever see the other's.

* `user()` and `permissions_for()` are memoised for the life of ONE request.
  The promise that has to survive is the one server.py's dispatch documents:
  a grant revoked, or a password reset, takes effect on the very NEXT
  request. So the revocation is made and the immediately following request
  must be refused — no sleep, no second attempt.

* The OID name table and the discovery device index are held against a
  generation counter. Both must rebuild when the thing under them moves.
"""

import http.client
import json
import os
import re
import sys
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("state_cache_")

from netpath.web import Service, WebServer
from netpath.web import api
from netpath.auth import hash_password

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=port, certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{port}")

conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)

ADMIN = "cacheadmin"
ADMIN_PASSWORD = "StateCacheAdmin2026"
READER = "cachereader"
READER_PASSWORD = "StateCacheReader2026"

# What each account may read. Disjoint on purpose: every live block one of
# them gets is a block the other must never see, so a leak in either
# direction is a failed check rather than a coincidence.
ADMIN_GRANTS = {"netflow": "write", "nodes": "write", "wireless": "write",
                "ipam": "write", "admin": "write", "settings": "write"}
READER_GRANTS = {"syslog": "read", "alerts": "read"}
ADMIN_BLOCKS = ("collector", "nodes", "wireless", "ipam", "storage")
READER_BLOCKS = ("syslog", "alerts")

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label
          + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return resp.status, payload, dict(resp.getheaders())


def login(username, password):
    status, payload, headers = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


try:
    service.app_db.add_user(ADMIN, hash_password(ADMIN_PASSWORD), must_change=False)
    service.app_db.set_permissions(ADMIN, ADMIN_GRANTS)
    service.app_db.add_user(READER, hash_password(READER_PASSWORD), must_change=False)
    service.app_db.set_permissions(READER, READER_GRANTS)
    admin_token = login(ADMIN, ADMIN_PASSWORD)
    reader_token = login(READER, READER_PASSWORD)

    # ------------------------------------------------------------------ 1
    # The whole point of the item: the composite count cache must not let
    # one account's redaction reach another's response.
    print("/api/state: the count cache never carries one account's redaction "
          "into another's response")

    status, admin_state, _ = call("GET", "/api/state", token=admin_token)
    check("the admin account can poll state", status == 200, status)
    status, reader_state, _ = call("GET", "/api/state", token=reader_token)
    check("the reader account can poll state", status == 200, status)
    check("they were granted genuinely different modules",
          not (set(ADMIN_GRANTS) & set(READER_GRANTS)))

    # Forty alternating polls, back to back — several TTL windows' worth of
    # requests, and many of them inside one window, which is the case that
    # shares a cached object.
    admin_missing = set()
    reader_leaked = set()
    reader_missing = set()
    admin_leaked = set()
    counts_seen = []
    for _round in range(20):
        status, a_state, _ = call("GET", "/api/state", token=admin_token)
        if status != 200:
            failures.append("admin poll returned %s" % status)
            break
        admin_missing |= {b for b in ADMIN_BLOCKS if b not in a_state}
        admin_leaked |= {b for b in READER_BLOCKS if b in a_state}
        counts_seen.append(a_state.get("nodes", {}).get("device_counts"))

        status, r_state, _ = call("GET", "/api/state", token=reader_token)
        if status != 200:
            failures.append("reader poll returned %s" % status)
            break
        reader_missing |= {b for b in READER_BLOCKS if b not in r_state}
        reader_leaked |= {b for b in ADMIN_BLOCKS if b in r_state}

    check("over 20 alternating rounds the admin never loses a block it may read",
          not admin_missing, sorted(admin_missing))
    check("…and never gains one it may not", not admin_leaked, sorted(admin_leaked))
    check("the reader never loses a block it may read",
          not reader_missing, sorted(reader_missing))
    check("…and never gains one it may not", not reader_leaked, sorted(reader_leaked))
    check("the admin's device_counts survived every round intact",
          all(isinstance(c, dict) and "total" in c for c in counts_seen),
          str(counts_seen[:2]))

    # In-process, where the wire cannot hide the object identity: the two
    # nested count dicts handed to a response must be COPIES, so that a
    # caller reaching one level down cannot reach the cache.
    print("/api/state: the cached structure is never the one handed out")
    admin_params = {"_username": ADMIN, "_token": "", "_cache": {}}
    first = api.get_state(service, admin_params, {})
    first["nodes"]["device_counts"]["total"] = -999
    first["wireless"]["ap_counts"]["poisoned"] = True
    second = api.get_state(service, dict(admin_params, _cache={}), {})
    check("poisoning one response's device_counts does not reach the next",
          second["nodes"]["device_counts"].get("total") != -999,
          second["nodes"]["device_counts"])
    check("…nor its ap_counts", "poisoned" not in second["wireless"]["ap_counts"],
          second["wireless"]["ap_counts"])

    # And the redaction itself, applied in process to a reader's result,
    # must leave the admin's next result whole — this is the exact failure
    # the item was about.
    reader_params = {"_username": READER, "_token": "", "_cache": {}}
    redacted = api.get_state(service, reader_params, {})
    check("a reader's in-process result really is redacted",
          "nodes" not in redacted and "collector" not in redacted,
          sorted(k for k in redacted if k in ADMIN_BLOCKS))
    after = api.get_state(service, dict(admin_params, _cache={}), {})
    check("and the admin's very next result is still whole",
          all(block in after for block in ADMIN_BLOCKS),
          sorted(b for b in ADMIN_BLOCKS if b not in after))

    # ------------------------------------------------------------------ 2
    # It is a cache, not a no-op: many polls in one window cost one compute.
    print("/api/state: N polls in one window cost one compute")
    real_state_counts = api._state_counts
    calls = []

    def counting_state_counts(svc):
        calls.append(time.time())
        return real_state_counts(svc)

    api._state_counts = counting_state_counts
    try:
        # Let any in-flight window expire so the count below starts clean.
        time.sleep(api.STATE_COUNTS_TTL_S + 0.2)
        started = time.time()
        polls = 0
        while time.time() - started < api.STATE_COUNTS_TTL_S * 0.5:
            status, _payload, _ = call("GET", "/api/state", token=admin_token)
            polls += 1
        check("many polls inside half a TTL computed the counts at most once",
              polls >= 5 and len(calls) <= 1, f"{polls} polls, {len(calls)} computes")
        # …and freshness returns of its own accord once the window is over.
        time.sleep(api.STATE_COUNTS_TTL_S + 0.2)
        call("GET", "/api/state", token=admin_token)
        check("and the window after the TTL recomputes them",
              len(calls) >= 1 and len(calls) <= 2, len(calls))
    finally:
        api._state_counts = real_state_counts

    # The counts must still be TRUE, not merely cheap: a device added now
    # shows up on the far side of one TTL.
    print("/api/state: a cached count still goes stale, and then correct")
    before_total = api.get_state(
        service, dict(admin_params, _cache={}), {})["nodes"]["device_counts"]["total"]
    service.nodes_db.add_device("10.77.77.77", name="cache-canary")
    time.sleep(api.STATE_COUNTS_TTL_S + 0.3)
    after_total = api.get_state(
        service, dict(admin_params, _cache={}), {})["nodes"]["device_counts"]["total"]
    check("a device added during a window is counted in the next",
          after_total == before_total + 1, (before_total, after_total))

    # ------------------------------------------------------------------ 3
    # Per-request memoisation: the guarantee it must not weaken.
    print("per-request memo: a revoked grant is refused on the NEXT request")
    status, _payload, _ = call("GET", "/api/nodes/devices?limit=1", token=admin_token)
    check("the admin can list devices to begin with", status == 200, status)

    service.app_db.set_permissions(ADMIN, {k: v for k, v in ADMIN_GRANTS.items()
                                           if k != "nodes"})
    # No sleep, no retry: the very next request on the same keep-alive
    # connection with the same cookie.
    status, payload, _ = call("GET", "/api/nodes/devices?limit=1", token=admin_token)
    check("the immediately following request is refused 403",
          status == 403, f"{status} {payload}")
    check("…and says which module and level it wanted",
          isinstance(payload, dict) and "nodes" in str(payload.get("error", "")),
          payload)

    service.app_db.set_permissions(ADMIN, ADMIN_GRANTS)
    status, _payload, _ = call("GET", "/api/nodes/devices?limit=1", token=admin_token)
    check("and granting it back is honoured on the next request too",
          status == 200, status)

    # The other half of the same guarantee, through the other memoised read.
    # Not /api/state: that one is in MUST_CHANGE_API on purpose — it is what
    # raises the change prompt. /api/syslog/search is an ordinary route the
    # reader may read, so the gate is the only thing that can refuse it.
    print("per-request memo: a password reset is refused on the NEXT request")
    status, _payload, _ = call("GET", "/api/syslog/search?limit=1", token=reader_token)
    check("the reader can search syslog to begin with", status == 200, status)
    service.app_db.set_password(READER, hash_password(READER_PASSWORD),
                                must_change=True)
    status, payload, _ = call("GET", "/api/syslog/search?limit=1", token=reader_token)
    check("an account that now owes a password change is refused at once",
          status == 403 and "password change" in str(payload).lower(),
          f"{status} {payload}")
    service.app_db.set_password(READER, hash_password(READER_PASSWORD),
                                must_change=False)
    status, _payload, _ = call("GET", "/api/syslog/search?limit=1", token=reader_token)
    check("and lifting it is honoured on the next request", status == 200, status)

    # Within ONE request the memo has to actually memoise, or it is only a
    # rename. get_config asks for the caller's grants; the dispatch gate
    # asked for them first; one cache, one read.
    print("per-request memo: one request, one read")
    cache = {}
    params = {"_username": ADMIN, "_cache": cache}
    reads = []
    real_permissions_for = service.app_db.permissions_for

    def counting_permissions_for(username):
        reads.append(username)
        return real_permissions_for(username)

    service.app_db.permissions_for = counting_permissions_for
    try:
        first = api.request_permissions(service, params)
        second = api.request_permissions(service, params)
        third = api.request_permissions(service, params)
    finally:
        service.app_db.permissions_for = real_permissions_for
    check("three asks inside one request are one app.db read", len(reads) == 1, reads)
    check("and they all say the same thing", first == second == third, (first, second))
    check("each ask gets its own dict, so a caller that stores one in a "
          "response cannot edit the memo",
          first is not second and second is not third)

    # A fresh request cache is a fresh read — that is what "per request"
    # means, and it is why a revocation lands on the next request.
    reads.clear()
    service.app_db.permissions_for = counting_permissions_for
    try:
        api.request_permissions(service, {"_username": ADMIN, "_cache": {}})
        api.request_permissions(service, {"_username": ADMIN, "_cache": {}})
    finally:
        service.app_db.permissions_for = real_permissions_for
    check("two requests are two reads", len(reads) == 2, reads)

    # A handler asking about a DIFFERENT account must never be handed the
    # caller's answer.
    other = api.request_permissions(service, params, READER)
    check("asking for another account inside the same request answers about "
          "that account", set(other) == set(READER_GRANTS), other)
    check("…and the caller's own answer is unchanged",
          set(api.request_permissions(service, params)) == set(ADMIN_GRANTS),
          api.request_permissions(service, params))

    # Called outside the server (a test, a script) there is no cache dict,
    # and the helpers must read straight through rather than raise.
    check("with no request cache the helper reads through",
          set(api.request_permissions(service, {"_username": ADMIN})) == set(ADMIN_GRANTS))
    check("…and so does the user lookup",
          api.request_user(service, {"_username": ADMIN})["username"] == ADMIN)
    check("an account that does not exist caches a good None",
          api.request_user(service, {"_username": "nobody-at-all", "_cache": {}}) is None)

    # ------------------------------------------------------------------ 4
    # No process-lifetime memo anywhere in netpath: a grant revoked has to
    # be able to take effect, and lru_cache on any of this would mean it
    # never could.
    print("no process-lifetime cache was introduced")
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "netpath")
    # Comment lines are skipped: the two helpers above explain in prose why
    # they are NOT lru_cache, and that explanation must not read as a use.
    banned = re.compile(r"(@\s*(functools\.)?(lru_cache|cache)\b"
                        r"|(functools\.)?lru_cache\s*\()")
    offenders = []
    for folder, _dirs, files in os.walk(root):
        if "__pycache__" in folder:
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(folder, name)
            with open(path, encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if line.lstrip().startswith("#"):
                        continue
                    if banned.search(line):
                        offenders.append(
                            "%s:%d" % (os.path.relpath(path, root), number))
    check("netpath/ still uses no lru_cache and no functools.cache",
          not offenders, offenders)

    # ------------------------------------------------------------------ 5
    print("the OID name table rebuilds only when the MIB corpus moves")
    table_a = api._oid_name_table(service)
    table_b = api._oid_name_table(service)
    check("two calls with nothing changed are one build",
          table_a is table_b)

    mib_id = service.nodes_db.add_mib_file(
        "CACHE-TEST-MIB.mib", "CACHE-TEST-MIB", 1, [], "")
    service.nodes_db.replace_mib_objects(
        mib_id, [{"name": "cacheTestObject", "oid": "1.3.6.1.4.1.99999.1"}])
    table_c = api._oid_name_table(service)
    check("installing a MIB rebuilds it",
          table_c is not table_a
          and table_c.get("1.3.6.1.4.1.99999.1") == "cacheTestObject",
          table_c.get("1.3.6.1.4.1.99999.1"))

    obj_id = [r["id"] for r in service.nodes_db.mib_objects(mib_id)][0]
    api.put_nodes_mib_object(service, {"_username": ADMIN}, {"name": "cacheTestRenamed"},
                             mib_id, obj_id)
    table_d = api._oid_name_table(service)
    check("an in-place rename rebuilds it too — the object count and the "
          "highest id never moved",
          table_d.get("1.3.6.1.4.1.99999.1") == "cacheTestRenamed",
          table_d.get("1.3.6.1.4.1.99999.1"))

    service.nodes_db.remove_mib_file(mib_id)
    table_e = api._oid_name_table(service)
    check("and deleting the file takes its names back out",
          "1.3.6.1.4.1.99999.1" not in table_e)

    # ------------------------------------------------------------------ 6
    # The one that must NOT be cached, and the reason written down as a
    # check so that re-adding the obvious cache fails here rather than in
    # test_device_identity's discovery listing.
    print("the discovery device index is rebuilt every listing, on purpose")
    canary_id = service.nodes_db.add_device("10.77.77.78", name="index-canary")
    index_a = api._device_index(service)
    check("a freshly added device is in it", canary_id in index_a["by_id"])

    # seed_identity is what the discovery sweep calls, and it deliberately
    # does NOT bump config_generation — an observation is not a setting. A
    # listing served from a generation-keyed cache would miss this, flag no
    # duplicate, and add the box a second time.
    generation_before = service.nodes_db.config_generation()
    service.nodes_db.seed_identity(canary_id, sys_name="canary-twin",
                                   sys_object_id="1.3.6.1.4.1.4243")
    check("learning an identity does not move config_generation",
          service.nodes_db.config_generation() == generation_before,
          (generation_before, service.nodes_db.config_generation()))
    index_b = api._device_index(service)
    check("…and the very next index still sees it, so the listing can flag "
          "the duplicate",
          ("canary-twin", "1.3.6.1.4.1.4243") in index_b["by_identity"],
          sorted(index_b["by_identity"])[:3])

    # Same argument for a learned alias, which feeds by_address.
    service.nodes_db.record_device_addresses(canary_id, ["10.77.77.79"], "test")
    index_c = api._device_index(service)
    check("a learned alias reaches the next index too",
          "10.77.77.79" in index_c["by_address"],
          sorted(index_c["by_address"])[-3:])
    check("no generation-keyed memo was left on the Service",
          getattr(service, "_api_device_index", None) is None)
    service.nodes_db.remove_device(canary_id)

    # A re-resolve is the case the MIB generation used to miss entirely.
    # mib_objects.id is INTEGER PRIMARY KEY without AUTOINCREMENT, so
    # replacing a file's objects with the same NUMBER of objects reuses the
    # ids just freed at the top of the table — leaving MAX(id), the object
    # count and the file count all identical. A key built from those three
    # alone went on serving the pre-resolve table: numeric OIDs for exactly
    # the objects the Resolve button had just made known.
    mib_db = service.nodes_db.mib_db
    mib_id = mib_db.add_mib_file("REGRESS-MIB", "REGRESS", 2, [], "")
    mib_db.replace_mib_objects(mib_id, [{"name": "ra", "oid": None},
                                        {"name": "rb", "oid": None}])
    before = service.nodes_db.mib_generation()
    mib_db.replace_mib_objects(mib_id, [{"name": "ra", "oid": "1.3.6.1.4.1.99.1"},
                                        {"name": "rb", "oid": "1.3.6.1.4.1.99.2"}])
    after = service.nodes_db.mib_generation()
    check("a re-resolve leaves max id, object count and file count identical",
          before[:3] == after[:3], (before[:3], after[:3]))
    check("…but the generation still moves, so the OID table is rebuilt",
          before != after, (before, after))
    mib_db.remove_mib_file(mib_id)

finally:
    server.stop()
    service.shutdown()

sys.exit(1 if failures else 0)

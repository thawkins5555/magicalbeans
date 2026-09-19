"""fortipoll's table walk (5.49.0): GETBULK on v2c/v3, GETNEXT still on v1,
the same split nodepoll's own walk already makes. Proves: the stored AP and
radio rows are identical whichever protocol walked them; a large AP count
takes far fewer round trips under GETBULK; a tooBig reply halves the
repetition count and the walk still completes; and a controller that refuses
GETBULK outright falls back to GETNEXT once and is never asked with GETBULK
again for the life of the poller."""
import os
import sys
import time
import types

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("fortipoll_getbulk_")

from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.snmppoll import PDU_GETBULK, PDU_GETNEXT
from netpath.wirelessdb import WirelessDatabase
from netpath import nodeoids as oids

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


# Compared across the two protocols; excludes ids, poll timestamps and
# response_ms (ping timing), which legitimately differ between two polls.
_AP_FIELDS = ("wtp_id", "vdom", "name", "status", "model", "mac_address",
             "ip", "station_count", "uptime_ticks", "session_uptime_ticks",
             "profile", "out_of_service")
_RADIO_FIELDS = ("radio_id", "channel", "operating_power_dbm",
                 "station_count", "mode", "bssid", "channel_width")


def poll_and_read(db, controller_id):
    controller = dict(db.controller(controller_id))
    poller = WirelessPoller(db)
    poller._poll_controller(controller)
    aps = db.access_points(controller_id)
    return {
        ap["wtp_id"]: (
            {field: ap[field] for field in _AP_FIELDS},
            [{field: r[field] for field in _RADIO_FIELDS}
             for r in db.radios_for(ap["id"])],
        )
        for ap in aps
    }


def test_identical_rows_getnext_vs_getbulk():
    stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py")
    try:
        db = WirelessDatabase(os.path.join(tmpdir("getbulk_identical_"), "wireless.db"))
        getnext_id = db.add_controller("GETNEXT", "127.0.0.1",
                                       snmp_version=0, community="public")
        getbulk_id = db.add_controller("GETBULK", "127.0.0.1",
                                       snmp_version=1, community="public")
        by_getnext = poll_and_read(db, getnext_id)
        by_getbulk = poll_and_read(db, getbulk_id)
        check(set(by_getnext) == set(by_getbulk) and len(by_getnext) == 2,
              f"both protocols find the same APs ({sorted(by_getnext)}, "
              f"{sorted(by_getbulk)})")
        check(by_getnext == by_getbulk,
              f"...with identical stored fields and radios "
              f"(GETNEXT={by_getnext}, GETBULK={by_getbulk})")
        db.close()
    finally:
        stub.kill()


def test_request_count_drops_for_a_large_ap_count():
    stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py", "", "100")
    try:
        db = WirelessDatabase(os.path.join(tmpdir("getbulk_count_"), "wireless.db"))
        controller_id = db.add_controller("c", "127.0.0.1",
                                          snmp_version=1, community="public")
        controller = dict(db.controller(controller_id))
        config = controller
        poller = WirelessPoller(db)

        def counting_session(counts):
            real_session = fortipoll_mod._Session

            class CountingSession(real_session):
                def request(self, *args, **kwargs):
                    counts["n"] += 1
                    return super().request(*args, **kwargs)
            return CountingSession

        real_session = fortipoll_mod._Session

        bulk_counts = {"n": 0}
        fortipoll_mod._Session = counting_session(bulk_counts)
        try:
            values = poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        finally:
            fortipoll_mod._Session = real_session
        check(len(values) == 100, f"the walk still finds all 100 APs (got {len(values)})")

        # Forced off, as a controller that already learned GETBULK does not
        # work would be -- the "before" comparison this pins.
        poller._bulk_repetitions[controller_id] = 0
        getnext_counts = {"n": 0}
        fortipoll_mod._Session = counting_session(getnext_counts)
        try:
            values2 = poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        finally:
            fortipoll_mod._Session = real_session
        check(values2 == values, "GETNEXT-only reads the identical 100 rows")

        check(bulk_counts["n"] * 5 < getnext_counts["n"],
              f"GETBULK takes far fewer requests for 100 APs "
              f"(GETBULK={bulk_counts['n']}, GETNEXT={getnext_counts['n']})")
        db.close()
    finally:
        stub.kill()


def test_toobig_halves_and_continues():
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_toobig_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    row_oid = f"{base_oid}.1"
    calls = []

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        calls.append(max_repetitions)
        if pdu_tag == PDU_GETBULK and max_repetitions > 5:
            return types.SimpleNamespace(error_status=1, varbinds=[])   # tooBig
        return types.SimpleNamespace(error_status=0, varbinds=[
            {"oid": row_oid, "type": "OctetString", "value": "AP0001"},
            {"oid": "9.9.9.9", "type": "OctetString", "value": "x"}])

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)

    check(values == {"1": "AP0001"}, f"the walk still finds the one real row ({values})")
    check(calls[0] == fortipoll_mod.BULK_MAX_REPETITIONS,
          f"starts at the shipped default (got {calls[0]})")
    check(calls == [40, 20, 10, 5], f"halves on each tooBig until it succeeds (got {calls})")
    check(poller._bulk_repetitions[controller_id] == 5,
          f"...and remembers the repetition count that worked "
          f"(got {poller._bulk_repetitions.get(controller_id)})")
    db.close()


def test_getbulk_refused_falls_back_and_remembers():
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_refused_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    row_oid = f"{base_oid}.1"
    calls = []

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        calls.append(pdu_tag)
        if pdu_tag == PDU_GETBULK:
            return types.SimpleNamespace(error_status=1, varbinds=[])   # tooBig, always
        if oid == base_oid:
            return types.SimpleNamespace(error_status=0, varbinds=[
                {"oid": row_oid, "type": "OctetString", "value": "AP0001"}])
        return types.SimpleNamespace(error_status=0, varbinds=[
            {"oid": "9.9.9.9", "type": "OctetString", "value": "x"}])

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)

    check(values == {"1": "AP0001"}, f"the walk still finds the one real row ({values})")
    check(poller._bulk_repetitions.get(controller_id) == 0,
          "a controller that refuses GETBULK even at repetitions=1 is "
          "remembered as GETNEXT-only")
    # Six tooBig GETBULK attempts (40->20->10->5->2->1) before the fallback,
    # then two GETNEXT calls -- one for the real row, one to discover the
    # end -- the same shape any GETNEXT walk ends on.
    check(PDU_GETBULK in calls and calls[-2:] == [PDU_GETNEXT, PDU_GETNEXT]
          and all(tag == PDU_GETBULK for tag in calls[:-2]),
          f"every GETBULK attempt halved down before falling back to "
          f"GETNEXT (got {calls})")

    calls.clear()
    values2 = poller._walk_column(controller, config, base_oid)
    check(values2 == values, "a second walk on the same controller reads the same row")
    check(all(tag == PDU_GETNEXT for tag in calls),
          f"...and never tries GETBULK again for the life of the poller "
          f"(got {calls})")
    db.close()


def test_out_of_order_oid_stops_walk_mid_response():
    """The no-advance guard has to apply inside one GETBULK response, not
    just across separate requests: a single reply carrying a row, then a
    repeated/out-of-order OID, must keep only the row before it."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_stuck_response_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        return types.SimpleNamespace(error_status=0, varbinds=[
            {"oid": f"{base_oid}.1", "type": "OctetString", "value": "AP0001"},
            {"oid": f"{base_oid}.1", "type": "OctetString", "value": "repeat"},
            {"oid": f"{base_oid}.2", "type": "OctetString", "value": "AP0002"}])

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)
    check(values == {"1": "AP0001"},
          f"the walk stops at the repeated OID inside the response, keeping "
          f"only the row before it, not the one after (got {values})")
    db.close()


def test_row_cap_reached_mid_response():
    """4096 is a row count now, not a request count: one GETBULK response
    carrying more than that many rows must still be cut off at exactly the
    cap, without needing a second request."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_cap_response_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    calls = {"n": 0}

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        calls["n"] += 1
        varbinds = [{"oid": f"{base_oid}.{i}", "type": "OctetString", "value": "x"}
                   for i in range(1, 5001)]
        return types.SimpleNamespace(error_status=0, varbinds=varbinds)

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)
    check(len(values) == fortipoll_mod._WALK_MAX_ROWS,
          f"cut off at exactly the row cap from one oversized response "
          f"(got {len(values)})")
    check(calls["n"] == 1, f"no second request was needed (got {calls['n']})")
    db.close()


def test_generr_on_getbulk_falls_back_to_getnext():
    """F1: a non-tooBig error status (genErr etc.) on the first GETBULK,
    before any row came back, must not return an empty table silently --
    it falls back to GETNEXT for the rest of the walk."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_generr_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    row_oid = f"{base_oid}.1"
    calls = []

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        calls.append(pdu_tag)
        if pdu_tag == PDU_GETBULK:
            return types.SimpleNamespace(error_status=5, varbinds=[])   # genErr
        if oid == base_oid:
            return types.SimpleNamespace(error_status=0, varbinds=[
                {"oid": row_oid, "type": "OctetString", "value": "AP0001"}])
        return types.SimpleNamespace(error_status=0, varbinds=[
            {"oid": "9.9.9.9", "type": "OctetString", "value": "x"}])

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)

    check(values == {"1": "AP0001"},
          f"genErr on GETBULK does not return an empty table silently "
          f"(got {values})")
    check(calls == [PDU_GETBULK, PDU_GETNEXT, PDU_GETNEXT],
          f"one genErr GETBULK attempt, then GETNEXT for the rest (got {calls})")
    check(poller._bulk_repetitions.get(controller_id) == 0,
          "the genErr verdict is remembered as GETNEXT-only")
    db.close()


def test_timeout_on_untried_controller_downgrades_once():
    """F2: a timeout on the first GETBULK ever tried against a controller
    (no learned verdict yet) retries once as GETNEXT rather than failing
    the whole poll -- a large reply can exceed path MTU on a tunnel that a
    single-row GETNEXT reply never would."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_timeout_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"
    row_oid = f"{base_oid}.1"
    calls = []

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        calls.append(pdu_tag)
        if pdu_tag == PDU_GETBULK:
            raise fortipoll_mod.SnmpTimeout("no reply")
        if oid == base_oid:
            return types.SimpleNamespace(error_status=0, varbinds=[
                {"oid": row_oid, "type": "OctetString", "value": "AP0001"}])
        return types.SimpleNamespace(error_status=0, varbinds=[
            {"oid": "9.9.9.9", "type": "OctetString", "value": "x"}])

    poller._snmp_walk_request = fake_walk_request
    values = poller._walk_column(controller, config, base_oid)

    check(values == {"1": "AP0001"},
          f"a timed-out first GETBULK still completes over GETNEXT (got {values})")
    check(calls == [PDU_GETBULK, PDU_GETNEXT, PDU_GETNEXT],
          f"exactly one retry as GETNEXT, then the walk's own end (got {calls})")
    check(poller._bulk_repetitions.get(controller_id) == 0,
          "the timeout verdict is remembered as GETNEXT-only")


def test_timeout_does_not_downgrade_a_learned_good_value():
    """F2: a controller that already has a working GETBULK repetition count
    is not undone by one transient timeout -- the timeout just fails the
    walk, the way any other unreachable-controller timeout always has."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_timeout_learned_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    controller = dict(db.controller(controller_id))
    config = {"snmp_version": 1, "community": "public"}
    poller = WirelessPoller(db)
    poller._bulk_repetitions[controller_id] = 20   # already learned, working
    base_oid = "1.3.6.1.4.1.12356.101.14.1.1.2"

    def fake_walk_request(controller, config, oid, session, pdu_tag,
                          max_repetitions, verify_replies=True):
        raise fortipoll_mod.SnmpTimeout("no reply")

    poller._snmp_walk_request = fake_walk_request
    try:
        poller._walk_column(controller, config, base_oid)
        raised = False
    except fortipoll_mod.SnmpTimeout:
        raised = True
    check(raised, "the timeout is not swallowed for an already-learned controller")
    check(poller._bulk_repetitions[controller_id] == 20,
          f"...and its learned repetition count is untouched "
          f"(got {poller._bulk_repetitions[controller_id]})")
    db.close()


def test_sweep_forgets_deleted_controllers_bulk_verdict():
    """F3: a controller id can be reused, so a stale GETNEXT-only (or
    learned-repetitions) verdict must not outlive the controller it was
    learned against, the same way _next_run/_engines are already swept."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_sweep_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    poller = WirelessPoller(db)
    poller._bulk_repetitions[controller_id] = 0
    poller._bulk_last_probe[controller_id] = time.time()
    db.remove_controller(controller_id)

    poller._schedule_pass()

    check(controller_id not in poller._bulk_repetitions,
          "a deleted controller's GETBULK verdict is dropped")
    check(controller_id not in poller._bulk_last_probe,
          "...and its re-probe timestamp with it")
    db.close()


def test_forget_bulk_verdict_reprobes_at_once():
    """F3: an operator's Poll Now (post_wireless_controller_poll calls this
    before poll_now) clears a learned verdict so the very next walk tries
    GETBULK again, rather than waiting out the hourly retry."""
    db = WirelessDatabase(os.path.join(tmpdir("getbulk_forget_"), "wireless.db"))
    controller_id = db.add_controller("c", "127.0.0.1",
                                      snmp_version=1, community="public")
    poller = WirelessPoller(db)
    poller._bulk_repetitions[controller_id] = 0
    poller._bulk_last_probe[controller_id] = time.time()

    poller.forget_bulk_verdict(controller_id)

    check(controller_id not in poller._bulk_repetitions
          and controller_id not in poller._bulk_last_probe,
          "forget_bulk_verdict clears both the verdict and its timestamp")
    use_bulk, _ = poller._bulk_settings(
        dict(db.controller(controller_id)), {"snmp_version": 1})
    check(use_bulk, "...so the very next walk tries GETBULK again immediately")
    db.close()


def main():
    test_identical_rows_getnext_vs_getbulk()
    test_request_count_drops_for_a_large_ap_count()
    test_toobig_halves_and_continues()
    test_getbulk_refused_falls_back_and_remembers()
    test_out_of_order_oid_stops_walk_mid_response()
    test_row_cap_reached_mid_response()
    test_generr_on_getbulk_falls_back_to_getnext()
    test_timeout_on_untried_controller_downgrades_once()
    test_timeout_does_not_downgrade_a_learned_good_value()
    test_sweep_forgets_deleted_controllers_bulk_verdict()
    test_forget_bulk_verdict_reprobes_at_once()

    print()
    if FAILURES:
        print(f"FAILURES: {len(FAILURES)}")
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())

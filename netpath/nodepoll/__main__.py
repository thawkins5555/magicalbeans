from __future__ import annotations

from ._decode import (IF_SPEED_SENTINEL, counter_rate, detect_reboot,
                     interface_speed_bps)


if __name__ == "__main__":
    # counter_rate / detect_reboot are pure functions and provable without
    # any network at all.
    assert counter_rate(100, 0.0, 200, 10.0, 32) == 10.0
    assert counter_rate(2**32 - 50, 0.0, 50, 10.0, 32) == 10.0        # one 32-bit wrap
    assert counter_rate(2**63, 0.0, 5, 10.0, 64) is None              # 64-bit: reset, not a wrap
    assert counter_rate(0, 0.0, 10**12, 1.0, 32, speed_bps=1e9) is None  # implausible vs. link speed
    assert counter_rate(100, 5.0, 200, 5.0, 32) is None               # dt == 0
    assert counter_rate(None, 0.0, 200, 10.0, 32) is None             # first poll
    print("counter_rate OK")

    assert interface_speed_bps(1_000_000_000, 1000) == 1e9             # ordinary 1G port
    assert interface_speed_bps(IF_SPEED_SENTINEL, 400_000) == 4e11     # a real 400G port
    assert interface_speed_bps(IF_SPEED_SENTINEL, 10_000_000) == 1e10  # kbit/s quirk, 10G port
    assert interface_speed_bps(1_000_000_000, 1_000_000) == 1e9        # ifSpeed contradicts it
    assert interface_speed_bps(IF_SPEED_SENTINEL, None) == float(IF_SPEED_SENTINEL)
    assert interface_speed_bps(None, None) is None
    print("interface_speed_bps OK")

    ok, note = detect_reboot(100, 1010.0, 500_000, 1000.0)
    assert ok, "a real restart must be detected"
    ok, _ = detect_reboot(29_000, 300.0, 2**32 - 1000, 0.0)
    assert not ok, "a 497-day TimeTicks wrap is not a reboot"
    ok, _ = detect_reboot(130_000, 300.0, 100_000, 0.0)
    assert not ok, "uptime going forwards is not a reboot"
    print("detect_reboot OK")

    print("all self-tests passed")

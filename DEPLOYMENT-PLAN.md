# Tier 0/1/2 fix deployment plan

Source: `DEMO-EVALUATION.md` (branch `claude/network-monitoring-platform-demo-6qy9vd`),
the fleet-operator evaluation of 4.46.4. This plan deploys every Tier 0, Tier 1
and Tier 2 recommendation from its §7, on branch
`claude/tier-fixes-deployment-plan-ct1t6g`, targeting release **4.47.0**.

Work is grouped into waves by file-conflict cluster, so parallel implementation
agents never edit the same file in the same wave. Every wave lands with tests
(new suites are picked up automatically by `tests/run_all.py`), and each wave
is committed only after the affected suites pass.

## Wave 1 — independent small fixes (parallel)

**W1-A: all five Tier 0 items**
- T0-1 MAC table collection on by default (`nodesdb.py` `mac_table_interval_s`)
- T0-2 Prefix search: `syslogdb._fts_query()` honours a trailing `*`
- T0-3 MIB catalog size cap raised so every shipped catalog entry installs
- T0-4 Wireless tab labelled FortiGate (`web/static/index.html`)
- T0-5 `busy_timeout` (plus `cache_size`/`mmap_size`) set centrally in `dbopen`

**W1-D: Tier 0 addition (user-requested) — notification roll-up window**
- T0-6 A configurable hold on first notifications (`notify_rollup_delay_s`,
  default 240 s): alerts open immediately in the UI as today, but their
  first email waits out the window so the dependency rollup can suppress
  children before anything is sent; everything due in the same flush is
  coalesced into one digest email, which counts once against the hourly
  budget. Directly addresses the §3.3 race (377 child alerts, 1,355 emails
  at 1000 devices) and the §3.4 budget exhaustion.

**W1-B: Tier 2 performance pair**
- T2-1 Hoist the `Intl.Collator` in `app.js` sort
- T2-2 Batch ICMP in `ipam_scan.py` (ICMP datagram sockets where permitted,
  subprocess fallback preserved for the demo harness and locked-down hosts)

**W1-C: Tier 1 #9 — portable secret store**
- The passphrase design `CREDENTIAL-SECURITY.md` §"Why there is no portable
  secret store, yet" endorses: scrypt-derived key, encrypt-then-MAC from
  stdlib primitives, passphrase from environment or root-only file for
  unattended restarts, refusal behaviour unchanged when unconfigured.
  Documentation updated to state exactly what is and is not protected.

## Wave 2 — alerting cluster and polling backend (parallel)

**W2-A: alert operations** (`alertsdb.py`, `alertengine.py`, alert routes)
- T1-2 Maintenance windows: scheduled, recurring-capable mutes over device
  groups/sites, plus bulk mute; the 24 h ad-hoc cap stays for ad-hoc mutes
- T1-3 One outbound webhook notification channel (URL + headers + JSON body
  through the existing template engine), alongside email
- T2-3 Un-acknowledge
- T2-5 Trap database cap raised and documented against measured burst rates

**W2-B: polling backend** (`nodeoids.py`, `nodepoll.py`, `nodesdb.py` only —
API/UI surfacing deferred to Wave 4 to avoid file conflicts)
- T1-5 (backend half) LLDP/CDP neighbour walk, stored neighbour table
- T1-7 PoE (per-port power, budget) and STP (bridge/port state, topology
  change) polling
- T1-8 PtP wireless RF metrics (RSSI, SNR, modulation, capacity) for
  airFiber / Cambium personas

## Wave 3 — the API-heavy trio (single agent, owns `api.py`/`server.py`)

- T1-1 CSV export on every table, honouring the current filter
- T1-6 Server-side paging on the device list (and the alert list's
  truncation ceiling addressed the same way)
- T1-4 Bulk device import (CSV paste / bulk POST)

## Wave 4 — surfacing the Wave 2 backend (single agent)

- T1-5 (frontend half) L2 topology from stored LLDP/CDP neighbours
- PoE/STP/RF columns and panes on the device views
- T2-4 ConfigRX diff between adjacent backups

## Wave 5 — authentication (single agent, touches `auth.py`/`server.py`)

- T1-10 API tokens (service accounts with scoped grants, no idle timeout)
  and LDAP simple-bind directory authentication (stdlib implementation,
  local accounts unchanged and always available as fallback)

## Wave 6 — integration

- Full `tests/run_all.py` and `demo/selftest.py` green
- `CHANGELOG.md` entry, `FEATURES.md`/`RUNBOOK.md`/`CREDENTIAL-SECURITY.md`
  updates collected from all waves, version bump to 4.47.0

## Verification gates

1. No wave commits until its own suites and the previously-passing suites pass.
2. `demo/selftest.py` (623 wire-format checks) must stay green after Wave 2.
3. Final gate: everything in `tests/run_all.py` green at 4.47.0.

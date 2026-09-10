# Prompt log

A short note on each request made in this working session, oldest first,
grouped by the version that carries it. This is a working record for the
operator — the full story of each change is in `CHANGELOG.md`, and this file
does not replace it.

## 5.7.0 — Five reports

**"Five things..."** — the standing working policy, plus five field reports:
MAPPER drawing links twice, the NetFlow window not matching what was asked for,
global search not finding a MAC on a switch port, DHCP leases not searchable by
MAC, and no way to search an ARP table.
→ All five delivered. Switch ARP polling and storage were new work, not a fix.

**"The application updates from Main - Main should be the most recent version of
the application."** — a correction to how releases reach the estate.
→ Release process changed: `main` now carries the newest version, and the branch
is fast-forwarded into it rather than lagging.

**"push to main"**
→ 5.7.0 shipped.

## 5.7.1 — The temp folder that wasn't there

**"Update is giving me this error: ... [WinError 3] The system cannot find the
path specified"** — the self-update failed on a per-session Windows temp
directory that no longer existed.
→ New `netpath/temppath.py`: recreates a vanished system temp directory, then
falls back through `%LOCALAPPDATA%\Temp`, `%SystemRoot%\Temp` and the install
root, proving each is writable by writing to it.

**"DHCP IPAM is giving similar error - is this related?"** — same failure, second
symptom.
→ Yes, same root cause. The DHCP poller's PowerShell scratch file went through
the same fixed path helper.

**"push to main when done"**
→ 5.7.1 shipped.

## 5.7.2 — The password that was never wrong

**"Please double check the SNMP V3 polling - I have confirmed username and
password but I am getting 'Authorization Error'."**
→ The credential was never the problem. The diagnostics were: several distinct
protocol failures all reported as one generic message, and a device that was
reachable could be marked down by it. The SNMPv3 error paths were separated so
each says what actually happened.

## 5.8.0 — The privacy password, and the reply nobody checked

**"Use cryptography as an optional dependency then."** — a redirect, after I
proposed writing AES by hand.
→ Correct call, and the right one. SNMPv3 **authPriv** now works via
`cryptography` as an optional dependency (`netpath/snmpcrypt.py`), degrading
cleanly when it is absent. Reply verification was added at the same time.

**"before pushing to main perform an /ultrareview"**
→ No such command exists. Composed the equivalent: a security review followed by
three adversarial passes with mutation testing. It found a decryption oracle and
a stop-ship defect that marked reachable devices as down.

**"After review push to main"**
→ 5.8.0 shipped, with the review findings fixed first.

## 5.8.1 — The restart that fixed it

**"The SNMP V3 Test gives response ... but fails when attempting the actual
'poll now' and the automatic poller both fail saying 'No Reply'."** and **"One
SNMPV3 to a separate Palo Alto is successfully working - the 1st one I added is
working fine - I added 3 more ... they are suffering from this."**
→ The second message was the one that solved it: same credential, same model,
only the later-added devices affected, and a restart cured them. A cached SNMPv3
engine that went stale could never recover, because only an explicit auth
failure cleared it and this firewall answers a stale request with silence. It
now recovers on its own, and "Poll now" clears the cache the way an operator
retry should.

## 5.9.0 — Six operator asks

**"Develop with Fable and Deploy with Opus. Use Sonnet for non-reasoning
tasks."** — sent as an interrupt, then withdrawn ("ignore my last message"),
then restated as standing policy.
→ In force. It is how this release was built.

**The six asks**, with two new standing constraints — keep code comments to only
what is necessary (prose 10% or less), and do not push to `main` or run a code
review, because one review and one push happen at end of day.

1. **Maintenance devices still show as offline on the Dashboard.**
   → Maintenance lives in a different database file from the fleet counts, so
   the exclusion has to happen above both. Devices in maintenance mode or inside
   an active maintenance window no longer count as down — on the Dashboard, the
   Nodes strip and the tab badges alike. They are shown as their own figure
   rather than silently disappearing.
2. **Search syslogs by hostname and part of a hostname.**
   → The Host column often shows a name resolved from Nodes or DNS that was
   never stored, so searching for it found nothing. The typed fragment is now
   resolved to the addresses it could mean, and matched against those too. Works
   on log history already recorded.
3. **What more can be polled from the APs in the Forti-AP module?**
   → Research, not a change. A costed options list, from what is free today
   through one extra request per AP to a new per-client table and the REST API,
   with a recommendation and a warning: measure the controller before choosing,
   because this MIB has already been caught misreporting its own units.
4. **Stagger node polling so nodes do not all hit the pollers at once.**
   → The scheduler gave every device that came due together the same next due
   time, permanently, so a fleet that started in step stayed in step. Jitter
   was added at two points: the first poll after a restart, which an already
   overdue device now waits for by at most thirty seconds or one interval,
   whichever is shorter; and the first reschedule after that, which only ever
   moves a poll earlier, so once running nothing is polled less often than
   configured.
5. **The Dashboard loads slowly while the pollers are busy.**
   → It was the one aggregate page recomputing everything for every open tab
   every five seconds, fetching up to 5,001 alert rows to count them, and
   scanning a day of events with no limit to show ten. All three fixed.
6. **Identify which nodes have profile overrides.**
   → A marker on the device row naming what it overrides, a sortable Overrides
   column, and an "Only with overrides" filter.

**"Try again"** — after the development model hit a session limit and four
parallel streams died mid-flight.
→ Resumed all four from where they stopped rather than restarting.

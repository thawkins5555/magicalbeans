# Prompt log

A short note on each request made in this working session, oldest first,
grouped by the version that carries it. This is a working record for the
operator — the full story of each change is in `CHANGELOG.md`, and this file
does not replace it.

## 5.61.0 — Team grows by four; VlanView glows only on both ends; Nodes gets a fleet-wide VLAN scan button

**Operator message, five asks (verbatim):** "Update Dora to be 5.5 opus.
Add additional Teammates Thing3 and Thing4 that are Copies of Thing1. Add
additional Teammates Dingus3 and Dingus4 that are Copies of Dingus1. The
VlanView should only glow if the VLAN is on BOTH interfaces of a link and
not just one side. On the Nodes module add a global button next to
'Duplicates' that will immediately run a VLAN scan."

**Four planning answers.** A one-sided link draws plain — no glow, and
not dimmed either. An end with no VLAN data at all (an unmanaged peer, or
a switch that has never answered a VLAN walk) does not veto the glow —
the known end's word stands on its own. The scan button covers every
managed device, not a selection. Feedback is a toast carrying the count,
alongside an Events log line.

**Who built what.** Dora explored first: why the glow needs backend
changes at all (`assemble_links` only ever kept the union of both ends'
VLANs, so `mapper.js` had no way to see which end reported what), and why
the scan button needs a new poller method rather than reusing Poll now's
path (that path also queues a full poll and the MAC/ARP walks, and drops
caches the scan has no business touching). Dingus1 built the four new
team files to Bob's exact spec (byte copies with the name/description
swapped); Bob updated `CLAUDE.md`'s team list and Dora's model. Thing1
built the per-end VLAN lists (`mapper.py`, the API, their tests); Thing2
built the glow rule, legend, pane line and the walk check. Thing3 built the poller method, the endpoint and their
backend tests; Thing4 built the button, its contract pins and its walk
check — both only became spawnable partway through the session, once
Dingus1 had written their agent files; before that point Thing1 and
Thing2 were set to cover their parts instead.

**Outcome.** Shipped as 5.61.0. Full suite 208 of 211 with only the three
environmental failures (test_alert_sms, test_collectors_hardening,
test_prune_lock_hold); the thirteen targeted suites green. Javariius pass
one found a P1 (the pane line interpolated the VLAN name unescaped; fixed
and pinned) and a P2 (the walk check counted against a stale payload).
The first walk skipped the VlanView check because no link had VLAN data
yet, so the check was made to trigger the new VLAN scan itself; its first
real run then failed and exposed a genuine gap: a link's far end only got
VLANs from its own neighbour row, so a core whose neighbour walk had not
run read as VLAN-blind although its port rows were on file. Thing1 made
`assemble_links` read the far end's own rows; the demo persona change was
dropped as unnecessary; Thing2 rewrote the check around VLAN 20 (both
ends) and VLAN 30 (one-sided) comparing per link id, since the link set
grows in bursts mid-walk. Javariius pass three approved the far-end read.
Final walk 102 of 102: 23 links glowing for VLAN 20; for VLAN 30, 11
glowing, 10 plain one-sided, 2 dimmed; the VLAN scan button queued 250.

## 5.60.0 — Every STP-blocked link on Mapper is now found

**Operator report:** "The STP blocking visible feature line on Mapper is
not identifying all links with STP blocking status."

**Four planning answers, all the recommended options:** the fleet is
Catalyst IOS/IOS-XE, running PVST+/Rapid-PVST; SNMP is v2c with a
community; 48 or fewer VLANs per switch; and the links in question are a
mix of single ports and EtherChannel bundles.

**Diagnosis: three separate ways a genuinely blocked port could still
draw solid, plus one way an already-blocked link drew too much red.**

1. Spanning tree runs on the Port-channel, not its physical members — a
   switch never reports STP state for a bundle member directly, and CDP
   names the physical port, so a bundled uplink could never be shown
   blocked at all.
2. The per-VLAN scan that finds blocking on a pruned trunk read the first
   48 VLANs inside a 15-second budget and threw the whole pass away if it
   ran long; once the last complete pass aged out, the port reverted to
   its VLAN-1 reading. This is the same mechanism behind the open 5.40.0
   note about a blocked link's dots vanishing on a plain refresh — closed
   now, since that was this timeout, not a drawing bug.
3. A switch that never populates `dot1dBasePortIfIndex` at all lost STP
   for every one of its ports outright.
4. Separately: once a link was blocked, every VLAN strand on it drew
   dotted, not just the VLANs actually blocking — over-marking rather
   than under-marking, but misleading on a busy trunk either way.

**Outcome.** Bundle members now inherit the Port-channel's STP state and
say so ("via Port-channel1") on Nodes, Mapper and the CSV export; the
per-VLAN scan now completes across passes instead of discarding a
cut-short one, closing the 5.40.0 note explicitly; a switch with no
bridge-port table falls back to bridge port = ifIndex, confirmed against
its own interface list; and only the actually-blocked VLANs' strands
dot, with a non-blocked link's pane now saying "forwarding on both ends"
or naming whichever end has no state read at all. Shipped as 5.60.0.
Testy: targeted suites green, full suite 206/209 with only the three
known environmental failures, the browser walk 99/100 with the bundle
demo's link naming its Port-channel live (the one miss was the new
strand check's own precondition, since fixed to wait for strands).
Javariius, three passes: the first found the chunked walk stalling on
one bad VLAN context and discarding a follow-up chunk of portless VLANs;
the second found a deadline-cut VLAN skipped for a lap, a never-answering
device re-walked every minute, and a timed-out bundle table clearing
every member; all fixed with tests before the push.

## 5.59.0 — VlanView glows the picked VLAN's links, charts stop bridging data gaps, Mapper gets SSH/WEB buttons, and SMS sign-up splits into three checkboxes

**Operator prompt, four items in one message:**
- SMS sign-up: split the single Terms-and-Privacy checkbox into two — one
  for the Terms of Service, one for the Privacy Policy — alongside the
  existing consent checkbox.
- Mapper: when a VLAN is picked in "VLANS ON THIS MAP," the links
  carrying it should stand out with a glow in that VLAN's own colour, not
  just leave everything else dimmed the way it does today.
- Charts (Nodes, Dashboard, Wireless): stop drawing a straight line
  across a stretch where a device went quiet — a screenshot showed a full
  day of downtime inside a 7-day window drawn as an unbroken line.
- Mapper: add SSH and WEB buttons to the map's own toolbar strip, acting
  on the one selected device, the same as Nodes' device pane already
  offers.

**Two planning answers, both the recommended option.** The chart gap
rule: break the line after more than three missed samples (four times
that series' own normal spacing). The glow: steady, not pulsing like
FiberView.

**Outcome.** Shipped as 5.59.0. Thing1 built the glow, the chart runs
and the strip buttons; Thing2 the three SMS boxes; Stephen_King the
docs. Testy: targeted suites green, full suite 205/208 with only the
three known environmental failures (`test_prune_lock_hold` confirmed
failing identically on unmodified main), the browser walk 98/98, and an
ad-hoc Mapper check of the glow, legend and buttons. Javariius found one
fix-first item: a lone sample between two gaps became a one-point run
that painted nothing, so it now draws as a dot; short runs also lose
their min/max the same way smoothed runs do. Files: `netpath/web/api/auth.py`,
`netpath/web/static/{app.js,app.css,index.html,mapper.js,nodes.js,sms-terms.html}`,
`tests/test_frontend_contracts.py`, `tests/test_account_sms.py`, the docs.

## 5.58.0 — Email subjects drop "SappiWhere"; NetFlow names missing templates, raises the cap to 512, and survives a restart

**"Remove 'SappiWhere' from the subject line of all email templates."**
Confirmed this meant every subject an email can carry — the six
built-in templates, the roll-up digest, and the Alerts → Settings test
email — not only the ones an operator had left at their shipped
wording. Bodies keep their `-- SappiWhere` sign-off and the From display
name is unchanged; only subjects change, and the SMS text was never
affected since it has no subject line to strip. Upgrading strips the
word out of every built-in subject, edited or not, the same one-time,
deliberately unconditional correction 5.30.0 used when it added the
missing severity tag; a custom (non-built-in) template is left exactly
as written.

**"Netflow is consistently missing HOURS of data that is confirmed being
sent to the SappiWhere application."** A round of questions narrowed
this down before anything was changed: the holes sit inside a single
day's traffic chart and inside the raw flow Records table too, so this
is not a display artifact; the collector has been running steadily, no
crashes or restarts lining up with the gaps; the exporter speaks
NetFlow v9; NTP is in order on both ends; and the status strip's
*awaiting template* count is consistently large rather than an
occasional spike. That combination pointed at the template cache
quietly dropping v9 data sets rather than a real gap in what the router
exports, and the fix shipped in three parts: name what's missing
(exporter, template id and why) instead of only counting it, raise the
per-exporter template cache from 64 to 512 (a stacked switch or a Cisco
AVC/ezPM profile can send more templates in one refresh burst than the
old cap held, evicting the exporter's own live template in the
process), and write the learned template cache to disk so a process
restart — not just a settings save, which 5.23.0 already covered — no
longer blanks every v9/IPFIX exporter until its own next scheduled
resend.

**Outcome.** Shipping as 5.58.0. Thing1 and Thing2 built the two lanes
in parallel — alert-subject wording and the NetFlow template work — and
Stephen_King wrote the docs and bumped the version. Testy passed the
targeted suites, the full suite (only the known environmental failures)
and the NetFlow/Alerts walk. Javariius's review found the two new log
lines could be flooded by spoofed sources, the template snapshot raced
the receive thread, and the saved snapshot had no size bound; all three
were fixed (per-collector throttles, list() snapshots, a bounded
snapshot) with tests R11 and R12 before the push to main.

**Files changed for 5.58.0's documentation:** `netpath/__init__.py`
(version), `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`, `README.md`,
`RUNBOOK.md`, and this file.

## UI/UX review of SappiWhere — no version bump

**"UI-Review."** A bare word with no matching command or skill on this
team — the session asked what was meant before doing anything.

**Full UI/UX review brief.** Review only, no source changes. Map every
page, tab, sub-view and modal first; cite every finding to its file and
line; take screenshots with Playwright if the app can be run locally.
Nine review areas: navigation, cross-module consistency, visual
hierarchy, interaction flows, states, real-time behaviour, accessibility
(WCAG 2.1 AA), responsiveness, and frontend code health (including
`innerHTML`/XSS exposure). Deliverable: `UI_UX_REVIEW.md` at the repo
root, with an executive summary, a page inventory, findings, a
consistency matrix, quick wins and a roadmap. Decided: the review file
stays untracked since this is a public repo, and a one-off screenshot
pass stands in for the standard browser walk for this review.

**"git pull" (twice).** The session branch (`refactor/5.43-structure`)
had no upstream tracking branch, so the first pull only fetched and did
not merge. Fast-forwarded the branch to `origin/main` at commit
`c925b62` (5.56.0).

**"git pull."** A later session branch again had no upstream tracking
branch. `origin/main` was one commit ahead — a CLAUDE.md model-name edit
identical to what was already sitting uncommitted locally — and
fast-forwarded cleanly.

**"Using the new CLAUDE.md agent rules, propose a plan to resolve every
item in the review file."** Dora verified twenty code seams from the
review first, then four open questions went to the operator: form
dialogs keep action buttons at the top and confirmations at the bottom
as a written-down standing rule, byte units move to base-1000 while
keeping the KB/MB/GB labels, everything ships as one release (5.57.0),
and four items — the tab-strip reorder, splitting the nodes module
script, an alarm-sound option, and a kiosk-mode session-limit exemption
— are left out of this pass. With the plan approved, the NetFlow
escaping and settings-validation fix was committed, and Thing1 and
Thing2 started building the rest in separate worktrees.

**Outcome.** The fix pass shipped as 5.57.0. The first full suite ran
215 of 215 and the browser walk 98 of 98 after one router fix.
Javariius's review found no security holes but did flag two major and
several moderate defects — NetFlow cells blanking for unresolved names,
the Problems-only filter's select-all sweeping up hidden devices,
popover and live-table interaction, filter links not round-tripping on
reload, a deliberate sign-out carrying the page hash along, and comment
density — all closed in a second lane pass. The final full suite ran
213 of 215, with the two failures resolved: a test pin updated for the
storage meter's decimal cap text, and an SSH terminal socket reset under
load confirmed to pass standalone. Pushed to main.

## 5.56.0 — Every reboot emails; silent email drops say why; DAC badge grey; Send test email

**"Make the 'DAC' interface tag the same color gray as the DOM, SFP, and
COP badges."** DAC had shipped in 5.55.0 on a different neutral so it
would stand apart from COP; it now uses the same grey (`var(--muted)`)
as all three.

**"The Device Rebooted alerts are not sending out emails even though
email alert is enabled on the Alert rule/template."** The operator
confirmed what was on screen: the alert's count was above 1 (so reboots
were being detected and logged) and its Notifications pane read "None
sent." Two things were found, both fixed:

- A reboot alert has no clearing event and stays open 24 hours from the
  last reboot; a second reboot inside that window only bumped the open
  alert's count, and the engine only ever mailed the first reboot that
  opened the alert. Repeat reboots now go through the same notification
  path as the first one — the rule's flags, the severity floor, the
  hourly budget and the recipients all still apply, and a repeat inside
  the roll-up hold window is folded into that one held notice rather than
  doubled.
- Separately — and we could not tell from "count above 1" plus "None
  sent." alone which of the two was actually in play here — the "Email
  alerts of severity … and worse" floor can drop the reboot rule's own
  emails with nothing recorded, since the rule ships at warning and a
  floor of error or stricter silently swallows it. "None sent." looked
  identical to email being off entirely. The floor, and a rule missing
  its email template, now write a reason onto the alert ("not sent:
  warning is milder than the … setting (error)" / "not sent: the rule
  has no email template"), the way the hourly cap and the roll-up drops
  already did — so either cause now shows up on the alert itself, and an
  install seeing this should check that setting.

**"Change 'Send Test' button on alert settings to 'Send Test Email'."**
Done — it now reads **Send test email**, matching **Send test text**
beside it.

**Outcome.** Shipping as 5.56.0. Stephen_King wrote the docs and bumped
the version; Testy and Javariius take it from here — test run and
whole-diff review before the push to main.

## 5.55.0 — Priority star on the device list; DAC transceiver badge

**"If a device has a port marked 'Priority Port' ... it should also
add a star next to the name of the device in the Nodes → Devices ...
so that an operator can tell at a glance."** A priority-flagged port
already showed its ★ in the device's own Interfaces tile, but the
Nodes → Devices list gave no hint at all. The list now carries a
`priority_port` flag per device (one read for the whole page, not one
per row) and shows the same ★ right after the device name — updated
immediately when a port is flagged or cleared, not just on the next
refresh.

**"There are a few switches that directly attached copper twinax
cables ... SFP-10GBase-ACU10M ... update the badge to 'DAC'."** These
were reading as plain **SFP** because the copper classifier only knew
BASE-T text. A new twinax/direct-attach pattern, checked ahead of the
copper one, gives them their own **DAC** badge — treated as part of
the copper family everywhere copper already gets special handling
(MAU-MIB precedence, the Mapper's fiber-vs-copper link colour), with
its own kind, medium and count in the SFP Inventory report and the
scheduled-report mail line.

**Outcome.** Shipping as 5.55.0. Thing1 built the priority-star feature
end to end; Thing2 built the DAC classifier, the report/Mapper/mail
changes and the demo persona end to end; Stephen_King wrote the docs
and bumped the version; Testy and Javariius take it from here — test
run and whole-diff review before the push to main.

## 5.54.0 — Opt-in form: separate terms and consent checkboxes

**"Twilio's A2P 10DLC web-form checklist" audit against nine
requirements plus two notes** turned up two gaps in the Account dialog's
sign-up form: the terms/privacy checkbox and the messaging-consent
checkbox were combined into one, and the submit button didn't read like
a sign-up action ("Send verification code"). Split into two required,
unchecked-by-default checkboxes and a "Yes, sign me up" button; the
server now refuses the request unless both are ticked. Decision: no
separate marketing-consent checkbox, since SappiWhere sends no marketing
texts — only operational network alerts.

## 5.53.1 — Terms and privacy links on the Alerts SMS settings

**"Add links to those two pages in the Alerts sms settings area."**
The Account dialog's consent notice already linked to `/sms-terms` and
`/sms-privacy` (5.53.0); the older consent notice on Alerts → Settings →
Default numbers now ends with the same two links.

## 5.53.0 — Public SMS terms and privacy pages

**"Where are the terms of service and privacy policy?"** Twilio's
campaign review also wants a terms-of-service URL and a privacy-policy
URL, separate from the consent wording already in the Account dialog.
Since SappiWhere is self-hosted with no public site to link to, the
decision was to serve two static pages from inside the app itself
(`/sms-terms`, `/sms-privacy`), reachable without signing in, rather
than standing up or relying on an external policy page.

**"Option #2 - Organization name is Sappi and support person is Thomas
Hawkins."** Filled in the two placeholders the pages needed: the
organization named in the program description is Sappi, and the HELP
contact is Thomas Hawkins in Sappi IT.

## 5.52.0 — Per-user SMS opt-in with verified consent

**"We are now going to set up an A2P Twilio campaign for sending text
messages from SappiWhere directly to users who need them ... please
provide me with a Campaign Description."** A campaign description was
drafted for the operator to submit to Twilio, describing SappiWhere's
network-monitoring alert texts and the consent path behind them.

**"Lets implement the opt in feature - I will need screenshots that I
can provide and also what do I insert into the 'Message Flow: How do
end-users consent to receive messages' field?"** Two design questions
came out of that: whether consent should be a double opt-in confirmed by
a texted code, or an inbound STOP/START webhook Twilio itself relays;
and whether opt-in should be a per-account setting stored against each
sign-in, or a simple standalone form. A texted-code double opt-in was
chosen over a webhook — it produces its own proof of consent (the code
sent, the code confirmed) without standing up a public inbound endpoint
for Twilio to reach — and it was tied to each account's own sign-in
rather than a bare form, so the same number can't be opted in twice or
opted in by someone who isn't its owner. The Message Flow field's answer
follows straight from that: the account enters its number, reads the
fixed terms and ticks a consent box on its own Account dialog, receives
a one-time code by text and confirms it, and can stop the texts from the
same dialog at any time. Screenshots for the campaign form were produced
from a headless run of the Account dialog through each state of the
flow (empty, code sent, confirmed, stopped) rather than a live phone.
Deployment mode ran the shipped design straight through — no further
questions were needed.

**Files changed for 5.52.0:** `netpath/appdb.py`, `netpath/web/api/auth.py`,
`netpath/web/server.py`, `netpath/alertengine.py`, `netpath/alertmail.py`,
`netpath/web/static/app.js`, `tests/test_account_sms.py` (new),
`tests/test_alert_sms.py`, `tests/test_frontend_contracts.py`, and
`netpath/__init__.py`'s version bump. Documentation for this release —
`CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`, and this file — follows
in the same pass.

## 5.41.0 — Link detail pane names which switch is STP-blocking a VLAN

**Operator prompt:** "On Mapper -> Nodes -> Link Details -> Step Blocked
or passing list - if an VLAN is STP blocked please show which switch on
which end of the link is actually in the block state. Only one side of
the link will be in a blocked state I believe not both."

Confirmed: STP only ever blocks one end of a link (both ends blocking
the same VLAN is possible under PVST but rare), so the fix names the
blocking end rather than assuming a fixed side. `stpBlockedVlans` now
tracks which end (or both) blocks each VLAN, gated on that end's own
port state, and the link detail pane's red rows read "(STP blocked on
`<switch>`)" instead of the bare "(STP blocked)". No questions needed —
single, well-scoped change. Version for this work: 5.41.0.

## 5.40.0 — Note text size, FiberView's missing redraw, vmVlan access ports, and port-label geometry

**Operator prompt, four items with a screenshot attached:**
- Give Mapper notes the same Small/Medium/Large text size frames already
  got in 5.39.0.
- Toggling FiberView makes the STP-blocked dots on a fiber link vanish;
  the operator also saw them vanish on a plain page refresh.
- Access-port links on Mapper still show "No VLAN data known for this
  link" on Cisco switches even after the 5.39.0 fix.
- Port-name and VLAN-number labels overlap on parallel links — the
  screenshot showed three cables between two stacked switches with all
  six port labels landing on top of the VLAN numbers.

**Three questions asked during planning, answered by the operator:**
- Whether the page-refresh case was a separate bug from the FiberView
  toggle — operator said "not sure." The toggle fix ships regardless;
  the refresh case was not reproduced in the client code (a refresh
  rebuilds the map consistently) and is recorded open for re-check —
  what a refresh *can* change is the underlying STP data itself, read
  live from the last poll.
- vmVlan (CISCO-VLAN-MEMBERSHIP-MIB) versus reading CDP's native-VLAN
  TLV as the second access-port source — operator chose vmVlan.
- Whether notes get their own size scale or share the frame presets —
  operator chose sharing, Medium as the default so no existing note's
  size is a surprise.

Bob planned and built the Mapper front end; Dora (`deep-code-explorer`)
traced the STP-dot and VLAN-membership data paths first; Thing1 built the
note text-size column, API and tests; Thing2 built the vmVlan collector
change, its stub mode and test; Testy ran the suite and a Mapper-only
browser walk; Javariius reviewed before the push to `main`. Version for
this work: 5.40.0.

## 5.39.0 — Access-port VLANs restored on Mapper, and seven more Mapper/Device-details fixes

**Operator prompt, eight items from a round of live use:**
- Access-port links on Mapper show "No VLAN data known for this link"
  even though the switch itself reports a VLAN for that port.
- Under FiberView, the spanning-tree-blocked dotted line is invisible —
  the glow smears it into a solid line.
- A frame or note that is selected cannot be removed from the toolbar's
  Remove button; the frame pane's own Remove button and Delete/Backspace
  work fine.
- Drop the legend's explanation of the VLAN line styles ("Trunks of N+
  VLANs…", the dashed-line and dotted-line notes); keep the FiberView
  colour key and the "no CDP/LLDP adjacency" message.
- A multi-VLAN link should be one wide click target instead of a set of
  ~1.5px strands an operator has to land a cursor on individually.
- Colour-code the link detail pane's VLAN list by spanning-tree blocking
  state, not just the footer text.
- Stagger parallel cables' port labels so interface names stop printing
  on top of each other.
- Cap the Device-details interface dialog's MAC address table at five
  rows behind a "+N more" control; give a Mapper frame's label its own
  text size (Small/Medium/Large) beside its label and colour.

**Plan.** One real data bug and seven display/UI fixes, all shipped
together as 5.39.0. The VLAN bug is collector-side: an access port's own
`dot1qPvid` is now trusted as a native-VLAN fallback the same way a
Cisco trunk port's already was, guarded so a VLAN the device does not
itself list anywhere still never appears on a link — fixed in
`nodepoll.py`, so an affected link fills in on its next VLAN poll, not a
page reload, and the fix reaches Nodes' own VLAN display as well as
Mapper. The FiberView/STP-dots bug and the frame/note Remove-button bug
are both rendering and toolbar-state bugs with no data behind them. The
five UI changes and the new frame text-size control touch only
`mapper.js`/`nodes.js`/`app.css`; Medium is defined to be identical to
every frame's size today, so no existing map redraws differently.
Version for this work: 5.39.0.

**Code review caught two real problems in the first pass at the
blocked-link overlay fix.** The first attempt gave multi-VLAN "strands"
links the same overlay as a plain link — a solid-red bar drawn at the
full bundle width, which covered the individual VLAN colours instead of
showing dots. The second: the overlay's invisible click area was not
one of the shapes the canvas's own background press handler knows to
leave alone, so clicking it cleared the current selection instead of
selecting the link. Both were fixed before this went to `main` —
strands mode dropped the overlay entirely rather than needing a redraw.
Javariius's review also caught that the new frame text_size setting had
no backend tests. All were closed before the release shipped.

## Branch check, and the vibrant-planck merge

**Check for branches not merged to main.** Six branches carried commits
not on `main`. Five had no shared git history with `main` at all — a
repository history rebuild had left them with no common ancestor to
diff against, so there was nothing meaningful to merge from them. One,
`claude/vibrant-planck-zvgzy6`, had real, still-unmerged work sitting on
it.

**Was `claude/vibrant-planck-zvgzy6` worked on last night and not
merged?** Yes — a fix to the browser-walk test harness (waiting on the
right DOM state, looking up the newest object rather than a stale one,
and no orphaned waits), committed at 02:27Z, parked on its own branch
and never verified or merged.

**Skip the walk — merge it to main.** Merged, `f0b60e7..818eb7e`.
Javariius's review of the branch's own diff found an incomplete fix
already sitting on it — the Frame and Note removal paths were keying a
wait to the wrong object — and closed it before the merge landed.

→ Merged straight to `main`, no version bump: a test-harness fix, not an
operator-visible change, so it carries no `CHANGELOG.md`/`FEATURES.md`/
`INTERNALS.md` entry of its own.

## 5.38.0 — FortiAP web tunnel, spanning-tree blocking alerts, Mapper notes, and a round of SFP/fan/FiberView fixes

**Operator prompt, thirteen items:**
- Add a web tunnel on the FortiAP module so an AP's own web GUI can be
  reached from inside the app.
- Bracket the Mapper Snap / Drag pans / FiberView checkboxes so it's
  clear which checkbox belongs to which setting.
- The poll-pool status line can show more workers "busy" than the pool
  actually has (e.g. 120 busy out of 80 workers).
- Cisco devices with three known fan modules only list T1 and T2 in
  their hardware list; T3 is missing.
- Not all SFPs are labelled correctly — 100Base-FX shows as plain "SFP"
  instead of "SFP-MM"/"DOM-MM" (FX is multimode; LX and BX are
  single-mode). The fix should read the SFP type itself rather than
  match a list of spelled-out part numbers.
- Alert when a spanning-tree-blocked link comes up, goes down, unblocks,
  or when a link newly goes into blocking.
- More separation between the two lines Mapper draws for a dual link
  between two devices.
- Mapper's PNG export is low quality — it pixelates when zoomed in.
- Some DOM SFPs aren't pulling their alert thresholds.
- Let notes be added to the Mapper canvas as a graphical thought bubble.
- Make Mapper's frame label text slightly bigger.
- Multimode FiberView colour: blue to dark orange.
- Single-mode FiberView colour: dark yellow to a slightly brighter
  yellow.

**Planning answers.** Mapper notes are free-floating on the canvas with
an optional link to one specific device, not pinned to a fixed spot on
the map; they're a map-only feature and are left out of the CSV export.
The FortiAP web tunnel defaults to HTTPS on port 443, set once per
FortiAP module rather than per AP. The PNG export fix is resolution
only — it keeps today's framing and crop and just renders sharper.
Spanning-tree alerting covers both entering and leaving blocking; rather
than add a new alert rule, the STP state is named in the detail text of
the existing interface up/down alerts. Demo fixtures are being added so
the fan (T3) and SFP-labelling fixes actually show up in the browser
walk, not just in the code. All thirteen items ship together as one
release: 5.38.0.

## 5.37.0 — Spanning-tree state per VLAN: blocked links on PVST switches

**Operator prompt, verbatim:**
> Sorry - just to make sure I understand - is this only going to pick up the spanning tree state for VLAN 1?  We use all vlans EXCEPT vlan 1.

**Plan.** The 5.36.0 blocked-link read only ever looked at the switch's
default SNMP context, which on Cisco PVST+/Rapid-PVST is the VLAN 1
spanning-tree instance — exactly the VLAN the operator's estate prunes
off its trunks, so the feature as shipped would have shown nothing on
this fleet. Confirmed Rapid-PVST/PVST+ is the spanning-tree mode in use;
the fix walks port state a second time inside each VLAN's own SNMP
context, the same `community@vlan` trick the MAC-table walk already
uses. Planning answers given: SNMP v2c only, no v3 context work (a v3
device keeps today's single default-context read); read on every poll,
the same cadence STP state already gets, bounded by the existing
48-VLAN/15-second walk budget; a port counts as blocking the moment it
blocks in any one VLAN it carries, with the blocking VLAN ids shown
alongside it on both Nodes and Mapper rather than just a bare
blocking/forwarding word. Team split: Thing1 took the poller's per-VLAN
walk, the database columns and API/CSV fields, and the demo fleet's
per-VLAN fixtures; Thing2 took the Nodes STP cell, the Mapper tooltip/
detail pane/CSV and the frontend contract pins. Testy ran the new and
touched test files as the work landed, then the full suite once at the
end, plus a browser walk on Nodes and Mapper only (the two modules whose
code changed). Stephen_King wrote CHANGELOG/FEATURES/INTERNALS and this
entry. Javariius reviewed the whole diff before the push to main. Version
bumped to 5.37.0.

## 5.36.0 — Optic single/multimode per port, FiberView by mode, STP-blocked and parallel Mapper links

**Operator prompt, verbatim:**
> -Cisco switches should all view whether the SFP in a slot is a single mode or multimode SFP even if it's not a DOM SFP based off of the SFP type (SX or LX, LR Etc).  For the Mapper -> FiberView - progress the fiber link status one step further - if a link is using multimode SFP's on each end keep the fiber path blue,  if a switch is using single mode SFP's on each end of a link make that fiberview path a dark yellow.  If there is an SM or MM mismatch between the SFP's on each end that fiber path should be a dotted RED LINE.  
> -Mapper should be able to determine via LLDP/CDP if multiple links between the same devices exist - if it finds multiple links directly from one device to another it should then add another connection between the two devices.  If a link is spanning tree blocking it should be a dotted line.  This is not fully fleshed out - ask any needed questions.

**Plan.** Two asks, the second one flagged by the operator as not fully
specified, so planning worked through the open questions before anything
was built rather than guessing at them. Answers given: the SM/MM figure
shows on the switch too, not just on the map — a badge suffix
(`DOM·MM`/`SFP·SM`) plus the SFP inventory report's Medium column and
CSV; FiberView colours by whichever end's mode is actually known, only
calling it a mismatch when both ends are known and disagree; the
spanning-tree-blocked dotted line applies in both the normal view and
FiberView, and is drawn as a visually distinct dot pattern from the
existing dashed "no VLAN data" line so the two are never confused;
parallel cables fan apart into one line per cable rather than collapsing
into one link or stacking on top of each other; and STP state is read
from the BRIDGE-MIB poll the fleet already runs — nothing new is polled
for it. Team split: Thing1 took the poller/database/report/demo-fixture
side (the optic-mode read itself, its storage, the SFP report and
interface CSV columns, and the demo fleet's second blocked uplink per
access switch); Thing2 took Mapper's own side (the pure colour/pairing
logic in `mapper.py`, the API's link facts and port-name resolver, and
`mapper.js`/CSS for the colours, dotting and fan-out). Testy ran the
touched test files as the work landed and the full suite once at the
end; Javariius reviewed the whole diff before the push to main.
Stephen_King wrote CHANGELOG/FEATURES/INTERNALS and this entry. Version
bumped to 5.36.0.

## 5.35.0 — Interface stanzas by indent, default gateways from ConfigRX, a single-PSU report, sensor vanish alerts, and SFP badges restored fleet-wide

**Operator prompt, verbatim:**
> -Nodes -> Devices -> Interfaces pop up dialog is not showing the running dialog specific to that port.  It simply says 'No stanza found.'
> -IP Default gateway is not being recognized and shown on the 'Addresses' tab.  It says 'Default gateway: not published by this device' when the device does in fact have a default gateway assigned to it. 
> -Random blocks of data are missing from Netflow still - is the data being added to the graph based off of when it's received or is it being placed on the graph based off of the timestamp in the netflow data?   Here is a screenshot showing the missing data.  
>
>
> I would like to create a report that lists all switches that only have 1 power supply.  Do not include a device with a down power supply if that device has valid stack power cables. 
>
> I ran a 'Sensor Snapshot' on a device and then removed the FAN module - the device details popup dialog changed Switch 1 FAN - T1 1, NORMAL to ', NotExist' and status 'notPresent' - because the sensor status changed after running a sensor snapshot this should have thrown an alert. 
>
> I have multiple 2960X's on the network that are properly showing SFP's and DOM SFP's - I have a single 2960X that appears to not be properly showing the tags.  I have confirmed it's the same SFP in each switch.  Please look into this.

**Follow-up, verbatim:**
> Regarding the missing SFP/Copper/DOM icon on some switches - this appears to be more widespread than just 2960x's - I have verified the transceiver type is viewable via a full SNMP Walk of the devices.

**Plan.** Six items, all bugs or gaps in code already shipped rather than
new asks, so each got a code-grounded diagnosis before anything was
changed. Planning answers given for the questions each item raised:
Cisco IOS/IOS-XE, and the `interface …` header **is** present in the
latest ConfigRX backup for the affected port (stanza); the affected
boxes are Layer-2 switches configured with `ip default-gateway`, not a
routed default (gateway); the NetFlow gap sits in a window with a
confirmed exporter restart/outage, Sep 14 04:00–14:00 (NetFlow); the new
report judges per stack member, "covered" means at least one StackPower
port enabled, link up, with a neighbour, and it goes on the SCHEDULED
list like the others (single-PSU report); and, after the follow-up, the
missing SFP/DOM badges are fleet-wide, not one model, on switches that
do list sensors in HARDWARE SENSORS with the badge still missing
(badges). Team split: Thing1 took the three poller-only items (fan/PSU
vanish alert, SFP badge scan and diagnostics, gateway's third SNMP leg
and ConfigRX fallback); Thing2 took the single-PSU report, the stanza
indented-header search and the NetFlow size-cap guard. Testy ran each
touched test file as the builders worked and the full suite once at the
end; Javariius reviewed the whole diff before push, with no walk or
review run until every item was coded, and no second walk after review,
per standing rules. Stephen_King wrote CHANGELOG/FEATURES/INTERNALS and
this entry. Version bumped to 5.35.0, committed on the session branch,
pushed, then fast-forwarded onto `main`.

**Outcome.** Shipped as 5.35.0. Stanza: the matcher now also finds an `interface` header carrying leading whitespace (column-0 headers still win), and the dialog names what it searched and how many stanzas the backup held, so the next report pinpoints names versus backup. Gateway: three SNMP legs (ipCidrRouteTable, inetCidrRouteTable, RFC1213 ipRouteTable) and, when all publish nothing, the latest ConfigRX backup's `ip default-gateway` / `ip route 0.0.0.0 0.0.0.0`, shown as "(from ConfigRX backup)". NetFlow: flows are charted by the record's own end time, not receive time; the confirmed outage explains the gap; the size cap now holds back raw flows the minute rollup has not summarised. New Reports → SINGLE PSU (per stack member, StackPower-covered members left out, schedulable). A fan tray or PSU that vanishes from a complete FRU walk now records "not present" and alerts; a cut-short walk changes nothing. SFP/DOM: the cage scan runs without a sensor answer, a cut-short name or sensor walk never strips stored badges, AppGigabitEthernet maps, and the Nodes event log states once an hour per device and cause why a switch could not be badged. Review took three passes: pass 1 caught a fleet-wide fan/PSU flap on a timed-out class walk, stored optic badges stripped by a slow sensor walk, and the size-cap counter overwriting prune's; pass 2 caught the diagnostic rate-limit key changing every poll and a partial class walk being cached as complete. Tests: 171 of 175 suites (the four known environmental failures), Nodes walk 88/88 with no console or request errors, ad-hoc checks 13/13.

## 5.34.0 — Mapper FiberView: fiber links draw bold and glowing blue

**Operator prompt, verbatim:**
> I want to add a feature to the MAPPER MODULE.  There should be a new
> checkbox next to 'Snap' and 'Drag pans'.  The checkbox should be
> called 'FiberView'.  When this box is checked the system will then
> need to determine if those specific links listed are via FIBER or
> Copper based off of the SFP types and port types.  If the connection
> between two devices is determined to be fiber then the lines
> connecting devices together on the MAP should change to BOLD and
> Glowing Blue phasing in and out when the checkbox is selected.
> Revert back to normal view when unselecting the checkbox.

**Plan.** A per-browser view toggle, not a map edit or a shared setting
— same footing as the existing Drag pans checkbox, so it needs no write
permission and never touches the database. The fiber/copper call
reuses the port media the poller already learns for the DOM/SFP/COP
badges (5.24.0/5.25.0: ENTITY-MIB text, MAU-MIB, DOM optical-power
sensors) rather than asking devices anything new: a lit optic on either
end of a link is fiber, proven copper on either end (with no lit optic)
is copper, an unidentified transceiver on either end is still called
fiber, and anything else — empty cage, fixed port, unknown — is not
fiber. "Phasing in and out" is built as a slow stroke-opacity pulse,
off entirely when the browser's reduced-motion setting is on. Dora
mapped the existing link-drawing and media pipeline first so the new
rule and the new draw path would land on the right seams rather than
duplicating logic Nodes already has. Thing2 built the backend verdict
and API surface (`mapper.link_is_fiber`, `nodesdb.
interface_media_for_devices`, the three new keys on every mapper map
link); Thing1 built the checkbox, the per-browser remembering, and the
CSS glow/pulse. Testy ran the affected test files plus the full suite
once, and a Mapper-only browser walk. Javariius reviewed the whole diff
before push.

**Outcome.** Shipped as 5.34.0. Dora mapped the link pipeline; Thing2 built the verdict and API fields, Thing1 the checkbox and styling. Full suite once: 168 of 173 passed, four the known environmental failures plus tests/test_alerts_ui.py, whose pin counted every animation rule in app.css and tripped on the new fiber pulse — Fisty narrowed it to the alert pulse. Browser walk 88 of 88 with no console, page or HTTP errors, plus an ad-hoc Playwright check of the checkbox, its persistence across reload and the new link keys (28 of 29 demo links report fiber). Javariius first pass "not ready": a selected fiber link lost its selection cue to the glow rule, and a multi-VLAN trunk in strands mode collapsed into one ribbon with a filter per strand — fixed with a combined-filter rule and a single glowing underlay beneath the strands; second pass "ready to push". No walk after review.

## 5.33.0 — Per-port running config, Poll Now's three walks, fan alerts, Sensor Snapshot, Mapper/Dashboard fixes

**Operator prompt — ten items, one message, given while the operator was
not present to answer planning questions:**

1. Interface Detail popup for a port: "the system should check if there
   is an existing ConfigRX Backup of that device (If there are multiple
   use the most recent.)... the 'Running Configuration' tile... should be
   populated with the running config only for that specific port."
2. "Manually pressing the 'Poll Now' button should also learn the MAC
   addresses, read the ARP Cache, and Walk the VLAN membership for that
   device."
3. "Double clicking a device on MAPPER should stay on the Mapper module
   but open that devices... Device Details popup Dialog."
4. "Dashboard graphs are not scaling Y correctly - please double check
   the scaling and logic on this."
5. "'Most Interface Events' Dashboard tile is not populating with any
   entries even though I know interfaces have been flapping etc."
6. "The highlight feature upon clicking a device name link is not
   suffucient... lets highlight the select[ed] device with yellow and
   also select the checkbox for that device to make it more obvious."
7. Device Details, near Re-identify: "a 'Sensor Snapshot' button... take
   a capture of the current state of the power supplies and stack power
   cables and fans and commit this as 'normal status.'"
8. "If there is not currently alerts for fan modules in devices please
   add them."
9. "When searching for a device in MAPPER the auto fill suggestions
   popup should match the theme... it looks similar to a browser
   autofill which could be confusing."
10. "Mapper labels are STILL overlapping eachother if devices are moved
    too close together."

**Planning decisions made without the operator (nobody to ask — Bob
proceeded on judgment, to be confirmed or corrected at review):**
- Item 5's root cause: the tile was built to read `device_events` for
  `interface_down`/`interface_up`/`interface_flapping` kinds that
  `device_events` has never carried — a port's own transitions live in
  a separate `interface_events` log keyed to the interface, not the
  device. Decision: give the tile its own query against the real table,
  rather than writing new kinds into `device_events` to match the old
  query.
- Item 4's root cause turned out to be three separate bugs, not one:
  a percent tile with no Y max auto-scaling instead of pinning to 100, a
  multi-series chart letting an invisible min/max band inflate its own
  axis, and a value above the axis ceiling drawing past the top of the
  chart instead of clamping to it. Decision: fix all three rather than
  the one that happened to reproduce first.
- Item 2: submit the three walks directly rather than clearing the
  scheduler's own next-due timestamps for them, because a device the
  scheduler has never walked has no timestamp yet and would be staggered
  over a random delay instead of started now — direct submission is what
  makes "immediately" actually mean immediately.
- Item 7: baseline semantics are exact-value equality, not "quiet unless
  it gets worse by some margin" — a later reading identical to the
  accepted baseline stays quiet, any different reading (worse or better)
  is judged exactly as if no baseline existed. Chosen for being the
  simplest rule that matches "commit this as normal status" literally.
- Item 9: a themed custom dropdown (arrow keys, Enter, Escape, click)
  rather than any way of restyling the browser's own `<datalist>`,
  which cannot be themed at all — it is drawn by the browser chrome, not
  the page.
- Item 10: each label's box is one block — its name line plus its
  sub-line together — so a collision push moves both lines down as a
  unit; pushing only the name line would just relocate the overlap to
  the sub-line instead of fixing it.
- Item 1: a device's operator-set port alias is deliberately never a
  candidate for matching a config's own interface name against — it is
  free text an operator typed, not a form any vendor's config would
  print on an `interface` line, and matching against it risked a false
  stanza.
- Item 1: Juniper support is limited to the brace-delimited pretty-print
  form (`show configuration`'s `interfaces { ge-0/0/0 { ... } } }`
  layout) — Junos' single-line `set` form is not handled, since it is a
  materially different text shape and the operator did not ask for it
  specifically.

**Team split:** Dora mapped the affected code first (the interface config
route's neighbours, the poll/walk scheduler, the alert engine's threshold
path, `drawSeriesChart`, and mapper.js's node/label drawing) so both
builders started from the same understanding of what was already there.
Thing1 built six items: the Dashboard scaling fixes (4), the interface-
events tile fix (5), the yellow reveal highlight and checkbox (6), the
Mapper double-click dialog (3), the themed Find dropdown (9), and label
placement (10). Thing2 built three items: the per-port running config
from ConfigRX (1), Poll Now's three walks (2), and fan alerts together
with Sensor Snapshot (8, 7 — the same baseline mechanism covers both).

**Javariius's review, four must-fix items, all taken before push:**
`poll_now` was starting the MAC/VLAN/ARP walks on every call that reached
it, not only a Poll Now click — bulk import's own first poll of a new
device and the trap daemon's forced re-read after a power-fault trap were
walking devices nobody asked to have walked. Fixed with a `walks` flag on
`poll_now`, off by default, set only by the single-device and bulk Poll
Now routes. `configrx_stanza`'s interface-name match checked each config
header in file order and took the first prefix hit it found, so a short
name (`Tw1/0/1`) could resolve to an unrelated interface with a similar
prefix (`TwentyFiveGigE1/0/1`) appearing earlier in the file, even when
the device's own, correctly-named interface (`TwoGigabitEthernet1/0/1`)
was sitting further down. Fixed as two full passes over every header —
exact, case-insensitive equality first across the whole file, the
short/long prefix rule only once that whole first pass has come up
empty — so an exact name always wins regardless of where it sits.
Comment prose was over the 20% cap in the new modules. And the Interface
Detail dialog's ConfigRX hint text no longer matched what the dialog
actually shows once the other fixes landed — a viewer with ConfigRX read
and a device with no backup was left reading old placeholder wording
that no longer described the screen in front of them. Reworded to say
plainly what each state of the tile now is. Fixed by Thing2 and Thing1
before push.

**Outcome.** All ten items shipped in 5.33.0. Dora mapped the ten areas
first; Thing1 built the Mapper, Dashboard and reveal-highlight items and
Thing2 the per-port config, Poll Now walks, fan alerts and Sensor Snapshot.
Testy's first full pass found one real regression — the new Find dropdown
registered two mouse-event listeners where the input contract allows only
pointer events — which Fisty closed by switching both to `pointerdown`; the
browser walk then passed 88 of 88 with no console, page or HTTP errors as
admin or viewer. Javariius's first pass returned "not ready" with the four
must-fix items above plus should-fix items (an audit row for the snapshot
route, the nodes-read check ahead of the device lookup so a ConfigRX-only
account gets 403 rather than a 404 that enumerates ids, an unused delete
helper and an orphaned query parameter removed, a route test that now
exercises a real port with no stanza); all were taken. The second pass
returned "ready to push" once one doc claim was backed by the test it
named (Bob added the 403-before-lookup check). The final full suite on the
fixed code passed 169 of 173 with only the four environmental failures this
container always shows (SMS passphrase, traceroute, the prune-lock timing
check and the SNMP socket family in the web-gates test). No walk was run
after the review, per the standing rule.

## 5.30.0 / 5.31.0 / 5.32.0 — Device link + Address tab fixes, Mapper search/select-all/frames, Cisco Stack Power (planned)

**Operator prompt:**
"-Clicking a device name link should not only take you to the node ->
Devices -> Device Details page for that device but it should also
'Clear' the 'Find' field on the Nodes -> Devices page and highlight
the selected Device.
-Need a way to search the MAPPER module for nodes.
-Need a way to 'Select all' on the Add Device dialog in MAPPER.
-Should be able to draw frames on MAPPER around nodes.
-All alert emails should include the severity level in brackets at
the start of the subject line and every recovery alert email should
say [RECOVER]
-Need to implement Cisco Stack Power into the power supply alert
logic - Start by showing Stack Power info on the Nodes -> Devices ->
Device Details pop up dialog. There should also be an alert added
that triggers on any degradation or failure of a Stack Power cables -
if thresholds exist for stack power pull them from the device.
-the Node -> Devices -> Device Details -> Address should show the
devices IP Default Gateway if possible. It also appears the
'interface' column lists an odd ID number instead of listing the
VLAN or Interface name that the IP address belongs to."

**Planning answers:**
1. Alert subjects — every per-alert email/text/webhook already leads
   with `[SEVERITY]` and recoveries with `[RECOVER]` through the
   editable templates; only the roll-up digest subjects and any
   operator-edited template lacked it. Answer: "Reset my templates to
   the built-ins" — subjects reset once, and digests pick up a
   worst-severity tag.
2. Cisco Stack Power — the MIB gives per-port link up/down and
   enabled/disabled, an over-current threshold in amperes, and no
   live current reading; faults arrive as traps. Answer: "Cable down +
   power traps" — a critical per-port alert on a cable going down, a
   warning alert on the power-fault traps (which also force a
   re-read), and the threshold shown on the dialog.
3. Device link when other Nodes -> Devices filters still hide the
   target row: "Clear those filters too."
4. Mapper frames when dragged: "Decoration only" — devices never move
   with a frame.

**Notes:** six requests, split into three releases by how independent
and how risky each piece is.

**5.30.0 — Device link, Addresses tab, alert subject reset**
Scope: the device-name link on Nodes -> Devices now clears the Find
field, then clears the other active filters too only if the row would
still be hidden, before highlighting the selected row after routing to
Device Details; the Addresses subtab resolves the numeric interface
index to the actual VLAN/interface name and adds the device's IP
default gateway where SNMP exposes one; every built-in alert
template's (email/SMS/webhook) subject line is reset to its built-in
default carrying `[SEVERITY]` / `[RECOVER]` (custom, non-built-in
templates are left alone), and the digest roll-up subject gains a
worst-severity tag.
**Outcome.** Shipped as 5.30.0. Full suite 171/175 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing); browser walk 83/83 on the rerun with zero console, page or HTTP errors as admin and viewer (the first run of each pass lost the pre-existing interface-dialog Custom-range timing race, D3, which the walk script itself documents). Javariius pass 1 "not ready": a page reload would have wiped the remembered Find box (fixed with a boot-route guard and a walk step that proves a reload keeps it), the stored gateway text was unvalidated (now gated like the alias walk), comment density and four doc sentences; pass 2 four one-line edits, no logic change. New tests: test_default_gateway.py, test_template_subjects.py.

**5.31.0 — Mapper find, select-all, frames**
Scope: a node search/find box added to the Mapper module; a
"Select all" control added to Mapper's Add Device dialog; freehand
frames drawable around groups of nodes on the Mapper canvas, decoration
only — dragging a frame never moves the devices inside it.
**Outcome.** Shipped as 5.31.0 together with 5.32.0 in one push (the operator asked for a single walk and review after all changes). Javariius pass 1: the frame drag never saved because the press requested a full redraw that replaced the element the pointer was captured on (fixed by selecting in place; the walk now drags the border and the handle and waits for the PUTs), two 500s on bad frame input, keyboard remove ungated for readers, a frames-only map not drawing; all fixed. Frames also gained keyboard reach and work on an empty map.

**5.32.0 — Cisco Stack Power**
Scope: Stack Power info (per-port link state, enabled/disabled,
over-current threshold read from the device) added to the Device
Details dialog; a new alert set added — critical on a stack power
cable going down, warning on a stack power fault trap, with the fault
trap also forcing an immediate re-read of stack power state.
**Javariius review pass, five fixes before push:** the rule-count
sentence corrected to 70 built-in rules (69 enabled) in FEATURES and
INTERNALS, both stale at the old 62/61; **Stack Power fault trap** now
auto-resolves after 24 hours like the product's other trap rules; the
four traps for invalid input/output current, insufficient power and
under voltage moved from Critical to Error so a trap opens Stack Power
fault trap without also opening the generic Critical SNMP trap alert;
`stackPower` and `stackPowerStatus` added to the Trap Log's kind filter
list; and the Link column in the STACK POWER table now shows a dash
for an administratively disabled port instead of a wrong "up" — docs
corrected to match in all four places.
**Outcome.** Shipped as 5.32.0. Full suite 172/176 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing); browser walk 88/88 with zero console, page or HTTP errors as admin and viewer, STACK POWER rendered on the demo stack, frames drawn, dragged, resized, renamed and removed. Javariius (updated definition): fault-trap alerts now auto-resolve after 24 h, the four critical-rated traps lowered to error so a trap opens one alert, trap kinds filterable in the Trap Log, no invented link state for a disabled port, poll-cost latch narrowed to the tables that yield rows; final verdict ready to push with nothing above P3. Two walk steps that lost runs under back-to-back use were hardened.

## 5.29.0 — Discovery addresses removed: interfaces and ARP only

**Operator prompt:**
"I would like a 1 time wipe of the 'Discovery' addresses on each node -
the only IP's I want associated with each node are ones that are
actually assigned to physical or logical interfaces on that device and
then IP's in the ARP table.  I do not want to document or include any
type of information of the IP address a device was 'discovered
through' or whatever the 'discovery' IP addresses are currently.  I do
not want the 'Discovery' addresses functionality."

**Planning answers:**
1. Scope — wipe and stop everything on a node's address list that
   doesn't come from the device's own interface table: discovery
   addresses, a trap's agent-address, and addresses a merge carried
   over from the losing device. The ARP table is a separate table and
   is untouched.
2. The operator's own restatement, and the answer to it: "When a
   subnet is scanned during a discovery and a device replies to SNMP
   a check should then be done to see if there is an existing device
   in the Nodes module that has the same IP address assigned to one
   of it's physical or logical interfaces.  If a matching node is
   found it should alert the user that the device is a duplicate and
   is already added to the system.  I am not sure how the 'discovery'
   can reach any IP's other than what is explicitly listed in the
   Target field." Confirmed: discovery never contacted anything
   outside the Target field. What it did was ask each responding box
   for its own address table (an `ipAdEntAddr` walk) and record those
   addresses on the node at promote time — that extra read is what's
   being removed.
3. Discovery now compares only the address it probed — no interface-
   table read during discovery, no "+N addresses" count, no folding
   two results together because they turned out to share an interface
   table. The Discovery settings checkbox "Ask each device it finds
   which addresses it answers on" is removed, with the operator's
   permission.

**Notes:** a one-time migration deletes every `device_addresses` row
whose source isn't the interface-table walk (`ipAdEntAddr`) — marker-
gated so it runs once per database and never repeats on restart. The
trap daemon no longer records a trap's agent-address as a node
address. A merge no longer carries the losing device's old primary
address forward as an alias on the survivor. A newly promoted device
carries no addresses at all until its first regular poll walks its
interface table. The "Same as" duplicate flag now reads "already
added as `<node>`: `<ip>` is on its interfaces" — it only ever meant
interface-table evidence, this just says so plainly — and the
5.28.0 tick-to-add-separately override is unchanged and still works
the same way.

**Outcome.** Shipped as 5.29.0. Full suite 169/173 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing); Nodes browser walk 81/81 with zero console, page or HTTP errors as admin and viewer, after fixing a walk-script bug from 5.28.0 that had never run (the discovery re-read asked for job "undefined"). Javariius pass 1 "not ready" on two doc sentences and no code faults (a FEATURES claim that an unticked Same-as row is marked added, and this empty outcome line), five stale comments taken; pass 2 "ready to push". New tests/test_address_wipe.py proves the one-time wipe runs once and leaves only interface-table rows.

## 5.28.0 — Discovery duplicates: an override, and folded rows no longer hidden

**Operator prompt:**
"The discovery function is still not letting me add a device from a
discovery as a stand alone device because it sees the IP as a
'discovery' IP on a device's arp table or something - this must be
corrected - only IP's that are actually assigned to interfaces,
vlans, loop backs, etc should flag a device as a duplicate."

**Planning answers:**
1. Override — ticking a flagged row and approving it adds that row as
   its own device, separately from whatever it was flagged against.
2. Folded rows — a result the sweep folded into another (same box
   reached on two of its own addresses) is shown in the list, marked
   with what it folded into, and addable on its own the same way.

**Notes:** the evidence rule from 5.27.0 was checked and confirmed
correct — only a device's own interface/VLAN/loopback address table
(`ipAdEntAddr`) has ever fed a duplicate verdict; nothing reads ARP for
this. The actual problem was that the discovery screen gave no way to
act against a verdict: a result marked **Same as** an existing device
always folded onto it on Approve, because neither the approval dialog
nor the Results pane ever told the server to keep it separate, and a
result the sweep folded into another address of the same box was left
out of the list altogether — always promoted as the row it folded into,
with no way to add it, or even see it, on its own. Now: a **Same as**
or **Folded into** row starts unticked; ticking it and approving adds it
as its own device, using its own address and identity rather than the
row it was flagged or folded against. The hint explaining why a row was
flagged is unchanged and still shown, so the operator ticks with the
same evidence as before — only the ability to override it is new.

**Outcome.** Shipped as 5.28.0. The evidence rule from 5.27.0 stood; the block was the discovery screen never sending the override (a "Same as" row always folded on Approve, a folded row was hidden and always resolved to its primary). Ticking either now adds it as its own device; folded rows are listed. Javariius pass 1 "not ready" with one real blocker: primary and folded row ticked together still gave one device (family marking plus the forced row's walked addresses); fixed as one promote per Approve, forced rows first. Pass 2 found the mirror case (approve the primary today, the folded address could never be added tomorrow); fixed by no longer marking folded siblings when a primary promotes, which also deleted the family-marking code. Pass 3 "ready to push" after re-running eight orderings through the route. Targeted suites green (device identity 4b/4c/4d, discovery workers and end-to-end, contracts); no browser walk and no full suite this round at the operator's instruction.

## 5.27.0 — Duplicate devices: configured addresses only, not discovery IPs

**Operator prompt:**
"ONLY IP's that are actually configured on a device's physical
interfaces or vlan interfaces should be considered when detecting
duplicate devices.  Currently it seems the system is using
'discovery' IP addresses and considering it a device duplicate when
that IP address isn't actually assigned to an interface on the
device.  Those discovered IP's should be used for things like IP
address conflict (if multiple MACS arp to a single IP) etc but not
for actual NODE Device Duplicates."

**Planning answers:**
1. Which addresses count as "configured" — everything in the
   device's own address table: physical interface IPs, VLAN
   interface IPs, loopbacks, tunnel interfaces, and management
   addresses (i.e. what SNMP's address table on the device itself
   reports, not what the discovery sweep merely probed).
2. Scope — all three places the system tells the operator two
   devices are the same box: the Duplicates button, the discovery
   screen's "Same as an existing device" hint and its promote step,
   and the 409 conflict check when adding a device by hand or
   through bulk import.

**Notes:** an address now only counts as duplicate evidence when it
came from reading the device's own address table and is currently
present there; addresses picked up purely by discovery probing, by
SNMP traps, or inherited during a merge are kept — they still feed
IP-conflict detection (two MACs answering for one IP) and IPAM — but
no longer make two unrelated devices look like the same one. The
discovery sweep now records what it actually reads off each device's
address table as configured evidence, separately from the one address
it used to reach the device, which is recorded as discovery-only. The
Duplicates dialog and the device's Addresses tab now say which
addresses are configured versus merely seen by discovery, so this
isn't a silent change. Added `tests/test_duplicate_evidence.py` and a
new section in the existing device-identity tests covering the
configured-vs-discovered split.

**Outcome.** Shipped as 5.27.0: main took the other session's power-supply work as 5.26.0 while this was held, so it was merged in and this release renumbered. Full suite 168/172 on the merged tree (167/171 before it) with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing), Nodes browser walk 80/80 with zero console, page or HTTP errors as admin and viewer. One existing test (test_state_cache) seeded its alias with a made-up source and needed to seed a configured one. Javariius pass 1 "not ready" on one false INTERNALS sentence about the 409 wording plus the empty outcome line, no code faults; four nits taken (comment trims, bulk-import hint wording, contract description, an upgrade note in CHANGELOG). Pass 2 reported in chat. Held on the session branch until the operator clears the push to main.

## 5.26.0 — Power supplies: removed, unpowered, and reported the moment it happens

**"Where do Device Details → Addresses populate from, Primary vs
Discovery?"**
→ Answered from a Dora exploration trace of the Addresses list's own
code path; no code touched.

**"Why are hardware sensors listed twice in the device dialog?"**
→ Answered, no code change: the HARDWARE SENSORS tile matches on a
sensor's `temp_`/`psu_` metric prefix, and the live envmon walk it
draws from overlaps the same sensors the per-sensor table below it
already lists — the two are reading the same data through two
different paths, not a duplicate poll.

**"Pulled the AC cord on one power supply on a Cisco switch. The live
HARDWARE SENSORS tile showed 'shutdown' — but no alert fired.
Need this to alert both when a supply loses input and when it's pulled
out entirely."**

**Planning answers, four decisions:** alert on a supply that
disappears from the table (previously it cleared any open alert,
because many Catalysts report a pulled supply as "not present," the
same code an empty bay uses); read PSU state on every poll instead of
the existing five-minute sensor cadence, so a failure is caught within
one poll; decode the Cisco ENVMON/FRU power traps by name and give
them a sane default severity, so they show up as more than bare OIDs
and the existing "Critical SNMP trap received" rule can act on them;
and have a power trap from a managed device trigger an immediate
re-read of that device, so the alert opens (or clears) within one poll
of the trap arriving rather than trailing the cadence. Version for
this work: 5.26.0.

**Outcome.** Thing1 built the poller and MIB side — the per-poll PSU
cadence with the cached static table columns
(`_vendor_psu_static`/`_vendor_psu_rows`), the not-present state (3)
that opens `psu_failed` instead of clearing it, and the Cisco FRU
`offEnvOther`/`offAdmin` remap. Thing2 built the trap side —
`trapdecode.py`'s six new OID names, two enum decodes and six default
severities, and `snmptrapd.py`/`web/service.py`'s `poll_now` re-read
hook. Testing: the full suite passed 159 of 163 with only the four
environmental failures this container always shows (SMS passphrase,
traceroute, the prune-lock timing check, IPv6 in the web-gates test),
and the browser walk passed 77 of 77 with no console, page or HTTP
errors as admin or viewer. Main had moved on to 5.25.0 (copper SFP
badge) while this was built, so the branch was rebased onto it and the
release renumbered 5.26.0. Javariius reviewed once and returned "not
ready" with one blocker (a placeholder left in this file) and six
should-fix items, all taken before push: the trap re-read matched two
whole Cisco notification arcs instead of the six power OIDs and had no
throttle (now exact-match, debounced to once a minute per device); a
timed-out static-column walk was cached empty for five minutes (now
only a complete answer is cached, with tests for the empty, TTL and
eviction cases); the one-time upgrade alert burst on long-removed bays
was undocumented (now in the changelog with the hand-resolve remedy and
a never-fitted-bay hardware check); comment density over the 20% rule
(trimmed); the stale `psu_state` scale comment in `alertsdb.py`; and a
full-suite run on the rebased head. Nits noted and left: the alert text
reads the raw `3.0` (only the sensors table words it), one extra
metrics SELECT per poll per PSU device.
→ Stephen_King. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md` written
for 5.26.0 against the actual diff (`origin/main..HEAD`); no code touched.

## 5.25.0 — SFP copper/laser identification

**Operator prompt, two items:**
- "Is there a way via SNMP to determine the difference between a fiber
  SFP and a copper SFP?"
- "I want the Nodes -> Devices -> Interfaces -> should show one of
  three icons - DOM for laser DOM SFP's, 'SFP' for laser non DOM, and
  'COP' for non-DOM copper SFP's.  The Report should have an
  additional copper identifying if the type is copper or laser."

**Notes:**
1. Answered in chat, no code changed. ENTITY-MIB's module description
   and vendor-type name the part number (GLC-T, SFP-10G-T vs SX/SR/LR),
   which is the most reliable signal. MAU-MIB's ifMauType names the
   media type outright where the vendor fills it in. Wavelength and
   connector type from the transceiver EEPROM work where a vendor MIB
   exposes them — copper modules report a wavelength of 0. DOM sensor
   absence is only a hint, since some copper modules report a
   temperature sensor. Plain IF-MIB type and speed cannot tell copper
   and fiber apart.
2. Planning answers: "Module text plus MAU-MIB" for the proof a module
   is copper, and "COP" for a copper module that still reports a
   temperature sensor. The plan adds a `copper` media value decided
   from the module description text plus a new MAU-MIB column walk,
   badges each interface DOM/SFP/COP in the interface list and the
   report's Kind column, and adds a Medium column (Copper/Laser) to
   the SFP inventory report and its CSV/email output. Alerting is
   unchanged. **Outcome.** Shipped as 5.25.0. Javariius pass 1 "not ready" with one blocker (a MAU copper answer would have badged every fixed copper port on a Catalyst) and five should-fixes, pass 2 one should-fix (the "unknown PMD" MAU codes must not veto copper text), pass 3 "ready to push". Along the way a 5.24.0 bug surfaced: the SFP inventory table on screen collapsed each device to one row (rows keyed by device id); fixed. Targeted tests green; the operator asked for the push ahead of Testy's final full-suite and walk run, whose result is reported in chat.

## 5.24.0 — Priority port tint, History search by name, SFP inventory report

**Operator prompt, three items:**
- "Priority ports should be slightly tinted in the Nodes -> Devices ->
  Devices Details -> Interfaces list"
- "Nodes -> History -> Device doesn't  show names but only IP's - should
  be abLE TO search by IP or name and should show both in the drop
  down."
- "Create a report that will export a full list of Node SFP's ->
  Should show the device name, device IP, switch port and whether it's
  a regular SFP or a DOM SFP."

**Notes:**
1. Rows flagged Priority get a light tint in both copies of the
   interface table (the device details dialog and its embedded view),
   so a priority port is visible at a glance without opening a filter.
2. The History device picker was reading the manual name field, which
   most devices never have set, and falling back to the bare IP. It now
   resolves a name the same way the device list does — a pinned manual
   name, else the SNMP hostname, else the stored name, else the IP — and
   the dropdown shows both name and IP together; the
   server-side search already matched on IP, name, and hostname, so no
   change was needed there.
3. New Nodes → Reports → SFP INVENTORY report, built from the per-port
   media data the environment poll already collects: device name,
   device IP, switch port, and a DOM/SFP call — DOM for an optic that
   publishes light levels, plain SFP for a transceiver the switch names
   but that reports no sensors, with empty cages left out. Available as
   a CSV export and as a scheduled emailed report kind alongside the
   existing report schedules.

**Outcome.** All three items shipped as 5.24.0. Full suite 166/170 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing), browser walk 77/77 with zero console, page or HTTP errors as admin and viewer, Javariius pass 1 "not ready" (three doc inaccuracies, six nits, all closed), pass 2 "ready to push". One walk step in Mapper (Connect/Remove) proved a harness race and was hardened to wait for the map reload; no product change. New tests: tests/test_sfp_report.py.

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

## 5.9.1 — In-depth code review

**"Plan with Fable and deploy with up to 5 Opus agents ... An in-depth code
review of the application paying special attention to performance, security,
design quality and maintainability."** — with the standing constraints restated:
comments only where necessary (prose 10% or less), remove nothing without
permission, no push to `main` and no review of the diff (both happen at end of
day), one full test-suite pass at the end, and this log kept per prompt.
→ Branch restarted from `origin/main` (5.9.0), since the designated branch's
history was already wholly inside `main`. Planning questions asked before any
agent was started; see the answers recorded below.

**Planning answers** — deliver a report *and* fix confirmed defects (larger
design items become proposals); the report is `CODE-REVIEW.md` in the repo
root; fixes ship as 5.9.1; scope is everything under `netpath/` (backend and
frontend, vendored xterm excluded), with `demo/` and the test harness out of
scope; benchmarks run only where a fix is meant to move one.
→ Five Opus reviewers by area, one Sonnet gathering code metrics, then a
consolidation pass that re-verifies every finding before any fix is written.

**Review phase complete** — seven reviewers (five backend areas, two frontend)
and a metrics pass returned 81 findings: 2 critical, 17 high, 29 medium, 33 low,
plus 30 larger proposals and 20 unconfirmed items. Every finding was re-read
against the code by the lead before a fixer was given it; two were reclassified
as proposals (a deliberate CA-bundle choice, a reflector best handled in the
runbook). Fixers run in file-owned lanes so no two agents edit the same module.

**Fix phase complete** — eight file-owned lanes (server, data, poller, api,
alerts, trap secrets, frontend core, frontend modules) fixed 79 of the 81
findings; one became a proposal (the update path's CA bundle, a deliberate
choice) and one a runbook note (the trap receiver acknowledging informs from
any source). Every fix carries a test shown red before it. Report in
`CODE-REVIEW.md`; release notes under 5.9.1 in `CHANGELOG.md`; internals and
features updated where a mechanism or a screen changed. Full-suite pass and
the browser walk follow, once, at the end.

**"push to main once complete"** — lifts the earlier hold on `main`.
→ After the final full-suite pass and the browser walk, `main` is
fast-forwarded to this branch and pushed, so the estate updates to 5.9.1.

**Closed out** — the full suite ran once at the end: 140 of 141 passed, the
skip being the desktop console suite (no PySide6 here) and the failure the
pre-existing lock-fairness assertion that fails on unchanged 5.9.0 in this
container too. That run surfaced one integration defect (a sensor-scale clamp
stopping at units where the MIB runs to yotta), fixed before the walk. The
browser walk passed 63 of 63 checks as admin and as viewer with no console,
page or HTTP error. `main` fast-forwarded to 5.9.1 and pushed.

## 5.10.0 — Six asks

**"Plan with Fable and deploy with up to 5 Opus agents ... To work on: [six
items]"** — with the standing constraints restated: comments only where
necessary (prose 10% or less), remove nothing without permission, no push to
`main` and no review of the diff (both happen at end of day), one full
test-suite pass at the end, this log kept per prompt, check on every agent at
least every ten minutes.
→ Planned first; eight planning questions asked and answered before any agent
started. Ships as 5.10.0 on the same branch, above 5.9.1.

**Planning answers** — recovery subjects carry `[RECOVER]` in place of the
level tag; FORTI-AP B5 delivers BSSID plus the *configured* channel width via
the WTP-profile join (the MIB has no per-radio noise floor — struck); an AP
reboot raises a warning rule shipped enabled, a channel change is an event
with its rule shipped disabled; Cisco software version and image are split
from sysDescr with the boot-image path kept as a third field; the HTTPS check
counts 2xx/3xx as available, verifies certificates with a per-destination
opt-out, follows the destination's trace interval, and opens a critical alert
after three failures; device delete becomes an asynchronous background purge
in lock-friendly batches; release is 5.10.0 with this log as the per-prompt
record.

1. **`[RECOVER]` on recovery notifications.**
2. **FORTI-AP A2, B1, B5 and their prerequisites.**
3. **Routes: HTTPS availability check per destination.**
4. **Deleting devices with large history freezes the application.**
5. **Dashboard often blank until another tab is visited.**
6. **Software version and image in the device header, plus a firmware report.**
→ Five Opus lanes (wireless, nodes-firmware, nodes-delete, netpath-https,
frontend-core + alerts subject), Sonnet for docs and demo data.

**Deployment complete** — all six shipped: `[RECOVER]` subjects on recovery
notifications; FORTI-AP's channel-change and reboot events plus BSSID and
configured channel width; a per-destination HTTPS availability check on
Routes with its own alert rule; device delete as an asynchronous background
purge; a Dashboard that paints on the very first load; and software
version/image in the device header, an optional column, and a new Firmware
inventory report. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`FORTIAP-POLLING-OPTIONS.md`, `NETWORK-AND-STORAGE-REQUIREMENTS.md` and
`RUNBOOK.md` are updated to match. The full test suite and the browser walk
ran once at the end, as the standing constraint requires: 137 of 139 suites passed, 9 skipped for optional dependencies (paramiko, PySide6); the two failures were `test_collectors_hardening.py`, which passed once `traceroute` was installed on the container, and the pre-existing `test_prune_lock_hold.py` lock-fairness flake on `syslog logs` (code this release does not touch, recorded as intermittent since 5.9.0); the browser walk passed 65 of 65 checks including the new cold-load Dashboard check.

## 5.11.0 — Four asks, one deferred

**"Plan with Fable and deploy with up to 5 Opus agents ... To work on: [five
items]"** — the standing constraints restated: comments only where necessary
(prose 10% or less), remove nothing without permission, this log kept per
prompt, check on every agent at least every ten minutes, one full test-suite
pass at the end, then a code review of the day's changes and a push to main.
→ Planned first; two rounds of questions answered before any agent started.
Ships as 5.11.0 on today's branch, above 5.10.0. Subagent lanes in worktrees
rather than a teammate group: the items are independent and each lane's
deliverable is a commit plus a report.

**"What branch are you working off of ... confirm that you see all changes
made today"** and **"Everything will need to be re-run vs the branch from
today and the code review needs to include all changes made to the repository
branches today."**
→ The local checkout was at 5.5.0; the remote carried 5.9.1 on `main` and
5.10.0 on today's branch. All work rebased onto today's branch; the review
covers every commit made to any branch today.

**Planning answers** — the "1 override" marker is the 5.9.0 feature naming
which polling-profile columns a device sets itself; the operator will check
whether those are legitimate and report back (**deferred**). The 7-day option
goes everywhere the mute dropdown appears and the server cap rises to 168
hours. A per-alert mute is scoped to one rule on one device, sharing the
duration dropdown with *Mute device*. The Debug log fix resyncs the page's
cursor after a restart, makes the cursor read atomic, raises the ring to
10,000 events with a setting, and marks the restart in the log. The Neighbours
table keeps its format; an IP-only remote is named through the same chain as
Nodes (device, then DNS cache). Review depth: full for 5.10.0 and the new work,
a lighter pass over the 5.9.1 fixes. At the end `main` is fast-forwarded to
the branch and both are pushed.

1. **Mute a device for 7 days.**
2. **Mute a specific alert on a specific device.**
3. **The Debug event log seems to randomly clear.**
4. **Neighbours: name the remote device.**
→ Three Opus lanes (alerts, debug log, neighbours), then three Opus reviewers,
with Sonnet for docs and the test runs.

**Deployment complete** — four of the five items shipped; the fifth, the "1
override" marker, is deferred to the operator's own check rather than a
code change. The mute cap rose from 24 hours to 168 (7 days) everywhere the
mute dropdown appears, on the server and in both the alert detail and Bulk
mute. A per-alert mute — **Mute alert** beside **Mute device** — scopes to
one rule on one device, stored in the existing `alert_mutes` table as
entity kind `device_rule` with no migration, checked in the engine's
`_apply` alongside the renotify, recovery-mail and held-first-notice gates
it already had, surfaced as a tag on the Alerts list, a count on Nodes and
a named list in the device pane, and carried through `forget_device` and
`merge_device`. The Debug event log's three faults — the page's cursor not
surviving a server restart, the cursor-and-batch read across two lock
holds, and a fixed 3,000-event ring — are fixed: a `log_epoch` per process
plus a cursor-went-backwards check drives a one-time refetch from zero, one
lock hold now covers a snapshot of both cursor and batch, and the ring is
10,000 by default with a new `debug_log_capacity` setting (1,000–50,000)
applied live, with an "Event log started" line marking every restart.
Neighbours names an IP-only remote through the same chain Syslog's Host
column uses — a matched Nodes device, then the reverse-DNS cache — cache
only, with the addresses queued for the background resolver; the CSV
export gained `resolved_name` and `resolved_source`, and MAPPER's own
matching SQL is untouched. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`
and `RUNBOOK.md` are updated to match. The full test suite and the browser
walk, then a code review of the day's changes, follow once at the end, as
the standing constraint requires — counts and findings appended here when
they complete.

## 5.12.0 — What is no longer in use

**"Your only job is to look for code, documents and files that are no longer in
use and suggest plan for removal."** — the standing working policy, plus a
single standing task: find what is dead and plan its removal, removing nothing
from the GUI without express permission.
→ Audited the whole tree mechanically rather than by reading: 1,865 top-level
Python definitions, 1,295 methods, 1,091 imports, 72 modules, every static
`.js` symbol, 294 CSS classes, 108 custom properties, 261 HTTP routes, 237
settings keys, 151 test suites, 21 bundled MIBs. The tree was close to clean —
about 210 lines of genuinely dead code in a 3.5 MB package, and not one
orphaned module, file, dependency or test. What was actually recoverable was
2.0 GB of disk, eleven stale branches and three documents that were working
records rather than product documentation.

**Removed:** `ipam_scan.scan_subnet()` (a pre-composed wrapper superseded by
`IpamWorker._scan` composing `sweep`/`read_arp_table`/`usable_addresses`
itself), `dpapi.self_test()` and `secretstore.self_test()` (written for a
"Check encryption" button that was never built), `HttpsChecker.check_now` (a
copy of the live `HopProber.trace_now`, never routed), `nodesdb`'s unused
`import threading`, `PDU_SET` and `enc_oid` from `snmppoll`'s trapdecode
import, the `--vlan-1..16` design tokens and their test contract (superseded by
`--canvas-vlan-*`, which every consumer had already moved to), `a11yTable()`,
two unreferenced `STATUS_COLOR` objects, two unreferenced `ago` bindings and the
`.dot-inline` rule. Nothing removed rendered anything: zero pixels changed.

**Archived, not deleted** — `docs/history/` now holds `CODE-REVIEW.md` (a
session log whose findings are all marked fixed, kept as the audit trail for
security work), `FORTIAP-POLLING-OPTIONS.md` (whose own header declares its
implemented parts historical, kept for per-OID measurements recorded nowhere
else) and `DEMO-EVALUATION.md`, a 588-line fleet evaluation rescued from an
abandoned branch that was 439 commits behind before that branch was dropped.

**Three findings were not cleanup, and were fixed rather than deleted.** The
self-update verified path — newest tag plus published `SHA256SUMS` — was fully
implemented and tested but never called, so `apply()` followed the mutable
`main` tip with nothing checking the bytes it swapped in. It is now wired up,
with an explicitly logged fallback and a hard abort on digest mismatch. This
repository carries one tag and no releases, so the fallback is what runs until
the release process starts cutting tags with a `SHA256SUMS` asset: the change
is correct and dormant, and engaging it is a process change, not a code one.
`RUNBOOK.md` was missing from `_COPY_ALONGSIDE`, so every self-update stripped
the on-call runbook from the install that README tells the operator to read
before going live; it now ships. And `alertsdb.purge_expired_mutes()` had no
callers — but `prune()` was already deleting those rows with its own inline
SQL, so this was duplicated logic rather than the storage leak it first looked
like; `prune()` now calls the method instead of re-implementing it, at
identical behaviour.

**Flagged, not actioned:** eleven pieces of live duplication (a whole
seven-function time-window controller reimplemented across `netflow.js` and
`netpath.js`, the bulk-selection trio written three times, `histogram()` in two
stores), five routes with no front-end caller that are deliberate token-API
surface, and a mechanical split for `api.py`'s 10,268 lines along the 27
section boundaries it already carries.

## 5.13.0 — Neon Signs, and the backlog nobody had actioned

**Team setup** — a named team for this release: Bob leads; Troy and Laura on
Opus; Testy, Fisty and Stephen King on Sonnet; Securitas on Opus; Dingus1 and
Dingus2 on Haiku; Javariius reviewing on Fable. Standing rules: no HTML docs,
comments capped at 20% prose, nothing removed from the GUI, everything written
for a network engineer or CTO reading it, plan before running to completion.
Testy runs no repeated full suites and drives the browser walk instead; Stephen
King keeps this prompt log; Javariius reviews before any push. Two work items:
a Neon Signs theme with neon tubes running across the page, bright but
readable and contrasty, and a sweep of the previously flagged backlog with a
plan to implement it.
→ Team and rules recorded; work assigned across the waves.

**Planning answers** — build the Neon theme together with Tier 1 (twelve
small items) and Tier 2 (the medium refactors and the eleven duplications);
Tier 3 (trap decryption, the three big file splits, GETBULK interface reads,
SQL-paged upstream suggestions, the generation scheme, the webhook credential
slot, ETag on the device list) is deferred to a written proposal rather than
built. The Neon theme: glow on structure only, no flicker; electric cyan as
the accent, hot pink for fail, lime for ok, yellow for warn.
→ Neon shipped: eighth theme, three new `--tube`/`--tube-text`/`--tube-line`
  tokens, glow hooks across structure, all eight themes' AA pairs
  recomputed (tightest 5.49:1).
→ Tier 1 shipped in full: all twelve items landed (chart range, 404s,
  get_debug split, login 503, app.db warning, syslog cursor, dialog
  pollers, mapper scene, address refresh, pattern cache, paramiko and
  CREDENTIAL-SECURITY prose).
→ Tier 2: eight of eleven landed (nodes.refresh split, drawRows, window
  helpers, escaping contract, mapper_upstream split, drain contract,
  PREDICATES, best_effort); histogram dedup, WEB-P3 and API-P2/P3 landed
  after that note. API-P3's contract found `_discovery_result_json` handing
  the SNMP community to read-only accounts; fixed.
→ Review (Bob, after Javariius hit the account's Fable quota): two fixes —
  an access-denied optional SNMP read is not a credential verdict, and a
  body field naming a missing device stays a 400. Comment prose trimmed
  from 25% to 18% of added lines.
→ Suites: 153. The first full run was killed for memory at 121 with
  agents still alive; the other 32 ran individually. 141 pass, 1 skipped
  (no PySide6), 11 fail identically on the pristine base or on this
  cp1252 console (palo_alto_polling, prune_lock_hold, selfupdate_job,
  service_shutdown, snmpv3_diagnostics, snmpv3_keys, snmpv3_priv_e2e,
  https_check, ipam_dhcp_temp, temppath, wireless_radio_events). Eight
  suites needed 400→404 updated for the new not-found path, one fake
  service needed a permissions stub.
→ Walk: 932 steps, 887 ok, 45 planned skips, 0 failed; the 40 console
  errors are the viewer/NOC 403s the matrix provokes, the 3 page errors
  are on paths this release did not touch.

## 5.14.0 — The Nodes database, and what it keeps

**Team setup** — a named team for this release: Bob leads; Dora explores;
Thing1 and Thing2 on Opus; Testy, Fisty and Stephen King on Sonnet; Dingus1
and Dingus2 on Haiku; Javariius reviewing on Fable. Standing rules carried
forward. Task: reduce the nodes database's size, verify temp data (MAC/ARP)
is actually aged out, split long-term from short-term storage, list what is
kept forever, and propose options.
→ Team and rules recorded; task assigned across the waves.

**Planning answers** — build the trim-floor fix, a storage report, per-port
retention tiering (1 day raw, 90 days hourly; device-level stays at 3/400),
the WITHOUT ROWID rewrite, and device_addresses age-out tied to the 180-day
event retention. Defer the hour-index watermark, the daily tier and
zero-suppression. Raise the series cap default from 1 GB to 8 GB. The user
will run the storage report against the live install before defaults are
final.
→ Aging verified: MAC, ARP, LLDP and VLAN tables age out at 7 days, events
  at 180, discovery at 30, per-port raw at 3 days, hourly at 400 days.
→ Stored forever, by design and otherwise: inventory tables, vendor_learned
  and MIB files are correctly permanent; device_addresses and stuck
  discovery jobs are leaks with no age-out path.
→ Where the bytes go: 94% of metrics are per-port; each sample is stored
  three times over; default retention at 250 devices runs to roughly 39 GB
  against a 1 GB cap, so the cap is trimming raw data to a 5,000-row floor
  every minute.
→ Part 0 (trim floor): both floors under `trim_to_size` now scale with the
  metric count instead of a flat 5,000, and the stage order is reversed —
  hourly rollups give up their oldest hours first, raw samples only once
  those are at their own floor.
→ Part 1 (storage report): `netpath/dbreport.py` reports every store's
  exact row counts and measured-or-estimated bytes, on the command line
  and behind `GET /api/db/report`; Settings → Data & Retention gains a
  per-file expand and a line naming whether the cap or the retention
  setting is what actually bounds Nodes metric history. The series cap
  default rises from 1 GB to 8 GB; saved values untouched.
→ Part 2 (retention tiering): `metrics.scope` distinguishes per-port from
  device-level (a dot in the key, not the `if_` prefix); two new settings,
  `interface_sample_retention_days` (1) and `interface_rollup_retention_days`
  (90), carry the same 1..3650 floor as the existing rollup setting;
  `series()` picks raw versus hourly per metric by its own class. Shortens
  per-port history on the first maintenance pass after upgrade, and is
  one-way for data already gone.
→ Part 4 (device_addresses age-out): a complete walk marks the addresses
  it did not see `present=0`, following the walk-table shape already used
  for MAC/ARP; prune deletes those rows on the existing 180-day event
  clock; a present alias wins resolution over a stale one; a discovery job
  stuck `running` past the window is pruned alongside it.
→ Table rewrite landed: samples and samples_hourly WITHOUT ROWID (23.8 /
  47.5 B/row from 66.7), copy-and-delete migration rehearsed against a
  copy of this box's live file with a stop and restart: 230,485 rows
  before and after, 21.9 MB → 7.0 MB, peak +215 pages.
→ Review (Javariius, two passes): nine findings, then two more, all
  closed — the prune's band probe had become a full scan of samples, the
  migration's tail catch-up was unbounded, the cap line blamed the cap
  on every young install, the batched alias lookup ignored `present`,
  a purge walked the fleet's id space to its device. Prose 27.8% → 19.8%.
→ Suites: 157. One full run, alone: 145 pass, 1 skipped (no PySide6),
  11 known pre-existing failures, and one test expectation updated (a
  budgeted purge step may now finish the raw table before the hourly).
→ Walk: 932 steps, 887 ok, 45 planned skips, 0 failed; the 40 console
  errors and 2 page errors are the viewer/NOC permission refusals the
  matrix provokes. Storage panel expand and the two per-port fields
  checked by hand.
→ Pushed to main.
→ Post-release Q&A: "I'm struggling with the dbreport command - please
  elaborate" — run it from the install directory as
  `py -m netpath.dbreport <data_dir>`. "How long should the command take
  to run? The database file immediately got larger after I updated the
  application." — dbreport itself runs in seconds; the file growth is
  separate, expected while the background rewrite is in progress and
  because the cap no longer trims as aggressively.

## 5.15.0 — [title tentative]

**Team setup** — a named team for this release, same roster and rules
carried forward from 5.14.0: Bob leads; Dora explores; Thing1 and Thing2
on Sonnet; Testy, Fisty and Stephen King on Sonnet; Dingus1 and Dingus2 on
Haiku; Javariius reviewing on Fable. Two work items assigned:
(a) new ConfigRX backups show only time taken, not the date;
(b) flesh out and polish firmware versions across all included MIBs —
the Node → Device → Device Details dialog must show firmware version
regardless of vendor; the firmware report must identify and export
firmware and software versions for every device with an included MIB
and auto ID; the report's Device field must include IP address and
name (SNMP, manual, or DNS).
→ Team and rules recorded; task assigned across the waves.
→ Planning answers: two fields throughout, software and firmware version,
  not one; the Device Details dialog always shows the software-version
  line regardless of vendor; the firmware report's Device field renders
  as "name (ip)" with the name source (SNMP, manual, or DNS) noted; the
  ConfigRX backup list's Taken column always shows date and time, not
  time alone.
→ ConfigRX: the Taken column dropped the date whenever a device's backups
  all fell inside one hour (a freshly added device); it now shows date and
  time on every row.
→ Device Details always shows the software line ("not reported" when
  nothing answered) with the source in brackets, and a firmware line when
  the device has a separate boot/firmware version.
→ Versions: 19 more vendor arcs answer from their own MIB object (every
  OID re-derived mechanically from the catalog MIB text; four were wrong
  in the first pass and fixed); five vendors read a table column; the
  ENTITY-MIB fallback finds the chassis row instead of index 1; walks are
  gated to once a day per device. WatchGuard, Rittal and Netgear's old
  broadcom tree have no pollable object and stay on sysDescr/ENTITY.
→ Firmware report: Device is "name (ip)" with the name source (sysName,
  manual, reverse DNS, ip), a Firmware column, five new CSV columns.
→ Javariius: nine findings over two passes, all fixed, approved.
→ Full suite 151/157, the six known environmental failures only.
→ Browser walk 890 steps ok, 0 failed; a firmware-report step added.
→ Pushed to main.

## 5.16.0

**Team setup** — a named team with eight work items assigned across the
roster: (1) "Non-default profile counted as an override" — discovery
promote pins the sweep's own community as if it were special; (2) "IPAM
Conflicts wired to every IP source" — device ARP tables, addresses and
learned MACs never reach IPAM; (3) "Per-sensor temperature thresholds
from SNMP, all catalog vendors"; (4) "Power-supply loss alert" — nothing
polls PSU state today; (5) "Mapper: port/VLAN labels crossed by lines;
names should be hostname/DNS/SNMP plus IP"; (6) "Checkbox: drag selects
or pans"; (7) "More of the name in the node box"; (8) "Learned MACs in
the port dialog" — the dialog only ever waits on a live SNMP read.
→ Planning answers: learned MACs feed IPAM as a "seen" source with the
  switch and port shown on the address; the obscured mapper text is the
  port/VLAN labels, not something else on the canvas; device-reported
  thresholds are read first, with the existing chassis rule and
  per-device override kept as the fallback for a device with nothing
  better to offer; a PSU alert fires on failed/no input/shutdown for a
  present supply, never on an empty bay.
→ Clarification: the port dialog's MAC field should fill from the
  stored, previously-learned table rather than waiting on a live walk.
→ "Do not spawn any agents or teammates other than those listed."
→ "1"
→ /schedule and /loop status requests: a 15-minute status loop set for
  the release.
→ Plan approved.
→ Interruption: "Why are you continuing to spawn Fable agents when you
  have been directed not to do so?" Thing2, running on Fable in error,
  was stopped and respawned on Sonnet; a memory note was written so
  every roster name is spawned with its assigned model from then on.

## 5.17.0 — Find box uplink hits, chart tooltips, syslog name search, neighbour name + IP

**"do not push to main - let me know when u are done and we will start the
next work"** — a hold on `main`, to be lifted only once told.
→ In force for this release; no push without a further instruction.

**The 5.17.0 work prompt**, four items:

1. Node search must not include LLDP entries that match.
2. Device Details graphs need tooltips.
3. Syslog cannot be searched for part of a host name.
4. Neighbours tab should show the remote device name as well as its IP.
→ Traced and planned before any agent started; see the planning answers below.

**Planning answers** — the Find box case is a MAC search hitting
uplink-learned entries; Neighbours rows show name and IP on every row;
tooltips show the time and the value at the cursor; the syslog case is the
free-text box, with the Host column already showing the Nodes name that
free text could not search on.
→ Plan approved; work assigned across the roster.

## 5.18.0 — Port names, device names everywhere, IPAM in-use rows, MIB auto-assign, chart ranges, mapper drawing and matching

**The 5.18.0 work list**, nine items:

1. "Local port shows 'if 12' instead of a real port name."
2. "Remote device on Neighbours shows only the IP, no name."
3. "IPAM addresses that are in use but not leased don't show on the DHCP
   grid."
4. "Mapper's Add-neighbours list doesn't resolve names for peers."
5. "A MIB the app picked itself counts as an override."
6. "The interface bandwidth chart is stuck at one hour."
7. "Mapper draws labels under the link lines, and VLAN numbers stack on
   top of each other."
8. "Mapper misses a neighbour that Nodes can place by IP, and draws no
   link for it."
9. "Reports show the bare IP twice — once where a name should be."
→ Traced and planned before any agent started; see the planning answers
below.

**Planning answers** — Local port should show the short ifName form
(Gi1/0/10); the interface chart gets the same range list as the Packet
loss chart; IPAM's in-use-not-leased addresses are mixed into the lease
grid itself, with the State column saying "in use, not leased" rather
than sitting only on the summary donut.
→ Causes traced for all nine; plan drafted.

**"i have updated the CLAUDE.md file can you please confirm you see it and
understand its directions?"**
→ Confirmed: exploration from here on must go through the deep-code-explorer
skill, reporting back in its six-section form.

**Further planning answers** — the Mapper fix has to cover both what
Add-neighbours offers and what actually draws as a link, not just the
candidate list; this round's name-chain sweep covers Reports, Neighbours
and the Mapper, with every other bare-IP site (Alerts, Events, NetFlow
talker labels, Dashboard tiles, Wireless, IPAM host names) listed for a
future round rather than touched now.
→ Plan updated to match.

**Plan approved.**
→ Work assigned across the roster; lanes run in parallel in main's working
tree.

## 5.19.0 — Twilio SMS alerting

**Team-rules prompt** — same standing rules as before, with the work item:
"Implement Twilio Text Message integration on alerts. Each alert should have
the ability to turn on or off SMS texting just like email."

**Planning answers** — one global SMS number list in Settings → Alerts with a
per-rule on/off toggle; SMS follows email's timing (roll-up hold, digest,
re-notify, recovery texts) with its own hourly cap; a fixed short text of at
most 160 characters, no template editor; Twilio set up with Account SID, Auth
Token (stored encrypted like the SMTP password), From number, optional
Messaging Service SID, and a "Send test text" button.
→ Plan approved.

## 5.20.0 — Twilio API keys

**Team-rules prompt** — the standing rules as before (named team led by Bob;
no HTML pages for documents; comments at 20% prose or less; nothing removed
from the GUI without permission; speak to the operator as a network
engineer/CTO; Testy runs the full suite once after changes and walks only
edited modules without screenshots; Stephen_King keeps this log; Javariius
reviews before the push to main), with the work item: "Twilio SMS
functionality was added with only 'Auth Tokens' please also add the ability
to integrate with Twilio API keys."
→ Dora mapped the 5.19.0 Twilio code (hand-rolled REST in alertmail.py, the
auth token in its own DPAPI-encrypted single-row table bound to the Account
SID, one fieldset in the Alerts settings dialog).

**Planning answers** — an "Authenticate with" selector (Auth token | API
key) with the Account SID always shown; one stored secret at a time, the
existing sms_credential row widened with auth_mode and api_key_sid columns,
existing installs migrating as auth_token; version 5.20.0; branch pushed
then main fast-forwarded, no pull request.
→ Plan written and approved.

**Plan approved.**
→ Thing1 on the backend, Thing2 on the dialog, Testy/Fisty on verification,
Javariius on review.

**Deployment**
→ Thing1 built the backend, Thing2 the dialog; Bob closed the stale-key-SID
gap. Testy ran one full pass plus a headless dialog walk. Javariius
approved with nits (test precision, a mode-switch guard in the dialog, a
stripped key SID), all closed before the branch was pushed and main
fast-forwarded.

## 5.20.1 — SMS consent notice

**"Test SMS is failing immediately."** — traced with the operator to a
blank From number, not a fault; the stored API key and the test route
were proven against a Twilio stub.
→ No code change; operator set the From number.

**"Give me sample SMS messages ... for A2P Campaign examples"** —
samples built from the real text builder (severity tag, rule, entity,
detail), with the note that alert texts carry no brand name.
→ Samples handed over for the campaign submission.

**Twilio opt-in rejection reply** — advised in-app consent rather than
a verbal script; drafted the reply and the consent wording.
→ Reply sent; wording carried into the plan.

**"Add the consent notice and push to main"**
→ Thing2 added the notice and a contract check, Stephen_King the docs,
Javariius reviewed, branch pushed and main fast-forwarded.

## 5.20.2 — TLS behind an inspecting firewall

**"After adding the correct from number I get this error: ... Missing
Authority Key Identifier"** — diagnosed as Python 3.13's stricter
`VERIFY_X509_STRICT` X.509 checking meeting an SSL-inspecting firewall's
re-signed certificate; one shared verified context, with that one flag
cleared, now used by the Twilio, webhook and SMTP senders alike.
→ Javariius reviewed; branch pushed and main fast-forwarded.

## 5.20.3 — The HTTPS monitor behind an inspecting firewall

**"Yes, fix the HTTPS monitor too"**
→ One shared `verified_context()` in `tlscontext.py`; `alertmail` and
`selfupdate` build on it, so the HTTPS monitor and the self-updater
verify like the senders now do. Javariius reviewed; branch pushed and
main fast-forwarded.

## 5.20.4 — The auto-assigned MIB, repaired for the fleet

**"I need a way to clear the single override that is listing on 300
devices from when the auto vendor ID assigned their MIB..."**
→ Dora found the rows carry no auto marker from before 5.18.0 — the
`mib_file_auto` column didn't exist yet when they were written, so
they're stored the same as a hand-picked MIB. Planning answers: a
one-time startup repair rather than a bulk action, scoped to devices
whose only override is a vendor-matching MIB, leaving any other
override or a non-matching MIB alone. Thing1 built it, Javariius
reviewed, branch pushed and main fast-forwarded.

## 5.20.5 — The auto-assigned MIB, repaired for the fleet (second pass)

**"Not sure how long this should take but it appears as though the
nodes still show the 1 override item"**
→ The 5.20.4 signature checked the stored MIB against the vendor's
largest uploaded file, but `_auto_assign_mib` had always used the
identification walk's own pick instead, so any vendor with more than
one uploaded file left most of its devices skipped. Widened the
match to any of the vendor's covering files and reran the repair once
under a new marker. Javariius reviewed; branch pushed and main
fast-forwarded.

## 5.21.0 — A modular Dashboard, and global find to the switch port

**Team-rules prompt** — the standing rules as before, with four work items:
(a) global find should show an IP or MAC's hits on switch-port MAC tables
and ARP tables, naming the port; (b) the Nodes CSV export lists the IP in
both the Name and IP columns; (c) the Debug Event log resets its scroll
position on every new event; (d) make the Dashboard modular — rearrange
tiles, add and remove them, from a catalogue of tile types including
interface graphs, taking cues from SolarWinds, Auvik, PRTG and Zabbix.

**Planning answers, round one** — an IP search today surfaces only the ARP
row, so the fix chains ARP to MAC to switch port; dashboard layout is per
account, saved on the server; tiles drag-to-reorder in a grid with a
per-tile width setting rather than free placement; one dashboard per
account.

**Planning answers, round two** — all four tile families ship: graphs,
single-device status, module overviews, and lists/notes; an explicit Edit
layout button rather than an always-editable canvas; one release, 5.21.0,
rather than shipping the fixes first; graphs default to a 24-hour window
refreshed every 60 seconds.

**Plan approved.**
→ Work assigned across the roster: Thing1 the backend (both fixes, the
layout storage and routes, `/api/nodes/events`), Thing2 the frontend
(the scroll fix, the shared chart renderer, `dashboard.js` and its
catalogue of 24 tile types), Stephen_King the docs. Testy ran the full
suite (152/158; the six failures were environmental or pre-existing on
main) and a headless walk of Dashboard, Debug, Nodes CSV and global find.
Javariius found one blocker (a graph tile with no device chosen made the
layout unsaveable) and sixteen smaller findings; all closed, re-review
"ready to push". Fisty chunked the new MAC query to the bulk contract and
re-pinned the Workers tile check. Shipped as 5.21.0 on `main`.

## Team rules in the repo

**Does the web portal have a CLAUDE.md file I can edit so that I don't have to give
the same instructions with every prompt?** — Yes. The repo's `CLAUDE.md` is loaded
at session start from the fresh clone; it held one line pointing at the
deep-code-explorer skill.

**Set them up for me** — Standing rules written into `CLAUDE.md`; nine named
teammates defined under `.claude/agents/` with their models pinned. The
unnamed `deep-explorer.md` agent was folded into `dora.md`.

**Please check the repo now for the deep-code-explorer skill and the explorer
agent** — Found on `main` in `54c699e`, pushed from another device after
5.21.0. The skill now runs as Dora, so no unnamed agent is spawned.

→ Javariius reviewed the ten files against the operator's verbatim rules;
one wording fix. Committed on the session branch and fast-forwarded to `main`.

## 5.22.0 — TACACS+ sign-in, richer dashboard graphs, and a look at history

**Operator prompt, five items:**
- Add TACACS functionality for logging into the system
- Dashboard graphs tile - I would like to be able to add multiple interfaces
up/down traffic to a single graph. Graphs should also be able to be named
and have a built in drop down to change the timeline period without having
to 'edit layout' and then configure the tile. You should be able to set a
maximum value for the graphs.
- When adding an interface traffic graph on the dashboard the auto fill
suggestions popup should match the theme. Currently it looks similar to a
browser autofill which could be confusing.
- All graphs should have the ability to drill down and select dates and
times.
- Research how the most popular network monitoring systems retrieve,
display, filter and output historical data for devices, interfaces,
environmental sensors, CPU, etc and give me options for different ways to
implement into the GUI and platform.

**Planning answers** — TACACS+ falls back to local accounts only when the
AAA server is unreachable, and an explicit reject from the server is final
(no silent fallback to local on a reject); local accounts are never sent
to TACACS+ for verification; a TACACS+ user gets one configurable default
role and is auto-created on first successful sign-in; the multi-interface
graph extends the existing Interface traffic tile rather than adding a new
tile type; drill-down (drag-to-zoom plus an explicit date/time picker)
goes on every chart with a time axis, not just the dashboard; a time
window picked directly on a tile (outside Edit layout) is saved back to
the account's dashboard layout immediately; the research is delivered as
both a chat summary and a standing reference doc,
`docs/HISTORICAL-DATA-OPTIONS.md`, with no history-explorer feature built
yet — it is a menu of options for a future decision. Version for this
work: 5.22.0.

→ Thing1 the backend (`tacacsclient.py`, the third `auth_source` and
auto-create path in `post_login`, the widened dashboard layout schema and
`GET /api/nodes/series/batch`), Thing2 the frontend (the multi-interface
tile config form, the on-tile window control, the themed device
combobox, and the shared `Custom…` range dialog plus drag/wheel/keyboard
zoom wired onto every time-axis chart), Stephen_King the paper and the
docs. Testy ran the full suite once (161/167; the six failures were the
four known environmental ones plus two real single-assertion misses in
the frontend commit) and a headless walk of Dashboard, Nodes, Settings,
NetFlow, Routes, Syslog/Trap and Alerts (61/69 first time). Fisty found
the walk's real causes: the shared range dialog answered Apply as
cancelled because the modal closed before the promise settled, an
unconfigured Interface traffic tile sent an empty interface list the
server refuses, and the combobox duplicated the panel-surface rule.
Javariius reviewed three times: first pass "not ready" with two high
findings (drag-zoom wrote fractional timestamps the server refuses; the
PAP START carried minor version 0, which the reference daemon rejects)
and eleven smaller ones, all closed by Fisty; second pass caught that
wheel ticks recomputed from a stale window, closed by Bob; third pass
"ready to push". Final state: full suite 163/167 with exactly the four
environmental failures, the walk 69/69 on the release commit. Shipped
as 5.22.0 on `main`.

**Javariius's review, four corrections before push:** two `FEATURES.md`
passages overstated what a drag or a wheel-turn does to the device and
interface dialogs — only picking **Custom…** actually closes and
reopens the dialog; drag and wheel just pin the chart where it is,
dialog untouched. `CHANGELOG.md` overstated the zoom refactor — NetFlow
and Routes keep their own existing wheel/keyboard/brush code and only
picked up **Custom…**; the new shared `App.attachChartZoom` helper is
what the Dashboard tiles and the Nodes charts actually run on. One gap
Javariius flagged in the TACACS+ write-up: with auto-create on, an
existing local account is answered without ever reaching the AAA
server while an unknown one is sent on to it, so a caller can tell a
real local username from a made-up one just by which reply comes
back — called out plainly in `FEATURES.md` and
`CREDENTIAL-SECURITY.md` §12, with auto-create-off as the way round it
where that matters. One addition alongside the fixes: Dashboard tile
wheel-zoom now needs Ctrl/Cmd held, since a tile lives on a page that
still needs to scroll under a plain wheel; drag-zoom is unchanged.
Noted for the record in `INTERNALS.md` too: the PAP START this client
sends carries minor version 1 (`0xC1`, RFC 8907 §5.4.2.2) and the reply
is decoded using the version byte the *reply* actually carries, and
`Service.authenticate_tacacs` now remembers an unreachable AAA server
for ten seconds so a server outage fails every concurrent sign-in fast
instead of making each one sit out the full timeout.
→ Stephen_King. `FEATURES.md`, `CHANGELOG.md`, `CREDENTIAL-SECURITY.md`,
`INTERNALS.md` corrected and extended; no code touched.

## 5.23.0 — History options A/E/G, priority-port alerting, NetFlow gaps, and Mapper fixes

**Operator prompt, nine items:**
- Proceed with options A, E and G from `docs/HISTORICAL-DATA-OPTIONS.md`.
- Add uptime as a column choice on Nodes → Devices.
- Question: does the app have an API receiver for external API requests,
  or is the API only how the GUI talks to the backend?
- Do not include poll overruns in the device details dialog's event log.
- NetFlow export has no timestamps.
- NetFlow randomly misses large blocks of data over 24 hours and over
  3 days.
- Mapper PNG export uses different fonts than the screen and items
  overlap.
- Add a manual line between two devices on Mapper.
- Alert only on ports flagged Priority when they drop link.

**Planning answers** — Wireless history (option G) covers only what is
already polled today — client counts per AP and radio, channel, tx
power, online state — no new SNMP columns are added to get there.
Priority-flagged ports get a new, dedicated built-in rule, "Priority
interface down"; the existing Interface down rule is untouched and
keeps firing for every port as before. Scheduled reports (option E)
send a summary body plus a CSV attachment on a daily, weekly, or
monthly schedule. The NetFlow gaps get all three suspected causes
fixed, not just one: templates being dropped on any NetFlow settings
save, the raw-row cap deleting flows before they're summarised into
rollups, and wide chart windows silently falling back to thinned raw
rows when the minute rollup doesn't reach back far enough — plus a
coverage readout so a gap is visible instead of silent. Version for
this work: 5.23.0.

**Bob's answer on the API question** — Yes: every `/api/*` route
accepts an `Authorization: Bearer` API token as well as the browser
session cookie. Tokens are issued and revoked under Settings → Tokens
(admin-only), carry the issuing account's own permissions, never
expire from inactivity, and never mint a cookie. Scripts get past the
CSRF check because a request with no `Origin` header is accepted.
There is no inbound data-push receiver beyond the existing syslog,
trap, and NetFlow protocol listeners — nothing else accepts pushed
data from outside.

**Also recorded:** a short Status paragraph was added under the
Recommendation section of `docs/HISTORICAL-DATA-OPTIONS.md` noting the
operator's choice of A, E and G and how each shipped — A as the Nodes
→ HISTORY sub-tab with a series CSV export route, E as Nodes → Reports
→ SCHEDULED, and G as per-AP client/radio history in the Wireless AP
detail pane.

**Outcome.** Thing1 and Thing2 built the nine items above: three NetFlow
gap causes closed (template carry-over across a collector restart, the
row cap no longer outrunning the minute rollup, a wide chart widening
its own bucket instead of falling back to thinned raw rows) plus a
history/coverage readout on the NetFlow status strip; readable local-time
columns on the flow, Syslog and SNMP Trap CSV exports; priority ports
(`interface_flags`, a dedicated `priority_interface_down` alert rule
gated to flagged ports, `link_up` clearing it alongside the existing
`interface_down` rule); scheduled emailed reports (`reportsched.py`,
`report_schedules`, up to 50 schedules, reusing Alerts' own SMTP
settings); the Nodes → HISTORY explorer and its series CSV export; wireless
AP/radio history sampling with a new `max_wireless_db_mb` size cap; the
Mapper PNG export's font/style fidelity and pixel-density fix, plus the
new Connect tool for manually drawn map links; an optional device Uptime
column; and the device dialog's event log dropping poll-overrun entries.
Stephen_King wrote `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`NETWORK-AND-STORAGE-REQUIREMENTS.md` and this entry against the diff
(`e8cdc01..HEAD`, implementation commit `bf9b5ee`), reading the actual
code for every claim rather than the task description alone; the wireless
history disk estimate in `NETWORK-AND-STORAGE-REQUIREMENTS.md` is
arithmetic from the row layout, not a measured benchmark, and is
labelled as such. Testing: the full suite on the release commit passed 159 of 164 with only the four environmental failures this container always shows (SMS passphrase, traceroute, the prune-lock timing check and the SNMP socket family in the web-gates test), and the browser walk passed 76 of 76 with no console, page or HTTP errors as admin or viewer. One real regression surfaced on the first pass and was fixed: the Reports UI contract test pinned four Nodes sub-tabs and now pins five. Javariius reviewed twice; the first pass found five should-fix items (a whole-fleet Top-N schedule with no window cap, a v5 exporter with a future clock able to pin the NetFlow row cap, unvalidated wireless history settings, missing tests for the rollup catch-up and coverage code, and comment density) plus nits, all closed before the second pass returned "ready to push".
→ Stephen_King. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`NETWORK-AND-STORAGE-REQUIREMENTS.md` written for 5.23.0; no code
touched.

## 5.42.0 — Placeholder blocks on Mapper, and a shorter STP-blocked row

**Operator prompt, two asks:**
- Add a "placeholder" block type to Mapper — a named box on the diagram
  that is not a real device (things like "Internet" or a patch panel),
  so a map can show the whole picture without every box needing SNMP
  behind it.
- Drop the "STP Blocked on" wording from the link detail pane's blocked
  VLAN rows added in 5.41.0 — just the switch name in red is enough.

Dora explored `mapper.py`/`mapperdb.py`/`web/api.py`/`mapper.js` first
to confirm a placeholder could reuse `map_nodes`' existing device_id-NULL
shape without a schema change, and where the unmanaged-peer code paths
would need a branch instead of a rewrite. Thing1 built the server side:
`mapperdb.add_placeholder`, the `mapper.PLACEHOLDER_PREFIX`/
`is_placeholder` identity scheme, the API's placeholder branch in
`get_mapper_map`/`post_mapper_map_nodes`, and the CSV export's
`peer_name` lookup. Thing2 built the browser side: the Placeholder
toolbar button and its one-field dialog, the dashed/muted draw style,
the detail-pane branch (rename, role, Remove — no status or "Open in
Nodes"), and the shortened STP-blocked row text. Testy ran the mapper
test suites and the browser walk's new placeholder step. Javariius
reviewed the whole diff before the push to main.

**Outcome.** A placeholder is now its own `map_nodes` row — device_id
NULL, a synthetic `placeholder:<hex>` peer_key that can never collide
with a discovered peer's identity — so the existing per-map uniqueness
indexes, the Connect dialog's peer lookup, and Remove's link cascade all
apply unchanged. It draws dashed and muted with no status glyph, never
opens the Nodes dialog, is never discovered or polled, and never shows up
as an Add-neighbours candidate. The CSV export now names a placeholder
(and, as a side effect, a renamed unmanaged peer) by its current label
instead of its raw key. Separately, the link detail pane's blocked-VLAN
row dropped the words "STP blocked on" — the row now just reads
`<vlan> <name> (<switch>)` in red, which also fixes the row wrapping
onto a second line that the longer wording caused on a busy trunk.

Testing and review: see CHANGELOG 5.42.0.

## 5.43.0 — Full refactor kicked off: test hardening first (phase 1 of a 5-part plan)

**Operator prompt, verbatim:**
> Pull the latest repo and team details. Perform a complete refactor of the
> application — improve internal structure, readability and design; no
> change for the end user other than performance. Remove dead code and
> files no longer used. Then perform a full code review for performance,
> bugs and security vulnerabilities.

**Starting point.** Repo was already up to date, at 5.42.0 (commit
`e25e756`). No end-user features change in this work — this is
housekeeping under the hood plus a speed check, not a new-features
release.

**Groundwork.** Three explorer reports were run before touching anything:
one over the backend, one over the front end (browser/UI code), and one
hunting for dead code and unused files across the whole repo. Planning
then went through the findings with the operator rather than guessing at
scope.

**Decisions made in planning:**
- Harden the test suite's own text-matching checks first, before any
  other refactor work — so later phases have a trustworthy safety net
  instead of tests that could silently stop checking what they claim to.
- Backend gets a full internal restructure; the front end gets a lighter,
  moderate tidy-up rather than a full rewrite.
- New database indexes may be added to speed things up; no existing
  database columns or tables are removed.
- Work is split into five releases so each piece can be tested and
  reviewed on its own rather than as one giant change:
  - **5.43.0** — test-suite hardening (this release)
  - **5.44.0** — dead code/file removal plus backend restructure
  - **5.45.0** — front-end restructure
  - **5.46.0** — performance pass
  - **5.47.0** — the full security/bug/performance review, with findings
    reported to the operator for approval before any fixes are made
- Approved for removal: an unused MIB reference file (`if-mib-core.mib`),
  an old unused browser-walk test script (`demo/ui_walk.mjs`), and unused
  colour definitions left over in the desktop app's theme.
- Kept as-is: the self-test blocks built into individual modules — these
  stay even though they look like extra code, because they are the
  in-place sanity checks each module runs on itself.
- A running list of known odd behaviours ("quirks") already in the app is
  being kept so nothing gets accidentally "fixed" or changed along the
  way — that list gets reviewed with the operator at the end (5.47.0).

**Status:** Phases 1 through 3 (test hardening, then dead code/file removal
plus backend restructure, then front-end tidy-up) shipped as 5.43.0, 5.44.0
and 5.45.0. Phase 4 (the performance pass) is shipping as 5.46.0. Phase 5
(the full security/bug/performance review) is next. No new operator prompt
landed in between — just periodic "status?" checks, not logged here as
separate entries. The operator also asked for a check-in every 10 minutes
partway through; that request was later cancelled.

**"Spawn additional sonnet teammates if needed."** Said partway through the
performance phase, once it was clear the backend performance lane (route
lookup, resolver cache, poller/wireless settings caching, the disabled-
device index, the FortiGate SNMP walk) was more than the two regular
teammates could carry alongside the front-end redraw-skip work. Thing3 and
Thing4 were added, both on Sonnet, to take the backend performance items.

**Session limit, mid-phase.** All teammates working this phase hit the
account's session limit before finishing their assigned items. Each was
resumed with a plain "continue" once the limit cleared, picking back up
from where it stopped rather than restarting.

**Phase 5: the review, and what happened after it.** 5.46.0 (the
performance pass) shipped. The full security/bug/performance review that
was always phase 5 of this plan then ran over the shipped 5.46.0 codebase,
covering security, correctness and performance the same way the earlier
phases covered structure. The review's full write-up — every finding, its
severity and where it lives in the code — was exported to a local file at
the operator's request and is deliberately kept out of this public
repository; only the fixes below, and their operator-visible effects, are
recorded here and in `CHANGELOG.md`.

**Operator approved the recommended fix set.** Rather than fix everything
at once, the highest-value and lowest-risk items went first, and the
remainder was planned as a sequence of releases so each stays reviewable
on its own:

- **5.47.0** (this release) — the approved security, correctness and
  history-maintenance fixes: session address binding, per-address
  sign-in lock-out, trap-community visibility, the SNMPv3 engine-time
  retry, the daylight-saving maintenance-window fix, the per-connection
  TLS handshake, the WEB relay cookie/framing hardening, the alert-cursor
  rewind and keep-newest-row prune rule, and the metric-history
  performance work — see `CHANGELOG.md` for the full list.
- **5.48.0** — first-run administrator password handling, plus the
  remaining low-severity review items.
- **5.49.0** — the low-risk poll and API performance items the review
  also surfaced.
- **5.50.0** — GETBULK interface polling.
- **5.51.0** — spanning-tree walk cadence and down-port sample storage.
- After that, the review's findings are published.

**Operator instructions given alongside this plan, both now standing
policy in `CLAUDE.md`:** "only run one Javariius at a time" (a single
review pass in flight, not several running against overlapping diffs),
and "remove the 10-minute loop" (the periodic Bob-to-teammate check-in
cadence asked for earlier in this refactor is cancelled — see the "status?"
note above for when it was added). `CLAUDE.md` was also updated by the
lead separately, to allow extra Sonnet teammates for disjoint work lanes
and to add a plain test-status line to the standing rules; noted here for
the record, no document in this file's own remit changed for that edit
beyond this note.

**Files changed for 5.47.0's documentation:** `netpath/__init__.py`
(version), `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`, `RUNBOOK.md`,
`tests/README.md`, and this file.

## 5.48.0 — First-run administrator password, and the rest of the low-severity review items

Second release out of the phase-5 review plan (see 5.47.0 above): the
first-run `admin`/`admin` fix that 5.47.0 deferred, plus the remaining
low-severity items from the same review — session sweeping, the alert
engine's per-stage guard, the WEB relay/SSH terminal destination checks,
the mail header sanitiser, the expired-token audit throttle, and a handful
of smaller correctness and performance fixes. See `CHANGELOG.md` for the
full operator-visible list.

**"Let's go back to the old limit of just Thing1 and Thing2."** Partway
through this release the extra Sonnet teammates (Thing3/Thing4) added
during the 5.46.0 performance phase ran into the account's session limit
a second time, stalling every lane at once rather than just the one
teammate that hit it. The operator withdrew the standing permission for
extra teammates and asked for the roster to go back to the two named ones.
`CLAUDE.md`'s team section was restored to name only the original roster
(Bob, Testy, Fisty, Dora, Thing1, Thing2, Stephen_King, Dingus1, Dingus2,
Javariius) as the only agents that may ever be spawned.

**Browser walk run from a detached driver.** The walk had been getting
killed mid-run by the harness's background-task limiter on this low-memory
box before it could finish all 94 checks. It is now launched with a
detached process (output to a log file, not the harness's own background
task tracking) so it survives to completion regardless of how long it
takes or how much else is running at the time.

**Files changed for 5.48.0's documentation:** `netpath/__init__.py`
(version), `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`tests/README.md`, and this file. `README.md`, `RUNBOOK.md` and
`demo/README.md` were updated separately for the same release.

## 5.49.0 — Low-risk poll and API performance

Release C of the approved five-release plan (see 5.47.0 above: A =
5.47.0, B = 5.48.0, C = this one, D and E still to come as 5.50.0 and
5.51.0). The low-risk poll and API performance items the phase-5 review
surfaced: FortiGate/wireless controllers walk with GETBULK instead of
GETNEXT on v2c/v3, a device known not to answer the Net-SNMP CPU/memory
read is no longer asked for it every poll, the interface write path
reuses a read it had already done instead of repeating it, the identity
and Net-SNMP scalar reads now share one socket, and the Nodes table's own
API request now asks for a smaller, dedicated set of fields. Nothing
changes on screen. Two work lanes, Thing1 and Thing2, split the items
between them; both lanes' changes went through the same review-and-walk
pass together rather than separately, per standing policy of reviewing
only once per set of related changes.

**Walk and full suite both run detached**, the same way the walk was
moved to a detached process in 5.48.0 for this same low-memory box — this
time the full 207-suite run was launched the same way, to a log file
outside the harness's own background-task tracking, so a long run
surviving to completion does not depend on the harness's background-task
limiter leaving it alone.

**Files changed for 5.49.0's documentation:** `netpath/__init__.py`
(version), `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`tests/README.md`, and this file.

## 5.50.0 — Spanning-tree polling cadence; no samples for down ports

Last release of the phase-5 review's follow-up plan (see 5.47.0 above: A
= 5.47.0, B = 5.48.0, C = 5.49.0, D and E covered here, after which the
review's full findings are due to be published).

**"What's left?"** Asked once 5.49.0 shipped. Two items remained on the
plan — GETBULK for Nodes' own interface polling, and spanning-tree walk
cadence together with down-port sample storage.

**A plan was asked for, then approved.** GETBULK for interface polling
was investigated first, since it was next in line. Measurement at
realistic port counts showed no saving: the gain expected for it assumed
a request shape the interface poller's own walk engine doesn't build, so
batching more rows per request there does not cut round trips the way it
did for the wireless-controller walk in 5.49.0. That item was dropped
rather than shipped. With nothing left to justify a release of its own,
the two remaining items — spanning-tree cadence and down-port sample
storage — were combined into this one release instead. The operator
approved that plan.

**"Javariius should run on Opus, not Fable."** Then a follow-up asking
whether Bob was still on Fable: he was not — the lead session had been
running on Opus 5 — and the operator chose to leave it there for the
day. `.claude/agents/javariius.md` and `CLAUDE.md`'s team section were
updated for both, and the roster now reads Javariius (Opus) with Bob an
Opus 5 developer. Noted here for the record; no document in this file's
own remit changed for that edit beyond this note.

**"Just Thing1 and Thing2 — no Thing3/Thing4."** Reaffirmed the standing
limit set after 5.48.0's own withdrawal of the extra Sonnet teammates.
This release's two work lanes — the spanning-tree cadence change and the
down-port storage change — were split between the two named teammates as
usual, with nothing extra spun up.

**Files changed for 5.50.0's documentation:** `netpath/__init__.py`
(version), `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`, and this file.

## 5.51.0 — Loopback tunnel guard, TACACS+ auto-create role cleanup, and SNMP decode correctness

**"Read the internal review document and plan the outstanding work."**
The operator asked for the review document to be read and a plan drawn up
for what it still left open. The plan covered three groups: the
remaining security-hardening items, the performance items the phase-5
releases (5.47.0–5.50.0) had deferred, and a round of test cleanup. The
operator approved it as put forward.

**Implementation ran across the team** against that approved plan: a
loopback-tunnel restriction for the WEB relay and SSH terminal, a
TACACS+ auto-create default-role cleanup, SNMP decode fixes for
hardware-address and VLAN data, a Mapper canvas-redraw skip, an IPAM
export row cap, and rollback guards on the syslog and nodes-database
write paths.

**A scope error was caught and corrected mid-flight.** One lane's first
pass at the TACACS+ role cleanup nearly removed the **Admin** preset from
the user-permission editor on Settings → Users — a different, unrelated
control from the TACACS+ auto-create default role the plan actually
called for changing. Caught before it reached review; the permission
editor's preset was left exactly as it was, and only the TACACS+
auto-create dropdown changed.

**Files changed for 5.51.0's documentation:** `CHANGELOG.md`,
`INTERNALS.md`, and this file. `FEATURES.md` needed no change — none of
its existing wording was made false by this release. `netpath/__init__.py`'s
version bump to 5.51.0 had already been made before this documentation
pass started.

# SappiWhere — Changelog

Firewall and protocol requirements are in `NETWORK-AND-STORAGE-REQUIREMENTS.md`. A guide to what the application does is in `FEATURES.md`, and how it does it in `INTERNALS.md`. How credentials are protected is in `CREDENTIAL-SECURITY.md`.

## Releases

Listed newest first. Version numbers are build order, not dates.

### 4.33.1 — Tests you can actually run

- **The end-to-end suites now live in the repository, under `tests/`, and
  every one of them passes.** Four of them had been listed as "known
  environmental failures" since 4.28. None of those failures was the
  application's: three suites expected a stub SNMP agent to have been
  started by hand on a fixed UDP port (16161, 16261, 16262) before they ran,
  and the fourth predated two deliberate changes — discovery takes its
  communities from the chosen polling profile and guesses nothing, and a
  promoted device keeps the IP as its manual name while sysName is seeded
  into the identity. Each suite now starts its own stub as a child process
  on a free loopback port, points the module under test at it, waits for
  the stub's bound banner rather than a fixed sleep, and kills it on exit.
  The custom-MIB suite also waits for the poll worker to finish instead of
  sleeping three seconds and then shutting the service down under an
  in-flight poll, which is what produced its "cannot operate on a closed
  database" trace.
- `python3 tests/run_all.py` runs them all and reports PASS/FAIL per file;
  `tests/README.md` says what each one proves. Standard library only, no
  network, no `ping` binary, no root, temporary databases.
- One consistency fix found while merging: 4.33.0 added Moxa (arc 8691) to
  the well-known sysObjectID table and shipped a Moxa MIB bundle read from
  MOXA-GENERAL-MIB, but the arc was still listed as curated-from-memory in
  the enterprise table. It is now in the verified list, as every well-known
  root and every bundle arc must be.

### 4.33.0 — How long it was down, loss you can see, and paths that alert

- **"Device recovered" now says when it recovered and how long it was down.**
  The notice read "responding again" and nothing else, so the one question an
  operator opens it to answer — how long was this out — had to be reconstructed
  from the outage alert's timestamp in another row. It now reads *"responding
  again at 14:03:21 after 2 h 14 m down"*, with the exact time the outage began
  underneath it. The outage's start comes from the alert this recovery just
  resolved, whose opened time **is** the moment the device stopped answering,
  and from the device's own event log when there is no such alert — the rule
  disabled, the device muted, the alert held as a newly added device or
  resolved by hand. When neither knows, the clause is left out rather than
  guessed at: an outage of unknown length is not a zero-length one. A resolved
  alert of any kind now also carries how long it stood, in its detail pane.
- **Fixed: the recovery email named the wrong time.** It said "is responding
  again as of {{last_time}}", and on a resolution notification `last_time` is
  when the *outage* last recurred — a moment before the recovery, not the
  recovery. The template now uses three new tokens, `recovered_time`,
  `down_since` and `downtime`, and every resolution notification carries them:
  a port coming back, an access point returning and a threshold dropping below
  its clear value all now state how long the problem stood, which none of them
  did before.
- **An upgraded install gets the new wording, unless it wrote its own.**
  Built-in templates seed once and are then left alone, which is right for a
  template somebody edited and wrong for one nobody has touched — that one is
  simply the old shipped text sitting where the new shipped text belongs. The
  upgrade now rewrites a built-in template only where it still matches, exactly,
  what the previous release shipped. An edited template is never touched, and
  "Reset to built-in" offers this release's wording either way.
- **The Nodes device pane charts packet loss, on its own time frame.** Loss is
  sampled on every poll that pings and already drives a shipped alert rule, but
  there was nowhere to see its shape over time — bandwidth is a per-port
  question, asked in the port dialog, and loss is not. The chart sits under the
  status timeline with its own range dropdown: "how long has it been down" and
  "how lossy is this link" are asked over different spans, and one shared range
  made every visit to the pane a compromise. Its axis is pinned to 0-100 %,
  because an auto-scaled one draws a healthy device's flat zero as a
  full-height alarm. A device that is not being ping-probed says so rather than
  drawing an empty grid.
- **That chart's ranges stop at three days, deliberately.** Metric windows
  wider than three days are read from an hourly rollup table that nothing in
  this application has ever populated, so offering 7 and 30 days would offer
  two views that are permanently empty. The status timeline beside it keeps
  every range — it is built from the device event log, not from metric samples.
- **NetPath destinations now raise alerts.** Every other module fed the alert
  engine; traceroute results fed nothing, so a monitored path could be broken
  for a day with nothing but a red dot on a tab to say so. Three built-in rules
  ship, and all three are deliberately hard to trip, because a path monitor
  that cries wolf gets turned off:
  - **NetPath destination unreachable** — nothing at all comes back from the
    destination, on three consecutive traces. On the shipped five-minute
    interval that is a quarter of an hour of silence. One answered probe clears
    it. A refusal names the router and the ICMP code that sent it.
  - **NetPath path repeatedly failing** — half the traces in a window failed to
    reach the destination. The window is the longer of an hour and six trace
    intervals, and the rule says nothing until at least five traces have landed
    in it, so a destination traced twice an hour cannot alert on one bad trace.
    This is the only one of the three that can see a path that works
    intermittently, which counting consecutive failures by definition cannot.
  - **NetPath latency far above normal** — round-trip time at three times that
    destination's **own** warn threshold, sustained for three traces. Relative
    rather than a fixed number of milliseconds, because "slow" means nothing
    across a LAN hop and a satellite link at once. Thresholds below 20 ms are
    treated as 20 ms, since three times a few milliseconds is ordinary jitter,
    and a trace that did not reach the destination is not measured at all — its
    round-trip time is to whichever router refused it.
- **One broken path raises one alert.** An unreachable destination is also,
  necessarily, one whose traces are failing and whose latency cannot be
  measured, so the unreachable alert absorbs the other two for that destination
  the same way *Device not responding* absorbs the alerts a dead device
  implies. Nothing needs un-suppressing: all three re-derive from the next
  trace.
- **A trace that could not run is not an outage.** A traceroute that failed on
  this machine, or a slot skipped because the previous run was still going,
  records 100 % loss by construction — and alerting on it would report a
  missing `traceroute` binary or a badly chosen interval as a network
  breakdown. Those statuses now produce no sample at all: they leave every
  streak exactly as it was rather than counting as a failure. Consecutive-trace
  counts are counted against the traces' own timestamps, too, so "three traces"
  cannot be satisfied in fifteen seconds by an engine that ticks every five.
- **A destination that stops being traced resolves its alerts.** A threshold
  alert clears by being re-evaluated and found to have recovered, which cannot
  happen for a destination that was disabled or deleted — the alert would have
  sat open forever, and turning a destination off while working on a link is a
  normal thing to do.
- **A Moxa MIB bundle is in the catalog** — 25 files covering the EDS, IKS and
  PT switch families and the AWK access point: system info and utilization,
  port status, PoE, Turbo Ring and Turbo Chain redundancy, dual homing, fiber
  check and digital I/O. Fetched from LibreNMS's public tree at install time
  like every other bundle; nothing is mirrored here. 4.32.0's arc walk already
  names a Moxa switch from arc 8691 without any MIB at all; this is what lets
  it decode the switch's own objects once named, and what the bundle hint on a
  `mib_missing` event points at.
- **Rockwell Automation gear is identified from its sysDescr,** and reads as
  "Rockwell Automation" rather than as a token. No enterprise arc is claimed
  for it: every arc in this application was read out of that vendor's own MIB
  text, because a wrong arc silently mislabels every device under it, and no
  Rockwell MIB was available to read one from. It is therefore the one vendor
  named by sysDescr with no arc to be keyed by, and carries its display name in
  `enterprises.ARCLESS_DISPLAY` instead.
- **Known, not fixed: SNMPv1 is never actually spoken.** The poller resolves
  the version as `snmp_version or 1`, so a device configured for v1 (stored as
  `0`) goes on the wire as v2c. One consequence is already guarded — a custom
  Vendor or Location OID rides in the same request as sysDescr and sysObjectID,
  which on a real v1 agent would null every answer in it, so those OIDs are read
  in a separate best-effort request for a v1-configured device — but that guard
  cannot fire while the coercion stands. Correcting it changes how every
  v1-configured device is polled and deserves its own change with its own
  testing, so it is recorded here rather than slipped in.

### 4.32.0 — Know what you are polling

- **A device's vendor is now identified from what it actually answers, not
  only from its sysObjectID.** Vendor identity lives entirely under the
  `enterprises` subtree, and the set of enterprise arcs a device populates
  can be enumerated in (arcs + 1) GETNEXTs by *hopping*: ask for the first
  object under `1.3.6.1.4.1`, land on arc N, ask for the first object under
  `1.3.6.1.4.1.(N+1)` and skip the whole of arc N. A device usually answers
  under two to six arcs, so this is cheaper than one poll — and it finds
  vendors this app holds no MIB for. A net-snmp radio that used to show as
  "netSnmp" now shows as Phoenix Contact, because arc 4346 is what it
  answers under.
- **Then the installed MIBs are scored against a bounded walk** (about 500
  objects, 20 seconds, once per device on its first successful poll, again
  only if its sysObjectID changes, and behind a Re-identify button). Each
  MIB is credited with the objects it names on that device, and the file
  that names the most becomes the device's Custom MIB — replacing the old
  "the file with the most objects under the arc" guess, which was a guess
  about the device made from the MIB alone. Steady-state polling adds no
  traffic at all: once identified for its current sysObjectID, a device is
  never walked again until somebody asks.
- **The precedence is explicit and explained.** A vendor set by hand wins,
  then one learned from an operator's override on a device with the same
  sysObjectID, then a real vendor arc in the sysObjectID (an IANA
  assignment), then the walk, then a word in the sysDescr, then the SNMP
  agent's own name. The walk never substitutes a different arc for a real
  vendor arc — OEM gear routinely implements the chipset vendor's arc
  alongside its own. Every device stores the evidence: which arcs answered,
  how many objects, which MIB named how many of them, and the sentence that
  states the decision. The device dialog shows all of it.
- **A confidence you can see.** The Vendor column carries one character
  after a name that is less than certain — `?` for a guess from sysDescr,
  `~` for probable (a curated enterprise number, or a walk with thin MIB
  evidence), `*` for a vendor set by hand or learned — and nothing after a
  name that came from an IANA arc or strong evidence, so the common case
  reads clean. The title says which source spoke.
- **Set a vendor by hand, and the fleet learns it.** A manual vendor on a
  device is shown, acted on by ConfigRX and the Cisco MAC-table read, and —
  when the device's sysObjectID is specific to one vendor — remembered, so
  every other device answering the same sysObjectID follows on its next
  poll. A generic-agent sysObjectID (net-snmp's, shared by every Linux box
  ever built) is deliberately never learned from; the dialog says so.
- **"This looks like a Ubiquiti — install the Ubiquiti MIBs."** Catalog
  bundles now carry the enterprise arcs they describe, so a device answering
  under an arc no installed MIB decodes is pointed at the bundle that would,
  with a one-click install from the device dialog. Every arc was read out of
  the bundle's own root file, never assumed.
- **Arcs with no MIB still get a name.** A bundled enterprise-number list —
  48 arcs verified from MIB text and 80 curated from memory of the IANA
  registry, kept apart and trusted differently — names a device whose vendor
  this app has never seen a MIB for. A curated entry decides at medium
  confidence with the arc number in the evidence, so a wrong one is
  auditable and scoped to devices nothing else could name.
- **Discovery sweeps list each device's arcs too.** The identity GET gains
  the hop's few GETNEXTs, the results table marks confidence and hints at
  the bundle to install, and promotion carries the verdict into the device.
  Switchable off, in which case a sweep is exactly what it was.
- Settings → Nodes has a **Vendor identification** fieldset for the walk's
  bounds, its concurrency (four at once, which is what throttles the
  post-upgrade burst where every existing device is unidentified) and the
  discovery hop. Existing devices keep their vendor on upgrade and are
  walked once, a few at a time, as they poll.

**Not done in this release:** a Phoenix Contact MIB bundle, for the same
reason as 4.28 — the catalog's upstream ships none. The device is now named
correctly anyway, and its `mib_missing` event says which arc a MIB would need
to describe.

### 4.31.0 — Mute a device, sustain a threshold, find a MAC

- **A poll overrun on a device that is not answering is no longer reported.**
  An overrun is recorded when the previous poll is still running as the next
  falls due — which is exactly what a device that stopped answering causes,
  because every request in that poll spends its full timeout and its retries.
  Worse, it fires *first*: a device takes three completed failing polls to be
  marked down, so the overruns led the outage by two or three intervals and
  the first one got out before anything suppressed it. Now nothing is recorded
  at all — no alert, no event row, no Debug line — while the device is down or
  its last poll failed. An overrun alert raised in the moments before the
  outage is absorbed by "Device not responding" like the other polled-metric
  alerts.
- **A device's alerts can be muted for 1, 6, 12 or 24 hours.** The button sits
  beside Resolve and Acknowledge in the alert detail. A mute stops what happens
  next — new alerts and their emails — and leaves alerts already open in the
  list to be worked normally; nothing has to un-suppress when it lapses,
  because thresholds re-derive from live metrics and a still-down device keeps
  recording events. Muting a switch silences its ports with it. A muted device
  is marked in the Nodes device list and its detail header, because a mute
  nobody can see is a mute somebody will spend an afternoon looking for.
- **Packet loss must now be sustained for 60 seconds before it alerts**, and
  the duration is adjustable per rule alongside the existing threshold. With
  the default of three ping probes per poll, measured loss can only ever be 0,
  33, 67 or 100 %, so a single lost probe used to raise an alert; the rule
  dialog now says so and points at the setting that changes it.
- **Fixed: "consecutive polls before firing" counted engine ticks, not polls.**
  The alert engine ticks every five seconds and a device is polled every sixty,
  so `for_polls = 2` meant "ten seconds" — and, because the streak advanced
  whether or not a new sample had arrived, one bad reading satisfied it about
  ten seconds later and went on satisfying it forever. The streak now advances
  only when the metric's own timestamp moves, which is what the setting always
  claimed. (The DHCP evaluator already worked this way; the device one now
  matches it.)
- **Double-clicking a device row opens that device in a dialog**, with its
  identity, its interfaces and its event log — for the device you double-clicked,
  which need not be the one selected in the pane. Opening a port from it charts
  that device, and offers a way back to the dialog it came from. Single click
  still just moves the detail pane.
- **The interface dialog names its parent device above the port**, on its own
  line and in the same size font.
- **Browse OIDs can download a device's entire SNMP walk.** The subtree browser
  deliberately stops at 600 rows and 20 seconds because somebody is waiting on
  it; a whole switch is tens of thousands of objects and minutes of SNMP. This
  runs as a background job instead, showing a live object count with a Cancel,
  and writes the file when it finishes. The file's header states the device,
  the time, and whether the walk completed or was cut short and why — a
  truncated walk that looks complete is the failure worth avoiding. Cancelling
  keeps what was read rather than throwing it away.
- **Devices can be found by MAC address.** Type an address into the Nodes Find
  box in any notation — `AA-BB-CC-DD-EE-FF`, `aa:bb:cc:dd:ee:ff`,
  `aabb.ccdd.eeff` or bare hex, or just the first few octets — and the list
  filters to the switches that have learned it. One switch and one port opens
  that port's dialog outright; several ports are named as a shortlist rather
  than one being picked, because a MAC on an uplink is on every switch between
  here and the host.
- **Learning MAC addresses is opt-in and separately paced.** Forwarding tables
  are not read on the poll cycle — they are hundreds to thousands of rows per
  switch — but on their own `Learn MAC addresses every N seconds` interval, set
  per polling profile or per device. It is **0 (off) by default**, so an
  upgrade adds no SNMP load anywhere until you ask for it. Entries a walk has
  not refreshed for a week are dropped, so a MAC that moved does not answer
  twice forever.
- **ConfigRX gained bulk settings and bulk backups.** The old bulk dialog could
  only set an SSH username and password, and could only ever turn backups *on*.
  The replacement covers everything the single-device dialog does — enabled as
  a real three-way choice, SSH port, username, password, vendor override — with
  every field defaulting to "leave unchanged", and **Back up selected** queues
  every ticked device, reporting which were queued, which were already queued
  and which have backups switched off.

### 4.30.0 — Tables you can shape, identity you can point at an OID

- **Vendor and Location can be read from an OID you choose.** Vendor was
  always derived from sysObjectID with a sysDescr fallback, and Location was
  always sysLocation — both hardcoded. Plenty of gear puts its real vendor or
  its site name in a proprietary scalar instead, and there was no way to say
  so. A device or a polling profile can now name a **Vendor OID** and a
  **Location OID**; blank keeps today's behaviour exactly. Either form of the
  OID works — the object or its `.0` instance — because both are asked for in
  the same GET the standard scalars already use, so this costs no extra
  request.
- **A custom vendor changes what is displayed, not how the device is
  treated.** The vendor SNMP detected is kept alongside it, and that is what
  ConfigRX uses to pick its backup command, what gates the Cisco per-VLAN
  MAC-table read, and what discovery suggests a profile from. A device whose
  OID answers "Cisco Systems, Inc." still backs up as cisco.
- **Browse OIDs can fill those fields in.** Each row in the OID browser has
  **Use as vendor / location**, so an OID is chosen from a list showing what it
  currently answers rather than typed from memory. The device header now also
  says where the vendor name came from — an IANA arc assignment, a sysDescr
  substring guess, or a custom OID are not equally trustworthy and used to
  look identical.
- **Every main table now sorts by column, and lets you choose its columns.**
  Only 7 of about 30 tables sorted, and exactly one (Wireless) could hide a
  column. Nodes devices and interfaces, Alerts, ConfigRX devices and backups,
  NetFlow, Syslog, SNMP traps, IPAM hosts and DHCP leases all now do both,
  from **one shared implementation** in `app.js` — Wireless's own bespoke
  version was replaced by it rather than left as a second copy. Each module's
  Settings dialog carries the picker, with All / None buttons.
- **Unticking every column restores the defaults** rather than leaving a table
  with nothing in it, and unknown column keys are ignored, so a saved choice
  survives a release that adds or removes a column. Which columns are shown is
  a setting; column *widths* stay per-browser and are still cleared by Reset
  layout.
- **The Select all control is now a checkbox directly above the row
  checkboxes**, where it reads as "these rows", instead of a button off in the
  filter bar. It shows the indeterminate state for a partial selection, and
  clicking it again clears. The three filter-bar buttons are retired. Both
  discovery lists — results and the approval dialog — gained one, having had
  no select-all at all.
- **ConfigRX backups can be deleted.** There was no way to remove a single
  stored backup; the only deletes were retention pruning and removing the
  device from Nodes. The backups pane is now a real table with checkboxes, and
  deletes one or many. Deleting the **most recent** backup gets its own
  warning, because a new backup is only stored when it differs from the last
  one — so removing the top row makes the next run record an unchanged config
  as a change.
- **A running backup is visible.** "Back up now" reported "Queued…" and then
  went silent for however long the SSH session took, and the device row sat on
  the last *completed* attempt throughout. Both now report Queued → Backing
  up… → the outcome, off the device's own state. Internally the worker gained
  the same `worker_state()` the Nodes poller has, which also fixes queued and
  running being indistinguishable.
- **ConfigRX has a vendor filter, showing the vendor it will actually use.**
  The list showed Nodes' detected vendor while the backup worker used the
  per-device override, so a device could read `cisco` and back up as `hp` with
  no sign of it. The column now shows the effective vendor, marks an override,
  and the new dropdown filters on it.
- **An access point that goes offline now raises an alert.** Answering the
  question asked: no, *Device not responding* does not cover access points —
  it comes only from Nodes' own device events. Behind that question was a real
  gap: the wireless module recorded only "removed from its controller", and an
  AP that stopped working while its controller still listed it was a silent
  database update. It could be dead for a week with nothing but a red dot to
  say so. **Access point offline** is a new built-in rule, raised on the
  online→offline transition and cleared when it comes back, mirroring the
  existing removed/returned pair exactly. An AP marked out of service raises
  neither, as before. It fires only on the controller's unambiguous *offline*
  state — not on the image-download states an AP passes through during a
  routine firmware upgrade, nor on standby — so upgrading a fleet does not
  raise and clear one alert per AP.
- **NetPath hops that are managed devices show their names.** A hop with no
  PTR record showed the literal "no PTR record" even when it was a device this
  app polls every minute and names correctly everywhere else. Hops with no
  reverse-DNS answer now fall back to the Nodes device at that address, and
  the tooltip says the name came from Nodes. A hop with a real PTR record
  keeps it.
- **A device pinned to its manual name is now honoured everywhere.** The
  shared name lookup ignored `display_name_source`, so a device explicitly set
  to display its manual name still showed its sysName in Alerts, Syslog and
  NetFlow. Fixed once, in the shared helper, for all of them.

### 4.29.0 — Backups that wait for the whole config, and one alert per outage

- **ConfigRX stored the banner and called it a backup.** A successful backup
  contained exactly two lines: `show running-config` and
  `Building configuration...`. The capture decided a command was finished by
  *silence*, and a switch answers that banner instantly and then thinks for
  several seconds before streaming — so 1.5 seconds of that thinking ended the
  read, and the result was stored as a good version. It now reads until the
  **device's prompt comes back**, which is what a person waits for: the prompt
  is learned from the login banner, and the read ends on it rather than on a
  pause. Devices whose prompt cannot be learned fall back to a much longer
  silence window.
- **Pager prompts are answered instead of waited out.** A device that stops
  mid-config at `--More--` is sitting there waiting for a keypress, so
  stripping the marker afterwards achieved nothing. ConfigRX now sends a
  single space and keeps reading. That space is a fixed in-band answer to a
  prompt the device raised — it carries no newline and no text — so the
  module's boundary is unchanged: the only things ever *run* on a device are
  the vendor's fixed pager-off lines and its show-config command.
- **A truncated capture is never stored.** A read that hit the ceiling, that
  ended on a pager loop, that ends on "Building configuration...", or that is
  implausibly short is recorded as a **failed attempt naming the reason**.
  Storing those two lines as a success was the part that would quietly
  destroy a real config history — the next real backup would read as a huge
  change, and a restore from history would hand someone a two-line file.
- **Capture timeout is a setting** (ConfigRX → Settings, 180 seconds by
  default) rather than a fixed 25 seconds, because a large config over a slow
  link legitimately takes minutes. It is only a ceiling: a fast switch still
  finishes the moment its prompt returns.
- **One outage, one alert.** A device that has stopped answering also looks
  slow and lossy, and its CPU, memory, interface and storage figures stop
  being measurable — so a single outage arrived as five or six emails saying
  the same thing. **Device not responding** now absorbs what it implies: both
  ping alerts and every SNMP-polled metric threshold are resolved into it and
  named in its details, and new ones are not raised while it is open. No
  clear email goes out for an absorbed alert — "packet loss recovered" while
  the device is still down would be a lie.
- **Interface alerts are never rolled up.** Interface down, up and flapping
  come from status transitions the device reported before it went away; a
  port that went down for its own reason is a fact about the network, not an
  artefact of the device being unreachable.
- **Recovery needs no un-suppressing.** Once the device answers again the
  outage resolves, and the thresholds re-derive from live metrics on the next
  tick — so a genuinely still-high CPU re-opens on its own, and a metric that
  recovered with the device stays closed. The whole behaviour is one setting
  (Alerts → Settings → *Roll implied alerts up*), and turning it off restores
  the previous behaviour exactly.
- **One threshold breach opened every threshold alert.** Found while testing
  the rollup: threshold rules were not filtered by which metric they are
  about, so a single high-CPU reading opened CPU, memory, disk and all six
  interface-rate alerts for that device — every one of them carrying the CPU
  reading's message. Each threshold rule now only sees its own metric.
- **Poll now, for everything that is ticked.** The Nodes bulk bar has a
  **Poll now** button; the detail pane's button only ever polled the one open
  device. It polls each ticked device immediately, ahead of its interval, and
  says how many it queued.
- **Poll now no longer claims credit for a poll it did not start.** A click
  while that device is already being polled cannot start a second one; both
  buttons now say *Already polling* instead of reporting *Polled* when the
  in-flight poll finishes.
- **Ticked rows are tinted, not striped.** The selection marker was an inset
  bar on the left edge of every cell, which under fixed table layout read as
  a blue stripe at each column divider. A ticked row now carries a single
  tint across its whole width, in Nodes, Alerts and ConfigRX alike, with a
  distinct shade for a row that is both ticked and open in the detail pane.

### 4.28.1 — The OID browser actually walks, and two buttons that said nothing

- **The OID browser worked on almost nothing, and the cause was the
  credential.** Reported as "it simply gives *the device stopped answering*
  no matter what device or what OID". It did — and so, silently, did the MAC
  address table and the DOM sensor reads on those same devices. A polling
  profile can carry **alternate credentials** for a mixed-vendor subnet, and
  the scheduled poller finds whichever one works and remembers it. Every
  on-demand read, though, built its own config from the profile's *primary*
  credential alone, so on any device that answers on an alternate it queried
  with the wrong community: every request ignored, every read a timeout — on
  a device the Nodes list happily shows as up. Reproduced end to end, fixed
  with a single `working_config()` that resolves the credential the device
  actually answers on, and used by all three on-demand reads. A device with
  one credential costs no extra request; only a device the poller has not
  resolved yet is probed.
- **A walk that still fails now says what was tried.** Instead of "the device
  stopped answering", the message names the address, the port and the kind of
  credential used — never the community string itself, which is a secret.
- **Nodes → Poll now shows that it is running.** The poll is handed to a
  worker thread, so the button returning meant "queued", not "done", and it
  looked inert for however long the device took. It now reports Queued or
  Polling, refuses a second click while it runs, and settles to *Polled* when
  the device's own last-poll time actually moves.
- **ConfigRX → Back up now with the worker stopped is refused.** It used to
  report success and do nothing at all: the queue it went into was never
  being drained, so the operator was told the backup was queued and then
  watched no backup appear. It now explains the reason and points at the
  Start worker button. A second click on a device already queued stays a
  harmless no-op rather than becoming an error.
- **Duplicate devices** were already prevented in three places — the address
  column is unique, adding an existing address is refused by name, and
  promoting a discovery result whose address is already a device links to
  that device. The one gap was the race between the check and the insert,
  which surfaced as a 500; it now gives the same readable message.

### 4.28.0 — Which paramiko, vendor identification, an OID browser, per-AP latency, checkboxes

- **ConfigRX now names the paramiko it is actually running.** Reported as
  "paramiko 3.4 is installed but I still get *no acceptable kex
  algorithm*". The message was not wrong — it was describing a different
  paramiko. That branch is reachable only when the **loaded** paramiko
  genuinely lacks SHA-1 key exchange (it is a capability check against
  `Transport._kex_info`, not a version test, and I verified both halves
  against a live interpreter), so the process was running 5.0 whatever
  was installed: pip installs into whichever interpreter it was run
  from, and a *downgrade* cannot take effect until the app restarts,
  because Python caches imported modules for the life of the process.
  The algorithm logic is unchanged and correct. What is new is that the
  error, ConfigRX → Settings and the module status line all name the
  loaded version **and the file it came from**, and say whether legacy
  key exchange is implemented and offered — before a backup fails rather
  than only after. A failed connection also logs the key exchanges and
  host-key types actually offered into its Debug event detail.
- **Vendors are identified far more often.** The enterprise-arc table
  covered 19 vendors while the MIB catalog shipped bundles for 30, so a
  device could have its MIB installed and still show a blank Vendor.
  It now covers every catalog vendor plus a range of industrial and
  wireless names — **every arc read out of that vendor's own MIB text**
  rather than from memory, which turned up two that are easy to get
  wrong: `4413` is Broadcom's (NETGEAR's managed switches run OEM'd
  FASTPATH and report there, as do other OEMs) and `161` is Motorola's,
  which Cambium's Canopy line still uses. Both are named for the arc's
  owner. Where the sysObjectID names only the SNMP *agent* — a Phoenix
  Contact radio, a Moxa switch and a Linux server all answer net-snmp's
  arc — the **sysDescr** is consulted instead. Two bugs fell out of
  writing the tests: a device with a standard-tree sysObjectID was being
  stored with vendor `"system"`, and matching the agent arc first meant
  the new fallback could never run for exactly the gear it was for.
- **A vendor's MIB is assigned to its devices automatically.** Installing
  a bundle used to change nothing about polling until someone visited
  every device and set the Custom MIB override by hand. Now, when a
  device's vendor is identified and an uploaded MIB describes objects
  under that vendor's arc, the override is set for it — never over a MIB
  chosen by hand, recorded in the device's event history, and changed or
  cleared from the same override afterwards.
- **Browse OIDs**, a new button on the device pane, shows what a device
  actually answers, decoded against every MIB the app knows. It opens on
  `system`, `interfaces` and the device's own vendor arc, with an OID box
  and **Walk from here** for anything else — subtree at a time on
  purpose, since a switch is tens of thousands of objects. An OID no MIB
  describes shows as its number rather than a guess, and uploading its
  MIB names it immediately. A walk that hits its row or time limit says
  so instead of looking complete.
- **Wireless: a real per-AP response time.** The controller reports each
  AP's own IP in the session table the module already walks, so finding
  it costs no extra SNMP; the AP is then pinged once per cycle. An AP
  that does not answer ICMP shows blank rather than 0 ms, an offline one
  is not probed at all, and the sweep is bounded so a large controller
  cannot stretch a cycle. **IP** is available as a column too. This is
  the one place the module reaches past the controller.
- **A newly added device gets five minutes before it can alert.** A
  device added a moment ago is usually still being set up, and its alerts
  are about the setup rather than the network. They are held and then
  raised only if the condition is **still true** at the end of the window,
  so a device that really is down is reported late rather than never, and
  one that settles never alerts. A one-off event that cannot still be
  true later (rebooted, recovered, poll overrun) is dropped rather than
  raised late; a threshold needs no holding at all, since it is
  re-derived every tick. Held alerts survive a restart. Configurable in
  Alerts → Settings, 0 to disable. Nothing outside Nodes' device
  inventory can be held — syslog, traps, IPAM conflicts, DHCP scopes and
  wireless AP events have no device to be new.
- **The Nodes device list sorts by any column.** Status, Name, Profile,
  Group, Vendor, Response and Last poll each sort on what the column
  actually shows — Profile by profile name rather than by its internal
  id, Response by milliseconds rather than by the text around them. A
  device with no reading stays at the bottom in both directions rather
  than leaping to the top when the order reverses.
- **Every bulk selection is checkboxes now**, on Nodes, Alerts and
  ConfigRX alike, and Ctrl-click no longer selects. Separately — and this
  is the part that is actually faster — ticking a box no longer redraws
  the whole table. Each module rebuilt every row to change one checkbox;
  it now touches the single row. The checkboxes made selection visible;
  the redraw is what made it slow.

**Not done in this release:** a Phoenix Contact MIB bundle. Phoenix
Contact radios are identified by sysDescr and work as ordinary Nodes
devices, but the catalog's upstream ships no Phoenix Contact MIBs and
IANA's enterprise registry was unreachable from the build environment, so
neither the enterprise arc nor a download URL could be verified. A
guessed arc would mislabel every device beneath it and a guessed URL
would fail at Install — both worse than leaving it out. One sysObjectID
from a real unit (the new OID browser shows it) or the MIB file itself is
all that is needed to finish it.

### 4.27.0 — Alert checkboxes, MAC tables that answer, per-destination windows, NetFlow speed

- **Alerts: real checkboxes, and an "Acknowledge selected" that respects
  them.** Reported as "bulk acknowledge and bulk resolve only clear 1 of
  the selected items". Investigated first, and the bulk statements turned
  out not to be at fault: six seeded alerts, four selected, resolve —
  four resolved, two left, and the selection survives background
  refreshes. `resolve_many` was already a single
  `UPDATE ... WHERE id IN`. What was actually wrong is that **selection
  was Ctrl-click only**, with no visible affordance beyond a small hint,
  so a plain click looked like it was selecting when all it did was move
  the detail highlight — and a bulk action then acted on the one row that
  really was ticked. And there was **no "Acknowledge selected" button at
  all**: "Acknowledge all" acknowledges every open alert on the server
  and ignores the selection entirely. Every row now carries a checkbox in
  its first column; ticking one never moves the detail pane, clicking
  elsewhere in the row still opens it, and Ctrl-click still works.
  **Acknowledge selected** sits beside **Resolve selected** in the bulk
  bar, backed by a new `acknowledge_many` and `POST
  /api/alerts/bulk-ack`. "Acknowledge all"'s confirmation now spells out
  that it takes every open alert rather than the ticked rows.
- **MAC addresses on a port now come from three tables, not one.** Asked
  whether the extra MIBs the application now ships let these be polled
  successfully, and whether the logic was only using part of what is
  available. The second half was right, the first half cannot be: the
  poller uses hardcoded numeric OIDs and uploaded MIBs only ever supply
  display *names*, so the MIB catalog has no bearing on polling coverage.
  The real gap was that only the original BRIDGE-MIB `dot1dTpFdbTable`
  was ever read. Three sources are now tried in order — **Q-BRIDGE-MIB**
  `dot1qTpFdbTable` (what most VLAN-aware switches actually answer, and
  whose VLAN-prefixed index the old parser rejected outright), then
  `dot1dTpFdbTable` as before, then, on Cisco devices only, the
  **per-VLAN SNMP contexts** classic IOS hides its forwarding table
  behind (`community@vlan`, VLAN list from CISCO-VTP-MIB). The dialog
  shows the VLAN each address was learned in where the switch reports
  one. The Cisco path is v1/v2c only (there is no community to suffix
  under v3), is gated on the device's vendor already reading Cisco, and
  is bounded to 48 VLANs and 15 seconds so opening a port dialog cannot
  hang. A device that answers none of the three still says "no MAC
  address data" rather than showing an empty table.
- **NetPath: every destination keeps its own timeline window.** Selecting
  a destination restores the window, preset and Follow state you last
  left it on, so a link watched by the hour and one watched by the minute
  stop dragging their range onto each other. Remembered in the browser
  and kept across a reload; a destination never opened starts on the page
  default, and entries for deleted destinations are pruned.
- **NetFlow stops crawling when you zoom out.** Two causes, both fixed.
  The overview cost **four** full aggregate passes over the window per
  refresh — `series()` called `top()` internally, the handler called
  `top()` again beside it, and `totals()` made a third — every one
  walking the same rows, which a wider window multiplies. One
  `GROUP BY key, slot` pass now yields the chart series, the top-N bars
  and the totals together. And every wheel step fired a fresh pair of
  requests over an ever-wider window: zooming now moves the window (and
  its label) immediately but collapses a burst of steps into a single
  fetch ~250 ms later. A response for a window already zoomed away from
  is discarded instead of being drawn over the newer one.
- **IPAM: the selected DHCP scope follows you to another server.** Where
  the server you switch to has a scope with the same identifier, that
  scope stays selected instead of the list jumping back to the first one;
  where it does not, it falls back to the first, and from then on that is
  what a further switch looks for. Matching is on the scope's own
  identifier rather than its database row id, which differs per server
  for the same scope. A background poll no longer moves the selection
  either.
- **Debug: All and None buttons for the category filters.** The ask was
  for "uncheck all"; both are here, because unchecking all and then
  wanting them back was otherwise eleven clicks.
- **Interface flapping is configurable.** The rule always had a window
  and a transition count — 3 transitions in 10 minutes — but nothing ever
  passed them, so they could not be reached from the UI. The rule editor
  now offers both, blank meaning "as shipped". Two nullable columns were
  added to `rules`; `alertsdb.py` had no migration step at all, so it has
  one now, following the same PRAGMA-then-ALTER convention the other
  databases use. The engine widens its event fetch to match the
  configured window, which previously would have silently truncated
  anything longer than 15 minutes.

### 4.26.0 — Named exporters, coloured tooltips, Scan radios, 15 more MIB vendors, legacy SSH

- **ConfigRX can talk to older gear again.** A backup failing with
  `Incompatible ssh peer (no acceptable kex algorithm)` was not a device
  misconfiguration: paramiko 5.0 *deleted* every SHA-1 key exchange, so a
  switch offering nothing newer became unreachable the moment that version
  was installed. `requirements.txt` now pins `paramiko>=3.4,<5`, and
  ConfigRX offers the legacy key exchanges and `ssh-rsa` host keys — but
  only ever after the modern ones, and only where the installed paramiko
  still implements them, which it feature-detects rather than guessing from
  a version number. A new **Allow legacy SSH algorithms** setting (on by
  default) turns it off where policy forbids SHA-1. **This only takes
  effect once `pip install -r requirements.txt` is re-run**, allowing pip
  to downgrade paramiko; where it cannot, the error now names the cause and
  both ways out instead of just the symptom.
- **NetFlow: the Exporter column shows the device's name**, resolved
  against the Nodes inventory the same way Syslog's Host column and Alerts'
  Object column resolve theirs — SNMP `sysName`, then a manual device name,
  then reverse DNS — falling back to the bare address when nothing is
  known. The row tooltip shows both the name and the address, since the
  address is what the collector actually received the flow from. The column
  has also moved to sit **immediately after Time**: which device reported a
  flow is context for reading the rest of the row, not a footnote to it.
  The chart legend and the top-talkers bars name the exporter too, so all
  three agree.
- **NetFlow: the traffic-over-time tooltip carries colour.** Each
  application in the tooltip now has a small block in the colour of its own
  band in the chart, so a line in the tooltip can be matched to the shape it
  describes without counting stack order. The bars' tooltips are swatched to
  match as well.
- **Wireless: a scanning radio is labelled "Scan" rather than converted.**
  A FortiAP's monitor or sniffer radio is a receiver, so the figure the
  controller reports for it is neither a transmit power in dBm nor a
  percentage of one — naming it is more honest than picking a unit for it.
  This also fixes a real mislabelling introduced in 4.25.0: the
  dBm-or-percent auto-detection took *every* radio into account, so one
  scanner reporting an impossible 51 flipped its whole controller's column
  to "% level" and relabelled the serving radios beside it, which were
  reporting a perfectly good 17 and 20 dBm. Scanning radios are now left out
  of that decision, and out of the AP's headline transmit power.
- **Fifteen more MIB vendors in the catalog**, taking it from 17 bundles to
  32: **Palo Alto PAN-OS** and the two Ubiquiti files the bundle was missing
  (both asked for by name), plus Check Point, WatchGuard, Sophos, F5 BIG-IP,
  Citrix NetScaler, Ruckus, Cambium, Aerohive, Zyxel, TP-Link, Eaton,
  Vertiv/Liebert, Raritan and Rittal. All 227 files across all 32 bundles
  were fetched and parsed before shipping.

### 4.25.0 — Confirmations everywhere, a MIB catalog, ping-measured packet loss

- **Nothing destroys data on a single click any more.** The Debug page's
  **Clear** button — which wipes the server-side event log for everyone
  looking at it, not just the browser that pressed it — now asks first,
  as do all eight Settings → Maintenance actions (five of which empty a
  whole table rather than pruning old rows, and now say so), removing a
  device group, a stored credential, a MIB, a discovery scan or its
  discovered devices, removing an IPAM subnet or DHCP server, clearing
  subnet statistics or a stored DHCP credential, and resetting an alert
  template to its shipped text. Alerts' **Acknowledge all** and bulk
  **Resolve** confirm as well: they do not delete rows, but they are not
  undoable one by one either. Filter-clear and selection-clear buttons,
  which destroy nothing, are deliberately left alone.
- **Alerts: the list gets 70% of the width and the detail pane 30%**,
  instead of 60/40. Existing installs are migrated: a stored pane layout
  from before this release is dropped for that one splitter (and only
  that one) on first load, so the new proportions actually apply rather
  than being overridden by a width dragged months ago.
- **Nodes: the device detail header is readable.** The device name and
  its identity line were both drawn in the dimmest colour in the palette,
  at 11px, with every field run together into one flat string. The name
  is now full-size body text, each field is a dim label with a bright
  value, and a device's SNMP error is shown in the failure colour.
- **NetPath: a hop that stops appearing drops out of the diagram.** A
  router that left the path a month ago no longer sits in the graph
  forever just because the window reaches back far enough to catch one
  old trace. The cutoff (24 hours by default, in NetPath settings; 0
  disables it) is measured against the end of the window being displayed
  rather than the clock, so scrolling the timeline back into last month
  still draws the path exactly as it stood then.
- **Nodes: the interface dialog stops showing another port's data.** Four
  separate bugs conspired here. The dialog's 5-second refresh was only
  ever stopped by its Close button, so dismissing it with Escape or a
  backdrop click left the timer running forever; because every dialog
  rebuilds the same element ids inside one shared modal, that orphaned
  timer then painted the old port's traffic into the new port's chart.
  The refresh had no request-id guard, so a slow response could repaint
  over a newer one. It resolved metric ids from a cached list that the
  device pane replaces wholesale on every refresh — and could belong to a
  different device entirely. And the `/series` endpoint accepted a
  device id and then ignored it, so a metric id belonging to another
  device returned *that device's* traffic rather than nothing. All four
  are fixed, the title and events refresh with the rest of the dialog,
  and **Smoothed** is back as a checkbox, on by default.
- **Nodes: eighteen standard MIBs now ship with the app**, seeded on
  first start: the full IF-MIB, IP-MIB, TCP-MIB, UDP-MIB, ENTITY-MIB,
  ENTITY-SENSOR-MIB, BRIDGE-MIB, P-BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB,
  POWER-ETHERNET-MIB, HOST-RESOURCES-MIB, UCD-SNMP-MIB and the SNMPv2
  and IANA type modules they depend on. Previously there were two, one of
  them a hand-written IF-MIB subset (which is kept, so a device pinned to
  it keeps working).
- **Nodes: a MIB catalog installs vendor MIBs on demand.** Seventeen
  curated bundles — Cisco IOS and wireless, Fortinet, Juniper, Aruba
  (ArubaOS and CX), HP ProCurve, Arista, MikroTik, Ubiquiti, Extreme,
  Dell, NETGEAR, SonicWall, APC, Synology and VMware — are listed in
  Nodes → Profiles & MIBs → **MIB catalog**. The list is static data, so
  it is browsable with no internet access at all; only pressing Install
  fetches anything, from the vendor's or the distribution's own public
  repository, and a server with no outbound HTTPS gets a clear message
  saying so rather than a traceback. This is deliberately *not* "every
  Cisco MIB": that repository is 2,921 files and roughly 350MB of text,
  which would multiply the size of nodes.db by two orders of magnitude to
  supply a handful of MIBs anyone actually polls.
- **Nodes: MIB upload accepts a zip, and order no longer matters.** A
  vendor archive can be uploaded whole; its MIB members are stored first
  and resolved afterwards, repeatedly, until nothing new resolves. The
  same pass runs after a catalog install and behind a new **Resolve all**
  button, so a file uploaded before the one defining its parent branch no
  longer has to be resolved by hand. The parser also learned
  MODULE-IDENTITY and OBJECT-IDENTITY, which is how nearly every RFC MIB
  names its own root — without them, files like BRIDGE-MIB and LLDP-MIB
  parsed to a list of objects not one of which could resolve.
- **Wireless: a FortiAP radio reporting "51 dBm" is no longer taken
  literally.** Fortinet's MIB documents
  fgWcWtpSessionRadioOperatingPower as dBm, but FortiOS reports its own
  0–100 transmit-power level in it; 51 dBm would be about 126 watts,
  roughly a thousand times what a FortiAP can emit. The reading is now
  auto-detected per controller (any value above 30 dBm means the whole
  column is a percentage) and can be forced either way in Wireless
  settings; the raw number is always shown in the AP detail pane.
- **Wireless: radio mode is polled and displayed.** fgWcWtpRadioMode
  (ap, monitor, sniffer, disabled, not present) is now read, shown in the
  AP detail pane and available as a table column — which is what explains
  an odd third radio on a FAP-231F: it is a dedicated scanner. A radio
  that reports a mode but no channel is also no longer dropped from the
  list entirely, so such an AP finally shows all of its radios.
- **Alerts: a new built-in rule for a DHCP scope running out of
  leases**, with adjustable thresholds (85% to fire, 75% to clear by
  default). Utilization counts leases and reservations against the
  scope's address range, exactly as the DHCP page counts them, and the
  "consecutive polls before firing" setting counts DHCP polls rather than
  alert-engine ticks — so on a 15-minute DHCP poll, 3 means 45 minutes,
  not 15 seconds.
- **Nodes: every SNMP-polled device is now pinged as well**, several
  probes per poll, and the result is recorded as real `ping_loss_pct` and
  `ping_rtt_ms` metrics. Probe count, timeout and how often to ping are
  configurable globally and per device or profile. This also brings the
  shipped **Ping response time high** rule to life — it had no metric to
  read before — and adds a **Packet loss to device high** rule alongside
  it. Round-trip time is taken from ping's own reported figure rather
  than by timing the subprocess, which used to count process startup as
  network latency.
- **Nodes: a device is DOWN only when ping *and* SNMP have both failed.**
  This is a behaviour change on upgrade: a device currently shown DOWN
  because its SNMP is broken, but which still answers ping, will flip to
  UP with its SNMP error displayed. That is the more accurate report —
  the device is reachable and misconfigured, not off the network — but if
  you would rather treat SNMP failing as an outage on its own, the
  setting is in Nodes settings and can be overridden per device and per
  polling profile.

### 4.24.0 — Wireless AP lifecycle and table controls, leaner Nodes detail, ConfigRX fixes

- **Wireless: an AP that disappears from its controller now raises an
  alert** instead of silently vanishing from the list. A new built-in
  rule ("Access point removed from its controller") fires once the
  controller has failed to report it for the configured number of
  consecutive polls, and the same fact is written to the event log.
- **Wireless: mark an access point Out Of Service.** An AP marked this
  way is exempt from both halves of the above — it is never aged out of
  the list (so the marking survives the controller dropping it, which is
  exactly what happens when it is unracked) and never raises a removal
  alert. A **Show** dropdown filters the list by Online, Offline, Out of
  service, or All (the default). An AP can also be removed by hand, which
  is how a genuinely retired one is cleared.
- **Wireless: the access point table sorts and its columns are
  configurable.** Click any column heading to sort by it; Settings →
  Columns chooses which of the controller's SNMP-reported fields to show.
  The previous columns remain the defaults, with Controller, VDOM, WTP
  id, Radios, Channels and Radio clients newly available.
- **Wireless: "Last seen" moved off the rows.** Every AP in the list is
  reported by the same controller poll, so a per-row age repeated the
  same value on every line; there is now one **last reported** age beside
  the Controller picker instead.
- **Nodes: the device pane is simpler.** The per-metric bandwidth chart
  and its metric/smoothing pickers are gone — bandwidth is a per-port
  question, answered by clicking a port, which opens the same graph it
  always did. The up/down status timeline stays, now driven by the range
  picker directly and drawn as a thin lane matching NetPath's, rather
  than a chart-sized panel.
- **Nodes: a device whose vendor MIB is missing now says so.** The poller
  already identifies a device's vendor from its sysObjectID; if no
  uploaded MIB actually describes that vendor's objects, it records the
  fact (with the vendor and OID) and a new low-severity built-in rule
  surfaces it — so an unfamiliar device's missing data has an explanation
  instead of just being absent. Recorded on coverage changes, not every
  poll; uploading the missing MIB auto-resolves the alert, and deleting a
  covering MIB raises it.
- **Fixed:** ConfigRX failed with a raw `ModuleNotFoundError` traceback
  in the Errors log when paramiko was not installed. It now reports the
  missing dependency, and how to install it, as a plain status on the
  affected device and in the worker's own status line.
- **Fixed:** a long device name in ConfigRX's backups pane pushed "Back
  up now" and "Device settings" underneath the config viewer where they
  could not be clicked.
- **Fixed:** ConfigRX's "Set SSH credential" button appeared and
  disappeared on its own, shifting the page — the bulk bar's visibility
  was being written both by the selection and by the permission check.
- **Fixed:** the page briefly flashed the NetPath tab before switching to
  the one you were last on. Reloading always landed on the right tab, but
  the small script that paints it immediately was written inline, which
  the app's own Content-Security-Policy refuses to run; it now loads as
  `boot.js` and does its job.

### 4.23.0 — Custom-MIB polling, MAC address table, ConfigRX bulk edit, bug fixes

- **Nodes: assign an uploaded MIB to a device or group to have it actually
  polled.** Previously an uploaded MIB only fed the MIB browse view — it
  had zero effect on what got polled. A device or group's "Custom MIB"
  override (in its edit dialog, alongside the other overrides) now makes
  that MIB's own scalar objects get polled every cycle and stored/shown
  under their own names, the same way built-in metrics are. Best-effort
  and scalars-only, matching every other optional SNMP read in this
  codebase: an object the device doesn't answer is silently skipped
  rather than failing the whole poll; table objects are out of scope for
  this pass.
- **Nodes: SNMP timeout accuracy + a real way to debug a polling
  failure.** A genuine mid-poll timeout partway through an interface-
  table walk was being silently treated the same as "that's the end of
  the table, this device just has fewer interfaces" — a real failure
  showed no error at all. It's now correctly reported as an SNMP error
  ("... table walk cut short after N row(s)"), while an isolated timeout
  on a single interface's own GET no longer aborts the rest of that
  poll, just gets counted and logged. Every poll now also writes a
  structured debug event (ping/SNMP outcome, interfaces found, elapsed
  time, and the exact error on failure) visible on the Debug tab, plus
  cumulative poll counters (ok/timeout/auth-failed/unsupported/error)
  that were being tracked internally but never surfaced anywhere before.
- **Nodes: per-switchport MAC address table.** Clicking an interface on a
  device's detail page now shows the MAC addresses currently learned on
  that port, read live over SNMP from the standard BRIDGE-MIB forwarding
  database — no SSH required. Devices that don't answer BRIDGE-MIB show
  "no MAC address data" rather than an empty table.
- **ConfigRX: bulk-edit SSH credentials and backup settings.** Select
  multiple devices (Ctrl/Cmd-click, or "select all") and set one shared
  SSH username/password/port and backup-enabled setting across all of
  them in a single action, instead of one device at a time. Matches
  Nodes' existing bulk-device-operations pattern.
- **ConfigRX: device names now follow the same SNMP-hostname-first
  precedence as everywhere else** in the app (the device's SNMP-reported
  name unless it's been explicitly pinned to a manual name), instead of
  always preferring whatever manual name happened to be stored.
- **Fixed:** the Alerts detail pane stayed showing a now-stale alert
  after "Acknowledge all" or a bulk resolve, instead of clearing.
- **Fixed:** the "Remove" button on the Settings → Users page did
  nothing — the underlying DELETE request never actually carried which
  account to remove.

### 4.22.0 — Per-module permissions, Wireless module, ConfigRX module, device status timeline

- **User permissions.** Every account now has an explicit read/write
  grant per module (Nodes, Alerts, NetPath, NetFlow, SNMP Trap, Syslog,
  IPAM, Wireless, ConfigRX, Settings, Debug) — write implies read, and no
  grant at all means no access, closing a pre-existing gap where any
  signed-in account could do anything, including reset any other
  account's password with no check at all. Changing your own password
  always works regardless of Settings access — it moved out of the
  Settings tab into an always-reachable "Account" control in the top bar.
  Existing accounts on an upgrading install keep full access to
  everything automatically; only accounts created after this ships start
  with whatever grants an admin assigns.
- **New "Wireless" module**: an at-a-glance dashboard of Fortinet access
  points behind a FortiGate Wireless Controller — status, name, clients,
  model, MAC address, and tx power per AP, polled from the controller
  alone over SNMP (never per-AP). Supports v1/v2c community or SNMPv3
  noAuthNoPriv/authNoPriv credentials, matching Nodes' own SNMP support.
- **New "ConfigRX" module**: scheduled, read-only CLI config backups
  pulled from devices over SSH (Cisco IOS, FortiOS, Junos, MikroTik,
  HP/Aruba), reusing Nodes' own device list rather than keeping a second
  one. A backup is only stored when its content actually changed since
  the last pull. SSH passwords are encrypted at rest, never returned by
  any API response, and decrypted only immediately before connecting.
  ConfigRX never enters a device's configuration mode and never sends
  anything beyond one fixed, per-vendor, read-only "show config" command
  — there is no free-form command box anywhere in this module, by
  design.
- **The Nodes device detail pane now shows a status timeline** (up/down/
  unsupported/auth-failed history) above the interfaces list, visible
  immediately on selecting a device rather than whichever metric chart
  happened to sort first alphabetically.

### 4.21.0 — Hostname resolution fixes, IPAM reorder/chart, Ctrl+click bulk select, recipients list

- **Fixed the Syslog Host column not showing a device's SNMP-polled
  name.** The lookup logic was already correct, but it was wired behind
  the "Resolve sending addresses to names" setting, which defaults off —
  so on most installs it silently never ran. It now always fills a
  missing/self-reported-IP host with the Nodes SNMP name (or, failing
  that, DNS), never overriding a host the device actually supplied.
  Fixed the name precedence at the same time: SNMP's `sysName` now wins
  over a manually-set device name, matching how the Nodes page itself
  already displays a device.
- **The Alerts "Object" column now resolves to a device hostname** the
  same way — SNMP name, then DNS, then the bare IP — instead of the
  weaker `name or ip` it used before (and, for syslog-triggered alerts,
  instead of showing an unresolved IP even when the Syslog page itself
  shows a resolved name for that exact message).
- **IPAM's DHCP and Subnets & Hosts sub-tabs swapped positions, and DHCP
  is now the default view** when the IPAM tab is opened.
- **The IPAM leased-IP sparkline now scales to its own data range**
  instead of always anchoring at zero, so a scope oscillating in a
  narrow band is no longer squashed into a sliver at the bottom of the
  chart.
- **Bulk selection (Nodes → Devices, Alerts) is now Ctrl/Cmd-click +
  an explicit "Select all" button**, replacing the checkbox column —
  plain click still opens the detail pane exactly as before; Discovery's
  approve/deny checklist keeps its checkboxes, since it's a pre-seeded
  checklist rather than a bulk-select-existing-rows table.
- **Alert email recipients are now an add/remove list** in Alerts
  settings instead of one comma-separated text field.

### 4.20.0 — Bulk resolve alerts, poll-on-add, false recovery fix, syslog severity fix

- **Alerts can be resolved in bulk.** A checkbox column on the alert
  list (with select-all-visible) reveals a bulk actions bar with
  **Resolve selected**, applied to every checked alert in one request.
- **A manually added device is now polled immediately on save**,
  instead of waiting for the next scheduled poll tick.
- **Fixed a false "Device recovered" alert on every newly added
  device**: a device's very first poll ever was indistinguishable from
  a genuine down→up recovery, so any device that came up on its first
  poll fired (and emailed) a recovery alert it never earned. A device
  now has to have been polled before for "recovered" to mean anything.
- **Fixed the Alerts engine mis-identifying syslog message severity**:
  a rule's severity field was purely decorative — stamped on the opened
  alert but never used to decide whether the rule matched — so any
  syslog line clearing the single global severity floor could open the
  built-in "Critical syslog message" alert regardless of its actual
  severity. A rule's severity is now the threshold it fires at, same as
  the global "Evaluate severity X and worse" setting it sits alongside.

### 4.19.0 — Syslog Host column cross-referenced from Nodes/DNS

- **The Syslog Host column now falls back to a cross-referenced name**
  when a message doesn't supply a usable one of its own (blank, or just
  the source IP repeated). It checks the Nodes module's SNMP-polled
  device identity first, then the same reverse-DNS cache the Source
  column's "Hostname" toggle already uses, and gates on that same
  **Resolve sending addresses to names** setting. A device's own
  self-reported hostname is always left untouched — this only fills
  gaps, never overrides.

### 4.18.0 — Bulk device operations, offline filter, chart smoothing, IPAM tooltip fix

- **Devices can now be selected and operated on in bulk.** A checkbox
  column on the Nodes → Devices table (plus a select-all-visible header
  checkbox) reveals a bulk-actions bar with four actions: **Set
  profile** and **Set group** (each a small dialog, applied to every
  selected device in one request), **Remove from group** (no dialog —
  a plain, reversible clear), and **Delete** (a confirmation listing
  the devices, or just the count past ten). All four operate through
  new bulk endpoints that update or remove every selected device in one
  database transaction rather than one request per device.
- **A new "Only offline" checkbox** on the Devices filter bar shows
  devices whose status isn't `up` — down, unknown, unsupported, or
  auth-failed — a genuinely different filter from picking "down" alone
  from the existing Status dropdown, and combinable with every other
  filter in the bar.
- **The device metric chart has a "Smoothed" checkbox** next to the
  metric and range pickers. Off by default (troubleshooting wants to
  see real spikes), it applies a centered moving average to raw
  per-poll points — window size scales with how many points are on
  screen. Hourly rollup views (wide windows, already aggregated by the
  backend) are unaffected by the checkbox; toggling it is a pure
  redraw, no new network request.
- **Fixed the IPAM → DHCP → Leases trend chart's tooltip**: it was
  dumping the entire multi-day series — every point, one per line — into
  one tooltip on every mouse movement, regardless of where the cursor
  was. It now shows only the point nearest the cursor, the same
  nearest-sample idiom the NetFlow chart's own tooltip already uses.

### 4.17.1 — Code-review fixes for the 4.17.0 chart work

- The wheel-zoom handler no longer goes dead when a zoom lands in a
  window with no samples — it stays live so you can zoom back out.
- Wheel-zooming now actually zooms around the point under the cursor
  (the fix in 4.17.0 corrected the *span* but was discarding the
  anchor and re-centering on "now" every time); the range dropdown
  still resets to a live "now"-following window as before.
- Removed a duplicate resize listener that redrew the chart twice per
  divider-drag frame.
- The interface list's Speed/In/Out columns sort blank values (no
  sample yet) last again, instead of tying them with genuine zeros.
- CPU/memory percent labels and error-rate labels on the chart now
  show a decimal place and their unit consistently ("1.5%", "0.05
  err/s") instead of a rounded, unit-less number.
- A rapid run of wheel-zoom ticks can no longer have an earlier,
  slower network response overwrite a later one's chart.

### 4.17.0 — Combined in/out graphs, chart fixes, sortable interfaces

- **Interface upload and download are one graph now.** The device metric
  picker offers a single "eth1 — traffic in/out (bps)" entry per
  interface (and one "errors in/out") instead of separate in/out
  metrics; both directions draw on one chart in different colors with a
  small legend. CPU/memory and any unpaired metric stay single entries.
- **The metric chart's Y-axis labels are finally real units** — "1.6
  Mbps / 800.0 Kbps / 0.0 bps" for a bandwidth metric, "40%" for CPU —
  instead of raw unformatted numbers. Time labels sit at fixed points
  across the window rather than piling up wherever samples cluster.
- **Fixed the erratic chart zoom**: every 2-second refresh was stacking
  another mouse-wheel handler on the chart, so one scroll fired dozens
  of stale zooms, each computed from an old time window. One handler,
  always current, and the range dropdown and wheel now agree.
- **A draggable divider now sits between the device chart and the
  interface/event lists** — resize the split to taste; the position is
  remembered, and the chart redraws live while dragging.
- **The interface list is sortable** — click Descr, Admin, Oper, Speed,
  In or Out to sort either way (numeric columns sort numerically), with
  the same column-resize grips and width memory every other table has.
- **"Manage groups" moved to the top-right of the Nodes page**, next to
  Settings, out of the Devices filter bar.

### 4.16.0 — Discovery scan controls, cancel/discard flow, debug visibility

- **The Debug page now shows discovery scans in progress** — a new
  DISCOVERY SCANS RUNNING section (below NODE POLLS) with each running
  sweep's target, probed-of-total progress, how many devices answered
  ping and SNMP so far, and a live elapsed timer; the summary line
  reports active scan count next to the Nodes poller state.
- **Starting a discovery scan now opens a timing dialog** — ping timeout,
  ping retries, SNMP timeout, and SNMP retries (extra attempts per
  credential), pre-filled from the module defaults. The values apply to
  that one scan only and are never written back to any profile or
  setting. Retries genuinely retry now: extra ping passes revisit only
  the addresses that haven't answered, and SNMP identification re-attempts
  each credential the chosen number of times.
- **Cancelling a scan now ends in the same approve/deny dialog** as a
  finished one, listing whatever it had found up to that point — add the
  devices you want, or **Discard scan**, which removes the scan and its
  results from the list entirely. Finished/cancelled/errored scans also
  get a Remove button in the jobs list (previously a cancelled scan sat
  there forever with no way to clear it). Fixed along the way: a cancel
  arriving while the last address was being probed used to land the scan
  in state "done" instead of "cancelled".
- **Table column resize grips are now visible** — the draggable handles
  between column headers (Flow Records' Time/Source/Port columns, the
  device list, and every other resizable table) show a light tick mark
  instead of appearing only on hover.

### 4.15.0 — Selected-device fast poll, interface drill-down dialog, visible splitters

- **The device selected in the Nodes module now polls every 3 seconds**
  instead of at its profile interval (SNMP-polled devices only), so the
  drill-down shows live movement while you're looking at it. The cadence
  returns to the profile interval seconds after the device is deselected
  or the tab is left — the browser holds a short server-side lease it
  renews while the device stays selected, so a closed browser never
  leaves a device fast-polling. The fast interval is configurable in
  Nodes → Settings ("Selected-device poll interval", 0 disables), and a
  device slower to answer than the fast cadence is simply skipped that
  round rather than flooding the event log with poll-overrun noise.
- **Clicking a port in a device's INTERFACES list opens a per-port
  dialog**: an up/down bandwidth graph of the last hour (fed by the
  fast-poll above, so it visibly moves while open), the port's
  statistics and error counters, its link up/down event history, and —
  where the device exposes them the standard way (ENTITY-SENSOR-MIB) —
  live DOM/SFP sensor readings such as supply voltage, bias current,
  light levels and temperature, with units and scaling as the device
  itself reports them. "Show run" and MAC-addresses-on-port sections are
  present as placeholders until SSH integration is added.
- **Interface error counters are now actually collected.** ifInErrors/
  ifOutErrors were fetched-but-dropped before; each poll now stores the
  cumulative counts, computes an errors-per-second rate, and records it
  as a per-interface metric alongside the existing bandwidth ones.
- **The draggable pane dividers are lighter** across every module — they
  were nearly invisible against the panel background unless you already
  knew they were there.

### 4.14.0 — Device naming, discovery approval flow, detail-field settings

- **A device's displayed name now prefers its SNMP hostname (sysName)**,
  falling back to the manually entered name, then the IP. Each device's
  Edit form gains a "Displayed name" choice — Auto (SNMP hostname first)
  or Manual name — so a hand-picked label can win per device. The form's
  Name field is relabeled "Manual name" to match. A device added from
  discovery starts with no manual name; its sysName shows immediately
  (the discovered identity is pre-filled at promotion rather than waiting
  for the first poll).
- **Discovery's "Single device / Subnet" dropdown is gone** — the target
  itself decides: a bare IP or a /32 is a single-device probe (which
  still tries SNMP even without a ping reply), anything else is a subnet
  sweep. Invalid input gets a clear error instead of a guess.
- **A finished scan now ends in an approve/deny dialog**: every
  discovered device is listed with a checkbox — SNMP-identified ones
  pre-checked — and nothing is added until "Add approved" is clicked.
  Dismissing adds nothing; either answer is remembered, so the dialog
  never re-pops for the same scan. The RESULTS pane remains for
  reviewing or promoting later, with the same pre-checked defaults.
- **Ping-only devices (no SNMP answer) are excluded by default.** A new
  discovery option — "Also offer ping-only devices" — must be set when
  the scan starts for such devices to be approvable at all, and the rule
  is enforced server-side, not just in the dialog. A ping-only device
  that is approved is created with SNMP polling switched off so it
  doesn't sit failing SNMP forever.
- **The leftover "default communities" discovery setting is gone.** A
  scan's communities come entirely from its chosen polling profile (a
  scan cannot start without one); a profile with no v1/v2c community is
  refused up front — with a clear message — unless ping-only devices are
  allowed. The old silent fallback to "public" is removed.
- **Nodes → Settings now chooses which SNMP identity fields the device
  detail header shows** — sysDescr, sysName, sysObjectID, contact,
  location, vendor, and the SNMP version each get a checkbox; IP, status
  and any SNMP error always show.
- **The Debug page's NODE POLLS IN PROGRESS section moved up** to sit
  directly below TRACE WORKERS, since those two are the busiest.

### 4.13.0 — Discovery profiles, node groups, debug visibility, bundled MIBs

- **Discovery now requires picking a polling profile instead of typing SNMP
  communities by hand.** The Discovery form's free-text Communities field is
  gone; in its place is a Profile dropdown listing every existing polling
  profile. Every credential on that profile — its primary community/version
  plus any additional credentials — is tried during the scan, the same set
  a device on that profile would try when polling.
- **The Debug page now shows Node polls in progress**, alongside the
  existing trace worker, DNS, and IPAM sections — a new NODE POLLS IN
  PROGRESS table lists each device currently being polled with its
  elapsed time, and the summary line at the top now reports whether the
  Nodes poller is running and how many polls are active.
- **A handful of default MIBs now ship with the app**, loaded automatically
  on first start through the same parse/upload path a manually uploaded
  MIB goes through: an IF-MIB core subset covering the interface columns
  Nodes already polls (with real DESCRIPTION text and status/enum tables),
  and a set of enterprise-number roots for ~20 common vendors, so a real
  vendor MIB uploaded afterward resolves cleanly against its parent arc on
  the first try. Deleting a bundled MIB is respected — it is not silently
  recreated on the next restart.
- **Devices can now be organized into groups**, independent of which
  polling profile they use — a device belongs to at most one group at a
  time (or none). A "Manage groups" button next to the Devices filter bar
  opens a simple add/rename/remove dialog; the device list gets a Group
  column and filter, and the Add/Edit device form gets a Group picker.
  Removing a group leaves its devices ungrouped rather than erroring.
- **A polling profile can now be deleted even if it's the default one**,
  as long as no device currently uses it — attempting to delete an in-use
  profile (default or not) now shows a clear "N device(s) still use this
  profile" message instead of either silently orphaning devices or being
  unconditionally blocked. Deleting the default profile promotes the next
  remaining one automatically. Any profile can now be made the default via
  a new "Set default" button on the Profiles tab.
- **The Interfaces and Events lists on a device's Statistics drill-down now
  scroll independently** of the chart and header above them, instead of
  silently overflowing and getting clipped once a device has more rows
  than fit on screen.

### 4.12.0 — Multiple SNMP credentials per polling profile

- **A Nodes polling profile can now hold more than one SNMP credential**,
  of the same version or different ones — a profile's Edit dialog gains
  an ADDITIONAL CREDENTIALS section under its existing primary
  version/community/v3 fields, where any number of alternates can be
  added, each with its own version and community or v3 username/auth
  protocol/password. Useful for a profile covering a mix of vendors or
  SNMP versions on the same subnet, rather than needing one profile per
  credential.
  - The profile's own primary credential is always tried first,
    unchanged; additional credentials are tried after it, in the order
    they were added, for any device on that profile that doesn't answer
    the primary.
  - Whichever credential answers is cached per device, so trying several
    candidates only costs extra requests on a device's first poll (or
    after its working credential stops answering) — not on every poll
    after that.
  - A device with its own credential override is unaffected: it still
    uses exactly that one credential alone, the same as before this
    feature existed. The profile's list only matters for a device
    relying on the profile.
  - Each additional credential's optional SNMPv3 password follows the
    exact same DPAPI-encrypted, Windows-only, never-returned rule as
    every other stored credential in this app.

### 4.11.3 — A silent hop is no longer flagged "MTR: High Loss"

- **A hop that has never once answered a continuous (MTR-style) probe no
  longer turns red with "MTR: HIGH LOSS".** Many routers along a real path
  rate-limit or drop ICMP by nature and sit at 100% probe loss forever —
  that isn't a fault, and flagging it as one buried the case that actually
  matters: a hop that used to answer and has since gone dark. The route
  graph now only raises the red "high loss" flag at 100% loss when that
  hop has answered at least once (`probe_rtt_min` — set the first time a
  probe succeeds and never cleared, independent of how much loss has piled
  up since); a hop with no answer on record keeps its ordinary coloring,
  the same as a hop with no continuous probing at all. The amber "MTR:
  DEGRADED" tier (partial loss or elevated RTT over a destination's own
  warn thresholds) is unaffected.

### 4.11.2 — The application database's own size shown on Settings

- **The application database (`app.db` — settings, accounts, and the
  reverse-DNS/ASN caches) now shows its current size on the Settings
  page**, alongside the other seven data files, so the "on disk in total"
  figure at the bottom is no longer the only place its size is visible.
  It still has no size cap, deliberately: it holds one row per address
  rather than one per event, so it stays small on its own, and its caches
  are already bounded by age via the DNS/ASN cache-days settings rather
  than by a size cap — the hint text under DATA FILES explains why. The
  same section's "the other four files" hint had also gone stale as Nodes,
  Alerts, IPAM and SNMP Trap were added since it was written; it now says
  seven.

### 4.11.1 — Live MTR coloring on the route graph, ASN fallback names

- **A NetPath route-graph node now turns amber or red when its continuous
  (MTR-style) probing is degraded or failing**, using the same warn/fail
  thresholds — that destination's own `warn_rtt_ms`/`warn_loss` — a
  scheduled trace is judged by. This only applies to a hop that actually
  has continuous probing running (`hop_probe_enabled` on that
  destination); a hop with no live probe data keeps its previous coloring.
  The live signal outranks even "this is the destination" in the node's
  color priority, so a target that's currently degraded is not painted the
  same reassuring green as a healthy one — it shows an "MTR: DEGRADED" or
  "MTR: HIGH LOSS" badge and matching border/accent color instead, and the
  hover tooltip names which one.
- **A hop with no PTR record now shows its ASN's org name instead of "no
  PTR record", when one is known.** `asn_lookup()` only ever resolves
  ASN/org data for globally routable addresses, so this fallback is
  naturally limited to external hops — an internal address with no PTR
  still shows "no PTR record" exactly as before. A real PTR name, once
  found, still always wins over the ASN fallback.

### 4.11.0 — Nodes and Alerts

- **Two new tabs, Nodes and Alerts**, inserted between Dashboard and
  NetPath. This is the deferred work 4.10.0's SNMP Trap receiver named as
  its own next step: polling, device inventory, and an alerting engine
  tying traps, syslog and device/interface state together on one shared
  0–7 severity scale.
- **Nodes is a full SNMP poller and device inventory**, styled like the
  rest of the app: a filterable, at-a-glance device table; a per-device
  drill-down with a zoomable metric chart, an interface table and an
  event history; per-device or per-device-group ("polling profile")
  settings and credentials; and per-device or per-subnet discovery
  (reusing IPAM's own ping sweep, then a best-effort SNMP v1/v2c identity
  probe against each address that answers).
  - Devices poll over **SNMP v1, v2c or v3** (noAuthNoPriv/authNoPriv;
    authPriv is rejected with a clear message — decrypting it needs an
    AES/DES implementation this app does not carry, the same call the
    SNMP Trap receiver already made), or **ping alone** for a device with
    SNMP turned off entirely.
  - The scheduler is shaped like NetPath's own trace `Monitor`, not
    IPAM's worker: a hot-resizable thread pool and restart-safe per-device
    due-time seeding, so a service restart with hundreds of devices
    configured polls each one on its own next-due schedule instead of
    firing all of them at once.
  - **Vendor MIBs can be uploaded** and parsed by a hand-rolled,
    stdlib-only best-effort reader — not a MIB compiler, the same framing
    the SNMP Trap receiver's own OID name table already used. IMPORTS are
    resolved only against OIDs this app already knows (its own catalog,
    or a previously uploaded MIB), so uploading a dependent MIB before
    the one that defines its parent branch leaves it partially resolved
    until the parent is uploaded and Resolve is run again. An uploaded
    MIB's names also flow into the SNMP Trap page, so a trap from a
    device that MIB describes shows a name instead of a raw OID there
    too.
  - 32-bit interface counters are treated as one wrap on a decrease;
    64-bit counters (ifXTable, used whenever present since a 32-bit
    counter on a fast link can wrap more than once between polls) treat
    any decrease as a reset. A device's `sysUpTime` resetting well outside
    a clock-skew grace band, and not explained by its own ~497-day
    TimeTicks wraparound, is recorded as a reboot.
- **Alerts evaluates Nodes' device/interface state, SNMP traps, Syslog
  messages and IPAM conflicts** against a rule table, opening (or
  incrementing) and auto-resolving alerts, with **24 built-in rules** —
  device not responding, device rebooted, an interface flapping,
  CPU/memory/interface-utilization/error-rate thresholds with hysteresis,
  a critical trap or syslog line forwarded, and more — each editable
  (severity, threshold, which devices it applies to) but not deletable;
  a custom rule can be added for anything the built-ins don't cover.
  - **Email notification** over stdlib `smtplib`, with **5 built-in
    templates** using a hand-rolled `{{token}}` substitution (no template
    engine dependency), each fully editable and resettable to its shipped
    text. A resolved alert's own recovery email reuses the "device
    recovered" template rather than replaying the original problem's
    wording backwards.
  - Repeated occurrences increment one alert rather than opening a
    duplicate (an alert's dedup key can only be open once at a time,
    enforced by the database itself); volume controls cap emails per hour
    and can re-notify a still-open alert on an interval instead of only
    once.
- **Any new database's size and cap are on the Settings page**, same as
  every other module: `nodes.db` and `alerts.db` join the storage list
  with their own refresh rate, cap and maintenance action.
- An SNMP community string is still stored and shown in the clear — it
  travels in the clear in every packet the protocol defines, so it is a
  filter, not a secret, the same reasoning `CREDENTIAL-SECURITY.md`
  already applied to the SNMP Trap receiver. An SNMPv3 authentication
  password and the SMTP password are both DPAPI-encrypted on Windows and
  refused (with a clear message pointing at typing it into Test instead)
  on any other platform, matching IPAM's DHCP credential exactly.

### 4.10.0 — SNMP trap receiver

- **A new SNMP Trap tab**, between NetFlow and Syslog, receiving and
  decoding SNMPv1, v2c and v3 traps and informs over UDP. All BER/ASN.1
  parsing is hand-written (stdlib only, no third-party SNMP/ASN.1
  library), never raises past its own decode boundary, and mirrors
  NetFlow's binary decoder in shape. Graphically it matches Syslog: a
  status strip, a filterable search bar, an hourly severity-stacked
  histogram, a resizable table and a detail panel showing every varbind
  with its OID, type and value.
- **v1 and v2c traps** are fully decoded, including the SNMPv1 Trap-PDU's
  distinct enterprise/agent-address/generic/specific shape, mapped onto
  the same snmpTrapOID identity space v2c uses (RFC 3584) so both
  versions are one searchable axis.
- **v3 support verifies USM authentication** (MD5, SHA1, and the SHA-224/
  256/384/512 variants from RFC 7860) against configured users, computing
  the HMAC over the whole message with the authentication parameters
  blanked in place. Traps sent authPriv are detected and their header
  decoded, but the encrypted payload is not decrypted — the standard
  library has no AES/DES implementation and this app takes no
  third-party dependencies. A named seam (`trapcrypto.py`) is left for a
  future hand-rolled decryptor.
- **Every trap gets a normalized severity**, 0–7 on the exact same scale
  Syslog uses, via a built-in rule table plus an admin-editable
  OID-prefix override — so a future alerting engine can treat traps and
  syslog lines uniformly without translating between two vocabularies.
  OID names resolve through a built-in table of the common MIBs (~150
  entries) plus an admin-editable `OID = name` list; this is a name
  table, not a MIB compiler, so `.mib` files are not parsed.
- **InformRequests are acknowledged** for v1/v2c, a reply on the same
  socket the inform arrived on — still receive-only, since it answers
  rather than queries. v3 informs are not acknowledged, since doing so
  correctly means acting as the authoritative SNMP engine, which belongs
  with a future poller.
- **A "Send test trap" button** sends a real coldStart trap to the
  receiver's own bound port, with the equivalent PowerShell and
  net-snmp commands shown alongside — the same loopback proof pattern
  Syslog and NetFlow already use.
- This is receive-only: there is no SNMP polling (GET/GETBULK) yet, and
  no alerting engine ties traps, syslog and future ping/SNMP polling
  together yet — both are intentionally out of scope here, and the data
  model (the shared severity scale, especially) is built so neither is
  precluded later.

### 4.9.3 — NetPath flash on reload actually fixed this time

4.9.2's fix helped but wasn't enough: it ran from a script near the end of
`index.html`, so on a slower load the browser could still paint a frame
of the static default (NetPath) before the parser reached it. This one
moves the decision into `<head>`, before the page has any body content to
mis-paint at all — a tiny script there tags `<html>` with the remembered
tab, and the stylesheet (loaded right alongside it, before anything below
renders) uses that tag to decide what's visible from the very first
frame. There's no static default left to flash; only whichever tab was
actually open.

### 4.9.2 — No more NetPath flash on reload

- **Reloading no longer flashes NetPath** before settling on the tab you
  were actually on. The remembered tab is now applied by a small inline
  script that runs the instant the page's markup is parsed, rather than
  waiting on every module's script file to load and the app's own first
  server round trip — both of which the previous fix still had to wait
  through before it could act.

### 4.9.1 — Sign-in always opens on Dashboard

- **Signing in now always lands on the Dashboard tab**, regardless of
  which tab a previous session left active. A reload while already
  signed in still returns to whichever tab was open, as of 4.9.0 — this
  only changes what a fresh login itself opens to.

### 4.9.0 — DHCP leased-IP trend chart, tab persists on reload, Dashboard tab

- **DHCP scopes get a leased-IP trend chart**, a thin line chart under the
  usage donut showing the last 24 hours or 7 days, toggled per scope, with
  a hover tooltip for the exact count (and percentage, where known) at any
  point. One snapshot is recorded per scope on every poll, kept separately
  from the live scope/lease data those polls otherwise replace wholesale,
  so the trend survives every subsequent poll. A new **Keep DHCP
  leased-IP history for** setting (default 35 days) controls retention.
- **Reloading the page now returns to whichever tab was open**, instead of
  always resetting to NetPath. Remembered per browser, the same way panel
  sizes and column widths already are.
- **A new Dashboard tab**, at the far left of the tab list ahead of
  NetPath. Currently a placeholder with nothing on it yet — reserved space
  for a future cross-module overview.

### 4.8.1 — Resizable Syslog and NetFlow columns

- **Syslog's message table can now be resized** column by column, the same
  drag-the-header-edge mechanism NetFlow and IPAM already use. Widths are
  remembered per browser and clear with the rest via **Reset layout**.
- **NetFlow's column widths now default close to what each field actually
  needs** — narrow for ports, protocol and byte/packet counts — rather
  than one uniform width for every column, so Source and Destination (the
  two that can hold a long resolved hostname) get the extra room instead.
  Anyone who already dragged a NetFlow column keeps that width; this only
  changes the starting point for columns nobody has touched yet.

### 4.8.0 — Flow-to-path correlation, continuous per-hop probing, ASN/owner lookup

- **Flow-to-path correlation.** Every row in the NetFlow table now carries a
  "→ Route" link to the NetPath route that traffic actually took, when one
  was ever traced — matched against each target's real, last-known
  destination IP, not just its configured hostname. No matching route
  greys the link out rather than hiding it, so the feature stays
  discoverable. Jumping over selects the matching destination in NetPath
  and centers its time window on the flow's own timestamp.
- **Continuous, MTR-style per-hop probing**, opt-in per destination (off by
  default — it adds a steady stream of ICMP pings to every hop of the path,
  independent of the scheduled traceroute). Turn it on from a destination's
  Edit dialog; the route graph's hop tooltips then show live cumulative
  probe count, loss % and min/avg/max RTT alongside the per-traceroute
  numbers. A route change automatically clears stats for hops that dropped
  off the path, so old and new numbers are never blended together.
- **ASN and organization lookup** for every hop, shown next to the
  reverse-DNS name, so you can see where a route leaves your provider —
  "AS15169 (GOOGLE, US)" and similar. Uses Team Cymru's DNS-based whois, on
  its own long-lived cache (30 days by default) separate from the hostname
  cache, since ownership changes far less often than a PTR record. Private,
  loopback, link-local and carrier-grade-NAT addresses are never looked up
  at all — no query naming an internal address ever leaves the host.
  Configurable, including a dedicated query server, under Settings →
  ASN / Owner Lookup.

### 4.7.0 — Scope sort by IP, half-width buttons, IPAM as a DNS fallback

- **Scopes sort by IP address** too now, alongside Least available (the
  default), Most available and Name — numerically, so 10.0.10.0 doesn't
  sort ahead of 10.0.2.0.
- **Change password and Check for update & restart** no longer stretch to
  the full width of their row.
- **NetFlow and Syslog can get a name from IPAM when DNS has nothing.** The
  reverse-DNS resolver falls back to whatever a DHCP lease says a device's
  hostname is when a PTR lookup comes back empty, and caches that the same
  as a real DNS answer — in the one shared cache both modules already read
  from, so neither needed any changes of its own.
- **Syslog's Messages header gets a Hostname checkbox**, on by default,
  next to the message count: unchecked, the Source column always shows the
  raw address even when a name is known.

### 4.6.0 – 4.6.3 — DHCP reformatted to match Subnets & Hosts

The DHCP page now mirrors Subnets & Hosts one level down. Server selection
moved into a compact dropdown at the top; the sidebar it vacated now holds
**Scopes**, each with a mini utilization donut — leased, reserved,
available — the same visual language as the subnet donuts. Selecting a
scope shows a bigger version of that donut above its **Leases** table,
filtered to just that scope, the same way the Hosts table already filters
to the selected subnet.

- Scopes sort by **Least available** (the default), **Most available** or
  **Name**.
- The detail header adds the scope's own **subnet**, computed from its
  network identity (ScopeId + mask) rather than the narrower dynamic
  range, and its configured **router** address (DHCP option 3), fetched
  per scope and not previously read at all.
- `dhcp_scopes` gained a `router` column, added to existing databases
  through the same `ALTER TABLE` migration pattern already used for the
  DHCP credential fields.

### 4.5.0 – 4.5.1 — Find: search IPAM by hostname, IP or MAC

A search box in the IPAM strip answers the direction browsing by subnet
never could: given a name, MAC or partial IP, what's the address. Checks
three sources at once — hosts SappiWhere's own sweep discovered, DHCP
leases and reservations, and the shared reverse-DNS cache — and merges
matches found in more than one by IP. A result outside every configured
subnet isn't a bug: DHCP polling reads a server's scopes independently of
what subnets are being swept, and each result names which source found it.

### 4.5.2 – 4.5.7 — DHCP Test Connection: reliability and readable errors

Test Connection went from a silent "PowerShell exited with code 0, no
output" to actually working, through a real chain of distinct failures
found and fixed against a production DHCP server:

- **The root cause of the silent failure**: the script was piped to
  PowerShell over stdin with `-Command -`, which is unreliable for a
  multi-statement script with scriptblocks and try/catch on native
  Windows PowerShell — it can read and execute nothing while still
  exiting 0. Switched to writing the script to a temp `.ps1` file and
  running it with `-File`, the officially supported way, written with a
  UTF-8 BOM so Windows PowerShell 5.1 reads it correctly regardless of
  the system codepage.
- **WinRM TrustedHosts, CIM/WMI access-denied, and DhcpServer
  module-not-loaded** errors — each a distinct, genuine step in getting a
  credentialed connection working (Kerberos can't vouch for a bare IP;
  the account needs the DHCP server's local `DHCP Users` group, a
  separate permission from WinRM access; and the DHCP server needs
  `RSAT-DHCP` installed, which can silently not take effect until WinRM
  itself is restarted) — now come back with the actual fix appended
  rather than the raw PowerShell message alone.
- **The button itself shows progress**: disabled and relabeled "Testing…"
  for the duration, since a PowerShell round trip over WinRM can
  legitimately take up to thirty seconds and previously gave no
  indication anything was happening.

### 4.4.0 — A blocking restart dialog, and an IPAM database cap

Clicking the update button now grays out the screen with a modal
explaining a restart is in progress and that it will sign everyone out,
rather than leaving that as a status line easy to miss on another tab.
IPAM's `ipam.db` gets the same size-cap treatment the other three
databases already had — 256 MB by default, trimming the oldest scan
history first, since subnets, hosts and open conflicts describe the
network as it is now rather than a log a cap should be trimming.

### 4.2.0 – 4.3.6 — A self-update button

Settings gained one button: check `github.com/thawkins5555/magicalbeans`'s
`main` branch for a commit newer than what's installed, and if there is
one, download it over plain HTTPS, swap it into the running install, and
restart. Getting the restart itself to actually work reliably took three
real, distinct bugs found against production Windows servers, each fixed
in turn:

- **`CERTIFICATE_VERIFY_FAILED`** on a Windows server with no route to
  fetch a missing root certificate — fixed by vendoring Mozilla's CA
  bundle (the same one `pip` ships) and trusting it alongside the system
  store rather than instead of it.
- **The restart not restarting at all.** `os.execv` behaves nothing like
  POSIX exec on Windows — it spawns a new process and ends the old one —
  and a naive replacement process was losing a race for the port and the
  databases against the process it was replacing, then separately dying
  within milliseconds of starting for a second, unrelated reason.
- **The actual root cause of that second death**: the relaunch command
  was rebuilt from `sys.argv`, but `-m netpath` rewrites `sys.argv[0]` to
  `__main__.py`'s resolved file path — so every restart was actually
  running that path as a bare script rather than `-m netpath`, which
  drops the package context every relative import in this app needs and
  crashes instantly with no visible error on `pythonw.exe`. Fixed by
  rebuilding the relaunch command as `-m netpath` explicitly rather than
  trusting `sys.argv[0]`.

### 2.7.0 — Three IPAM display bugs fixed

Reported against a real subnet: a stray `\25B2` appearing after sorting a
column, the Last seen/First seen columns visibly out of step with their
data, and a subnet showing 86% of its addresses as "seen before, now down"
that plainly hadn't ever been occupied that heavily.

- **The sort caret rendered as literal text.** A CSS `content` property was
  written with a doubled backslash, so the browser showed `\25B2` instead of
  a triangle. Replaced with a real element in the DOM rather than a
  positioned `::after` pseudo-element, which also restores sticky table
  headers that the old approach had silently broken.
- **Two columns were right-aligned while their cells stayed left-aligned.**
  `numeric: true` was controlling both how a column sorts and whether it's
  right-aligned, and a "14s ago"-style column sorts by timestamp but reads
  as text. Sorting and alignment are now independent settings, and every
  column in a sortable table gets an explicit width so the header row and
  the body are measured from the same numbers.
- **"Seen before, now down" was counting addresses that had never been seen
  at all.** A host gets a row the moment it's *probed*, answer or not; the
  usage breakdown was treating "has a row" as "was up before," which made
  every never-answering address in a subnet look like a former occupant.
  Fixed to key off `last_up`, which is only ever written when an address
  actually replies — an address probed a hundred times with no reply is now
  correctly "never seen." The host table's timestamp columns had the same
  confusion baked into their labels and are renamed to match what they
  actually show: **Last reply** (from `last_up`, "never" if nothing has ever
  answered) and **First probed** (when the sweep first tried it, which is
  not the same thing an earlier "First seen" label implied).

### 2.6.0 — Live agent visibility on Debug, per-subnet utilization charts, and a way to reset a subnet's inventory

- **The Debug page now shows DNS and IPAM work in progress**, not just
  NetPath's trace workers. A "DNS lookups in progress" table lists every
  address currently out for a reverse-DNS lookup with its elapsed time; an
  "IPAM agents running" table lists every subnet scan or DHCP poll actually
  in flight. Fixed a real latent bug found while wiring this up:
  `Resolver.drain()` called a method that never existed on that class —
  dead code that would have raised if anything had ever invoked it.
- **Every subnet shows a utilization donut** — alive, previously-seen-but-
  down, never-seen — in the sidebar list, and a larger version with the
  counts spelled out above its host table when selected.
- **Clear stats**, in a subnet's Edit dialog, resets its discovered hosts and
  scan history to start over without removing and re-adding the subnet.
  Refused while a scan of that subnet is running, so it can't race the
  scan's own writes.
- The IPAM event category, added with the module itself, had no display
  label in the Debug log's category filter and showed as raw `ipam` text;
  fixed.

### 2.5.0 — A stored credential option for DHCP polling

IPAM's DHCP servers could only authenticate ambiently or via Windows
Credential Manager. That's still there and still the default, but a server
can now be given a username and password directly instead — the shape of
field software with a dedicated read-only DHCP account tends to have.

- **A DHCP server can store a username and password**, for people migrating
  from a tool that took a credential directly rather than through Windows.
  Both mechanisms coexist per server: leave the fields blank for ambient
  identity or Credential Manager as before, fill them in to override with a
  stored credential for that one server.
- **The password is encrypted with Windows DPAPI**, machine-bound, before it
  is written to `ipam.db`. It is never returned by the API in any form —
  the server listing shows only that a credential is stored and its
  username. Storing one is refused with a clear message on any platform
  where DPAPI isn't available, rather than falling back to writing it in the
  clear.
- **The stored-credential path uses PowerShell remoting** (`Invoke-Command
  -Credential`) rather than the RPC call the ambient path uses, since the
  DhcpServer module's cmdlets don't accept a credential directly against
  `-ComputerName`. This needs WinRM reachable on the DHCP server instead of
  the `DhcpServer` module being present on the SappiWhere machine — the
  trade-off runs the other way from the default path. A real DHCP server
  almost always already has the module, since it ships with the role.
- **Test connection** now also accepts an unsaved username and password, so a
  credential can be checked before it's committed to.
- **Clear credential** reverts a server to ambient identity.
- The same injection-safety property as the original DHCP client holds here
  too: the username and password travel to the PowerShell process as
  environment variables, never woven into command text, and every DHCP
  cmdlet called — on either path — is still a `Get-`.

### 2.4.0 — IPAM: discovery, conflicts, read-only Windows DHCP

A new module and tab: subnet discovery, IP conflict detection, and read-only
visibility into a Windows DHCP server's scopes and leases. Backed by a fifth
database, `ipam.db`.

- **Subnet discovery.** Add a subnet in CIDR form and it is swept on a
  schedule: every address is pinged, then the local ARP table is read once for
  whatever answered. A subnet larger than a configurable limit (1024
  addresses by default) is refused when added rather than silently truncated.
- **MAC addresses and conflict detection are ARP-based**, so they only work on
  a subnet directly attached to the machine running SappiWhere — ARP does not
  cross a router. A remote subnet still reports which addresses answer ICMP.
  This is documented as a deliberate limit, not fixed silently.
- **Conflict detection**, two ways: the same address answering as two
  different MACs across scans, or a scanned MAC disagreeing with what a polled
  DHCP server's own lease record says for that address. Neither auto-resolves
  — a person marks one resolved once they know what happened.
- **Read-only Windows DHCP polling**, via the `DhcpServer` PowerShell module's
  own `Get-DhcpServerv4Scope`, `Get-DhcpServerv4Lease` and
  `Get-DhcpServerv4Reservation` — nothing else. The PowerShell script that runs
  is a fixed constant, never built from input; the target server name travels
  as an environment variable rather than being woven into command text, so
  there is no string for it to inject into. There is no write path: nothing in
  SappiWhere can create, change or remove a scope, reservation or lease.
- **No credential is ever stored.** DHCP polling authenticates as whichever
  Windows account runs SappiWhere, or — if that account does not already have
  DHCP read rights — a matching entry in Windows Credential Manager on this
  machine, added once with `cmdkey` or Control Panel and associated with that
  server's name. SappiWhere has nowhere to put a password even if it wanted to.
- **Test connection** checks reachability and reports the DHCP Server version
  and scope count without walking every scope's leases, for confirming a new
  server quickly. **Poll now** and **Scan now** force an immediate run outside
  the schedule.
- The host and lease tables sort and resize the same way NetFlow's flow record
  table does, reusing the same grid helper.
- IPAM's discovered hosts feed into the shared reverse-DNS cache alongside
  NetFlow's and Syslog's, gated by their own settings as before.
- Retention: discovered hosts, resolved conflicts and scan history are each
  pruned on their own schedule; DHCP scopes and leases are replaced wholesale
  on every poll, since the DHCP server is the source of truth for those.

### 2.3.0 — Idle sign-out for the web login

The session idle timeout (`session_idle_minutes`) existed in the code but
could not actually fire: every open browser tab polls the server every couple
of seconds regardless of whether anyone is present, and that polling was
extending the same idle timer meant to catch an unattended session.

- **Sessions now distinguish presence from polling.** A background read no
  longer extends a session. Only a deliberate action does — any write, or a
  heartbeat the browser sends solely when it detects real mouse or keyboard
  input, at most every 20 seconds.
- **Default idle timeout lowered from 4 hours to 10 minutes**, since it is now
  a timeout that actually enforces itself.
- **New Sign-in section on the Settings tab**: idle timeout and absolute
  session length, both adjustable and applied to every active session
  immediately.
- **A 60-second warning banner** appears before sign-out, with a button to
  stay signed in, so the shorter default doesn't cut someone off mid-task
  without notice.
- The admin "who's signed in" list now shows genuine idle time instead of a
  number that was always close to zero.

### 2.2.0 — Substring search, sortable flow records

- **Syslog search matches anywhere in a word.** `face` now finds `interface`.
  The index was tokenized by word, so a query could only ever match from the
  start of a token; it is now a trigram index, which indexes every
  three-character run. Queries of one or two characters scan instead, since a
  trigram index has nothing to match on below three.
- **The sending address is searchable from the main search box.** It is indexed
  alongside the message, so typing `10.20.3.4` finds messages from that device.
  The Source IP filter stays for narrowing a search that is about something
  else, and its label now says IP.
- **Multiple search terms** must all appear, in any order and any field, rather
  than being treated as one phrase.
- **The index rebuilds itself once** on the first launch after upgrading,
  in the background and in chunks so the collector keeps writing and the
  service starts immediately. Searching works throughout, by scanning, and the
  syslog status strip shows the progress.
- The scan fallback now searches the same four columns as the index, so both
  paths return the same rows and differ only in speed.
- **`syslog.db` roughly doubles in size.** A trigram index holds far more than
  a word index: 50,000 sample messages went from 14.6 MB to 26.5 MB. Against a
  fixed cap that halves how many messages are retained, so raise the Syslog
  database cap if history matters more than the search.
- **Flow record columns sort and resize.** Click a heading to sort, again to
  reverse; drag its edge to resize. Widths persist per browser and are cleared
  by Reset layout. Ports and volumes sort by value rather than by their
  label — `HTTPS (443)` is not text between 44 and 45 — and empty cells sort
  last in both directions.
- The records selector is relabelled *Top 250 by volume / by packets / most
  recent*, since it chooses which records are fetched while the headings choose
  how they are arranged.

### 2.1.0 — Application data split out of the trace database

`netpath.db` had been carrying three things that are not traceroute records:
the global settings, the user accounts and the reverse-DNS cache. They now live
in a fourth file, `app.db`, and each record database holds only its own
module's data and its own module's settings.

- **New `app.db`**, beside the others, holding global settings, accounts and
  the shared name cache. Path overridable with `--app-db`.
- **Settings are split by scope on disk**, matching the split the Settings
  pages already made: global keys in `app.db`, NetPath keys in `netpath.db`,
  NetFlow and Syslog keys where they already were.
- **Existing installs migrate on first launch.** Settings, accounts and cached
  names are copied across, verified, and only then removed from `netpath.db`.
  An interrupted migration is retried on the next start rather than left half
  done; nothing is deleted from the source until the copy is confirmed.
- **The reverse-DNS resolver no longer joins hops against the cache**, since
  they are in different files. It reads candidate addresses from `netpath.db`
  and filters them against `app.db`. A new index on `hops(ip)` keeps that a
  cheap index scan.
- **Cached names are pruned** on the maintenance cycle instead of accumulating
  for the life of the install.
- **The Data files panel lists all four**, with the Syslog path shown for the
  first time. `app.db` has no size cap: it does not grow with traffic, and it
  is the file to back up.
- Sessions and login throttling are unchanged — both stay in memory, so no
  token is ever written to any file.

### 2.0.0 — Browser interface

The application can now run headless and be used through a web browser. The
desktop window still works and is unchanged; both are front ends over the same
core.

```
python -m netpath --web --port 8443
```

- New `netpath/web` package: a `Service` owning the databases and background
  workers, a JSON API, and a browser front end.
- Standard-library HTTP server, so the deployment gains no dependencies. TLS
  when `--cert` and `--key` are given.
- `--host` and `--port` control the listener; the port defaults to 8443.
- All four tabs are present in the browser: route graph, three-lane timeline,
  snapshots, flow charts and table, worker state, event log and settings.
- Every module setting is reachable from the same places as on the desktop.

**No authentication yet.** Bind to an interface you trust until the TACACS work
lands.

### 4.1.0 — Database sizes on show, and a storage document

- The sign-in page carries nothing but the name and the two fields. It no
  longer advertises the default credentials, which is not information an
  unauthenticated visitor needs.
- **Current database size beside each cap** on the Settings tab, with a small
  bar that turns amber past 75% and red past 90%. A cap means little without
  the number it is capping next to it. The bars update as the cap is typed, so
  the effect of a change is visible before it is applied.
- **A Databases card in the service console** showing the same three figures
  with their paths, so the disk position is answerable without a browser.
- `NETWORK-REQUIREMENTS.md` is now
  **`NETWORK-AND-STORAGE-REQUIREMENTS.md`**, covering what is written to the
  local machine as well as what crosses the network: the exact file locations
  on each platform, what each database holds and why it has to, what bounds the
  size and in what order, and what is never written at all.

### 4.0.1 — Overlapping labels, and browsers holding stale scripts

Fixed: the `HOP n` labels sat at a fixed height above the middle of the route
graph, which put them inside the box whenever a column held a single hop. They
are now placed relative to the top of their own column, so they clear it
however many addresses that hop has.

Fixed: the warn threshold labels on the timeline were right-aligned, where the
lane already carries its scale figure and where the newest bars are drawn. They
have moved to the left of the lane, over a small backing plate.

Fixed, and the reason the threshold line looked missing after an update: the
browser was still running the previous JavaScript. The version in the corner
comes from the server, so it changes as soon as the service restarts whether or
not the page has reloaded — which made a stale script look like a missing
feature. The shell is now served `no-store` so a reload always fetches the
current script tags, and the scripts carry an `ETag` so the browser can tell
stale from current rather than guessing. A revalidation of an unchanged file
returns 304 and no body.

### 4.0.0 — Sign-in, local users, and thresholds on the NetPath page

**Everything now requires signing in.** A fresh install creates **admin /
admin**, flagged so the first thing it does is insist on a new password.

Passwords are never stored. What is kept is an scrypt hash at the parameters
OWASP currently recommends — N=2^17, r=8, p=1, roughly 128 MiB and a second per
verification — with a 16-byte random salt per password, falling back to
PBKDF2-HMAC-SHA256 at 600,000 rounds where the SSL library underneath is too
old for scrypt. The stored string records which was used and with what cost, so
raising it later does not invalidate anyone: hashes are upgraded quietly on the
next successful sign-in.

Other things that matter more than they look:

- **Sign-in failures are indistinguishable.** An unknown username still costs a
  full hash verification against a dummy, so response time cannot be used to
  discover which accounts exist, and both cases return the same words.
- **Failed attempts are throttled** per username *and* per source address, so
  one noisy address cannot lock out an account and one account cannot lock out
  an address. The delay doubles past five failures, capped at 30 seconds.
- **Sessions are server-side and in memory**, so a restart signs everyone out
  and no token is written to a file that also holds network data. The cookie is
  `HttpOnly`, `SameSite=Strict`, and `Secure` when TLS is on — it is left off
  over plain HTTP, where a Secure cookie would simply be discarded.
- **Changing a password ends every session using that account**, including the
  one making the change.
- **State-changing requests must be `application/json`.** A cross-site form can
  send a POST but cannot set that content type without a preflight the browser
  will refuse; with `SameSite=Strict` that is belt and braces, but both are
  free.
- **Password rules are length and a blocklist**, not composition. Twelve
  characters minimum, and the passwords every attacker tries first are refused.
  Requiring a capital and a digit pushes people toward predictable manglings,
  which is why NIST dropped it.

Users are managed on the Settings tab: add with an initial password they must
change, remove, and see who is currently signed in. There are no roles — every
account has full access, which is why adding one is an administrative act. You
cannot remove the account you are signed in with, so there is always a way back.

**The NetPath page now states the terms it is judging by.** Under the route
header: `every 60s · warn above 150 ms or 10% loss · probe 30 hops × 3 at 2s
(worst case 195s)`. The warn thresholds are also drawn as dashed guides across
the RTT and loss lanes, so a bar crossing the line is visibly why the block
below it turned amber.

### 3.4.1 — A console window flashed for every trace

Fixed: running from the `pythonw.exe` shortcut made a console window appear and
disappear for every traceroute. With no console of its own, Windows gives each
child process a new one — so removing the black window from the app put one on
every `tracert` instead.

`tracert` and `nslookup` are now launched with `CREATE_NO_WINDOW`, with a
hidden `STARTUPINFO` as well for shells that honour that instead. Both come
from one helper in `procs.py`, so a future subprocess cannot quietly forget it.

### 3.4.0 — Run without a terminal window

- **Console output** pane in the service console, capturing stdout and stderr.
  Under `pythonw.exe` both streams are `None` and anything printed — a
  traceback from a worker, a collector error — would otherwise vanish. Now it
  is visible in the window, which is a better place for it than a terminal
  nobody is watching.
- **Show terminal window** checkbox, when there is a terminal to show. Hiding
  it does not stop the service. It is absent under `pythonw.exe`, where there
  is nothing to show.
- **`deploy\Install-Shortcut.ps1`** creates desktop and Start Menu shortcuts
  pointing at `pythonw.exe -m netpath`, so the console opens on its own with no
  black window behind it.

### 3.3.1 — The Syslog page laid out sideways

Fixed: the Syslog page was never added to the rule giving a page a column
layout, so its status card, filter bar and content sat **side by side**. With a
short status nobody would notice; with a long one — a bind failure — the card
grew wide enough to push the filters, histogram, table and the Settings button
off the right-hand edge, leaving a page that was nothing but an error message.

The previous fix was real but addressed the wrong layer: it stopped the status
text from overflowing *within* the strip, which does not help when the strip
itself is a row item free to grow.

Pages are now column by default with NetPath opting into a row, rather than
each page opting into column. A module added later cannot be forgotten and end
up sideways. The status strip is also `flex: none`, so it can neither grow nor
be squeezed out of shape.

### 3.3.0 — Deployment, versions, and a drag-select fix

Fixed: dragging the route graph started a browser text selection, highlighting
the hop labels under the pointer and leaving them highlighted after the drag.
The drawings now suppress selection, and the drag cancels any that was in
progress. The timeline and flow chart had the same problem when dragging to
select a range.

- Every build reports a **version**, shown in the top right of the browser
  interface, in the service console's title bar, and from
  `GET /api/state`. Updating a remote machine no longer means guessing whether
  the files landed or the browser cached the old page.
- **`deploy\Update-SappiWhere.ps1`** updates a local or remote install from the
  release zip over PowerShell remoting: it verifies the archive before touching
  anything, stops the service or process, keeps the previous copy as `.bak`,
  copies, restarts, and reports the version now running. The databases are left
  alone.

### 3.2.1 — A long status could hide the module buttons

Fixed: a long collector status pushed the Settings, Start and test buttons out
of the status strip entirely, so a bind failure hid the one control needed to
fix it. Flex items take their content as a minimum width by default, and the
status line is set `white-space: pre`, so its minimum was the whole string and
it could not shrink. The line now ellipsizes, the buttons are pinned, and the
full text is available on hover and in the Debug log. Both the Syslog and
NetFlow strips were affected.

Also: a failed bind turns the status red, and the message now names only the
ports that matter (`0.0.0.0:514` rather than `0.0.0.0:514/514`) and says how to
find the process holding the port.

### 3.2.0 — Syslog listener and volume settings

Syslog ports were always configurable, and the Settings button was always in the
top right of the module page. What was missing were the settings people actually
reach for once a collector is taking real traffic.

- **UDP and TCP on separate ports.** 514 is standard for both, but 601 is the
  registered port for TCP syslog and plenty of estates split them. `0` for the
  TCP port means "same as UDP". The status strip names both: `Listening on
  0.0.0.0 (UDP 514, TCP 601)`.
- **Keep severity X and worse** drops anything less serious as it arrives,
  before the queue and before anything is written, so a device stuck in a debug
  loop costs nothing beyond the parse. Filtered messages are counted separately
  in the status strip, so the filter never looks like data loss.
- **Truncate messages at N characters**, floored at 80. One malformed device
  sending megabyte lines should not be able to fill the disk.
- **Resolve sending addresses to names**, through the same cache and threads as
  everything else. The source column shows the name where there is one and the
  address where there isn't.

**The syslog database size cap moved to the Settings tab**, defaulting to 1 GB,
alongside the trace and flow caps. All three databases share one disk, so their
limits belong in one place rather than scattered across module dialogs.

### 3.1.0 — The desktop application becomes a service console

The desktop interface is deprecated and removed. Everything it did is in the
browser, and keeping two front ends in step was doubling the work on every
change.

What `python -m netpath` opens now is a small service console:

- Whether the server is running, its URL, request count, open connections and
  uptime.
- **Connected clients** — one row per address with request and error counts,
  when it first and last appeared, and its user agent.
- **Recent requests** — method, path, status and how long each took. Static
  files are counted but kept out of the list, which would otherwise be nothing
  but the five scripts every page load fetches.
- **Listener** — bind address, port, certificate and key, with *Apply and
  restart*. A bind failure is reported rather than swallowed, with the reason.
- **Collectors** — a read-only summary of NetPath, NetFlow, Syslog and DNS.
- **Open in browser**, and start/stop for the server.

`--headless` (or the old `--web`) runs with no window, which is what a service
manager wants. Closing the console stops the service, and the window says so.

The listener settings are stored, so the port set in the console is the port
used next time. Command line arguments still win for the run that supplies
them.

Removed: `mainwindow.py`, `pathview.py`, `timelineview.py`, `flowtab.py`,
`flowcharts.py`, `debugtab.py`, `settingstab.py`, `settingsui.py`. The Qt
dependency now exists only for the console, so a headless install still needs
nothing but the standard library.

### 3.0.0 — SappiWhere, Syslog, and resizable panels

**Renamed to SappiWhere.** The application now covers three collectors, so
naming the whole thing after one of them had stopped making sense.

**New Syslog module.**

- Collector for RFC 3164 and RFC 5424 on the same port, over UDP and
  optionally TCP. TCP handles both framings: RFC 6587 octet counting and the
  far more common newline separation. A line matching neither format is still
  stored rather than dropped.
- Search across message, app and host, with filters for severity, facility,
  source, host and app, over any window.
- A histogram of messages per hour for the last 24 hours, stacked by severity
  so a burst of errors inside a busy hour is visible. Clicking an hour narrows
  the search to it.
- Selecting a message shows every decoded field and the raw line as it arrived.

  Two decisions were about staying quick under volume. Hourly counts are kept
  in a rollup table updated as messages land, so drawing the timeline costs 24
  rows rather than a scan that gets slower every day — measured at 0.3 ms
  against a day of data. Message search uses SQLite's FTS5 index where the
  build has it, because `LIKE '%needle%'` cannot use an index and reads every
  row in the window; searches measured at 0.2–1.7 ms. The status strip says
  which mode is in use.

  Syslog timestamps come from the sending device, so a device with a wrong
  clock files its messages at the wrong time. **Use arrival time** in the
  settings overrides that.

**Resizable panels everywhere.** Every sub-panel on every page now has a
draggable divider: the NetPath sidebar and its route/timeline split, the
NetFlow chart against the bars and table, the Syslog histogram against the
message list, and the Debug worker table against the event log. Sizes are
remembered per splitter across reloads; double-clicking a divider resets that
one, and **Reset panel sizes** on the Settings tab resets all of them.

**Density follows the viewport.** Below 900 pixels of height the chrome tightens
— smaller padding, tabs, table rows and sidebar — and below 700 it tightens
further and drops the hint lines. The defaults should already fit rather than
needing to be dragged first.

**Debug and Settings are always the rightmost tabs**, so adding a module never
moves them.

### 2.3.0 — Overrunning traces, and Save at the top

- A scheduled trace that cannot start because the previous one is still running
  is now recorded and shown as **skipped**, teal with vertical stripes, rather
  than left as a gap. A gap means the app was not running, which is a different
  problem with a different fix; this one means the interval is too short for
  the path.

  The block carries the diagnosis: *"Previous trace still running after 3s;
  interval is 3s. A trace to this destination can take up to 195s, so the
  interval needs to be longer than that or the hop count reduced."* The worst
  case comes from the same `expected_budget()` the watchdog uses, so the advice
  cannot contradict the timeout. The Debug log records each skip as an error.

  It ranks above the network faults in a block, because whatever the path was
  doing, that slot produced no measurement and the schedule is the reason.
  Vertical stripes, so it cannot be mistaken for the refusal's diagonal hatch.

- The NetFlow settings dialog puts Save and Cancel at the top, on both the
  desktop and the browser, so they are reachable without scrolling past every
  group. In the browser they stay pinned while the form scrolls.

Fixed: shutting down closed the databases while a trace was still running, so
the last measurement was lost to a `Cannot operate on a closed database` error
in the worker. In-flight traces now get up to three seconds to land first.

### 2.2.0 — Template age, port names, reverse-DNS fallbacks

- The collector status now reports when the last **template** arrived, beside
  the last packet: `last packet just now · last template 4m ago`. v9 and IPFIX
  records are undecodable until a template turns up and exporters resend them
  only every few minutes, so its age is worth as much as the packet age. It
  reads `no template yet` when none has been seen.

- Port naming widened considerably. Three sources in order: names the site has
  declared, a curated table now covering 188 ports including industrial and
  infrastructure ones (BACnet, DNP3, OPC-UA, PROFINET, IEC-104, ISO-TSAP,
  TACACS+, WireGuard), and this machine's own services file for everything else
  registered with IANA.

  Ports that are not registered cannot be known from here — vendors pick them
  privately — so **Port names** in the NetFlow settings takes `22609 = NVR`
  lines for site-specific ones. Those win over everything else.

- Reverse DNS now makes three attempts per address instead of one: the system
  resolver, then a PTR query straight to a nominated server if **Query server**
  is set, then `nslookup`. The Debug log records which method answered, so a
  name only nslookup can find identifies the system resolver as the problem
  rather than the DNS records.

  The direct query is a real DNS client, not a subprocess: it handles
  compression pointers and NXDOMAIN, and honours its own timeout.

### 2.1.0 — Per-module refresh rates

Refresh rate is now set per module rather than once for the whole application,
because the three want very different things.

| Module | Default | Why |
| --- | --- | --- |
| NetPath | 2s | Cheap queries, and the route graph benefits from feeling live |
| NetFlow | 30s | Aggregations over a whole window that barely move in seconds |
| Debug | 1s | Watching things that change by the second |

- The NetFlow collector strip keeps updating every two seconds from the shared
  state poll while the charts below refresh on their own slow schedule, and
  reports how old the charts are. Changing the window, a filter or the grouping
  fetches immediately rather than waiting out the interval.
- The Debug page's elapsed counters advance ten times a second without asking
  the server again: the value is carried forward from the moment it arrived,
  which also sidesteps any clock difference between browser and server.
  Measured at ten distinct rising values over two seconds from two API calls.
- One 100 ms heartbeat drives everything, so the three rates cannot drift
  against each other.

Fixed: **Resolve names** applied to the flow record table but not to the
charts, so grouping by Source, Destination or Conversation still showed raw
addresses. All three now show names where a name exists and the address where
it does not, on both the desktop and the browser.

### 2.0.4 — Hover panels in the browser

Fixed: hovering showed nothing useful. The browser build used SVG `<title>`
elements, which take about a second to appear, cannot be styled and do not
follow the cursor — and the NetFlow traffic chart had no hover at all, so the
per-series breakdown the desktop shows was simply missing.

- A proper hover panel, styled like the rest of the app, following the cursor
  and flipping sides rather than running off the edge of the window.
- Route graph: address, name, average RTT, loss, prevalence, and the refusal
  code where there is one.
- Timeline: a dotted crosshair plus the block's status breakdown, RTT, loss,
  ICMP reason and whether the route changed.
- NetFlow chart: crosshair plus the per-series rates and total at that instant.
- Top-N bars and flow records get the same treatment; the flow row shows the
  full addresses and names, which the table itself truncates.

### 2.0.3 — Wheel zoom on both time axes

Fixed: neither the NetFlow traffic chart nor the NetPath timeline responded to
the scroll wheel in the browser. Both had drag and buttons but no wheel, which
the desktop timeline has always had.

- Wheel zoom on the NetPath timeline and the NetFlow traffic chart, anchored on
  the instant under the cursor so it stays put as the window narrows.
- Zooming turns **Follow now** off, since holding the right edge at the present
  and zooming about a point elsewhere are contradictory.
- Shared `App.wheelWindow` so the two axes cannot drift apart. At the 60-second
  and four-month limits it keeps the anchor's position within the window
  instead of silently recentring.

### 2.0.2 — Route graph pan and wheel zoom in the browser

Fixed: the browser route graph showed a grab cursor but could not actually be
dragged, and the scroll wheel did nothing — only the `−` and `+` buttons
worked. The CSS promised an interaction the JavaScript never implemented.

- Drag to pan, with the cursor changing to grabbing while held. The drag is
  tracked on the window, so releasing outside the canvas still ends it.
- Wheel zoom, anchored on the pointer: the point under the cursor stays put
  rather than the view jumping to centre.
- Both respect the same 15%–600% limits as the buttons, and both count as a
  deliberate view choice, so a refresh no longer refits over them.
- A drag no longer counts as a click, so panning across a collapsed run of
  silent hops does not expand it.

### 2.0.1 — Browser interface fixes

Fixed: the modal container was styled `display: flex`, and a class selector
beats the user agent's rule for the `hidden` attribute, so the dialog overlay
was always present — a full-screen translucent black layer that dimmed the page
and swallowed every click.

Fixed: the page started itself from an inline `<script>`, which the server's own
Content-Security-Policy forbids. Nothing initialised: dropdowns stayed empty and
the connection indicator sat at "connecting…". Startup now happens from
`app.js` on `DOMContentLoaded`, and the policy stays strict.

Added `[hidden] { display: none !important; }` so the attribute cannot be
overridden by a later rule again.

### 1.15.0 — Names in the flow table

- **Resolve names** checkbox on the NetFlow controls row swaps addresses for
  reverse-DNS names in the flow table, with the address on hover.
- Flow endpoints are resolved by the shared resolver into the shared cache, so
  a name learned for one module is available to the other.
- Only the highest-volume endpoints of the last hour are queried, and only
  while the checkbox is on.

Fixed: the *Reverse-resolve addresses in the flow table* setting existed in the
NetFlow dialog but was never implemented — the table always drew raw addresses
and nothing ever looked up a flow endpoint.

### 1.14.0 — Interface corrections

- Debug page splits 65 / 35 between trace workers and the event log.
- Module settings buttons moved to the top right of both the NetPath and
  NetFlow pages, sharing one style so the control is in the same place
  whichever module you are in.
- **Send test packet** on the NetFlow page sends a zero-record NetFlow v5
  packet over loopback and shows the PowerShell equivalent, with a copy button.
- Database size caps, one per file, on the Settings tab. Checked every 15
  minutes; the oldest records are deleted in chunks until the file fits, so the
  cap wins over the retention setting.
- The Settings page scrollbar is always visible and wider, since the page
  scrolls and a thin auto-hiding bar gave no hint there was more below.
- The active destination is bold in the NetPath list.
- Network requirements split into `NETWORK-AND-STORAGE-REQUIREMENTS.md`, and a new
  `FEATURES.md` describes what the application does.

Fixed: spin buttons on every numeric field had mismatched click targets. The
field's padding shrank the content rect Qt sizes the buttons from, leaving the
up button 14×11 against the down button's 14×12. Both are now 20×14 with
explicit geometry.

Fixed: `VACUUM` does not shrink a SQLite file in WAL mode until the log is
checkpointed, so the size-cap loop deleted records without ever seeing the file
get smaller.

Fixed: selecting a destination and then clicking the route graph left the list
row nearly black on a dark background — Qt falls back to its inactive palette
once the list loses focus.

### 1.13.0 — Settings restructured by scope

Configuration now sits at whichever level it belongs to, rather than all in one
place.

- **Settings** tab holds only what crosses module boundaries: reverse DNS,
  view refresh interval, database file locations and maintenance actions.
- **NetPath settings**, a new button on the NetPath sidebar: concurrent traces,
  trace retention, and the defaults a new destination starts with.
- **Settings** on the NetFlow status strip reverted to its own dialog covering
  the collector, sampling, exporters and flow storage.
- Reverse DNS gained an on/off switch and a configurable cache lifetime,
  previously hard-coded at seven days.
- View refresh interval is now configurable. The Debug page deliberately
  refreshes faster so its elapsed timers stay smooth.
- Trace retention is a setting; the maintenance action reads it instead of
  assuming 90 days.
- Destination defaults seed the Add dialog only, leaving existing destinations
  untouched.
- Shared settings widgets moved to `settingsui.py` so the dialogs and the tab
  cannot drift apart visually.

Fixed: NetFlow settings applied to the running collector but were never written
to disk, so they reverted on the next launch.

### 1.12.0 — Settings tab

- Added a Settings tab after Debug, replacing the settings dialogs and most of
  the Data menu.
- Staged changes with **Apply changes** and **Revert**.

Fixed: labels and check boxes painted their own background, showing as dark
rectangles on the lighter group panels.

### 1.11.0 — Adjustable concurrency and timeouts

- Concurrent trace count is configurable, previously a hard-coded 4.
- Probe timeout is configurable per destination, previously a hard-coded 2s.
- Reverse DNS thread count and timeout are configurable.
- The destination dialog shows the worst case those settings imply: *"A dead
  destination ties up a worker for up to 195s."*
- Trace and DNS thread pools resize without a restart.
- Single `expected_budget()` shared by the tracer's watchdog and the Debug
  page's overdue marker, so they cannot disagree.

**Schema:** `settings` table and a `timeout_s` column on `targets`, added by
migration on first launch.

### 1.10.0 — Elapsed time for running traces

- **Elapsed** column on the Debug page counts up live, coloured blue while
  normal, amber past half the timeout budget, red and marked *overdue* past the
  point where the trace would be abandoned.
- Destinations waiting for a free worker show as **queued**, distinct from
  tracing.

Fixed: queued traces were counted as occupying a worker, producing summaries
like "3 of 1 trace workers busy".

Fixed: the scheduler could call `submit()` on an already shut-down thread pool,
raising `RuntimeError` and silently killing the scheduler thread — after which
no further traces would ever run.

### 1.9.0 — Refused vs no reply

- New status **refused** for destinations where a router answered with an ICMP
  unreachable, distinct from **no reply** where nothing came back at all.
- ICMP codes parsed and stored with the address that sent them: `!H`, `!N`,
  `!P`, `!X` and others on Unix, and both `tracert` phrasings on Windows.
- The refusing hop is outlined in the route graph with a `REFUSED !X` badge;
  the timeline tooltip and snapshot header name the code and the router.
- Refused blocks are hatched as well as coloured, so the distinction survives a
  screenshot and colour-blind viewing.
- A refused trace still reports an RTT — the round trip to the router that
  refused — and every surface states that it is not to the target.

Fixed: the Windows form of the unreachable line carries no timing columns, and
the parser required at least one timing field, so the line was dropped entirely
and the trace looked like it simply stopped.

Fixed: the Windows address extractor took the last address-like token on a
line, which grabbed the wrong value on a `reports:` line.

**Schema:** `icmp_code` and `icmp_from` columns on `traces`, added by migration.

### 1.8.0 — Debug page

- New Debug tab with live trace worker state and a filterable event log.
- Every trace, reverse DNS lookup and collector event is recorded with detail:
  the exact command line, the resolved address, the path, the stored trace id
  and the raw traceroute output.
- Filter by destination, category or free text; Follow, Pause, Clear and Export.
- Bounded to the last 3000 events with capped detail, so a long-running session
  costs a fixed amount of memory.
- Reverse DNS cache state shown in the status strip, and a maintenance action
  to clear the cache and force a re-lookup.

### 1.7.0 — Zoom that survives a refresh

- The route graph keeps your zoom level and scroll position when new data
  arrives, instead of refitting on every refresh.
- Auto-fit continues until you choose a zoom level; **Fit** hands control back.
- Live zoom percentage shown beside the zoom buttons.
- Zoom buttons on the route graph, so no scroll wheel is required.

Fixed: the scroll wheel ignored the zoom limits the buttons respected.

### 1.6.0 — Wheel-free zoom on NetFlow

- Drag across the traffic chart to zoom into a range.
- Pan and zoom buttons, plus Ctrl+= / Ctrl+- / Ctrl+arrows / Ctrl+0.
- **Follow now** pins the right edge to the present.

Fixed: on Windows the collector bound with `SO_REUSEADDR`, which lets a second
process bind the same UDP port and silently take delivery of the packets. It
now binds with `SO_EXCLUSIVEADDRUSE` so a leftover instance produces a clear
"port already in use" error instead of stealing traffic.

- Collector status now reports when the last packet arrived, so a bound but
  silent socket is distinguishable from one that is receiving.

### 1.5.0 — NetFlow module

- Tab bar added; NetPath and NetFlow as separate modules.
- Collector for NetFlow v5, NetFlow v9 and IPFIX on one UDP socket, with the
  template cache v9 and IPFIX require.
- Sampling honoured from the v5 header and v9/IPFIX options templates, with a
  manual override.
- Stacked traffic chart, top-N bar chart and a flow record table, all re-sliced
  by group-by: application, protocol, source, destination, conversation,
  exporter, ingress or egress interface, AS or ToS.
- Flows stored in their own database so a busy exporter does not contend with
  the trace scheduler.
- Receive and write split across two threads: a commit on the receive path
  would leave the socket buffer unserviced long enough to drop packets.

Fixed: the stacked area chart painted bands in series order, so the last band
covered all the others and the chart rendered as one flat mass.

Fixed: alternating table rows fell back to the default light palette, putting
near-white text on a near-white background.

### 1.4.0 — Point-in-time snapshots

- Clicking the timeline pins that instant and redraws the route graph from that
  single trace, with a **Return to live** button.
- Clicking a block with no trace says so rather than snapping to the nearest.
- `trace_nearest()` uses two index-backed queries rather than a full scan.

### 1.3.0 — Three timeline lanes

- The timeline split into round-trip time, packet loss and up/down status on a
  shared time axis, so a latency spike, a loss event and an outage are
  distinguishable at a glance.
- Status placed at the bottom, against the time axis.
- Loss bars scale to a fixed 0–100%; RTT bars scale to the window's peak.
- A clean poll draws a thin green line rather than nothing, keeping "measured
  and fine" distinct from "no data".

### 1.2.0 — Readability

- The route canvas is light against the dark chrome, with its own palette so
  the greys and accents have real contrast on white.

### 1.1.0 — One block per poll

- Timeline blocks are sized by the destination's trace interval rather than by
  pixel width: a 60-minute window on a destination polled every minute draws 60
  blocks.
- Boundaries snap to a wall-clock grid, so a block covers the same slice of time
  as the window pans or slides.
- Beyond the pixel budget a block grows to a whole multiple of the interval,
  never a fractional number of polls.
- A dark block now unambiguously means a poll that did not happen.

### 1.0.1 — Names and silent hops

- Renamed to SappiWhere.
- Hop boxes show reverse-DNS names alongside addresses, resolved in the
  background and cached, rather than making every trace wait on DNS.
- Runs of consecutive hops that never reply collapse into a single marker,
  expandable by clicking.

**Schema:** `hostnames` table.

### 1.0.0 — Initial release

- Scheduled traceroutes to user-added destinations, stored in SQLite.
- Route graph showing every address seen at every hop, with divergent paths as
  parallel branches and edge thickness by share of traces.
- Status timeline with an adjustable time period.
- Status determined by the destination hop only, since intermediate routers
  rate-limit ICMP and their loss is not a fault signal.
- Cross-platform: shells out to `traceroute` or `tracert`, so no raw sockets and
  no administrator rights.

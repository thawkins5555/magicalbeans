/* NODES' settings dialog, fetched by App.loadExtra the first time the
   Settings button is pressed. Registers on App.extras, not App.pages. */
(() => {
  const escape = App.escapeHtml;

  // The identity fields the device detail header can show, in display
  // order; the detail_fields setting is a comma-separated subset of these.
  const DETAIL_FIELDS = [
    ['sys_descr', 'System description (sysDescr)'],
    ['sys_name', 'SNMP hostname (sysName)'],
    ['sys_object_id', 'sysObjectID'],
    ['sys_contact', 'Contact (sysContact)'],
    ['sys_location', 'Location (sysLocation)'],
    ['vendor', 'Vendor'],
    ['snmp_version', 'SNMP version in use'],
    ['sw_version', 'Software version'],
    ['fw_version', 'Firmware / boot ROM version'],
    ['sw_image', 'Software image (and boot file)'],
  ];

  function settingsDialog(ctx) {
    const { COLUMNS, IFACE_COLUMNS } = ctx;
    const s = App.state.nodesSettings || {};
    const { check, number } = App.form;
    const detailChosen = new Set(String(s.detail_fields || '')
      .split(',').map((f) => f.trim()).filter(Boolean));
    const settingsBox = App.modal('Nodes settings', `
      <fieldset><legend>POLLING</legend>
        ${check('np-enabled', 'Run the poller', s.enabled)}
        ${check('np-workers-auto', 'Size the poll pool automatically', s.poll_workers_auto)}
        ${number('np-workers-min', 'Fewest poll worker threads', s.poll_workers_min, 'min=1 max=512')}
        ${number('np-workers-max', 'Most poll worker threads', s.poll_workers_max, 'min=1 max=512')}
        ${number('np-headroom', 'Spare capacity multiplier', s.poll_pool_headroom, 'min=1 max=4 step=0.1')}
        <p class="hint">With this on (the default), the poller adds up how long each
          device's polls actually take and how often each one is due, keeps enough
          threads for that plus the spare capacity above, and never goes below the
          fewest or above the most. It grows quickly and shrinks slowly. A fleet
          that outgrows the maximum still raises the
          <strong>poll_pool_saturated</strong> alert, which is the one case that
          needs a person. Turn it off to set the number yourself below.</p>
        ${number('np-workers', 'Poll worker threads (when not automatic)', s.poll_workers, 'min=1 max=512')}
        ${number('np-macworkers', 'Table-walk threads', s.mac_walk_workers, 'min=1 max=32')}
        <p class="hint">MAC, LLDP/CDP and VLAN walks run on their own small pool,
          deliberately separate from the poll pool so a walk of a core switch can
          never starve ordinary polling. Four is the shipped default.</p>
        ${number('np-interval', 'Default poll interval', s.default_interval_s, 'min=10')} s
        ${number('np-focus', 'Selected-device poll interval (0 = off)', s.focus_poll_interval_s, 'min=0')} s
        ${number('np-timeout', 'Default SNMP timeout', s.default_snmp_timeout_s, 'min=0.5 step=0.5')} s
        ${number('np-retries', 'Default SNMP retries', s.default_snmp_retries, 'min=0')}
        ${number('np-downafter', 'Consecutive failures before "down"', s.down_after_failures, 'min=1')}
        ${number('np-snmpfailafter', 'SNMP polls missed before "SNMP failing" alert',
                 s.snmp_fail_alert_after, 'min=1')}
        ${check('np-pingonly', 'A device is DOWN only when ping and SNMP both fail', s.unreachable_ping_only)}
        <p class="hint">With this on (the default), a device that still answers ping
          but whose SNMP is failing stays UP and shows its SNMP error, rather than
          being reported as an outage it isn't having. Turn it off to treat SNMP
          failing as down on its own. Overridable per device and per profile.</p>
        ${check('np-v3verify', 'Verify the signature on every SNMPv3 reply',
                s.v3_verify_replies !== false)}
        <p class="hint">New in 5.8.0, and on by default. A signed request's reply
          must come back signed with the same key, and an encrypted request's
          reply encrypted; anything less is refused as a downgrade and the device
          shows why. <b>Turning this off gives that up for every device</b> — an
          unsigned answer is accepted, as every release before 5.8.0 accepted
          it, though a reply that does carry a signature is still verified —
          so use it only to
          keep polling one agent or proxy that answers unsigned while you chase
          that device, not as a fix.</p>
      </fieldset>
      <fieldset><legend>PING</legend>
        ${number('np-pingcount', 'Probes per ping', s.ping_count, 'min=1 max=20')}
        ${number('np-pingtimeout', 'Ping timeout', s.ping_timeout_ms, 'min=100 step=100')} ms
        ${number('np-pinginterval', 'Ping every (0 = with every poll)', s.ping_interval_s, 'min=0')} s
        <p class="hint">Every SNMP-polled device is pinged as well, and the results
          become the <code>ping_loss_pct</code> and <code>ping_rtt_ms</code> metrics
          the packet-loss and response-time alert rules watch. More than one probe per
          poll is what makes loss measurable at all — a single probe can only ever say
          0% or 100%. Both are overridable per device and per profile.</p>
      </fieldset>
      <fieldset><legend>SNMP TABLE WALKS</legend>
        ${number('np-bulkreps', 'GETBULK rows per request (0 = GETNEXT only)',
                 s.snmp_bulk_max_repetitions, 'min=0 step=5')}
        ${number('np-tablewalkrows', 'Stop a table walk after',
                 s.snmp_walk_max_rows, 'min=100 step=1000')} rows
        <p class="hint">Every table walk — interfaces, MAC forwarding tables,
          DOM sensors, and the OID browser's own per-subtree reads — uses
          GETBULK on v2c/v3: one request answers this many rows instead of
          one GETNEXT per row. 0 falls back to plain GETNEXT, for a device
          whose agent mishandles GetBulk. A device answering "tooBig" is
          retried automatically at half as many rows. v1 always uses
          GETNEXT — GETBULK does not exist in that version of the
          protocol.</p>
      </fieldset>
      <fieldset><legend>MAC ADDRESS &amp; ARP TABLES</legend>
        ${number('np-macretention', 'Forget a learned MAC after',
                 s.mac_table_retention_days, 'min=0 step=1')} days
        <p class="hint">Which switches learn MAC addresses at all, and how
          often, is set per polling profile (<b>Learn MAC addresses every</b>);
          which routers have their ARP cache read is set the same way
          (<b>Read the ARP cache every</b>) and is off by default. This is only
          how long an entry stays searchable once no walk has refreshed it,
          so a device dropped from the schedule stops answering the Find box
          from a table nobody has confirmed since. ARP rows age out on this
          same clock — it is the same "nothing has walked this device"
          question, not a second one.</p>
      </fieldset>
      <fieldset><legend>FULL SNMP WALK</legend>
        ${number('np-walkrows', 'Stop a full walk after',
                 s.oid_walk_max_rows, 'min=100 step=1000')} objects
        ${number('np-walkbudget', 'or after', s.oid_walk_budget_s,
                 'min=10 step=10')} seconds
        <p class="hint">Bounds on <b>Download full walk</b> in the OID browser.
          Generous, because that runs as a background job with a progress
          count and a cancel rather than in a dialog you are waiting on — but
          real, so a device whose agent loops cannot walk forever. Whichever
          bound stops a walk is named in the downloaded file's header.</p>
      </fieldset>
      <fieldset><legend>VENDOR IDENTIFICATION</legend>
        ${check('np-vendorwalk', 'Identify a device\'s vendor by walking its enterprise arcs once',
                s.vendor_walk_enabled !== false)}
        ${number('np-vendorobjects', 'Stop the identification walk after',
                 s.vendor_walk_max_objects, 'min=50 step=50')} objects
        ${number('np-vendorbudget', 'or after', s.vendor_walk_budget_s,
                 'min=5 step=5')} seconds
        ${number('np-vendorparallel', 'At most', s.vendor_walk_parallel,
                 'min=1 max=16')} walks at once
        ${check('np-dischop', 'Discovery sweeps also list each device\'s enterprise arcs',
                s.discovery_arc_hop !== false)}
        <p class="hint">Runs once per device on its first successful poll, again
          only if its sysObjectID changes, and behind <b>Re-identify</b> — never
          on the steady-state poll cycle. A device that stops answering is
          retried at most three times, an hour apart. The sweep's arc listing
          is separate and cheap: one GETNEXT per enterprise arc a device
          answers under, typically three to eight per device.</p>
      </fieldset>
      <fieldset><legend>DISCOVERY</legend>
        <p class="hint">Every discovery sweep now uses a chosen polling
          profile's own credentials — see the Profile picker on the
          Discovery subtab.</p>
        ${number('np-maxscan', 'Max addresses per subnet sweep', s.max_scan_addresses, 'min=1')}
        ${number('np-discworkers', 'Addresses probed at once',
                 s.discovery_workers, 'min=1 max=256')}
        <p class="hint">How many addresses a sweep identifies in parallel. It
          does not raise the packet rate — probes are still released at the
          configured probes per second; the workers only overlap the waiting,
          which is what a sweep of a large subnet spends nearly all its time
          doing. The Start-discovery dialog can set a different figure for one
          scan.</p>
      </fieldset>
      <fieldset><legend>DEVICE DETAILS</legend>
        <p class="hint">Identity fields shown in a device's detail header.
          IP, status and any SNMP error always show.</p>
        ${DETAIL_FIELDS.map(([key, label]) =>
          check(`np-df-${key}`, label, detailChosen.has(key))).join('')}
      </fieldset>
      ${App.columnPickerFieldset('DEVICE LIST COLUMNS', 'devices', COLUMNS,
                                 s.table_columns)}
      ${App.columnPickerFieldset('INTERFACE LIST COLUMNS', 'ifaces', IFACE_COLUMNS,
                                 s.table_columns_ifaces)}
      <fieldset><legend>STORAGE</legend>
        ${number('np-sampledays', 'Keep raw samples for', s.sample_retention_days, 'min=1')} days
        ${number('np-rollupdays', 'Keep hourly rollups for', s.rollup_retention_days, 'min=1')} days
        ${number('np-if-sampledays', 'Keep per-port raw samples for', s.interface_sample_retention_days, 'min=1')} days
        ${number('np-if-rollupdays', 'Keep per-port hourly rollups for', s.interface_rollup_retention_days, 'min=1')} days
        <p class="hint">Raw samples are rolled up into hourly minimum, average
          and maximum before the raw rows are dropped, so the rollup figure is
          what decides how far back a wide chart can go. The first two fields
          are the device-level tier — CPU, memory, reachability, the worst-port
          summaries. The two below them are the per-interface tier, every
          metric whose key ends in a port index: they are the great majority
          of the rows in the metric history file, so they keep a shorter
          history. Shortening either tier is a one-way door — history already
          dropped does not come back if you raise the number again.</p>
        ${number('np-eventdays', 'Keep events for', s.event_retention_days, 'min=1')} days
        ${number('np-maxmib', 'Max MIB file size', Math.round((s.max_mib_bytes || 0) / 1024 / 1024), 'min=1')} MB
        <p class="hint">A chart is drawn from raw samples while its window
          fits inside that metric's own raw retention — ${s.sample_retention_days || 3}
          days for a device-level metric, ${s.interface_sample_retention_days || 1}
          for a per-port one; anything wider reads hourly rollups (min, average
          and max per hour), which are summarised once an hour and kept for
          ${s.rollup_retention_days || 400} days device-level and
          ${s.interface_rollup_retention_days || 90} per port. So raw retention
          decides how far back you can see every individual poll — not how far
          back the chart goes. Raw samples are also capped at
          ${(s.sample_row_cap_per_metric || 5000).toLocaleString()} per metric,
          which at the default interval is roughly a week.</p>
        <p class="hint">All four settings are ceilings, not guarantees: the
          metric history file also has a size cap on Settings → Data &amp;
          Retention, and when it is over that cap the oldest hourly rollups
          go first and then, once those are at their floor, the oldest raw
          samples, whichever tier they belong to. Settings shows how far back
          the file still reaches.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
        const { on, num } = App.form.readers(box);
        await App.post('/api/settings', { scope: 'nodes', values: {
          enabled: on('#np-enabled'), poll_workers: num('#np-workers'),
          poll_workers_auto: on('#np-workers-auto'),
          poll_workers_min: num('#np-workers-min'),
          poll_workers_max: num('#np-workers-max'),
          poll_pool_headroom: num('#np-headroom'),
          mac_walk_workers: num('#np-macworkers'),
          default_interval_s: num('#np-interval'), focus_poll_interval_s: num('#np-focus'),
          default_snmp_timeout_s: num('#np-timeout'),
          default_snmp_retries: num('#np-retries'), down_after_failures: num('#np-downafter'),
          snmp_fail_alert_after: num('#np-snmpfailafter'),
          unreachable_ping_only: on('#np-pingonly'),
          v3_verify_replies: on('#np-v3verify'),
          ping_count: num('#np-pingcount'),
          ping_timeout_ms: num('#np-pingtimeout'),
          ping_interval_s: num('#np-pinginterval'),
          mac_table_retention_days: num('#np-macretention'),
          snmp_bulk_max_repetitions: num('#np-bulkreps'),
          snmp_walk_max_rows: num('#np-tablewalkrows'),
          oid_walk_max_rows: num('#np-walkrows'),
          oid_walk_budget_s: num('#np-walkbudget'),
          vendor_walk_enabled: on('#np-vendorwalk'),
          vendor_walk_max_objects: num('#np-vendorobjects'),
          vendor_walk_budget_s: num('#np-vendorbudget'),
          vendor_walk_parallel: num('#np-vendorparallel'),
          discovery_arc_hop: on('#np-dischop'),
          max_scan_addresses: num('#np-maxscan'),
          discovery_workers: Math.max(1, num('#np-discworkers') || 0),
          detail_fields: DETAIL_FIELDS.map(([key]) => key)
            .filter((key) => on(`#np-df-${key}`)).join(','),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-devices'), COLUMNS),
          table_columns_ifaces: App.readColumnPicker(
            box.querySelector('#cols-ifaces'), IFACE_COLUMNS),
          sample_retention_days: num('#np-sampledays'),
          rollup_retention_days: num('#np-rollupdays'),
          interface_sample_retention_days: num('#np-if-sampledays'),
          interface_rollup_retention_days: num('#np-if-rollupdays'),
          event_retention_days: num('#np-eventdays'),
          max_mib_bytes: num('#np-maxmib') * 1024 * 1024,
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('nodes');
        })()) },
    ], { buttonsTop: true });
    App.wireColumnPickers(settingsBox);
  }

  App.extras.nodesSettings = { open: settingsDialog };
})();

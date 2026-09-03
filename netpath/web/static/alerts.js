/* The Alerts page: open/acked/resolved alerts with a histogram, rules and
   email templates. Table/modal patterns follow snmp.js and ipam.js. */
(() => {
  const SEV_COLOR = ['var(--fail)', 'var(--fail)', 'var(--fail)', 'var(--blocked)',
                     'var(--warn)', 'var(--text)', 'var(--accent)', 'var(--faint)'];
  const PAD = { left: 40, right: 10, top: 8, bottom: 18 };

  const view = {
    t0: Date.now() / 1000 - 86400,
    t1: Date.now() / 1000,
    alerts: [],
    selected: null,
    checked: new Set(),
    // Set by bulkAction right after a resolve/acknowledge completes ("Resolved
    // 3 of 3"): shown on the engine counters line for a few seconds, then
    // dropped by the first drawStatus after it expires. Not in the bulk bar:
    // that bar hides the instant the selection clears, and the refresh the
    // action triggers runs synchronously, so nothing put there would paint.
    bulkNotice: null,
    // Per session only, like every other table's sort: a saved sort order is
    // a different feature from saved columns, and mixing the two storage
    // models is how Reset layout ends up eating a settings choice.
    alertSort: { key: 'last_ts', descending: true },
    rules: [],
    rulesSelected: null,
    templates: [],
    templatesSelected: null,
    hist: null,
    // device entity_id -> until_ts, refreshed with the rest of the page.
    mutes: new Map(),
    // What the detail pane was last rendered from, so a refresh that
    // changes nothing leaves the markup (and any open dropdown) alone.
    detailSignature: null,
  };

  const MUTE_HOURS = [1, 6, 12, 24];

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function ago(ts) {
    if (!ts) return '—';
    const age = Date.now() / 1000 - ts;
    if (age < 5) return 'just now';
    if (age < 90) return `${Math.round(age)}s ago`;
    if (age < 5400) return `${Math.round(age / 60)}m ago`;
    return `${(age / 3600).toFixed(1)}h ago`;
  }

  function window_() {
    const seconds = Number(App.el('alerts-range').value) || 86400;
    view.t1 = Date.now() / 1000;
    view.t0 = view.t1 - seconds;
    return { t0: view.t0, t1: view.t1 };
  }

  function filters() {
    return {
      state: App.el('alerts-filter-state').value,
      severity: App.el('alerts-filter-sev').value,
      rule_id: App.el('alerts-filter-rule').value,
      device: App.el('alerts-filter-device').value.trim(),
      q: App.el('alerts-filter-text').value.trim(),
    };
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const alerts = server.alerts || { counters: {} };
    App.el('alerts-status').textContent = alerts.status || 'Engine stopped';
    App.el('alerts-dot').style.background = alerts.running ? 'var(--ok)' : 'var(--faint)';
    App.el('alerts-toggle').textContent = alerts.running ? 'Stop engine' : 'Start engine';
    const c = alerts.counters || {};
    App.el('alerts-counters').textContent =
      `${c.opened || 0} opened · ${c.resolved || 0} resolved · ` +
      `${c.emails_sent || 0} emails sent` +
      (c.suppressed ? ` · ${c.suppressed} suppressed` : '') +
      (c.send_errors ? ` · ${c.send_errors} send errors` : '') +
      (view.bulkNotice && Date.now() < view.bulkNotice.until
        ? ` · ${view.bulkNotice.text}` : '');
    if (view.bulkNotice && Date.now() >= view.bulkNotice.until) view.bulkNotice = null;
    const badge = App.el('alerts-open-badge');
    const openCount = alerts.open_count || 0;
    badge.textContent = openCount;
    badge.hidden = openCount === 0;
  }

  /* --------------------------------------------------------- histogram */

  function drawHistogram() {
    const svg = App.el('alerts-hist-svg');
    svg.innerHTML = '';
    const box = App.el('alerts-hist').getBoundingClientRect();
    const width = Math.max(box.width, 300);
    const height = Math.max(box.height, 70);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const data = view.hist;
    if (!data || !data.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 12 }, 'No alerts in this window'));
      return;
    }
    const plot = { x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: Math.max(height - PAD.top - PAD.bottom, 10) };
    const peak = Math.max(...data.map((b) => b.total), 1);
    const slotWidth = plot.w / data.length;
    data.forEach((bucket, index) => {
      const x = plot.x + index * slotWidth;
      const w = Math.max(slotWidth - 1, 1);
      if (!bucket.total) return;
      let bottom = plot.y + plot.h;
      const severities = Object.keys(bucket.by_severity).map(Number).sort((a, b) => b - a);
      for (const sev of severities) {
        const count = bucket.by_severity[String(sev)];
        const h = (count / peak) * plot.h;
        bottom -= h;
        svg.appendChild(App.svgNode('rect', {
          x, y: bottom, width: w, height: Math.max(h, 1),
          fill: SEV_COLOR[sev] || 'var(--muted)', 'fill-opacity': 0.85 }));
      }
      const hit = App.svgNode('rect', { x, y: plot.y, width: w, height: plot.h,
        fill: 'transparent', style: 'cursor:pointer' });
      hit.addEventListener('mousemove', (event) =>
        App.tooltip(`${new Date(bucket.t0 * 1000).toLocaleString()}\n${bucket.total} alert(s)`, event));
      hit.addEventListener('mouseleave', App.hideTooltip);
      svg.appendChild(hit);
    });
  }

  /* ------------------------------------------------------------- table */

  const COLUMNS = [
    // A real checkbox column, because Ctrl-click alone is invisible: a plain
    // click looks like it selects a row when all it does is move the detail
    // highlight, so a bulk action then acts on far fewer rows than the
    // operator believes they picked.
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      cell: (r) => `<input type="checkbox" class="alerts-check"${
        view.checked.has(r.id) ? ' checked' : ''}>` },
    { key: 'severity', label: 'Sev', width: 60, numeric: true, on: true,
      cell: (r) => `<span class="sev sev-${r.severity}">${r.severity}</span>` },
    { key: 'state', label: 'State', width: 80, on: true },
    { key: 'entity_label', label: 'Object', width: 170, on: true },
    { key: 'rule_name', label: 'Rule', width: 150, on: true },
    { key: 'message', label: 'Message', width: 260, on: true,
      cell: (r) => `<span class="msg">${escape(r.message)}</span>` },
    { key: 'count', label: 'Count', width: 60, numeric: true, on: true,
      cell: (r) => (r.count > 1 ? r.count : '') },
    { key: 'opened_ts', label: 'Opened', width: 90, numeric: true, on: true,
      cell: (r) => ago(r.opened_ts) },
    { key: 'last_ts', label: 'Last seen', width: 90, numeric: true, on: true,
      cell: (r) => ago(r.last_ts) },
    { key: 'severity_name', label: 'Severity name', width: 110 },
    { key: 'acked_by', label: 'Acknowledged by', width: 140,
      cell: (r) => escape(r.acked_by || '\u2014') },
    { key: 'resolved_ts', label: 'Resolved', width: 90, numeric: true,
      cell: (r) => (r.resolved_ts ? ago(r.resolved_ts) : '\u2014') },
    { key: 'entity_kind', label: 'Kind', width: 80 },
  ];

  const alertColumns = () => App.visibleColumns(
    COLUMNS, (App.state.alertsSettings || {}).table_columns);

  function onAlertSort(key, descending) {
    view.alertSort = { key, descending };
    drawTable();
  }

  function drawTable() {
    const columns = alertColumns();
    const checked = view.checked;
    const table = App.grid(App.el('alerts-table'), {
      name: 'alerts', caption: 'Alerts', columns,
      sort: view.alertSort, onSort: onAlertSort,
      selectAll: {
        key: 'check',
        checked: view.alerts.length > 0 && view.alerts.every((a) => checked.has(a.id)),
        some: view.alerts.some((a) => checked.has(a.id)),
        onToggle: (on) => {
          checked.clear();
          if (on) for (const a of view.alerts) checked.add(a.id);
          drawTable();
        },
      } });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.alerts, view.alertSort.key,
                              view.alertSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable'
        + (view.selected === row.id ? ' selected' : '')
        + (view.checked.has(row.id) ? ' bulk-checked' : '');
      // The checkbox owns selection; the rest of the row owns the detail
      // pane. stopPropagation keeps ticking a box from also moving the
      // highlight, which would make one click mean two different things.
      const box = tr.querySelector('.alerts-check');
      if (box) {
        box.onclick = (event) => {
          event.stopPropagation();
          toggleChecked(row.id, tr);
        };
      }
      tr.onclick = () => {
        view.selected = row.id;
        drawTable();
        showDetail(row);
      };
    });
    table.appendChild(body);
    App.el('alerts-count').textContent = `${view.alerts.length} shown`;
    drawBulkBar();
  }

  /* ------------------------------------------------------- bulk actions */

  /* Given the row, only that row is touched: redrawing every row to change
     one checkbox is what made ticking several alerts feel slow on a long
     list — the boxes themselves cost nothing. */
  function toggleChecked(id, tr) {
    const on = !view.checked.has(id);
    if (on) view.checked.add(id);
    else view.checked.delete(id);
    if (tr) {
      tr.classList.toggle('bulk-checked', on);
      const box = tr.querySelector('.alerts-check');
      if (box) box.checked = on;
      App.refreshSelectAll(App.el('alerts-table'), view.alerts.length,
                           view.checked.size);
      drawBulkBar();
      return;
    }
    drawTable();
  }


  function drawBulkBar() {
    const n = view.checked.size;
    App.el('alerts-bulk-bar').hidden = n === 0;
    if (n) App.el('alerts-bulk-count').textContent = `${n} selected`;
  }

  /* A bulk action changes state for potentially every alert on screen,
     including whichever one is currently open in the detail pane — unlike
     a single-row action, there's no cheap way to know if what's shown is
     still accurate, so every bulk action always deselects rather than
     leaving stale severity/state/button data on screen. refresh()'s own
     cleanup only catches an alert that *vanished* from the list, which a
     state change alone (still open, now acked) never does. */
  function clearSelection() {
    view.selected = null;
    App.el('alerts-detail-empty').hidden = false;
    App.el('alerts-detail').hidden = true;
  }

  async function bulkResolve() {
    await bulkAction('/api/alerts/bulk-resolve', 'Resolved', 'resolved');
  }

  async function bulkAcknowledge() {
    await bulkAction('/api/alerts/bulk-ack', 'Acknowledged', 'acknowledged');
  }

  /* Both bulk actions have the same shape: act on exactly what is ticked,
     then drop the selection and the detail pane, because either could have
     changed the state of whatever was on show. `key` is the count the API
     hands back ({"resolved": n} / {"acknowledged": n}) — read here rather
     than assumed equal to the selection, since a row someone else already
     resolved between the tick and the click counts as ticked but not acted
     on, and a mismatch is exactly what an operator needs to see. */
  async function bulkAction(path, verb, key) {
    const ids = [...view.checked];
    if (!ids.length) return;
    const result = await App.post(path, { alert_ids: ids });
    // The notice is painted on the counters line, which reruns every poll
    // and would be a noisy live region; the one-shot result is announced
    // through the shared sr-only status instead.
    App.announce(`${verb} ${result[key]} of ${ids.length}`);
    view.bulkNotice = { text: `${verb} ${result[key]} of ${ids.length}`,
                        until: Date.now() + 6000 };
    clearSelection();
    view.checked.clear();
    drawBulkBar();
    drawStatus();
    App.refreshNow('alerts');
  }

  function showDetail(row) {
    App.el('alerts-detail-empty').hidden = true;
    const el = App.el('alerts-detail');
    el.hidden = false;
    // The refresh re-renders this pane so an alert's state and its device's
    // mute stay true without a click — but rebuilding the markup wholesale
    // every few seconds would close the mute dropdown under an operator
    // half way through choosing a duration, and re-fetch the notification
    // list for nothing. So the pane is rebuilt only when something it
    // actually displays has changed.
    const signature = [row.id, row.state, row.count, row.last_ts,
                       row.acked_by, row.resolved_ts, row.rollup_note,
                       view.mutes.get(String(row.entity_id)) || ''].join('|');
    if (view.detailSignature === signature) return;
    view.detailSignature = signature;
    const rows = view.rules.length ? view.rules : [];
    const rule = rows.find((r) => r.id === row.rule_id);
    // Only a Nodes device can be muted; entity_id is already its device id.
    // Checked against canWrite here rather than tagged data-requires-write,
    // because applyPermissions only ever runs over markup that already
    // exists — see the note on it in app.js.
    const muteable = row.entity_kind === 'device' && row.entity_id
      && App.canWrite('alerts');
    const mutedUntil = row.entity_kind === 'device'
      ? view.mutes.get(String(row.entity_id)) : null;
    let muteHtml = '';
    if (mutedUntil) {
      muteHtml = `<span class="hint" id="alerts-d-muted">Muted until ` +
        `${escape(new Date(mutedUntil * 1000).toLocaleTimeString())}</span>` +
        (muteable ? `<button id="alerts-d-unmute">Lift mute</button>` : '');
    } else if (muteable) {
      muteHtml = `<select id="alerts-d-mute-hours" title="How long to silence new alerts for this device">` +
        MUTE_HOURS.map((h) => `<option value="${h}">${h} hour${h === 1 ? '' : 's'}</option>`).join('') +
        `</select><button id="alerts-d-mute">Mute device</button>`;
    }
    el.innerHTML = `
      <div class="bar"><span class="section sev sev-${row.severity}">${escape(row.severity_name)}</span>
        <span class="grow"></span>
        ${muteHtml}
        ${row.state !== 'resolved' ? '<button id="alerts-d-resolve">Resolve</button>' : ''}
        ${row.state === 'open' ? '<button id="alerts-d-ack">Acknowledge</button>' : ''}</div>
      <p><b>${escape(row.entity_label)}</b> · ${escape(row.rule_name)}</p>
      <p>${escape(row.message)}</p>
      ${row.detail ? `<p class="hint">${escape(row.detail)}</p>` : ''}
      ${row.rollup_note ? `<p class="hint"><b>Rolled up into this alert</b><br>` +
        `${escape(row.rollup_note).split('\n').join('<br>')}</p>` : ''}
      <p class="hint">Opened ${new Date(row.opened_ts * 1000).toLocaleString()} · ` +
        `last seen ${new Date(row.last_ts * 1000).toLocaleString()} · occurred ${row.count} time(s)</p>
      ${row.acked_by ? `<p class="hint">Acknowledged by ${escape(row.acked_by)}${row.ack_note ? `: ${escape(row.ack_note)}` : ''}</p>` : ''}
      ${row.resolved_ts ? `<p class="hint">Resolved ${new Date(row.resolved_ts * 1000).toLocaleString()}${row.resolved_by ? ` by ${escape(row.resolved_by)}` : ' automatically'}` +
        // How long it stood, which is the question a resolved alert is
        // usually opened to answer. Both timestamps are already on the row,
        // so this costs nothing.
        `${App.duration(row.resolved_ts - row.opened_ts) ? ` · open for ${App.duration(row.resolved_ts - row.opened_ts)}` : ''}</p>` : ''}
      <div class="bar"><span class="section">NOTIFICATIONS</span></div>
      <div id="alerts-d-notifications" class="hint">Loading…</div>`;
    const resolveBtn = document.getElementById('alerts-d-resolve');
    if (resolveBtn) resolveBtn.onclick = async () => {
      await App.post(`/api/alerts/${row.id}/resolve`, {});
      App.refreshNow('alerts');
    };
    const ackBtn = document.getElementById('alerts-d-ack');
    if (ackBtn) ackBtn.onclick = async () => {
      await App.post(`/api/alerts/${row.id}/ack`, {});
      App.refreshNow('alerts');
    };
    const muteBtn = document.getElementById('alerts-d-mute');
    if (muteBtn) muteBtn.onclick = async () => {
      const hours = Number(App.el('alerts-d-mute-hours').value) || 1;
      await App.post('/api/alerts/mute', {
        entity_kind: 'device', entity_id: String(row.entity_id), hours });
      App.refreshNow('alerts');
    };
    const unmuteBtn = document.getElementById('alerts-d-unmute');
    if (unmuteBtn) unmuteBtn.onclick = async () => {
      await App.del('/api/alerts/mute', {
        entity_kind: 'device', entity_id: String(row.entity_id) });
      App.refreshNow('alerts');
    };
    App.get(`/api/alerts/${row.id}`).then((full) => {
      const box = document.getElementById('alerts-d-notifications');
      if (!box) return;
      if (!full.notifications.length) { box.textContent = 'None sent.'; return; }
      box.innerHTML = full.notifications.map((n) =>
        `<div>${new Date(n.ts * 1000).toLocaleString()} — ${escape(n.kind)} to ${escape(n.to_addr)}: ` +
        `${n.ok ? 'sent' : `<span class="err">failed (${escape(n.error)})</span>`}</div>`).join('');
    }).catch(() => {});
  }

  /* --------------------------------------------------------------- rules */

  function drawRulesTable() {
    const table = App.el('alerts-rules-table');
    table.innerHTML = '<caption class="sr-only">Alert rules</caption><thead><tr><th scope="col">Name</th>' +
      '<th scope="col">Kind</th><th scope="col">Sev</th><th scope="col">On</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const r of view.rules) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.rulesSelected === r.id ? ' selected' : '');
      tr.innerHTML = `<td>${escape(r.name)}${r.is_builtin ? '' : ' <span class="hint">(custom)</span>'}</td>` +
        `<td>${escape(r.kind)}${r.source_kind ? `: ${escape(r.source_kind)}` : ''}</td>` +
        `<td><span class="sev sev-${r.severity}">${r.severity}</span></td>` +
        `<td>${r.enabled ? 'yes' : 'no'}</td>`;
      tr.onclick = () => { view.rulesSelected = r.id; drawRulesTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function templateOptionsHtml(selectedId) {
    return `<option value="">(none)</option>` + view.templates.map((t) =>
      `<option value="${t.id}" ${t.id === selectedId ? 'selected' : ''}>${escape(t.name)}</option>`).join('');
  }

  function editRule() {
    const r = view.rules.find((x) => x.id === view.rulesSelected);
    if (!r) return;
    // dhcp_threshold and netpath_threshold are threshold rules in every
    // respect the editor cares about — they just measure a DHCP scope or a
    // traceroute destination rather than a device metric. A kind missing from
    // this list opens an editor with no threshold fields at all.
    const isThreshold = r.kind === 'threshold' || r.kind === 'dhcp_threshold'
      || r.kind === 'netpath_threshold';
    const pollNoun = { dhcp_threshold: 'DHCP polls',
                       netpath_threshold: 'traces' }[r.kind] || 'polls';
    // The flapping rule counts link transitions in a time window rather than
    // comparing a value to a threshold, so it gets its own two fields
    // instead of the threshold ones.
    const isFlapping = r.source_kind === 'flapping';
    App.modal(`Edit ${r.name}`, `
      <label>Name <input id="ar-name" value="${escape(r.name)}"></label>
      <label>Severity <select id="ar-sev">${[0,1,2,3,4,5,6,7].map((n) =>
        `<option value="${n}" ${r.severity === n ? 'selected' : ''}>${n} ${App.state.severities?.[n] || ''}</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" id="ar-enabled" ${r.enabled ? 'checked' : ''}> Enabled</label>
      <label>Device filter (substring, blank = all) <input id="ar-devfilter" value="${escape(r.device_filter || '')}"></label>
      <label>Template <select id="ar-template">${templateOptionsHtml(r.template_id)}</select></label>
      ${isThreshold ? `
      <label>Threshold <input id="ar-threshold" type="number" step="0.1" value="${r.threshold ?? ''}"></label>
      <label>Clear threshold <input id="ar-clear" type="number" step="0.1" value="${r.clear_threshold ?? ''}"></label>
      <label>Consecutive ${pollNoun} before firing <input id="ar-forpolls" type="number" min="1" value="${r.for_polls || 1}"></label>
      ${r.kind === 'threshold' ? `
      <label>Or: sustained for <input id="ar-forseconds" type="number" min="0"
        placeholder="off" value="${r.for_seconds ?? ''}"> seconds</label>
      <p class="hint">Blank counts polls, as above. A number here requires the
        breach to have lasted that long in real polling time instead —
        measured between the samples themselves, so a device that stopped
        being polled cannot accumulate time while silent.</p>
      ${r.key === 'packet_loss_high' ? `<p class="hint">Loss is quantised by
        Nodes&nbsp;&rarr;&nbsp;Settings&nbsp;&rarr;&nbsp;<b>Ping probes per
        poll</b>: at the default of 3 the only measurable values are 0, 33, 67
        and 100&nbsp;%, so any threshold from 1 to 33 means "one probe of three
        lost". Raise the probe count for a finer threshold.</p>` : ''}` : ''}
      ${isFlapping ? `
      <label>Flaps before firing <input id="ar-flapcount" type="number" min="2"
        placeholder="3" value="${r.flap_min_transitions ?? ''}"></label>
      <label>Within <input id="ar-flapwindow" type="number" min="1"
        placeholder="10" value="${r.flap_window_s ? Math.round(r.flap_window_s / 60) : ''}"> minutes</label>
      <p class="hint">Fires when an interface records this many link up/down
        transitions inside the window. Blank uses the shipped defaults, 3
        transitions within 10 minutes.</p>` : ''}
      ${r.kind === 'dhcp_threshold' ? `<p class="hint">Percentage of a scope's
        address range that is leased or reserved. Counted the same way the DHCP
        page counts it, and evaluated once per DHCP poll rather than once per
        alert-engine tick, so "consecutive polls" means what it says.</p>` : ''}
      ${r.kind === 'netpath_threshold' ? `<p class="hint">${{
        trace_loss_pct: 'Packet loss to the destination itself, on its latest' +
          ' trace. Intermediate routers are never measured — rate-limited ICMP' +
          ' from a transit hop is not a fault. 100 means nothing came back at all.',
        trace_unreached_pct: 'Share of a destination\'s recent traces that did' +
          ' not reach it, over the longer of an hour and six trace intervals,' +
          ' and only once at least five traces have landed in that window.' +
          ' This is the rule that catches a path that works intermittently.',
        trace_rtt_warn_pct: 'Round-trip time as a percentage of THIS' +
          ' destination\'s own warn threshold, not a fixed number of' +
          ' milliseconds — 300 means three times whatever that destination is' +
          ' set to warn at, so one rule suits a LAN hop and a satellite link.' +
          ' Thresholds below 20 ms are treated as 20 ms, since three times a' +
          ' few milliseconds is ordinary jitter. Only measured on a trace that' +
          ' reached the destination.',
      }[r.source_kind] || 'Evaluated once per completed trace to this' +
        ' destination, so "consecutive traces" means what it says.'}</p>` : ''}` : ''}
      `, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const values = {
          name: box.querySelector('#ar-name').value.trim(),
          severity: Number(box.querySelector('#ar-sev').value),
          enabled: box.querySelector('#ar-enabled').checked,
          device_filter: box.querySelector('#ar-devfilter').value.trim(),
          template_id: box.querySelector('#ar-template').value ? Number(box.querySelector('#ar-template').value) : null,
        };
        if (isThreshold) {
          values.threshold = Number(box.querySelector('#ar-threshold').value);
          values.clear_threshold = Number(box.querySelector('#ar-clear').value);
          values.for_polls = Number(box.querySelector('#ar-forpolls').value);
          const seconds = box.querySelector('#ar-forseconds');
          if (seconds) {
            // Blank (and 0) mean NULL — "count polls" — the same
            // blank-is-the-shipped-default the flapping fields use.
            const text = seconds.value.trim();
            values.for_seconds = text === '' || Number(text) === 0
              ? null : Number(text);
          }
        }
        if (isFlapping) {
          // Blank means NULL — "use the shipped defaults" — not zero, which
          // would mean "fire on no transitions at all".
          const count = box.querySelector('#ar-flapcount').value.trim();
          const minutes = box.querySelector('#ar-flapwindow').value.trim();
          values.flap_min_transitions = count === '' ? null : Number(count);
          values.flap_window_s = minutes === '' ? null : Number(minutes) * 60;
        }
        await App.put(`/api/alerts/rules/${r.id}`, values);
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ]);
  }

  function addRule() {
    App.modal('Add custom rule', `
      <label>Key (stable identifier) <input id="ar-key" placeholder="my_custom_rule"></label>
      <label>Name <input id="ar-name"></label>
      <label>Kind <select id="ar-kind">
        <option value="device_event">device_event</option>
        <option value="interface_event">interface_event</option>
        <option value="threshold">threshold</option>
        <option value="dhcp_threshold">dhcp_threshold</option>
        <option value="netpath_threshold">netpath_threshold</option>
        <option value="wireless_event">wireless_event</option>
        <option value="trap">trap</option>
        <option value="syslog">syslog</option>
        <option value="ipam">ipam</option>
      </select></label>
      <label>Source kind (meaning depends on kind — e.g. device_event: down/up/rebooted; threshold: a metric key) <input id="ar-source"></label>
      <label>Severity <select id="ar-sev">${[0,1,2,3,4,5,6,7].map((n) =>
        `<option value="${n}" ${n === 4 ? 'selected' : ''}>${n} ${App.state.severities?.[n] || ''}</option>`).join('')}</select></label>
      <label>Template <select id="ar-template">${templateOptionsHtml(null)}</select></label>
      <label>Threshold (threshold rules only) <input id="ar-threshold" type="number" step="0.1"></label>
      <label>Clear threshold (threshold rules only) <input id="ar-clear" type="number" step="0.1"></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        const key = box.querySelector('#ar-key').value.trim();
        const name = box.querySelector('#ar-name').value.trim();
        if (!key || !name) return;
        const values = {
          key, name, kind: box.querySelector('#ar-kind').value,
          source_kind: box.querySelector('#ar-source').value.trim(),
          severity: Number(box.querySelector('#ar-sev').value),
          template_id: box.querySelector('#ar-template').value ? Number(box.querySelector('#ar-template').value) : null,
        };
        const t = box.querySelector('#ar-threshold').value;
        const c = box.querySelector('#ar-clear').value;
        if (t) values.threshold = Number(t);
        if (c) values.clear_threshold = Number(c);
        await App.post('/api/alerts/rules', values);
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ]);
  }

  function removeRule() {
    const r = view.rules.find((x) => x.id === view.rulesSelected);
    if (!r || r.is_builtin) return;
    App.modal('Remove rule', `<p>Remove <b>${escape(r.name)}</b>?</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Remove', primary: true, onClick: async () => {
        await App.del(`/api/alerts/rules/${r.id}`);
        App.closeModal();
        view.rulesSelected = null;
        App.refreshNow('alerts');
      } },
    ]);
  }

  /* ----------------------------------------------------------- templates */

  function drawTemplatesTable() {
    const table = App.el('alerts-templates-table');
    table.innerHTML = '<caption class="sr-only">Notification templates</caption><thead><tr><th scope="col">Name</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const t of view.templates) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.templatesSelected === t.id ? ' selected' : '');
      tr.innerHTML = `<td>${escape(t.name)}${t.is_builtin ? '' : ' <span class="hint">(custom)</span>'}</td>`;
      tr.onclick = () => { view.templatesSelected = t.id; drawTemplatesTable(); };
      tr.ondblclick = () => editTemplate(t.id);
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function editTemplate(id) {
    const t = view.templates.find((x) => x.id === id) ||
      view.templates.find((x) => x.id === view.templatesSelected);
    if (!t) return;
    const tokens = t.tokens || [];
    const box = App.modal(`Edit template: ${t.name}`, `
      <label>Name <input id="at-name" value="${escape(t.name)}" ${t.is_builtin ? 'readonly' : ''}></label>
      <label>Subject <input id="at-subject" value="${escape(t.subject)}"></label>
      <label>Body <textarea id="at-body" rows="10">${escape(t.body)}</textarea></label>
      <label class="check"><input type="checkbox" id="at-html" ${t.is_html ? 'checked' : ''}> HTML body</label>
      <div class="bar"><span class="section">TOKENS (click to insert)</span></div>
      <div id="at-tokens" style="max-height:140px;overflow:auto;border:1px solid var(--hairline);border-radius:4px;padding:6px">
        ${tokens.map((tok) => `<div class="clickable token-row" data-token="${escape(tok.token)}"><code>{{${escape(tok.token)}}}</code> — ${escape(tok.description)}</div>`).join('')}
      </div>
      <div id="at-preview" class="hint"></div>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Preview', onClick: async (box) => {
        // Preview requires the template already saved; save first then preview.
        await saveTemplate(box, t, true);
      } },
      ...(t.is_builtin ? [{ label: 'Reset to default', onClick: () => {
        App.confirmDestructive('Reset template',
          `<p>Reset <b>${escape(t.name)}</b> to the text it shipped with?</p>` +
          '<p class="hint">Your edits to this template\'s subject and body are ' +
          'discarded and cannot be recovered.</p>', 'Reset', async () => {
            await App.post(`/api/alerts/templates/${t.id}/reset`, {});
            App.refreshNow('alerts');
          }, (confirmed) => { if (!confirmed) editTemplate(t); });
      } }] : []),
      { label: 'Save', primary: true, onClick: (box) => saveTemplate(box, t, false) },
    ], { buttonsTop: true });
    box.classList.add('wide');
    for (const row of box.querySelectorAll('.token-row')) {
      row.onclick = () => {
        const textarea = box.querySelector('#at-body');
        const pos = textarea.selectionStart || textarea.value.length;
        const token = `{{${row.dataset.token}}}`;
        textarea.value = textarea.value.slice(0, pos) + token + textarea.value.slice(pos);
        textarea.focus();
      };
    }
  }

  async function saveTemplate(box, t, previewOnly) {
    const values = {
      name: box.querySelector('#at-name').value.trim(),
      subject: box.querySelector('#at-subject').value,
      body: box.querySelector('#at-body').value,
      is_html: box.querySelector('#at-html').checked,
    };
    await App.put(`/api/alerts/templates/${t.id}`, values);
    if (previewOnly) {
      const preview = await App.post(`/api/alerts/templates/${t.id}/preview`, {});
      box.querySelector('#at-preview').innerHTML =
        `<div class="bar"><span class="section">PREVIEW</span></div>` +
        `<p><b>${escape(preview.subject)}</b></p><pre>${escape(preview.body)}</pre>`;
      return;
    }
    App.closeModal();
    App.refreshNow('alerts');
  }

  function addTemplate() {
    App.modal('Add template', `
      <label>Key (stable identifier) <input id="at-key" placeholder="my_template"></label>
      <label>Name <input id="at-name"></label>
      <label>Subject <input id="at-subject"></label>
      <label>Body <textarea id="at-body" rows="8"></textarea></label>
      <label class="check"><input type="checkbox" id="at-html"> HTML body</label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        const key = box.querySelector('#at-key').value.trim();
        const name = box.querySelector('#at-name').value.trim();
        if (!key || !name) return;
        await App.post('/api/alerts/templates', {
          key, name, subject: box.querySelector('#at-subject').value,
          body: box.querySelector('#at-body').value,
          is_html: box.querySelector('#at-html').checked,
        });
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ], { buttonsTop: true });
  }

  /* ---------------------------------------------------------- settings */

  function normalizeRecipients(raw) {
    if (Array.isArray(raw)) return raw.slice();
    return String(raw || '').split(',').map((a) => a.trim()).filter(Boolean);
  }

  function recipientsListHtml(list) {
    if (!list.length) return '<p class="hint">No recipients yet.</p>';
    const rows = list.map((addr, index) => `
      <tr>
        <td>${escape(addr)}</td>
        <td><button type="button" class="as-to-remove" data-index="${index}">Remove</button></td>
      </tr>`).join('');
    return `<table><caption class="sr-only">Alert details</caption><tbody>${rows}</tbody></table>`;
  }

  function settingsDialog() {
    const s = App.state.alertsSettings || {};
    const recipients = normalizeRecipients(s.smtp_to_default);
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const box = App.modal('Alerts settings', `
      <fieldset><legend>ENGINE</legend>
        ${check('as-enabled', 'Run the alert engine', s.enabled)}
        <label>Evaluate severity <select id="as-minsev"></select> and worse (syslog only)</label>
        ${number('as-retention', 'Keep resolved alerts for', s.retention_days, 'min=1')} days
      </fieldset>
      <fieldset><legend>EMAIL SERVER</legend>
        ${check('as-email', 'Send email notifications', s.email_enabled)}
        <label>SMTP host <input id="as-host" value="${escape(s.smtp_host || '')}"></label>
        ${number('as-port', 'Port', s.smtp_port, 'min=1 max=65535')}
        <label>Security <select id="as-security">
          <option value="none" ${s.smtp_security === 'none' ? 'selected' : ''}>None</option>
          <option value="starttls" ${!s.smtp_security || s.smtp_security === 'starttls' ? 'selected' : ''}>STARTTLS</option>
          <option value="ssl" ${s.smtp_security === 'ssl' ? 'selected' : ''}>SSL/TLS</option>
        </select></label>
        ${check('as-verify', 'Verify server certificate', s.smtp_verify_cert !== false)}
        <label>Username <input id="as-user" value="${escape(s.smtp_username || '')}"></label>
        <label>Password <input id="as-pass" type="password"
          placeholder="${s.has_smtp_credential ? 'stored — leave blank to keep' : ''}"></label>
        <p class="hint" id="as-cred-status"></p>
      </fieldset>
      <fieldset><legend>IDENTITY &amp; RECIPIENTS</legend>
        <label>From address <input id="as-from" value="${escape(s.smtp_from || '')}"></label>
        <label>From name <input id="as-fromname" value="${escape(s.smtp_from_name || '')}"></label>
        <p class="hint">Default recipients</p>
        <div id="as-to-list">${recipientsListHtml(recipients)}</div>
        <label>Add recipient <input id="as-to-add" placeholder="name@example.com"></label>
        <button type="button" id="as-to-add-btn">Add</button>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        ${number('as-renotify', 'Re-notify an open alert every', s.renotify_minutes, 'min=0')} min (0 = once)
        ${check('as-clear', 'Send an email when an alert clears', s.notify_on_clear)}
        ${number('as-maxhour', 'Max emails per hour', s.max_emails_per_hour, 'min=1')}
        ${number('as-grace', 'Hold alerts on a newly added device for',
                 Math.round((s.new_device_grace_s ?? 300) / 60), 'min=0')} min
        <p class="hint">A device added a moment ago is usually still being set
          up — wrong community, not cabled yet, still booting — so its alerts
          are held this long and then raised only if the condition is still
          true. One that settles inside the window never alerts at all. A
          one-off event that cannot still be true later (rebooted, recovered)
          is dropped rather than raised late. 0 turns the hold off.</p>
        ${check('as-rollup', 'Roll implied alerts up under the device-down alert',
                s.rollup_enabled !== false)}
        <p class="hint">A device that has stopped answering also looks slow and
          lossy, and its CPU, memory, interface and storage figures stop being
          measurable — so one outage used to arrive as five or six emails. With
          this on, only <b>Device not responding</b> is raised: the ping and
          SNMP-metric alerts it implies are resolved into it and named in its
          details. Interface up/down and flapping alerts are never rolled up —
          a port that went down for its own reason is still worth knowing about.
          When the device comes back, any metric that is genuinely still
          breaching re-opens on the next poll by itself.</p>
      </fieldset>
      ${App.columnPickerFieldset('ALERT LIST COLUMNS', 'alerts', COLUMNS,
                                 s.table_columns)}
      <fieldset><legend>TEST</legend>
        <label>Send a test email to <input id="as-testto" placeholder="you@example.com"></label>
        <p class="hint" id="as-test-status"></p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Send test', onClick: async (box) => {
        const to = box.querySelector('#as-testto').value.trim();
        const status = box.querySelector('#as-test-status');
        if (!to) { status.textContent = 'Enter a recipient first'; return; }
        status.textContent = 'Sending…';
        try {
          const result = await App.post('/api/alerts/smtp/test', { to });
          status.textContent = result.ok ? 'Sent.' : `Failed: ${result.error}`;
        } catch (error) {
          status.textContent = `Error: ${error.message}`;
        }
      } },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        const text = (id) => box.querySelector(id).value.trim();
        const password = box.querySelector('#as-pass').value;
        if (password) {
          try {
            await App.post('/api/alerts/smtp/credential', { password });
          } catch (error) {
            box.querySelector('#as-cred-status').textContent = error.message;
            return;
          }
        }
        await App.post('/api/settings', { scope: 'alerts', values: {
          enabled: on('#as-enabled'), min_severity: Number(box.querySelector('#as-minsev').value),
          retention_days: num('#as-retention'), email_enabled: on('#as-email'),
          smtp_host: text('#as-host'), smtp_port: num('#as-port'),
          smtp_security: box.querySelector('#as-security').value,
          smtp_verify_cert: on('#as-verify'), smtp_username: text('#as-user'),
          smtp_from: text('#as-from'), smtp_from_name: text('#as-fromname'),
          smtp_to_default: recipients, renotify_minutes: num('#as-renotify'),
          notify_on_clear: on('#as-clear'), max_emails_per_hour: num('#as-maxhour'),
          new_device_grace_s: num('#as-grace') * 60,
          rollup_enabled: on('#as-rollup'),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-alerts'), COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ], { buttonsTop: true });
    App.wireColumnPickers(box);
    const select = box.querySelector('#as-minsev');
    (App.state.severities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = name;
      select.appendChild(option);
    });
    select.value = String(s.min_severity ?? 7);

    function renderRecipients() {
      box.querySelector('#as-to-list').innerHTML = recipientsListHtml(recipients);
      for (const btn of box.querySelectorAll('.as-to-remove')) {
        btn.onclick = () => {
          recipients.splice(Number(btn.dataset.index), 1);
          renderRecipients();
        };
      }
    }
    renderRecipients();
    box.querySelector('#as-to-add-btn').onclick = () => {
      const input = box.querySelector('#as-to-add');
      const addr = input.value.trim();
      if (!addr || !addr.includes('@')) return;
      recipients.push(addr);
      input.value = '';
      renderRecipients();
    };
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'alerts') return;
    drawStatus();
    const { t0, t1 } = window_();
    const span = t1 - t0;
    const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);
    const f = filters();
    const [overview, list, rules, templates, mutes] = await Promise.all([
      App.get('/api/alerts/overview', { t0, t1, bucket }),
      App.get('/api/alerts', f),
      App.get('/api/alerts/rules'),
      App.get('/api/alerts/templates'),
      App.get('/api/alerts/mutes'),
    ]);
    view.hist = overview.buckets;
    view.alerts = list.alerts;
    view.rules = rules.rules;
    view.templates = templates.templates;
    // entity_id -> until_ts, for the devices with an active mute. The server
    // only ever returns unexpired ones, so presence here means muted.
    view.mutes = new Map(mutes.mutes.filter((m) => m.entity_kind === 'device')
      .map((m) => [String(m.entity_id), m.until_ts]));
    view.checked = new Set([...view.checked].filter((id) =>
      view.alerts.some((a) => a.id === id)));
    const current = view.alerts.find((a) => a.id === view.selected);
    if (view.selected && !current) {
      view.selected = null;
      view.detailSignature = null;
      App.el('alerts-detail-empty').hidden = false;
      App.el('alerts-detail').hidden = true;
    }
    fillRuleFilter();
    drawHistogram();
    drawTable();
    // Re-render the open detail from the row we just fetched, so its state
    // and the device's mute stay true without a click. Only after
    // drawTable(), which owns the row highlight.
    if (current) showDetail(current);
    drawRulesTable();
    drawTemplatesTable();
  }

  function fillRuleFilter() {
    const select = App.el('alerts-filter-rule');
    const current = select.value;
    select.innerHTML = '<option value="">any rule</option>' +
      view.rules.map((r) => `<option value="${r.id}">${escape(r.name)}</option>`).join('');
    select.value = current;
  }

  function init() {
    for (const btn of document.querySelectorAll('#page-alerts > .subtabs > .subtab')) {
      btn.onclick = () => selectSub(btn.dataset.subtab);
    }
    App.fillRanges(App.el('alerts-range'), 'Last 24 hours');
    const sev = App.el('alerts-filter-sev');
    sev.innerHTML = '<option value="">Any severity</option>';
    (App.state.severities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = `${name} and worse`;
      sev.appendChild(option);
    });
    App.el('alerts-apply').onclick = () => App.refreshNow('alerts');
    for (const id of ['alerts-filter-device', 'alerts-filter-text']) {
      App.el(id).onkeydown = (e) => { if (e.key === 'Enter') App.refreshNow('alerts'); };
    }
    for (const id of ['alerts-filter-sev', 'alerts-filter-state', 'alerts-filter-rule', 'alerts-range']) {
      App.el(id).onchange = () => App.refreshNow('alerts');
    }
    // Acknowledge-all and bulk-resolve don't delete rows, but they change
    // state for everything on screen in one click and there is no undo, so
    // they get the same guard as a delete.
    App.el('alerts-ack-all').onclick = () => {
      const open = view.alerts.filter((a) => a.state === 'open').length;
      App.confirmDestructive('Acknowledge all',
        `<p>Acknowledge every open alert${open ? ` (${open} shown)` : ''}?</p>` +
        '<p class="hint">Every open alert on the server — not your ticked ' +
        'selection, and not just the ones matching the current filter. Use ' +
        '"Acknowledge selected" for the rows you have ticked. They cannot be ' +
        'un-acknowledged in bulk.</p>', 'Acknowledge', async () => {
          await App.post('/api/alerts/ack-all', {});
          view.checked.clear();
          clearSelection();
          App.refreshNow('alerts');
        });
    };
    App.el('alerts-bulk-ack').onclick = () => {
      const n = view.checked.size;
      if (!n) return;
      App.confirmDestructive('Acknowledge alerts',
        `<p>Acknowledge the <b>${n}</b> selected alert(s)?</p>` +
        '<p class="hint">Only the ones you have ticked, and only those still ' +
        'open. They cannot be un-acknowledged in bulk.</p>',
        'Acknowledge', bulkAcknowledge);
    };
    App.el('alerts-bulk-resolve').onclick = () => {
      const n = view.checked.size;
      if (!n) return;
      App.confirmDestructive('Resolve alerts',
        `<p>Resolve the <b>${n}</b> selected alert(s)?</p>` +
        '<p class="hint">Resolved alerts are what "Delete resolved alerts" in ' +
        'Settings later removes.</p>', 'Resolve', bulkResolve);
    };
    App.el('alerts-bulk-clear').onclick = () => { view.checked.clear(); drawTable(); };
    App.el('alerts-toggle').onclick = async () => {
      const running = (App.state.serverState.alerts || {}).running;
      await App.post('/api/alerts/engine', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('alerts');
    };
    App.el('alerts-settings').onclick = settingsDialog;
    App.el('alerts-add-rule').onclick = addRule;
    App.el('alerts-edit-rule').onclick = editRule;
    App.el('alerts-remove-rule').onclick = removeRule;
    App.el('alerts-add-template').onclick = addTemplate;
    App.el('alerts-edit-template').onclick = () => editTemplate(view.templatesSelected);

    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'alerts') drawHistogram();
      });
    }
  }

  function selectSub(name) {
    for (const btn of document.querySelectorAll('#page-alerts > .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#page-alerts > .subpage')) {
      page.classList.toggle('active', page.id === `alerts-sub-${name}`);
    }
  }

  App.pages.alerts = { init, refresh, fastTick: drawStatus };
})();

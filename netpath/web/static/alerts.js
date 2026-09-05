/* The Alerts page: open/acked/resolved alerts with a histogram, rules and
   email templates. Table/modal patterns follow snmp.js and ipam.js. */
(() => {

  const view = {
    t0: Date.now() / 1000 - 86400,
    t1: Date.now() / 1000,
    alerts: [],
    selected: null,
    checked: new Set(),
    // Set by bulkAction right after a resolve/acknowledge completes ("Resolved
    // 3 of 3"), and by detailAction when a single-row action fails: shown on
    // the engine counters line for a few seconds, then dropped by the first
    // drawStatus after it expires. Not in the bulk bar:
    // that bar hides the instant the selection clears, and the refresh the
    // action triggers runs synchronously, so nothing put there would paint.
    bulkNotice: null,
    // How many alerts match the current filters, against the capped page the
    // list is actually showing. {total, capped, cap} from /api/alerts/total.
    alertTotal: null,
    // {ruleId: {auto_resolve_after_s, notify}} from /api/alerts/rules/extras.
    ruleExtras: {},
    // Newest first until the operator clicks a heading. That click is
    // remembered per browser (App.recallSort) — separately from the column
    // *choice*, which is an account setting: mixing the two storage models
    // is how Reset layout ends up eating a settings choice.
    alertSort: App.recallSort('alerts', { key: 'last_ts', descending: true }),
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
    // Paging past ALERTS_LIST_CAP (4.47.0): the campaign that found
    // alerts_truncated at fleet scale was an operator paging through an
    // incident looking at a view that was truncated at exactly the moment
    // completeness mattered. pageFilterSig is the last filter combination
    // a page was fetched under — when it changes the offset resets, same
    // as nodes.js's device pager.
    pageOffset: 0,
    pageLimit: 300,
    pageFilterSig: null,
  };

  const MUTE_HOURS = [1, 6, 12, 24];

  /* How the detail pane names an alert's object when it has to explain why
     Mute is unavailable. Only the kinds that do NOT resolve to a device need
     a phrase here; device and interface both do, so they never reach it. */
  const KIND_LABELS = {
    trap: 'an SNMP trap', syslog: 'a syslog source', ipam: 'an IPAM address',
    ap: 'a wireless access point', dhcp_scope: 'a DHCP scope',
    netpath_target: 'a NetPath destination',
  };

  // One implementation, in app.js. This was twelve copies of the same three
  // lines, which is how one of them came to be missing a character while the
  // others were not — this copy omitted the apostrophe.
  const escape = App.escapeHtml;

  // One relative-time vocabulary for the whole product: App.ago (app.js).
  const ago = (ts) => App.ago(ts, '\u2014');

  /* Fills in the two device-address links beside the object line once the
     ip lookup resolves \u2014 done after the pane is already on screen so
     opening an alert never waits on a Nodes fetch. Guarded by the alert
     still being the one on screen: a slow lookup landing after the
     operator moved to another alert must not rewrite a pane that has
     moved on. deviceId arrives as the String() showDetail's signature
     needs; App.deviceIndex's byId is keyed by the device row's own
     (numeric) id, so it is looked up back as a number. */
  async function loadDeviceLinks(deviceId, alertId) {
    const { byId } = await App.deviceIndex();
    const device = byId.get(Number(deviceId));
    const ip = device ? device.ip : null;
    if (view.selected !== alertId || !ip) return;
    const box = document.getElementById('alerts-d-links');
    if (!box) return;
    box.innerHTML =
      `<a class="linkish inline" href="${App.buildRoute('syslog', [], { source: ip })}">Syslog for this device</a> \u00b7 ` +
      `<a class="linkish inline" href="${App.buildRoute('snmp', [], { source: ip })}">Recent traps</a>`;
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
      // The rule list is filled by the refresh below, so on the load after a
      // reload the restored choice is not on the element yet; the first fetch
      // has to honour it or the list contradicts the filter for a tick. Once
      // the list exists the control answers for itself — including "any rule",
      // which the old `value || saved` form could not express.
      rule_id: App.controlOrSaved('alerts', 'alerts-filter-rule'),
      device: App.el('alerts-filter-device').value.trim(),
      q: App.el('alerts-filter-text').value.trim(),
    };
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const alerts = server.alerts || { counters: {} };
    App.setText(App.el('alerts-status'), alerts.status || 'Alert engine stopped');
    App.setBg(App.el('alerts-dot'), alerts.running ? 'var(--ok)' : 'var(--line)');
    App.setText(App.el('alerts-toggle'), alerts.running ? 'Stop alert engine' : 'Start alert engine');
    const c = alerts.counters || {};
    if (App.state.kiosk) {
      App.setHtml(App.el('alerts-counters'), App.figures([
        { value: alerts.open_count || 0, label: 'open',
          className: alerts.open_count ? 'warn' : '' },
        { value: c.opened || 0, label: 'opened' },
        { value: c.resolved || 0, label: 'resolved' },
      ]));
    } else App.setText(App.el('alerts-counters'),
      `${c.opened || 0} opened · ${c.resolved || 0} resolved · ` +
      `${c.emails_sent || 0} emails sent` +
      (c.suppressed ? ` · ${c.suppressed} suppressed` : '') +
      (c.send_errors ? ` · ${c.send_errors} send errors` : '') +
      // Only shown once the webhook channel has actually done something —
      // most installs never turn it on, and a permanent ". 0 webhooks sent"
      // would be noise on every one of them.
      (c.webhooks_sent || c.webhook_errors
        ? ` · ${c.webhooks_sent || 0} webhooks sent` +
          (c.webhook_errors ? ` (${c.webhook_errors} failed)` : '') : '') +
      // How far behind the engine is, and how many events it could not
      // apply: an engine that has stopped keeping up used to look exactly
      // like one with nothing to do.
      (c.backlog ? ` · ${Number(c.backlog).toLocaleString()} event(s) behind` : '') +
      (c.apply_errors ? ` · ${Number(c.apply_errors).toLocaleString()} apply errors` : '') +
      (view.bulkNotice && Date.now() < view.bulkNotice.until
        ? ` · ${view.bulkNotice.text}` : ''));
    if (view.bulkNotice && Date.now() >= view.bulkNotice.until) view.bulkNotice = null;
    const badge = App.el('alerts-open-badge');
    const openCount = alerts.open_count || 0;
    App.setText(badge, String(openCount));
    if (badge.hidden !== (openCount === 0)) badge.hidden = openCount === 0;
    // Both injected in init() (see its own comment on why) rather than
    // declared with data-requires-write, so this is what keeps them honest
    // against a grant that changes while the page is open.
    const writable = App.canWrite('alerts');
    for (const id of ['alerts-bulkmute-btn', 'alerts-bulk-unack']) {
      const btn = document.getElementById(id);
      if (!btn) continue;
      if (btn.disabled !== !writable) btn.disabled = !writable;
      const title = writable ? '' : 'Needs Alerts write';
      if (btn.title !== title) btn.title = title;
    }
  }

  /* --------------------------------------------------------- histogram */

  function drawHistogram() {
    // No click here: Alerts has no pinned-window mode, so the bars carry no
    // pointer cursor either (they used to promise a click they never had).
    const plot = view.histPlot || { buckets: view.hist || [], span: view.t1 - view.t0 };
    App.stackedHistogram(App.el('alerts-hist-svg'), App.el('alerts-hist'), {
      buckets: plot.buckets, unit: 'alerts', span: plot.span,
      empty: 'No alerts in this window', minHeight: 70,
    });
  }

  /* ------------------------------------------------------------- table */

  const COLUMNS = [
    // A real checkbox column, because Ctrl-click alone is invisible: a plain
    // click looks like it selects a row when all it does is move the detail
    // highlight, so a bulk action then acts on far fewer rows than the
    // operator believes they picked.
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      // See the Nodes device list: an unlabelled box in a row is only
      // identifiable by counting rows.
      cell: (r) => `<input type="checkbox" class="alerts-check" aria-label="Select alert on ${
        escape(r.entity_label || r.object || 'this object')}"${
        view.checked.has(r.id) ? ' checked' : ''}>` },
    { key: 'severity', label: 'Sev', width: 60, numeric: true, mono: false, on: true,
      // The name, not the digit. Syslog and SNMP Trap both show the word in
      // this column; Alerts showed "2" and kept the word in a column that is
      // off by default, so the one page an operator triages from was the one
      // that made them remember the scale.
      cell: (r) => `<span class="sev sev-${r.severity}">${
        escape(App.state.severities?.[r.severity] || r.severity)}</span>` },
    { key: 'state', label: 'State', width: 80, on: true },
    { key: 'entity_label', label: 'Object', width: 170, on: true },
    { key: 'rule_name', label: 'Rule', width: 150, on: true },
    { key: 'message', label: 'Message', width: 260, on: true,
      cell: (r) => `<span class="msg">${escape(r.message)}</span>` },
    { key: 'count', label: 'Count', width: 60, numeric: true, on: true,
      cell: (r) => (r.count > 1 ? r.count : '') },
    { key: 'opened_ts', label: 'Opened', width: 90, numeric: true, on: true,
      cell: (r) => App.agoCell(r.opened_ts, '\u2014') },
    { key: 'last_ts', label: 'Last seen', width: 90, numeric: true, on: true,
      cell: (r) => App.agoCell(r.last_ts, '\u2014') },
    { key: 'severity_name', label: 'Severity name', width: 110 },
    { key: 'acked_by', label: 'Acknowledged by', width: 140,
      cell: (r) => escape(r.acked_by || '\u2014') },
    { key: 'resolved_ts', label: 'Resolved', width: 90, numeric: true,
      cell: (r) => App.agoCell(r.resolved_ts, '\u2014') },
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
        // It only ever reaches the rows that were sent. Saying "select all"
        // above a truncated list is how select-all-then-acknowledge came to
        // acknowledge 300 of 1,842.
        label: truncated() ? `Select the ${view.alerts.length} shown`
                           : 'Select all rows',
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
        // #/alerts/998 — the link that goes in the ticket.
        App.setRoute([row.id]);
        drawTable();
        showDetail(row);
      };
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
    App.el('alerts-count').textContent = countLabel();
    drawBulkBar();
  }

  /* True when the server sent fewer alerts than match the filters — the
     case the old "300 shown" label hid. */
  function truncated() {
    const t = view.alertTotal;
    if (!t || typeof t.total !== 'number') return false;
    return t.capped || t.total > view.alerts.length;
  }

  function countLabel() {
    const t = view.alertTotal || {};
    return App.countLabel(view.alerts.length,
      typeof t.total === 'number' ? t.total : null, !!t.capped);
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
    return bulkAction('/api/alerts/bulk-resolve', 'Resolved', 'resolved');
  }

  async function bulkAcknowledge() {
    return bulkAction('/api/alerts/bulk-ack', 'Acknowledged', 'acknowledged');
  }

  /* Both bulk actions have the same shape: act on exactly what is ticked,
     then drop the selection and the detail pane, because either could have
     changed the state of whatever was on show. `key` is the count the API
     hands back ({"resolved": n} / {"acknowledged": n}) — read here rather
     than assumed equal to the selection, since a row someone else already
     resolved between the tick and the click counts as ticked but not acted
     on, and a mismatch is exactly what an operator needs to see. Returns
     the outcome sentence — App.runJob at the call site defaults its "done"
     label to a resolved string, and toasts (and announces) it there, so
     this no longer has to call App.announce itself. */
  async function bulkAction(path, verb, key) {
    const ids = [...view.checked];
    if (!ids.length) return null;
    const result = await App.post(path, { alert_ids: ids });
    const text = `${verb} ${result[key]} of ${ids.length}`;
    // Also painted on the counters line, which reruns every poll and would
    // be a noisy live region on its own — the toast is the one-shot report.
    view.bulkNotice = { text, until: Date.now() + 6000 };
    clearSelection();
    view.checked.clear();
    drawBulkBar();
    drawStatus();
    App.refreshNow('alerts');
    return text;
  }

  /* One line at the top of the detail pane saying an action on THIS alert
     failed. The counters line says so too, but that is at the other end of
     the page and expires after a few seconds; the operator's eyes are on the
     button they just pressed. Cleared on the next success and wiped by the
     next full rebuild of the pane — which the signature guard skips while
     nothing about the alert has changed, so a failure that changed nothing
     leaves the line standing. */
  function detailError(text) {
    const pane = document.getElementById('alerts-detail');
    if (!pane) return;
    let line = document.getElementById('alerts-d-error');
    if (!text) {
      if (line) line.remove();
      return;
    }
    if (!line) {
      line = document.createElement('p');
      line.id = 'alerts-d-error';
      line.className = 'hint';
      line.style.color = 'var(--fail)';
      pane.insertBefore(line, pane.firstChild);
    }
    line.textContent = text;
  }

  // Past tense for the button/toast once App.runJob's promise settles —
  // the label a caller passes in ("Resolve", "Mute") is the verb, not the
  // outcome.
  const DETAIL_DONE = { Resolve: 'Resolved', Acknowledge: 'Acknowledged',
    Unacknowledge: 'Unacknowledged', Mute: 'Muted', 'Lift mute': 'Mute lifted' };

  /* Every single-row action in the detail pane goes through here. Each one
     used to `await App.post` bare, so a 403 (an account whose grant changed
     under an open page) or a 500 left the button looking as though it had
     worked and the alert unchanged — and Acknowledge was the sharpest case:
     the pane kept offering "Acknowledge" after it had worked, so the only
     way to tell was to re-read the State column. App.runJob now disables
     the button, names the outcome on it and in a toast, and — since
     showDetail() below rebuilds the button row from the alert's new state —
     a button whose action just succeeded is usually not even there any
     more by the time its "done" label would revert. A failure now lands in
     three places that matter: the engine counters line, where the bulk
     actions report theirs; the detail pane itself, where the button is; and
     nowhere at all in the console, because the refresh is awaited inside
     its own try. */
  async function detailAction(label, run, button) {
    try {
      await App.runJob(button, { queued: `${label}…`,
        done: DETAIL_DONE[label] || 'Done' }, run());
      detailError('');
    } catch (error) {
      const text = `${label} failed: ${error.message}`;
      view.bulkNotice = { text, until: Date.now() + 6000 };
      drawStatus();
      detailError(text);
    }
    // Awaited, and its own failure caught: an un-awaited refresh left the
    // button looking as though the action had worked while the pane still
    // showed the old state, and a refresh that itself failed threw out of an
    // event handler into the console.
    try {
      await App.refreshNow('alerts');
    } catch (error) { /* the notice above already says what happened */ }
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
    // device_id is the API's resolution of this alert to a Nodes device by
    // the same rule the engine's mute check uses: a device alert is its own
    // device, an interface alert is the switch the port is on, and anything
    // outside Nodes (a trap from an unpolled host, a DHCP scope, an AP) is
    // null. It is in the signature because the mute area is drawn from it.
    const deviceId = row.device_id ? String(row.device_id) : '';
    const mutedUntil = deviceId ? (view.mutes.get(deviceId) || null) : null;
    const signature = [row.id, row.state, row.count, row.last_ts,
                       row.acked_by, row.resolved_ts, row.rollup_note,
                       deviceId, mutedUntil || ''].join('|');
    if (view.detailSignature === signature) return;
    view.detailSignature = signature;
    const rows = view.rules.length ? view.rules : [];
    const rule = rows.find((r) => r.id === row.rule_id);
    // Checked against canWrite here rather than tagged data-requires-write,
    // because applyPermissions only ever runs over markup that already
    // exists — see the note on it in app.js.
    const writable = App.canWrite('alerts');
    const muteable = Boolean(deviceId) && writable;
    // The mute area is always drawn, disabled with a reason rather than
    // absent: a control that silently is not there reads as a missing
    // feature, which is exactly how "Mute Device is gone" was reported.
    // A device or interface alert whose device has since been removed from
    // Nodes resolves to nothing either, and saying so beats naming a kind
    // that plainly is muteable everywhere else on the page.
    const wasDevice = row.entity_kind === 'device' || row.entity_kind === 'interface';
    const why = deviceId
      ? 'Muting a device needs Alerts write'
      : (wasDevice
        ? 'The device this alert is about is no longer in Nodes'
        : `Mute is for device alerts; this one is about ` +
          `${KIND_LABELS[row.entity_kind] || 'an object outside Nodes'}`);
    let muteHtml;
    if (mutedUntil) {
      const until = escape(App.when(mutedUntil));
      muteHtml = `<span class="hint" id="alerts-d-muted">Muted until ${until}</span>` +
        (muteable
          ? `<button id="alerts-d-unmute">Lift mute</button>`
          : `<button disabled title="${escape(why)}">Lift mute</button>`);
    } else if (muteable) {
      muteHtml = `<select id="alerts-d-mute-hours" class="fixed" title="How long to silence new alerts for this device">` +
        MUTE_HOURS.map((h) => `<option value="${h}">${h} hour${h === 1 ? '' : 's'}</option>`).join('') +
        `</select><button id="alerts-d-mute">Mute device</button>`;
    } else {
      muteHtml = `<button id="alerts-d-mute" disabled title="${escape(why)}">Mute device</button>`;
    }
    // One line under the bar saying why the button is dead, because a
    // disabled control with only a tooltip is unreadable on a touch screen
    // and invisible to anyone who does not think to hover it.
    const muteHint = muteable
      ? '' : `<p class="hint" id="alerts-d-mute-why">${escape(why)}</p>`;
    el.innerHTML = `
      <div class="bar wrap"><span class="section sev sev-${row.severity}">${escape(row.severity_name)}</span>
        <span class="grow"></span>
        ${muteHtml}
        ${writable && row.state !== 'resolved' ? '<button id="alerts-d-resolve">Resolve</button>' : ''}
        ${writable && row.state === 'open' ? '<button id="alerts-d-ack">Acknowledge</button>' : ''}
        ${writable && row.state === 'acked' ? '<button id="alerts-d-unack">Unacknowledge</button>' : ''}</div>
      ${muteHint}
      <p><b>${deviceId
        ? `<a class="linkish inline" href="${App.buildRoute('nodes', ['device', deviceId])}">${escape(row.entity_label)}</a>`
        : escape(row.entity_label)}</b> · ${escape(row.rule_name)}` +
        `${deviceId ? ` · <span id="alerts-d-links"></span>` : ''}</p>
      <p>${escape(row.message)}</p>
      ${row.detail ? `<p class="hint">${escape(row.detail)}</p>` : ''}
      ${row.rollup_note ? `<p class="hint"><b>Rolled up into this alert</b><br>` +
        `${escape(row.rollup_note).split('\n').join('<br>')}</p>` : ''}
      <p class="hint">Opened ${App.when(row.opened_ts)} · ` +
        `last seen ${App.when(row.last_ts)} · occurred ${row.count} time(s)</p>
      ${row.acked_by ? `<p class="hint">Acknowledged by ${escape(row.acked_by)}${row.ack_note ? `: ${escape(row.ack_note)}` : ''}</p>` : ''}
      ${row.resolved_ts ? `<p class="hint">Resolved ${App.when(row.resolved_ts)}${row.resolved_by ? ` by ${escape(row.resolved_by)}` : ' automatically'}` +
        // How long it stood, which is the question a resolved alert is
        // usually opened to answer. Both timestamps are already on the row,
        // so this costs nothing.
        `${App.duration(row.resolved_ts - row.opened_ts) ? ` · open for ${App.duration(row.resolved_ts - row.opened_ts)}` : ''}</p>` : ''}
      <div class="bar"><span class="section">NOTIFICATIONS</span></div>
      <div id="alerts-d-notifications" class="hint">Loading…</div>`;
    if (deviceId) loadDeviceLinks(deviceId, row.id);
    const resolveBtn = document.getElementById('alerts-d-resolve');
    if (resolveBtn) resolveBtn.onclick = () =>
      detailAction('Resolve', () => App.post(`/api/alerts/${row.id}/resolve`, {}), resolveBtn);
    const ackBtn = document.getElementById('alerts-d-ack');
    if (ackBtn) ackBtn.onclick = () =>
      detailAction('Acknowledge', () => App.post(`/api/alerts/${row.id}/ack`, {}), ackBtn);
    const unackBtn = document.getElementById('alerts-d-unack');
    if (unackBtn) unackBtn.onclick = () =>
      detailAction('Unacknowledge', () => App.post(`/api/alerts/${row.id}/unack`, {}), unackBtn);
    const muteBtn = muteable ? document.getElementById('alerts-d-mute') : null;
    if (muteBtn) muteBtn.onclick = () => detailAction('Mute', () => {
      const hours = Number(App.el('alerts-d-mute-hours').value) || 1;
      return App.post('/api/alerts/mute',
                      { entity_kind: 'device', entity_id: deviceId, hours });
    }, muteBtn);
    const unmuteBtn = document.getElementById('alerts-d-unmute');
    if (unmuteBtn) unmuteBtn.onclick = () => detailAction('Lift mute', () =>
      App.del('/api/alerts/mute', { entity_kind: 'device', entity_id: deviceId }), unmuteBtn);
    App.get(`/api/alerts/${row.id}`).then((full) => {
      const box = document.getElementById('alerts-d-notifications');
      if (!box) return;
      if (!full.notifications.length) { box.textContent = 'None sent.'; return; }
      box.innerHTML = full.notifications.map((n) =>
        `<div>${App.when(n.ts)} — ${escape(n.kind)} to ${escape(n.to_addr)}: ` +
        `${n.ok ? 'sent' : `<span class="err">failed (${escape(n.error)})</span>`}</div>`).join('');
    }).catch(() => {});
  }

  /* ---------------------------------- bulk unacknowledge, and unack gate */

  async function bulkUnacknowledge() {
    return bulkAction('/api/alerts/bulk-unack', 'Unacknowledged', 'unacknowledged');
  }

  /* -------------------------------- maintenance windows and bulk mute

     Both dialogs below share one "scope" picker: a device GROUP (whatever
     currently carries that device_group_id in Nodes) or an explicit list of
     devices — the same two shapes maintenance_windows.scope_kind and the
     bulk-mute route both take. Neither the group list nor the device list
     lives in `view`: both are fetched fresh each time one of these dialogs
     opens rather than kept in step with the page's own poll, since they are
     used rarely enough that one extra round trip on open costs nothing and
     is simpler than another thing refresh() has to keep current. */

  async function scopeSources() {
    try {
      const [groups, devices] = await Promise.all([
        App.get('/api/nodes/device-groups'), App.get('/api/nodes/devices'),
      ]);
      return { groups: groups.groups || [], devices: devices.devices || [] };
    } catch (error) {
      // Nodes read is what serves both lists. An account with Alerts write
      // but no Nodes read still gets a working dialog — device_ids typed
      // into the "Specific devices" box the fallback below offers — just
      // not a picker to choose them from.
      return { groups: [], devices: [] };
    }
  }

  function scopeFieldsHtml(prefix, groups, devices, current) {
    current = current || {};
    const scopeKind = current.scope_kind || 'group';
    const groupOptions = groups.length
      ? groups.map((g) => `<option value="${g.id}" ${
          current.scope_group_id === g.id ? 'selected' : ''}>${escape(g.name)}</option>`).join('')
      : '<option value="">(no device groups — use Specific devices)</option>';
    const selected = new Set((current.scope_device_ids || []).map(String));
    const deviceOptions = devices.length
      ? devices.map((d) => `<option value="${d.id}" ${
          selected.has(String(d.id)) ? 'selected' : ''}>${escape(d.name || d.ip)}</option>`).join('')
      : '';
    return `
      <label>Scope <select id="${prefix}-scope-kind">
        <option value="group" ${scopeKind === 'group' ? 'selected' : ''}>A device group</option>
        <option value="devices" ${scopeKind === 'devices' ? 'selected' : ''}>Specific devices</option>
      </select></label>
      <div id="${prefix}-scope-group" ${scopeKind !== 'group' ? 'hidden' : ''}>
        <label>Device group <select id="${prefix}-group">${groupOptions}</select></label>
      </div>
      <div id="${prefix}-scope-devices" ${scopeKind !== 'devices' ? 'hidden' : ''}>
        ${devices.length
          ? `<label>Devices (ctrl/cmd-click for several) <select id="${prefix}-devices" multiple size="6">${deviceOptions}</select></label>`
          : `<label>Device ids, comma-separated <input id="${prefix}-devices-text" value="${
              [...selected].join(', ')}"></label>`}
      </div>`;
  }

  function wireScopeFields(box, prefix) {
    const select = box.querySelector(`#${prefix}-scope-kind`);
    const groupBox = box.querySelector(`#${prefix}-scope-group`);
    const devicesBox = box.querySelector(`#${prefix}-scope-devices`);
    select.onchange = () => {
      groupBox.hidden = select.value !== 'group';
      devicesBox.hidden = select.value !== 'devices';
    };
  }

  function readScopeFields(box, prefix) {
    const kind = box.querySelector(`#${prefix}-scope-kind`).value;
    if (kind === 'group') {
      const groupId = box.querySelector(`#${prefix}-group`).value;
      if (!groupId) throw new Error('Choose a device group');
      return { scope_kind: 'group', scope_group_id: Number(groupId) };
    }
    const picker = box.querySelector(`#${prefix}-devices`);
    const ids = picker
      ? [...picker.selectedOptions].map((o) => Number(o.value))
      : box.querySelector(`#${prefix}-devices-text`).value.split(',')
          .map((s) => Number(s.trim())).filter((n) => Number.isFinite(n) && n > 0);
    if (!ids.length) throw new Error('Choose at least one device');
    return { scope_kind: 'devices', scope_device_ids: ids };
  }

  async function bulkMuteDialog() {
    const { groups, devices } = await scopeSources();
    App.modal('Bulk mute', `
      ${scopeFieldsHtml('bm', groups, devices)}
      <label>For <select id="bm-hours" class="fixed">${MUTE_HOURS.map((h) =>
        `<option value="${h}">${h} hour${h === 1 ? '' : 's'}</option>`).join('')}</select></label>
      <label>Reason (optional) <input id="bm-reason"></label>
      <p class="hint">Same 24-hour cap as muting one device. For a planned
        cutover measured in days, use a <b>maintenance window</b> instead —
        its duration is set by when it ends, not by this cap.</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Mute', primary: true, onClick: async (box) => {
        const scope = readScopeFields(box, 'bm');
        const result = await App.post('/api/alerts/bulk-mute', {
          ...scope, hours: Number(box.querySelector('#bm-hours').value) || 1,
          reason: box.querySelector('#bm-reason').value.trim(),
        });
        App.announce(`Muted ${result.muted} device(s)`);
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ]);
    wireScopeFields(App.el('modal-box'), 'bm');
  }

  function windowStatus(w) {
    if (w.active) return 'active now';
    return w.start_ts > Date.now() / 1000 ? 'upcoming' : 'ended';
  }

  function windowRowHtml(w) {
    const scope = w.scope_kind === 'group'
      ? `device group #${w.scope_group_id ?? '—'}`
      : `${w.scope_device_ids.length} device(s)`;
    const canEnd = w.active || w.start_ts > Date.now() / 1000;
    return `<tr data-id="${w.id}">
      <td>${escape(w.name)}</td>
      <td>${escape(scope)}${w.recurrence ? ' · weekly' : ''}</td>
      <td>${App.when(w.start_ts)}</td>
      <td>${App.when(w.end_ts)}</td>
      <td>${windowStatus(w)}</td>
      <td>${canEnd ? `<button type="button" class="aw-end" data-id="${w.id}">End now</button>` : ''}
        <button type="button" class="aw-delete" data-id="${w.id}">Delete</button></td>
    </tr>`;
  }

  async function windowsDialog() {
    const writable = App.canWrite('alerts');
    const { windows } = await App.get('/api/alerts/windows');
    const rows = (windows || []).slice().sort((a, b) => b.start_ts - a.start_ts);
    const box = App.modal('Maintenance windows', `
      <p class="hint">While a window is active, alerts for its covered
        devices behave exactly like muting each of them by hand — their
        interfaces and access points go quiet too, and any notification
        already held for the roll-up wait is released once the window ends
        if the alert is still standing.</p>
      <div class="table-wrap"><table id="aw-table">
        <caption class="sr-only">Maintenance windows</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Scope</th>
          <th scope="col">Start</th><th scope="col">End</th>
          <th scope="col">Status</th><th scope="col"></th></tr></thead>
        <tbody>${rows.length ? rows.map(windowRowHtml).join('')
          : '<tr><td colspan="6" class="hint">No maintenance windows.</td></tr>'}</tbody>
      </table></div>`, [
      { label: 'Cancel', onClick: App.closeModal },
      ...(writable ? [{ label: 'Add window', primary: true, onClick: addWindowDialog }] : []),
    ], { buttonsTop: true });
    if (!writable) return box;
    for (const btn of box.querySelectorAll('.aw-end')) {
      btn.onclick = async () => {
        btn.disabled = true;
        try {
          await App.post(`/api/alerts/windows/${btn.dataset.id}/end`, {});
          await windowsDialog();
        } catch (error) {
          App.announce(`End window failed: ${error.message}`);
          btn.disabled = false;
        }
      };
    }
    for (const btn of box.querySelectorAll('.aw-delete')) {
      btn.onclick = () => {
        const w = (windows || []).find((x) => String(x.id) === btn.dataset.id);
        App.confirmDestructive('Delete maintenance window',
          `<p>Delete <b>${escape(w ? w.name : 'this window')}</b>?</p>` +
          '<p class="hint">Alerts for its covered devices resume the moment ' +
          'this is deleted, if the window is currently active.</p>', 'Delete',
          () => App.del(`/api/alerts/windows/${btn.dataset.id}`, {}),
          () => windowsDialog());
      };
    }
    return box;
  }

  function localInputValue(date) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
      `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  async function addWindowDialog() {
    const { groups, devices } = await scopeSources();
    const start = new Date(Date.now() + 5 * 60000);
    const end = new Date(start.getTime() + 2 * 3600000);
    App.modal('Add maintenance window', `
      <label>Name <input id="aw-name" placeholder="Weekend core cutover"></label>
      ${scopeFieldsHtml('aw', groups, devices)}
      <label>Start <input id="aw-start" type="datetime-local" value="${localInputValue(start)}"></label>
      <label>End <input id="aw-end" type="datetime-local" value="${localInputValue(end)}"></label>
      <label class="check"><input type="checkbox" id="aw-weekly"> Repeats weekly</label>
      <p class="hint">Silences alerts for the covered devices for the whole
        span above, every 7 days, until this window is deleted or ended —
        not just the once. A window may start in the future: it has no
        effect until then.</p>
      <label>Reason (optional) <input id="aw-reason"></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        if (!App.requireFields(box, [['#aw-name', 'Name']])) return;
        const scope = readScopeFields(box, 'aw');
        const startTs = new Date(box.querySelector('#aw-start').value).getTime() / 1000;
        const endTs = new Date(box.querySelector('#aw-end').value).getTime() / 1000;
        if (!(endTs > startTs)) throw new Error('End must be after start');
        await App.post('/api/alerts/windows', {
          ...scope, name: box.querySelector('#aw-name').value.trim(),
          start_ts: startTs, end_ts: endTs,
          recurrence: box.querySelector('#aw-weekly').checked ? 'weekly' : null,
          reason: box.querySelector('#aw-reason').value.trim(),
        });
        App.closeModal();
        await windowsDialog();
      } },
    ]);
    wireScopeFields(App.el('modal-box'), 'aw');
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
        `<td><span class="sev sev-${r.severity}">${
          escape(App.state.severities?.[r.severity] || r.severity)}</span></td>` +
        `<td>${r.enabled ? 'yes' : 'no'}</td>`;
      tr.onclick = () => { view.rulesSelected = r.id; drawRulesTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
    // auto_resolve_after_s and notify are not in the rules payload's own
    // serializer; refresh() fetches them alongside and stashes them here.
    const extras = (view.ruleExtras || {})[String(r.id)] || {};
    App.modal(`Edit ${r.name}`, `
      <label>Name <input id="ar-name" value="${escape(r.name)}"></label>
      <label>Severity <select id="ar-sev">${[0,1,2,3,4,5,6,7].map((n) =>
        `<option value="${n}" ${r.severity === n ? 'selected' : ''}>${n} ${App.state.severities?.[n] || ''}</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" id="ar-enabled" ${r.enabled ? 'checked' : ''}> Enabled</label>
      <label>Device filter (substring, blank = all) <input id="ar-devfilter" value="${escape(r.device_filter || '')}"></label>
      <label>Template <select id="ar-template">${templateOptionsHtml(r.template_id)}</select></label>
      <label>Auto-resolve after <input id="ar-autoresolve" type="number" min="1"
        placeholder="never" value="${extras.auto_resolve_after_s
          ? Math.round(extras.auto_resolve_after_s / 60) : ''}"> minutes
        (blank = never)</label>
      <p class="hint">For a rule that fires on something momentary — a reboot,
        a trap, a syslog line — where nothing will ever arrive to clear it.
        The alert resolves itself this long after its last occurrence. Blank
        leaves it open until somebody resolves it or the condition clears.</p>
      <label class="check"><input type="checkbox" id="ar-notify"
        ${extras.notify !== false ? 'checked' : ''}> Send email for this rule</label>
      <p class="hint">Off makes the rule raise alerts that appear in the list
        and the badge but never reach a mailbox — for the noisy ones nobody
        wants paged about, which used to mean disabling the rule outright.</p>
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
        // Blank means NULL — "never auto-resolve" — not zero, which would
        // resolve every alert the moment it opened.
        const autoText = box.querySelector('#ar-autoresolve').value.trim();
        values.auto_resolve_after_s = autoText === '' || Number(autoText) === 0
          ? null : Number(autoText) * 60;
        values.notify = box.querySelector('#ar-notify').checked;
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
      <label>Clear threshold (threshold rules only) <input id="ar-clear" type="number" step="0.1"></label>
      <label>Auto-resolve after <input id="ar-autoresolve" type="number" min="1"
        placeholder="never"> minutes (blank = never)</label>
      <label class="check"><input type="checkbox" id="ar-notify" checked>
        Send email for this rule</label>
      <p class="hint">A trap or syslog rule usually wants an auto-resolve: the
        event is momentary and nothing will ever arrive to clear it.</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        if (!App.requireFields(box, [['#ar-key', 'Key'],
                                     ['#ar-name', 'Name']])) return;
        const key = box.querySelector('#ar-key').value.trim();
        const name = box.querySelector('#ar-name').value.trim();
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
        const autoText = box.querySelector('#ar-autoresolve').value.trim();
        if (autoText && Number(autoText) > 0) {
          values.auto_resolve_after_s = Number(autoText) * 60;
        }
        values.notify = box.querySelector('#ar-notify').checked;
        await App.post('/api/alerts/rules', values);
        App.closeModal();
        App.refreshNow('alerts');
      } },
    ]);
  }

  function removeRule() {
    const r = view.rules.find((x) => x.id === view.rulesSelected);
    if (!r || r.is_builtin) return;
    App.confirmDestructive('Remove rule',
      `<p>Remove <b>${escape(r.name)}</b>?</p>`,
      'Remove',
      () => App.del(`/api/alerts/rules/${r.id}`),
      (confirmed) => {
        if (!confirmed) return;
        view.rulesSelected = null;
        App.refreshNow('alerts');
      });
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
    App.wireRowKeyboard(body);
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
      <div id="at-tokens" class="scrollbox small" style="padding:6px">
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
        ${App.canStoreSecrets()
          ? `<label>Password <input id="as-pass" type="password"
          placeholder="${s.has_smtp_credential ? 'stored — leave blank to keep' : ''}"></label>`
          : App.credentialUnavailableHtml('An SMTP password')}
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
      <fieldset><legend>WEBHOOK</legend>
        ${check('as-webhook', 'Send an HTTP POST for notifications', s.webhook_enabled)}
        <label>URL <input id="as-webhook-url" value="${escape(s.webhook_url || '')}"
          placeholder="https://hooks.example.com/..."></label>
        <p class="hint">https:// required unless the host is localhost or a
          private (RFC1918) address — the same trust level the SMTP host
          above gets, since this is an operator-configured endpoint too.
          Delivered at the same points email is: a fresh alert, a clear, a
          re-notify and the roll-up digest, one JSON POST each, whether or
          not email itself is configured.</p>
        <label>Extra headers, one "Name: value" per line
          <textarea id="as-webhook-headers" rows="3" placeholder="Authorization: Bearer ...">${
            escape((s.webhook_headers || []).join('\n'))}</textarea></label>
        ${number('as-webhook-timeout', 'Timeout', s.webhook_timeout_s ?? 10, 'min=1 step=0.5')} s
        ${number('as-webhook-maxhour', 'Max webhooks per hour', s.webhook_max_per_hour ?? 600, 'min=1')}
        <p class="hint">Its own budget, kept apart from Max emails per hour
          above — a webhook receiver is a machine, not an inbox, and turning
          this on for a big fleet should not eat into a mail quota someone
          already tuned.</p>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        ${number('as-renotify', 'Re-notify an open alert every', s.renotify_minutes, 'min=0')} min (0 = once)
        ${check('as-clear', 'Send an email when an alert clears', s.notify_on_clear)}
        ${number('as-maxhour', 'Max emails per hour', s.max_emails_per_hour, 'min=1')}
        ${number('as-rollupdelay', 'Hold notifications for roll-up',
                 Math.round((s.notify_rollup_delay_s ?? 240) / 60), 'min=0')} min
        <p class="hint">A new alert's own email waits this long before it is
          sent, so several alerts opening close together — a mass outage's
          worth of "device not responding" rows, one per device as a slow
          poll cycle reaches each of them — go out as one digest instead of
          one email apiece, and stay inside <b>Max emails per hour</b> rather
          than burning through it in the first minute. Nothing about the
          alert itself waits: it still opens on the Alerts page and counts
          toward the totals immediately. An alert that clears, or turns out
          to be implied by another one, before the wait is up is never
          emailed at all. 0 sends the moment an alert opens, as before this
          setting existed.</p>
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
      <fieldset><legend>THIS BROWSER</legend>
        ${check('as-desktop', 'Show a desktop notification for a new alert of ' +
                'severity 1 or 2', App.desktopNotifyEnabled())}
        <p class="hint" id="as-desktop-status">Off by default. This one setting
          is remembered by this browser rather than by your account, because
          the permission that makes it work is granted by this browser to this
          address — an account setting would promise something a different
          machine could not keep. The browser asks for permission the first
          time you turn it on.</p>
      </fieldset>
      ${App.columnPickerFieldset('ALERT LIST COLUMNS', 'alerts', COLUMNS,
                                 s.table_columns)}
      <fieldset><legend>TEST</legend>
        <label>Send a test email to <input id="as-testto" placeholder="you@example.com"></label>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      // The one control in the product whose only purpose is to report an
      // outcome — it used to write its own tiny status line, missable next
      // to a 4000-pixel form. App.runJob toasts the success; a refusal
      // (bad host, auth failure) lands in .modal-error like every other
      // failure in this dialog, since a result whose ok is false is not a
      // rejected request but still has to be reported as one.
      { label: 'Send test', onClick: (box, button) => {
        if (!App.requireFields(box, [['#as-testto', 'A recipient']])) return;
        const to = box.querySelector('#as-testto').value.trim();
        return App.runJob(button, { queued: 'Sending…', done: 'Sent' },
          App.post('/api/alerts/smtp/test', { to }).then((result) => {
            if (!result.ok) throw new Error(result.error || 'not sent');
            return result;
          }));
      } },
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        const text = (id) => box.querySelector(id).value.trim();
        const password = (box.querySelector('#as-pass') || {}).value || '';
        if (password) {
          try {
            await App.post('/api/alerts/smtp/credential', { password });
          } catch (error) {
            box.querySelector('#as-cred-status').textContent = error.message;
            throw error;
          }
        }
        // Per browser, so it is stored (and its permission asked for) here
        // rather than travelling to the server with the rest.
        const notifyState = await App.setDesktopNotify(on('#as-desktop'));
        if (notifyState === 'blocked' || notifyState === 'unsupported') {
          box.querySelector('#as-desktop-status').textContent =
            notifyState === 'blocked'
              ? 'Desktop notifications are blocked for this address in this ' +
                'browser — everything else below was saved.'
              : 'This browser does not support desktop notifications — ' +
                'everything else below was saved.';
        }
        await App.post('/api/settings', { scope: 'alerts', values: {
          enabled: on('#as-enabled'), min_severity: Number(box.querySelector('#as-minsev').value),
          retention_days: num('#as-retention'), email_enabled: on('#as-email'),
          smtp_host: text('#as-host'), smtp_port: num('#as-port'),
          smtp_security: box.querySelector('#as-security').value,
          smtp_verify_cert: on('#as-verify'), smtp_username: text('#as-user'),
          smtp_from: text('#as-from'), smtp_from_name: text('#as-fromname'),
          smtp_to_default: recipients,
          webhook_enabled: on('#as-webhook'), webhook_url: text('#as-webhook-url'),
          webhook_headers: box.querySelector('#as-webhook-headers').value
            .split('\n').map((line) => line.trim()).filter(Boolean),
          webhook_timeout_s: num('#as-webhook-timeout'),
          webhook_max_per_hour: num('#as-webhook-maxhour'),
          renotify_minutes: num('#as-renotify'),
          notify_on_clear: on('#as-clear'), max_emails_per_hour: num('#as-maxhour'),
          notify_rollup_delay_s: num('#as-rollupdelay') * 60,
          new_device_grace_s: num('#as-grace') * 60,
          rollup_enabled: on('#as-rollup'),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-alerts'), COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('alerts');
        })()) },
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

  /* A route into this tab: #/alerts, #/alerts?state=open&severity=2, or
     #/alerts/<id>. Runs after refresh(), so view.alerts is populated and an
     alert named by a link can be found in it. An alert that is not in the
     current page of the list is fetched on its own rather than reported as
     missing — a link from a ticket is usually to something older than the
     300 rows on screen. */
  async function activate(opts) {
    if (!opts) return;
    const parts = opts.parts || [];
    const query = opts.query || {};
    let filtered = false;
    for (const [id, key] of [['alerts-filter-state', 'state'],
                             ['alerts-filter-sev', 'severity'],
                             ['alerts-filter-device', 'device'],
                             ['alerts-filter-text', 'q']]) {
      if (query[key] === undefined) continue;
      const field = App.el(id);
      if (!field) continue;
      field.value = query[key];
      filtered = true;
    }
    if (filtered) await App.refreshNow('alerts');
    if (parts[0] === undefined) return;
    const alertId = Number(parts[0]);
    if (!Number.isFinite(alertId)) return;
    view.selected = alertId;
    drawTable();
    let row = (view.alerts || []).find((a) => a.id === alertId);
    if (!row) {
      try {
        row = (await App.get(`/api/alerts/${alertId}`)).alert;
      } catch (error) {
        return;                    // a link to an alert that has been pruned
      }
    }
    showDetail(row);
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'alerts') return;
    drawStatus();
    const { t0, t1 } = window_();
    const span = t1 - t0;
    const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);
    const f = filters();
    const filterSig = JSON.stringify(f);
    if (view.pageFilterSig !== null && view.pageFilterSig !== filterSig) view.pageOffset = 0;
    view.pageFilterSig = filterSig;
    const [overview, list, total, rules, ruleExtras, templates, mutes] =
      await Promise.all([
      App.get('/api/alerts/overview', { t0, t1, bucket }),
      App.get('/api/alerts', { ...f, limit: view.pageLimit, offset: view.pageOffset }),
      // Same filters, in the same round trip, so the label under the table
      // can say what fraction of the matches is on screen.
      App.get('/api/alerts/total', f),
      App.get('/api/alerts/rules'),
      App.get('/api/alerts/rules/extras'),
      App.get('/api/alerts/templates'),
      App.get('/api/alerts/mutes'),
    ]);
    view.hist = overview.buckets;
    view.histPlot = App.plottedRange(overview.buckets, bucket, t0, t1);
    // No dedicated summary line exists for this histogram yet (unlike
    // Syslog/SNMP's #sl-hist-summary / #sn-hist-summary) — guarded until
    // index.html grows an #alerts-hist-summary span beside "ALERTS PER
    // HOUR" for this to fill in.
    const histSummaryEl = App.el('alerts-hist-summary');
    if (histSummaryEl) {
      const histTotal = overview.buckets.reduce((sum, b) => sum + b.total, 0);
      const p = view.histPlot;
      histSummaryEl.textContent =
        `${histTotal.toLocaleString()} alerts · ${App.stamp(p.t0, p.span)} – ${App.stamp(p.t1, p.span)}` +
        (p.narrowed ? ` (of a ${App.duration(span)} window)` : '');
    }
    view.alerts = list.alerts;
    view.alertTotal = total;
    drawAlertsPager();
    view.rules = rules.rules;
    view.ruleExtras = ruleExtras.rules || {};
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

  /* Filled from the refresh, after init() — so a restored choice arrives
     from the store here rather than from restoreControls. A rule that has
     since been deleted matches no option, which selects nothing at all:
     snap back to "any rule" rather than show a blank filter. */
  function drawAlertsPager() {
    const pager = App.el('alerts-pager');
    const total = (view.alertTotal || {}).total || 0;
    // Nothing to page through: the whole matching set fit on one page, so
    // showing prev/next controls for a page that has no "next" would just
    // be two more disabled buttons nobody needs.
    if (total <= view.alerts.length && view.pageOffset === 0) {
      pager.hidden = true;
      return;
    }
    pager.hidden = false;
    const shown = view.alerts.length;
    const from = shown ? view.pageOffset + 1 : 0;
    const to = view.pageOffset + shown;
    App.el('alerts-page-summary').textContent = `${from}–${to} of ${total.toLocaleString()}`;
    App.el('alerts-page-prev').disabled = view.pageOffset <= 0;
    App.el('alerts-page-next').disabled = to >= total;
  }

  function exportAlertsCsv() {
    // The export ceiling (50,000) is well past ALERTS_LIST_CAP (2,000):
    // the whole filtered set leaves in one file regardless of which page
    // is on screen.
    App.exportCsv('/api/alerts/export.csv', filters());
  }

  function fillRuleFilter() {
    const select = App.el('alerts-filter-rule');
    const current = select.value || App.savedControl('alerts', 'alerts-filter-rule') || '';
    select.innerHTML = '<option value="">any rule</option>' +
      view.rules.map((r) => `<option value="${r.id}">${escape(r.name)}</option>`).join('');
    select.value = current;
    // Dropped from the store as well as from the control: while it is stored,
    // filters() above would go on sending a rule id that matches nothing.
    if (select.selectedIndex < 0) {
      select.value = '';
      App.rememberControl('alerts', 'alerts-filter-rule', '');
    }
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back. Listeners run in registration order. restoreControls
       stays at the end, after the range and severity lists exist; it assigns
       from script, which fires no event. */
    const CONTROLS = ['alerts-filter-sev', 'alerts-filter-state',
      'alerts-filter-rule', 'alerts-filter-device', 'alerts-filter-text',
      'alerts-range'];
    App.rememberControls('alerts', CONTROLS);
    for (const btn of document.querySelectorAll('#page-alerts > .subtabs > .subtab')) {
      btn.onclick = () => {
        App.rememberSub('alerts', btn.dataset.subtab);
        selectSub(btn.dataset.subtab);
      };
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
    App.filterBar('alerts', {
      text: ['alerts-filter-device', 'alerts-filter-text'],
      selects: ['alerts-filter-sev', 'alerts-filter-state', 'alerts-filter-rule', 'alerts-range'],
      apply: 'alerts-apply', clear: 'alerts-clear',
      clears: ['alerts-filter-device', 'alerts-filter-text', 'alerts-filter-sev',
               'alerts-filter-rule'],
    });
    App.el('alerts-export-csv').onclick = exportAlertsCsv;
    App.el('alerts-page-prev').onclick = () => {
      view.pageOffset = Math.max(0, view.pageOffset - view.pageLimit);
      App.refreshNow('alerts');
    };
    App.el('alerts-page-next').onclick = () => {
      const total = (view.alertTotal || {}).total || 0;
      if (view.pageOffset + view.pageLimit >= total) return;
      view.pageOffset += view.pageLimit;
      App.refreshNow('alerts');
    };
    // Acknowledge-all and bulk-resolve don't delete rows, but they change
    // state for everything on screen in one click and there is no undo, so
    // they get the same guard as a delete.
    App.el('alerts-ack-all').onclick = () => {
      // The route acknowledges every open alert on the SERVER, so the number
      // in the question has to be the server's, not the truncated page's —
      // it used to say "(N shown)", which read as the size of the action.
      const open = ((App.state.serverState || {}).alerts || {}).open_count;
      App.confirmDestructive('Acknowledge all',
        `<p>Acknowledge ${open != null ? `all ${open.toLocaleString()}` : 'every'} ` +
        'open alert(s)?</p>' +
        '<p class="hint">Every open alert on the server — not your ticked ' +
        'selection, and not just the ones matching the current filter. Use ' +
        '"Acknowledge selected" for the rows you have ticked, or Unacknowledge ' +
        'afterwards for any that were acted on too soon.</p>', 'Acknowledge',
        (button) => App.runJob(button, { queued: 'Acknowledging…' }, (async () => {
          const result = await App.post('/api/alerts/ack-all', {});
          view.checked.clear();
          clearSelection();
          App.refreshNow('alerts');
          return `Acknowledged ${Number(result.acknowledged || 0).toLocaleString()} alert(s)`;
        })()));
    };
    App.el('alerts-bulk-ack').onclick = () => {
      const n = view.checked.size;
      if (!n) return;
      App.confirmDestructive('Acknowledge alerts',
        `<p>Acknowledge the <b>${n}</b> selected alert(s)?</p>` +
        '<p class="hint">Only the ones you have ticked, and only those still ' +
        'open.</p>',
        'Acknowledge', (button) => App.runJob(button,
          { queued: 'Acknowledging…' }, bulkAcknowledge()));
    };
    // Injected rather than declared in the bulk bar's own markup: it is the
    // one bulk action that reverses another one (Acknowledge selected /
    // Acknowledge all), which is why it earns a button at all where a
    // resolved alert's own reversal does not.
    const bulkUnackBtn = document.createElement('button');
    bulkUnackBtn.id = 'alerts-bulk-unack';
    bulkUnackBtn.textContent = 'Unacknowledge selected';
    App.el('alerts-bulk-resolve').insertAdjacentElement('afterend', bulkUnackBtn);
    bulkUnackBtn.onclick = () => {
      const n = view.checked.size;
      if (!n) return;
      App.confirmDestructive('Unacknowledge alerts',
        `<p>Return the <b>${n}</b> selected alert(s) to unacknowledged?</p>` +
        '<p class="hint">Only the ones you have ticked, and only those ' +
        'currently acknowledged.</p>',
        'Unacknowledge', (button) => App.runJob(button,
          { queued: 'Unacknowledging…' }, bulkUnacknowledge()));
    };
    App.el('alerts-bulk-resolve').onclick = () => {
      const n = view.checked.size;
      if (!n) return;
      App.confirmDestructive('Resolve alerts',
        `<p>Resolve the <b>${n}</b> selected alert(s)?</p>` +
        '<p class="hint">Resolved alerts are what "Delete resolved alerts" in ' +
        'Settings later removes.</p>', 'Resolve', (button) => App.runJob(button,
          { queued: 'Resolving…' }, bulkResolve()));
    };
    App.el('alerts-bulk-clear').onclick = () => { view.checked.clear(); drawTable(); };
    App.el('alerts-toggle').onclick = async () => {
      const running = (App.state.serverState.alerts || {}).running;
      await App.post('/api/alerts/engine', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('alerts');
    };
    App.el('alerts-settings').onclick = settingsDialog;
    // Both injected rather than declared in index.html: neither has a
    // subpage of its own — everything either does lives inside a modal, the
    // same way Settings itself does — so there is no static markup for them
    // to hang off. Write-gated by hand rather than with data-requires-write,
    // since these are added after this module's own init() runs and the
    // very first applyPermissions() sweep (on the initial config load) would
    // otherwise miss them; refresh() below keeps them current on any later
    // permission change the same way applyPermissions does for everything
    // declared in markup.
    const windowsBtn = document.createElement('button');
    windowsBtn.id = 'alerts-windows-btn';
    windowsBtn.textContent = 'Maintenance windows';
    windowsBtn.onclick = windowsDialog;
    App.el('alerts-settings').insertAdjacentElement('beforebegin', windowsBtn);
    const bulkMuteBtn = document.createElement('button');
    bulkMuteBtn.id = 'alerts-bulkmute-btn';
    bulkMuteBtn.textContent = 'Bulk mute';
    bulkMuteBtn.onclick = bulkMuteDialog;
    App.el('alerts-settings').insertAdjacentElement('beforebegin', bulkMuteBtn);
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

    // Last thing in init(): the range and severity lists above are filled
    // and nothing has been fetched, so the first refresh reads these back
    // out of the DOM the way it reads the markup defaults.
    App.restoreControls('alerts', CONTROLS);
    selectSub(App.recallSub('alerts', 'current'));
  }

  function selectSub(name) {
    for (const btn of document.querySelectorAll('#page-alerts > .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#page-alerts > .subpage')) {
      page.classList.toggle('active', page.id === `alerts-sub-${name}`);
    }
  }

  App.pages.alerts = { init, refresh, activate, fastTick: drawStatus };
})();
